import { jest } from "@jest/globals";
import { ForbiddenException } from "@nestjs/common";
import { ethers } from "ethers";

// Mock the BLS primitives (@noble/curves) so the unit test focuses on the
// owner-authorization gate without pulling in the ESM-only curve library.
// The gate runs BEFORE any of these are invoked; on the success path we only
// assert that signing was reached and produced a stubbed signature.
jest.unstable_mockModule("../../utils/bls.util.js", () => {
  const fakeG2Point = { toHex: () => "ab".repeat(96) };
  const fakeG1Point = { toHex: () => "cd".repeat(48) };
  return {
    BLS_DST: "TEST_DST",
    bls: {
      G2: { hashToCurve: jest.fn(async () => fakeG2Point) },
      G1: { Point: { fromHex: () => fakeG1Point } },
    },
    sigs: {
      getPublicKey: () => fakeG1Point,
      sign: jest.fn(async () => fakeG2Point),
    },
    encodeG2Point: () => new Uint8Array(256),
  };
});

const { BlsService } = await import("./bls.service.js");
const { BlockchainService } = await import("../blockchain/blockchain.service.js");
type BlockchainService = InstanceType<typeof BlockchainService>;
// LocalKeySigner imports the (mocked) bls.util sigs — must load AFTER the mock above.
const { LocalKeySigner } = await import("../signer/local-key.signer.js");
import type { PackedUserOp } from "../blockchain/blockchain.service.js";
import type { NodeKeyPair } from "../../interfaces/node.interface.js";
import type { SignerService } from "../signer/signer.service.js";

/**
 * Fix 2 Stage 1 — owner-authorization gate tests.
 *
 * The node co-signs ONLY when the request carries the FULL UserOperation plus a
 * valid owner ECDSA signature (EIP-191) over the AUTHORITATIVE userOpHash, which
 * is DERIVED from the userOp via EntryPoint.getUserOpHash (never caller-supplied).
 * BlockchainService.getUserOpHash + getAccountOwner are mocked.
 */
describe("BlsService — owner-authorization gate (Fix 2 Stage 1)", () => {
  // A valid BLS12-381 private key scalar (non-zero, < curve order). 0x...01.
  const node: NodeKeyPair = {
    nodeId: "node_test",
    nodeName: "test",
    privateKey: "0x" + "00".repeat(31) + "01",
    publicKey: "0x",
    description: "test node",
  };

  // The victim account owner (EOA). The gate recovers an EIP-191 sig over the
  // derived userOpHash and compares to this account's on-chain owner.
  const ownerWallet = new ethers.Wallet(
    "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
  );
  const victimAccount = "0x08923CE682336DF2f238C034B4add5Bf73d4028A";

  // The authoritative hash that EntryPoint.getUserOpHash returns for the userOp.
  const derivedHash = "0x8bb1b199f427dfc49e5fe40f2f3278cb1a48587824b78263051c8c4d81d77a81";

  // A well-formed v0.7 PackedUserOperation for the victim account.
  function makeUserOp(sender: string): PackedUserOp {
    return {
      sender,
      nonce: "0",
      initCode: "0x",
      callData: "0x",
      accountGasLimits: "0x" + "00".repeat(32),
      preVerificationGas: "0",
      gasFees: "0x" + "00".repeat(32),
      paymasterAndData: "0x",
      signature: "0x",
    };
  }

  let service: InstanceType<typeof BlsService>;
  let getAccountOwner: jest.Mock<(account: string) => Promise<string>>;
  let getUserOpHash: jest.Mock<(userOp: PackedUserOp) => Promise<string>>;

  // Sign a hash exactly the way the account owner signs the UserOperation:
  // EIP-191 prefix over the raw 32-byte hash.
  async function signEip191(wallet: ethers.Wallet, hash: string): Promise<string> {
    return wallet.signMessage(ethers.getBytes(hash));
  }

  beforeEach(() => {
    getAccountOwner = jest.fn<(account: string) => Promise<string>>();
    getUserOpHash = jest.fn<(userOp: PackedUserOp) => Promise<string>>();
    const blockchain = { getAccountOwner, getUserOpHash } as unknown as BlockchainService;
    // Default local-key signer (byte-identical to the pre-port signing path).
    const signer = {
      forNode: (n: { privateKey: string }) => new LocalKeySigner(n.privateKey),
    } as unknown as SignerService;
    service = new BlsService(blockchain, signer);
  });

  it("signs and returns a signature when ownerAuth recovers to the derived-hash owner", async () => {
    getUserOpHash.mockResolvedValue(derivedHash);
    getAccountOwner.mockResolvedValue(ownerWallet.address);
    const ownerAuth = await signEip191(ownerWallet, derivedHash);

    const result = await service.signMessage(makeUserOp(victimAccount), ownerAuth, node);

    // account must be derived from userOp.sender, not caller-claimed.
    expect(getAccountOwner).toHaveBeenCalledWith(victimAccount);
    expect(getUserOpHash).toHaveBeenCalledTimes(1);
    expect(result.nodeId).toBe(node.nodeId);
    expect(result.signature).toMatch(/^0x[0-9a-f]+$/);
    expect(result.signatureCompact).toBeTruthy();
    // The signed hash is the EntryPoint-derived one.
    expect(result.message).toBe(derivedHash);
  });

  // ── CRITICAL regression (the Codex finding) ──────────────────────────────
  // An attacker who OWNS account A cannot get the node to co-sign a userOp for
  // victim account B by supplying B's userOp + A-owner's signature. Because:
  //   - account = userOp.sender = B  (derived, attacker cannot lie)
  //   - userOpHash is derived from B's userOp via EntryPoint
  //   - the gate requires B's on-chain owner to have signed that hash
  // The attacker's signature recovers to A's owner != B's owner → 403.
  it("CRITICAL: rejects (403) cross-account oracle — attacker owns a different account", async () => {
    const attackerWallet = ethers.Wallet.createRandom();
    // The node always derives the hash from the submitted userOp (the victim's).
    getUserOpHash.mockResolvedValue(derivedHash);
    // The submitted userOp is the VICTIM's account; its on-chain owner is ownerWallet.
    getAccountOwner.mockResolvedValue(ownerWallet.address);
    // Attacker signs the (derived) victim hash with their OWN key — they own a
    // different account, not the victim's.
    const ownerAuth = await signEip191(attackerWallet as unknown as ethers.Wallet, derivedHash);

    await expect(
      service.signMessage(makeUserOp(victimAccount), ownerAuth, node)
    ).rejects.toBeInstanceOf(ForbiddenException);
  });

  it("rejects (403) when userOp.sender's owner != ownerAuth signer", async () => {
    getUserOpHash.mockResolvedValue(derivedHash);
    getAccountOwner.mockResolvedValue(ownerWallet.address);
    const wrongSigner = ethers.Wallet.createRandom();
    const ownerAuth = await signEip191(wrongSigner as unknown as ethers.Wallet, derivedHash);

    await expect(
      service.signMessage(makeUserOp(victimAccount), ownerAuth, node)
    ).rejects.toBeInstanceOf(ForbiddenException);
  });

  it("attacker cannot substitute a different hash — only the EntryPoint-derived hash is signed", async () => {
    // Owner signs SOME OTHER hash; the node only ever derives & checks against the
    // EntryPoint hash, so a sig over an unrelated hash never authorizes.
    getUserOpHash.mockResolvedValue(derivedHash);
    getAccountOwner.mockResolvedValue(ownerWallet.address);
    const otherHash = "0x" + "11".repeat(32);
    const ownerAuth = await signEip191(ownerWallet, otherHash);

    await expect(
      service.signMessage(makeUserOp(victimAccount), ownerAuth, node)
    ).rejects.toBeInstanceOf(ForbiddenException);
  });

  it("rejects (403) when EntryPoint.getUserOpHash reverts", async () => {
    getUserOpHash.mockRejectedValue(new Error("execution reverted"));
    getAccountOwner.mockResolvedValue(ownerWallet.address);
    const ownerAuth = await signEip191(ownerWallet, derivedHash);

    await expect(
      service.signMessage(makeUserOp(victimAccount), ownerAuth, node)
    ).rejects.toBeInstanceOf(ForbiddenException);
  });

  it("rejects (403, not 400) when ownerAuth is malformed", async () => {
    getUserOpHash.mockResolvedValue(derivedHash);
    getAccountOwner.mockResolvedValue(ownerWallet.address);

    await expect(
      service.signMessage(makeUserOp(victimAccount), "0xdeadbeef", node)
    ).rejects.toBeInstanceOf(ForbiddenException);
  });

  it("rejects (403, not 400) when ownerAuth is missing/undefined", async () => {
    getUserOpHash.mockResolvedValue(derivedHash);
    getAccountOwner.mockResolvedValue(ownerWallet.address);

    await expect(
      service.signMessage(makeUserOp(victimAccount), undefined, node)
    ).rejects.toBeInstanceOf(ForbiddenException);
  });

  it("rejects (403, not 400) when userOp.sender is not a valid address", async () => {
    getUserOpHash.mockResolvedValue(derivedHash);
    getAccountOwner.mockResolvedValue(ownerWallet.address);
    const ownerAuth = await signEip191(ownerWallet, derivedHash);
    const bad = { ...makeUserOp(victimAccount), sender: "not-an-address" };

    await expect(service.signMessage(bad, ownerAuth, node)).rejects.toBeInstanceOf(
      ForbiddenException
    );
    // Shape rejected before any chain read.
    expect(getUserOpHash).not.toHaveBeenCalled();
    expect(getAccountOwner).not.toHaveBeenCalled();
  });

  it("rejects (403, not 400) when a required userOp field is missing", async () => {
    getUserOpHash.mockResolvedValue(derivedHash);
    getAccountOwner.mockResolvedValue(ownerWallet.address);
    const ownerAuth = await signEip191(ownerWallet, derivedHash);
    const bad = { ...makeUserOp(victimAccount) } as Partial<PackedUserOp>;
    delete bad.callData;

    await expect(service.signMessage(bad as PackedUserOp, ownerAuth, node)).rejects.toBeInstanceOf(
      ForbiddenException
    );
    expect(getUserOpHash).not.toHaveBeenCalled();
    expect(getAccountOwner).not.toHaveBeenCalled();
  });

  it("rejects (403) fail-closed for a P256/passkey-only account (owner == zero address)", async () => {
    getUserOpHash.mockResolvedValue(derivedHash);
    getAccountOwner.mockResolvedValue(ethers.ZeroAddress);
    const ownerAuth = await signEip191(ownerWallet, derivedHash);

    await expect(
      service.signMessage(makeUserOp(victimAccount), ownerAuth, node)
    ).rejects.toBeInstanceOf(ForbiddenException);
  });

  it("rejects (403) fail-closed when the on-chain owner read fails", async () => {
    getUserOpHash.mockResolvedValue(derivedHash);
    getAccountOwner.mockRejectedValue(new Error("rpc down"));
    const ownerAuth = await signEip191(ownerWallet, derivedHash);

    await expect(
      service.signMessage(makeUserOp(victimAccount), ownerAuth, node)
    ).rejects.toBeInstanceOf(ForbiddenException);
  });

  it("matches owner regardless of address checksum casing", async () => {
    getUserOpHash.mockResolvedValue(derivedHash);
    getAccountOwner.mockResolvedValue(ethers.getAddress(ownerWallet.address));
    const ownerAuth = await signEip191(ownerWallet, derivedHash);

    const result = await service.signMessage(makeUserOp(victimAccount), ownerAuth, node);
    expect(result.nodeId).toBe(node.nodeId);
  });
});
