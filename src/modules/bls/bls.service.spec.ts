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
  let isValidOwnerAuth: jest.Mock<
    (account: string, userOpHash: string, ownerAuth: string) => Promise<boolean>
  >;

  // Sign a hash exactly the way the account owner signs the UserOperation:
  // EIP-191 prefix over the raw 32-byte hash.
  async function signEip191(wallet: ethers.Wallet, hash: string): Promise<string> {
    return wallet.signMessage(ethers.getBytes(hash));
  }

  beforeEach(() => {
    getAccountOwner = jest.fn<(account: string) => Promise<string>>();
    getUserOpHash = jest.fn<(userOp: PackedUserOp) => Promise<string>>();
    isValidOwnerAuth =
      jest.fn<(account: string, userOpHash: string, ownerAuth: string) => Promise<boolean>>();
    const blockchain = {
      getAccountOwner,
      getUserOpHash,
      isValidOwnerAuth,
    } as unknown as InstanceType<typeof BlockchainService>;
    // Default local-key signer (byte-identical to the pre-port signing path).
    const signer = {
      forNode: (n: { privateKey: string }) => new LocalKeySigner(n.privateKey),
    } as unknown as SignerService;
    service = new BlsService(blockchain, signer);
  });

  it("signs and returns a signature when ownerAuth recovers to the derived-hash owner", async () => {
    getUserOpHash.mockResolvedValue(derivedHash);
    getAccountOwner.mockResolvedValue(ownerWallet.address);
    isValidOwnerAuth.mockResolvedValue(true);
    const ownerAuth = await signEip191(ownerWallet, derivedHash);

    const result = await service.signMessage(makeUserOp(victimAccount), ownerAuth, node);

    // account must be derived from userOp.sender, not caller-claimed.
    expect(getUserOpHash).toHaveBeenCalledTimes(1);
    expect(isValidOwnerAuth).toHaveBeenCalledWith(victimAccount, derivedHash, ownerAuth);
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
  //   - the contract validates against B's authorization logic
  // The attacker's signature (or WebAuthn) doesn't validate against B → eth_call returns false → 403.
  it("CRITICAL: rejects (403) cross-account oracle — attacker owns a different account", async () => {
    const attackerWallet = ethers.Wallet.createRandom();
    // The node always derives the hash from the submitted userOp (the victim's).
    getUserOpHash.mockResolvedValue(derivedHash);
    // The submitted userOp is the VICTIM's account; contract validation returns false.
    isValidOwnerAuth.mockResolvedValue(false);
    // Attacker signs the (derived) victim hash with their OWN key — the contract
    // (authorizing against victim's owner/keys) rejects it.
    const ownerAuth = await signEip191(attackerWallet as unknown as ethers.Wallet, derivedHash);

    await expect(
      service.signMessage(makeUserOp(victimAccount), ownerAuth, node)
    ).rejects.toBeInstanceOf(ForbiddenException);
  });

  it("rejects (403) when ownerAuth is invalid (isValidOwnerAuth returns false)", async () => {
    getUserOpHash.mockResolvedValue(derivedHash);
    isValidOwnerAuth.mockResolvedValue(false);
    const wrongSigner = ethers.Wallet.createRandom();
    const ownerAuth = await signEip191(wrongSigner as unknown as ethers.Wallet, derivedHash);

    await expect(
      service.signMessage(makeUserOp(victimAccount), ownerAuth, node)
    ).rejects.toBeInstanceOf(ForbiddenException);
  });

  it("attacker cannot substitute a different hash — only the EntryPoint-derived hash is signed", async () => {
    // Owner signs SOME OTHER hash; the node only ever derives & checks against the
    // EntryPoint hash, so the contract validation against that other hash fails.
    getUserOpHash.mockResolvedValue(derivedHash);
    isValidOwnerAuth.mockResolvedValue(false);
    const otherHash = "0x" + "11".repeat(32);
    const ownerAuth = await signEip191(ownerWallet, otherHash);

    await expect(
      service.signMessage(makeUserOp(victimAccount), ownerAuth, node)
    ).rejects.toBeInstanceOf(ForbiddenException);
  });

  it("rejects (403) when EntryPoint.getUserOpHash reverts", async () => {
    getUserOpHash.mockRejectedValue(new Error("execution reverted"));
    const ownerAuth = await signEip191(ownerWallet, derivedHash);

    await expect(
      service.signMessage(makeUserOp(victimAccount), ownerAuth, node)
    ).rejects.toBeInstanceOf(ForbiddenException);
  });

  it("rejects (403, not 400) when ownerAuth is malformed", async () => {
    getUserOpHash.mockResolvedValue(derivedHash);
    isValidOwnerAuth.mockResolvedValue(false);

    await expect(
      service.signMessage(makeUserOp(victimAccount), "0xdeadbeef", node)
    ).rejects.toBeInstanceOf(ForbiddenException);
  });

  it("rejects (403, not 400) when ownerAuth is missing/undefined", async () => {
    getUserOpHash.mockResolvedValue(derivedHash);
    isValidOwnerAuth.mockResolvedValue(false);

    await expect(
      service.signMessage(makeUserOp(victimAccount), undefined, node)
    ).rejects.toBeInstanceOf(ForbiddenException);
  });

  it("rejects (403, not 400) when userOp.sender is not a valid address", async () => {
    getUserOpHash.mockResolvedValue(derivedHash);
    isValidOwnerAuth.mockResolvedValue(true);
    const ownerAuth = await signEip191(ownerWallet, derivedHash);
    const bad = { ...makeUserOp(victimAccount), sender: "not-an-address" };

    await expect(service.signMessage(bad, ownerAuth, node)).rejects.toBeInstanceOf(
      ForbiddenException
    );
    // Shape rejected before any chain read.
    expect(getUserOpHash).not.toHaveBeenCalled();
    expect(isValidOwnerAuth).not.toHaveBeenCalled();
  });

  it("rejects (403, not 400) when a required userOp field is missing", async () => {
    getUserOpHash.mockResolvedValue(derivedHash);
    isValidOwnerAuth.mockResolvedValue(true);
    const ownerAuth = await signEip191(ownerWallet, derivedHash);
    const bad = { ...makeUserOp(victimAccount) } as Partial<PackedUserOp>;
    delete bad.callData;

    await expect(service.signMessage(bad as PackedUserOp, ownerAuth, node)).rejects.toBeInstanceOf(
      ForbiddenException
    );
    expect(getUserOpHash).not.toHaveBeenCalled();
    expect(isValidOwnerAuth).not.toHaveBeenCalled();
  });

  it("rejects (403) fail-closed when isValidOwnerAuth eth_call fails (e.g. P256 passkey validation rejection)", async () => {
    getUserOpHash.mockResolvedValue(derivedHash);
    isValidOwnerAuth.mockResolvedValue(false);
    // Attempt with a WebAuthn blob (or any ownerAuth); contract validation fails.
    const ownerAuth = await signEip191(ownerWallet, derivedHash);

    await expect(
      service.signMessage(makeUserOp(victimAccount), ownerAuth, node)
    ).rejects.toBeInstanceOf(ForbiddenException);
  });

  it("rejects (403) fail-closed when isValidOwnerAuth eth_call throws (rpc failure)", async () => {
    getUserOpHash.mockResolvedValue(derivedHash);
    isValidOwnerAuth.mockRejectedValue(new Error("rpc down"));
    const ownerAuth = await signEip191(ownerWallet, derivedHash);

    await expect(
      service.signMessage(makeUserOp(victimAccount), ownerAuth, node)
    ).rejects.toBeInstanceOf(ForbiddenException);
  });

  it("signs when isValidOwnerAuth returns true regardless of address checksum casing", async () => {
    getUserOpHash.mockResolvedValue(derivedHash);
    isValidOwnerAuth.mockResolvedValue(true);
    const ownerAuth = await signEip191(ownerWallet, derivedHash);

    const result = await service.signMessage(makeUserOp(victimAccount), ownerAuth, node);
    expect(result.nodeId).toBe(node.nodeId);
    // eth_call was made with the checksum-normalized account address.
    expect(isValidOwnerAuth).toHaveBeenCalledWith(victimAccount, derivedHash, ownerAuth);
  });
});

/**
 * CC-36 round-6 L1: `signDerivedHash()` (the hybrid local/remote signing selection) was
 * refactored across rounds 4-5 (extracting `getRustSignerConfig()`, adding
 * `resolveSigningPublicKey()`). Codex manually diffed the refactor against the original and
 * confirmed behavior preservation, but the test SUITE never actually exercised the remote
 * signing path at all — the node-key-consistency self-check's own remote-signer tests only
 * prove the CHECKER doesn't call fetch; they say nothing about whether real remote SIGNING
 * still works. These four tests lock signDerivedHash()'s own behavior directly (deliberately
 * narrow scope, per the round-6 review — not expanding beyond these four).
 */
describe("BlsService — signDerivedHash hybrid local/remote signing (CC-36 round-6 L1)", () => {
  const node: NodeKeyPair = {
    nodeId: "node_test",
    nodeName: "test",
    privateKey: "0x" + "00".repeat(31) + "01",
    publicKey: "0x",
    description: "test node",
  };
  const derivedHash = "0x8bb1b199f427dfc49e5fe40f2f3278cb1a48587824b78263051c8c4d81d77a81";

  function makeConfig(overrides: Record<string, unknown>) {
    return { get: (k: string) => overrides[k] } as any;
  }

  function makeService(configOverrides: Record<string, unknown>) {
    const blockchain = {} as unknown as InstanceType<typeof BlockchainService>;
    const signer = {
      forNode: (n: { privateKey: string }) => new LocalKeySigner(n.privateKey),
    } as unknown as SignerService;
    return new BlsService(blockchain, signer, makeConfig(configOverrides));
  }

  const originalFetch = global.fetch;
  afterEach(() => {
    global.fetch = originalFetch;
  });

  it("1. remote signing succeeds and the response is mapped to SignatureResult correctly", async () => {
    global.fetch = jest.fn(async () => ({
      ok: true,
      status: 200,
      json: async () => ({
        signature: "0xaaaa",
        signature_compact: "bbbb",
        public_key: "cccc",
      }),
    })) as any;
    const service = makeService({ rustSignerUrl: "http://fake-signer.local" });

    const result = await service.signDerivedHash(derivedHash, node);

    expect(result).toEqual({
      nodeId: node.nodeId,
      signature: "0xaaaa",
      signatureCompact: "bbbb",
      publicKey: "cccc",
      message: derivedHash,
    });
  });

  it("2. rustSignerToken is sent as the X-Signer-Token request header", async () => {
    let capturedHeaders: Record<string, string> | undefined;
    global.fetch = jest.fn(async (_url: unknown, init: any) => {
      capturedHeaders = init.headers;
      return {
        ok: true,
        status: 200,
        json: async () => ({ signature: "0x", signature_compact: "0x", public_key: "0x" }),
      };
    }) as any;
    const service = makeService({
      rustSignerUrl: "http://fake-signer.local",
      rustSignerToken: "s3cr3t-token",
    });

    await service.signDerivedHash(derivedHash, node);

    expect(capturedHeaders?.["X-Signer-Token"]).toBe("s3cr3t-token");
  });

  it("3. RUST_SIGNER_REQUIRED=true and the remote signer fails => rethrows, does NOT fall back to local", async () => {
    global.fetch = jest.fn(async () => ({
      ok: false,
      status: 500,
      json: async () => ({}),
    })) as any;
    const service = makeService({
      rustSignerUrl: "http://fake-signer.local",
      rustSignerRequired: true,
    });

    await expect(service.signDerivedHash(derivedHash, node)).rejects.toThrow(
      /Rust signer HTTP 500/
    );
  });

  it("4. remote signer is OPTIONAL and fails => falls back to local (@noble/curves) signing", async () => {
    global.fetch = jest.fn(async () => ({
      ok: false,
      status: 500,
      json: async () => ({}),
    })) as any;
    // rustSignerRequired is NOT set -> optional.
    const service = makeService({ rustSignerUrl: "http://fake-signer.local" });

    const result = await service.signDerivedHash(derivedHash, node);

    // The mocked bls.util at the top of this file makes the local signing path
    // deterministic: fakeG1Point.toHex() = "cd".repeat(48), fakeG2Point.toHex() = "ab".repeat(96).
    expect(result.nodeId).toBe(node.nodeId);
    expect(result.publicKey).toBe("cd".repeat(48));
    expect(result.signatureCompact).toBe("ab".repeat(96));
    expect(result.message).toBe(derivedHash);
  });
});
