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
import type { NodeKeyPair } from "../../interfaces/node.interface.js";

/**
 * Fix 2 Stage 1 — owner-authorization gate tests.
 *
 * Verifies that the DVT node co-signs ONLY when the request carries a valid
 * account-owner ECDSA signature (EIP-191) over the userOpHash, matching the
 * v0.18 account's `_validateECDSA` convention. BlockchainService.getAccountOwner
 * is mocked so no chain access is needed.
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

  const account = "0x08923CE682336DF2f238C034B4add5Bf73d4028A";
  // userOpHash to be co-signed.
  const userOpHash = "0x8bb1b199f427dfc49e5fe40f2f3278cb1a48587824b78263051c8c4d81d77a81";

  // The account owner (EOA). The contract recovers an EIP-191 sig over userOpHash
  // and compares to `owner`. We reproduce the same with ethers.
  const ownerWallet = new ethers.Wallet(
    "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
  );

  let service: InstanceType<typeof BlsService>;
  let getAccountOwner: jest.Mock<(account: string) => Promise<string>>;

  // Sign userOpHash exactly the way the account owner signs the UserOperation:
  // EIP-191 prefix over the raw 32-byte hash.
  async function signAsOwner(wallet: ethers.Wallet, hash: string): Promise<string> {
    return wallet.signMessage(ethers.getBytes(hash));
  }

  beforeEach(() => {
    getAccountOwner = jest.fn<(account: string) => Promise<string>>();
    const blockchain = { getAccountOwner } as unknown as BlockchainService;
    service = new BlsService(blockchain);
  });

  it("signs and returns a signature when ownerAuth recovers to the on-chain owner", async () => {
    getAccountOwner.mockResolvedValue(ownerWallet.address);
    const ownerAuth = await signAsOwner(ownerWallet, userOpHash);

    const result = await service.signMessage(userOpHash, account, ownerAuth, node);

    expect(getAccountOwner).toHaveBeenCalledWith(account);
    expect(result.nodeId).toBe(node.nodeId);
    expect(result.signature).toMatch(/^0x[0-9a-f]+$/);
    expect(result.signatureCompact).toBeTruthy();
    expect(result.message).toBe(userOpHash);
  });

  it("rejects (403) when ownerAuth is signed by the wrong signer", async () => {
    getAccountOwner.mockResolvedValue(ownerWallet.address);
    const attacker = ethers.Wallet.createRandom();
    const ownerAuth = await signAsOwner(attacker as unknown as ethers.Wallet, userOpHash);

    await expect(service.signMessage(userOpHash, account, ownerAuth, node)).rejects.toBeInstanceOf(
      ForbiddenException
    );
  });

  it("rejects (403) when ownerAuth is over a tampered userOpHash", async () => {
    getAccountOwner.mockResolvedValue(ownerWallet.address);
    const otherHash = "0x" + "11".repeat(32);
    // Owner signed a different hash than the one being requested.
    const ownerAuth = await signAsOwner(ownerWallet, otherHash);

    await expect(service.signMessage(userOpHash, account, ownerAuth, node)).rejects.toBeInstanceOf(
      ForbiddenException
    );
  });

  it("rejects (403) when ownerAuth is malformed / not a real signature", async () => {
    getAccountOwner.mockResolvedValue(ownerWallet.address);
    const ownerAuth = "0xdeadbeef";

    await expect(service.signMessage(userOpHash, account, ownerAuth, node)).rejects.toBeInstanceOf(
      ForbiddenException
    );
  });

  it("rejects (403) fail-closed for a P256/passkey-only account (owner == zero address)", async () => {
    getAccountOwner.mockResolvedValue(ethers.ZeroAddress);
    const ownerAuth = await signAsOwner(ownerWallet, userOpHash);

    await expect(service.signMessage(userOpHash, account, ownerAuth, node)).rejects.toBeInstanceOf(
      ForbiddenException
    );
  });

  it("rejects (403) fail-closed when the on-chain owner read fails", async () => {
    getAccountOwner.mockRejectedValue(new Error("rpc down"));
    const ownerAuth = await signAsOwner(ownerWallet, userOpHash);

    await expect(service.signMessage(userOpHash, account, ownerAuth, node)).rejects.toBeInstanceOf(
      ForbiddenException
    );
  });

  it("matches owner regardless of address checksum casing", async () => {
    // Chain read returns lowercase; gate must still match.
    getAccountOwner.mockResolvedValue(ethers.getAddress(ownerWallet.address));
    const ownerAuth = await signAsOwner(ownerWallet, userOpHash);

    const result = await service.signMessage(userOpHash, account, ownerAuth, node);
    expect(result.nodeId).toBe(node.nodeId);
  });
});
