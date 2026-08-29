import { ethers } from "ethers";
import {
  assembleOverIssueFraudProof,
  executeGuardianSlash,
  preflightVerify,
  queueGuardianSlash,
  AssembledFraudProof,
} from "./guardian-fraud-proof-assembler.js";
import {
  overIssueEvidenceHash,
  deriveFraudProofId,
  encodeOverIssueFraudProof,
} from "./guardian-fraud-proof.js";
import type { GuardianSignerRecord } from "./guardian-signer-store.js";

const S1 = ethers.getAddress("0x0000000000000000000000000000000000001111");
const S2 = ethers.getAddress("0x0000000000000000000000000000000000002222");
const S3 = ethers.getAddress("0x0000000000000000000000000000000000003333");
const OPERATOR = ethers.getAddress("0x000000000000000000000000000000000000abcd");
const TOKEN = ethers.getAddress("0x000000000000000000000000000000000000beef");
const EPOCH = 1000n;

const verifiedRecord = (over?: Partial<GuardianSignerRecord>): GuardianSignerRecord => ({
  proposalId: "42",
  operator: OPERATOR,
  slashLevel: 2,
  epoch: EPOCH.toString(),
  evidenceHash: overIssueEvidenceHash(TOKEN, OPERATOR, EPOCH), // binds TOKEN
  signerMask: "7",
  claimedSigners: [S1, S2, S3],
  executionBlock: 500,
  txHash: "0x" + "ab".repeat(32),
  chainId: "11155111",
  commitment: "0x" + "22".repeat(32),
  commitmentVerified: true,
  executionBlockTimestamp: 1_700_000_000,
  ...over,
});

describe("guardian-fraud-proof assembler (CC-89 stage-2 F2)", () => {
  it("assembles a fraudProof the verifier will accept from a verified record", () => {
    const out = assembleOverIssueFraudProof(verifiedRecord(), TOKEN);
    expect(out.fraudProofId).toBe(deriveFraudProofId(42n));
    expect(out.guiltyGuardians).toEqual([S1, S2, S3]); // exact committed signer set
    // fraudProof matches the exact encoding the verifier decodes.
    expect(out.fraudProof).toBe(
      encodeOverIssueFraudProof({
        proposalId: 42n,
        operator: OPERATOR,
        slashLevel: 2,
        epoch: EPOCH,
        disputedToken: TOKEN,
        signerMask: 0x7n,
        claimedSigners: [S1, S2, S3],
      })
    );
  });

  it("REFUSES an unverified record (never assemble from a non-self-checked set)", () => {
    expect(() =>
      assembleOverIssueFraudProof(verifiedRecord({ commitmentVerified: false }), TOKEN)
    ).toThrow(/not self-verified/);
  });

  it("REFUSES a truthy-but-not-true commitmentVerified (strict === true gate)", () => {
    expect(() =>
      assembleOverIssueFraudProof(
        verifiedRecord({ commitmentVerified: "false" as unknown as boolean }),
        TOKEN
      )
    ).toThrow(/not self-verified/);
  });

  it("REFUSES a corrupt record whose claimedSigners are not canonical (unsorted)", () => {
    expect(() =>
      assembleOverIssueFraudProof(verifiedRecord({ claimedSigners: [S2, S1, S3] }), TOKEN)
    ).toThrow(/not strictly ascending/);
  });

  it("REFUSES a corrupt record with duplicate claimedSigners", () => {
    expect(() =>
      assembleOverIssueFraudProof(verifiedRecord({ claimedSigners: [S1, S1] }), TOKEN)
    ).toThrow(/not strictly ascending/);
  });

  it("REFUSES a corrupt record with a zero-address claimed signer", () => {
    expect(() =>
      assembleOverIssueFraudProof(
        verifiedRecord({ claimedSigners: [ethers.ZeroAddress, S1] }),
        TOKEN
      )
    ).toThrow(/zero address/);
  });

  it("REFUSES a corrupt record with too many claimedSigners (> MAX_VALIDATORS)", () => {
    const many = Array.from({ length: 14 }, (_, i) =>
      ethers.getAddress("0x" + (i + 1).toString(16).padStart(40, "0"))
    );
    expect(() =>
      assembleOverIssueFraudProof(verifiedRecord({ claimedSigners: many }), TOKEN)
    ).toThrow(/exceeds MAX/);
  });

  it("REFUSES a token that does not bind to the slash (token-swap guard)", () => {
    const wrongToken = ethers.getAddress("0x000000000000000000000000000000000000c0de");
    expect(() => assembleOverIssueFraudProof(verifiedRecord(), wrongToken)).toThrow(
      /does not bind/
    );
  });

  describe("preflightVerify", () => {
    const verifierIface = new ethers.Interface([
      "function verify(bytes32 domainDigest, uint256 fraudProofId, address[] guiltyGuardians, bytes fraudProof) view returns (bool)",
    ]);
    const aggregatorIface = new ethers.Interface([
      "function fraudProofDigest(uint256 fraudProofId, address[] guiltyGuardians) view returns (bytes32)",
    ]);
    const assembled: AssembledFraudProof = assembleOverIssueFraudProof(verifiedRecord(), TOKEN);
    const domainDigest = ethers.keccak256(ethers.toUtf8Bytes("SP 4.11 domain-bound preflight"));

    const mockProvider = (result: boolean) =>
      ({
        provider: null as any,
        resolveName: async (n: string) => n,
        call: async (tx: { to?: string; data?: string }) => {
          const selector = tx.data?.slice(0, 10);
          if (selector === aggregatorIface.getFunction("fraudProofDigest")!.selector) {
            expect(tx.to).toBe(S2);
            return aggregatorIface.encodeFunctionResult("fraudProofDigest", [domainDigest]);
          }
          if (selector === verifierIface.getFunction("verify")!.selector) {
            expect(tx.to).toBe(S3);
            const decoded = verifierIface.decodeFunctionData("verify", tx.data!);
            expect(decoded.domainDigest).toBe(domainDigest);
            expect(decoded.guiltyGuardians).toEqual([S1, S2, S3]);
            return verifierIface.encodeFunctionResult("verify", [result]);
          }
          throw new Error(`unexpected selector ${selector}`);
        },
      }) as unknown as ethers.Provider;

    it("uses SP 4.11's domain-bound four-parameter selector", () => {
      expect(verifierIface.getFunction("verify")!.selector).toBe("0x61077735");
    });

    it("returns true when the on-chain verifier accepts", async () => {
      expect(await preflightVerify(mockProvider(true), S3, S2, assembled)).toBe(true);
    });

    it("returns false when the on-chain verifier rejects (no throw)", async () => {
      expect(await preflightVerify(mockProvider(false), S3, S2, assembled)).toBe(false);
    });
  });

  describe("SP 4.11 queue/execute lifecycle", () => {
    const aggregatorIface = new ethers.Interface([
      "function queueGuardianSlash(uint256 fraudProofId, address[] guiltyGuardians, bytes fraudProof)",
      "function executeGuardianSlash(uint256 fraudProofId, address[] guiltyGuardians, bytes fraudProof)",
    ]);
    const assembled: AssembledFraudProof = assembleOverIssueFraudProof(verifiedRecord(), TOKEN);
    const txHash = "0x" + "cd".repeat(32);

    const mockSigner = (calls: Array<{ to?: string; data?: string }>) =>
      ({
        provider: null,
        resolveName: async (n: string) => n,
        sendTransaction: async (tx: { to?: string; data?: string }) => {
          calls.push(tx);
          return { hash: txHash };
        },
      }) as unknown as ethers.Signer;

    it("queues the exact set before execution", async () => {
      const calls: Array<{ to?: string; data?: string }> = [];
      expect(await queueGuardianSlash(mockSigner(calls), S2, assembled)).toBe(txHash);
      expect(calls).toHaveLength(1);
      const decoded = aggregatorIface.decodeFunctionData("queueGuardianSlash", calls[0].data!);
      expect(decoded.fraudProofId).toBe(assembled.fraudProofId);
      expect(decoded.guiltyGuardians).toEqual([S1, S2, S3]);
      expect(decoded.fraudProof).toBe(assembled.fraudProof);
    });

    it("executes with the identical queued set and proof", async () => {
      const calls: Array<{ to?: string; data?: string }> = [];
      expect(await executeGuardianSlash(mockSigner(calls), S2, assembled)).toBe(txHash);
      expect(calls).toHaveLength(1);
      const decoded = aggregatorIface.decodeFunctionData("executeGuardianSlash", calls[0].data!);
      expect(decoded.fraudProofId).toBe(assembled.fraudProofId);
      expect(decoded.guiltyGuardians).toEqual([S1, S2, S3]);
      expect(decoded.fraudProof).toBe(assembled.fraudProof);
    });
  });
});
