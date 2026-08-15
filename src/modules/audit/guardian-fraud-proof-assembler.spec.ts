import { ethers } from "ethers";
import {
  assembleOverIssueFraudProof,
  preflightVerify,
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
const OUTSIDER = ethers.getAddress("0x0000000000000000000000000000000000009999");
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
    const out = assembleOverIssueFraudProof(verifiedRecord(), TOKEN, [S2, S1]); // unsorted input
    expect(out.fraudProofId).toBe(deriveFraudProofId(42n));
    expect(out.guiltyGuardians).toEqual([S1, S2]); // canonicalized ascending
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
      assembleOverIssueFraudProof(verifiedRecord({ commitmentVerified: false }), TOKEN, [S1])
    ).toThrow(/not self-verified/);
  });

  it("REFUSES a truthy-but-not-true commitmentVerified (strict === true gate)", () => {
    expect(() =>
      assembleOverIssueFraudProof(
        verifiedRecord({ commitmentVerified: "false" as unknown as boolean }),
        TOKEN,
        [S1]
      )
    ).toThrow(/not self-verified/);
  });

  it("REFUSES a corrupt record whose claimedSigners are not canonical (unsorted)", () => {
    expect(() =>
      assembleOverIssueFraudProof(verifiedRecord({ claimedSigners: [S2, S1, S3] }), TOKEN, [S1])
    ).toThrow(/not strictly ascending/);
  });

  it("REFUSES a corrupt record with duplicate claimedSigners", () => {
    expect(() =>
      assembleOverIssueFraudProof(verifiedRecord({ claimedSigners: [S1, S1] }), TOKEN, [S1])
    ).toThrow(/not strictly ascending/);
  });

  it("REFUSES a corrupt record with a zero-address claimed signer", () => {
    expect(() =>
      assembleOverIssueFraudProof(
        verifiedRecord({ claimedSigners: [ethers.ZeroAddress, S1] }),
        TOKEN,
        [S1]
      )
    ).toThrow(/zero address/);
  });

  it("REFUSES a corrupt record with too many claimedSigners (> MAX_VALIDATORS)", () => {
    const many = Array.from({ length: 14 }, (_, i) =>
      ethers.getAddress("0x" + (i + 1).toString(16).padStart(40, "0"))
    );
    expect(() =>
      assembleOverIssueFraudProof(verifiedRecord({ claimedSigners: many }), TOKEN, [many[0]])
    ).toThrow(/exceeds MAX/);
  });

  it("REFUSES a token that does not bind to the slash (token-swap guard)", () => {
    const wrongToken = ethers.getAddress("0x000000000000000000000000000000000000c0de");
    expect(() => assembleOverIssueFraudProof(verifiedRecord(), wrongToken, [S1])).toThrow(
      /does not bind/
    );
  });

  it("REFUSES guilty guardians not ⊆ claimedSigners (cannot slash an innocent address)", () => {
    expect(() => assembleOverIssueFraudProof(verifiedRecord(), TOKEN, [OUTSIDER])).toThrow(
      /not among the slash's signers/
    );
  });

  it("REFUSES an empty guilty set", () => {
    expect(() => assembleOverIssueFraudProof(verifiedRecord(), TOKEN, [])).toThrow(/empty/);
  });

  it("REFUSES a zero address in the guilty set", () => {
    expect(() =>
      assembleOverIssueFraudProof(verifiedRecord(), TOKEN, [ethers.ZeroAddress, S1])
    ).toThrow(/zero address/);
  });

  it("REFUSES a duplicate in the guilty set", () => {
    expect(() => assembleOverIssueFraudProof(verifiedRecord(), TOKEN, [S1, S1])).toThrow(
      /duplicate/
    );
  });

  describe("preflightVerify", () => {
    const iface = new ethers.Interface([
      "function verify(uint256 fraudProofId, address[] guiltyGuardians, bytes fraudProof) view returns (bool)",
    ]);
    const assembled: AssembledFraudProof = assembleOverIssueFraudProof(verifiedRecord(), TOKEN, [
      S1,
    ]);

    const mockProvider = (result: boolean) =>
      ({
        provider: null as any,
        resolveName: async (n: string) => n,
        call: async () => iface.encodeFunctionResult("verify", [result]),
      }) as unknown as ethers.Provider;

    it("returns true when the on-chain verifier accepts", async () => {
      expect(await preflightVerify(mockProvider(true), S3, assembled)).toBe(true);
    });

    it("returns false when the on-chain verifier rejects (no throw)", async () => {
      expect(await preflightVerify(mockProvider(false), S3, assembled)).toBe(false);
    });
  });
});
