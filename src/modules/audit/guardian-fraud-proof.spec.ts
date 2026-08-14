import { ethers } from "ethers";
import {
  decodeSignerMask,
  deriveFraudProofId,
  overIssueEvidenceHash,
  encodeOverIssueFraudProof,
  FRAUD_ID_TAG,
  OVERISSUE_EVIDENCE_TAG,
  OverIssueFraudProofInputs,
} from "./guardian-fraud-proof.js";

const coder = ethers.AbiCoder.defaultAbiCoder();

const S1 = ethers.getAddress("0x0000000000000000000000000000000000001111");
const S2 = ethers.getAddress("0x0000000000000000000000000000000000002222");
const S3 = ethers.getAddress("0x0000000000000000000000000000000000003333");
const OPERATOR = ethers.getAddress("0x000000000000000000000000000000000000abcd");
const TOKEN = ethers.getAddress("0x000000000000000000000000000000000000beef");

describe("guardian-fraud-proof encoding (CC-89 stage-2)", () => {
  it("decodeSignerMask reads the first word of abi.encode(mask, sigG2)", () => {
    const proof = coder.encode(["uint256", "bytes"], [0x7n, "0xdeadbeef"]);
    expect(decodeSignerMask(proof)).toBe(0x7n);
  });

  it("deriveFraudProofId is deterministic, id-bound, and matches the verifier's keccak", () => {
    const id = deriveFraudProofId(42n);
    // Same value the Solidity verifier computes: keccak256(abi.encode("GUARDIAN_FRAUD_V1", proposalId)).
    const expected = BigInt(ethers.keccak256(coder.encode(["string", "uint256"], [FRAUD_ID_TAG, 42n])));
    expect(id).toBe(expected);
    expect(deriveFraudProofId(42n)).toBe(id); // deterministic
    expect(deriveFraudProofId(43n)).not.toBe(id); // proposal-bound
    expect(id).toBeLessThan(1n << 256n); // valid uint256
  });

  it("overIssueEvidenceHash binds token/operator/epoch (fixed preimage)", () => {
    const h = overIssueEvidenceHash(TOKEN, OPERATOR, 1000n);
    const expected = ethers.keccak256(
      coder.encode(
        ["string", "address", "address", "uint256"],
        [OVERISSUE_EVIDENCE_TAG, TOKEN, OPERATOR, 1000n]
      )
    );
    expect(h).toBe(expected);
    // token swap ⇒ different hash (this is what closes the Codex Critical on-chain).
    const other = ethers.getAddress("0x000000000000000000000000000000000000c0de");
    expect(overIssueEvidenceHash(other, OPERATOR, 1000n)).not.toBe(h);
  });

  it("encodeOverIssueFraudProof round-trips through the verifier's decode shape", () => {
    const inputs: OverIssueFraudProofInputs = {
      proposalId: 42n,
      operator: OPERATOR,
      slashLevel: 2,
      epoch: 1000n,
      disputedToken: TOKEN,
      signerMask: 0x7n,
      claimedSigners: [S1, S2, S3],
    };
    const bytes = encodeOverIssueFraudProof(inputs);
    const [proposalId, operator, slashLevel, epoch, disputedToken, signerMask, claimedSigners] = coder.decode(
      ["uint256", "address", "uint8", "uint256", "address", "uint256", "address[]"],
      bytes
    );
    expect(BigInt(proposalId)).toBe(42n);
    expect(operator).toBe(OPERATOR);
    expect(Number(slashLevel)).toBe(2);
    expect(BigInt(epoch)).toBe(1000n);
    expect(disputedToken).toBe(TOKEN);
    expect(BigInt(signerMask)).toBe(0x7n);
    expect([...claimedSigners]).toEqual([S1, S2, S3]);
  });
});
