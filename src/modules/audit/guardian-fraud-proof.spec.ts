import { ethers } from "ethers";
import {
  decodeSignerMaskFromBlsProof,
  deriveFraudProofId,
  overIssueEvidenceHash,
  overIssueSlashMessageHash,
  computeSignersCommitment,
  encodeOverIssueFraudProof,
  orderSignersFromSlotMap,
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
  it("decodeSignerMaskFromBlsProof reads the first word of abi.encode(mask, sigG2)", () => {
    const proof = coder.encode(["uint256", "bytes"], [0x7n, "0xdeadbeef"]);
    expect(decodeSignerMaskFromBlsProof(proof)).toBe(0x7n);
  });

  it("deriveFraudProofId is deterministic, id-bound, and matches the verifier's keccak", () => {
    const id = deriveFraudProofId(42n);
    const expected = BigInt(
      ethers.keccak256(coder.encode(["string", "uint256"], [FRAUD_ID_TAG, 42n]))
    );
    expect(id).toBe(expected);
    expect(deriveFraudProofId(42n)).toBe(id);
    expect(deriveFraudProofId(43n)).not.toBe(id);
    expect(id).toBeLessThan(1n << 256n);
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
    const [proposalId, operator, slashLevel, epoch, disputedToken, signerMask, claimedSigners] =
      coder.decode(
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

  describe("orderSignersFromSlotMap (byte-critical derivation)", () => {
    // slot→address map returning an already-scrambled order to prove the ascending sort.
    const slotMap: Record<number, string> = { 1: S3, 2: S1, 3: S2 };
    const resolver = (slot: number) => Promise.resolve(slotMap[slot] ?? ethers.ZeroAddress);

    it("maps set bits to 1-indexed slots and sorts ascending by uint160", async () => {
      // mask 0x7 = bits 0,1,2 → slots 1,2,3 → [S3,S1,S2] → sorted [S1,S2,S3]
      expect(await orderSignersFromSlotMap(0x7n, resolver)).toEqual([S1, S2, S3]);
    });

    it("selects only the set slots (bit i ⇔ slot i+1)", async () => {
      // mask 0x5 = bits 0,2 → slots 1,3 → [S3,S2] → sorted [S2,S3]
      expect(await orderSignersFromSlotMap(0x5n, resolver)).toEqual([S2, S3]);
    });

    it("rejects a signerMask with bits above MAX_VALIDATORS (slot 13)", async () => {
      await expect(orderSignersFromSlotMap(1n << 13n, resolver)).rejects.toThrow(
        /bits above slot 13/
      );
    });

    it("rejects a zero-address slot (partial/wrong set)", async () => {
      // mask 0xF = slots 1..4, but slot 4 is unset in the map → zero → throw
      await expect(orderSignersFromSlotMap(0xfn, resolver)).rejects.toThrow(/is zero/);
    });
  });

  it("computeSignersCommitment matches a golden vector (TS↔Solidity byte-alignment)", () => {
    // Same fixed vector asserted in the Foundry test (OverIssueFraudProofVerifier.t.sol golden test):
    // chainId=1, aggregator=0x…0A99, proposalId=42, operator=…abcd, slashLevel=2, epoch=1000,
    // token=…beef, signerMask=0x7, claimedSigners=[S1,S2,S3]. If ethers and Solidity abi.encode
    // ever diverge for these types, this hex changes and both suites break.
    const AGG = ethers.getAddress("0x0000000000000000000000000000000000000a99");
    const mh = overIssueSlashMessageHash(1n, 42n, OPERATOR, 2, 1000n, TOKEN);
    const commitment = computeSignersCommitment(AGG, 1n, 42n, mh, 0x7n, [S1, S2, S3]);
    expect(mh).toBe("0x593a53c8408d4f89674782c8cf0d3d2b3def99ac442ee6431f64e05965c50a46");
    expect(commitment).toBe("0x8c38195124813c84cddbf33daca3efbb3f4718ba43167e6b30550229693f6588");
  });
});
