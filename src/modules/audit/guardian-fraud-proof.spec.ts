import { ethers } from "ethers";
import {
  decodeSignerMaskFromBlsProof,
  deriveFraudProofId,
  overIssueEvidenceHash,
  overIssueSlashMessageHash,
  rawSlashMessageHash,
  computeSignersCommitment,
  encodeOverIssueFraudProof,
  decodeVerifyAndExecuteCalldata,
  orderSignersFromSlotMap,
  VERIFY_AND_EXECUTE_ABI,
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

// Fixed BLS-consensus domain for the golden vector (mirrored in the Foundry test).
const DOMAIN = {
  chainId: 11155111n,
  aggregator: ethers.getAddress("0x00000000000000000000000000000000000000a9"),
  registry: ethers.getAddress("0x00000000000000000000000000000000000000b5"),
};

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

  it("overIssueSlashMessageHash == rawSlashMessageHash with the fixed-preimage evidenceHash", () => {
    const raw = rawSlashMessageHash(
      DOMAIN,
      42n,
      OPERATOR,
      2,
      1000n,
      overIssueEvidenceHash(TOKEN, OPERATOR, 1000n)
    );
    expect(overIssueSlashMessageHash(DOMAIN, 42n, OPERATOR, 2, 1000n, TOKEN)).toBe(raw);
  });

  describe("decodeVerifyAndExecuteCalldata (watcher calldata decode)", () => {
    const iface = new ethers.Interface([VERIFY_AND_EXECUTE_ABI]);
    const blsProof = coder.encode(["uint256", "bytes"], [0x7n, "0xdead"]);

    it("decodes a slash-only verifyAndExecute call into its signed fields + signerMask", () => {
      const evidenceHash = ethers.keccak256("0x1234");
      const data = iface.encodeFunctionData("verifyAndExecute", [
        42n,
        OPERATOR,
        2,
        [], // repUsers
        [], // newScores
        1000n,
        evidenceHash,
        blsProof,
      ]);
      const args = decodeVerifyAndExecuteCalldata(data);
      expect(args.proposalId).toBe(42n);
      expect(args.operator).toBe(OPERATOR);
      expect(args.slashLevel).toBe(2);
      expect(args.repUsers).toEqual([]);
      expect(args.newScores).toEqual([]);
      expect(args.epoch).toBe(1000n);
      expect(args.evidenceHash).toBe(evidenceHash);
      expect(args.signerMask).toBe(0x7n); // from proof[:32]
    });

    it("throws on a non-verifyAndExecute selector (guards against wrong/wrapped calls)", () => {
      expect(() => decodeVerifyAndExecuteCalldata("0xdeadbeef")).toThrow();
    });
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

  it("SP 4.11 slash message + signers commitment match a cross-language golden (TS↔Solidity)", () => {
    // CROSS-LANGUAGE PIN. The SAME fixed vector is asserted in the Foundry test
    // `test_Golden_CrossLanguage_SPLayout` (OverIssueFraudProofVerifier.t.sol): domain
    // {chainId=11155111, aggregator=0x…00A9, registry=0x…00B5}, proposalId=42, operator=…abcd,
    // slashLevel=2, epoch=1000, token=…beef, signerMask=0x7, claimedSigners=[S1,S2,S3]. If ethers
    // and Solidity abi.encode ever diverge for the SP 4.11 domain layout, this hex changes and BOTH
    // suites break — the contract↔TS drift guard the obsolete-format cutover had removed.
    const mh = overIssueSlashMessageHash(DOMAIN, 42n, OPERATOR, 2, 1000n, TOKEN);
    const commitment = computeSignersCommitment(DOMAIN, 42n, mh, 0x7n, [S1, S2, S3]);
    expect(mh).toBe("0x7e794aa98ce38cd7e22a456963f67a1a7de057e15ee261a62373af7516cb820d");
    expect(commitment).toBe("0xb35d1e5b965d5a628e796f584596cf57080b6b00f9c566226adf70990db15ad4");
  });
});
