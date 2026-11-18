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
  OVERISSUE_CATEGORY,
  overIssueEvidence,
  OverIssueFraudProofInputs,
} from "./guardian-fraud-proof.js";

const coder = ethers.AbiCoder.defaultAbiCoder();

const S1 = ethers.getAddress("0x0000000000000000000000000000000000001111");
const S2 = ethers.getAddress("0x0000000000000000000000000000000000002222");
const S3 = ethers.getAddress("0x0000000000000000000000000000000000003333");
const OPERATOR = ethers.getAddress("0x000000000000000000000000000000000000abcd");
const TOKEN = ethers.getAddress("0x000000000000000000000000000000000000beef");
// blockhash(executionBlock - 1) in the fixtures (#441, SP BLSAggregator-4.14.0 commitment layout).
const PARENT = "0x" + "5a".repeat(32);

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

  it("overIssueEvidenceHash binds token/operator/epoch (M0 §3.1 category rule)", () => {
    const h = overIssueEvidenceHash(TOKEN, OPERATOR, 1000n);
    const body = coder.encode(["address", "address", "uint256"], [TOKEN, OPERATOR, 1000n]);
    const expected = ethers.keccak256(
      coder.encode(
        ["bytes32", "bytes32", "bytes32"],
        [
          ethers.id("SuperPaymaster.DVT.Evidence.v2"),
          ethers.id("DVT.Evidence.OverIssue.v1"),
          ethers.keccak256(body),
        ]
      )
    );
    expect(h).toBe(expected);
    expect(OVERISSUE_CATEGORY).toBe(ethers.id("DVT.Evidence.OverIssue.v1"));
    // the evidence bytes decode to (category, body), as DVTValidator-0.9.0 decodes them
    const [c, b] = coder.decode(["bytes32", "bytes"], overIssueEvidence(TOKEN, OPERATOR, 1000n));
    expect(c).toBe(OVERISSUE_CATEGORY);
    expect(ethers.hexlify(b)).toBe(body);
    // the 2.0.0 pre-image no longer matches
    expect(h).not.toBe(
      ethers.keccak256(
        coder.encode(
          ["string", "address", "address", "uint256"],
          ["DVT_OVERISSUE_EVIDENCE_V1", TOKEN, OPERATOR, 1000n]
        )
      )
    );
    const other = ethers.getAddress("0x000000000000000000000000000000000000c0de");
    expect(overIssueEvidenceHash(other, OPERATOR, 1000n)).not.toBe(h);
  });

  it("encodeOverIssueFraudProof refuses a zero or malformed parentBlockHash", () => {
    const base: OverIssueFraudProofInputs = {
      proposalId: 42n,
      operator: OPERATOR,
      slashLevel: 2,
      epoch: 1000n,
      disputedToken: TOKEN,
      signerMask: 0x7n,
      claimedSigners: [S1, S2, S3],
      parentBlockHash: PARENT,
    };
    for (const bad of ["0x" + "00".repeat(32), "0x1234", "", "0x" + "zz".repeat(32)]) {
      expect(() => encodeOverIssueFraudProof({ ...base, parentBlockHash: bad })).toThrow(
        /non-zero bytes32/
      );
    }
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
      parentBlockHash: PARENT,
    };
    const bytes = encodeOverIssueFraudProof(inputs);
    const [
      proposalId,
      operator,
      slashLevel,
      epoch,
      disputedToken,
      signerMask,
      claimedSigners,
      parentBlockHash,
    ] = coder.decode(
      ["uint256", "address", "uint8", "uint256", "address", "uint256", "address[]", "bytes32"],
      bytes
    );
    expect(parentBlockHash).toBe(PARENT);
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

    it("rejects a signerMask with bits above MAX_VALIDATORS (slot 64)", async () => {
      await expect(orderSignersFromSlotMap(1n << 64n, resolver)).rejects.toThrow(
        /bits above slot 64/
      );
    });

    it("accepts slots 14 and 64 (SP MAX_VALIDATORS is 64, not 13; clestons #468)", async () => {
      const hi: Record<number, string> = { 14: S3, 64: S2 };
      const hiResolver = (slot: number) => Promise.resolve(hi[slot] ?? ethers.ZeroAddress);
      // bit 13 ⇔ slot 14, bit 63 ⇔ slot 64
      expect(await orderSignersFromSlotMap((1n << 13n) | (1n << 63n), hiResolver)).toEqual([
        S2,
        S3,
      ]);
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
    // #441: the 4.14.0 layout appends blockhash(executionBlock - 1). Golden recomputed independently
    // with `cast abi-encode` + `cast keccak` (the same method reproduces the old 4.11 golden
    // 0xb35d1e5b…, which is how the method was checked).
    const commitment = computeSignersCommitment(DOMAIN, 42n, mh, 0x7n, [S1, S2, S3], PARENT);
    // Verifier 3.0.0 evidence rule (OverIssue.v1); recomputed with cast, which reproduces 2.0.0's
    // 0x7e794aa9… / 0xc625f313… with the old pre-image.
    expect(mh).toBe("0xbb533ecaa9492a031d8b2cedf23bd7ac1728776e03e86332efdaf50da1dd84d6");
    expect(commitment).toBe("0x5b15a0d0e5ab230f8accd36c14a9878f4acb351b38d96ad3bfbf20a86d0e5d06");
  });
});
