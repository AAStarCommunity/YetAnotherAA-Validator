import { ethers } from "ethers";
import {
  SlashLevel,
  QUEUE_SLASH_TAG,
  MAX_VALIDATORS,
  PendingSlotCoSigner,
  CoSignRequest,
  buildQueueMessageHash,
  buildExecuteMessageHash,
  buildSignerMask,
  recomputeMessageHash,
  encodeProof,
} from "./slash-consensus.js";

const OPERATOR = ethers.getAddress("0x" + "12".repeat(20));
const EVIDENCE_HASH = "0x" + "cd".repeat(32);
const CHAIN_ID = 11155111;

describe("slash-consensus primitives (SP #329)", () => {
  it('QUEUE_SLASH_TAG is keccak256 of the UTF-8 literal, matching Solidity keccak256("QUEUE_SLASH")', () => {
    expect(QUEUE_SLASH_TAG).toBe(ethers.keccak256(ethers.toUtf8Bytes("QUEUE_SLASH")));
  });

  it("SlashLevel enum matches the on-chain values (WARNING=0, MINOR=1, MAJOR=2)", () => {
    expect(SlashLevel.WARNING).toBe(0);
    expect(SlashLevel.MINOR).toBe(1);
    expect(SlashLevel.MAJOR).toBe(2);
  });

  it("buildQueueMessageHash byte-matches a hand-computed 5-field AbiCoder reference (with domain tag)", () => {
    const epoch = 1_700_000;
    const slashLevel = SlashLevel.MINOR;
    const reference = ethers.keccak256(
      new ethers.AbiCoder().encode(
        ["bytes32", "address", "uint8", "uint256", "uint256"],
        [ethers.keccak256(ethers.toUtf8Bytes("QUEUE_SLASH")), OPERATOR, slashLevel, epoch, CHAIN_ID]
      )
    );
    expect(buildQueueMessageHash(OPERATOR, slashLevel, epoch, CHAIN_ID)).toBe(reference);
    expect(reference).toMatch(/^0x[0-9a-f]{64}$/);
  });

  it("buildExecuteMessageHash byte-matches a hand-computed 8-field reference (empty rep arrays + evidenceHash)", () => {
    const proposalId = 42n;
    const epoch = 1_700_000;
    const slashLevel = SlashLevel.MINOR;
    const reference = ethers.keccak256(
      new ethers.AbiCoder().encode(
        ["uint256", "address", "uint8", "address[]", "uint256[]", "uint256", "uint256", "bytes32"],
        [proposalId, OPERATOR, slashLevel, [], [], epoch, CHAIN_ID, EVIDENCE_HASH]
      )
    );
    expect(
      buildExecuteMessageHash(proposalId, OPERATOR, slashLevel, epoch, CHAIN_ID, EVIDENCE_HASH)
    ).toBe(reference);
    expect(reference).toMatch(/^0x[0-9a-f]{64}$/);
  });

  it("the queue and execute preimages are distinct (domain separation holds)", () => {
    const epoch = 1_700_000;
    const queue = buildQueueMessageHash(OPERATOR, SlashLevel.MINOR, epoch, CHAIN_ID);
    const exec = buildExecuteMessageHash(
      1n,
      OPERATOR,
      SlashLevel.MINOR,
      epoch,
      CHAIN_ID,
      EVIDENCE_HASH
    );
    expect(queue).not.toBe(exec);
  });

  it("buildExecuteMessageHash is sensitive to evidenceHash (evidence binding is real)", () => {
    const a = buildExecuteMessageHash(1n, OPERATOR, 1, 5, CHAIN_ID, "0x" + "11".repeat(32));
    const b = buildExecuteMessageHash(1n, OPERATOR, 1, 5, CHAIN_ID, "0x" + "22".repeat(32));
    expect(a).not.toBe(b);
  });

  it("encodeProof produces abi.encode(uint256 signerMask, bytes sigG2) and round-trips", () => {
    const signerMask = 0b101n;
    const sigG2 = "0x" + "ab".repeat(64);
    const encoded = encodeProof(signerMask, sigG2);
    // Matches a direct AbiCoder reference.
    expect(encoded).toBe(new ethers.AbiCoder().encode(["uint256", "bytes"], [signerMask, sigG2]));
    // And decodes back to the same values.
    const [mask, sig] = new ethers.AbiCoder().decode(["uint256", "bytes"], encoded);
    expect(mask).toBe(signerMask);
    expect(sig).toBe(sigG2);
  });

  it("PendingSlotCoSigner fails closed: coSign(req) throws the disarmed error", async () => {
    const coSigner = new PendingSlotCoSigner();
    const req: CoSignRequest = {
      step: "queue",
      operator: OPERATOR,
      slashLevel: SlashLevel.MINOR,
      epoch: 1,
      chainId: CHAIN_ID,
      messageHash: "0x" + "00".repeat(32),
    };
    await expect(coSigner.coSign(req)).rejects.toThrow(/quorum co-sign deferred.*disarmed/s);
  });

  // ── buildSignerMask: PINNED bit convention (slot s → bit s-1) ────────────────────
  describe("buildSignerMask (slot s → bit s-1)", () => {
    it("matches the pinned reference values", () => {
      expect(buildSignerMask([1, 2, 3])).toBe(7n);
      expect(buildSignerMask([1, 2])).toBe(3n);
      expect(buildSignerMask([1, 3])).toBe(5n);
      expect(buildSignerMask([2, 3])).toBe(6n);
      expect(buildSignerMask([1])).toBe(1n);
      expect(buildSignerMask([13])).toBe(1n << 12n);
    });

    it("is order-independent and de-duplicates slots", () => {
      expect(buildSignerMask([3, 1, 2])).toBe(7n);
      expect(buildSignerMask([2, 2, 3, 3, 1])).toBe(7n);
    });

    it("empty slot list → 0n", () => {
      expect(buildSignerMask([])).toBe(0n);
    });

    it("rejects slot <= 0", () => {
      expect(() => buildSignerMask([0])).toThrow(/out of range/);
      expect(() => buildSignerMask([-1])).toThrow(/out of range/);
    });

    it(`rejects slot > MAX_VALIDATORS (${MAX_VALIDATORS})`, () => {
      expect(() => buildSignerMask([MAX_VALIDATORS + 1])).toThrow(/out of range/);
      expect(() => buildSignerMask([1, 2, 99])).toThrow(/out of range/);
    });

    it("rejects a non-integer slot", () => {
      expect(() => buildSignerMask([1.5])).toThrow(/out of range/);
    });
  });

  // ── recomputeMessageHash: ONE code path for requester + responders ───────────────
  describe("recomputeMessageHash", () => {
    it("queue step === buildQueueMessageHash", () => {
      const req: CoSignRequest = {
        step: "queue",
        operator: OPERATOR,
        slashLevel: SlashLevel.MINOR,
        epoch: 1_700_000,
        chainId: CHAIN_ID,
        evidenceHash: EVIDENCE_HASH,
        messageHash: "0x00",
      };
      expect(recomputeMessageHash(req)).toBe(
        buildQueueMessageHash(OPERATOR, SlashLevel.MINOR, 1_700_000, CHAIN_ID)
      );
    });

    it("execute step === buildExecuteMessageHash", () => {
      const req: CoSignRequest = {
        step: "execute",
        operator: OPERATOR,
        slashLevel: SlashLevel.MINOR,
        epoch: 1_700_000,
        chainId: CHAIN_ID,
        proposalId: "42",
        evidenceHash: EVIDENCE_HASH,
        messageHash: "0x00",
      };
      expect(recomputeMessageHash(req)).toBe(
        buildExecuteMessageHash(42n, OPERATOR, SlashLevel.MINOR, 1_700_000, CHAIN_ID, EVIDENCE_HASH)
      );
    });

    it("execute step without proposalId → throws", () => {
      const req: CoSignRequest = {
        step: "execute",
        operator: OPERATOR,
        slashLevel: SlashLevel.MINOR,
        epoch: 1,
        chainId: CHAIN_ID,
        evidenceHash: EVIDENCE_HASH,
        messageHash: "0x00",
      };
      expect(() => recomputeMessageHash(req)).toThrow(/proposalId/);
    });

    it("execute step without evidenceHash → throws", () => {
      const req: CoSignRequest = {
        step: "execute",
        operator: OPERATOR,
        slashLevel: SlashLevel.MINOR,
        epoch: 1,
        chainId: CHAIN_ID,
        proposalId: "7",
        messageHash: "0x00",
      };
      expect(() => recomputeMessageHash(req)).toThrow(/evidenceHash/);
    });
  });
});
