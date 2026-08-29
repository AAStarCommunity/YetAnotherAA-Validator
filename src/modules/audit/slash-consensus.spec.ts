import { ethers } from "ethers";
import {
  SlashLevel,
  MAX_VALIDATORS,
  PendingSlotCoSigner,
  CoSignRequest,
  buildQueueMessageHash,
  buildExecuteMessageHash,
  buildSignerMask,
  recomputeMessageHash,
  encodeProof,
} from "./slash-consensus.js";
import type { BlsConsensusDomain } from "./bls-consensus-domain.js";
import { PROOF_SCHEMA_VERSION } from "./proof-archive.js";

const OPERATOR = ethers.getAddress("0x" + "12".repeat(20));
const EVIDENCE_HASH = "0x" + "cd".repeat(32);
const CHAIN_ID = 11155111;
const DOMAIN: BlsConsensusDomain = {
  chainId: BigInt(CHAIN_ID),
  aggregator: ethers.getAddress("0x" + "a9".repeat(20)),
  registry: ethers.getAddress("0x" + "b5".repeat(20)),
};

// SP 4.11 domain constants, recomputed inline (NOT imported from the helper) so these tests are an
// INDEPENDENT cross-check of the helper's encoding — mirrors BLSAggregator.sol:238/242/243/255.
const DOMAIN_NAME = ethers.id("SuperPaymaster.BLSConsensus.v1");
const TAG_QUEUE_SLASH = ethers.id("SuperPaymaster.BLS.QueueSlash.v1");
const TAG_EXECUTE_SLASH = ethers.id("SuperPaymaster.BLS.ExecuteSlash.v1");
const ABI = new ethers.AbiCoder();

function domSep(d: BlsConsensusDomain): string {
  return ethers.keccak256(
    ABI.encode(
      ["bytes32", "uint256", "address", "address"],
      [DOMAIN_NAME, d.chainId, d.aggregator, d.registry]
    )
  );
}

describe("slash-consensus primitives (SP 4.11 BLSAggregator)", () => {
  it("SlashLevel enum matches the on-chain values (WARNING=0, MINOR=1, MAJOR=2)", () => {
    expect(SlashLevel.WARNING).toBe(0);
    expect(SlashLevel.MINOR).toBe(1);
    expect(SlashLevel.MAJOR).toBe(2);
  });

  it("buildQueueMessageHash byte-matches the SP 4.11 domain-separated queue pre-image (:911)", () => {
    const epoch = 1_700_000;
    const slashLevel = SlashLevel.MINOR;
    const reference = ethers.keccak256(
      ABI.encode(
        ["bytes32", "bytes32", "address", "uint8", "uint256"],
        [domSep(DOMAIN), TAG_QUEUE_SLASH, OPERATOR, slashLevel, epoch]
      )
    );
    expect(buildQueueMessageHash(DOMAIN, OPERATOR, slashLevel, epoch)).toBe(reference);
    expect(reference).toMatch(/^0x[0-9a-f]{64}$/);
  });

  it("buildExecuteMessageHash byte-matches the SP 4.11 domain-separated execute pre-image (:977)", () => {
    const proposalId = 42n;
    const epoch = 1_700_000;
    const slashLevel = SlashLevel.MINOR;
    const reference = ethers.keccak256(
      ABI.encode(
        ["bytes32", "bytes32", "uint256", "address", "uint8", "uint256", "bytes32"],
        [domSep(DOMAIN), TAG_EXECUTE_SLASH, proposalId, OPERATOR, slashLevel, epoch, EVIDENCE_HASH]
      )
    );
    expect(
      buildExecuteMessageHash(DOMAIN, proposalId, OPERATOR, slashLevel, epoch, EVIDENCE_HASH)
    ).toBe(reference);
    expect(reference).toMatch(/^0x[0-9a-f]{64}$/);
  });

  it("execute pre-image is NOT the obsolete pre-4.11 encoding (empty rep arrays + raw chainid)", () => {
    const proposalId = 42n;
    const epoch = 1_700_000;
    const slashLevel = SlashLevel.MINOR;
    const obsolete = ethers.keccak256(
      ABI.encode(
        ["uint256", "address", "uint8", "address[]", "uint256[]", "uint256", "uint256", "bytes32"],
        [proposalId, OPERATOR, slashLevel, [], [], epoch, CHAIN_ID, EVIDENCE_HASH]
      )
    );
    expect(
      buildExecuteMessageHash(DOMAIN, proposalId, OPERATOR, slashLevel, epoch, EVIDENCE_HASH)
    ).not.toBe(obsolete);
  });

  it("the domain binds aggregator + Registry (a different deployment gives a different hash)", () => {
    const epoch = 1_700_000;
    const base = buildExecuteMessageHash(DOMAIN, 1n, OPERATOR, 1, epoch, EVIDENCE_HASH);
    const otherAgg = buildExecuteMessageHash(
      { ...DOMAIN, aggregator: ethers.getAddress("0x" + "c1".repeat(20)) },
      1n,
      OPERATOR,
      1,
      epoch,
      EVIDENCE_HASH
    );
    const otherReg = buildExecuteMessageHash(
      { ...DOMAIN, registry: ethers.getAddress("0x" + "d2".repeat(20)) },
      1n,
      OPERATOR,
      1,
      epoch,
      EVIDENCE_HASH
    );
    const otherChain = buildExecuteMessageHash(
      { ...DOMAIN, chainId: 1n },
      1n,
      OPERATOR,
      1,
      epoch,
      EVIDENCE_HASH
    );
    expect(new Set([base, otherAgg, otherReg, otherChain]).size).toBe(4);
  });

  it("the queue and execute preimages are distinct (path-tag separation holds)", () => {
    const epoch = 1_700_000;
    const queue = buildQueueMessageHash(DOMAIN, OPERATOR, SlashLevel.MINOR, epoch);
    const exec = buildExecuteMessageHash(DOMAIN, 1n, OPERATOR, SlashLevel.MINOR, epoch, EVIDENCE_HASH);
    expect(queue).not.toBe(exec);
  });

  it("buildExecuteMessageHash is sensitive to evidenceHash (evidence binding is real)", () => {
    const a = buildExecuteMessageHash(DOMAIN, 1n, OPERATOR, 1, 5, "0x" + "11".repeat(32));
    const b = buildExecuteMessageHash(DOMAIN, 1n, OPERATOR, 1, 5, "0x" + "22".repeat(32));
    expect(a).not.toBe(b);
  });

  it("encodeProof produces abi.encode(uint256 signerMask, bytes sigG2) and round-trips", () => {
    const signerMask = 0b101n;
    const sigG2 = "0x" + "ab".repeat(64);
    const encoded = encodeProof(signerMask, sigG2);
    expect(encoded).toBe(new ethers.AbiCoder().encode(["uint256", "bytes"], [signerMask, sigG2]));
    const [mask, sig] = new ethers.AbiCoder().decode(["uint256", "bytes"], encoded);
    expect(mask).toBe(signerMask);
    expect(sig).toBe(sigG2);
  });

  it("buildSignerMask maps 1-indexed slots to bit s-1, dedups, and rejects out-of-range", () => {
    expect(buildSignerMask([1, 2, 3])).toBe(7n);
    expect(buildSignerMask([1, 3])).toBe(5n);
    expect(buildSignerMask([2, 2, 3])).toBe(6n);
    expect(() => buildSignerMask([0])).toThrow();
    expect(() => buildSignerMask([MAX_VALIDATORS + 1])).toThrow();
  });

  it("PendingSlotCoSigner fails closed (disarmed node never co-signs)", async () => {
    await expect(new PendingSlotCoSigner().coSign({} as CoSignRequest)).rejects.toThrow(/disarmed/);
  });

  // ── recomputeMessageHash: ONE code path for requester + responders ───────────────
  describe("recomputeMessageHash", () => {
    it("queue step === buildQueueMessageHash", () => {
      const req: CoSignRequest = {
        proofSchemaVersion: PROOF_SCHEMA_VERSION,
        step: "queue",
        operator: OPERATOR,
        slashLevel: SlashLevel.MINOR,
        epoch: 1_700_000,
        chainId: CHAIN_ID,
        evidenceHash: EVIDENCE_HASH,
        messageHash: "0x00",
      };
      expect(recomputeMessageHash(req, DOMAIN)).toBe(
        buildQueueMessageHash(DOMAIN, OPERATOR, SlashLevel.MINOR, 1_700_000)
      );
    });

    it("execute step === buildExecuteMessageHash", () => {
      const req: CoSignRequest = {
        proofSchemaVersion: PROOF_SCHEMA_VERSION,
        step: "execute",
        operator: OPERATOR,
        slashLevel: SlashLevel.MINOR,
        epoch: 1_700_000,
        chainId: CHAIN_ID,
        proposalId: "42",
        evidenceHash: EVIDENCE_HASH,
        messageHash: "0x00",
      };
      expect(recomputeMessageHash(req, DOMAIN)).toBe(
        buildExecuteMessageHash(DOMAIN, 42n, OPERATOR, SlashLevel.MINOR, 1_700_000, EVIDENCE_HASH)
      );
    });

    it("refuses when the request chainId disagrees with the local domain (cross-chain guard)", () => {
      const req: CoSignRequest = {
        proofSchemaVersion: PROOF_SCHEMA_VERSION,
        step: "queue",
        operator: OPERATOR,
        slashLevel: SlashLevel.MINOR,
        epoch: 1,
        chainId: 999,
        evidenceHash: EVIDENCE_HASH,
        messageHash: "0x00",
      };
      expect(() => recomputeMessageHash(req, DOMAIN)).toThrow(/chainId/);
    });

    it("execute step without proposalId → throws", () => {
      const req: CoSignRequest = {
        proofSchemaVersion: PROOF_SCHEMA_VERSION,
        step: "execute",
        operator: OPERATOR,
        slashLevel: SlashLevel.MINOR,
        epoch: 1,
        chainId: CHAIN_ID,
        evidenceHash: EVIDENCE_HASH,
        messageHash: "0x00",
      };
      expect(() => recomputeMessageHash(req, DOMAIN)).toThrow(/proposalId/);
    });

    it("execute step without evidenceHash → throws", () => {
      const req: CoSignRequest = {
        proofSchemaVersion: PROOF_SCHEMA_VERSION,
        step: "execute",
        operator: OPERATOR,
        slashLevel: SlashLevel.MINOR,
        epoch: 1,
        chainId: CHAIN_ID,
        proposalId: "7",
        messageHash: "0x00",
      };
      expect(() => recomputeMessageHash(req, DOMAIN)).toThrow(/evidenceHash/);
    });
  });
});
