import { ethers } from "ethers";

/**
 * DVT Phase 2 (目标2) — slash-consensus primitives, increment 2.
 *
 * These are the PURE, side-effect-free building blocks the two-step slash orchestration
 * (AuditService.coordinateQuorumCoSign) is composed from, plus the quorum co-sign seam.
 * They are broken out here so the exact on-chain preimages can be unit-tested in isolation
 * against a hand-computed ethers.AbiCoder reference — a byte mismatch here would make every
 * DVTValidator write revert (BLS aggregate verification is over these exact hashes).
 *
 * Interface source of truth: SuperPaymaster #329 (finalized). The two slash steps are
 * INDEPENDENT (each quorum co-signed once over its own preimage, each carrying its own proof):
 *
 *   Step 1 (queue):   DVTValidator.queueSlashWithProof(operator, slashLevel, epoch, proof)
 *     messageHash = keccak256(abi.encode(
 *       keccak256("QUEUE_SLASH"), operator, slashLevel, epoch, block.chainid))   // 5 fields
 *
 *   Step 2 (execute): DVTValidator.executeWithProof(id, repUsers, newScores, epoch, proof)
 *     messageHash = keccak256(abi.encode(
 *       proposalId, operator, slashLevel, repUsers[], newScores[],
 *       epoch, block.chainid, evidenceHash))                                     // 8 fields
 *     For a slash-only proposal repUsers and newScores are BOTH empty ([]).
 *
 *   proof (both steps): abi.encode(uint256 signerMask, bytes sigG2)
 */

const ABI = new ethers.AbiCoder();

/**
 * Domain-separation tag for the queue-slash preimage. keccak256("QUEUE_SLASH") — the UTF-8
 * bytes of the literal, exactly matching the Solidity `keccak256("QUEUE_SLASH")`.
 */
export const QUEUE_SLASH_TAG = ethers.id("QUEUE_SLASH");

/**
 * On-chain slash severity enum (SP #329 SlashLevel). The audit's credit-over-limit rule maps
 * to MINOR (see AuditService). WARNING is 2-of-3 quorum in the N=3 bootstrap; MINOR/MAJOR 3-of-3.
 */
export enum SlashLevel {
  WARNING = 0,
  MINOR = 1,
  MAJOR = 2,
}

/**
 * Step-1 queue preimage — keccak256 over the 5-field encoding with the QUEUE_SLASH domain tag.
 * This is the message the DVT quorum co-signs before queueSlashWithProof.
 */
export function buildQueueMessageHash(
  operator: string,
  slashLevel: number,
  epoch: bigint | number,
  chainId: bigint | number
): string {
  return ethers.keccak256(
    ABI.encode(
      ["bytes32", "address", "uint8", "uint256", "uint256"],
      [QUEUE_SLASH_TAG, operator, slashLevel, epoch, chainId]
    )
  );
}

/**
 * Step-2 execute preimage — keccak256 over the 8-field encoding. repUsers/newScores are empty
 * for a slash-only proposal; evidenceHash binds the on-chain slash to the archived proof
 * (the audit passes proofHash here). This is the message the DVT quorum co-signs before
 * executeWithProof.
 */
export function buildExecuteMessageHash(
  proposalId: bigint | number,
  operator: string,
  slashLevel: number,
  epoch: bigint | number,
  chainId: bigint | number,
  evidenceHash: string
): string {
  return ethers.keccak256(
    ABI.encode(
      ["uint256", "address", "uint8", "address[]", "uint256[]", "uint256", "uint256", "bytes32"],
      [proposalId, operator, slashLevel, [], [], epoch, chainId, evidenceHash]
    )
  );
}

/** abi.encode(uint256 signerMask, bytes sigG2) — the wire proof both slash steps carry. */
export function encodeProof(signerMask: bigint, sigG2: string): string {
  return ABI.encode(["uint256", "bytes"], [signerMask, sigG2]);
}

/**
 * On-chain validator-set capacity (BLSAggregator.MAX_VALIDATORS). signerMask bits are indexed
 * `[0, MAX_VALIDATORS)`; the contract rejects any `signerMask >> MAX_VALIDATORS != 0`, so a slot
 * must live in `[1, MAX_VALIDATORS]`. Kept in sync with the on-chain constant (verify against
 * BLSAggregator.sol before changing).
 */
export const MAX_VALIDATORS = 13;

/**
 * Build the on-chain `signerMask` bitmap from a list of 1-indexed validator slots.
 *
 * PINNED CONVENTION (BLSAggregator.sol `_reconstructPkAgg` / `verify`): slot `s` (1-indexed)
 * maps to bit `s-1` (0-indexed) — the contract iterates `for slot 1..MAX_VALIDATORS` and
 * includes the validator at `slot` iff `((signerMask >> (slot-1)) & 1) == 1`. So:
 *   buildSignerMask([1,2,3]) === 7n   (1<<0 | 1<<1 | 1<<2)
 *   buildSignerMask([1,2])   === 3n
 *   buildSignerMask([1,3])   === 5n
 *   buildSignerMask([2,3])   === 6n
 *
 * Slots are de-duplicated (a slot contributes at most one bit). A non-integer, `<= 0`, or
 * `> MAX_VALIDATORS` slot is REJECTED (throws) rather than silently masked — an out-of-range
 * bit would be rejected on-chain (`SlotOutOfRange`) and must never reach a submitted proof.
 */
export function buildSignerMask(slots: number[]): bigint {
  let mask = 0n;
  const seen = new Set<number>();
  for (const slot of slots) {
    if (!Number.isInteger(slot) || slot <= 0 || slot > MAX_VALIDATORS) {
      throw new Error(
        `buildSignerMask: slot ${slot} out of range — must be an integer in [1, ${MAX_VALIDATORS}]`
      );
    }
    if (seen.has(slot)) continue;
    seen.add(slot);
    mask |= 1n << BigInt(slot - 1);
  }
  return mask;
}

/**
 * A structured slash co-sign request. Carries EVERY field a peer needs to recompute the
 * on-chain messageHash from first principles (so a responder NEVER trusts the requester's
 * `messageHash`) and to independently re-confirm the underlying violation before signing.
 */
export interface CoSignRequest {
  /** Which slash step this request co-signs: the 5-field queue preimage or 8-field execute. */
  step: "queue" | "execute";
  /** Operator being slashed (checksummed address). */
  operator: string;
  /** SP #329 SlashLevel (WARNING=0, MINOR=1, MAJOR=2). */
  slashLevel: number;
  /** Deterministic slash epoch = the finalized violationBlock. */
  epoch: number;
  /** Chain the slash targets (bound into both preimages — cross-chain replay guard). */
  chainId: number;
  /** Real on-chain proposal id (decimal string). REQUIRED for the execute step. */
  proposalId?: string;
  /** Content-addressed proofHash bound into the execute preimage (`evidenceHash`). */
  evidenceHash?: string;
  /** The requester's computed messageHash — a responder MUST recompute + match, never trust. */
  messageHash: string;
}

/**
 * Recompute the on-chain messageHash for a co-sign request — the ONE code path both the
 * requester and every responder use, so a byte-for-byte agreement is structural, not trusted.
 * Dispatches to buildQueueMessageHash (queue) / buildExecuteMessageHash (execute). Throws when
 * the execute step is missing its `proposalId`/`evidenceHash` (a peer then refuses to sign).
 */
export function recomputeMessageHash(req: CoSignRequest): string {
  if (req.step === "queue") {
    return buildQueueMessageHash(req.operator, req.slashLevel, req.epoch, req.chainId);
  }
  if (req.step === "execute") {
    if (req.proposalId === undefined || req.proposalId === null || req.proposalId === "") {
      throw new Error("recomputeMessageHash: execute step requires a proposalId");
    }
    if (typeof req.evidenceHash !== "string" || req.evidenceHash.length === 0) {
      throw new Error("recomputeMessageHash: execute step requires an evidenceHash");
    }
    return buildExecuteMessageHash(
      BigInt(req.proposalId),
      req.operator,
      req.slashLevel,
      req.epoch,
      req.chainId,
      req.evidenceHash
    );
  }
  throw new Error(
    `recomputeMessageHash: unknown step "${String((req as { step?: unknown }).step)}"`
  );
}

/**
 * A peer-side violation re-confirmation. Given a co-sign request, an armed node independently
 * re-reads the operator's on-chain state pinned at `epoch` (= violationBlock) and re-derives the
 * content-address. `confirmed` is true only when this node's OWN rule fires on that block; the
 * returned `proofHash` is compared against `req.evidenceHash` for the execute step (the
 * "innocent-operator" defense — a substituted operator yields a different proofHash). Any RPC
 * error / indeterminate read resolves to `{ confirmed: false, proofHash: null }` (fail-closed).
 */
export type CoSignVerifier = (
  req: CoSignRequest
) => Promise<{ confirmed: boolean; proofHash: string | null }>;

/**
 * The quorum co-sign seam. Given a structured request, an implementation gathers enough peer BLS
 * signatures to meet the slash-level threshold, aggregates them into a single G2 signature, and
 * returns the aggregate together with the signerMask bitmap (bit `s-1` set ⇔ SP validator slot
 * `s` contributed). AuditService injects this so the two-step orchestration is fully
 * unit-testable and the live gossip aggregator can drop in behind the same interface.
 */
export interface IQuorumCoSigner {
  coSign(req: CoSignRequest): Promise<{ signerMask: bigint; sigG2: string }>;
}

/** DI token for the injected quorum co-signer (factory-provided in AuditModule). */
export const QUORUM_COSIGNER = "QUORUM_COSIGNER";

/**
 * Default (disarmed) co-signer. Used whenever `AUDIT_EXECUTE_SLASH` is off: the audit still
 * FILES + ARCHIVES the proposal, but every co-sign fails closed so no queue/execute that would
 * revert (or over-slash) is ever submitted. The live gossip aggregator (GossipQuorumCoSigner) is
 * substituted by the AuditModule factory only when the node is explicitly armed.
 */
export class PendingSlotCoSigner implements IQuorumCoSigner {
  async coSign(_req: CoSignRequest): Promise<{ signerMask: bigint; sigG2: string }> {
    throw new Error(
      "quorum co-sign deferred — node is disarmed (AUDIT_EXECUTE_SLASH!=true); " +
        "the live gossip BLS aggregator is only wired on an armed node"
    );
  }
}
