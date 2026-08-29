import { ethers } from "ethers";
import {
  BlsConsensusDomain,
  queueSlashMessageHash,
  executeSlashMessageHash,
} from "./bls-consensus-domain.js";

export type { BlsConsensusDomain } from "./bls-consensus-domain.js";

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
 * On-chain slash severity enum (SP #329 SlashLevel). The audit's credit-over-limit rule maps
 * to MINOR (see AuditService). WARNING is 2-of-3 quorum in the N=3 bootstrap; MINOR/MAJOR 3-of-3.
 */
export enum SlashLevel {
  WARNING = 0,
  MINOR = 1,
  MAJOR = 2,
}

/**
 * Step-1 queue preimage — the LIVE SP 4.11 BLSAggregator queue-slash message (:911):
 * `keccak256(abi.encode(domainSeparator, TAG_QUEUE_SLASH, operator, slashLevel, epoch))`. The
 * domain (chainId+aggregator+Registry) is the signing node's OWN config — never a wire value — so
 * a node only ever co-signs a hash valid on the aggregator it is configured for.
 */
export function buildQueueMessageHash(
  domain: BlsConsensusDomain,
  operator: string,
  slashLevel: number,
  epoch: bigint | number
): string {
  return queueSlashMessageHash(domain, operator, slashLevel, BigInt(epoch));
}

/**
 * Step-2 execute preimage — the LIVE SP 4.11 BLSAggregator execute-slash message (:977):
 * `keccak256(abi.encode(domainSeparator, TAG_EXECUTE_SLASH, proposalId, operator, slashLevel,
 * epoch, evidenceHash))`. `evidenceHash` binds the on-chain slash to the archived proof (the audit
 * passes proofHash here). The obsolete pre-4.11 shape (empty rep arrays + raw chainId, no domain)
 * is gone — a signature over it would fail SP's `_checkSignatures`.
 */
export function buildExecuteMessageHash(
  domain: BlsConsensusDomain,
  proposalId: bigint | number,
  operator: string,
  slashLevel: number,
  epoch: bigint | number,
  evidenceHash: string
): string {
  return executeSlashMessageHash(
    domain,
    BigInt(proposalId),
    operator,
    slashLevel,
    BigInt(epoch),
    evidenceHash
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
  /**
   * Proof-schema version (finding-1) = proof-archive `PROOF_SCHEMA_VERSION`. The responder REFUSES
   * to co-sign a request whose version differs from its own — an EXPLICIT, diagnosable refusal for a
   * mixed-version fleet, instead of a silent proofHash divergence that quietly loses quorum. Does
   * NOT affect the on-chain messageHash (recomputeMessageHash ignores it); it only gates co-sign.
   */
  proofSchemaVersion: number;
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
 *
 * `domain` is the RECOMPUTING node's OWN (chainId, aggregator, Registry) — NEVER taken from the
 * request — so a responder can only ever produce a signature valid on the aggregator/Registry/chain
 * it is configured for. As a defence-in-depth, an explicit cross-chain refusal fires when the
 * request's advertised `chainId` disagrees with the local domain (the message would mismatch
 * anyway; failing loudly here is clearer than a silent hash divergence).
 */
export function recomputeMessageHash(req: CoSignRequest, domain: BlsConsensusDomain): string {
  if (BigInt(req.chainId) !== domain.chainId) {
    throw new Error(
      `recomputeMessageHash: request chainId ${req.chainId} != local domain chainId ${domain.chainId}`
    );
  }
  if (req.step === "queue") {
    return buildQueueMessageHash(domain, req.operator, req.slashLevel, req.epoch);
  }
  if (req.step === "execute") {
    if (req.proposalId === undefined || req.proposalId === null || req.proposalId === "") {
      throw new Error("recomputeMessageHash: execute step requires a proposalId");
    }
    if (typeof req.evidenceHash !== "string" || req.evidenceHash.length === 0) {
      throw new Error("recomputeMessageHash: execute step requires an evidenceHash");
    }
    return buildExecuteMessageHash(
      domain,
      BigInt(req.proposalId),
      req.operator,
      req.slashLevel,
      req.epoch,
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
