import { promises as fs } from "fs";
import * as path from "path";
import { ethers } from "ethers";

/**
 * DVT slash-proof archival (DVT Phase 2 / 目标2, increment 1).
 *
 * A detection produces a content-addressed evidence record. The record is the durable,
 * auditable justification for a slash: any node (or a human reviewer) can re-fetch it by
 * its `proofHash` and re-derive the same hash from the content, so a proposer cannot
 * silently alter the evidence after the fact.
 *
 * Increment 1 fills only the evidence + proposal-intent fields. The BLS quorum fields
 * (`signerMask`, `sigG2`, `participants`, `attestations`) are placeholders here — they are
 * populated in increment 2 when the multi-node co-sign lands (see AuditService).
 */

export interface EvidenceSource {
  /** Where the observation came from: an on-chain `view` read or a decoded `event`. */
  type: "view" | "event";
  /** Human-readable source name, e.g. "SuperPaymaster.getAvailableCredit". */
  name: string;
  /** Stringified observed value (bigints are serialized as decimal strings). */
  value: string;
  /** Tx hash, for `event` sources. */
  tx?: string;
  /** Block number, for `event` sources. */
  block?: number;
}

export interface Evidence {
  /** Rule id that fired, e.g. "credit-over-limit". */
  rule: string;
  /** The observed quantity that breached the rule (stringified). */
  observed: string;
  /** The threshold that was breached (stringified). */
  threshold: string;
  /** Each raw source reading that supports the detection. */
  sources: EvidenceSource[];
  /**
   * Block number ALL rule inputs were pinned to (a FINALIZED/safe block, from
   * blockchain.getViolationBlock()). Part of the content-address identity — two nodes
   * reading the same block agree.
   */
  violationBlock: number;
  /**
   * Block HASH of `violationBlock` (finding-3). Pinning the irreversible slash to a
   * finalized block's hash — not just its number — makes the evidence reorg-safe: a
   * reorg that rewrites `violationBlock` would change this hash, so the justification
   * cannot be silently invalidated. Deliberately EXCLUDED from the content-address
   * identity (a finalized block's hash is a deterministic function of its number, and
   * two nodes reading the same finalized number already agree on the hash).
   */
  violationBlockHash?: string;
  /**
   * Unix ms when the observation was made. Kept for humans ONLY — deliberately
   * EXCLUDED from the content-address identity so wall-clock never perturbs proofHash.
   */
  observedAt: number;
}

/** The durable slash-proof record. Schema version "dvt-slash-proof/1". */
export interface SlashProof {
  version: "dvt-slash-proof/1";
  /**
   * REAL on-chain proposal id (auto-incrementing uint256, as a decimal string) parsed from the
   * DVTValidator's ProposalCreated event. `null` when unresolved (proposal not filed, write
   * reverted, or the event was absent) — never a fabricated value; see `proposalIdNote`.
   */
  proposalId: string | null;
  /** Present only when `proposalId` is null: a human-readable reason the id could not be resolved. */
  proposalIdNote?: string;
  chainId: number;
  operator: string;
  slashLevel: number;
  reason: string;
  /**
   * DETERMINISTIC slash epoch — the violationBlock (an on-chain fact), NOT a wall-clock value.
   * Bound into BOTH co-sign preimages (queue + execute) and passed as the on-chain epoch arg, so
   * two DVT nodes observing the SAME violation derive the SAME epoch → the SAME messageHash → the
   * gossip BLS aggregate verifies. (observedAt stays the only wall-clock field, under `evidence`.)
   */
  epoch: number;
  /**
   * The 8-field EXECUTE preimage the quorum co-signs before executeWithProof — the SAME message
   * actually SUBMITTED on-chain: buildExecuteMessageHash(proposalId, operator, slashLevel, epoch,
   * chainId, evidenceHash=proofHash). Set ONLY when the execute tx actually landed (`executeTx`
   * present, finding-5). "0x" (with a `messageHashNote`) when nothing was submitted — i.e. the
   * file-only path (executeSlash off), a skipped/failed execute, or an unresolved proposalId. In
   * the file-only-but-proposal-resolved case the computed-but-not-submitted preimage is kept under
   * `intendedExecuteMessageHash` so the record stays unambiguous about what was vs wasn't sent.
   */
  messageHash: string;
  /** Present only when `messageHash` is "0x": why the execute preimage was not the submitted one. */
  messageHashNote?: string;
  /**
   * The 8-field EXECUTE preimage that WOULD be co-signed + submitted, computed once the real
   * proposalId is known but NO execute tx was sent (file-only path, or execute skipped/failed).
   * Kept distinct from `messageHash` (finding-5) so a reader never mistakes an intended preimage
   * for one that was actually submitted. Undefined when the execute was submitted (then it lives in
   * `messageHash`) or when the proposalId is unresolved (no preimage can be computed at all).
   */
  intendedExecuteMessageHash?: string;
  /**
   * The 5-field QUEUE preimage co-signed before queueSlashWithProof — buildQueueMessageHash(
   * operator, slashLevel, epoch, chainId). Present only on the armed (executeSlash) path where the
   * queue step actually runs; undefined on the file-only proposal path.
   */
  queueMessageHash?: string;
  /** Bitmask of co-signers (hex) — "0x" until a real quorum execute co-sign lands. */
  signerMask: string;
  /** Aggregated G2 signature — "0x" until a real quorum execute co-sign lands. */
  sigG2: string;
  /** Content address of this record (keccak256 over the immutable evidence core). */
  proofHash: string;
  /** Co-signing node ids — empty until increment 2. */
  participants: string[];
  /** Address of the node that filed the proposal. */
  proposer: string;
  /** Penalty amount (stringified wei) — 0 in increment 1 (level-driven on-chain). */
  penaltyAmount: string;
  evidence: Evidence;
  /** Per-node attestations — empty until increment 2. */
  attestations: Record<string, string>;
  createdAt: number;
  /**
   * Tx hash of the createProposal SUBMISSION (proposal-intent), when filed. This is the
   * proposal tx, NOT the slash execution. Undefined when no proposal was filed.
   */
  proposalTx?: string;
  /**
   * Tx hash of the STEP-1 queueSlashWithProof submission (armed executeSlash path only). The
   * on-chain slash-intent pre-flag. Undefined when the queue step did not run / failed.
   */
  queueTx?: string;
  /**
   * Tx hash of the STEP-2 executeWithProof submission — the irreversible on-chain slash. Present
   * only on the armed path after a successful quorum co-sign + execute. Undefined otherwise. This
   * is what durably references the evidence to the executed slash (finding-2).
   */
  executeTx?: string;
}

/**
 * The ON-CHAIN identity that content-addresses a detection. Deliberately excludes all
 * wall-clock (observedAt / epoch / createdAt) so two DVT nodes observing the SAME on-chain
 * violation — same operator, same debt/limit, pinned to the same block — derive the SAME
 * proofHash. This is what makes the archive content-addressed and cross-node de-duplicating.
 */
export interface ProofIdentity {
  chainId: number;
  operator: string;
  /** Rule id, e.g. "credit-over-limit". */
  rule: string;
  /** On-chain credit limit at violationBlock (stringified). */
  creditLimit: string;
  /** On-chain debt at violationBlock (stringified). */
  debt: string;
  /** Block all rule inputs were pinned to. */
  violationBlock: number;
}

/** Deterministic JSON with recursively sorted keys — a stable content-address preimage. */
function stableStringify(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return "[" + value.map(stableStringify).join(",") + "]";
  }
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return "{" + keys.map(k => JSON.stringify(k) + ":" + stableStringify(obj[k])).join(",") + "}";
}

/**
 * Content-address a detection: keccak256 over the canonical (sorted-key) serialization
 * of its ON-CHAIN identity. Deterministic and wall-clock-free — the same on-chain
 * violation always yields the same hash, which is what makes the archive tamper-evident,
 * de-duplicating, and stable across nodes/ticks.
 */
export function computeProofHash(identity: ProofIdentity): string {
  return ethers.keccak256(ethers.toUtf8Bytes(stableStringify(identity)));
}

/**
 * Proof archive backend. `put` is idempotent on `proofHash` (same evidence overwrites
 * the same file), so redundant detections across ticks don't multiply records. `has`
 * lets a proposer skip re-proposing a violation whose proof is already archived.
 */
export interface IProofArchive {
  put(proof: SlashProof): Promise<{ proofHash: string; location: string }>;
  has(proofHash: string): Promise<boolean>;
  count(): Promise<number>;
  /**
   * DURABLE executed-slash journal (finding-2). `recordSlashed` persists a coarse
   * `chainId|operator|rule` marker after a slash EXECUTES so a process restart reloads it and
   * does NOT re-slash the same sustained condition; `hasSlashed` reads it back; `removeSlashed`
   * clears it once the operator is observed healthy (condition resolved → a genuinely new
   * violation may slash again). Content-free markers, addressed by the coarse key only.
   */
  recordSlashed(coarseKey: string): Promise<void>;
  hasSlashed(coarseKey: string): Promise<boolean>;
  removeSlashed(coarseKey: string): Promise<void>;
}

/** Filesystem-backed archive: one `<proofHash>.json` per detection under `dir`. */
export class LocalProofArchive implements IProofArchive {
  constructor(private readonly dir: string) {}

  /** Sub-directory holding the durable executed-slash markers (kept out of the proof set). */
  private slashedDir(): string {
    return path.join(this.dir, "slashed");
  }

  /** Filesystem-safe marker filename for a coarse key (encoded so `|`/case survive verbatim). */
  private slashedFile(coarseKey: string): string {
    return path.join(this.slashedDir(), `${encodeURIComponent(coarseKey)}.slashed`);
  }

  async put(proof: SlashProof): Promise<{ proofHash: string; location: string }> {
    await fs.mkdir(this.dir, { recursive: true });
    const location = path.join(this.dir, `${proof.proofHash}.json`);
    await fs.writeFile(location, JSON.stringify(proof, null, 2), "utf8");
    return { proofHash: proof.proofHash, location };
  }

  async has(proofHash: string): Promise<boolean> {
    try {
      await fs.access(path.join(this.dir, `${proofHash}.json`));
      return true;
    } catch {
      return false;
    }
  }

  async count(): Promise<number> {
    try {
      const entries = await fs.readdir(this.dir);
      // Only `<proofHash>.json` proof files count — the `slashed/` marker dir is excluded.
      return entries.filter(e => e.endsWith(".json")).length;
    } catch {
      // Directory not created yet → nothing archived.
      return 0;
    }
  }

  async recordSlashed(coarseKey: string): Promise<void> {
    await fs.mkdir(this.slashedDir(), { recursive: true });
    // The marker's existence is the signal; its content is the raw key for human inspection.
    await fs.writeFile(this.slashedFile(coarseKey), coarseKey, "utf8");
  }

  async hasSlashed(coarseKey: string): Promise<boolean> {
    try {
      await fs.access(this.slashedFile(coarseKey));
      return true;
    } catch {
      return false;
    }
  }

  async removeSlashed(coarseKey: string): Promise<void> {
    try {
      await fs.rm(this.slashedFile(coarseKey));
    } catch {
      // Already absent (never slashed, or cleared before) → nothing to do.
    }
  }
}

/**
 * STUB — IPFS-pinned archive. Deferred to increment 3 (content-address pinning so proofs
 * survive independent of any single node's disk). The interface is ready; the impl is not.
 */
export class IpfsProofArchive implements IProofArchive {
  async put(): Promise<{ proofHash: string; location: string }> {
    throw new Error("IpfsProofArchive not implemented — increment 3");
  }

  async has(): Promise<boolean> {
    throw new Error("IpfsProofArchive not implemented — increment 3");
  }

  async count(): Promise<number> {
    throw new Error("IpfsProofArchive not implemented — increment 3");
  }

  async recordSlashed(): Promise<void> {
    throw new Error("IpfsProofArchive not implemented — increment 3");
  }

  async hasSlashed(): Promise<boolean> {
    throw new Error("IpfsProofArchive not implemented — increment 3");
  }

  async removeSlashed(): Promise<void> {
    throw new Error("IpfsProofArchive not implemented — increment 3");
  }
}
