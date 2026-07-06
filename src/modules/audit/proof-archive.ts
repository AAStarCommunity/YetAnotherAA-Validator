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
   * Block number ALL rule inputs were pinned to (from one provider.getBlockNumber()).
   * Part of the content-address identity — two nodes reading the same block agree.
   */
  violationBlock: number;
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
   * actually submitted on-chain: buildExecuteMessageHash(proposalId, operator, slashLevel, epoch,
   * chainId, evidenceHash=proofHash). "0x" (with a `messageHashNote`) when the real proposalId is
   * unresolved (proposal not filed / event absent) — never a stale or wrong preimage.
   */
  messageHash: string;
  /** Present only when `messageHash` is "0x": why the execute preimage could not be computed. */
  messageHashNote?: string;
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
}

/** Filesystem-backed archive: one `<proofHash>.json` per detection under `dir`. */
export class LocalProofArchive implements IProofArchive {
  constructor(private readonly dir: string) {}

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
      return entries.filter(e => e.endsWith(".json")).length;
    } catch {
      // Directory not created yet → nothing archived.
      return 0;
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
}
