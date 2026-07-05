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
  /** Unix ms when the observation was made. */
  observedAt: number;
}

/** The durable slash-proof record. Schema version "dvt-slash-proof/1". */
export interface SlashProof {
  version: "dvt-slash-proof/1";
  proposalId: string;
  chainId: number;
  operator: string;
  slashLevel: number;
  reason: string;
  epoch: number;
  /** BLS message the quorum signs over the proposal. */
  messageHash: string;
  /** Bitmask of co-signers — empty until increment 2. */
  signerMask: string;
  /** Aggregated G2 signature — empty until increment 2. */
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
  /** Tx hash of the createProposal call, when the proposal-intent was filed. */
  executedTx?: string;
}

/** The immutable subset that defines a detection — the content-address preimage. */
export type ProofCore = Pick<
  SlashProof,
  "version" | "chainId" | "operator" | "slashLevel" | "reason" | "epoch" | "messageHash" | "evidence"
>;

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
 * of its immutable core. Deterministic — the same evidence always yields the same hash,
 * which is what makes the archive tamper-evident and de-duplicating.
 */
export function computeProofHash(core: ProofCore): string {
  return ethers.keccak256(ethers.toUtf8Bytes(stableStringify(core)));
}

/**
 * Proof archive backend. `put` is idempotent on `proofHash` (same evidence overwrites
 * the same file), so redundant detections across ticks don't multiply records.
 */
export interface IProofArchive {
  put(proof: SlashProof): Promise<{ proofHash: string; location: string }>;
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

  async count(): Promise<number> {
    throw new Error("IpfsProofArchive not implemented — increment 3");
  }
}
