import { promises as fs } from "fs";
import * as path from "path";

/**
 * CC-89 stage-2 — the watcher's DATA-AVAILABILITY layer.
 *
 * SP's A' commitment (`proposalSignersCommitment[proposalId]`, PR #371) is an irreversible
 * `bytes32` fingerprint of the fraud-time signer ADDRESS set — you cannot reverse it back to the
 * addresses. So when a slash is later found fraudulent, the fraud-proof assembler needs the actual
 * `claimedSigners` that reproduce that commitment. This store is where each DVT node durably keeps
 * `proposalId → {claimedSigners, ...}` captured at execution time.
 *
 * Because the commitment is irreversible, a slash whose signer set NO node recorded is permanently
 * un-attributable. The watcher must therefore run REDUNDANTLY across the fleet (each node writes its
 * own store dir); this store is the per-node half of that redundancy, made restart-safe by a
 * persisted scan cursor so a node that was down backfills from where it left off.
 *
 * THREE areas keep a wrong set from ever being trusted (Codex CC-89 review):
 *   - VERIFIED (`<proposalId>.json`) — canonical. ONLY records whose recomputed commitment matched
 *     on-chain. The fraud-proof assembler reads ONLY these.
 *   - UNVERIFIED (`unverified/<proposalId>.json`) — quarantine. A record was built but its self-check
 *     did NOT match on-chain (byte drift / wrong branch / a non-verifyAndExecute path). Kept as
 *     durable evidence needing review; NEVER read by the assembler.
 *   - FAILED (`failed/<block>-<logIndex>.json`) — dead-letter. The record could not be built at all
 *     (tx fetch error, wrapped/undecodable call, hole slot). Retried each tick so a transient error
 *     self-heals and a permanent one stays VISIBLE + RECOVERABLE instead of silently lost.
 */

/** One durably-recorded slash execution: everything needed to rebuild its fraudProof later. */
export interface GuardianSignerRecord {
  /** The disputed proposalId (BLSAggregator). Stringified bigint (JSON has no bigint). */
  proposalId: string;
  operator: string;
  slashLevel: number;
  /** Stringified bigint. */
  epoch: string;
  /** The RAW evidenceHash committed on-chain (opaque; binds the off-chain evidence). */
  evidenceHash: string;
  /** Stringified bigint. */
  signerMask: string;
  /** Co-signer addresses, strictly ascending by uint160 — reproduces SP's commitment `sorted`. */
  claimedSigners: string[];
  /** The block verifyAndExecute was mined in — the block `validatorAtSlot` was resolved at. */
  executionBlock: number;
  txHash: string;
  chainId: string;
  /** The on-chain commitment this record reproduces (self-check anchor). */
  commitment: string;
  /** Whether the locally-recomputed commitment matched the on-chain value at capture time. */
  commitmentVerified: boolean;
  /** The executionBlock's timestamp (chain time, not wall-clock). */
  executionBlockTimestamp: number;
}

/** A log the watcher could not turn into a record — durable retry queue entry. */
export interface GuardianCaptureFailure {
  block: number;
  logIndex: number;
  txHash: string;
  /** Best-effort (from the event topic); the retry re-derives the rest. */
  proposalId: string;
  reason: string;
  attempts: number;
  /** Once attempts hit the cap, the entry is PARKED — kept durable but no longer auto-retried. */
  parked: boolean;
}

export interface IGuardianSignerStore {
  /** Persist a VERIFIED record (canonical, self-check passed). */
  putVerified(record: GuardianSignerRecord): Promise<string>;
  /** Persist an UNVERIFIED record (quarantine — self-check failed; never read by the assembler). */
  putUnverified(record: GuardianSignerRecord): Promise<string>;
  /** True if this proposal already reached a terminal state (verified OR quarantined). */
  hasTerminal(proposalId: bigint): Promise<boolean>;
  /** Read a canonical (verified) record; null if absent/quarantined-only. */
  getVerified(proposalId: bigint): Promise<GuardianSignerRecord | null>;
  /** Count of canonical verified records. */
  count(): Promise<number>;

  /** Dead-letter a log that could not be captured (idempotent by block+logIndex; bumps attempts). */
  putFailure(failure: GuardianCaptureFailure): Promise<void>;
  /** True if a dead-letter already exists for this log (so a re-scan won't double-process it). */
  hasFailure(block: number, logIndex: number): Promise<boolean>;
  /** List dead-letters (both retryable and parked — caller filters on `parked`). */
  listFailures(): Promise<GuardianCaptureFailure[]>;
  /** Remove a dead-letter once it has been captured. */
  removeFailure(block: number, logIndex: number): Promise<void>;

  /** Persisted scan cursor: the last block fully scanned for SlashExecuted (restart-safe). */
  readCursor(): Promise<number | null>;
  writeCursor(block: number): Promise<void>;
}

/** Atomic write: temp file + rename, so a crash mid-write never leaves a truncated file. */
async function atomicWrite(file: string, data: string): Promise<void> {
  const tmp = `${file}.tmp`;
  await fs.writeFile(tmp, data, "utf8");
  await fs.rename(tmp, file);
}

/**
 * Disk-backed store. Canonical verified records at `<dir>/<proposalId>.json`; quarantine under
 * `<dir>/unverified/`; dead-letters under `<dir>/failed/`; cursor at `<dir>/.cursor`. Safe for the
 * single-writer-per-node model (each node owns its own dir); NOT a shared multi-writer store.
 */
export class LocalGuardianSignerStore implements IGuardianSignerStore {
  constructor(private readonly dir: string) {}

  private verifiedFile(proposalId: bigint): string {
    return path.join(this.dir, `${proposalId.toString()}.json`);
  }
  private unverifiedDir(): string {
    return path.join(this.dir, "unverified");
  }
  private unverifiedFile(proposalId: bigint): string {
    return path.join(this.unverifiedDir(), `${proposalId.toString()}.json`);
  }
  private failedDir(): string {
    return path.join(this.dir, "failed");
  }
  private failedFile(block: number, logIndex: number): string {
    return path.join(this.failedDir(), `${block}-${logIndex}.json`);
  }
  private cursorFile(): string {
    return path.join(this.dir, ".cursor");
  }

  async putVerified(record: GuardianSignerRecord): Promise<string> {
    await fs.mkdir(this.dir, { recursive: true });
    const location = this.verifiedFile(BigInt(record.proposalId));
    await atomicWrite(location, JSON.stringify(record, null, 2));
    return location;
  }

  async putUnverified(record: GuardianSignerRecord): Promise<string> {
    await fs.mkdir(this.unverifiedDir(), { recursive: true });
    const location = this.unverifiedFile(BigInt(record.proposalId));
    await atomicWrite(location, JSON.stringify(record, null, 2));
    return location;
  }

  async hasTerminal(proposalId: bigint): Promise<boolean> {
    for (const f of [this.verifiedFile(proposalId), this.unverifiedFile(proposalId)]) {
      try {
        await fs.access(f);
        return true;
      } catch {
        // not present — check the next
      }
    }
    return false;
  }

  async getVerified(proposalId: bigint): Promise<GuardianSignerRecord | null> {
    try {
      const raw = await fs.readFile(this.verifiedFile(proposalId), "utf8");
      return JSON.parse(raw) as GuardianSignerRecord;
    } catch {
      return null;
    }
  }

  async count(): Promise<number> {
    try {
      const files = await fs.readdir(this.dir);
      return files.filter(f => f.endsWith(".json")).length;
    } catch {
      return 0;
    }
  }

  async putFailure(failure: GuardianCaptureFailure): Promise<void> {
    await fs.mkdir(this.failedDir(), { recursive: true });
    await atomicWrite(
      this.failedFile(failure.block, failure.logIndex),
      JSON.stringify(failure, null, 2)
    );
  }

  async hasFailure(block: number, logIndex: number): Promise<boolean> {
    try {
      await fs.access(this.failedFile(block, logIndex));
      return true;
    } catch {
      return false;
    }
  }

  async listFailures(): Promise<GuardianCaptureFailure[]> {
    let files: string[];
    try {
      files = await fs.readdir(this.failedDir());
    } catch {
      return [];
    }
    const out: GuardianCaptureFailure[] = [];
    for (const f of files) {
      if (!f.endsWith(".json")) continue;
      try {
        out.push(JSON.parse(await fs.readFile(path.join(this.failedDir(), f), "utf8")));
      } catch {
        // A corrupt/unreadable dead-letter would otherwise silently disable retries for that log
        // (nothing re-scans a range past the cursor). Recover block+logIndex from the FILENAME
        // (`<block>-<logIndex>.json`) and surface it as a PARKED corrupt entry so it stays visible
        // for manual recovery instead of vanishing.
        const m = /^(\d+)-(\d+)\.json$/.exec(f);
        if (m) {
          out.push({
            block: parseInt(m[1], 10),
            logIndex: parseInt(m[2], 10),
            txHash: "",
            proposalId: "",
            reason: "corrupt dead-letter file (unreadable) — manual recovery needed",
            attempts: Number.MAX_SAFE_INTEGER,
            parked: true,
          });
        }
      }
    }
    return out;
  }

  async removeFailure(block: number, logIndex: number): Promise<void> {
    try {
      await fs.rm(this.failedFile(block, logIndex));
    } catch {
      // already gone — fine
    }
  }

  async readCursor(): Promise<number | null> {
    try {
      const raw = await fs.readFile(this.cursorFile(), "utf8");
      const n = parseInt(raw.trim(), 10);
      return Number.isFinite(n) && n >= 0 ? n : null;
    } catch {
      return null;
    }
  }

  async writeCursor(block: number): Promise<void> {
    await fs.mkdir(this.dir, { recursive: true });
    await atomicWrite(this.cursorFile(), String(block));
  }
}
