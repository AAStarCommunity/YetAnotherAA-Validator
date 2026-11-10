// Durable local state for the watcher: records, dead letters, cursor, status. Plain JSON files,
// written atomically (temp file + rename) so a crash never leaves a half-written record.
import {
  mkdirSync,
  readFileSync,
  renameSync,
  existsSync,
  readdirSync,
  openSync,
  writeSync,
  fsyncSync,
  closeSync,
  statSync,
} from "node:fs";
import { join, dirname } from "node:path";
import { SafeError } from "./safe-error.mjs";

const bigintSafe = (_, v) => (typeof v === "bigint" ? v.toString() : v);

/**
 * Atomic AND durable (#400 Low; W2c R1 H1): the bytes are fsynced before the rename and the
 * directory after it, so a power cut leaves either the old file or the complete new one, never an
 * empty file, and a returned write survives the crash (the W2 journal relies on that).
 */
/** Write every byte of `buf` to `fd`; `write` is injectable for a fault test. */
/** A well-formed amendment for `key`: its key, a tx hash, how it was proven, and at least one
 * event, each with a name and a position. */
export function validAmendment(a, key) {
  return (
    !!a &&
    typeof a === "object" &&
    String(a.key) === BigInt(key).toString() &&
    /^0x[0-9a-fA-F]{64}$/.test(String(a.txHash)) &&
    a.provenBy === "trace" && // the only supported proof
    Array.isArray(a.spEvents) &&
    a.spEvents.length > 0 &&
    a.spEvents.every(
      e =>
        e &&
        typeof e === "object" &&
        typeof e.event === "string" &&
        /^[A-Z][A-Za-z0-9]{0,63}$/.test(e.event) &&
        typeof e.logIndex === "number" &&
        Number.isSafeInteger(e.logIndex) &&
        e.logIndex >= 0 &&
        (e.args === undefined || (e.args && typeof e.args === "object"))
    )
  );
}

export function writeAll(fd, buf, write = writeSync) {
  let off = 0;
  while (off < buf.length) {
    const n = write(fd, buf, off, buf.length - off);
    if (!(n > 0)) throw new Error(`short write: ${off} of ${buf.length} bytes`);
    off += n;
  }
}

export function atomicWriteJson(path, obj) {
  const tmp = `${path}.tmp-${process.pid}`;
  const buf = Buffer.from(JSON.stringify(obj, bigintSafe, 2) + "\n", "utf8");
  const fd = openSync(tmp, "w", 0o600);
  try {
    // writeSync may write fewer bytes than asked (e.g. a full disk): loop until every byte is
    // written, and refuse zero progress, so a short file is never fsynced and renamed into place
    // (Codex W2c R2).
    writeAll(fd, buf);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  renameSync(tmp, path);
  const d = openSync(dirname(path), "r");
  try {
    fsyncSync(d);
  } finally {
    closeSync(d);
  }
}

export function readJson(path, fallback) {
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch (e) {
    if (e.code === "ENOENT") return fallback;
    throw e; // a corrupt state file must stop the scan, not be silently reset
  }
}

export class Store {
  constructor(dir) {
    this.dir = dir;
    for (const d of ["records", "deadletters", "publications", "amendments"])
      mkdirSync(join(dir, d), { recursive: true, mode: 0o700 });
  }

  /**
   * Record id: BLS actions by (kind, key); SuperPaymaster events by (route, tx, logIndex); a dead
   * letter for a whole transaction (route "tx") by its hash.
   */
  static recordId(rec) {
    if (rec.route === "bls")
      return `bls-${rec.kind ?? "UNRECOVERED"}-${BigInt(rec.key).toString(16).padStart(64, "0")}`;
    if (rec.route === "tx") return `tx-${rec.txHash.toLowerCase()}`;
    const route = rec.route === "public" || rec.route === "unattributed" ? rec.route : "owner";
    return `${route}-${rec.txHash.toLowerCase()}-${rec.logIndex}`;
  }

  /**
   * Idempotent put. A record already on disk is kept as is (first write wins: the disclosure
   * pipeline acts on it), unless the new one upgrades an UNRECOVERED placeholder for the same key.
   * Returns "new" | "same" | "upgraded".
   */
  putRecord(rec) {
    const id = Store.recordId(rec);
    const path = join(this.dir, "records", `${id}.json`);
    // A file that exists but does not parse was never a valid record (#400 Low): rewrite it rather
    // than treat it as "the same" and lose the record for good.
    let existed = existsSync(path);
    if (existed) {
      try {
        JSON.parse(readFileSync(path, "utf8"));
      } catch {
        existed = false;
      }
    }
    if (!existed) atomicWriteJson(path, { id, ...rec });
    // Reconcile the dead letter for this key even if the record was already written: a crash
    // between the two writes must not leave a resolved action being retried forever.
    let resolved = false;
    if (rec.route === "bls" && rec.kind !== undefined) {
      const placeholder = join(
        this.dir,
        "deadletters",
        `${Store.recordId({ ...rec, kind: undefined })}.json`
      );
      if (existsSync(placeholder)) {
        atomicWriteJson(`${placeholder}.resolved`, { resolvedBy: id });
        renameSync(placeholder, `${placeholder}.done`);
        resolved = true;
      }
    }
    if (existed) return "same";
    return resolved ? "upgraded" : "new";
  }

  /** Dead letter: an action seen but not authenticated; retried on later ticks, never dropped. */
  putDeadLetter(rec) {
    const id = Store.recordId({ ...rec, kind: undefined });
    const path = join(this.dir, "deadletters", `${id}.json`);
    let prev = null;
    try {
      prev = readJson(path, null);
    } catch {
      prev = null; // a corrupt dead letter is replaced, never a reason to stop
    }
    // Evidence a dead letter has already established (an authenticated BLS record, classified SP
    // records awaiting only a price) survives any later, weaker failure (Codex #400-fix R2 M3/M4).
    const keep = {};
    if (prev?.pendingRecord && !rec.pendingRecord) keep.pendingRecord = prev.pendingRecord;
    if (prev?.pendingRecords && !rec.pendingRecords) keep.pendingRecords = prev.pendingRecords;
    atomicWriteJson(path, {
      id,
      ...rec,
      ...keep,
      ...(keep.pendingRecord ? { status: prev.status } : {}),
      attempts: (prev?.attempts ?? 0) + 1,
      firstSeen: prev?.firstSeen ?? rec.seenAt,
    });
    return prev ? "retried" : "new";
  }

  /** Open dead letters. An unreadable file is counted in `corruptDeadLetters`, never a reason to
   * stop the scan (#400 Low). */
  listDeadLetters() {
    this.corruptDeadLetters = 0;
    const out = [];
    for (const f of readdirSync(join(this.dir, "deadletters")).filter(f => f.endsWith(".json"))) {
      try {
        const v = JSON.parse(readFileSync(join(this.dir, "deadletters", f), "utf8"));
        if (v) out.push(v);
      } catch {
        this.corruptDeadLetters++;
      }
    }
    return out;
  }

  /** A dead letter whose action now has its record(s): keep it, marked done. */
  resolveDeadLetter(id) {
    const path = join(this.dir, "deadletters", `${id}.json`);
    if (!existsSync(path)) return false;
    renameSync(path, `${path}.done`);
    return true;
  }

  /** A dead letter that used every retry and was turned into a record (exhaust). */
  retireDeadLetter(id) {
    const path = join(this.dir, "deadletters", `${id}.json`);
    if (!existsSync(path)) return;
    // never overwrite an earlier retirement of the same id (#400 review L2): number them
    let target = `${path}.exhausted`;
    for (let k = 2; existsSync(target); k++) target = `${path}.exhausted.${k}`;
    renameSync(path, target);
  }

  /** Unattributed records of txs whose answers never became readable (#400 review L1). */
  countUnreadable() {
    return readdirSync(join(this.dir, "records")).filter(f => f.endsWith("-unreadable.json"))
      .length;
  }

  /**
   * SP effects proven to belong to a BLS action only after its record was written (#400 review
   * L4). The record itself is first-write-wins (its bytes may be published), so the later proof is
   * kept beside it, also first-write-wins. Returns "new" | "same".
   */
  putBlsAmendment(key, amendment) {
    const path = join(
      this.dir,
      "amendments",
      `bls-${BigInt(key).toString(16).padStart(64, "0")}.json`
    );
    if (existsSync(path)) {
      // an existing amendment counts only if it is a valid one for this key; a truncated or
      // foreign file is repaired, never trusted (Codex follow-up R2)
      let cur = null;
      try {
        cur = JSON.parse(readFileSync(path, "utf8"));
      } catch {
        cur = null;
      }
      if (validAmendment(cur, key)) {
        // persisted only if it is THIS proof: the same tx and the same events
        const same =
          String(cur.txHash).toLowerCase() === String(amendment.txHash).toLowerCase() &&
          JSON.stringify(cur.spEvents, bigintSafe) ===
            JSON.stringify(amendment.spEvents, bigintSafe);
        if (same) return "same";
        // a different valid proof for the same action: both kept, never one overwriting the other
        let c = 1;
        while (existsSync(`${path}.conflict.${c}`)) c++;
        atomicWriteJson(`${path}.conflict.${c}`, amendment);
        return "conflict";
      }
      // keep the invalid bytes for inspection, then persist the valid proof (Codex follow-up R3)
      let k = 1;
      while (existsSync(`${path}.invalid.${k}`)) k++;
      renameSync(path, `${path}.invalid.${k}`);
      atomicWriteJson(path, amendment);
      return "repaired";
    }
    atomicWriteJson(path, amendment);
    return "new";
  }

  getBlsAmendment(key) {
    try {
      return readJson(
        join(this.dir, "amendments", `bls-${BigInt(key).toString(16).padStart(64, "0")}.json`),
        null
      );
    } catch {
      return null;
    }
  }

  countAmendments() {
    return readdirSync(join(this.dir, "amendments")).filter(f => f.endsWith(".json")).length;
  }

  countExhausted() {
    return readdirSync(join(this.dir, "deadletters")).filter(f => /\.exhausted(\.\d+)?$/.test(f))
      .length;
  }

  /**
   * Whether an AUTHENTICATED record exists for this BLS key: a parseable record with a kind.
   * UNRECOVERED, placeholder or corrupt files do not count, so a later authentication still
   * writes the real record (Codex #400-fix R2).
   */
  hasBlsRecord(key) {
    const suffix = `-${BigInt(key).toString(16).padStart(64, "0")}.json`;
    return readdirSync(join(this.dir, "records")).some(f => {
      if (!f.startsWith("bls-") || !f.endsWith(suffix)) return false;
      // UNRECOVERED placeholders carry no kind, so the kind test excludes them too.
      try {
        return JSON.parse(readFileSync(join(this.dir, "records", f), "utf8")).kind !== undefined;
      } catch {
        return false;
      }
    });
  }

  /** Update fields of an open dead letter without counting an attempt (no-op when absent). */
  patchDeadLetter(id, patch) {
    const path = join(this.dir, "deadletters", `${id}.json`);
    let cur = null;
    try {
      cur = readJson(path, null);
    } catch {
      cur = null;
    }
    if (!cur) return false;
    atomicWriteJson(path, { ...cur, ...patch, id: cur.id ?? id, attempts: cur.attempts });
    return true;
  }

  /** Ids of the open dead letters (file names), sorted. */
  listDeadLetterIds() {
    return readdirSync(join(this.dir, "deadletters"))
      .filter(f => f.endsWith(".json"))
      .map(f => f.slice(0, -5))
      .sort();
  }

  /** The open dead letter with this id, or null. */
  getDeadLetter(id) {
    try {
      return readJson(join(this.dir, "deadletters", `${id}.json`), null);
    } catch {
      return null;
    }
  }

  countRecords() {
    return readdirSync(join(this.dir, "records")).filter(f => f.endsWith(".json")).length;
  }

  /** The last positive trace-capability verification ({ verifiedAt (ms), txHash, by }), or null. */
  getTraceCapability() {
    try {
      return readJson(join(this.dir, "trace-capability.json"), null);
    } catch {
      return null; // unreadable counts as never verified: degraded, never healthy
    }
  }

  putTraceCapability(v) {
    atomicWriteJson(join(this.dir, "trace-capability.json"), v);
  }

  getCursor() {
    return readJson(join(this.dir, "cursor.json"), null);
  }

  setCursor(c) {
    atomicWriteJson(join(this.dir, "cursor.json"), c);
  }

  writeStatus(s) {
    atomicWriteJson(join(this.dir, "status.json"), s);
  }

  /** Every stored record (W2c: the publisher walks the flagged ones). */
  listRecords() {
    return readdirSync(join(this.dir, "records"))
      .filter(f => f.endsWith(".json"))
      .sort()
      .map(f => readJson(join(this.dir, "records", f), null))
      .filter(Boolean);
  }

  /** Record file names, sorted (the publisher reads them in bounded, rotating batches). */
  recordFiles() {
    return readdirSync(join(this.dir, "records"))
      .filter(f => f.endsWith(".json"))
      .sort();
  }

  /** One record file, parsed; throws when it is unreadable. */
  readRecordFile(name, maxBytes = Infinity) {
    const path = join(this.dir, "records", name);
    // size first: an oversized or corrupt file is refused before it is read (Codex W2c R3)
    if (statSync(path).size > maxBytes) throw new Error("record file too large");
    return JSON.parse(readFileSync(path, "utf8"));
  }

  /** Publication scheduling (Codex W2c R2): rotation cursor, per-record progress, the reverify
   * generation. Kept apart from the journals; unreadable counts as empty (only order is lost). */
  getSchedule() {
    try {
      return readJson(join(this.dir, "publish-schedule.json"), null) ?? {};
    } catch {
      return {};
    }
  }

  putSchedule(s) {
    atomicWriteJson(join(this.dir, "publish-schedule.json"), s);
  }

  /** The full alert list of the last pass (the Telegram digest may say "N more"). */
  putAlertList(alerts) {
    atomicWriteJson(join(this.dir, "alerts-latest.json"), { alerts });
  }

  /** Every readable record, and the names of record files that do not parse (Codex W2c R1 M7). */
  listRecordsTolerant() {
    const records = [];
    const corrupt = [];
    for (const f of readdirSync(join(this.dir, "records"))
      .filter(f => f.endsWith(".json"))
      .sort()) {
      try {
        const v = JSON.parse(readFileSync(join(this.dir, "records", f), "utf8"));
        if (v) records.push(v);
      } catch {
        corrupt.push(f);
      }
    }
    return { records, corrupt };
  }

  /** The last status written, or null (unreadable counts as none). */
  readStatus() {
    try {
      return readJson(join(this.dir, "status.json"), null);
    } catch {
      return null;
    }
  }

  /** The publication journal of a record (publishRecord's state), or null. */
  getPublication(id) {
    return readJson(join(this.dir, "publications", `${Store.safeId(id)}.json`), null);
  }

  /** Durable, atomic: publishRecord awaits this after every stage. */
  putPublication(id, state) {
    atomicWriteJson(join(this.dir, "publications", `${Store.safeId(id)}.json`), state);
  }

  getAlertState() {
    return readJson(join(this.dir, "alerts.json"), null);
  }

  putAlertState(s) {
    atomicWriteJson(join(this.dir, "alerts.json"), s);
  }

  /** Record ids are ours (recordId), but a file name is checked anyway. */
  static safeId(id) {
    if (!/^[A-Za-z0-9-]{1,200}$/.test(String(id))) throw new SafeError("store: bad record id");
    return id;
  }
}
