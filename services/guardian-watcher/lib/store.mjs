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
} from "node:fs";
import { join, dirname } from "node:path";

const bigintSafe = (_, v) => (typeof v === "bigint" ? v.toString() : v);

/**
 * Atomic AND durable (#400 Low; W2c R1 H1): the bytes are fsynced before the rename and the
 * directory after it, so a power cut leaves either the old file or the complete new one, never an
 * empty file, and a returned write survives the crash (the W2 journal relies on that).
 */
export function atomicWriteJson(path, obj) {
  const tmp = `${path}.tmp-${process.pid}`;
  const fd = openSync(tmp, "w", 0o600);
  try {
    writeSync(fd, JSON.stringify(obj, bigintSafe, 2) + "\n");
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
    for (const d of ["records", "deadletters"])
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
    const prev = readJson(path, null);
    atomicWriteJson(path, {
      id,
      ...rec,
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
    if (existsSync(path)) renameSync(path, `${path}.exhausted`);
  }

  countExhausted() {
    return readdirSync(join(this.dir, "deadletters")).filter(f => f.endsWith(".exhausted")).length;
  }

  /** Whether any record exists for this BLS key (whatever its kind, UNRECOVERED included). */
  hasBlsRecord(key) {
    const suffix = `-${BigInt(key).toString(16).padStart(64, "0")}.json`;
    return readdirSync(join(this.dir, "records")).some(
      f => f.startsWith("bls-") && f.endsWith(suffix)
    );
  }

  countRecords() {
    return readdirSync(join(this.dir, "records")).filter(f => f.endsWith(".json")).length;
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
}
