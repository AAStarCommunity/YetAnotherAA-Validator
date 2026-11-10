// Durable local state for the watcher: records, dead letters, cursor, status. Plain JSON files,
// written atomically (temp file + rename) so a crash never leaves a half-written record.
import {
  mkdirSync,
  readFileSync,
  renameSync,
  writeFileSync,
  existsSync,
  readdirSync,
} from "node:fs";
import { join } from "node:path";

const bigintSafe = (_, v) => (typeof v === "bigint" ? v.toString() : v);

export function atomicWriteJson(path, obj) {
  const tmp = `${path}.tmp-${process.pid}`;
  writeFileSync(tmp, JSON.stringify(obj, bigintSafe, 2) + "\n", { mode: 0o600 });
  renameSync(tmp, path);
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

  /** Record id: BLS actions by (kind, key); owner-route events by (tx, logIndex). */
  static recordId(rec) {
    if (rec.route === "bls")
      return `bls-${rec.kind ?? "UNRECOVERED"}-${BigInt(rec.key).toString(16).padStart(64, "0")}`;
    return `owner-${rec.txHash.toLowerCase()}-${rec.logIndex}`;
  }

  /**
   * Idempotent put. A record already on disk is kept as is (first write wins: the disclosure
   * pipeline acts on it), unless the new one upgrades an UNRECOVERED placeholder for the same key.
   * Returns "new" | "same" | "upgraded".
   */
  putRecord(rec) {
    const id = Store.recordId(rec);
    const path = join(this.dir, "records", `${id}.json`);
    if (existsSync(path)) return "same";
    if (rec.route === "bls" && rec.kind !== undefined) {
      const placeholder = join(
        this.dir,
        "deadletters",
        `bls-UNRECOVERED-${BigInt(rec.key).toString(16).padStart(64, "0")}.json`
      );
      const had = existsSync(placeholder);
      atomicWriteJson(path, { id, ...rec });
      if (had) {
        atomicWriteJson(`${placeholder}.resolved`, { resolvedBy: id });
        renameSync(placeholder, `${placeholder}.done`);
        return "upgraded";
      }
      return "new";
    }
    atomicWriteJson(path, { id, ...rec });
    return "new";
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

  listDeadLetters() {
    return readdirSync(join(this.dir, "deadletters"))
      .filter(f => f.endsWith(".json"))
      .map(f => readJson(join(this.dir, "deadletters", f), null))
      .filter(Boolean);
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
