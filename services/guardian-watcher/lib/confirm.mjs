// D-RPC2 (M0 §5.2a; DSR logs c8a0e5ef, 437b8937): before anything ACCUSATORY is published, a second,
// independently operated provider must reproduce it. The first provider is trusted only to be honest
// but possibly inconsistent; a single provider can answer itself consistently and still be wrong
// (C1-C4 in the PR), and only an independent re-run catches that.
//
// How: the record's block is scanned again, from scratch, on the second provider, into a temporary
// store: the whole pipeline (getLogs, receipts, traces, reconstruction, rules) runs on its answers
// alone, so nothing the first provider said can leak into the confirmation. The re-run's record for
// the same action must be equal, field for field, except the fields that record WHEN it was seen.
//
// States (persisted under holds/<record id>.json, first-write-wins on the record itself):
//   confirmed          the second provider reproduced the record: it may be published;
//   unconfirmed        a mismatch, or the second provider could not answer: retried. An answer that
//                      is not there yet (unavailable) is retried with a backoff and never counts
//                      toward the cap, so an outage of the second provider cannot bury an
//                      accusation (#422 review);
//   unconfirmed-final  CONFIRM_MAX_ATTEMPTS MISMATCHES: never published, reported; re-armed only by
//                      hand (deploy/guardian-watcher/rearm-hold.mjs, journalled).
// There is no bypass. Only the operator's label for the second provider is stored, never its URL or
// host.
import { mkdtempSync, rmSync, readdirSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { Store, atomicWriteJson, readJson } from "./store.mjs";
import { MAX_DEADLETTER_ATTEMPTS } from "./scan.mjs";
import { LOCAL_ONLY } from "./record-file.mjs";

/** Mismatches (the second provider reproduced something else) before a hold is final. */
export const CONFIRM_MAX_ATTEMPTS = 10;
/** Backoff after an unavailable answer (60 s doubling per consecutive one) or a mismatch (doubling
 * per mismatch), at most 1 h: the CONFIRM_MAX_ATTEMPTS-th mismatch comes at least
 * finalAfterMismatchesMs() after the first. */
export const CONFIRM_BACKOFF_BASE_MS = 60_000;
export const CONFIRM_BACKOFF_MAX_MS = 3_600_000;
/** Record files read per confirmation pass (like the publisher's bound), rotating. */
export const CONFIRM_MAX_PARSE = 500;
/** The least time from a hold's first mismatch to its CONFIRM_MAX_ATTEMPTS-th (it is final then). */
export const finalAfterMismatchesMs = () => {
  let t = 0;
  for (let m = 1; m < CONFIRM_MAX_ATTEMPTS; m++) t += backoffMs(m);
  return t;
};
export const backoffMs = streak =>
  Math.min(CONFIRM_BACKOFF_MAX_MS, CONFIRM_BACKOFF_BASE_MS * 2 ** Math.max(0, streak - 1));

/** A record that names someone as having done wrong: flagged, on the owner route or a BLS action.
 * Unattributed and public-route records accuse nobody, so they are not held. */
export function isAccusatory(rec) {
  return !!rec?.verdict?.flagged && (rec.route === "owner" || rec.route === "bls");
}

/** Fields that record when or how often a record was seen, not what it says: the same set the
 * published record leaves out (lib/record-file.mjs), so what is published is what was confirmed. */
const WHEN = LOCAL_ONLY;

/** The record without its when-fields, as stable JSON (keys sorted at every level). */
export function accusationView(rec) {
  const sort = x => {
    if (Array.isArray(x)) return x.map(sort);
    if (!x || typeof x !== "object") return x;
    const out = {};
    for (const k of Object.keys(x).sort()) out[k] = sort(x[k]);
    return out;
  };
  const top = {};
  for (const k of Object.keys(rec).sort()) if (!WHEN.has(k)) top[k] = rec[k];
  return JSON.stringify(sort(top), (k, v) => (typeof v === "bigint" ? `${v}n` : v));
}

/** The digest a confirmation is bound to: the record's content without its when-fields. */
export const viewDigest = rec => createHash("sha256").update(accusationView(rec)).digest("hex");

/** The top-level fields on which two records differ (when-fields ignored). */
function diffFields(a, b) {
  const keys = new Set([...Object.keys(a), ...Object.keys(b)]);
  const out = [];
  for (const k of [...keys].sort()) {
    if (WHEN.has(k)) continue;
    if (accusationView({ v: a[k] }) !== accusationView({ v: b[k] })) out.push(k);
  }
  return out;
}

/** Records in a store that are about the same action as `rec`: the same BLS key (any kind), or the
 * same tx and log position (any route). */
function sameAction(store, rec) {
  const dir = join(store.dir, "records");
  const out = [];
  for (const f of readdirSync(dir).filter(n => n.endsWith(".json"))) {
    let r;
    try {
      r = JSON.parse(readFileSync(join(dir, f), "utf8"));
    } catch {
      continue;
    }
    if (
      rec.route === "bls"
        ? r.route === "bls" && String(r.key) === String(rec.key)
        : r.route !== "bls" &&
          String(r.txHash).toLowerCase() === String(rec.txHash).toLowerCase() &&
          String(r.logIndex) === String(rec.logIndex)
    )
      out.push(r);
  }
  return out;
}

/**
 * Re-run the record's block on the second provider. Returns
 *   { state: "confirmed" }
 *   { state: "mismatch", fields: [...] , reason }   the second provider reproduced something else;
 *   { state: "unavailable", reason }                it could not answer (yet): not finalized there,
 *                                                   a failed tick, or only a dead letter.
 */
export async function reRun(second, cfg, rs, ident, rec, { runOnce, now } = {}) {
  const block = Number(rec.blockNumber);
  if (!Number.isSafeInteger(block) || block < 0)
    return { state: "unavailable", reason: "record has no block" };
  const d = mkdtempSync(join(tmpdir(), "guardian-watcher-confirm-"));
  try {
    const temp = new Store(d);
    const c = { ...cfg, startBlock: block, maxBlocksPerTick: 1, dataDir: d };
    // A record the first provider produced by EXHAUSTION (a dead letter retried until
    // MAX_DEADLETTER_ATTEMPTS, e.g. price.unavailable) can only be reproduced the same way: the
    // re-run keeps ticking on its own temporary store while it holds only a dead letter for the
    // action, up to the same attempt budget (D-RPC2 Codex R1 #3).
    let mine = [];
    for (let i = 0; i < MAX_DEADLETTER_ATTEMPTS + 2; i++) {
      const { status } = await runOnce(
        second,
        c,
        temp,
        rs,
        ident,
        now === undefined ? {} : { now }
      );
      if (!status.ok) return { state: "unavailable", reason: "second provider tick failed" };
      if (!(status.cursor >= block))
        return { state: "unavailable", reason: "block not finalized on the second provider" };
      mine = sameAction(temp, rec);
      if (mine.length || temp.listDeadLetters().length === 0) break;
    }
    if (!mine.length) {
      const dls = temp.listDeadLetters();
      return dls.length
        ? { state: "unavailable", reason: "second provider could only produce a dead letter" }
        : { state: "mismatch", fields: ["*"], reason: "second provider saw no such action" };
    }
    // the record with the same id, else the first other record about the same action
    const same = mine.find(r => Store.recordId(r) === Store.recordId(rec)) ?? mine[0];
    const fields = diffFields(rec, same);
    return fields.length
      ? { state: "mismatch", fields, reason: `second provider differs on ${fields.join(", ")}` }
      : { state: "confirmed" };
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
}

/** The hold for a record id, or null. */
export function getHold(store, id) {
  try {
    return readJson(join(store.dir, "holds", `${id}.json`), null);
  } catch {
    return null; // unreadable counts as not confirmed
  }
}

/** Whether an accusatory record may be published: only once the second provider confirmed it. */
export function mayPublish(store, rec) {
  if (!isAccusatory(rec)) return true;
  try {
    const h = getHold(store, Store.recordId(rec));
    // bound to the content that was compared (D-RPC2 Codex R1 #1): a confirmation of another
    // record under the same id (an alias file) does not authorize this one
    return h?.state === "confirmed" && h.digest === viewDigest(rec);
  } catch {
    return false; // a record whose id cannot be derived is never published
  }
}

/**
 * One confirmation pass. At most CONFIRM_MAX_PARSE record files are read, rotating from a persisted
 * cursor (holds/_pass.json); each accusatory record not yet confirmed (for its current content),
 * not final, and not backing off is re-run on the second provider. `secondHost` (the operator's
 * provider label, never a URL or host) is stored with each hold. The returned counts are
 * store-wide, from every hold whose record still exists:
 *   confirmed, unconfirmed, final;
 *   mismatch  unconfirmed and the last answer was a mismatch (degraded at once);
 *   waiting   unconfirmed and the last 2+ attempts in a row were unavailable (degraded);
 * and for this pass: checked (re-runs), backingOff (skipped until nextAttemptAt).
 */
const cursorMemo = new WeakMap();
/** A counter read from a hold file: a non-negative safe integer, anything else counts as 0 (a hold
 * is a local file and may be damaged; Codex D-RPC2 R11). */
const num = v => (Number.isSafeInteger(v) && v >= 0 ? v : 0);
export async function confirmPending(
  store,
  second,
  secondHost,
  cfg,
  rs,
  ident,
  { runOnce, now, maxParse = CONFIRM_MAX_PARSE } = {}
) {
  const nowMs = now ?? Date.now();
  const counts = {
    confirmed: 0,
    unconfirmed: 0,
    final: 0,
    checked: 0,
    mismatch: 0,
    waiting: 0,
    backingOff: 0,
  };
  const dir = join(store.dir, "records");
  const holds = join(store.dir, "holds");
  if (!existsSync(holds)) {
    const { mkdirSync } = await import("node:fs");
    mkdirSync(holds, { recursive: true, mode: 0o700 });
  }
  const names = readdirSync(dir)
    .filter(n => n.endsWith(".json"))
    .sort();
  const passFile = join(holds, "_pass.json");
  // the rotation as last computed in this process, so a cursor that cannot be saved still rotates
  // (Codex D-RPC2 R8 #4); otherwise the saved one, or the beginning
  let cursor = null;
  if (cursorMemo.has(store)) cursor = cursorMemo.get(store);
  else
    try {
      const c = readJson(passFile, null)?.cursor;
      cursor = typeof c === "string" ? c : null; // a damaged cursor starts over (Codex D-RPC2 R12)
    } catch {
      cursor = null; // unreadable: start over (only the order is lost)
    }
  let start = 0;
  if (cursor) {
    const k = names.findIndex(n => n > cursor);
    start = k < 0 ? 0 : k;
  }
  const batch = names.slice(start, start + maxParse);
  for (const f of batch) {
    let rec;
    try {
      rec = JSON.parse(readFileSync(join(dir, f), "utf8"));
    } catch {
      continue;
    }
    if (!isAccusatory(rec)) continue;
    // one malformed record must not stop the pass (Codex R1 #2), and only the canonical file of a
    // record is confirmed: an alias file under another name never is (Codex R1 #1)
    let id;
    try {
      id = Store.recordId(rec);
    } catch {
      counts.malformed = (counts.malformed ?? 0) + 1;
      continue;
    }
    if (f !== `${id}.json`) {
      counts.malformed = (counts.malformed ?? 0) + 1;
      continue;
    }
    // the digest once, per record: a record it cannot be computed for (e.g. nested too deep) is
    // reported and skipped, never stopping the pass (Codex D-RPC2 R10)
    let digest;
    try {
      digest = viewDigest(rec);
    } catch {
      counts.malformed = (counts.malformed ?? 0) + 1;
      continue;
    }
    const prev = getHold(store, id);
    // a confirmation counts only for the content it was made on
    if (prev?.state === "confirmed" && prev.digest === digest) continue;
    if (prev?.state === "unconfirmed-final") continue;
    const sameContent = prev?.digest === digest;
    // a deadline further away than the cap allows (the clock was ahead when it was set, or it
    // was rolled back) is not trusted: the record is retried now (Codex D-RPC2 R8 #1)
    if (
      sameContent &&
      Number.isSafeInteger(prev?.nextAttemptAt) &&
      nowMs < prev.nextAttemptAt &&
      prev.nextAttemptAt - nowMs <= CONFIRM_BACKOFF_MAX_MS
    ) {
      counts.backingOff++;
      continue;
    }
    counts.checked++;
    let r;
    try {
      r = await reRun(second, cfg, rs, ident, rec, { runOnce, now });
    } catch {
      r = { state: "unavailable", reason: "confirmation run threw" };
    }
    // new content starts afresh; the same content carries its counters
    const base = sameContent ? prev : null;
    const mismatches = num(base?.mismatches) + (r.state === "mismatch" ? 1 : 0);
    const unavailableStreak = r.state === "unavailable" ? num(base?.unavailableStreak) + 1 : 0;
    const state =
      r.state === "confirmed"
        ? "confirmed"
        : mismatches >= CONFIRM_MAX_ATTEMPTS
          ? "unconfirmed-final"
          : "unconfirmed";
    const holdDoc = {
      id,
      state,
      digest: digest,
      attempts: num(base?.attempts) + 1,
      mismatches,
      unavailableStreak,
      // both kinds of failure back off (#422 re-review L1): an unavailable answer by its streak, a
      // mismatch by the mismatch count, so CONFIRM_MAX_ATTEMPTS mismatches take hours (a provider's
      // transient inconsistency is not made final within minutes)
      ...(r.state === "unavailable"
        ? { nextAttemptAt: nowMs + backoffMs(unavailableStreak) }
        : r.state === "mismatch" && state !== "unconfirmed-final"
          ? { nextAttemptAt: nowMs + backoffMs(mismatches) }
          : {}),
      lastResult: r.state,
      ...(r.fields ? { fields: r.fields } : {}),
      ...(r.reason ? { reason: r.reason } : {}),
      secondProvider: secondHost,
      ...(prev?.rearmed ? { rearmed: prev.rearmed } : {}),
      firstHeldAt: prev?.firstHeldAt ?? new Date(nowMs).toISOString(),
      lastCheckedAt: new Date(nowMs).toISOString(),
    };
    // one hold that cannot be written does not stop the pass (Codex D-RPC2 R9 #3): it stays
    // unconfirmed (mayPublish reads the old hold, or none), it is reported, and the traversal goes on
    try {
      atomicWriteJson(join(holds, `${id}.json`), holdDoc);
    } catch {
      counts.holdUnsaved = (counts.holdUnsaved ?? 0) + 1;
    }
  }
  // the rotation: the traversal advances by the batch; reaching the last name starts over
  const last = batch.at(-1) ?? null;
  const next = start + batch.length >= names.length ? null : last;
  cursorMemo.set(store, next);
  try {
    atomicWriteJson(passFile, { cursor: next });
  } catch {
    counts.cursorUnsaved = true; // reported (degraded); the rotation goes on in memory
  }
  // store-wide counts from the holds of records that still exist
  const present = new Set(names);
  for (const h of readdirSync(holds).filter(n => n.endsWith(".json") && n !== "_pass.json")) {
    if (!present.has(h)) continue;
    let hold;
    try {
      hold = JSON.parse(readFileSync(join(holds, h), "utf8"));
      if (!hold || typeof hold !== "object") continue;
    } catch {
      continue;
    }
    if (hold?.state === "confirmed") counts.confirmed++;
    else if (hold?.state === "unconfirmed-final") counts.final++;
    else if (hold?.state === "unconfirmed") {
      counts.unconfirmed++;
      if (hold.lastResult === "mismatch") counts.mismatch++;
      else if (num(hold.unavailableStreak) >= 2) counts.waiting++;
    }
  }
  return counts;
}
