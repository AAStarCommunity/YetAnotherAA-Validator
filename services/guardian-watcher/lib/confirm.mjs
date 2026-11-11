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
//   unconfirmed        a mismatch, or the second provider could not answer yet: retried each tick;
//   unconfirmed-final  still unconfirmed after CONFIRM_MAX_ATTEMPTS: never published, reported.
// There is no bypass. Only the second provider's host is stored, never its URL.
import { mkdtempSync, rmSync, readdirSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Store, atomicWriteJson, readJson } from "./store.mjs";

export const CONFIRM_MAX_ATTEMPTS = 10;

/** A record that names someone as having done wrong: flagged, on the owner route or a BLS action.
 * Unattributed and public-route records accuse nobody, so they are not held. */
export function isAccusatory(rec) {
  return !!rec?.verdict?.flagged && (rec.route === "owner" || rec.route === "bls");
}

/** Fields that record when or how often a record was seen, not what it says. */
const WHEN = new Set(["id", "seenAt", "firstSeen", "exhaustedAfter", "provenAt", "lastReasons"]);

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
    const { status } = await runOnce(second, c, temp, rs, ident, now === undefined ? {} : { now });
    if (!status.ok) return { state: "unavailable", reason: "second provider tick failed" };
    if (!(status.cursor >= block))
      return { state: "unavailable", reason: "block not finalized on the second provider" };
    const mine = sameAction(temp, rec);
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
  return getHold(store, Store.recordId(rec))?.state === "confirmed";
}

/**
 * One confirmation pass over every accusatory record not yet confirmed or final. `secondHost` is
 * stored with each hold (never the URL). Returns counts.
 */
export async function confirmPending(
  store,
  second,
  secondHost,
  cfg,
  rs,
  ident,
  { runOnce, now } = {}
) {
  const counts = { confirmed: 0, unconfirmed: 0, final: 0, checked: 0 };
  const dir = join(store.dir, "records");
  const holds = join(store.dir, "holds");
  if (!existsSync(holds)) {
    const { mkdirSync } = await import("node:fs");
    mkdirSync(holds, { recursive: true, mode: 0o700 });
  }
  for (const f of readdirSync(dir).filter(n => n.endsWith(".json"))) {
    let rec;
    try {
      rec = JSON.parse(readFileSync(join(dir, f), "utf8"));
    } catch {
      continue;
    }
    if (!isAccusatory(rec)) continue;
    const id = Store.recordId(rec);
    const prev = getHold(store, id);
    if (prev?.state === "confirmed") {
      counts.confirmed++;
      continue;
    }
    if (prev?.state === "unconfirmed-final") {
      counts.final++;
      continue;
    }
    counts.checked++;
    let r;
    try {
      r = await reRun(second, cfg, rs, ident, rec, { runOnce, now });
    } catch {
      r = { state: "unavailable", reason: "confirmation run threw" };
    }
    const attempts = (prev?.attempts ?? 0) + 1;
    const state =
      r.state === "confirmed"
        ? "confirmed"
        : attempts >= CONFIRM_MAX_ATTEMPTS
          ? "unconfirmed-final"
          : "unconfirmed";
    atomicWriteJson(join(holds, `${id}.json`), {
      id,
      state,
      attempts,
      lastResult: r.state,
      ...(r.fields ? { fields: r.fields } : {}),
      ...(r.reason ? { reason: r.reason } : {}),
      secondProvider: secondHost,
      firstHeldAt: prev?.firstHeldAt ?? new Date(now ?? Date.now()).toISOString(),
      lastCheckedAt: new Date(now ?? Date.now()).toISOString(),
    });
    counts[
      state === "confirmed" ? "confirmed" : state === "unconfirmed-final" ? "final" : "unconfirmed"
    ]++;
  }
  return counts;
}
