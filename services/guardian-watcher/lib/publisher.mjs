// Publication loop (W2c, M0 §5.3): after each scan, every FLAGGED record is published through the
// sinks, resuming its durable journal (store/publications/<id>.json). publishRecord does the
// per-record work and is crash-safe stage by stage; this module only decides what to run, reads
// the writer's roles from chain, builds the sinks and delivers the run's alerts.
import { ethers } from "ethers";
import { Store, atomicWriteJson } from "./store.mjs";
import { publishRecord, PersistError } from "./publish.mjs";
import { recordFile } from "./record-file.mjs";
import { MAX_RECORD_BYTES } from "./cid.mjs";
import { SafeError, safeText, guarded } from "./safe-error.mjs";
import { assertWriterRole } from "../sinks/registry.mjs";

/**
 * Fully done: nothing left to run, unless a weekly reverify of the pins is due. With `pinners`
 * (configured names) every one must hold a current pin, so a failed pin keeps being repaired
 * (Codex W2c R1 M5); with `cid` the journal must describe the record's current bytes, and a
 * recorded bytes change is never done (M4). `ignoreRegistry`: everything but the registry stage
 * (an acknowledged registry incident parks only that stage: R2).
 */
export function isDone(rec, st, { pinners, cid, ignoreRegistry = false } = {}) {
  if (!st?.published || !st.telegram?.at) return false;
  if (st.bytesChanged) return false;
  if (cid !== undefined && st.cid !== cid) return false;
  if (pinners && !pinners.every(n => st.pins?.[n]?.current)) return false;
  // a pin not verified since a failed check is not done: it is retried (Codex W2c R20 #3)
  if (uncheckedPin(st, pinners)) return false;
  if (rec.route !== "bls" || ignoreRegistry) return true; // owner route: repo + Telegram only
  return st.registry?.phase === "confirmed";
}

/** An unresolved, unacknowledged registry incident, or a recorded bytes change: alerted on every
 * run. */
const openIncident = st =>
  ((st?.registry?.phase === "conflict" || st?.registry?.phase === "reverted") &&
    !st.registry.ack) ||
  !!st?.bytesChanged;

/**
 * What still needs someone's attention in a journal, beyond stalls (Codex W2c R20): an unresolved
 * incident, a final receipt whose entry was not visible, a pin not verified since a failed check.
 * Kept in the record's schedule entry and counted store-wide until the journal no longer says so.
 */
export function attentionKind(pub, pinners) {
  if (openIncident(pub)) return "incident";
  if (pub?.registry?.phase === "landed" && pub.registry.inconsistentAt) return "inconsistent";
  // a receipt without the Disclosed event, while the stage has not moved on (Codex W2c R21 #1)
  const ph = pub?.registry?.phase;
  if (pub?.registry?.noEventAt && (ph === "signed" || ph === "sent" || ph === "landed"))
    return "inconsistent";
  if (uncheckedPin(pub, pinners)) return "unverified";
  return null;
}
/** A CONFIGURED provider's current pin whose last re-verification failed (Codex W2c R20 #3); an
 * unconfigured provider is never retried, so it cannot hold the record (R21 #3). */
function uncheckedPin(pub, pinners) {
  const names = pinners ?? Object.keys(pub?.pins ?? {});
  return names.some(n => pub?.pins?.[n]?.current && pub.pins[n].checkError);
}
const withAttention = (e, kind) => {
  const { attention: _old, ...rest } = e ?? {};
  void _old;
  return kind ? { ...rest, attention: kind } : rest;
};

/** An acknowledged registry incident: the registry stage is parked; everything else still runs. */
const parked = st =>
  (st?.registry?.phase === "conflict" || st?.registry?.phase === "reverted") && !!st.registry.ack;

/** Per-pass bounds (Codex W2c R1 H3, R2): a sink outage or a large history cannot hold the next
 * scan for long. At most PASS_MAX_PARSE record files are read per pass (rotating), at most
 * PASS_MAX_RECORDS are published, and none is started after PASS_MAX_MS (always at least one). */
export const PASS_MAX_RECORDS = 25;
export const PASS_MAX_MS = 120_000;
export const PASS_MAX_PARSE = 500;

/** A record's id, validated, or null (a parseable file with an unusable identity: R2 M7). */
function recordIdOf(rec) {
  // Always derived from the record's own fields; a stored `id` must agree with it, so an alias
  // (a copy with another file name and a rewritten id) is refused (Codex W2c R4).
  try {
    const id = Store.recordId(rec);
    if (typeof id !== "string" || !/^[A-Za-z0-9._-]+$/.test(id)) return null;
    if (rec.id !== undefined && rec.id !== id) return null;
    return id;
  } catch {
    return null;
  }
}

/**
 * Run publication for the flagged records of this pass's batch. Returns { alerts, counts,
 * stopped, reverifyRemaining }. A PersistError stops the pass (state is no longer durable); any
 * other error of one record is an alert and the pass moves on: one bad record never blocks the
 * others. `reverifyGen`: the open weekly reverify generation (a done record whose pins were not
 * yet re-checked in it runs again, with reverify), or null.
 */
/**
 * The disclose stalls of the WHOLE store (DSR): each record's stall (fee-capped, unfunded, or
 * "unknown" when its journal is unreadable) is kept in that record's entry of the publication
 * schedule, set whenever the record is read and written atomically with the rotation itself, so
 * a stall and the cursor past it are persisted together or not at all (Codex W2c R13/R14: a
 * separate index could be lost or go stale independently). A record outside a pass's batch keeps
 * its entry. When the schedule is absent or unreadable the state is unknown until one complete
 * sweep has read every record again: bounded by the pass budgets, never a full rebuild in one go.
 */
/** The stall a journal is in: none once the registry stage is final: confirmed (Codex W2c R12 #1)
 * or a terminal incident (reverted / conflict never sign again and are reported as incidents; a
 * fee cap left on them could never clear: R13 #2). */
const NO_STALL_PHASES = new Set(["confirmed", "reverted", "conflict"]);
export function stallKind(pub) {
  const r = pub?.registry;
  if (!r || NO_STALL_PHASES.has(r.phase)) return null;
  if (r.feeCapped) return "feeCapped";
  if (/INSUFFICIENT_FUNDS/.test(String(r.lastBroadcastError ?? ""))) return "insufficientFunds";
  return null;
}
function countStalls(sched) {
  const all = Object.values(sched?.entries ?? {}).map(e => e?.stall);
  // unknown until the stall entries are known complete (stallsTracked, no pending sweep)
  const unknown =
    sched?.stallsTracked !== true || sched?.stallsNeed !== undefined || all.includes("unknown");
  // records whose publication is failing (a stage that has not succeeded since, a run that threw,
  // an unreadable file or journal): store-wide, until a retry succeeds (Codex W2c R19 #1)
  const failing =
    Object.values(sched?.entries ?? {}).filter(e => e?.failing === true || e?.stageFailed === true)
      .length + Object.keys(sched?.badFiles ?? {}).length;
  const att = Object.values(sched?.entries ?? {}).map(e => e?.attention);
  return {
    incidents: att.filter(k => k === "incident").length,
    inconsistent: att.filter(k => k === "inconsistent").length,
    unverified: att.filter(k => k === "unverified").length,
    feeCapped: all.filter(k => k === "feeCapped").length,
    insufficientFunds: all.filter(k => k === "insufficientFunds").length,
    failing,
    ...(unknown ? { unknown: true } : {}),
  };
}
/** Store-wide counts from the schedule as last computed (in memory) or saved. */
export function stallCounts(store) {
  return countStalls(getSchedule(store));
}
const withStall = (e, kind) => {
  const { stall: _old, ...rest } = e ?? {};
  void _old;
  return kind ? { ...rest, stall: kind } : rest;
};

export async function publishPending(
  store,
  sinks,
  {
    reverifyGen = null,
    maxPendingMs,
    maxRecords = PASS_MAX_RECORDS,
    maxMs = PASS_MAX_MS,
    maxParse = PASS_MAX_PARSE,
    now = Date.now,
  } = {}
) {
  // The budget covers preparation too (Codex W2c R3): it starts before the directory is read.
  const t0 = now();
  const alerts = [];
  const counts = {
    flagged: 0,
    done: 0,
    ran: 0,
    incidents: 0,
    failed: 0,
    parked: 0,
    deferred: 0,
    unreadable: 0,
    feeCapped: 0, // a disclose tx whose replacement needs a fee above maxFeePerGas (#411 F1)
    insufficientFunds: 0, // a disclose tx the writer cannot pay for (#411 F1)
  };
  const pinners = (sinks.pinners ?? []).map(p => p.name);
  const sched = getSchedule(store);
  const entries = { ...(sched.entries ?? {}) };
  // Absent, unreadable or written before stalls were tracked: unknown until a sweep that began at
  // the first name has completed (the same arithmetic as reverifyGenNeed: one more sweep when a
  // traversal is already part-way through).
  let stallsNeed = sched.stallsNeed;
  // (an unreadable schedule is { unreadable: true }: not tracked either)
  // A process's first pass also re-establishes them (Codex W2c R15 #2): saves lost before a
  // restart (rotation kept only in memory) may cover any number of passes, so the saved stalls are
  // not trusted until a sweep has re-read every record; within the budgets, marked unknown.
  // (its own per-process set: publishPhase may save the schedule, and fill the memo, first)
  if (sched.stallsTracked !== true || !stallsReconciling.has(store))
    stallsNeed = (sched.sweeps ?? 0) + (sched.cursor ? 2 : 1);
  stallsReconciling.add(store);
  if (sched.unreadable)
    alerts.push("publication schedule unreadable; stall state unknown until a full sweep");
  // A bounded batch of record files, in sorted order from the cursor (the last file read). A
  // SWEEP is one traversal from the first name to the last; it never wraps inside a batch, so a
  // completed sweep visited every file that existed throughout it (Codex W2c R4). Listing the names
  // (no contents) is the only full-directory step: ~45 ms for 50 000 files, measured.
  const names = store.recordFiles();
  let sweeps = sched.sweeps ?? 0;
  let start = 0;
  if (sched.cursor) {
    const k = names.findIndex(n => n > sched.cursor);
    if (k < 0) sweeps += 1; // the previous traversal had reached the end: it is complete
    start = k < 0 ? 0 : k;
  }
  const candidates = names.slice(start, start + maxParse);
  const badFiles = { ...(sched.badFiles ?? {}) };
  // a canonical file whose journal was never examined keeps the stall state unknown (Codex W2c
  // R15 #3), keyed by its file name; retired with the file like any entry
  const unknownFile = name => {
    const nid = String(name).replace(/\.json$/, "");
    // failing: alerted on its own, it does not hold a reverify generation open (#413 review F2)
    if (/^[A-Za-z0-9-]{1,200}$/.test(nid))
      entries[nid] = { ...withStall(entries[nid], "unknown"), failing: true };
    // a file name that cannot be an id is kept apart, so its failure stays counted while it is
    // outside later batches; cleared when it reads as a valid record or is gone (Codex W2c R21 #2)
    else badFiles[String(name).slice(0, 300)] = true;
  };
  const bad = [];
  const seenIds = new Set();
  const work = [];
  let read = 0;
  for (const name of candidates) {
    // the deadline covers preparation too; always at least one file, so a sweep progresses
    if (read > 0 && now() - t0 >= maxMs) break;
    read++;
    let rec;
    let id;
    let prev;
    let cid;
    try {
      rec = store.readRecordFile(name, 2 * MAX_RECORD_BYTES);
      if (!rec?.verdict?.flagged) {
        delete badFiles[String(name).slice(0, 300)];
        // an unflagged record has no publication: drop any entry its file left (e.g. "unknown"
        // while it was unreadable), so a repaired file settles the stalls and the generation
        // (Codex W2c R16)
        delete entries[String(name).replace(/\.json$/, "")];
        continue;
      }
      id = recordIdOf(rec);
      // the file name, the derived id and the stored id must agree, and one id is one record: a
      // restored copy under another name would run on a stale journal (Codex W2c R3)
      if (!id || name !== `${id}.json` || seenIds.has(id)) {
        bad.push(name);
        unknownFile(name);
        continue;
      }
      seenIds.add(id);
      delete badFiles[String(name).slice(0, 300)];
      counts.flagged++;
      try {
        prev = store.getPublication(id) ?? {};
      } catch {
        // never reset: not published (nor signed for) until repaired by hand; its stall is unknown
        entries[id] = { ...withStall(entries[id], "unknown"), failing: true };
        counts.failed++;
        alerts.push(`${id}: publication journal unreadable; record skipped, journal kept as is`);
        continue;
      }
      // every record read is refreshed from its journal, deferred ones included (Codex W2c R15 #1)
      entries[id] = withAttention(
        withStall(entries[id], stallKind(prev)),
        attentionKind(prev, pinners)
      );
      try {
        cid = recordFile(rec).cid;
      } catch {
        cid = null; // publishRecord fails on it, and says so
      }
    } catch {
      bad.push(name);
      unknownFile(name);
      continue;
    }
    // Registered before any limit applies, so a deferred or newly found record still counts
    // toward the reverify generation (Codex W2c R3).
    const e = (entries[id] = { ...(entries[id] ?? {}) });
    const reverify = reverifyGen !== null && e.reverifiedGen !== reverifyGen;
    const isParked = parked(prev);
    if (!reverify && isDone(rec, prev, { pinners, cid, ignoreRegistry: isParked })) {
      if (isParked) counts.parked++;
      else counts.done++;
      // its stall was refreshed from prev above: a done record clears a stale one (W2c R12 #1)
      entries[id] = { ...e, done: true, failing: false, stageFailed: false };
      if (openIncident(prev)) counts.incidents++;
      continue;
    }
    work.push({ rec, id, cid, reverify, isParked, prev });
  }
  if (bad.length) {
    counts.unreadable += bad.length;
    counts.failed += bad.length;
    alerts.push(
      // a count only: a file name is the directory's content and may carry anything (a token
      // pasted into a name), so it never reaches an alert, alerts-latest.json or Telegram (R22)
      `${bad.length} record file(s) unreadable, oversized, duplicated or without a matching id; not published (see records/ on the host)`
    );
  }
  // Least recently run first (failures included), so a bounded pass rotates through a backlog.
  work.sort((a, b) => (entries[a.id]?.lastRunAt ?? 0) - (entries[b.id]?.lastRunAt ?? 0));
  let stopped = false;
  for (const { rec, id, cid, reverify, isParked, prev: listed } of work) {
    if (stopped || counts.ran >= maxRecords || (counts.ran > 0 && now() - t0 >= maxMs)) {
      counts.deferred++;
      if (openIncident(listed)) counts.incidents++;
      continue;
    }
    counts.ran++;
    const e = entries[id] ?? {};
    // the journal as it is now, not as it was when the batch was listed (Codex W2c R3)
    let prev;
    try {
      prev = store.getPublication(id) ?? {};
    } catch {
      entries[id] = { ...withStall(entries[id], "unknown"), failing: true };
      counts.failed++;
      alerts.push(`${id}: publication journal unreadable; record skipped, journal kept as is`);
      continue;
    }
    try {
      const r = await publishRecord(
        rec,
        isParked ? { ...sinks, registry: null } : sinks, // a parked incident stops only the registry
        prev,
        { persist: st => store.putPublication(id, st), reverify, maxPendingMs }
      );
      for (const a of r.alerts) alerts.push(`${id}: ${a}`);
      const done = isDone(rec, r.state, { pinners, cid, ignoreRegistry: isParked });
      const stageFailed = (r.failures ?? []).length > 0;
      if (stageFailed) counts.failed++; // a sink failed or refused: the pass is not ok (R3)
      entries[id] = {
        ...withAttention(withStall(e, stallKind(r.state)), attentionKind(r.state, pinners)),
        lastRunAt: now(),
        done,
        failing: false,
        // an unresolved stage failure stays on the record until a retry succeeds, so it counts
        // store-wide while the record is outside later batches (Codex W2c R19 #1)
        stageFailed: stageFailed && !done,
        // re-checked in this generation even if a stage failed: the failure is reported (ok =
        // false, alerts), and a broken provider must not hold every generation open
        ...(reverify ? { reverifiedGen: reverifyGen } : {}),
      };
      if (done) counts.done++;
      if (openIncident(r.state)) counts.incidents++;
      // the two disclose stalls the watcher must report as degraded, store-wide (DSR)
      if (r.state.registry?.feeCapped) counts.feeCapped++;
      if (/INSUFFICIENT_FUNDS/.test(String(r.state.registry?.lastBroadcastError ?? "")))
        counts.insufficientFunds++;
    } catch (err) {
      // a failure still rotates (R2); the stall is what the journal now says (it may have advanced
      // before the failure), unknown if it cannot be read
      let kind;
      let att = e.attention ?? null;
      try {
        const cur = store.getPublication(id);
        kind = stallKind(cur);
        att = attentionKind(cur, pinners);
      } catch {
        kind = "unknown";
      }
      entries[id] = { ...withAttention(withStall(e, kind), att), lastRunAt: now(), failing: true };
      counts.failed++;
      if (err instanceof PersistError) {
        alerts.push(`${id}: ${err.message}; publication pass stopped`);
        stopped = true;
        continue;
      }
      alerts.push(`${id}: ${safeText("publish", err)}`);
    }
  }
  // An entry is retired only on established absence: its canonical file is not in this pass's
  // listing (an orphan must not hold a generation open; a live record keeps its state: R4).
  const listed = new Set(names);
  for (const id of Object.keys(entries)) if (!listed.has(`${id}.json`)) delete entries[id];
  for (const n of Object.keys(badFiles)) if (!listed.has(n)) delete badFiles[n];
  // The traversal advances by the files actually read; reaching the last name completes it.
  const lastRead = candidates[read - 1] ?? null;
  const reachedEnd = start + read >= names.length;
  let cursor = lastRead;
  if (reachedEnd) {
    sweeps += 1;
    cursor = null;
  }
  const { sweep: _oldSweep, ...rest } = sched;
  void _oldSweep;
  const { unreadable: _u, ...kept } = rest;
  void _u;
  const { stallsNeed: _n, badFiles: _b, ...kept2 } = kept;
  (void _n, _b);
  const next = {
    ...kept2,
    cursor,
    entries,
    sweeps,
    stallsTracked: true,
    ...(Object.keys(badFiles).length ? { badFiles } : {}),
    ...(stallsNeed !== undefined && sweeps < stallsNeed ? { stallsNeed } : {}),
  };
  const reverifyRemaining =
    reverifyGen === null
      ? 0
      : // a record that keeps failing is alerted on its own; it does not hold the generation open
        Object.values(entries).filter(x => !x.failing && x.reverifiedGen !== reverifyGen).length;
  if (!saveSchedule(store, next)) {
    counts.failed++;
    alerts.push("publication schedule not saved; rotation kept in memory, retried next pass");
  }
  return { alerts, counts, stopped, reverifyRemaining, sweeps, stalls: countStalls(next) };
}

// The schedule as last computed in this process, so a failing schedule write keeps rotation fair
// in memory while it is retried (Codex W2c R3).
const scheduleMemo = new WeakMap();
// the stores whose stalls this process has started re-establishing (Codex W2c R15 #2)
const stallsReconciling = new WeakSet();
function getSchedule(store) {
  return scheduleMemo.get(store) ?? store.getSchedule();
}
function saveSchedule(store, s) {
  scheduleMemo.set(store, s);
  try {
    store.putSchedule(s);
    return true;
  } catch {
    return false;
  }
}

/**
 * Deliver the run's alerts as ONE Telegram message, only when the set differs from the last one
 * sent or `repeatMs` has passed (a standing incident keeps reminding, hourly by default, without
 * a message every minute). The alert state is local and durable. A failed send is reported in
 * status, never retried in a loop, and never alerted through itself.
 */
export async function deliverAlerts(
  store,
  telegram,
  alerts,
  { now = Date.now(), repeatMs = 3_600_000, maxParts = ALERT_MAX_PARTS, detailsSaved = true } = {}
) {
  if (!alerts.length) {
    store.putAlertState({ ...(store.getAlertState() ?? {}), lastSetHash: null });
    return { sent: false, reason: "none" };
  }
  const setHash = ethers.id(JSON.stringify([...alerts].sort()));
  const last = store.getAlertState() ?? {};
  const due = last.lastSetHash !== setHash || now - (last.lastSentAt ?? 0) >= repeatMs;
  if (!due) return { sent: false, reason: "unchanged" };
  if (!telegram) return { sent: false, reason: "no telegram sink" };
  // Every chunk must be delivered before the set counts as sent (Codex W2c R1 M6): the Telegram
  // sink truncates at 4000 characters, so one long message would silently lose its tail. A failure
  // part-way leaves the set unsent; the next run sends all of it again (at least once).
  // At most maxParts messages per pass (Codex W2c R2): beyond that the last part says how many
  // lines are not shown; the full list is in alerts-latest.json. Never a silent cut.
  let chunks = alertChunks(alerts);
  const truncated = chunks.length > maxParts;
  if (truncated) {
    const shown = chunks.slice(0, maxParts - 1);
    const hidden = chunks.slice(maxParts - 1).reduce((n, c) => n + c.length, 0);
    chunks = [
      ...shown,
      [`... and ${hidden} more alert line(s) not shown; full list in alerts-latest.json`],
    ];
  }
  for (let i = 0; i < chunks.length; i++) {
    const head = `DVT guardian watcher: ${alerts.length} alert(s)`;
    const part = chunks.length > 1 ? ` (part ${i + 1}/${chunks.length})` : "";
    try {
      await telegram.send([head + part, ...chunks[i]].join("\n"));
    } catch (e) {
      return { sent: false, reason: safeText("telegram", e), partsSent: i };
    }
  }
  // A shortened digest points at alerts-latest.json: without that file it is not acknowledged, so
  // the set goes out again next pass (Codex W2c R3).
  if (truncated && !detailsSaved)
    return {
      sent: false,
      reason: "alert details not stored; digest re-sent next pass",
      parts: chunks.length,
    };
  store.putAlertState({ ...last, lastSetHash: setHash, lastSentAt: now });
  return { sent: true, parts: chunks.length };
}

/** Telegram text budget per message, under the sink's 4000-character cut with room for a header. */
export const ALERT_CHUNK_CHARS = 3500;
/** Telegram messages per pass, at most. */
export const ALERT_MAX_PARTS = 5;

/** Alerts grouped into messages of at most `max` characters; an alert longer than that is split
 * into numbered pieces, so nothing is ever cut off. */
export function alertChunks(alerts, max = ALERT_CHUNK_CHARS) {
  const lines = [];
  for (const a of alerts) {
    const t = String(a);
    if (t.length <= max) lines.push(t);
    else {
      const n = Math.ceil(t.length / (max - 16));
      for (let i = 0; i < n; i++)
        lines.push(`[${i + 1}/${n}] ${t.slice(i * (max - 16), (i + 1) * (max - 16))}`);
    }
  }
  const out = [];
  let cur = [];
  let len = 0;
  for (const l of lines) {
    if (cur.length && len + l.length + 1 > max) {
      out.push(cur);
      cur = [];
      len = 0;
    }
    cur.push(l);
    len += l.length + 1;
  }
  if (cur.length) out.push(cur);
  return out;
}

const ROLE_ABI = [
  "function owner() view returns (address)",
  "function MAX_VALIDATORS() view returns (uint256)",
  "function validatorAtSlot(uint8) view returns (address)",
];

/**
 * The roles the writer must not hold, read from chain at `blockTag` on every run: the aggregator
 * owner and every registered guardian (validatorAtSlot[1..MAX_VALIDATORS]); the deployer comes
 * from the release manifest. Fails closed: any unreadable value is an error, and an empty
 * guardian set is refused by assertWriterRole.
 */
export async function readRoles(provider, aggregator, deployer, blockTag = "finalized") {
  return guarded("role read", async () => {
    const agg = new ethers.Contract(aggregator, ROLE_ABI, provider);
    const aggregatorOwner = await agg.owner({ blockTag });
    const max = Number(await agg.MAX_VALIDATORS({ blockTag }));
    if (!Number.isSafeInteger(max) || max < 1 || max > 255)
      throw new SafeError("role read: MAX_VALIDATORS out of range");
    const slots = await Promise.all(
      Array.from({ length: max }, (_, i) => agg.validatorAtSlot(i + 1, { blockTag }))
    );
    const guardians = slots.filter(a => a !== ethers.ZeroAddress);
    return { deployer, aggregatorOwner, guardians };
  });
}

/**
 * Roles at the newest state the node will show: "latest" must answer; "pending" is added when the
 * node serves it (a role being granted in the mempool is then refused too). The union is returned,
 * so a writer appointed in either is refused. A residual remains: a role granted after this read
 * and mined before our tx. Closing it needs an on-chain constraint (M0 §5.5), not a watcher check.
 */
export async function currentRoles(provider, aggregator, deployer) {
  const latest = await readRoles(provider, aggregator, deployer, "latest");
  let pending = null;
  try {
    pending = await readRoles(provider, aggregator, deployer, "pending");
  } catch {
    pending = null; // a node without pending state: latest alone (still fresh at sign time)
  }
  if (!pending) return latest;
  const owners = [latest.aggregatorOwner, pending.aggregatorOwner];
  return {
    deployer,
    aggregatorOwner: latest.aggregatorOwner,
    // every address that holds the owner role at either state is refused as a guardian would be
    guardians: [...new Set([...latest.guardians, ...pending.guardians, ...owners])],
  };
}

/**
 * One publication pass, after a scan. `built` comes from buildSinks (startup). The writer's roles
 * are re-read from chain on every pass; if they cannot be read, or the writer holds one, the
 * registry stage is skipped this pass (pins, mirror and Telegram still run) and that is alerted.
 * Returns the status block for status.json.
 */
export async function publishPhase(
  store,
  chain,
  cfg,
  p,
  built,
  { now = Date.now(), degraded = null } = {}
) {
  const out = { at: new Date(now).toISOString() };
  const alerts = [];
  // a degraded watcher (lag past maxLagBlocks, a budget stop, a slow tick, trace capability, no
  // second provider...) is alerted through the same de-duplicated channel (DSR, W2c). The reasons are
  // the watcher's own wording (SafeError rule), never an RPC's text.
  if (Array.isArray(degraded) && degraded.length)
    alerts.push(`watcher degraded: ${degraded.filter(x => typeof x === "string").join("; ")}`);
  let registry = null;
  try {
    const roles = await readRoles(chain, cfg.aggregator, p.registry.deployer);
    assertWriterRole(await built.wallet.getAddress(), roles);
    // The pass's set (finalized) gates the stage; the sink re-reads the roles at the latest AND
    // pending state right before each signature, and refuses if either holds the writer.
    registry = built.registryFor(roles, () =>
      currentRoles(chain, cfg.aggregator, p.registry.deployer)
    );
    out.guardians = roles.guardians.length;
  } catch (e) {
    out.registrySkipped = safeText("writer role check", e);
    alerts.push(`registry stage skipped this pass: ${out.registrySkipped}`);
  }
  // The weekly reverify is a generation: opened when due, closed only when every done record has
  // been re-checked in it, however many bounded passes that takes (Codex W2c R2).
  // Contract (Codex W2c R5): a generation covers the records that existed when it opened. It
  // closes only after a full directory traversal that began after it opened (so every such record
  // is registered and re-checked, whatever the bounded batches had reached). A record added later
  // is not done, so it needs no re-check: it is published by the normal path when reached.
  const schedFailures = []; // generation-transition schedule writes that failed (Codex W2c R4)
  // an unreadable alerts.json must not abort every pass (#413 review B1): it only holds the digest
  // dedupe and lastReverifyAt, so it is reset (a digest may repeat, a re-check may run early),
  // alerted, and the pass is not ok. If the reset fails too, the pass throws and is degraded.
  let alertStateReset = false;
  try {
    store.getAlertState();
  } catch {
    store.putAlertState({});
    alertStateReset = true;
    alerts.push("alert state (alerts.json) was unreadable; reset");
  }
  const meta = store.getAlertState() ?? {};
  let gen = getSchedule(store).reverifyGen ?? null;
  if (gen === null && now - (meta.lastReverifyAt ?? 0) >= p.reverifyEveryMs) {
    gen = now;
    const sc = getSchedule(store);
    // A traversal already under way began before the generation: it does not count, the next
    // full one does.
    const need = (sc.sweeps ?? 0) + (sc.cursor ? 2 : 1);
    if (!saveSchedule(store, { ...sc, reverifyGen: gen, reverifyGenNeed: need }))
      schedFailures.push("generation open");
  }
  // A generation opened before reverifyGenNeed existed gets a finite threshold now, needing a
  // fresh traversal (Codex W2c R5); without it the generation could never close.
  if (gen !== null && getSchedule(store).reverifyGenNeed === undefined) {
    const sc = getSchedule(store);
    const { reverifyGenSweeps, ...rest } = sc;
    void reverifyGenSweeps;
    if (!saveSchedule(store, { ...rest, reverifyGenNeed: (sc.sweeps ?? 0) + (sc.cursor ? 2 : 1) }))
      schedFailures.push("generation migration");
  }
  const genNeed = getSchedule(store).reverifyGenNeed ?? Infinity;
  const res = await publishPending(
    store,
    { pinners: built.pinners, mirror: built.mirror, telegram: built.telegram, registry },
    { reverifyGen: gen, maxPendingMs: p.maxPendingMs, ...(p.limits ?? {}) }
  );
  const reverified =
    gen !== null && !res.stopped && res.reverifyRemaining === 0 && res.sweeps >= genNeed;
  if (reverified) {
    store.putAlertState({ ...(store.getAlertState() ?? {}), lastReverifyAt: gen });
    const { reverifyGen, reverifyGenNeed, ...rest } = getSchedule(store);
    void reverifyGen;
    void reverifyGenNeed;
    if (!saveSchedule(store, rest)) schedFailures.push("generation close");
  }
  alerts.push(...res.alerts);
  for (const w of schedFailures)
    alerts.push(`publication schedule not saved at ${w}; kept in memory, retried next pass`);
  let detailsSaved = true;
  try {
    store.putAlertList(alerts);
  } catch {
    detailsSaved = false;
  }
  const delivery = await deliverAlerts(store, built.telegram, alerts, {
    now,
    repeatMs: p.alertRepeatMs,
    detailsSaved,
  });
  const deliveredOk =
    delivery.sent === true || delivery.reason === "none" || delivery.reason === "unchanged";
  return {
    ...out,
    ...res.counts,
    stalls: res.stalls, // store-wide (DSR), not this batch's counts
    failed: res.counts.failed + schedFailures.length,
    stopped: res.stopped,
    reverifying: gen !== null && !reverified ? { gen, remaining: res.reverifyRemaining } : null,
    reverified,
    alerts: alerts.length,
    delivery,
    // Explicit pass result (Codex W2c R2): no failed record, no stop, no skipped registry stage,
    // and the alerts delivered. Deferred work is pending, not a failure.
    ok:
      !res.stopped &&
      res.counts.failed === 0 &&
      !schedFailures.length &&
      !out.registrySkipped &&
      !alertStateReset &&
      deliveredOk,
  };
}
