// Publication loop (W2c, M0 §5.3): after each scan, every FLAGGED record is published through the
// sinks, resuming its durable journal (store/publications/<id>.json). publishRecord does the
// per-record work and is crash-safe stage by stage; this module only decides what to run, reads
// the writer's roles from chain, builds the sinks and delivers the run's alerts.
import { ethers } from "ethers";
import { Store } from "./store.mjs";
import { publishRecord, PersistError } from "./publish.mjs";
import { recordFile } from "./record-file.mjs";
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
  if (rec.route !== "bls" || ignoreRegistry) return true; // owner route: repo + Telegram only
  return st.registry?.phase === "confirmed";
}

/** An unresolved, unacknowledged registry incident, or a recorded bytes change: alerted on every
 * run. */
const openIncident = st =>
  ((st?.registry?.phase === "conflict" || st?.registry?.phase === "reverted") &&
    !st.registry.ack) ||
  !!st?.bytesChanged;

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
  try {
    const id = rec.id ?? Store.recordId(rec);
    return typeof id === "string" && /^[A-Za-z0-9._-]+$/.test(id) ? id : null;
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
  };
  const pinners = (sinks.pinners ?? []).map(p => p.name);
  const sched = store.getSchedule();
  const entries = { ...(sched.entries ?? {}) };
  // A bounded, rotating batch of record files: the cursor names the last file read.
  const names = store.recordFiles();
  let start = 0;
  if (sched.cursor) {
    const k = names.findIndex(n => n > sched.cursor);
    start = k < 0 ? 0 : k;
  }
  const batch = [];
  for (let i = 0; i < Math.min(maxParse, names.length); i++)
    batch.push(names[(start + i) % names.length]);
  const bad = [];
  const work = [];
  for (const name of batch) {
    let rec;
    let id;
    let prev;
    let cid;
    try {
      rec = store.readRecordFile(name);
      if (!rec?.verdict?.flagged) continue;
      id = recordIdOf(rec);
      if (!id) {
        bad.push(name);
        continue;
      }
      counts.flagged++;
      try {
        prev = store.getPublication(id) ?? {};
      } catch {
        // never reset: not published (nor signed for) until repaired by hand
        counts.failed++;
        alerts.push(`${id}: publication journal unreadable; record skipped, journal kept as is`);
        continue;
      }
      try {
        cid = recordFile(rec).cid;
      } catch {
        cid = null; // publishRecord fails on it, and says so
      }
    } catch {
      bad.push(name);
      continue;
    }
    const e = entries[id] ?? {};
    // Every known flagged record is re-checked once per generation, done or not (its current pins
    // are otherwise skipped).
    const reverify = reverifyGen !== null && e.reverifiedGen !== reverifyGen;
    const isParked = parked(prev);
    if (!reverify && isDone(rec, prev, { pinners, cid, ignoreRegistry: isParked })) {
      if (isParked) counts.parked++;
      else counts.done++;
      entries[id] = { ...e, done: true };
      if (openIncident(prev)) counts.incidents++;
      continue;
    }
    work.push({ rec, id, prev, cid, reverify, isParked });
  }
  if (bad.length) {
    counts.unreadable += bad.length;
    counts.failed += bad.length;
    alerts.push(
      `${bad.length} record file(s) unreadable or without a usable id; not published (first: ${bad.slice(0, 5).join(", ")})`
    );
  }
  // Least recently run first (failures included), so a bounded pass rotates through a backlog.
  work.sort((a, b) => (entries[a.id]?.lastRunAt ?? 0) - (entries[b.id]?.lastRunAt ?? 0));
  const t0 = now();
  let stopped = false;
  for (const { rec, id, prev, cid, reverify, isParked } of work) {
    if (stopped || counts.ran >= maxRecords || (counts.ran > 0 && now() - t0 >= maxMs)) {
      counts.deferred++;
      if (openIncident(prev)) counts.incidents++;
      continue;
    }
    counts.ran++;
    const e = entries[id] ?? {};
    try {
      const r = await publishRecord(
        rec,
        isParked ? { ...sinks, registry: null } : sinks, // a parked incident stops only the registry
        prev,
        { persist: st => store.putPublication(id, st), reverify, maxPendingMs }
      );
      for (const a of r.alerts) alerts.push(`${id}: ${a}`);
      const done = isDone(rec, r.state, { pinners, cid, ignoreRegistry: isParked });
      entries[id] = {
        ...e,
        lastRunAt: now(),
        done,
        failing: false,
        ...(reverify ? { reverifiedGen: reverifyGen } : {}),
      };
      if (done) counts.done++;
      if (openIncident(r.state)) counts.incidents++;
    } catch (err) {
      entries[id] = { ...e, lastRunAt: now(), failing: true }; // a failure still rotates (R2)
      counts.failed++;
      if (err instanceof PersistError) {
        alerts.push(`${id}: ${err.message}; publication pass stopped`);
        stopped = true;
        continue;
      }
      alerts.push(`${id}: ${safeText("publish", err)}`);
    }
  }
  const reverifyRemaining =
    reverifyGen === null
      ? 0
      : // a record that keeps failing is alerted on its own; it does not hold the generation open
        Object.values(entries).filter(x => !x.failing && x.reverifiedGen !== reverifyGen).length;
  try {
    store.putSchedule({ ...sched, cursor: batch.at(-1) ?? null, entries });
  } catch {
    alerts.push("publication schedule not saved (rotation order only; journals unaffected)");
  }
  return { alerts, counts, stopped, reverifyRemaining };
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
  { now = Date.now(), repeatMs = 3_600_000, maxParts = ALERT_MAX_PARTS } = {}
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
  if (chunks.length > maxParts) {
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
export async function publishPhase(store, chain, cfg, p, built, { now = Date.now() } = {}) {
  const out = { at: new Date(now).toISOString() };
  const alerts = [];
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
  const meta = store.getAlertState() ?? {};
  let gen = store.getSchedule().reverifyGen ?? null;
  if (gen === null && now - (meta.lastReverifyAt ?? 0) >= p.reverifyEveryMs) {
    gen = now;
    store.putSchedule({ ...store.getSchedule(), reverifyGen: gen });
  }
  const res = await publishPending(
    store,
    { pinners: built.pinners, mirror: built.mirror, telegram: built.telegram, registry },
    { reverifyGen: gen, maxPendingMs: p.maxPendingMs, ...(p.limits ?? {}) }
  );
  const reverified = gen !== null && !res.stopped && res.reverifyRemaining === 0;
  if (reverified) {
    store.putAlertState({ ...(store.getAlertState() ?? {}), lastReverifyAt: gen });
    const { reverifyGen, ...rest } = store.getSchedule();
    void reverifyGen;
    store.putSchedule(rest);
  }
  alerts.push(...res.alerts);
  try {
    store.putAlertList(alerts);
  } catch {
    // the digest still goes out; only the full list on disk is missing
  }
  const delivery = await deliverAlerts(store, built.telegram, alerts, {
    now,
    repeatMs: p.alertRepeatMs,
  });
  const deliveredOk =
    delivery.sent === true || delivery.reason === "none" || delivery.reason === "unchanged";
  return {
    ...out,
    ...res.counts,
    stopped: res.stopped,
    reverifying: gen !== null && !reverified ? { gen, remaining: res.reverifyRemaining } : null,
    reverified,
    alerts: alerts.length,
    delivery,
    // Explicit pass result (Codex W2c R2): no failed record, no stop, no skipped registry stage,
    // and the alerts delivered. Deferred work is pending, not a failure.
    ok: !res.stopped && res.counts.failed === 0 && !out.registrySkipped && deliveredOk,
  };
}
