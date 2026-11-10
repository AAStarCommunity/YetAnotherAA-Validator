// Publication loop (W2c, M0 §5.3): after each scan, every FLAGGED record is published through the
// sinks, resuming its durable journal (store/publications/<id>.json). publishRecord does the
// per-record work and is crash-safe stage by stage; this module only decides what to run, reads
// the writer's roles from chain, builds the sinks and delivers the run's alerts.
import { ethers } from "ethers";
import { Store } from "./store.mjs";
import { publishRecord, PersistError } from "./publish.mjs";
import { SafeError, safeText, guarded } from "./safe-error.mjs";
import { assertWriterRole } from "../sinks/registry.mjs";

/** Fully done: nothing left to run, unless a weekly reverify of the pins is due. */
export function isDone(rec, st) {
  if (!st?.published || !st.telegram?.at) return false;
  if (rec.route !== "bls") return true; // owner/guardian route: repo + Telegram only (M0 §5.3)
  return st.registry?.phase === "confirmed";
}

/** An unresolved, unacknowledged registry incident: publishRecord re-alerts it every run. */
const openIncident = st =>
  (st?.registry?.phase === "conflict" || st?.registry?.phase === "reverted") && !st.registry.ack;

/**
 * Run publication for every flagged record. Returns { alerts, counts }.
 * A PersistError stops the pass (state is no longer durable); any other error of one record is
 * an alert and the pass moves on: one bad record never blocks the others.
 */
export async function publishPending(store, sinks, { reverify = false, maxPendingMs } = {}) {
  const alerts = [];
  const counts = { flagged: 0, done: 0, ran: 0, incidents: 0, failed: 0 };
  // One unreadable record or journal never blocks the others (Codex W2c R1 M7). An unreadable
  // journal is never reset: that record is not published (nor signed for) until it is repaired.
  const { records, corrupt } = store.listRecordsTolerant();
  for (const f of corrupt) {
    counts.failed++;
    alerts.push(`${f}: record file unreadable; not published`);
  }
  for (const rec of records) {
    if (!rec?.verdict?.flagged) continue;
    counts.flagged++;
    const id = rec.id ?? Store.recordId(rec);
    let prev;
    try {
      prev = store.getPublication(id) ?? {};
    } catch {
      counts.failed++;
      alerts.push(`${id}: publication journal unreadable; record skipped, journal kept as is`);
      continue;
    }
    if (isDone(rec, prev) && !reverify) {
      counts.done++;
      continue;
    }
    counts.ran++;
    try {
      const r = await publishRecord(rec, sinks, prev, {
        persist: st => store.putPublication(id, st),
        reverify,
        maxPendingMs,
      });
      for (const a of r.alerts) alerts.push(`${id}: ${a}`);
      if (isDone(rec, r.state)) counts.done++;
      if (openIncident(r.state)) counts.incidents++;
    } catch (e) {
      if (e instanceof PersistError) {
        alerts.push(`${id}: ${e.message}; publication pass stopped`);
        counts.failed++;
        return { alerts, counts, stopped: true };
      }
      counts.failed++;
      alerts.push(`${id}: ${safeText("publish", e)}`);
    }
  }
  return { alerts, counts, stopped: false };
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
  { now = Date.now(), repeatMs = 3_600_000 } = {}
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
  const chunks = alertChunks(alerts);
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
  const meta = store.getAlertState() ?? {};
  const reverify = now - (meta.lastReverifyAt ?? 0) >= p.reverifyEveryMs;
  const res = await publishPending(
    store,
    { pinners: built.pinners, mirror: built.mirror, telegram: built.telegram, registry },
    { reverify, maxPendingMs: p.maxPendingMs }
  );
  if (reverify && !res.stopped)
    store.putAlertState({ ...(store.getAlertState() ?? {}), lastReverifyAt: now });
  alerts.push(...res.alerts);
  const delivery = await deliverAlerts(store, built.telegram, alerts, {
    now,
    repeatMs: p.alertRepeatMs,
  });
  return {
    ...out,
    ...res.counts,
    stopped: res.stopped,
    reverified: reverify && !res.stopped,
    alerts: alerts.length,
    delivery,
  };
}
