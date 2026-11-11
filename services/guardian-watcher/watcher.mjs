#!/usr/bin/env node
// Guardian watcher (M0 §5): detection + records (W1) and, with config.publish, their publication
// (W2: IPFS pins, git mirror, Telegram, DisclosureRegistry). Runs on the Mac Mini under launchd.
//
//   RPC_URL=... node services/guardian-watcher/watcher.mjs --config <config.json> [--once]
//
// config.json (non-secret; addresses are the release manifest's):
//   { "chainId": 10, "aggregator": "0x..", "startBlock": N, "dataDir": "/path",
//     "roles": { "superPaymaster": "0x.." },
//     "forwarders": { "dvtValidator": "0x..", "ownerSafe": "0x..", "multiSendCallOnly": "0x.." },
//     "maxBlocksPerTick": 2000, "page": 5000, "intervalMs": 60000,
//     "publish": { "enabled": true, ... }   (lib/sinks-config.mjs; secrets are Keychain items) }
//
// Fail-open on errors: a failed tick is recorded in status.json and retried; the process keeps
// running, because a watcher that stops is the outcome it exists to prevent.
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { ethers } from "ethers";
import { makeProvider } from "../../scripts/disclosure/recheck-lib.mjs";
import { validateRuleset } from "./lib/rules.mjs";
import { Store } from "./lib/store.mjs";
import { tick, verifyTrace } from "./lib/scan.mjs";
import { confirmPending } from "./lib/confirm.mjs";
import { SafeError, safeText } from "./lib/safe-error.mjs";
import { acquireLock, DEFAULT_LOCK_PORT } from "./lib/lock.mjs";
import { publishConfig, buildSinks } from "./lib/sinks-config.mjs";
import { publishPhase } from "./lib/publisher.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));

/**
 * Identity of the ruleset the watcher actually evaluates: its keccak256 content hash always, plus the
 * git commit whose ruleset.json has exactly those bytes. Outside a checkout, or with local edits,
 * the commit is null and `verified` is false: a record never names a commit it was not judged by.
 */
export function rulesetIdentity(bytes, dir = HERE) {
  const hash = ethers.keccak256(bytes);
  try {
    const commit = execFileSync(
      "git",
      ["-C", dir, "log", "-1", "--format=%H", "--", "ruleset.json"],
      // stderr is not inherited: git's diagnostics never reach our output (Codex W2b R4).
      { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }
    ).trim();
    if (!/^[0-9a-f]{40}$/.test(commit)) return { commit: null, hash, verified: false };
    const committed = execFileSync("git", ["-C", dir, "show", `${commit}:./ruleset.json`], {
      stdio: ["ignore", "pipe", "ignore"],
    });
    const same = ethers.keccak256(committed) === hash;
    return same ? { commit, hash, verified: true } : { commit: null, hash, verified: false };
  } catch {
    return { commit: null, hash, verified: false };
  }
}

export function loadConfig(path) {
  const c = JSON.parse(readFileSync(path, "utf8"));
  for (const k of ["aggregator", "dataDir"]) if (!c[k]) throw new Error(`config: ${k} required`);
  if (!Number.isSafeInteger(c.startBlock) || c.startBlock < 0)
    throw new Error("config: startBlock required");
  if (!c.roles?.superPaymaster) throw new Error("config: roles.superPaymaster required");
  for (const a of [c.aggregator, c.roles.superPaymaster, ...Object.values(c.forwarders ?? {})]) {
    if (!ethers.isAddress(a)) throw new Error(`config: bad address ${a}`);
  }
  if (
    c.maxTickFraction !== undefined &&
    !(typeof c.maxTickFraction === "number" && c.maxTickFraction > 0 && c.maxTickFraction <= 10)
  )
    throw new Error("config: maxTickFraction must be a number in (0, 10]");
  if (c.maxLagBlocks !== undefined && !(Number.isSafeInteger(c.maxLagBlocks) && c.maxLagBlocks > 0))
    throw new Error("config: maxLagBlocks must be a positive integer");
  return {
    maxBlocksPerTick: 2000,
    page: 5000,
    intervalMs: 60_000,
    // the cursor this far behind finalized is degraded (about 1 h of Sepolia blocks): DSR 2892c30f
    maxLagBlocks: 300,
    // a tick slower than this share of the poll interval is degraded (DSR 97a9d55c): the work per
    // tick grows with the local archive, and that must show before it outruns the interval
    maxTickFraction: 0.5,
    // D-RPC2: nothing accusatory is published without a second provider's confirmation; running
    // without one is degraded (RPC_URL_2)
    requireSecondProvider: true,
    forwarders: {},
    ...c,
  };
}

/** The second provider's label for holds and status: config.secondProvider, a plain name. */
export function secondProviderLabel(cfg) {
  const n = cfg?.secondProvider;
  return typeof n === "string" && /^[a-z][a-z0-9-]{0,30}$/i.test(n) ? n : "second";
}

/** The disclose stalls that make the watcher degraded (DSR, #411 F1): fixed wording, counts only. */
export function stallReasons(publication) {
  // store-wide counts (lib/publisher.mjs stallCounts), never the batch's (DSR)
  const out = [];
  // no store-wide counts at all (the pass threw, or never reported them) is not "no stalls"
  // (#413 review B1)
  if (!publication?.stalls) return ["stall state unknown: no publication result"];
  const st = publication.stalls;
  // an unreadable, unrebuildable index is not "no stalls" (Codex W2c R12 #3)
  if (st.unknown) out.push("stall state unknown: the stall index is unreadable");
  if (st.feeCapped)
    out.push(`${st.feeCapped} disclose tx(s) need a fee above registry.maxFeePerGas`);
  if (st.insufficientFunds)
    out.push(
      `${st.insufficientFunds} disclose tx(s) not payable: the writer has insufficient funds`
    );
  // what still needs attention (Codex W2c R20), store-wide until the journal no longer says so
  if (st.incidents)
    out.push(`${st.incidents} unresolved registry or bytes incident(s) (acknowledge or resolve)`);
  if (st.inconsistent)
    out.push(
      `${st.inconsistent} disclose receipt(s) final but the entry not visible (RPC inconsistent)`
    );
  if (st.unverified)
    out.push(`${st.unverified} pin(s) not re-verified since a failed check (retried every pass)`);
  // the generic count last: a specific cause above names the same record more precisely
  if (st.failing)
    out.push(`${st.failing} record(s) failing publication (retried every pass; see the alerts)`);
  return out;
}

/**
 * Why a publication result makes the watcher degraded (#413 review B1), fixed wording: a pass that
 * threw or did not report ok, and the store-wide disclose stalls (DSR, #411 F1). The heartbeat
 * alerts on healthy: false.
 */
export function publicationReasons(publication) {
  const reasons = [];
  if (publication?.error) reasons.push("publication pass failed (see the alerts)");
  else if (publication?.ok !== true)
    reasons.push("publication pass not ok (a stage failed, stopped or was skipped)");
  reasons.push(...stallReasons(publication));
  return reasons;
}

/**
 * One iteration's publication, as the resident loop runs it (#413 review B1): a pass that throws,
 * or that does not report ok, makes the watcher degraded (fixed wording, healthy = false) so the
 * heartbeat sees it; so do disclose stalls and a slow iteration. Returns the next slowNote.
 */
export async function publicationStep({
  status,
  run,
  slowNote,
  iterStart,
  cfg,
  carried = [],
  now = Date.now,
}) {
  // the interim status carried the last publication's reasons (runOnce); they are replaced by this
  // pass's, so health is the scan's plus the current publication's (Codex W2c R19 #2)
  const scanDegraded = (status.degraded ?? []).filter(r => !carried.includes(r));
  try {
    // the previous iteration's slowness is only known after its publication: carried here
    const degraded = [...scanDegraded, ...(slowNote ? [slowNote] : [])];
    status.publication = await run(degraded.length ? degraded : undefined);
  } catch (e) {
    status.publication = { error: safeText("publication", e) };
  }
  const reasons = publicationReasons(status.publication);
  // the whole iteration (scan and publication) against the interval: a slow one is degraded,
  // and alerted by the next pass (tickMs covers the scan alone)
  status.iterationMs = now() - iterStart;
  const limit = (cfg.maxTickFraction ?? 0.5) * cfg.intervalMs;
  const nextSlow =
    status.iterationMs > limit
      ? // fixed wording: the alert set's identity must not change with every duration (Codex W2c
        // R9); the measured time is status.iterationMs
        `iteration slower than ${Math.round(limit)} ms (maxTickFraction of the interval)`
      : null;
  if (nextSlow) reasons.push(nextSlow);
  const all = [...scanDegraded, ...reasons];
  status.degraded = all.length ? all : null;
  status.healthy = status.ok === true && all.length === 0;
  return nextSlow;
}

/** The lock port the watcher takes for this config (one process per host), shared with every tool
 * that must not run beside it (deploy/guardian-watcher/rearm-hold.mjs; Codex D-RPC2 R8 #3). */
export function watcherLockPort(cfg, p = cfg.publish?.enabled ? publishConfig(cfg.publish) : null) {
  return p?.lockPort ?? cfg.lockPort ?? DEFAULT_LOCK_PORT;
}

export const TRACE_VERIFY_MS = 3_600_000;

/**
 * Trace capability (DSR, #400; Codex #400-fix R4): known only by positive verification, from a
 * real trace aligned with its receipt, kept in the store. Re-verified actively when the last proof
 * is older than traceVerifyMs (quiet ticks too) or this tick saw a sign of trouble. Healthy needs
 * a proof younger than 2 x traceVerifyMs and no unsupported / log-less / all-failed traces now.
 */
export async function traceHealth(chain, cfg, store, stats, finalized, nowMs) {
  const every = cfg.traceVerifyMs ?? TRACE_VERIFY_MS;
  let cap = store.getTraceCapability();
  const sampleTx = cap?.txHash ?? null;
  // A trace this tick that shows the capability is missing outweighs any older proof (Codex
  // #400-fix R5): the proof is dropped, and only a new positive verification restores health.
  if (stats?.unsupported || stats?.noLogs || stats?.inconsistent) {
    cap = null;
    store.putTraceCapability(null);
  } else if (stats?.verifiedTx) {
    cap = { verifiedAt: nowMs, txHash: stats.verifiedTx, by: "scan" };
    store.putTraceCapability(cap);
  }
  const trouble = !!(
    stats?.unsupported ||
    stats?.noLogs ||
    stats?.inconsistent ||
    stats?.unaligned ||
    (stats?.failed && !stats?.verified)
  );
  let check = null;
  if (finalized !== null && (trouble || !cap || nowMs - cap.verifiedAt >= every)) {
    check = await verifyTrace(chain, cfg, finalized, { sampleTx });
    if (check.state === "verified") {
      cap = { verifiedAt: nowMs, txHash: check.txHash, by: "probe" };
      store.putTraceCapability(cap);
    } else if (check.state === "unsupported") {
      cap = null;
      store.putTraceCapability(null);
    }
  }
  const degraded = [];
  const fresh = !!cap && nowMs - cap.verifiedAt < 2 * every;
  if (check?.state === "unsupported") degraded.push(`trace unsupported: ${check.reason}`);
  else if (!fresh)
    degraded.push(`trace capability unverified: ${check?.reason ?? "no recent verification"}`);
  if (stats?.unsupported) degraded.push(`trace unsupported on ${stats.unsupported} tx(s)`);
  if (stats?.noLogs)
    degraded.push(`trace without logs on ${stats.noLogs} tx(s): withLog not honoured`);
  if (stats?.failed && !stats?.verified)
    degraded.push(`all ${stats.failed} trace call(s) this tick failed`);
  if (stats?.inconsistent)
    degraded.push(`receipt disagrees with getLogs on ${stats.inconsistent} tx(s)`);
  if (stats?.unaligned)
    degraded.push(
      `trace did not align with a consistent receipt on ${stats.unaligned} tx(s) (${stats.unalignedWhy})`
    );
  if (check && check.state === "unverified" && check.failed > 0)
    degraded.push(`verification: ${check.failed} sample trace call(s) failed`);
  return {
    trace: {
      capability:
        check?.state === "unsupported"
          ? "unsupported"
          : fresh
            ? "verified"
            : cap
              ? "stale"
              : "unverified",
      verifiedAt: cap ? new Date(cap.verifiedAt).toISOString() : null,
      sampleTx: cap?.txHash ?? null,
      ...(check
        ? { lastCheck: check.state, ...(check.reason ? { reason: check.reason } : {}) }
        : {}),
      thisTick: stats ?? {},
    },
    degraded: degraded.length ? degraded : null,
  };
}

/**
 * One tick. `second` ({ chain, host }) is the D-RPC2 second provider: after the scan, every
 * accusatory record not yet confirmed is re-run on it (lib/confirm.mjs). Without it, the tick is
 * degraded, because accusatory records can never be confirmed and so never published.
 */
export async function runOnce(chain, cfg, store, rs, ident, { now, second, carry } = {}) {
  const nowMs = now ?? Date.now();
  const started = new Date(nowMs).toISOString();
  // `carry`: fields kept from the previous status while this run has not replaced them yet (the
  // last publication result, marked in progress: Codex W2c R1 M8).
  const status = { at: started, ruleset: ident, lastError: null, ...(carry ?? {}) };
  let carried = []; // the reasons taken from the carried publication (replaced by publicationStep)
  // wall time of this tick and the archive it ran over, reported with every status
  const tickStart = Date.now();
  const timing = () => {
    const ms = Date.now() - tickStart;
    const limit = (cfg.maxTickFraction ?? 0.5) * (cfg.intervalMs ?? 60_000);
    let files = null;
    try {
      files = store.countArchiveFiles();
    } catch {
      files = null;
    }
    return { ms, limit, files };
  };
  const finish = async (stats, finalized, isolated = 0, more = []) => {
    let h;
    try {
      h = await traceHealth(chain, cfg, store, stats, finalized, nowMs);
    } catch {
      h = { trace: { capability: "unverified" }, degraded: ["trace capability check failed"] };
    }
    status.trace = h.trace;
    // A tick that had to isolate malformed RPC answers is not healthy: the data is being set aside,
    // not read (#403 review L-2). The scan still moved on; the reason and count say why.
    const extra = isolated ? [`${isolated} malformed RPC answer(s) isolated this tick`] : [];
    for (const m of more) extra.push(m);
    // measured last, after capability verification and the archive count, so the whole tick shows
    // (follow-up #2 R12)
    const tm = timing();
    status.archiveFiles = tm.files;
    status.tickMs = Date.now() - tickStart;
    if (status.tickMs > tm.limit)
      extra.push(
        `tick took ${status.tickMs} ms, more than ${Math.round(tm.limit)} ms (maxTickFraction of the interval)`
      );
    // the status written before this iteration's publication keeps the last publication's
    // degradation (Codex W2c R18): a scan-only "healthy" must not read as recovered
    if (carry?.publication) {
      carried = publicationReasons(carry.publication);
      extra.push(...carried);
    }
    status.degraded = h.degraded || extra.length ? [...(h.degraded ?? []), ...extra] : null;
    status.healthy = status.ok === true && !status.degraded;
  };
  try {
    const s = await tick(chain, cfg, store, rs, { ruleset: ident, now: started });
    const cur = store.getCursor();
    const totals = store.bumpCounters({ budgetStops: s.budgetStop ? 1 : 0 });
    Object.assign(status, {
      ok: true,
      finalized: s.finalized,
      cursor: cur?.block ?? null,
      lagBlocks: cur ? s.finalized - cur.block : null,
      scanned: [s.from, s.to],
      newRecords: s.newRecords,
      flaggedThisTick: s.flagged.length,
      records: store.countRecords(),
      deadLetters: store.listDeadLetters().length,
      corruptDeadLetters: store.corruptDeadLetters,
      exhaustedThisTick: s.exhausted,
      // txs isolated this tick (a malformed answer: #400 review L1), and unreadable txs that ended
      // as unattributed records, in total
      isolatedThisTick: s.isolated ?? 0,
      unreadableTotal: store.countUnreadable(),
      blsAmendments: store.countAmendments(),
      amendmentConflictsThisTick: s.amendmentConflicts ?? 0,
      amendmentConflictsTotal: store.countAmendmentConflicts(),
      exhaustedTotal: store.countExhausted(),
      // ticks that hit the isolation budget (stopped early, or a block overflowed into quarantine)
      // and quarantine records (set-aside answers, nobody accused): DSR log 2892c30f
      budgetStopThisTick: !!s.budgetStop,
      budgetStopsTotal: totals.budgetStops ?? 0,
      quarantinedThisTick: s.quarantined ?? 0,
      quarantinedTotal: store.countQuarantined(),
      ...(totals.reset ? { countersReset: true } : {}),
      bloom: {
        recovered: s.bloomRecovered,
        falsePositives: s.bloomFalsePositives,
        unchecked: s.bloomUnchecked,
      },
    });
    const more = [];
    if (s.budgetStop) more.push("isolation budget reached this tick (the rest is read next tick)");
    const lag = cur ? s.finalized - cur.block : null;
    const maxLag = cfg.maxLagBlocks ?? 300;
    if (lag !== null && lag > maxLag)
      more.push(`cursor ${lag} blocks behind finalized (> ${maxLag})`);
    // D-RPC2: confirm accusatory records on the second provider (never on the first)
    if (second?.chain) {
      try {
        status.confirm = {
          secondProvider: second.host ?? null,
          ...(await confirmPending(store, second.chain, second.host ?? null, cfg, rs, ident, {
            runOnce,
            now: nowMs,
          })),
        };
        if (status.confirm.final)
          more.push(
            `${status.confirm.final} accusatory record(s) final after repeated mismatches with the second provider (held; re-arm by hand: rearm-hold.mjs)`
          );
        // held and not publishable: a disagreement, or a second provider that keeps not answering
        // (DSR, ded99d78): degraded, never published
        if (status.confirm.holdUnsaved)
          more.push(
            `${status.confirm.holdUnsaved} D-RPC2 hold(s) could not be saved (those records stay held)`
          );
        if (status.confirm.cursorUnsaved)
          more.push("D-RPC2 confirmation cursor not saved (rotating in memory)");
        if (status.confirm.mismatch)
          more.push(
            `${status.confirm.mismatch} accusatory record(s) differ on the second provider (held, not published)`
          );
        if (status.confirm.waiting)
          more.push(
            `${status.confirm.waiting} accusatory record(s) not confirmable: the second provider has not answered on 2+ consecutive attempts (held, retried with backoff, not published)`
          );
      } catch {
        status.confirm = { secondProvider: second.host ?? null, error: "confirmation pass failed" };
        more.push("D-RPC2 confirmation pass failed");
      }
    } else {
      status.confirm = { secondProvider: null };
      // required in production (loadConfig defaults requireSecondProvider: true)
      if (cfg.requireSecondProvider)
        more.push("no second provider (D-RPC2): accusatory records stay held");
    }
    await finish(s.trace, s.finalized, s.isolated ?? 0, more);
    store.writeStatus(status);
    return { status, summary: s, carried };
  } catch (e) {
    status.ok = false;
    status.lastError = safeText("tick", e); // never a foreign error's text (lib/safe-error.mjs)
    status.records = store.countRecords();
    status.deadLetters = store.listDeadLetters().length;
    status.cursor = store.getCursor()?.block ?? null;
    await finish(null, null);
    store.writeStatus(status);
    return { status, summary: null, carried };
  }
}

/** `--once` exit code: 0 only for a healthy scan (trace capability verified, DSR #400) AND, when
 * publication ran, a pass that reported ok (no failed record, stop, skipped registry stage or
 * undelivered alerts: Codex W2c R2). */
export function onceExitCode(status) {
  const pubOk = !status.publication || status.publication.ok === true;
  return status.healthy === true && pubOk ? 0 : 1;
}

async function main() {
  const arg = n => {
    const i = process.argv.indexOf(`--${n}`);
    return i > 0 ? process.argv[i + 1] : undefined;
  };
  const cfgPath = arg("config");
  if (!cfgPath || !process.env.RPC_URL) {
    console.error("usage: RPC_URL=.. watcher.mjs --config <config.json> [--once]");
    process.exit(2);
  }
  const cfg = loadConfig(cfgPath);
  const bytes = readFileSync(join(HERE, "ruleset.json"));
  const rs = validateRuleset(JSON.parse(bytes.toString("utf8")));
  const ident = rulesetIdentity(bytes);
  if (!ident.verified)
    console.error(
      "WARNING: ruleset.json does not match a committed version; records carry ruleset.verified = false"
    );
  // W2c: publication is opt-in (config.publish.enabled). Everything that can refuse is checked
  // BEFORE anything is created or read from the network: the publish config, then the lock (one
  // process per host: it covers scanning too, two watchers on one data dir would race the store),
  // then secrets and the writer key, loaded once. A bad setup refuses to start, never half-runs.
  const p = cfg.publish?.enabled ? publishConfig(cfg.publish) : null;
  await acquireLock(watcherLockPort(cfg, p));
  const chain = makeProvider(process.env.RPC_URL);
  // D-RPC2: the second provider's URL comes from the environment (on the Mini, from the Keychain);
  // only the operator's label for it is ever recorded
  const second = process.env.RPC_URL_2
    ? // only the operator's label for the second provider is ever stored, never anything derived
      // from its URL: a hostname can carry an access token in a subdomain (cf. Codex A7 R16)
      { chain: makeProvider(process.env.RPC_URL_2), host: secondProviderLabel(cfg) }
    : null;
  // the registry signs only for the configured chain (#413 review N2): a missing chainId refuses
  // to start, and a mismatching RPC refuses each signature
  if (p && !Number.isSafeInteger(cfg.chainId))
    throw new SafeError("config: chainId required when publish is enabled");
  const pub = p ? { p, built: await buildSinks(p, chain, { chainId: cfg.chainId }) } : null;
  const store = new Store(cfg.dataDir);
  const once = process.argv.includes("--once");
  let lastPub = store.readStatus()?.publication ?? null;
  let first = true;
  let slowNote = null; // the last iteration was slower than maxTickFraction of the interval
  for (;;) {
    // The last publication result stays visible, marked in progress, until this pass replaces it.
    const carry = pub
      ? { publication: { ...(lastPub ?? {}), inProgress: true, since: new Date().toISOString() } }
      : undefined;
    const iterStart = Date.now();
    const { status, carried } = await runOnce(chain, cfg, store, rs, ident, { second, carry });
    if (first && status.degraded) console.error(`WARNING: DEGRADED: ${status.degraded.join("; ")}`);
    first = false;
    if (pub) {
      slowNote = await publicationStep({
        status,
        slowNote,
        iterStart,
        cfg,
        carried,
        run: degraded => publishPhase(store, chain, cfg, pub.p, pub.built, { degraded }),
      });
      lastPub = status.publication;
      store.writeStatus(status);
    }
    console.log(JSON.stringify(status));
    if (once) process.exit(onceExitCode(status));
    await new Promise(r => setTimeout(r, cfg.intervalMs));
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  // Last boundary (Codex W2b R4): nothing reaches Node's default handler, which would print a
  // foreign error's message and properties.
  main().catch(e => {
    console.error(safeText("watcher fatal", e));
    process.exit(1);
  });
}
