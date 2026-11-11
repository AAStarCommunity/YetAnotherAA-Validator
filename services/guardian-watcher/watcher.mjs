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
import { safeText } from "./lib/safe-error.mjs";
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
    forwarders: {},
    ...c,
  };
}

/** The disclose stalls that make the watcher degraded (DSR, #411 F1): fixed wording, counts only. */
export function stallReasons(publication) {
  const out = [];
  if (publication?.feeCapped)
    out.push(`${publication.feeCapped} disclose tx(s) need a fee above registry.maxFeePerGas`);
  if (publication?.insufficientFunds)
    out.push(
      `${publication.insufficientFunds} disclose tx(s) not payable: the writer has insufficient funds`
    );
  return out;
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

export async function runOnce(chain, cfg, store, rs, ident, { now, carry } = {}) {
  const nowMs = now ?? Date.now();
  const started = new Date(nowMs).toISOString();
  // `carry`: fields kept from the previous status while this run has not replaced them yet (the
  // last publication result, marked in progress: Codex W2c R1 M8).
  const status = { at: started, ruleset: ident, lastError: null, ...(carry ?? {}) };
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
    await finish(s.trace, s.finalized, s.isolated ?? 0, more);
    store.writeStatus(status);
    return { status, summary: s };
  } catch (e) {
    status.ok = false;
    status.lastError = safeText("tick", e); // never a foreign error's text (lib/safe-error.mjs)
    status.records = store.countRecords();
    status.deadLetters = store.listDeadLetters().length;
    status.cursor = store.getCursor()?.block ?? null;
    await finish(null, null);
    store.writeStatus(status);
    return { status, summary: null };
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
  await acquireLock(p?.lockPort ?? cfg.lockPort ?? DEFAULT_LOCK_PORT);
  const chain = makeProvider(process.env.RPC_URL);
  const pub = p ? { p, built: await buildSinks(p, chain) } : null;
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
    const { status } = await runOnce(chain, cfg, store, rs, ident, { carry });
    if (first && status.degraded) console.error(`WARNING: DEGRADED: ${status.degraded.join("; ")}`);
    first = false;
    if (pub) {
      try {
        // the previous iteration's slowness is only known after its publication: carried here
        const degraded = [...(status.degraded ?? []), ...(slowNote ? [slowNote] : [])];
        status.publication = await publishPhase(store, chain, cfg, pub.p, pub.built, {
          degraded: degraded.length ? degraded : undefined,
        });
      } catch (e) {
        status.publication = { error: safeText("publication", e) };
      }
      lastPub = status.publication;
      // a stalled disclose is a degraded watcher (DSR, #411 F1), whatever else the pass did; fixed
      // wording, counts only. The heartbeat alerts on healthy: false.
      const stalls = stallReasons(status.publication);
      if (stalls.length) {
        status.degraded = [...(status.degraded ?? []), ...stalls];
        status.healthy = false;
      }
      // the whole iteration (scan and publication) against the interval: a slow one is degraded,
      // and alerted by the next pass (tickMs covers the scan alone)
      status.iterationMs = Date.now() - iterStart;
      const limit = (cfg.maxTickFraction ?? 0.5) * cfg.intervalMs;
      slowNote =
        status.iterationMs > limit
          ? // fixed wording: the alert set's identity must not change with every duration (Codex W2c
            // R9); the measured time is status.iterationMs
            `iteration slower than ${Math.round(limit)} ms (maxTickFraction of the interval)`
          : null;
      if (slowNote) {
        status.degraded = [...(status.degraded ?? []), slowNote];
        status.healthy = false;
      }
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
