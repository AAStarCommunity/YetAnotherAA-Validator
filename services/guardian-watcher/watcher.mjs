#!/usr/bin/env node
// Guardian watcher (M0 §5): detection + records only (W1). Runs on the Mac Mini under launchd.
//
//   RPC_URL=... node services/guardian-watcher/watcher.mjs --config <config.json> [--once]
//
// config.json (non-secret; addresses are the release manifest's):
//   { "chainId": 10, "aggregator": "0x..", "startBlock": N, "dataDir": "/path",
//     "roles": { "superPaymaster": "0x.." },
//     "forwarders": { "dvtValidator": "0x..", "ownerSafe": "0x..", "multiSendCallOnly": "0x.." },
//     "maxBlocksPerTick": 2000, "page": 5000, "intervalMs": 60000 }
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
      {
        encoding: "utf8",
      }
    ).trim();
    if (!/^[0-9a-f]{40}$/.test(commit)) return { commit: null, hash, verified: false };
    const committed = execFileSync("git", ["-C", dir, "show", `${commit}:./ruleset.json`]);
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
  return { maxBlocksPerTick: 2000, page: 5000, intervalMs: 60_000, forwarders: {}, ...c };
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

export async function runOnce(chain, cfg, store, rs, ident, { now } = {}) {
  const nowMs = now ?? Date.now();
  const started = new Date(nowMs).toISOString();
  const status = { at: started, ruleset: ident, lastError: null };
  const finish = async (stats, finalized) => {
    let h;
    try {
      h = await traceHealth(chain, cfg, store, stats, finalized, nowMs);
    } catch {
      h = { trace: { capability: "unverified" }, degraded: ["trace capability check failed"] };
    }
    status.trace = h.trace;
    status.degraded = h.degraded;
    status.healthy = status.ok === true && !status.degraded;
  };
  try {
    const s = await tick(chain, cfg, store, rs, { ruleset: ident, now: started });
    const cur = store.getCursor();
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
      exhaustedTotal: store.countExhausted(),
      bloom: {
        recovered: s.bloomRecovered,
        falsePositives: s.bloomFalsePositives,
        unchecked: s.bloomUnchecked,
      },
    });
    await finish(s.trace, s.finalized);
    store.writeStatus(status);
    return { status, summary: s };
  } catch (e) {
    status.ok = false;
    status.lastError = e.shortMessage ?? e.message;
    status.records = store.countRecords();
    status.deadLetters = store.listDeadLetters().length;
    status.cursor = store.getCursor()?.block ?? null;
    await finish(null, null);
    store.writeStatus(status);
    return { status, summary: null };
  }
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
  const chain = makeProvider(process.env.RPC_URL);
  const store = new Store(cfg.dataDir);
  const once = process.argv.includes("--once");
  let first = true;
  for (;;) {
    const { status } = await runOnce(chain, cfg, store, rs, ident);
    if (first && status.degraded) console.error(`WARNING: DEGRADED: ${status.degraded.join("; ")}`);
    first = false;
    console.log(JSON.stringify(status));
    if (once) process.exit(status.healthy ? 0 : 1);
    await new Promise(r => setTimeout(r, cfg.intervalMs));
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) main();
