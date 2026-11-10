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
import { tick } from "./lib/scan.mjs";

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

export async function runOnce(chain, cfg, store, rs, ident) {
  const started = new Date().toISOString();
  const status = { at: started, ruleset: ident, lastError: null };
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
    });
    store.writeStatus(status);
    return { status, summary: s };
  } catch (e) {
    status.ok = false;
    status.lastError = e.shortMessage ?? e.message;
    status.records = store.countRecords();
    status.deadLetters = store.listDeadLetters().length;
    status.cursor = store.getCursor()?.block ?? null;
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
  for (;;) {
    const { status } = await runOnce(chain, cfg, store, rs, ident);
    console.log(JSON.stringify(status));
    if (once) process.exit(status.ok ? 0 : 1);
    await new Promise(r => setTimeout(r, cfg.intervalMs));
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) main();
