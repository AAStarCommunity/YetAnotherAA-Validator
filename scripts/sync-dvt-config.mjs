#!/usr/bin/env node
// Sync — or --check — the DVT-OWNED fields of deploy/sdk-dvt-config.*.json against ground truth.
//
// The config's stale nodeIds (CC-22) are exactly what this prevents: the DVT-owned fields
// (dvtNodes[].nodeId + pubkey, sourced from each node's live GET /node/info; and optionally the
// validator address) can be re-derived from ground truth instead of hand-edited. The
// airaccount-owned fields (e2e_account, router mount) are NEVER touched here — they are
// coordination-sourced (see docs/INTERFACES.md §2).
//
// Two modes:
//   node scripts/sync-dvt-config.mjs            # APPLY: fetch live /node/info, rewrite drifted fields
//   node scripts/sync-dvt-config.mjs --check    # VERIFY only: print drift, exit 1 if any (CI guard)
//
// Options:
//   --file <path>        config file (default deploy/sdk-dvt-config.testnet.json)
//   --env <name>         environment key (default = the file's `active`)
//   --validator <0x..>   also check/set environments[env].validator (e.g. from a deploy artifact)
//   --timeout <ms>       per-node /node/info timeout (default 8000)
//
// Exit codes: 0 = in sync (or applied); 1 = drift found (--check) or a fatal error.

import { readFileSync, writeFileSync } from "fs";

const args = process.argv.slice(2);
const has = f => args.includes(f);
const val = (f, d) => {
  const i = args.indexOf(f);
  return i >= 0 && i + 1 < args.length ? args[i + 1] : d;
};

const CHECK = has("--check");
const FILE = val("--file", "deploy/sdk-dvt-config.testnet.json");
const VALIDATOR = val("--validator", null);
const TIMEOUT = parseInt(val("--timeout", "8000"), 10);

const norm = s => (s || "").toLowerCase();
const norm0x = s => {
  const h = (s || "").toLowerCase().replace(/^0x/, "");
  return "0x" + h;
};

let config;
try {
  config = JSON.parse(readFileSync(FILE, "utf8"));
} catch (e) {
  console.error(`‼ cannot read ${FILE}: ${e.message}`);
  process.exit(1);
}

const ENV = val("--env", config.active);
const env = config.environments?.[ENV];
if (!env) {
  console.error(`‼ environment '${ENV}' not found in ${FILE}`);
  process.exit(1);
}
if (!Array.isArray(env.dvtNodes) || env.dvtNodes.length === 0) {
  console.error(`‼ environments.${ENV}.dvtNodes is empty — nothing to sync`);
  process.exit(1);
}

async function fetchInfo(url) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), TIMEOUT);
  try {
    const res = await fetch(`${url.replace(/\/$/, "")}/node/info`, { signal: ctrl.signal });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } finally {
    clearTimeout(t);
  }
}

console.log(`${CHECK ? "CHECK" : "SYNC"} ${FILE} · env=${ENV} · ${env.dvtNodes.length} nodes`);

const drifts = [];
let unreachable = 0;

for (const node of env.dvtNodes) {
  let info;
  try {
    info = await fetchInfo(node.url);
  } catch (e) {
    unreachable++;
    console.error(`  ⚠ ${node.url} unreachable (${e.message}) — skipped (not treated as drift)`);
    continue;
  }
  const liveNodeId = norm0x(info.nodeId);
  const livePub = norm0x(info.publicKey);
  if (!liveNodeId || liveNodeId === "0x" || !livePub || livePub === "0x") {
    console.error(`  ⚠ ${node.url} /node/info missing nodeId/publicKey — skipped`);
    unreachable++;
    continue;
  }
  const nodeIdDrift = norm(node.nodeId) !== liveNodeId;
  const pubDrift = norm(node.pubkey) !== livePub;
  if (nodeIdDrift || pubDrift) {
    drifts.push({ url: node.url });
    if (nodeIdDrift) console.log(`  ✗ ${node.url} nodeId: ${node.nodeId} → ${liveNodeId}`);
    if (pubDrift) console.log(`  ✗ ${node.url} pubkey: ${node.pubkey} → ${livePub}`);
    if (!CHECK) {
      node.nodeId = liveNodeId;
      node.pubkey = livePub;
    }
  } else {
    console.log(`  ✓ ${node.url} in sync`);
  }
}

// Optional validator check/set (source = a deploy artifact, passed explicitly).
if (VALIDATOR) {
  const want = norm0x(VALIDATOR);
  if (norm(env.validator) !== want) {
    drifts.push({ field: "validator" });
    console.log(`  ✗ validator: ${env.validator} → ${want}`);
    if (!CHECK) env.validator = VALIDATOR;
  } else {
    console.log(`  ✓ validator in sync`);
  }
}

if (unreachable > 0) {
  console.error(
    `\n⚠ ${unreachable} node(s) unreachable — their fields were NOT verified. Re-run when they are up.`
  );
}

if (drifts.length === 0) {
  console.log(`\n✔ ${ENV} config is in sync${unreachable ? " (for reachable nodes)" : ""}.`);
  process.exit(0);
}

if (CHECK) {
  console.error(`\n✗ ${drifts.length} field(s) drift from live. Run without --check to apply.`);
  process.exit(1);
}

writeFileSync(FILE, JSON.stringify(config, null, 2) + "\n", "utf8");
console.log(
  `\n✔ applied ${drifts.length} update(s) → ${FILE} (run prettier if your repo formats JSON).`
);
process.exit(0);
