#!/usr/bin/env node
// A3 release check (DSR 19557717): every watched SuperPaymaster event that a function WITHOUT a
// caller restriction can emit must be listed, under that function, in ruleset.json
// publicRoute.functions. Otherwise the watcher would classify that event as the owner route
// ("a watched event no permissionless function can emit is always the owner route") and attribute
// an outsider's call to the owner.
//
//   node scripts/disclosure/a3-emission-diff.mjs <table.json> [--ruleset path] [--json]
//   node scripts/disclosure/a3-emission-diff.mjs --self-test
//
// <table.json> is SP's mechanically generated emission table (Slither or similar, on the release
// tree), one row per external/public function of the contracts the watcher reads (format agreed
// with DSR, 4d1240b3):
//   { "tool", "toolVersion", "command", "spCommit": "<40 hex>",
//     "rows": [ { "contract": "SuperPaymaster", "function": "updatePrice()",
//                 "selector": "0x673a7e28", "callerRestricted": false, "restriction": null,
//                 "events": [ { "name": "PriceUpdated", "signature": "PriceUpdated(int256,uint256)",
//                               "topic0": "0x…", "via": "updatePrice → _setPrice" } ] } ] }
// `events` must include everything the function can emit through internal calls and delegatecall.
// Watched events are matched by topic0 (what the watcher decides on), computed from the watcher's
// own ABI; every selector and topic0 in the table is recomputed and must agree.
// Exit 0 when nothing is missing; 1 when something is (each gap printed); 2 on bad input.
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { ethers } from "ethers";
import { publicFunction } from "../../services/guardian-watcher/lib/rules.mjs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..", "..");

/**
 * The gaps between an emission table and the watcher's public route.
 * Returns { missingFunctions, missingEvents, stale } :
 *   missingFunctions: [{ signature, events }]  permissionless functions emitting watched events,
 *                     absent from publicRoute.functions;
 *   missingEvents:    [{ signature, events }]  listed functions whose entry lacks watched events
 *                     the table says they can emit;
 *   stale:            [signature]              publicRoute entries the table does not show as
 *                     permissionless (informational: a narrower route is safe, not a gap).
 */
export function diffEmissions(table, ruleset, watched) {
  // watched: [{ name, topic0 }]. Functions are looked up exactly as the watcher does at runtime:
  // by selector, through rules.mjs publicFunction (#C-line Codex R1 #5).
  const byTopic = new Map(watched.map(w => [w.topic0.toLowerCase(), w.name]));
  const missingFunctions = [];
  const missingEvents = [];
  const restrictedOnPublicRoute = [];
  const inTable = new Set();
  for (const r of table.rows) {
    const hit = publicFunction(ruleset, r.selector);
    inTable.add(r.selector.toLowerCase());
    if (r.callerRestricted !== false) {
      // a restricted function still matched by the public route would classify privileged
      // activity as public (and possibly unflagged): a gap, not a stale entry (Codex R1 #6)
      if (hit)
        restrictedOnPublicRoute.push({
          contract: r.contract,
          signature: r.function,
          listedAs: hit[0],
        });
      continue;
    }
    const emits = [
      ...new Set(r.events.map(e => byTopic.get(e.topic0.toLowerCase())).filter(Boolean)),
    ].sort();
    if (!emits.length) continue;
    if (!hit) {
      missingFunctions.push({ contract: r.contract, signature: r.function, events: emits });
      continue;
    }
    const have = new Set(hit[1].events ?? []);
    const lack = emits.filter(e => !have.has(e));
    if (lack.length)
      missingEvents.push({ contract: r.contract, signature: r.function, events: lack });
  }
  // listed on the public route but absent from the table: the function no longer exists (safe)
  const stale = Object.keys(ruleset?.publicRoute?.functions ?? {})
    .filter(sig => !inTable.has(ethers.id(sig).slice(0, 10)))
    .sort();
  return { missingFunctions, missingEvents, restrictedOnPublicRoute, stale };
}

function validateTable(t, watched) {
  if (!t || !Array.isArray(t.rows)) throw new Error("table: `rows` must be an array");
  // provenance: which tree, which tool, how (Codex R1 #4); an empty inventory proves nothing
  if (!/^[0-9a-f]{40}$/.test(t.spCommit ?? ""))
    throw new Error("table: spCommit must be a full 40-hex SHA");
  for (const k of ["tool", "toolVersion", "command"])
    if (typeof t[k] !== "string" || !t[k].trim()) throw new Error(`table: ${k} must be stated`);
  if (!t.rows.length) throw new Error("table: no rows (an empty inventory proves nothing)");
  const seen = new Map();
  const byTopic = new Map(watched.map(w => [w.topic0.toLowerCase(), w.name]));
  const hex = (x, n) => typeof x === "string" && new RegExp(`^0x[0-9a-fA-F]{${n}}$`).test(x);
  for (const [i, r] of t.rows.entries()) {
    const at = `rows[${i}]`;
    if (typeof r?.contract !== "string" || !r.contract.trim())
      throw new Error(`${at}.contract must be stated`);
    if (typeof r?.function !== "string" || !/^[A-Za-z_$][\w$]*\(.*\)$/.test(r.function))
      throw new Error(`${at}.function must be a function signature`);
    if (!hex(r.selector, 8) || ethers.id(r.function).slice(0, 10) !== r.selector.toLowerCase())
      throw new Error(`${at}.selector is not keccak256(${r.function})[0:4]`);
    if (typeof r.callerRestricted !== "boolean")
      throw new Error(`${at}.callerRestricted must be true or false (no default)`);
    if (!Array.isArray(r.events)) throw new Error(`${at}.events must be an array`);
    // one row per (contract, selector); an identical repeat is harmless, a conflicting one is not
    const dupKey = `${r.contract}|${r.selector.toLowerCase()}`;
    const canon = JSON.stringify([
      r.function,
      r.callerRestricted,
      [...r.events.map(e => e.topic0.toLowerCase())].sort(),
    ]);
    if (seen.has(dupKey) && seen.get(dupKey) !== canon)
      throw new Error(`${at}: conflicting duplicate row for ${dupKey}`);
    seen.set(dupKey, canon);
    for (const [k, e] of r.events.entries()) {
      const ea = `${at}.events[${k}]`;
      if (typeof e?.signature !== "string" || !hex(e.topic0, 64))
        throw new Error(`${ea} needs a signature and a 32-byte topic0`);
      if (ethers.id(e.signature) !== e.topic0.toLowerCase())
        throw new Error(`${ea}.topic0 is not keccak256(${e.signature})`);
      // a name that disagrees with its topic0 would make the diff misread the row
      const known = byTopic.get(e.topic0.toLowerCase());
      if (known && e.name !== known)
        throw new Error(`${ea}: topic0 is the watched ${known}, but the row names it ${e.name}`);
    }
  }
}

/** Two public-route signatures with one selector would make the runtime lookup pick the first. */
function validateRuleset(ruleset) {
  const bySel = new Map();
  for (const sig of Object.keys(ruleset?.publicRoute?.functions ?? {})) {
    const sel = ethers.id(sig).slice(0, 10);
    if (bySel.has(sel))
      throw new Error(`ruleset: ${bySel.get(sel)} and ${sig} share selector ${sel}`);
    bySel.set(sel, sig);
  }
}

/** The watched SP events with their topic0, from the watcher's own ABI. */
async function watchedEvents() {
  const m = await import(join(ROOT, "services/guardian-watcher/lib/sp-abi.mjs"));
  return m.SP_WATCHED_EVENTS.map(name => ({ name, topic0: m.spIface.getEvent(name).topicHash }));
}

function selfTest(watched) {
  const ev = (name, signature) => ({ name, signature, topic0: ethers.id(signature), via: "test" });
  const sigOf = n => watched.find(w => w.name === n);
  const W = n => {
    const w = sigOf(n);
    return { name: n, signature: null, topic0: w.topic0, via: "test" };
  };
  const row = (fn, restricted, events) => ({
    contract: "SuperPaymaster",
    function: fn,
    selector: ethers.id(fn).slice(0, 10),
    callerRestricted: restricted,
    restriction: restricted ? "onlyOwner" : null,
    events,
  });
  const ruleset = {
    publicRoute: {
      functions: {
        "updatePrice()": { events: ["PriceUpdated", "PriceModeChanged"] },
        "retired()": { events: ["PriceUpdated"] },
      },
    },
  };
  const table = {
    rows: [
      // listed, but lacks EmergencyPriceCancelled
      row("updatePrice()", false, [
        W("PriceUpdated"),
        W("PriceModeChanged"),
        W("EmergencyPriceCancelled"),
      ]),
      // permissionless, emits a watched event, not listed at all
      row("expireWithdraw(address)", false, [
        ev("OperatorWithdrawalExpired", "OperatorWithdrawalExpired(address,uint256)"),
        W("OperatorPaused"),
      ]),
      // permissionless, emits only an unwatched event: fine
      row("poke()", false, [
        ev("OperatorWithdrawalExpired", "OperatorWithdrawalExpired(address,uint256)"),
      ]),
      // restricted: never a gap
      row("setGuardian(address)", true, [W("GuardianSet")]),
    ],
  };
  table.spCommit = "0".repeat(40);
  table.tool = "test";
  table.toolVersion = "0";
  table.command = "selfTest";
  const d = diffEmissions(table, ruleset, watched);
  // a function that became restricted but is still listed: a gap
  const restr = diffEmissions(
    { rows: [row("updatePrice()", true, [W("PriceUpdated")])] },
    ruleset,
    watched
  );
  const restrictedOk =
    restr.restrictedOnPublicRoute.length === 1 &&
    restr.restrictedOnPublicRoute[0].signature === "updatePrice()";
  const ok =
    JSON.stringify(d.missingFunctions.map(x => [x.signature, x.events])) ===
      JSON.stringify([["expireWithdraw(address)", ["OperatorPaused"]]]) &&
    JSON.stringify(d.missingEvents.map(x => [x.signature, x.events])) ===
      JSON.stringify([["updatePrice()", ["EmergencyPriceCancelled"]]]) &&
    JSON.stringify(d.stale) === JSON.stringify(["retired()"]);
  const clean = diffEmissions(
    { rows: [row("updatePrice()", false, [W("PriceUpdated")])] },
    ruleset,
    watched
  );
  const cleanOk = !clean.missingFunctions.length && !clean.missingEvents.length;
  // validation refuses: unstated restriction, a wrong selector, a topic0 not of its signature, a
  // watched topic0 under another name
  const refuses = [
    { rows: [{ ...row("f()", false, []), callerRestricted: undefined }] },
    { rows: [{ ...row("f()", false, []), selector: "0x12345678" }] },
    {
      rows: [
        row("f()", false, [
          { name: "X", signature: "X(uint256)", topic0: ethers.id("Y(uint256)"), via: "" },
        ]),
      ],
    },
    {
      rows: [
        row("f()", false, [
          { ...ev("Renamed", "OperatorPaused(address)"), topic0: sigOf("OperatorPaused").topic0 },
        ]),
      ],
    },
  ].map(t => {
    try {
      validateTable(t, watched);
      return false;
    } catch {
      return true;
    }
  });
  // provenance and inventory refusals
  const prov = { spCommit: "0".repeat(40), tool: "t", toolVersion: "0", command: "c" };
  const more = [
    { ...prov, rows: [] },
    { rows: [row("f()", false, [])] },
    { ...prov, rows: [{ ...row("f()", false, []), contract: "" }] },
    { ...prov, rows: [row("f()", false, []), row("f()", true, [])] },
  ].map(t => {
    try {
      validateTable(t, watched);
      return false;
    } catch {
      return true;
    }
  });
  // a real 4-byte collision: burn(uint256) and collate_propagate_storage(bytes16) are both 0x42966c68
  let ambiguous = false;
  try {
    validateRuleset({
      publicRoute: { functions: { "burn(uint256)": {}, "collate_propagate_storage(bytes16)": {} } },
    });
  } catch {
    ambiguous = true;
  }
  const pass =
    ok && cleanOk && restrictedOk && refuses.every(Boolean) && more.every(Boolean) && ambiguous;
  console.log(
    JSON.stringify(
      { selfTest: pass ? "PASS" : "FAIL", got: d, clean, restrictedOk, refuses, more, ambiguous },
      null,
      2
    )
  );
  return pass;
}

const args = process.argv.slice(2);
const isMain = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) {
  const watched = await watchedEvents();
  if (args.includes("--self-test")) process.exit(selfTest(watched) ? 0 : 1);
  const tablePath = args.find(a => !a.startsWith("--"));
  if (!tablePath) {
    console.error(
      "usage: a3-emission-diff.mjs <table.json> [--ruleset path] [--json] | --self-test"
    );
    process.exit(2);
  }
  const ri = args.indexOf("--ruleset");
  const rulesetPath = ri > 0 ? args[ri + 1] : join(ROOT, "services/guardian-watcher/ruleset.json");
  let table, ruleset;
  try {
    table = JSON.parse(readFileSync(tablePath, "utf8"));
    validateTable(table, watched);
    ruleset = JSON.parse(readFileSync(rulesetPath, "utf8"));
    validateRuleset(ruleset);
  } catch (e) {
    console.error(`bad input: ${e.message}`);
    process.exit(2);
  }
  const d = diffEmissions(table, ruleset, watched);
  const rulesetText = readFileSync(rulesetPath, "utf8");
  const rb = Buffer.from(rulesetText, "utf8");
  const rulesetBlob = createHash("sha1")
    .update(Buffer.concat([Buffer.from(`blob ${rb.length}\0`), rb]))
    .digest("hex");
  const report = {
    rulesetBlob,
    spCommit: table.spCommit ?? null,
    tool: table.tool ?? null,
    toolVersion: table.toolVersion ?? null,
    command: table.command ?? null,
    watched,
    ...d,
  };
  if (args.includes("--json")) console.log(JSON.stringify(report, null, 2));
  else {
    for (const g of d.missingFunctions)
      console.log(
        `MISSING FUNCTION ${g.signature}: emits watched ${g.events.join(", ")}; add it to publicRoute.functions`
      );
    for (const g of d.missingEvents)
      console.log(
        `MISSING EVENTS   ${g.signature}: add ${g.events.join(", ")} to its publicRoute entry`
      );
    for (const s of d.stale)
      console.log(`info: publicRoute lists ${s}, which the table does not show as permissionless`);
    if (!d.missingFunctions.length && !d.missingEvents.length)
      console.log(
        `OK: every watched event a permissionless function can emit is on the public route (${table.rows.length} functions checked)`
      );
  }
  process.exit(
    d.missingFunctions.length || d.missingEvents.length || d.restrictedOnPublicRoute.length ? 1 : 0
  );
}
