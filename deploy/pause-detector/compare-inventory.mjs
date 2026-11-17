#!/usr/bin/env node
// Deploy-day positive control (DSR 2026-11-18): the inventory the detector built on its own must be
// EXACTLY the operator list SP's post-deploy read-back gives. A detector filter that misses an
// operator (an unlisted OperatorConfigured signature, a wrong startBlock) shows here as "missing";
// the deployment is not complete until this exits 0.
//
//   node deploy/pause-detector/compare-inventory.mjs <stateDir>/state.json <sp-operators.json>
//
// <sp-operators.json> is a JSON list of addresses (SP's read-back). Exit 0: equal; 1: they differ
// (both differences are printed); 2: an input cannot be read. Reads only the two files it is given.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { ethers } from "ethers";

/** Compare the state's inventory with SP's list. Pure. Throws on an input that is not addresses. */
export function compareInventory(state, list) {
  if (!state || typeof state.operators !== "object" || Array.isArray(state.operators))
    throw new Error("the state has no operators map");
  if (!Array.isArray(list)) throw new Error("the SP list is not a JSON list");
  const norm = a => {
    if (typeof a !== "string" || !ethers.isAddress(a))
      throw new Error(`${JSON.stringify(a)} is not an address`);
    return ethers.getAddress(a);
  };
  const mine = new Set(Object.keys(state.operators).map(norm));
  const theirs = new Set(list.map(norm));
  const missing = [...theirs].filter(a => !mine.has(a)).sort();
  const extra = [...mine].filter(a => !theirs.has(a)).sort();
  return { equal: !missing.length && !extra.length, missing, extra, count: mine.size };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const [statePath, listPath] = process.argv.slice(2);
  if (!statePath || !listPath) {
    console.error("usage: compare-inventory.mjs <state.json> <sp-operators.json>");
    process.exit(2);
  }
  let r;
  try {
    r = compareInventory(
      JSON.parse(readFileSync(statePath, "utf8")),
      JSON.parse(readFileSync(listPath, "utf8"))
    );
  } catch (e) {
    console.error(`compare-inventory: ${e.message}`);
    process.exit(2);
  }
  if (r.equal) {
    console.log(`inventory matches SP's read-back: ${r.count} operator(s)`);
    process.exit(0);
  }
  console.log("inventory DIFFERS from SP's read-back; the deployment is not complete:");
  for (const a of r.missing) console.log(`  missing (SP has it, the detector does not): ${a}`);
  for (const a of r.extra) console.log(`  extra (the detector has it, SP does not): ${a}`);
  process.exit(1);
}
