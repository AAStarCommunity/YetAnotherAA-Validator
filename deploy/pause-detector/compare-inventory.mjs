#!/usr/bin/env node
// Deploy-day positive control (DSR 2026-11-18): the inventory the detector built on its own must be
// EXACTLY the operator list SP's post-deploy read-back gives. A detector filter that misses an
// operator (an unlisted OperatorConfigured signature, a wrong startBlock) shows here as "missing";
// the deployment is not complete until this exits 0.
//
//   node deploy/pause-detector/compare-inventory.mjs <stateDir>/state.json <sp-operators.json> \
//     --chain-id <id> --sp <SP proxy> [--allow-empty]
//
// <sp-operators.json> is a JSON list of addresses (SP's read-back of CONFIGURED operators). Exit 0:
// equal; 1: they differ (both differences are printed), or SP's list is empty without
// --allow-empty (an empty read-back is more likely a failed one: clestons #453 Medium); 2: an input
// cannot be read, or the state belongs to another chain or SP. Reads only the two files given.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { ethers } from "ethers";

/** Compare the state's inventory with SP's list. Pure. Throws on an input that is not addresses. */
export function compareInventory(state, list, { chainId, sp, allowEmpty = false } = {}) {
  if (!state || typeof state.operators !== "object" || Array.isArray(state.operators))
    throw new Error("the state has no operators map");
  if (!Number.isSafeInteger(chainId) || state.chainId !== chainId)
    throw new Error(`the state is for chain ${state.chainId}, not ${chainId}`);
  if (
    typeof sp !== "string" ||
    !ethers.isAddress(sp) ||
    String(state.spProxy).toLowerCase() !== sp.toLowerCase()
  )
    throw new Error(`the state is for SP ${state.spProxy}, not ${sp}`);
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
  const empty = theirs.size === 0 && !allowEmpty;
  return {
    equal: !empty && !missing.length && !extra.length,
    empty,
    missing,
    extra,
    count: mine.size,
  };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const pos = [];
  const opt = {};
  const argv = process.argv.slice(2);
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--allow-empty") opt.allowEmpty = true;
    else if (argv[i] === "--chain-id" || argv[i] === "--sp") opt[argv[i]] = argv[++i];
    else pos.push(argv[i]);
  }
  const [statePath, listPath] = pos;
  const flag = k => opt[k];
  if (!statePath || !listPath || !flag("--chain-id") || !flag("--sp")) {
    console.error(
      "usage: compare-inventory.mjs <state.json> <sp-operators.json> --chain-id <id> --sp <SP proxy> [--allow-empty]"
    );
    process.exit(2);
  }
  let r;
  try {
    r = compareInventory(
      JSON.parse(readFileSync(statePath, "utf8")),
      JSON.parse(readFileSync(listPath, "utf8")),
      { chainId: Number(flag("--chain-id")), sp: flag("--sp"), allowEmpty: opt.allowEmpty === true }
    );
  } catch (e) {
    console.error(`compare-inventory: ${e.message}`);
    process.exit(2);
  }
  if (r.equal) {
    console.log(`inventory matches SP's read-back: ${r.count} operator(s)`);
    process.exit(0);
  }
  if (r.empty) {
    console.log(
      "SP's read-back lists no operators: more likely a failed read-back (pass --allow-empty if it truly has none)"
    );
    process.exit(1);
  }
  console.log("inventory DIFFERS from SP's read-back; the deployment is not complete:");
  for (const a of r.missing) console.log(`  missing (SP has it, the detector does not): ${a}`);
  for (const a of r.extra) console.log(`  extra (the detector has it, SP does not): ${a}`);
  process.exit(1);
}
