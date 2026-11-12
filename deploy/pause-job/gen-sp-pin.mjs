#!/usr/bin/env node
// Generate (or --check) deploy/pause-job/sp-pin.json: everything the pause job takes from
// SuperPaymaster, read through the GitHub API at ONE pinned SP commit, never hand-written
// (DSR 4019916a condition 4; the SignersCommitted lesson: no premise we did not read from SP):
//   - the ABI fragments the job calls or filters on, copied from SP's committed abis/ files;
//   - the ROLE_* set, parsed from the Registry's role constants (IRegistry.sol), each id recomputed
//     as keccak256 of its name and checked against the literal in the source;
//   - the git blob SHA of every file read, so the pin says exactly what it was made from.
//
//   node deploy/pause-job/gen-sp-pin.mjs <40-hex SP commit>            # write sp-pin.json
//   node deploy/pause-job/gen-sp-pin.mjs --check                       # re-derive at the file's
//                                                                       # spCommit; exit 1 on any diff
// Before deploy the pin moves to the rc.8 tag commit (condition 3): regenerate, review the diff.
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { ethers } from "ethers";

const HERE = dirname(fileURLToPath(import.meta.url));
const OUT = join(HERE, "sp-pin.json");
const REPO = "AAStarCommunity/SuperPaymaster";
const FILES = {
  sp: "abis/SuperPaymaster.full.json",
  registry: "abis/Registry.json",
  roles: "contracts/src/interfaces/v3/IRegistry.sol",
};
const SP_NAMES = [
  ["function", "pauseUnderstakedOperator"],
  ["function", "operators"],
  ["function", "owner"],
  ["function", "pendingOwner"],
  ["function", "guardian"],
  ["function", "BLS_AGGREGATOR"],
  ["function", "REGISTRY"],
  ["event", "OperatorConfigured"],
  ["error", "OperatorNotConfigured"],
  ["error", "OperatorMeetsMinimumStake"],
];
const REG_NAMES = [
  ["function", "owner"],
  ["function", "pendingOwner"],
  ["function", "blsAggregator"],
  ["function", "hasRole"],
  ["function", "isReputationSource"],
  ["function", "getRoleConfig"],
  ["event", "RoleConfigured"],
];

const fail = (code, m) => {
  console.error(`gen-sp-pin: ${m}`);
  process.exit(code);
};
const blobSha = buf => createHash("sha1").update(`blob ${buf.length}\0`).update(buf).digest("hex");

function fetchAt(path, sha) {
  let j;
  try {
    j = JSON.parse(
      execFileSync("gh", ["api", `repos/${REPO}/contents/${path}?ref=${sha}`], {
        encoding: "utf8",
        maxBuffer: 64 << 20,
      })
    );
  } catch {
    fail(3, `gh api could not fetch ${path} at ${sha}`);
  }
  let buf;
  if (j.encoding === "base64" && j.content) buf = Buffer.from(j.content, "base64");
  else {
    // files over 1 MB come back without content: fetch the blob by its SHA
    try {
      const b = JSON.parse(
        execFileSync("gh", ["api", `repos/${REPO}/git/blobs/${j.sha}`], {
          encoding: "utf8",
          maxBuffer: 256 << 20,
        })
      );
      buf = Buffer.from(b.content, "base64");
    } catch {
      fail(3, `gh api could not fetch the blob of ${path}`);
    }
  }
  if (blobSha(buf) !== j.sha) fail(3, `${path}: content does not match its blob SHA`);
  return { buf, blob: j.sha };
}

function pick(abiFile, names, label) {
  const abi = JSON.parse(abiFile.toString("utf8"));
  const items = Array.isArray(abi) ? abi : abi.abi;
  return names.map(([type, name]) => {
    const hits = items.filter(x => x.type === type && x.name === name);
    if (hits.length !== 1)
      fail(1, `${label}: ${hits.length} ${type}s named ${name} (need exactly 1)`);
    return hits[0];
  });
}

/** The ROLE_* constants of IRegistry.sol: name -> id, each literal checked. Pure. */
export function parseRoles(raw) {
  // comments removed first (Codex R2 P2-7): `bytes32 /* x */ constant ROLE_X = ...` is a declaration
  const src = raw.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/\/\/[^\n]*/g, "");
  const re =
    /^\s*bytes32\s+constant\s+(ROLE_[A-Z0-9_]+)\s*=\s*keccak256\(\s*"([A-Z0-9_]+)"\s*\)\s*;/gm;
  const roles = {};
  for (const m of src.matchAll(re)) {
    if (m[1] !== `ROLE_${m[2]}`) throw new Error(`${m[1]} hashes "${m[2]}", not its own name`);
    if (roles[m[1]]) throw new Error(`${m[1]} declared twice`);
    roles[m[1]] = ethers.id(m[2]);
  }
  // any other mention of a bytes32 ROLE_ constant we did not parse is a shape we do not know
  // every identifier ROLE_* that is declared or assigned anywhere must be one we parsed
  const all = [...src.matchAll(/\b(ROLE_[A-Z0-9_]+)\s*=(?!=)/g)].map(m => m[1]);
  for (const n of all) if (!roles[n]) throw new Error(`${n} has a form this parser does not read`);
  if (!Object.keys(roles).length) throw new Error("no ROLE_* constants found");
  return roles;
}

export function derive(spCommit, fetch = fetchAt) {
  const sp = fetch(FILES.sp, spCommit);
  const reg = fetch(FILES.registry, spCommit);
  const rs = fetch(FILES.roles, spCommit);
  let roles;
  try {
    roles = parseRoles(rs.buf.toString("utf8"));
  } catch (e) {
    fail(1, `${FILES.roles}: ${e.message}`);
  }
  const pin = {
    schema: "aoa-pause-job-sp-pin/1",
    spRepo: REPO,
    spCommit,
    sources: { [FILES.sp]: sp.blob, [FILES.registry]: reg.blob, [FILES.roles]: rs.blob },
    abi: {
      superPaymaster: pick(sp.buf, SP_NAMES, FILES.sp),
      registry: pick(reg.buf, REG_NAMES, FILES.registry),
    },
    roles,
  };
  // the fragments must load, and the job's decision inputs must have the shape it relies on
  const spI = new ethers.Interface(pin.abi.superPaymaster);
  const op = spI.getFunction("operators");
  if (!op.outputs.some(o => o.name === "isPaused" && o.type === "bool"))
    fail(1, "operators() has no bool isPaused output");
  if (
    spI
      .getFunction("pauseUnderstakedOperator")
      .inputs.map(i => i.type)
      .join() !== "address"
  )
    fail(1, "pauseUnderstakedOperator is not (address)");
  new ethers.Interface(pin.abi.registry);
  return pin;
}

const args = process.argv.slice(2);
if (import.meta.url === `file://${process.argv[1]}`) {
  const text = p => `${JSON.stringify(p, null, 2)}\n`;
  if (args[0] === "--check") {
    let cur;
    try {
      cur = JSON.parse(readFileSync(OUT, "utf8"));
    } catch {
      fail(1, "sp-pin.json is missing or not JSON");
    }
    if (!/^[0-9a-f]{40}$/.test(cur.spCommit ?? "")) fail(1, "sp-pin.json has no 40-hex spCommit");
    const want = text(derive(cur.spCommit));
    if (readFileSync(OUT, "utf8") !== want)
      fail(1, `sp-pin.json differs from SP at ${cur.spCommit}`);
    console.log(`sp-pin.json matches SP at ${cur.spCommit}`);
  } else if (/^[0-9a-f]{40}$/.test(args[0] ?? "")) {
    writeFileSync(OUT, text(derive(args[0])));
    console.log(`wrote sp-pin.json from SP at ${args[0]}`);
  } else fail(2, "usage: gen-sp-pin.mjs <40-hex SP commit> | --check");
}
