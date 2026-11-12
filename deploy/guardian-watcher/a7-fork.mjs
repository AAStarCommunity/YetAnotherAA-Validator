#!/usr/bin/env node
// A7 rehearsal fork (DSR 272084f2 "one fork, one state"; M0 §9): load SuperPaymaster's dumped A7
// deployment state into a local anvil, prove it is the same state SP read back, and only then hand
// the fork to the rehearsal drills (§9 items 1-8).
//
//   A7_FORK_URL=<archive RPC> node deploy/guardian-watcher/a7-fork.mjs \
//     --dump <state.json> --dump-sha256 <hex> --readback <a7-readback.json> \
//     (--pins-commit <SP manifest commit> | --address-book <{key: address}.json>) --fund <test key address>
//     [--fork-provider <name>] [--anvil <path>] [--schema <file>] [--abi-dir <dir>] [--port 8546]
//     [--record <out.json>] [--keep]
//
// Steps, each one fatal on failure:
//   1. the read-back validates against SP's frozen aoa-a7-readback/1 schema (Draft 2020-12), fetched
//      through the GitHub API at the pinned SP commit (or --schema), its sha256 pinned; the dump's
//      sha256 equals --dump-sha256 and header.dumpSha256;
//   2. SP's committed abis/ at header.spCommit are fetched through the GitHub API (DSR: not a local
//      build, never SP's working tree; --abi-dir only for an offline copy), each file's sha256
//      recorded; the SlashLevel enum order is read from SP's source at the same commit;
//   3. the anvil binary is SP's build (Commit SHA 4e8874b2 = header.anvilCommit, header.anvilVersion);
//      anvil --fork-url $A7_FORK_URL --fork-block-number header.forkBlock --chain-id header.chainId
//      --hardfork amsterdam --load-state <dump>; its head must be header.readbackBlock;
//   4. every field is compared with an independent read at that head (a7-readback.mjs). The probe
//      runs last, between evm_snapshot and evm_revert, so the drills get the read-back state itself.
//      Any mismatch, or any field without an independent reader, stops;
//   5. only then anvil_setBalance gives the rehearsal's own test key gas;
//   6. the record notes the anvil build, every input sha256, the fork block and every comparison;
//      any URL-like string is redacted from output and record.
// The fork URL is read from the environment and never printed or recorded, not even its host:
// --fork-provider <name> is the operator's non-secret label for it.
import { spawn, execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync, existsSync, readdirSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { ethers } from "ethers";
import { preflight, anvilBuild, waitForAnvil, startFailure, verdict } from "./a7-fork-checks.mjs";
import {
  validate,
  compare,
  sanitize,
  SCHEMA_ID,
  SCHEMA_SHA256,
  SCHEMA_SOURCE,
  ANVIL_COMMIT,
  ABI_FILES,
  SAFE_GETTERS,
  EXAMPLE_SHA256,
  fieldInventory,
  checkInventory,
  abiGapUnverified,
} from "./a7-readback.mjs";

const args = process.argv.slice(2);
const opt = k => {
  const i = args.indexOf(`--${k}`);
  return i >= 0 ? args[i + 1] : undefined;
};
// every diagnostic is redacted (Codex A7 R2 #5): an input echoed into a message can hold a URL
const die = (code, msg) => {
  console.error(
    `a7-fork: ${String(msg).replace(/(?:[a-z][a-z0-9+.-]*:\/\/|\b(?:https?|wss?|ftp|file):)\S*/gi, "(a URL: not shown)")}`
  );
  process.exit(code);
};
// nothing uncaught may print raw input (Codex A7 R3 #3): any failure outside die() is a fixed line
process.on("uncaughtException", () => die(3, "unexpected failure (no detail printed)"));
process.on("unhandledRejection", () => die(3, "unexpected failure (no detail printed)"));
const readInput = (path, what) => {
  try {
    return readFileSync(path);
  } catch {
    return die(1, `cannot read ${what}`);
  }
};
const dumpPath = opt("dump");
const dumpSha = (opt("dump-sha256") ?? "").toLowerCase().replace(/^0x/, "");
const readbackPath = opt("readback");
const fund = opt("fund");
const port = Number(opt("port") ?? 8546);
const recordPath = opt("record");
const forkUrl = process.env.A7_FORK_URL;
// a provider NAME (e.g. "alchemy"), checked to be a plain label, never a URL or host
const forkProvider = opt("fork-provider") ?? null;
if (forkProvider !== null && !/^[a-z][a-z0-9-]{0,30}$/i.test(forkProvider))
  die(2, "--fork-provider must be a plain provider name (letters, digits, dashes)");
if (!dumpPath || !/^[0-9a-f]{64}$/.test(dumpSha) || !readbackPath || !ethers.isAddress(fund ?? ""))
  die(
    2,
    "usage: A7_FORK_URL=.. a7-fork.mjs --dump <file> --dump-sha256 <hex> --readback <file> --address-book <file> --fund <address>"
  );
if (!forkUrl) die(2, "A7_FORK_URL (an archive RPC of the forked chain) is not set");
const sha256 = buf => createHash("sha256").update(buf).digest("hex");
const ghRaw = (path, ref, repo = SCHEMA_SOURCE.repo) => {
  const r = spawnSync(
    "gh",
    [
      "api",
      "-H",
      "Accept: application/vnd.github.raw",
      `repos/${repo}/contents/${path}?ref=${ref}`,
    ],
    { stdio: ["ignore", "pipe", "ignore"], maxBuffer: 64 << 20 }
  );
  return r.status === 0 ? r.stdout : null;
};
// SP's exact build (DSR): anvil 1.8.7-nightly, commit 4e8874b2. Stable 1.7.1 has no Amsterdam and
// panics on it; 1.8.6 computes Amsterdam gas wrongly. Any other commit is refused, whatever --anvil
// names; the default is the separate ~/.foundry-a7 install (the shared ~/.foundry is not changed).
const anvilBin =
  opt("anvil") ??
  (existsSync(join(homedir(), ".foundry-a7/bin/anvil"))
    ? join(homedir(), ".foundry-a7/bin/anvil")
    : "anvil");

// ---- 1. inputs: schema, read-back, dump, address book
const schemaText = opt("schema")
  ? readInput(opt("schema"), "--schema")
  : ghRaw(SCHEMA_SOURCE.path, SCHEMA_SOURCE.ref);
if (!schemaText) die(3, "cannot fetch SP's read-back schema through the GitHub API (--schema)");
if (sha256(schemaText) !== SCHEMA_SHA256)
  die(1, `the read-back schema is not SP's pinned file (sha256 ${SCHEMA_SHA256})`);
const schema = JSON.parse(schemaText.toString("utf8"));
const rbText = readInput(readbackPath, "--readback");
let rb;
try {
  rb = JSON.parse(rbText.toString("utf8"));
} catch {
  die(1, "read-back is not JSON");
}
const errors = validate(schema, rb);
if (errors.length)
  die(1, `read-back does not validate against ${SCHEMA_ID}: ${errors.slice(0, 10).join("; ")}`);
const h = rb.header;
if (h.source !== "fork") die(1, 'read-back source is not "fork": not a fork read-back');
const dump = readInput(dumpPath, "--dump");
if (sha256(dump) !== dumpSha) die(1, "dump sha256 does not match --dump-sha256");
if (h.dumpSha256 !== dumpSha) die(1, "the read-back was taken from another dump (dumpSha256)");
if (h.anvilCommit !== ANVIL_COMMIT)
  die(1, "the read-back was taken on another anvil commit than the pinned build");
if (h.hardfork !== "amsterdam") die(1, "read-back hardfork is not amsterdam");
// the address book: SP's deployments/release/rc8/<chain>.pins.json at the step-13 manifest commit,
// through the GitHub API (DSR); --address-book only for an offline copy (then unverified)
const CHAINS = { 11155111: "sepolia", 10: "optimism", 1: "mainnet" };
// the field inventory: SP's fork example pinned in this checkout (sha256), never the read-back
const exampleText = readInput(
  join(dirname(fileURLToPath(import.meta.url)), "fixtures/a7/aoa-a7-readback-1.example.json"),
  "the pinned example fixture"
);
if (sha256(exampleText) !== EXAMPLE_SHA256)
  die(1, "the pinned example fixture is not SP's (sha256)");
const exampleJson = JSON.parse(exampleText.toString("utf8"));
const inventory = fieldInventory(exampleJson);
const checksInv = checkInventory(exampleJson);
let addressBook = null;
let addressBookDoc = null;
let addressBookSha = null;
let addressBookSource = null;
if (opt("pins-commit") || opt("address-book")) {
  const pinsPath = `deployments/release/rc8/${CHAINS[h.chainId] ?? h.chainId}.pins.json`;
  const raw = opt("pins-commit")
    ? ghRaw(pinsPath, opt("pins-commit"))
    : readInput(opt("address-book"), "--address-book");
  if (!raw) die(3, `cannot fetch SP ${pinsPath} at the manifest commit`);
  addressBookSource = opt("pins-commit") ? `${pinsPath} @ ${opt("pins-commit")}` : "offline copy";
  addressBookSha = sha256(raw);
  try {
    const j = JSON.parse(raw.toString("utf8"));
    addressBookDoc = j; // the whole document goes through the URL gate (Codex A7 R11)
    addressBook = j && typeof j.addresses === "object" ? j.addresses : j;
  } catch {
    die(1, "address book is not JSON");
  }
  for (const [k, v] of Object.entries(addressBook))
    if (!ethers.isAddress(v)) die(1, "an address book entry is not an address");
}

// ---- 2. SP's committed ABIs and SlashLevel order at header.spCommit
const abi = {};
const abiFiles = {};
const missingAbi = [];
for (const [key, file] of Object.entries(ABI_FILES)) {
  if (!(key in rb.contracts)) continue;
  if (!file) {
    missingAbi.push(key);
    continue;
  }
  const raw = opt("abi-dir")
    ? (() => {
        try {
          return readFileSync(join(opt("abi-dir"), file));
        } catch {
          return null;
        }
      })()
    : ghRaw(`abis/${file}`, h.spCommit);
  if (!raw) die(3, `cannot fetch SP abis/${file} at ${h.spCommit}`);
  try {
    const j = JSON.parse(raw.toString("utf8"));
    abi[key] = new ethers.Interface(Array.isArray(j) ? j : j.abi);
  } catch {
    die(1, `abis/${file} is not an ABI`);
  }
  abiFiles[key] = { file, sha256: sha256(raw) };
}
// DisclosureRegistry is retired (DSR 009967e4; archive tag archive/guardian-watcher-w2-2026-11-12):
// its ABI is no longer fetched from the DVT repo. A read-back that still carries it leaves its fields
// without an ABI, hence unverified, and the rehearsal stops until SP's schema drops the contract.
// SlashLevel names -> index, from SP's source at spCommit (the ABI shows only uint8)
let slashLevels = null;
{
  const src = opt("abi-dir")
    ? null
    : ghRaw("contracts/src/modules/monitoring/BLSAggregator.sol", h.spCommit);
  const m = src?.toString("utf8").match(/enum\s+SlashLevel\s*\{([^}]*)\}/);
  if (m)
    slashLevels = Object.fromEntries(
      m[1]
        .replace(/\/\/.*$/gm, "")
        .split(",")
        .map(s => s.trim())
        .filter(Boolean)
        .map((n, i) => [n, i])
    );
}

// ---- 3. the pinned anvil on the fork, with the dump loaded
// Before anything starts (#412 review F2, N1): the UPSTREAM is the read-back's chain and has the
// fork block (anvil's own chainId is whatever --chain-id says, so it proves nothing), and nothing
// is already listening on --port (the tool would otherwise compare against that process).
const preRpc = async (url, method, params) => {
  try {
    const r = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
      signal: AbortSignal.timeout(10_000),
    });
    return (await r.json())?.result;
  } catch {
    return undefined;
  }
};
{
  const f = await preflight({
    rpc: preRpc,
    forkUrl,
    chainId: h.chainId,
    forkBlock: h.forkBlock,
    port,
  });
  if (f) die(f.code, f.msg);
}
let versionText = null;
try {
  versionText = execFileSync(anvilBin, ["--version"], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "ignore"],
  });
} catch {
  // not runnable: anvilBuild reports it
}
const build = anvilBuild(versionText, {
  pinnedCommit: ANVIL_COMMIT,
  headerVersion: h.anvilVersion,
});
if (build.fail) die(build.fail.code, build.fail.msg);
const { version: anvilVersion, commit: anvilCommit } = build;
const anvil = spawn(
  anvilBin,
  [
    "--fork-url",
    forkUrl,
    "--fork-block-number",
    String(h.forkBlock),
    "--chain-id",
    String(h.chainId),
    "--hardfork",
    "amsterdam",
    "--load-state",
    dumpPath,
    "--port",
    String(port),
    "--silent",
  ],
  { stdio: ["ignore", "ignore", "pipe"] }
);
let anvilErr = "";
anvil.stderr.on("data", d => (anvilErr += d));
const stop = () => {
  if (!args.includes("--keep")) anvil.kill("SIGTERM");
};
process.on("exit", stop);
const rpc = `http://127.0.0.1:${port}`;
const p = new ethers.JsonRpcProvider(rpc, undefined, { staticNetwork: true });
const up = await waitForAnvil({
  proc: anvil,
  ping: () => p.send("eth_blockNumber", []),
  sleep: () => new Promise(r => setTimeout(r, 500)),
});
if (!up) {
  const f = startFailure(anvilErr);
  die(f.code, f.msg);
}

// ---- 4. compare at the head (which must be readbackBlock)
// raw upstream JSON-RPC (this script's own provider); undefined result on any failure
const upstream = async (method, params) => {
  try {
    const r = await fetch(forkUrl, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
      signal: AbortSignal.timeout(20_000),
    });
    const j = await r.json();
    return j.error ? { error: j.error } : { result: j.result };
  } catch {
    return { error: { message: "transport" } };
  }
};
class Infra extends Error {}
const isRevert = e => {
  const inner = e?.error ?? e?.info?.error ?? {};
  return inner.code === 3 || /revert/i.test(String(inner.message ?? e?.shortMessage ?? ""));
};
const reader = {
  chainId: async () => Number(await p.send("eth_chainId", [])),
  head: async () => Number(await p.send("eth_blockNumber", [])),
  block: async n => {
    const b = await p.send("eth_getBlockByNumber", [ethers.toQuantity(n), false]);
    return b ? { hash: b.hash } : null;
  },
  code: async (a, block) =>
    p.send("eth_getCode", [a, block === undefined ? "latest" : ethers.toQuantity(block)]),
  keccak: c => ethers.keccak256(c),
  slot: async (a, s) => p.send("eth_getStorageAt", [a, s, "latest"]),
  // distinct outcomes (Codex A7 R1 #3): value / empty / revert / decode; anything else throws
  call: async (a, iface, f, callArgs = []) => {
    let out;
    try {
      out = await p.send("eth_call", [
        { to: a, data: iface.encodeFunctionData(f, callArgs) },
        "latest",
      ]);
    } catch (e) {
      if (isRevert(e)) return { status: "revert" };
      throw new Infra("eth_call failed");
    }
    if (out === "0x") return { status: "empty" };
    try {
      const r = iface.decodeFunctionResult(f, out);
      return { status: "value", v: f.outputs.length === 1 ? r[0] : r };
    } catch {
      return { status: "decode" };
    }
  },
  logs: async ({ address, topics, fromBlock, toBlock }) => {
    const all = [];
    for (let b = fromBlock; b <= toBlock; b += 10_000) {
      const to = Math.min(toBlock, b + 9_999);
      const part = await p.send("eth_getLogs", [
        { address, topics, fromBlock: ethers.toQuantity(b), toBlock: ethers.toQuantity(to) },
      ]);
      all.push(...part);
    }
    return all;
  },
  upstreamHeader: async n => {
    const r = await upstream("eth_getBlockByNumber", [ethers.toQuantity(n), false]);
    return r.result
      ? {
          blockAccessListHash: "blockAccessListHash" in r.result,
          slotNumber: "slotNumber" in r.result,
        }
      : undefined;
  },
  // the probe, last; snapshot/revert so the drills get the read-back state; the sender is
  // impersonated (no key); judged: fork receipt gasUsed, upstream simulateV1 gasUsed, upstream
  // eth_call at gas = gasUsed; recorded only: estimates and gas - 1
  upstreamCodehash: async (a, n) => {
    const r = await upstream("eth_getCode", [a, ethers.toQuantity(n)]);
    return typeof r.result === "string" && r.result !== "0x"
      ? ethers.keccak256(r.result).toLowerCase()
      : undefined;
  },
  probe: async ({ sender, initcode, forkBlock, gasUsed }) => {
    const tx = { from: sender, data: initcode };
    const blockTag = ethers.toQuantity(forkBlock);
    const out = {};
    const sim = await upstream("eth_simulateV1", [
      { blockStateCalls: [{ calls: [tx] }] },
      blockTag,
    ]);
    const c0 = sim.result?.[0]?.calls?.[0];
    // judged (#412 review F3): a number on success; "unsupported" only when the method does not
    // exist (-32601); anything else (a revert, an RPC error) is "failed" and fails the comparison
    if (c0 && c0.status === "0x1") out.simulate = Number(c0.gasUsed);
    else if (
      sim.error?.code === -32601 ||
      /not (found|supported|available)/i.test(String(sim.error?.message ?? ""))
    )
      out.simulate = "unsupported";
    else out.simulate = "failed";
    const at = await upstream("eth_call", [{ ...tx, gas: ethers.toQuantity(gasUsed) }, blockTag]);
    out.callAtGasUsed = at.result !== undefined && !at.error;
    const at1 = await upstream("eth_call", [
      { ...tx, gas: ethers.toQuantity(gasUsed - 1) },
      blockTag,
    ]);
    out.callAtGasUsedMinusOne = at1.result !== undefined && !at1.error;
    const el = await upstream("eth_estimateGas", [tx, blockTag]);
    out.estimateLive = el.result === undefined ? undefined : Number(el.result);
    const snap = await p.send("evm_snapshot", []);
    try {
      out.estimateFork = Number(await p.send("eth_estimateGas", [tx]));
      await p.send("anvil_impersonateAccount", [sender]);
      const hash = await p.send("eth_sendTransaction", [
        { ...tx, gas: ethers.toQuantity(gasUsed * 2) },
      ]);
      // bounded receipt polling of our own (Codex A7 R9): ethers' waitForTransaction logs RPC
      // errors to stdout from inside its poller; a failure here throws into the fixed diagnostic
      let rc = null;
      for (let i = 0; i < 60 && !rc; i++) {
        rc = await p.send("eth_getTransactionReceipt", [hash]);
        if (!rc) await new Promise(r => setTimeout(r, 500));
      }
      await p.send("anvil_stopImpersonatingAccount", [sender]);
      out.gasUsedFork = rc && rc.status === "0x1" ? Number(rc.gasUsed) : undefined;
    } finally {
      // the revert must succeed (Codex A7 R2 #3); the head and hash are re-checked after compare
      if ((await p.send("evm_revert", [snap])) !== true) throw new Infra("evm_revert failed");
    }
    return out;
  },
};
let result;
try {
  result = await compare(rb, reader, {
    anvilVersion,
    anvilCommit,
    dumpSha256: dumpSha,
    forkBlock: h.forkBlock,
    abi,
    safe: new ethers.Interface(SAFE_GETTERS),
    addressBook,
    addressBookDoc,
    fieldInventory: inventory,
    checkInventory: checksInv,
    slashLevels,
  });
} catch (e) {
  // a failed observation proves nothing: the run stops (fixed wording, nothing from the RPC)
  die(3, `a read failed (${e instanceof Infra ? e.message : "RPC error"}): no verdict`);
}
const { cmp, unverified } = result;
// a contract with no ABI file is unverified unless compare() verified it as not deployed
unverified.push(...abiGapUnverified(missingAbi, result.absent ?? []));
// ABIs or the address book not fetched from SP at the pinned commits are not authenticated
// (Codex A7 R2 #4): usable for a dry run, never for SAME STATE
if (opt("abi-dir")) unverified.push("ABIs from --abi-dir (not SP's abis/ at spCommit)");
if (opt("address-book") && !opt("pins-commit"))
  unverified.push("address book from --address-book (not SP's pins at the manifest commit)");
// the probe ran between snapshot and revert: the drills must get exactly the read-back block
{
  const head = Number(await p.send("eth_blockNumber", []));
  const b = await p.send("eth_getBlockByNumber", [ethers.toQuantity(h.readbackBlock), false]);
  cmp.push({
    path: "fork restored after the probe (head, hash)",
    sp: `${h.readbackBlock} ${h.readbackBlockHash}`,
    fork: `${head} ${b?.hash}`,
    ok:
      head === h.readbackBlock &&
      !!b?.hash &&
      b.hash.toLowerCase() === h.readbackBlockHash.toLowerCase(),
  });
}
// the anvil this tool started must still be the one answering (#412 review N1)
const { failed, proven, exitCode } = verdict({ cmp, unverified, anvil });

// ---- 5. gas for the rehearsal's own test key, only on a proven fork
if (proven) await p.send("anvil_setBalance", [fund, ethers.toQuantity(ethers.parseEther("100"))]);

const record = {
  schema: "aoa-a7-rehearsal-fork/3",
  at: new Date().toISOString(),
  anvilVersion,
  anvilCommit,
  readbackSchema: { ...SCHEMA_SOURCE, sha256: SCHEMA_SHA256 },
  abiFiles,
  abiSource: opt("abi-dir") ? "offline copy (--abi-dir)" : `GitHub API at ${h.spCommit}`,
  slashLevels,
  addressBookSha256: addressBookSha,
  addressBookSource,
  // the operator's own label for the fork RPC, never anything derived from A7_FORK_URL: a
  // hostname can carry an access token in a subdomain (Codex A7 R16)
  forkProvider: forkProvider,
  dumpSha256: dumpSha,
  readbackSha256: sha256(rbText),
  spReadback: { spCommit: h.spCommit, tag: h.tag, providers: h.providers },
  chainId: h.chainId,
  forkBlock: h.forkBlock,
  readbackBlock: h.readbackBlock,
  funded: proven ? fund : null,
  compared: cmp.length,
  failed,
  unverified,
  verdict: proven ? "SAME STATE: drills may run" : "STOP: the fork is not proven to be SP's state",
  rpc: args.includes("--keep") ? rpc : null,
};
const text = JSON.stringify(sanitize(record, new Set(["rpc"])), null, 2);
if (recordPath) writeFileSync(recordPath, text + "\n");
console.log(text);
process.exit(exitCode);
