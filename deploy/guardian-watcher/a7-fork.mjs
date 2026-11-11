#!/usr/bin/env node
// A7 rehearsal fork (DSR 272084f2 "one fork, one state"; M0 §9): load SuperPaymaster's dumped A7
// deployment state into a local anvil, prove it is the same state SP read back, and only then hand
// the fork to the rehearsal drills (§9 items 1-8).
//
//   A7_FORK_URL=<archive RPC> node deploy/guardian-watcher/a7-fork.mjs \
//     --dump <state.json> --dump-sha256 <hex> --readback <a7-readback.json> \
//     --fund <test key address> [--abi-dir <dir>] [--anvil <path>] [--schema <file>] [--port 8546]
//     [--record <out.json>] [--keep]
//
// Steps, each one fatal on failure:
//   1. the read-back validates against SP's aoa-a7-readback/1 schema (Draft 2020-12), fetched through
//      the GitHub API at the pinned SP commit (or --schema), its sha256 pinned; the dump's sha256
//      equals --dump-sha256 and header.dumpSha256;
//   2. the anvil binary is SP's build (Commit SHA 4e8874b2, header.anvilCommit, header.anvilVersion);
//      anvil --fork-url $A7_FORK_URL --fork-block-number header.forkBlock --chain-id header.chainId
//      --hardfork amsterdam --load-state <dump>;
//   3. anvil_setBalance gives the rehearsal's own test key gas;
//   4. every field is compared with an independent read (a7-readback.mjs): header, contracts,
//      checks, then the Amsterdam probe (last: it sends a transaction on the fork). Amsterdam is
//      proven from upstream (SP's ethConfig + this script's own upstream header), never from the
//      local engine's eth_config. Any mismatch, or any field without an independent reader, stops;
//   5. the record notes the anvil build, both sha256s, the fork block and every comparison.
// --abi-dir holds <contractKey>.json (a forge artifact or a bare ABI array) built from SP at
// header.spCommit: a null ("absent") field is decided from it (the selector is not in the ABI), never
// by calling, because a contract with a fallback answers any selector (DSR). Without it, every null
// field is unverified. Each ABI file's sha256 is recorded.
// The fork URL is read from the environment and never printed or recorded (only its host).
import { spawn, execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync, existsSync, readdirSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { ethers } from "ethers";
import {
  validate,
  compare,
  SCHEMA_ID,
  SCHEMA_SHA256,
  SCHEMA_SOURCE,
  ANVIL_COMMIT,
} from "./a7-readback.mjs";

const args = process.argv.slice(2);
const opt = k => {
  const i = args.indexOf(`--${k}`);
  return i >= 0 ? args[i + 1] : undefined;
};
const die = (code, msg) => {
  console.error(`a7-fork: ${msg}`);
  process.exit(code);
};
const dumpPath = opt("dump");
const dumpSha = (opt("dump-sha256") ?? "").toLowerCase().replace(/^0x/, "");
const readbackPath = opt("readback");
const fund = opt("fund");
const port = Number(opt("port") ?? 8546);
const recordPath = opt("record");
const forkUrl = process.env.A7_FORK_URL;
if (!dumpPath || !/^[0-9a-f]{64}$/.test(dumpSha) || !readbackPath || !ethers.isAddress(fund ?? ""))
  die(
    2,
    "usage: A7_FORK_URL=.. a7-fork.mjs --dump <file> --dump-sha256 <hex> --readback <file> --fund <address>"
  );
if (!forkUrl) die(2, "A7_FORK_URL (an archive RPC of the forked chain) is not set");
const sha256 = buf => createHash("sha256").update(buf).digest("hex");
// SP's exact build (DSR): anvil 1.8.7-nightly, commit 4e8874b2. Stable 1.7.1 has no Amsterdam and
// panics on it; 1.8.6 computes Amsterdam gas wrongly. Any other commit is refused, whatever --anvil
// names; the default is the separate ~/.foundry-a7 install (the shared ~/.foundry is not changed).
const anvilBin =
  opt("anvil") ??
  (existsSync(join(homedir(), ".foundry-a7/bin/anvil"))
    ? join(homedir(), ".foundry-a7/bin/anvil")
    : "anvil");

// ---- 1. inputs: schema, read-back, dump
let schemaText;
if (opt("schema")) schemaText = readFileSync(opt("schema"));
else {
  const r = spawnSync(
    "gh",
    [
      "api",
      "-H",
      "Accept: application/vnd.github.raw",
      `repos/${SCHEMA_SOURCE.repo}/contents/${SCHEMA_SOURCE.path}?ref=${SCHEMA_SOURCE.ref}`,
    ],
    { stdio: ["ignore", "pipe", "ignore"], maxBuffer: 1 << 20 }
  );
  if (r.status !== 0)
    die(3, "cannot fetch SP's read-back schema through the GitHub API (--schema)");
  schemaText = r.stdout;
}
if (sha256(schemaText) !== SCHEMA_SHA256)
  die(1, `the read-back schema is not SP's pinned file (sha256 ${SCHEMA_SHA256})`);
const schema = JSON.parse(schemaText.toString("utf8"));
const rbText = readFileSync(readbackPath);
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
if (h.source !== "fork") die(1, `read-back source is ${h.source}: not a fork read-back`);
const dump = readFileSync(dumpPath);
if (sha256(dump) !== dumpSha) die(1, "dump sha256 does not match --dump-sha256");
if (h.dumpSha256 !== dumpSha) die(1, "the read-back was taken from another dump (dumpSha256)");
if (h.anvilCommit !== ANVIL_COMMIT)
  die(1, "the read-back was taken on another anvil commit than the pinned build");
if (h.hardfork !== "amsterdam") die(1, `read-back hardfork is ${h.hardfork}, expected amsterdam`);

// ABIs of SP's build at header.spCommit, for null ("absent") fields
const abi = {};
const abiFiles = {};
if (opt("abi-dir")) {
  for (const f of readdirSync(opt("abi-dir")).filter(x =>
    /^[A-Za-z_][A-Za-z0-9_]*\.json$/.test(x)
  )) {
    const raw = readFileSync(join(opt("abi-dir"), f));
    let frags;
    try {
      const j = JSON.parse(raw.toString("utf8"));
      frags = new ethers.Interface(Array.isArray(j) ? j : j.abi);
    } catch {
      die(1, `ABI file ${f} is not an ABI or a forge artifact`);
    }
    const key = f.slice(0, -5);
    abi[key] = new Set(frags.fragments.filter(x => x.type === "function").map(x => x.selector));
    abiFiles[key] = sha256(raw);
  }
}

// ---- 2. the pinned anvil on the fork, with the dump loaded
let anvilVersion;
let anvilCommit;
try {
  const v = execFileSync(anvilBin, ["--version"], { encoding: "utf8" });
  anvilVersion = v.split("\n")[0].trim();
  anvilCommit = v.match(/^Commit SHA:\s*([0-9a-f]{40})\s*$/m)?.[1] ?? null;
} catch {
  die(3, "anvil not runnable (--anvil <path>)");
}
if (anvilCommit !== ANVIL_COMMIT)
  die(1, `anvil commit is ${anvilCommit ?? "unknown"}, required ${ANVIL_COMMIT} (--anvil <path>)`);
if (anvilVersion !== h.anvilVersion)
  die(1, `anvil is "${anvilVersion}", SP dumped with "${h.anvilVersion}"`);
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
let up = false;
for (let i = 0; i < 120 && !up; i++) {
  await new Promise(r => setTimeout(r, 500));
  if (anvil.exitCode !== null) break;
  try {
    await p.getBlockNumber();
    up = true;
  } catch {
    // starting
  }
}
// anvil's own message may echo the fork URL: only a fixed category is shown
if (!up)
  die(
    3,
    `anvil did not start (${
      /panicked|unimplemented/i.test(anvilErr)
        ? "it crashed: this build cannot run the read-back's hardfork"
        : /fork|connect|request|dns|timed? ?out/i.test(anvilErr)
          ? "cannot reach or read the fork RPC"
          : /unknown|invalid/i.test(anvilErr)
            ? "rejected an argument"
            : "no RPC"
    })`
  );

// ---- 3. gas for the rehearsal's own test key
await p.send("anvil_setBalance", [fund, ethers.toQuantity(ethers.parseEther("100"))]);

// ---- 4. compare; reads at header.readbackBlock (or latest when the fork does not serve it)
const head = await p.getBlockNumber();
const tag = h.readbackBlock <= head ? ethers.toQuantity(h.readbackBlock) : "latest";
const TYPES = {
  address: "address",
  uint256: "uint256",
  bytes32: "bytes32",
  bool: "bool",
  string: "string",
};
// raw upstream JSON-RPC (this script's own provider): Amsterdam-only header fields at forkBlock
const upstream = async (method, params) => {
  try {
    const r = await fetch(forkUrl, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
      signal: AbortSignal.timeout(20_000),
    });
    return (await r.json())?.result;
  } catch {
    return undefined;
  }
};
const reader = {
  chainId: async () => Number((await p.getNetwork()).chainId),
  block: async n => {
    try {
      const b = await p.send("eth_getBlockByNumber", [ethers.toQuantity(n), false]);
      return b ? { hash: b.hash } : null;
    } catch {
      return null;
    }
  },
  code: async a => p.send("eth_getCode", [a, tag]),
  keccak: c => ethers.keccak256(c),
  slot: async (a, s) => p.send("eth_getStorageAt", [a, s, tag]),
  call: async (a, name, type) => {
    if (!TYPES[type]) return undefined;
    const i = new ethers.Interface([`function ${name}() view returns (${TYPES[type]})`]);
    try {
      const out = await p.send("eth_call", [{ to: a, data: i.encodeFunctionData(name, []) }, tag]);
      if (out === "0x") return undefined; // no such function (or an EOA)
      const v = i.decodeFunctionResult(name, out)[0];
      return typeof v === "bigint" ? v.toString() : v;
    } catch {
      return undefined;
    }
  },
  upstreamHeader: async n => {
    const b = await upstream("eth_getBlockByNumber", [ethers.toQuantity(n), false]);
    return b
      ? { blockAccessListHash: "blockAccessListHash" in b, slotNumber: "slotNumber" in b }
      : undefined;
  },
  // last: it changes the fork. Same sender and init code as SP; the sender is impersonated (no key)
  probe: async ({ sender, initcode, forkBlock }) => {
    try {
      const tx = { from: sender, data: initcode };
      const estimateLive = await upstream("eth_estimateGas", [tx, ethers.toQuantity(forkBlock)]);
      const estimateFork = Number(await p.send("eth_estimateGas", [tx]));
      await p.send("anvil_impersonateAccount", [sender]);
      const hash = await p.send("eth_sendTransaction", [
        { ...tx, gas: ethers.toQuantity(estimateFork * 2) },
      ]);
      const rc = await p.waitForTransaction(hash, 1, 30_000);
      await p.send("anvil_stopImpersonatingAccount", [sender]);
      return {
        estimateFork,
        gasUsedFork: rc && rc.status === 1 ? Number(rc.gasUsed) : undefined,
        estimateLive: estimateLive === undefined ? undefined : Number(estimateLive),
      };
    } catch {
      return undefined;
    }
  },
};
const { cmp, unverified } = await compare(rb, reader, {
  anvilVersion,
  anvilCommit,
  dumpSha256: dumpSha,
  forkBlock: h.forkBlock,
  abi,
});

const failed = cmp.filter(x => !x.ok);
const record = {
  schema: "aoa-a7-rehearsal-fork/2",
  at: new Date().toISOString(),
  anvilVersion,
  anvilCommit,
  readbackSchema: { ...SCHEMA_SOURCE, sha256: SCHEMA_SHA256 },
  abiFiles,
  forkHost: (() => {
    try {
      return new URL(forkUrl).hostname;
    } catch {
      return null;
    }
  })(),
  dumpSha256: dumpSha,
  readbackSha256: sha256(rbText),
  spReadback: { spCommit: h.spCommit, tag: h.tag, providers: h.providers },
  chainId: h.chainId,
  forkBlock: h.forkBlock,
  readbackBlock: h.readbackBlock,
  readAt: tag,
  funded: fund,
  compared: cmp.length,
  failed,
  unverified,
  verdict:
    failed.length || unverified.length
      ? "STOP: the fork is not proven to be SP's state"
      : "SAME STATE: drills may run",
  rpc: args.includes("--keep") ? rpc : null,
};
const text = JSON.stringify(record, null, 2);
if (recordPath) writeFileSync(recordPath, text + "\n");
console.log(text);
process.exit(failed.length || unverified.length ? 1 : 0);
