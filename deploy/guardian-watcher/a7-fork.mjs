#!/usr/bin/env node
// A7 rehearsal fork (DSR 272084f2 "one fork, one state"; M0 §9): load SuperPaymaster's dumped A7
// deployment state into a local anvil, prove it is the same state SP read back, and only then hand
// the fork to the rehearsal drills (§9 items 1-8).
//
//   A7_FORK_URL=<archive RPC> node deploy/guardian-watcher/a7-fork.mjs \
//     --dump <state.json> --dump-sha256 <hex> --readback <a7-readback.json> \
//     --fund <test key address> [--port 8546] [--record <out.json>] [--keep]
//
// Steps, each one fatal on failure:
//   1. the dump's sha256 equals --dump-sha256 and the read-back's dumpSha256;
//   2. anvil --fork-url $A7_FORK_URL --fork-block-number <readback.forkBlock> --chain-id
//      <readback.chainId> --hardfork <readback.hardfork> --load-state <dump> (a fork-mode dump holds
//      only the changed state, so the fork parameters are required);
//   3. anvil_setBalance gives the rehearsal's own test key gas (the dump carries no funded account);
//   4. the read-back is regenerated from the fork, field by field, for everything this script can
//      read independently, and compared with SP's aoa-a7-readback/1 file; any difference, or any
//      field it cannot check, stops here (no drill runs on a state that was not proven);
//   5. the rehearsal record notes the anvil version, the dump's and the read-back's sha256, the fork
//      block and every comparison.
// The fork URL is read from the environment and never printed or recorded (only its host).
import { spawn, execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { ethers } from "ethers";

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
// the SAME anvil build SP dumped with (its version is in the read-back): a dump of one EVM build is
// not proven on another, and a build without the read-back's hardfork panics on it (anvil 1.7.1 on
// "amsterdam"). --anvil names a separately installed binary; the shared ~/.foundry is not changed.
// SP's exact build (DSR): anvil 1.8.7-nightly, commit 4e8874b2. Stable 1.7.1 has no Amsterdam and
// panics on it; 1.8.6 computes Amsterdam gas wrongly. Any other commit is refused, whatever --anvil names.
const ANVIL_COMMIT = "4e8874b2bdc840929585ca73e170993c50a4a531";
// Sepolia's Amsterdam activation (EIP-7910 eth_config "current"), as SP read it back
const AMSTERDAM = { activationTime: 1791294816, forkId: "0x6c1d9423" };
const anvilBin =
  opt("anvil") ??
  (existsSync(join(homedir(), ".foundry-a7/bin/anvil"))
    ? join(homedir(), ".foundry-a7/bin/anvil")
    : "anvil");

// ---- 1. inputs
const dump = readFileSync(dumpPath);
if (sha256(dump) !== dumpSha) die(1, "dump sha256 does not match --dump-sha256");
const rbText = readFileSync(readbackPath);
let rb;
try {
  rb = JSON.parse(rbText.toString("utf8"));
} catch {
  die(1, "read-back is not JSON");
}
if (rb.schema !== "aoa-a7-readback/1")
  die(1, `read-back schema is ${rb.schema}, expected aoa-a7-readback/1`);
if (
  String(rb.dumpSha256 ?? "")
    .toLowerCase()
    .replace(/^0x/, "") !== dumpSha
)
  die(1, "the read-back was taken from another dump (dumpSha256 differs)");
for (const k of ["chainId", "hardfork", "forkBlock", "anvilVersion", "anvilCommit", "ethConfig"])
  if (rb[k] === undefined || rb[k] === null) die(1, `read-back has no ${k}`);
if (String(rb.anvilCommit).toLowerCase() !== ANVIL_COMMIT)
  die(1, "the read-back was taken on another anvil commit than the pinned build");
if (String(rb.hardfork).toLowerCase() !== "amsterdam")
  die(1, `read-back hardfork is ${rb.hardfork}, expected amsterdam`);

// ---- 2. anvil on the fork, with the dump loaded
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
if (rb.anvilVersion && anvilVersion !== String(rb.anvilVersion).trim())
  die(
    1,
    `anvil is "${anvilVersion}", SP dumped with "${rb.anvilVersion}": use the same build (--anvil <path>)`
  );
const anvil = spawn(
  anvilBin,
  [
    "--fork-url",
    forkUrl,
    "--fork-block-number",
    String(rb.forkBlock),
    "--chain-id",
    String(rb.chainId),
    "--hardfork",
    String(rb.hardfork),
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

// ---- 4. regenerate and compare
const EIP1967_IMPL = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";
const codehash = async a => ethers.keccak256(await p.getCode(a));
const word = async (a, slot) => p.getStorage(a, slot);
const call = async (a, sig, ret) => {
  const i = new ethers.Interface([`function ${sig} view returns (${ret})`]);
  const name = sig.slice(0, sig.indexOf("("));
  return i.decodeFunctionResult(
    name,
    await p.call({ to: a, data: i.encodeFunctionData(name, []) })
  )[0];
};
const tryCall = async (a, sig, ret) => {
  try {
    return await call(a, sig, ret);
  } catch {
    return undefined;
  }
};
const norm = v =>
  typeof v === "string" && /^0x[0-9a-fA-F]+$/.test(v)
    ? v.toLowerCase()
    : typeof v === "bigint"
      ? v.toString()
      : v;
const cmp = [];
const unverified = [];
const check = (path, theirs, ours) =>
  cmp.push({
    path,
    sp: theirs ?? null,
    fork: ours ?? null,
    ok: ours !== undefined && JSON.stringify(norm(theirs)) === JSON.stringify(norm(ours)),
  });

// the header: the fork itself
check("chainId", rb.chainId, Number((await p.getNetwork()).chainId));
check("forkBlock", rb.forkBlock, Number(rb.forkBlock)); // as launched
check("anvilCommit", rb.anvilCommit, anvilCommit);
check("hardfork", rb.hardfork, "amsterdam"); // as launched, refused above if anything else
// (i) Amsterdam is proven from UPSTREAM, never from the local engine (DSR: a local anvil's eth_config
// reports the engine's own configuration, not Sepolia's; SP a3a_exec.py). SP's read-back carries
// upstream Sepolia's eth_config at the fork block, which must be Sepolia's Amsterdam activation.
const asNum = v => {
  try {
    return Number(BigInt(v));
  } catch {
    return undefined;
  }
};
check(
  "ethConfig.activationTime=Amsterdam",
  AMSTERDAM.activationTime,
  asNum(rb.ethConfig?.activationTime)
);
check("ethConfig.forkId=Amsterdam", AMSTERDAM.forkId, norm(rb.ethConfig?.forkId));
// (iii) behavioural positive control: SP's Amsterdam probe (EIP-8037 CREATE gas) rerun on THIS
// loaded fork must give SP's measured value and the expected one. The probe is sent as a contract
// creation from the funded test key (impersonated; no key is used) and measured as the receipt's
// gasUsed. Until SP publishes the probe's init code, the probe is unverified and the run stops.
const probe = rb.amsterdamProbe;
if (!probe || probe.createGasUsed === undefined || probe.expected === undefined)
  unverified.push("amsterdamProbe");
else {
  check("amsterdamProbe.sp=expected", String(probe.expected), String(probe.createGasUsed));
  if (typeof probe.initcode !== "string" || !/^0x(?:[0-9a-fA-F]{2})+$/.test(probe.initcode))
    unverified.push("amsterdamProbe.initcode");
  else {
    let used;
    try {
      await p.send("anvil_impersonateAccount", [fund]);
      const h = await p.send("eth_sendTransaction", [
        { from: fund, data: probe.initcode, gas: ethers.toQuantity(10_000_000) },
      ]);
      used = (await p.waitForTransaction(h, 1, 30_000))?.gasUsed?.toString();
      await p.send("anvil_stopImpersonatingAccount", [fund]);
    } catch {
      used = undefined;
    }
    check("amsterdamProbe.fork=sp", String(probe.createGasUsed), used);
    check("amsterdamProbe.fork=expected", String(probe.expected), used);
  }
}
// per contract: the fields this script reads independently
const FIELDS = {
  codehash: async c => codehash(c.address),
  erc1967Impl: async c => {
    const w = await word(c.address, EIP1967_IMPL);
    return ethers.getAddress(ethers.dataSlice(w, 12));
  },
  implCodehash: async c => {
    const impl = ethers.getAddress(ethers.dataSlice(await word(c.address, EIP1967_IMPL), 12));
    return codehash(impl);
  },
  owner: c => tryCall(c.address, "owner()", "address"),
  pendingOwner: c => tryCall(c.address, "pendingOwner()", "address"),
  guardian: c => tryCall(c.address, "guardian()", "address"),
  version: c => tryCall(c.address, "version()", "string"),
};
for (const [name, c] of Object.entries(rb.contracts ?? {})) {
  if (!ethers.isAddress(c?.address ?? "")) {
    unverified.push(`contracts.${name}.address`);
    continue;
  }
  check(`contracts.${name}.address`, c.address, c.address);
  for (const [k, v] of Object.entries(c)) {
    if (k === "address") continue;
    if (v === null) continue; // SP read nothing there (e.g. no proxy slot); nothing to compare
    if (FIELDS[k]) check(`contracts.${name}.${k}`, v, await FIELDS[k](c));
    else unverified.push(`contracts.${name}.${k}`);
  }
}
// checks{}: the §9.7 items this script knows how to read; any other is listed, unverified
const KNOWN_CHECKS = {
  categoryCount: async () =>
    tryCall(rb.contracts?.dvtValidator?.address, "categoryCount()", "uint256"),
  verifier: async () =>
    tryCall(rb.contracts?.blsAggregator?.address, "fraudProofVerifier()", "address"),
};
for (const [k, v] of Object.entries(rb.checks ?? {})) {
  const want = v && typeof v === "object" && "value" in v ? v.value : v;
  if (KNOWN_CHECKS[k]) check(`checks.${k}`, want, await KNOWN_CHECKS[k]());
  else unverified.push(`checks.${k}`);
}

const failed = cmp.filter(x => !x.ok);
const record = {
  schema: "aoa-a7-rehearsal-fork/1",
  at: new Date().toISOString(),
  anvilVersion,
  anvilCommit,
  forkHost: (() => {
    try {
      return new URL(forkUrl).hostname;
    } catch {
      return null;
    }
  })(),
  dumpSha256: dumpSha,
  readbackSha256: sha256(rbText),
  forkCorroboration: rb.ethConfig?.corroboration ?? null,
  spReadback: {
    spCommit: rb.spCommit ?? null,
    tag: rb.tag ?? null,
    anvilVersion: rb.anvilVersion ?? null,
    anvilCommit: rb.anvilCommit ?? null,
    ethConfig: rb.ethConfig ?? null,
  },
  chainId: rb.chainId,
  hardfork: rb.hardfork,
  forkBlock: rb.forkBlock,
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
