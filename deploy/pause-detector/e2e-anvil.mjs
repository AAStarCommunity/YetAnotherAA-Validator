#!/usr/bin/env node
// The pause detector end to end against SuperPaymaster's REAL compiled contracts: SP's own
// contracts/script/v3/DeployAnvil.s.sol deploys the stack from an SP checkout AT sp-pin.json's
// commit (built with `forge build`); this script refuses any other commit. The understaked state is
// produced on chain the real way (the Registry owner raises ROLE_PAYMASTER_SUPER's minStake), and
// the pause is done the way the alert tells a person to: the exact `cast send` command it prints,
// run here with anvil's public test account #1 (not a secret). The detector itself only reads.
//
//   node deploy/pause-detector/e2e-anvil.mjs --sp /path/to/SuperPaymaster   (checkout at the pin)
//
// This file is a TEST: it holds anvil test keys and sends transactions to set the chain up. The
// detector (detector.mjs, lib/detect.mjs) does neither; check-pause-detector.mjs proves that.
import { execFileSync, spawn, spawnSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { ethers } from "ethers";
import { PIN, emptyState, runRound, spIface, regIface, IMPL_SLOT } from "./lib/detect.mjs";
import { readOnlyChain, resolvedKeys } from "./detector.mjs";

const HERE_E2E = dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const die = (c, m) => {
  console.error(`detector e2e: ${m}`);
  process.exit(c);
};
const i = args.indexOf("--sp");
const spDir = i >= 0 ? args[i + 1] : null;
if (!spDir) die(2, "usage: e2e-anvil.mjs --sp <SuperPaymaster checkout at sp-pin.json's commit>");
const git = a => execFileSync("git", ["-C", spDir, ...a], { encoding: "utf8" });
if (git(["rev-parse", "HEAD"]).trim() !== PIN.spCommit)
  die(2, `the SP checkout is not at sp-pin.json's ${PIN.spCommit}`);
if (git(["status", "--porcelain", "--untracked-files=no"]).trim())
  die(2, "the SP checkout has local changes to tracked files");

const bin = n =>
  existsSync(join(homedir(), ".foundry/bin", n)) ? join(homedir(), ".foundry/bin", n) : n;
const PORT = 20000 + Math.floor(Math.random() * 20000);
const URL = `http://127.0.0.1:${PORT}`;
// anvil's well-known public test accounts (not secrets): #0 deploys and owns SP, #1 is "the human"
const DEPLOYER_PK = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const HUMAN_PK = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";

const anvil = spawn(bin("anvil"), ["--port", String(PORT), "--silent"], { stdio: "ignore" });
process.on("exit", () => {
  try {
    anvil.kill("SIGKILL");
  } catch {
    /* gone */
  }
});
const p = new ethers.JsonRpcProvider(URL, undefined, { staticNetwork: true, cacheTimeout: -1 });
for (let k = 0; ; k++) {
  try {
    await p.send("eth_chainId", []);
    break;
  } catch {
    if (k > 100) die(3, "anvil did not start");
    await new Promise(r => setTimeout(r, 100));
  }
}
const cfgFile = join(spDir, "deployments/config.anvil.json");
const before = existsSync(cfgFile) ? readFileSync(cfgFile) : null;
try {
  execFileSync(
    bin("forge"),
    [
      "script",
      "contracts/script/v3/DeployAnvil.s.sol:DeployAnvil",
      "--rpc-url",
      URL,
      "--broadcast",
      "--disable-code-size-limit",
      "--private-key",
      DEPLOYER_PK,
    ],
    {
      cwd: spDir,
      env: { ...process.env, ENV: "anvil", LOCAL_DEV_GOVERNANCE_ACK: "true" },
      stdio: ["ignore", "ignore", "pipe"],
      maxBuffer: 64 << 20,
    }
  );
} catch (e) {
  die(
    3,
    `DeployAnvil failed: ${String(e.stderr ?? "")
      .split("\n")
      .filter(l => /Error/.test(l))
      .slice(0, 3)
      .join(" | ")}`
  );
}
const deployed = JSON.parse(readFileSync(cfgFile, "utf8"));
if (before) writeFileSync(cfgFile, before);
await p.send("anvil_mine", ["0x80"]); // anvil finalized = latest - 64
const SP = deployed.superPaymaster;
const REG = deployed.registry;

const results = [];
const cell = (name, ok, got) =>
  results.push({
    name,
    ok: !!ok,
    got: JSON.stringify(got ?? null, (k, v) => (typeof v === "bigint" ? String(v) : v)),
  });
let sectionNo = 0;
const section = async fn => {
  const k = ++sectionNo;
  try {
    await fn();
  } catch (e) {
    cell(`section ${k} ran to the end`, false, String(e?.message ?? e).slice(0, 300));
  }
};

// the identity pins, read here the way the tag read-back will provide them
const implOf = async a => `0x${(await p.getStorage(a, IMPL_SLOT)).slice(-40)}`;
const impl = await implOf(SP);
const hashOf = async a => ethers.keccak256(await p.getCode(a));
const CFG = {
  chainId: 31337,
  spProxy: SP,
  registry: REG,
  implementation: impl,
  proxyCodeHash: await hashOf(SP),
  implementationCodeHash: await hashOf(impl),
  registryCodeHash: await hashOf(REG),
  registryImplementation: await implOf(REG),
  registryImplementationCodeHash: await hashOf(await implOf(REG)),
  startBlock: 1,
  logChunk: 50,
  rescanBlocks: 20000,
};
const chain = readOnlyChain(URL);
const deployer = new ethers.Wallet(DEPLOYER_PK, p);
const read = async (to, iface, fn, a = []) =>
  iface.decodeFunctionResult(fn, await p.call({ to, data: iface.encodeFunctionData(fn, a) }));
const ROLE_SUPER = PIN.roles.ROLE_PAYMASTER_SUPER;
const roleCfgType = PIN.abi.registry.find(f => f.name === "getRoleConfig").outputs[0];
const cfgIface = new ethers.Interface([
  {
    type: "function",
    name: "configureRole",
    stateMutability: "nonpayable",
    inputs: [
      { name: "roleId", type: "bytes32" },
      { ...roleCfgType, name: "config" },
    ],
    outputs: [],
  },
]);
const raiseMinStake = async () => {
  const c = (await read(REG, regIface, "getRoleConfig", [ROLE_SUPER]))[0];
  const next = c.toObject();
  next.minStake = c.minStake * 1000n + 10n ** 24n;
  const tx = await deployer.sendTransaction({
    to: REG,
    data: cfgIface.encodeFunctionData("configureRole", [ROLE_SUPER, next]),
  });
  if ((await tx.wait()).status !== 1) throw new Error("configureRole reverted");
};
const isPaused = async op => (await read(SP, spIface, "operators", [op])).isPaused;
const snapshot = () => p.send("evm_snapshot", []);
const revert = id => p.send("evm_revert", [id]);
const nonceOfAll = async () => p.getTransactionCount(deployer.address, "latest");

// ---- D1: nothing understaked: both DeployAnvil operators found, all ok, clear, silent
let st = emptyState(CFG);
await section(async () => {
  const n0 = await nonceOfAll();
  const r = await runRound(st, { chain, cfg: CFG });
  cell(
    "inventory: both DeployAnvil operators found from the SP proxy's logs",
    Object.keys(st.operators).length === 2,
    st.operators
  );
  cell(
    "identity confirmed at B against the real deployment",
    r.report.identity.ok,
    r.report.identity
  );
  cell(
    "nothing understaked: every operator ok, the round clear, no alert",
    r.report.clear && r.alerts.length === 0 && r.report.operators.every(o => o.status === "ok"),
    r
  );
  cell(
    "the round sent nothing (the deployer's nonce is unchanged)",
    (await nonceOfAll()) === n0,
    n0
  );
});

// ---- D2: understaked by a real configureRole: PAUSE NEEDED with a command that works
const s1 = await snapshot();
await section(async () => {
  await raiseMinStake();
  await p.send("anvil_mine", ["0x80"]);
  const r = await runRound(st, { chain, cfg: CFG });
  const act = r.alerts.filter(a => a.key.startsWith("actionable:"));
  cell(
    "understaked after a real minStake raise: both operators actionable",
    act.length === 2 && r.report.clear === false,
    r.alerts.map(a => a.text)
  );
  // the human runs exactly the printed command (plus RPC and signer flags)
  for (const a of act) {
    const line = a.text.split("\n")[1];
    const cmd = line.replace(/ --rpc-url <RPC> <your signer flags>$/, "");
    const m = cmd.match(
      /^cast send (0x[0-9a-fA-F]{40}) "pauseUnderstakedOperator\(address\)" (0x[0-9a-fA-F]{40})$/
    );
    cell(
      `the alert's command is exactly cast send <SP> "pauseUnderstakedOperator(address)" <op>`,
      m && m[1] === ethers.getAddress(SP),
      cmd
    );
    execFileSync(
      bin("cast"),
      [
        "send",
        m[1],
        "pauseUnderstakedOperator(address)",
        m[2],
        "--rpc-url",
        URL,
        "--private-key",
        HUMAN_PK,
      ],
      { stdio: "ignore" }
    );
    cell(`running the alert's command pauses ${m[2]}`, await isPaused(m[2]), m[2]);
  }
  await p.send("anvil_mine", ["0x80"]);
  const before = structuredClone(st.alerts);
  for (const a of act) st.alerts[a.key] = 1;
  const r2 = await runRound(st, { chain, cfg: CFG });
  cell(
    "after the pauses: both operators paused, the round clear, no new alert",
    r2.report.clear &&
      r2.report.operators.every(o => o.status === "paused") &&
      r2.alerts.length === 0,
    r2.report.operators
  );
  const res = resolvedKeys(st, r2.alerts, r2.report);
  cell(
    "the two PAUSE NEEDED alerts resolve on the next clear round",
    act.every(a => res.includes(a.key)),
    res
  );
  st.alerts = before;
});
await revert(s1);

// ---- D3: identity: a different implementation pin fails closed, no PAUSE NEEDED
const s2 = await snapshot();
await section(async () => {
  await raiseMinStake();
  await p.send("anvil_mine", ["0x80"]);
  const bad = { ...CFG, implementation: ethers.getAddress(`0x${"1".repeat(40)}`) };
  const r = await runRound(emptyState(bad), { chain, cfg: bad });
  cell(
    "a wrong implementation pin: identity unknown, no PAUSE NEEDED, not clear",
    !r.report.identity.ok &&
      !r.alerts.some(a => a.key.startsWith("actionable:")) &&
      r.alerts.some(a => a.key === "identity") &&
      !r.report.clear,
    r.alerts.map(a => a.key)
  );
  const bad2 = { ...CFG, registryCodeHash: ethers.keccak256("0x00") };
  const r2 = await runRound(emptyState(bad2), { chain, cfg: bad2 });
  cell("a wrong Registry code hash: identity unknown", !r2.report.identity.ok, r2.report.identity);
});
await revert(s2);

// ---- D5: detector.mjs itself, as launchd runs it: under the plist's permission flags
await section(async () => {
  // under the real home, as on the Mini (repo and ~/.aoa-pause-detector share /Users/<u>): Node
  // 24's permission model mishandles a rename when the allowed paths have no common root
  const home = realpathSync(mkdtempSync(join(homedir(), ".pd-e2e-")));
  process.on("exit", () => rmSync(home, { recursive: true, force: true }));
  const d = join(home, ".aoa-pause-detector");
  for (const x of [d, join(d, "state"), join(d, "secrets")]) mkdirSync(x, { mode: 0o700 });
  for (const n of ["aoa-dvt-detector-rpc-primary", "aoa-dvt-detector-rpc-fallback"])
    writeFileSync(join(d, "secrets", n), URL, { mode: 0o600 });
  const cfgPath = join(d, "config.json");
  writeFileSync(
    cfgPath,
    JSON.stringify({
      ...CFG,
      stateDir: join(d, "state"),
      secretsDir: join(d, "secrets"),
      telegram: null,
      realertMinutes: 360,
      lockPort: 40000 + Math.floor(Math.random() * 20000),
      rpc: { primary: "anvil-a", fallback: "anvil-b" },
    })
  );
  const repo = join(HERE_E2E, "../..");
  const flag =
    Number(process.versions.node.split(".")[0]) >= 22
      ? "--permission"
      : "--experimental-permission";
  const r = spawnSync(
    process.execPath,
    [
      flag,
      `--allow-fs-read=${repo}`,
      `--allow-fs-read=${d}`,
      `--allow-fs-write=${join(d, "state")}`,
      join(HERE_E2E, "detector.mjs"),
      "--config",
      cfgPath,
    ],
    { encoding: "utf8", env: { PATH: process.env.PATH, HOME: home } }
  );
  if (!existsSync(join(d, "state", "status.json")))
    throw new Error(`no status.json; exit ${r.status}: ${r.stderr.slice(0, 400)}`);
  const status = JSON.parse(readFileSync(join(d, "state", "status.json"), "utf8"));
  cell(
    "the detector process runs under the permission model and ends a clear round",
    r.status === 0 && status.clear === true,
    { code: r.status, stderr: r.stderr.slice(0, 300), clear: status.clear }
  );
  cell(
    "its status names both operators read ok at a canonical B",
    status.report?.canonical &&
      status.report.operators.length === 2 &&
      status.report.operators.every(o => o.status === "ok"),
    status.report?.operators
  );
  const st = JSON.parse(readFileSync(join(d, "state", "state.json"), "utf8"));
  cell(
    "its state persisted the inventory with a mode-600 file",
    Object.keys(st.operators).length === 2 &&
      (statSync(join(d, "state", "state.json")).mode & 0o777) === 0o600,
    st.operators
  );
});

// ---- D4: the RPC client refuses a broadcast even against a live node
await section(async () => {
  let refused = false;
  try {
    await chain.rpc("eth_sendRawTransaction", ["0x00"]);
  } catch (e) {
    refused = /refused/.test(e.message);
  }
  cell("the detector's RPC client refuses eth_sendRawTransaction", refused, refused);
});

const nf = results.filter(r => !r.ok).length;
for (const r of results)
  console.log(`${r.ok ? "ok  " : "FAIL"} ${r.name}${r.ok ? "" : `\n     got ${r.got}`}`);
console.log(`\n${results.length - nf}/${results.length} cells (SP ${PIN.spCommit}, DeployAnvil)`);
process.exit(nf ? 1 : 0);
