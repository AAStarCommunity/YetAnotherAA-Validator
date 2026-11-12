#!/usr/bin/env node
// The pause path end to end against SuperPaymaster's REAL compiled contracts (DSR 4019916a
// condition 3: no mocks on the pause path; the SignersCommitted lesson). SP's own
// contracts/script/v3/DeployAnvil.s.sol deploys the full stack (Registry, GTokenStaking, SP proxy,
// xPNTs v2, ...) from an SP checkout AT sp-pin.json's commit, built with `forge build`; this
// script refuses any other commit. The understaked state is produced on chain the real way: the
// Registry owner raises ROLE_PAYMASTER_SUPER's minStake with configureRole.
//
//   node deploy/pause-job/e2e-anvil.mjs --sp /path/to/SuperPaymaster   (checkout at the pin, built)
//
// anvil test-only conveniences (anvil_setBalance, evm_snapshot/revert, impersonation) set up and
// isolate cells; none of them is on the pause path. Exit 0 only if every cell passes.
import { execFileSync, spawn } from "node:child_process";
import {
  mkdtempSync,
  readFileSync,
  writeFileSync,
  mkdirSync,
  chmodSync,
  existsSync,
} from "node:fs";
import { createServer } from "node:net";
import { tmpdir, homedir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { ethers } from "ethers";
import { PIN, emptyState, runRound, stateProblems, spIface, regIface } from "./lib/core.mjs";
import { rpcChain, writeDurable } from "./pause-job.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const opt = k => {
  const i = args.indexOf(`--${k}`);
  return i >= 0 ? args[i + 1] : undefined;
};
const die = (c, m) => {
  console.error(`e2e-anvil: ${m}`);
  process.exit(c);
};
const spDir = opt("sp");
if (!spDir) die(2, "usage: e2e-anvil.mjs --sp <SuperPaymaster checkout at sp-pin.json's commit>");
const head = execFileSync("git", ["-C", spDir, "rev-parse", "HEAD"], { encoding: "utf8" }).trim();
if (head !== PIN.spCommit)
  die(2, `the SP checkout is at ${head}, sp-pin.json pins ${PIN.spCommit}`);
// every tracked build input at the pin, the deploy script and the submodules included (Codex R1 P2-9)
const dirty = execFileSync("git", ["-C", spDir, "status", "--porcelain", "--untracked-files=no"], {
  encoding: "utf8",
});
if (dirty.trim()) die(2, "the SP checkout has local changes to tracked files");
// untracked files may only be build outputs (Codex R2 P2-9): anything else could be an input
const untracked = execFileSync("git", ["-C", spDir, "ls-files", "--others", "--exclude-standard"], {
  encoding: "utf8",
})
  .split("\n")
  .filter(f => f && !/^(out|cache|broadcast|node_modules)\//.test(f));
if (untracked.length)
  die(2, `the SP checkout has untracked files: ${untracked.slice(0, 3).join(", ")}`);
const subs = execFileSync("git", ["-C", spDir, "submodule", "status", "--recursive"], {
  encoding: "utf8",
});
for (const line of subs
  .split("\n")
  .filter(l => /^(singleton-paymaster|contracts\/lib)/.test(l.slice(1).trim().split(" ")[1] ?? "")))
  if (!line.startsWith(" "))
    die(2, `an SP build submodule is not at its pinned commit: ${line.trim().split(" ")[1]}`);

const bin = n =>
  existsSync(join(homedir(), ".foundry/bin", n)) ? join(homedir(), ".foundry/bin", n) : n;
const PORT = 20000 + Math.floor(Math.random() * 20000);
const URL = `http://127.0.0.1:${PORT}`;
// anvil's well-known public test accounts (not secrets): #0 deploys SP and owns it
const DEPLOYER_PK = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

const anvil = spawn(bin("anvil"), ["--port", String(PORT), "--silent"], { stdio: "ignore" });
const stop = () => {
  try {
    anvil.kill("SIGKILL");
  } catch {
    /* gone */
  }
};
process.on("exit", stop);
const p = new ethers.JsonRpcProvider(URL, undefined, { staticNetwork: true, cacheTimeout: -1 });
for (let i = 0; ; i++) {
  try {
    await p.send("eth_chainId", []);
    break;
  } catch {
    if (i > 100) die(3, "anvil did not start");
    await new Promise(r => setTimeout(r, 100));
  }
}

// ---- deploy SP with SP's own anvil script
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
if (before) writeFileSync(cfgFile, before); // leave the SP checkout as it was
// anvil's "finalized" is latest - 64: mine past it so the deployed operators are final, as on a
// real chain some minutes after deploy (the inventory reads finalized blocks only)
await p.send("anvil_mine", ["0x80"]);
const SP = deployed.superPaymaster;
const REG = deployed.registry;
const startBlock = 1;

const results = [];
const cell = (name, ok, got) =>
  results.push({
    name,
    ok: !!ok,
    got: JSON.stringify(got ?? null, (k, v) => (typeof v === "bigint" ? String(v) : v)),
  });
// a section that throws records ONE failing cell and the run goes on: a mutant must turn a named
// assertion red, not crash the script
let sectionNo = 0;
const section = async fn => {
  const k = ++sectionNo;
  try {
    await fn();
  } catch (e) {
    cell(`section ${k} ran to the end`, false, String(e?.message ?? e).slice(0, 300));
  }
};

const deployer = new ethers.Wallet(DEPLOYER_PK, p);
const send = async (to, iface, fn, a, from = deployer) => {
  const tx = await from.sendTransaction({ to, data: iface.encodeFunctionData(fn, a) });
  const r = await tx.wait();
  if (r.status !== 1) throw new Error(`${fn} reverted`);
};
const read = async (to, iface, fn, a = []) =>
  iface.decodeFunctionResult(fn, await p.call({ to, data: iface.encodeFunctionData(fn, a) }));
const ROLE_SUPER = PIN.roles.ROLE_PAYMASTER_SUPER;
const adminIface = new ethers.Interface([
  "function setGuardian(address)",
  "function setOperatorPaused(address operator, bool paused)",
]);
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
  await send(REG, cfgIface, "configureRole", [ROLE_SUPER, next]);
};
const snapshot = () => p.send("evm_snapshot", []);
const revert = id => p.send("evm_revert", [id]);
const isPaused = async op => (await read(SP, spIface, "operators", [op])).isPaused;

const chain = rpcChain(URL);
const CFG = {
  logChunk: 50,
  gasLimitMax: "300000",
  maxFeePerGasCap: "200000000000",
  maxPriorityFeePerGas: "1000000000",
  receiptWaitMs: 10_000,
  pollMs: 200,
};
const work = mkdtempSync(join(tmpdir(), "pause-e2e-"));
let n = 0;
const fresh = async (cap = String(10n ** 18n)) => {
  const w = ethers.Wallet.createRandom();
  await p.send("anvil_setBalance", [
    w.address,
    ethers.toQuantity(BigInt(cap) < 10n ** 18n ? BigInt(cap) : 10n ** 18n),
  ]);
  const st = emptyState({
    chainId: 31337,
    signer: w.address,
    spProxy: SP,
    registry: REG,
    startBlock,
    registryStartBlock: startBlock,
    cap,
  });
  const path = join(work, `state-${n++}.json`);
  const signer = { address: w.address, sign: tx => w.signTransaction(tx) };
  const persist = s => writeDurable(path, s);
  return {
    w,
    st,
    path,
    signer,
    persist,
    round: (o = {}) =>
      runRound(st, {
        chain: o.chain ?? chain,
        signer,
        persist: o.persist ?? persist,
        cfg: { ...CFG, ...(o.cfg ?? {}) },
      }),
  };
};
const ops = st => Object.keys(st.operators).sort();

const finalize = () => p.send("anvil_mine", ["0x80"]);
const copy = o => structuredClone(o);
const lcHex = h => h.toLowerCase();
// the cost of the final transactions, summed independently from the chain's receipts
const receiptSum = async st => {
  let sum = 0n;
  for (const t of st.ledger.txs.filter(x => x.status === "final")) {
    const r = await p.getTransactionReceipt(t.includedHash);
    sum += r.gasUsed * r.gasPrice;
  }
  return sum;
};

// ---- C1: nothing understaked: inventory from the SP proxy, nothing sent
await section(async () => {
  const j = await fresh();
  const r = await j.round();
  cell(
    "inventory: both DeployAnvil operators found from the SP proxy's OperatorConfigured logs",
    ops(j.st).length === 2 && ops(j.st).every(o => ethers.isAddress(o)),
    ops(j.st)
  );
  cell(
    "meets minimum stake: decision 'meets', nothing sent, no alert",
    r.report.operators.every(o => o.decision === "meets") &&
      j.st.ledger.txs.length === 0 &&
      r.alerts.length === 0,
    r
  );
  cell(
    "identity: a fresh signer passes the same-block identity check (B pinned by hash)",
    r.report.identity.ok && /^0x[0-9a-f]{64}$/.test(r.report.block.hash),
    r.report
  );
});

// ---- C2: understaked -> both paused in one round, in turn; reservation held until FINAL
await raiseMinStake();
const understaked = await snapshot();
await section(async () => {
  const j = await fresh();
  const r1 = await j.round();
  const [a, b] = ops(j.st);
  cell(
    "understaked: round 1 pauses both in turn (nonce 0 included before nonce 1 is signed)",
    j.st.ledger.txs.length === 2 &&
      r1.report.sent.join() === [a, b].join() &&
      j.st.ledger.txs.every((t, i) => t.nonce === i && t.status === "included"),
    { r: r1.report, a: r1.alerts }
  );
  cell("both operators paused on chain after round 1", (await isPaused(a)) && (await isPaused(b)));
  cell(
    "included, not final: both reservations still held, nothing spent",
    j.st.ledger.spent === "0" &&
      BigInt(j.st.ledger.reserved) === j.st.ledger.txs.reduce((x, t) => x + BigInt(t.reserve), 0n),
    copy(j.st.ledger)
  );
  const r2 = await j.round();
  cell(
    "round 2 before finality: still included, nothing sent, still reserved",
    r2.report.sent.length === 0 &&
      j.st.ledger.txs.every(t => t.status === "included") &&
      j.st.ledger.spent === "0",
    copy(j.st.ledger)
  );
  await finalize();
  const r3 = await j.round();
  cell(
    "after finality: final, spent = sum of receipt costs (summed here from the receipts), nothing reserved",
    j.st.ledger.txs.every(t => t.status === "final" && t.ok) &&
      BigInt(j.st.ledger.spent) === (await receiptSum(j.st)) &&
      j.st.ledger.reserved === "0" &&
      stateProblems(j.st).length === 0 &&
      r3.report.sent.length === 0,
    copy(j.st.ledger)
  );
  cell(
    "an already paused operator is understaked + paused, not a candidate, counter 0",
    r3.report.operators.every(
      o => o.decision === "understaked" && o.paused === true && o.understakedRounds === 0
    ),
    r3.report.operators
  );
  cell(
    "no pause-timeout alert when every pause landed within a round",
    ![...r1.alerts, ...r2.alerts, ...r3.alerts].some(x => x.key.startsWith("timeout")),
    [r1.alerts, r2.alerts, r3.alerts]
  );
});

// ---- C2b: an operator-specific failure does not starve the next operator (Codex R2 P2-6)
await revert(understaked);
const u0 = await snapshot();
await section(async () => {
  const j = await fresh();
  const [a, b] = [
    "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
    "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
  ].sort();
  const aData = spIface.encodeFunctionData("pauseUnderstakedOperator", [a]).toLowerCase();
  const failFirst = {
    ...chain,
    estimateGas: tx =>
      tx.data.toLowerCase() === aData ? Promise.reject(new Error("x")) : chain.estimateGas(tx),
  };
  const r = await j.round({ chain: failFirst });
  cell(
    "operator-specific estimate failure: the next operator is still paused in the same round",
    r.report.sent.join() === b &&
      (await isPaused(b)) &&
      !(await isPaused(a)) &&
      r.alerts.some(x => x.key === `estimate:${a}`),
    { sent: r.report.sent, a: r.alerts }
  );
});
await revert(u0);
const u0b = await snapshot();
// ---- C2c: incoherent receipts (nonce 1 seen, nonce 0 not) never persist (Codex R2 P1-4)
await section(async () => {
  const j = await fresh();
  await j.round();
  const before = copy(j.st.ledger);
  const h0 = j.st.ledger.txs[0].hashes;
  const half = {
    ...chain,
    receipt: h => (h0.includes(h) ? Promise.resolve(null) : chain.receipt(h)),
  };
  const r = await j.round({ chain: half });
  cell(
    "incoherent receipts: the reconciled copy is discarded, the journal unchanged, alert",
    JSON.stringify(j.st.ledger) === JSON.stringify(before) &&
      r.alerts.some(x => x.key === "reconcile") &&
      stateProblems(j.st).length === 0,
    { a: r.alerts, now: j.st.ledger.txs.map(t => t.status) }
  );
  await finalize();
  await j.round();
  cell(
    "incoherent receipts: the next coherent round proceeds to final",
    j.st.ledger.txs.every(t => t.status === "final") && stateProblems(j.st).length === 0,
    j.st.ledger.txs.map(t => t.status)
  );
});
await revert(u0b);
const u0c = await snapshot();
// ---- C2d: the role inventory starts at the Registry's own deploy block (Codex R2 P1-3): a role
// configured BEFORE SP's start block is found from registryStartBlock, and missed from startBlock
await section(async () => {
  const c = (await read(REG, regIface, "getRoleConfig", [ROLE_SUPER]))[0].toObject();
  const NEW = ethers.id("CONFIGURED_BEFORE_SP_START");
  await send(REG, cfgIface, "configureRole", [NEW, { ...c, owner: deployer.address }]);
  const late = Number(await p.getBlockNumber()) + 1;
  await finalize();
  const mk = reg => {
    const w = ethers.Wallet.createRandom();
    return {
      w,
      st: emptyState({
        chainId: 31337,
        signer: w.address,
        spProxy: SP,
        registry: REG,
        startBlock: late,
        registryStartBlock: reg,
        cap: String(10n ** 18n),
      }),
    };
  };
  const a = mk(1);
  const b = mk(late);
  const ids = [];
  for (const x of [a, b]) {
    await p.send("anvil_setBalance", [x.w.address, ethers.toQuantity(10n ** 18n)]);
    const r = await runRound(x.st, {
      chain,
      signer: { address: x.w.address, sign: t => x.w.signTransaction(t) },
      persist: () => {},
      cfg: CFG,
    });
    ids.push(r.report.identity);
  }
  cell(
    "roles: scanned from the Registry's deploy block, a role configured before SP's start is found and fails closed",
    Object.keys(a.st.roles).includes(lcHex(NEW)) &&
      !ids[0].ok &&
      ids[0].problems.some(x => x.includes("not in the pinned")),
    { roles: Object.keys(a.st.roles), id: ids[0] }
  );
  cell(
    "roles: (control) scanned only from SP's start block, the same role is not seen",
    !Object.keys(b.st.roles).includes(lcHex(NEW)) && ids[1].ok,
    { roles: Object.keys(b.st.roles), id: ids[1] }
  );
});
await revert(u0c);

// ---- C3: a reorg removes an included pause: back to sent, resent, reservation kept throughout
await revert(understaked);
const u1 = await snapshot();
await section(async () => {
  const j = await fresh();
  const pre = await snapshot();
  const r1 = await j.round({ cfg: { receiptWaitMs: 2000 } });
  const included = copy(j.st.ledger.txs);
  await revert(pre); // the blocks holding both pauses are gone
  let r2 = { alerts: [] };
  let threw = null;
  try {
    r2 = await j.round();
  } catch (e) {
    threw = e.message;
  }
  cell(
    "reorg: the round after a reorg runs (the vanished inclusions are detected, not a nonce mismatch)",
    threw === null,
    threw
  );
  const t0 = j.st.ledger.txs[0];
  cell(
    "reorg: an included pause whose receipt vanished goes back to pending and is resent (same hash)",
    included[0].status === "included" &&
      r2.alerts.some(a => a.key.startsWith("reorg:")) &&
      t0.hashes[0] === included[0].hashes[0],
    { included: included.map(t => t.status), now: j.st.ledger.txs.map(t => t.status), a: r2.alerts }
  );
  cell(
    "reorg: the reservation was never released",
    BigInt(j.st.ledger.reserved) === j.st.ledger.txs.reduce((x, t) => x + BigInt(t.reserve), 0n) &&
      j.st.ledger.spent === "0" &&
      stateProblems(j.st).length === 0,
    copy(j.st.ledger)
  );
  await finalize();
  await j.round();
  cell(
    "reorg: after re-inclusion and finality both are final and paused, counted once",
    j.st.ledger.txs.every(t => t.status === "final") &&
      (await isPaused(ops(j.st)[0])) &&
      (await isPaused(ops(j.st)[1])) &&
      BigInt(j.st.ledger.spent) === (await receiptSum(j.st)) &&
      stateProblems(j.st).length === 0,
    copy(j.st.ledger)
  );
  void r1;
});

// ---- C4: identity failures: nothing broadcast, not even a journalled transaction
await revert(u1);
const u2 = await snapshot();
await section(async () => {
  const j = await fresh();
  await send(SP, adminIface, "setGuardian", [j.w.address]);
  const r = await j.round();
  cell(
    "identity: the signer is SP.guardian -> check fails, nothing sent, alert",
    !r.report.identity.ok &&
      r.report.identity.problems.some(x => x.includes("SuperPaymaster.guardian")) &&
      j.st.ledger.txs.length === 0 &&
      r.alerts.some(a => a.key === "identity"),
    r.report.identity
  );
});
await revert(u2);
const u2b = await snapshot();
await section(async () => {
  // journal a transaction, crash before broadcast, then the signer becomes guardian: the restart
  // must NOT broadcast the journalled bytes (Codex R1 P1-4)
  const j = await fresh();
  let crashed = false;
  try {
    await j.round({
      persist: s => {
        writeDurable(j.path, s);
        if (!crashed && s.ledger.txs.some(t => t.status === "signed")) {
          crashed = true;
          throw new Error("crash");
        }
      },
    });
  } catch {
    /* the crash */
  }
  await send(SP, adminIface, "setGuardian", [j.w.address]);
  const st = JSON.parse(readFileSync(j.path, "utf8"));
  const r = await runRound(st, { chain, signer: j.signer, persist: j.persist, cfg: CFG });
  const nonce = Number(await p.getTransactionCount(j.w.address, "latest"));
  const pend = Number(await p.getTransactionCount(j.w.address, "pending"));
  cell(
    "recovery is gated: a journalled pause is not broadcast while the identity check fails",
    crashed &&
      !r.report.identity.ok &&
      nonce === 0 &&
      pend === 0 &&
      st.ledger.txs[0].status === "signed",
    { nonce, pend, status: st.ledger.txs[0]?.status }
  );
});
await revert(u2b);
const u3 = await snapshot();
await section(async () => {
  const j = await fresh();
  const c = (await read(REG, regIface, "getRoleConfig", [ROLE_SUPER]))[0].toObject();
  await send(REG, cfgIface, "configureRole", [
    ethers.id("NOT_IN_THE_PIN"),
    { ...c, owner: deployer.address },
  ]);
  const r = await j.round();
  cell(
    "identity: a role configured in the not-yet-finalized tail, outside the pinned set, fails closed",
    !r.report.identity.ok &&
      r.report.identity.problems.some(x => x.includes("not in the pinned")) &&
      j.st.ledger.txs.length === 0,
    r.report.identity
  );
  await finalize();
  const r2 = await j.round();
  cell(
    "identity: the same role once finalized is in the inventory and still fails closed",
    Object.keys(j.st.roles).includes(ethers.id("NOT_IN_THE_PIN")) &&
      !r2.report.identity.ok &&
      j.st.ledger.txs.length === 0,
    { roles: Object.keys(j.st.roles), id: r2.report.identity }
  );
});
await revert(u3);
const u4 = await snapshot();
await section(async () => {
  const j = await fresh();
  const mint = new ethers.Interface([
    "function safeMintForRole(bytes32 roleId, address user, bytes data) returns (uint256)",
  ]);
  const data = ethers.AbiCoder.defaultAbiCoder().encode(
    ["tuple(string,string,uint256)"],
    [["PauseE2E", "pause-e2e.eth", 30n * 10n ** 18n]]
  );
  await send(REG, mint, "safeMintForRole", [PIN.roles.ROLE_COMMUNITY, j.w.address, data]);
  const has = (await read(REG, regIface, "hasRole", [PIN.roles.ROLE_COMMUNITY, j.w.address]))[0];
  const r = await j.round();
  cell(
    "identity: the signer holds ROLE_COMMUNITY -> fails closed, nothing sent",
    has &&
      !r.report.identity.ok &&
      r.report.identity.problems.some(x => x.includes("holds role")) &&
      j.st.ledger.txs.length === 0,
    { has, id: r.report.identity }
  );
});
await section(async () => {
  const j = await fresh();
  const src = new ethers.Interface(["function setReputationSource(address source, bool active)"]);
  await send(REG, src, "setReputationSource", [j.w.address, true]);
  const r = await j.round();
  cell(
    "identity: the signer is a reputation source -> fails closed, nothing sent",
    !r.report.identity.ok &&
      r.report.identity.problems.some(x => x.includes("reputation source")) &&
      j.st.ledger.txs.length === 0,
    r.report.identity
  );
});
await section(async () => {
  // B leaves the canonical chain while the round reads (provider-level injection: the first
  // by-number lookup, the re-check of B, returns another hash): nothing of the round is acted on
  const j = await fresh();
  let n = 0;
  const shifty = {
    ...chain,
    blockByNumber: async x => {
      const b = await chain.blockByNumber(x);
      if (typeof x === "number" && b && ++n === 1) return { ...b, hash: `0x${"ee".repeat(32)}` };
      return b;
    },
  };
  const r = await j.round({ chain: shifty });
  cell(
    "reorg under B during the round: identity voided, nothing sent, alert",
    !r.report.identity.ok &&
      r.report.identity.problems.some(x => x.includes("left the canonical chain")) &&
      j.st.ledger.txs.length === 0,
    r.report.identity
  );
});
await revert(u4);
const u5 = await snapshot();

// ---- C5: the cap: refuse + alert; 2 rounds unpaused -> pause timeout
await section(async () => {
  const j = await fresh("1000");
  const r1 = await j.round();
  cell(
    "cap: remainder below the reservation -> not sent, 'remaining cap insufficient' alert",
    j.st.ledger.txs.length === 0 &&
      r1.alerts.some(a => a.key === "cap" && a.text.startsWith("remaining cap insufficient")),
    r1.alerts
  );
  const r2 = await j.round();
  cell(
    "pause timeout: understaked and unpaused for 2 rounds -> 'pause timeout' alert",
    r2.alerts.some(a => a.key.startsWith("timeout:") && a.text.startsWith("pause timeout")) &&
      !r1.alerts.some(a => a.key.startsWith("timeout:")),
    [r1.alerts, r2.alerts]
  );
});
await revert(u5);
const u6 = await snapshot();

// ---- C6: crash between journalling and broadcast: the same bytes go out next round
await section(async () => {
  const j = await fresh();
  let crashed = false;
  const crashy = s => {
    writeDurable(j.path, s);
    if (!crashed && s.ledger.txs.some(t => t.status === "signed")) {
      crashed = true;
      throw new Error("simulated crash after the durable write, before broadcast");
    }
  };
  let threw = false;
  try {
    await j.round({ persist: crashy });
  } catch {
    threw = true;
  }
  const saved = JSON.parse(readFileSync(j.path, "utf8"));
  const savedHash = saved.ledger.txs[0]?.hash;
  const nonceAfterCrash = Number(await p.getTransactionCount(j.w.address, "pending"));
  cell(
    "crash: the signed transaction is on disk and was NOT broadcast",
    threw &&
      saved.ledger.txs.length === 1 &&
      saved.ledger.txs[0].status === "signed" &&
      nonceAfterCrash === 0,
    { l: saved.ledger, nonceAfterCrash }
  );
  const st2 = structuredClone(saved);
  await runRound(st2, { chain, signer: j.signer, persist: j.persist, cfg: CFG });
  const minedTx = await p.getTransaction(savedHash);
  cell(
    "restart: the journalled bytes themselves were broadcast and included (hash from disk found on chain)",
    minedTx?.blockNumber != null && st2.ledger.txs[0].includedHash === savedHash,
    { savedHash, st: st2.ledger.txs.map(t => [t.status, t.includedHash]) }
  );
  await finalize();
  await runRound(st2, { chain, signer: j.signer, persist: j.persist, cfg: CFG });
  cell(
    "restart: final once, ledger consistent",
    st2.ledger.txs[0].status === "final" && stateProblems(st2).length === 0,
    copy(st2.ledger)
  );
});
await revert(u6);
const u7 = await snapshot();

// ---- C7: a pause that never lands is replaced at the same nonce with a HIGHER fee
await section(async () => {
  const j = await fresh();
  await p.send("evm_setAutomine", [false]);
  const quick = { cfg: { receiptWaitMs: 300, pollMs: 100, bumpAfterRounds: 2 } };
  let before;
  try {
    const r1 = await j.round(quick);
    before = copy(j.st.ledger.txs[0]);
    await j.round(quick);
    await j.round(quick);
    const kept = j.st.ledger.txs[0].hashes.length === 1;
    await j.round(quick);
    const t = j.st.ledger.txs[0];
    cell(
      "stuck: replaced at the same nonce with a strictly higher maxFee and tip; both hashes kept",
      r1.report.sent.length === 1 &&
        kept &&
        t.hashes.length === 2 &&
        t.hashes[0] === before.hash &&
        t.nonce === 0 &&
        BigInt(t.maxFeePerGas) > BigInt(before.maxFeePerGas) &&
        BigInt(t.maxPriorityFeePerGas) > BigInt(before.maxPriorityFeePerGas),
      { before, t }
    );
    cell(
      "stuck: the reservation never shrinks and is held against the cap",
      BigInt(t.reserve) >= BigInt(before.reserve) &&
        BigInt(j.st.ledger.reserved) === BigInt(t.reserve) &&
        stateProblems(j.st).length === 0,
      copy(j.st.ledger)
    );
  } finally {
    await p.send("evm_setAutomine", [true]);
  }
  await p.send("evm_mine", []);
  await finalize();
  await j.round();
  const t = j.st.ledger.txs[0];
  cell(
    "stuck: once final, the landed hash is one of those signed; cost counted once",
    t.status === "final" &&
      t.hashes.includes(t.includedHash) &&
      BigInt(j.st.ledger.spent) === (await receiptSum(j.st)) &&
      stateProblems(j.st).length === 0,
    copy(j.st.ledger)
  );
});
await revert(u7);
const u8 = await snapshot();
await section(async () => {
  // replacement impossible (fee ceiling): the current bytes are still rebroadcast (Codex R1 P2-5)
  const j = await fresh();
  await p.send("evm_setAutomine", [false]);
  try {
    const quick = { cfg: { receiptWaitMs: 200, pollMs: 100, bumpAfterRounds: 0 } };
    await j.round(quick);
    const h = j.st.ledger.txs[0].hash;
    await p.send("anvil_dropTransaction", [h]); // the mempool lost it
    const r = await j.round({
      cfg: { ...quick.cfg, maxFeePerGasCap: j.st.ledger.txs[0].maxFeePerGas },
    });
    const inPool = await p.getTransaction(h);
    cell(
      "stuck, replacement above the ceiling: alerted, and the current bytes are rebroadcast",
      r.alerts.some(a => a.key.startsWith("stuck:")) &&
        inPool != null &&
        j.st.ledger.txs[0].hashes.length === 1,
      { a: r.alerts, inPool: !!inPool }
    );
  } finally {
    await p.send("evm_setAutomine", [true]);
  }
});
await revert(u8);
const u9 = await snapshot();

// ---- C7c: an overrun (a cost above its reservation, as an OP inclusion-time fee can produce) is
// RECORDED, not discarded, and stops every broadcast (Codex R3 P1). Round 1 pauses only the first
// operator (the second's estimate fails); its reservation is shrunk in the journal so the real
// receipt cost overruns it on this L1 test chain; round 2 finds the second operator still a
// candidate and must broadcast nothing.
await section(async () => {
  const j = await fresh();
  const [a, b] = [
    "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
    "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
  ].sort();
  const bData = spIface.encodeFunctionData("pauseUnderstakedOperator", [b]).toLowerCase();
  const noB = {
    ...chain,
    estimateGas: tx =>
      tx.data.toLowerCase() === bData ? Promise.reject(new Error("x")) : chain.estimateGas(tx),
  };
  await j.round({ chain: noB });
  const one = j.st.ledger.txs.length === 1 && j.st.ledger.txs[0].operator === a;
  j.st.ledger.txs[0].reserve = "1";
  j.st.ledger.reserved = "1";
  j.st.ledger.cap = "1"; // a valid ledger: spent 0 + reserved 1 = cap 1
  await finalize();
  const nonce = Number(await p.getTransactionCount(j.w.address, "latest"));
  const r = await j.round();
  cell(
    "overrun: the real cost is recorded (final, spent = receipts) even though it exceeds the cap",
    one &&
      j.st.ledger.txs[0].status === "final" &&
      BigInt(j.st.ledger.spent) === (await receiptSum(j.st)) &&
      BigInt(j.st.ledger.spent) > BigInt(j.st.ledger.cap) &&
      r.alerts.some(x => x.key.startsWith("overrun:")),
    { one, l: copy(j.st.ledger), a: r.alerts }
  );
  cell(
    "overrun: with spent > cap the remaining candidate is NOT paused and nothing is broadcast",
    r.report.sent.length === 0 &&
      !(await isPaused(b)) &&
      Number(await p.getTransactionCount(j.w.address, "pending")) === nonce &&
      r.alerts.some(x => x.key === "cap" && x.text.includes("exceeds the cap")),
    { sent: r.report.sent, a: r.alerts }
  );
});
await revert(u9);
const u9b = await snapshot();

// ---- C7d: the funding is the hard bound (DSR 65db9e38, Codex R7 P1): a balance above the budget
// left (cap - spent) is a top-up, and nothing is broadcast
await section(async () => {
  const j = await fresh();
  await p.send("anvil_setBalance", [j.w.address, ethers.toQuantity(10n ** 18n + 1n)]);
  const r = await j.round();
  cell(
    "top-up: a signer balance above cap - spent broadcasts nothing and alerts",
    r.report.sent.length === 0 &&
      j.st.ledger.txs.length === 0 &&
      r.alerts.some(x => x.key === "topup"),
    { sent: r.report.sent, a: r.alerts }
  );
});

await section(async () => {
  // a top-up that replaces an INCLUDED (not yet final) pause's cost is caught (Codex R8 P2)
  const j = await fresh();
  const [a, b] = [
    "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
    "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
  ].sort();
  const bData = spIface.encodeFunctionData("pauseUnderstakedOperator", [b]).toLowerCase();
  const noB = {
    ...chain,
    estimateGas: tx =>
      tx.data.toLowerCase() === bData ? Promise.reject(new Error("x")) : chain.estimateGas(tx),
  };
  await j.round({ chain: noB });
  const included =
    j.st.ledger.txs.length === 1 &&
    j.st.ledger.txs[0].status === "included" &&
    j.st.ledger.spent === "0";
  await p.send("anvil_setBalance", [j.w.address, ethers.toQuantity(10n ** 18n)]); // back to the cap
  const r = await j.round();
  cell(
    "top-up over an included, unfinalized cost: no broadcast, topup alert (b stays unpaused)",
    included &&
      r.report.sent.length === 0 &&
      !(await isPaused(b)) &&
      r.alerts.some(x => x.key === "topup"),
    { included, sent: r.report.sent, a: r.alerts }
  );
  void a;
});

await revert(u9b);
const u9c = await snapshot();

// ---- C8: another use of the key stops the round
await section(async () => {
  const j = await fresh();
  await (await j.w.connect(p).sendTransaction({ to: j.w.address, value: 0n })).wait();
  let msg = "";
  try {
    await j.round();
  } catch (e) {
    msg = e.message;
  }
  cell(
    "nonce history: a transaction the job did not journal stops the round",
    /does not match the journal/.test(msg) && j.st.ledger.txs.length === 0,
    msg
  );
});
await section(async () => {
  // a foreign use of the key AT a nonce the journal still holds as pending (clestons B3): our
  // journalled bytes never went out (crash after the durable write); the key is used elsewhere
  const j = await fresh();
  let crashed = false;
  try {
    await j.round({
      persist: s => {
        writeDurable(j.path, s);
        if (!crashed && s.ledger.txs.some(t => t.status === "signed")) {
          crashed = true;
          throw new Error("crash");
        }
      },
    });
  } catch {
    /* the crash */
  }
  const st = JSON.parse(readFileSync(j.path, "utf8"));
  await (await j.w.connect(p).sendTransaction({ to: j.w.address, value: 0n, nonce: 0 })).wait();
  let msg = "";
  try {
    await runRound(st, { chain, signer: j.signer, persist: () => {}, cfg: CFG });
  } catch (e) {
    msg = e.message;
  }
  cell(
    "nonce history: a pending journalled nonce consumed by a foreign transaction stops the round",
    crashed && /consumed by a transaction the job did not journal/.test(msg),
    msg
  );
});
await revert(u9c);
const u10 = await snapshot();

// ---- C9: a failed getLogs range is retried, never skipped
await section(async () => {
  const j = await fresh();
  let failOnce = true;
  const flaky = {
    ...chain,
    getLogs: f =>
      failOnce ? ((failOnce = false), Promise.reject(new Error("down"))) : chain.getLogs(f),
  };
  const r1 = await j.round({ chain: flaky });
  const c1 = j.st.cursor.operators;
  const ops1 = ops(j.st).length;
  cell(
    "getLogs failure: cursor stays, alert raised, no operator in the inventory yet",
    c1 === startBlock - 1 && ops1 === 0 && r1.alerts.some(a => a.key === "inventory:operators"),
    { c1, ops1, a: r1.alerts }
  );
  const r2 = await j.round();
  cell(
    "next round: the same range is read, both operators found, the cursor reaches finalized",
    ops(j.st).length === 2 && j.st.cursor.operators === r2.report.finalized,
    { cursor: j.st.cursor, f: r2.report.finalized }
  );
});
await revert(u10);

// ---- C10: the CLI end to end
await section(async () => {
  const home = join(work, "cli");
  mkdirSync(join(home, "secrets"), { recursive: true, mode: 0o700 });
  mkdirSync(join(home, "state"), { recursive: true, mode: 0o700 });
  chmodSync(join(home, "secrets"), 0o700);
  chmodSync(join(home, "state"), 0o700);
  const w = ethers.Wallet.createRandom();
  const pw = "e2e-only-password-not-a-secret";
  writeFileSync(join(home, "keystore"), await w.encrypt(pw), { mode: 0o600 });
  writeFileSync(join(home, "secrets/aoa-dvt-pause-keystore-pw"), pw, { mode: 0o600 });
  writeFileSync(join(home, "secrets/aoa-dvt-pause-rpc-primary"), "http://127.0.0.1:1", {
    mode: 0o600,
  }); // down: the round must use the fallback
  writeFileSync(join(home, "secrets/aoa-dvt-pause-rpc-fallback"), URL, { mode: 0o600 });
  await p.send("anvil_setBalance", [w.address, ethers.toQuantity(10n ** 17n)]);
  const cfg = {
    chainId: 31337,
    spProxy: SP,
    registry: REG,
    startBlock,
    registryStartBlock: startBlock,
    capWei: String(10n ** 17n),
    gasLimitMax: "300000",
    maxFeePerGasCap: "200000000000",
    maxPriorityFeePerGas: "1000000000",
    logChunk: 50,
    stateDir: join(home, "state"),
    secretsDir: join(home, "secrets"),
    keystore: join(home, "keystore"),
    telegram: null,
    realertMinutes: 60,
    lockPort: 30000 + Math.floor(Math.random() * 20000),
    rpc: { primary: "alchemy", fallback: "infura" },
  };
  writeFileSync(join(home, "config.json"), JSON.stringify(cfg));
  const cli = a => {
    try {
      return {
        code: 0,
        out: execFileSync(
          "node",
          [join(HERE, "pause-job.mjs"), "--config", join(home, "config.json"), ...a],
          { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }
        ),
      };
    } catch (e) {
      return { code: e.status, out: String(e.stderr) };
    }
  };
  await p.send("anvil_setBalance", [w.address, ethers.toQuantity(10n ** 17n + 1n)]);
  const overfunded = cli(["--init"]);
  cell(
    "CLI: --init refuses a signer funded above the cap (fund exactly the cap)",
    overfunded.code !== 0 && /more than the cap/.test(overfunded.out),
    overfunded
  );
  await p.send("anvil_setBalance", [w.address, ethers.toQuantity(10n ** 17n)]);
  const init = cli(["--init"]);
  const run = cli([]);
  const status = JSON.parse(readFileSync(join(home, "state/status.json"), "utf8"));
  cell(
    "CLI: --init on a nonce-0 key creates the state",
    init.code === 0 && /state created/.test(init.out),
    init
  );
  cell(
    "CLI: a round pauses both, writes status.json, exits 1 (alerts undelivered without Telegram)",
    status.report?.sent?.length === 2 && run.code === 1 && status.delivery.ok === false,
    { run, status: status.report }
  );
  cell(
    "CLI: the primary is down -> the whole round ran on the fallback, named in status, alerted",
    status.provider === "infura" && status.alerts.some(a => a.includes("primary RPC (alchemy)")),
    { provider: status.provider, alerts: status.alerts }
  );
  const again = cli(["--init"]);
  cell(
    "CLI: --init refuses when a state exists",
    again.code !== 0 && /already exists/.test(again.out),
    again
  );
  // the lock: a second process while the port is held exits 75 without touching the state
  const statusBefore = readFileSync(join(home, "state/status.json"), "utf8");
  const holder = createServer().listen({ host: "127.0.0.1", port: cfg.lockPort, exclusive: true });
  await new Promise(r => holder.once("listening", r));
  const locked = cli([]);
  holder.close();
  cell(
    "CLI: a second run while the lock is held exits 75",
    locked.code === 75 && /holds the lock/.test(locked.out),
    locked
  );
  const loser = JSON.parse(readFileSync(join(home, "state/lock-loser.json"), "utf8"));
  cell(
    "CLI: the lock loser leaves the owner's status.json untouched and notes itself apart (Codex R6 P2)",
    readFileSync(join(home, "state/status.json"), "utf8") === statusBefore &&
      /holds the lock/.test(loser.note ?? ""),
    loser
  );
  // a config failure that is not about reporting itself is reported (Codex R6 P2): status.json
  writeFileSync(join(home, "config.json"), JSON.stringify({ ...cfg, receiptWaitMs: 5 }));
  const badCfg = cli([]);
  writeFileSync(join(home, "config.json"), JSON.stringify(cfg));
  const cfgStatus = JSON.parse(readFileSync(join(home, "state/status.json"), "utf8"));
  cell(
    "CLI: an out-of-range config value exits 78 with a startup status (not stderr only)",
    badCfg.code === 78 && /receiptWaitMs/.test(cfgStatus.startup ?? ""),
    { badCfg, cfgStatus }
  );
  const good = readFileSync(join(home, "state/state.json"));
  writeFileSync(join(home, "state/state.json"), "{", { mode: 0o600 });
  const corrupt = cli([]);
  const corruptStatus = JSON.parse(readFileSync(join(home, "state/status.json"), "utf8"));
  writeFileSync(join(home, "state/state.json"), good, { mode: 0o600 });
  cell(
    "CLI: an unreadable state.json exits 1 with a startup status, not silently",
    corrupt.code === 1 && /startup/.test(corruptStatus.startup ?? ""),
    { corrupt, corruptStatus }
  );
  const leaked = [
    init.out,
    run.out,
    again.out,
    locked.out,
    readFileSync(join(home, "state/status.json"), "utf8"),
    readFileSync(join(home, "state/state.json"), "utf8"),
  ].some(t => t.includes(pw) || t.includes(`127.0.0.1:${PORT}`));
  cell(
    "CLI: neither the keystore password nor the RPC URL appears in output, status or state",
    !leaked
  );
});

stop();
let nf = 0;
for (const r of results) {
  console.log(
    `${r.ok ? "ok  " : "FAIL"} ${r.name}${r.ok ? "" : `\n     got ${r.got.slice(0, 1200)}`}`
  );
  if (!r.ok) nf++;
}
console.log(`\n${results.length - nf}/${results.length} cells (SP ${PIN.spCommit}, DeployAnvil)`);
process.exit(nf ? 1 : 0);
