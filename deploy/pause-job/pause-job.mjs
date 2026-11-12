#!/usr/bin/env node
// The DVT pause job (D2, DSR 4019916a): one round of lib/core.mjs per launchd start
// (io.aastar.dvt-pause-job, StartInterval 600). See README.md.
//
//   node deploy/pause-job/pause-job.mjs --config ~/.aoa-pause-job/config.json [--init]
//
// --init creates the state for a NEW signer (nonce 0, empty ledger) and refuses if a state exists.
// The RPC URL, the keystore password and the Telegram token are 0600 files in the secrets directory
// (lib/secrets.mjs); none is ever printed, logged or put in argv.
import {
  closeSync,
  constants,
  existsSync,
  fsyncSync,
  lstatSync,
  openSync,
  readFileSync,
  renameSync,
  unlinkSync,
  writeSync,
} from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { ethers } from "ethers";
import { emptyState, runRound, stateProblems } from "./lib/core.mjs";
import { readSecretFile, secretsDirProblems, okDir, SECRET_NAMES } from "./lib/secrets.mjs";
import { SafeError, safeText } from "./lib/safe-error.mjs";

/** The cumulative spend ceiling per chain (DSR 4019916a condition 5); config may only lower it. */
export const CAP_CEILING = {
  11155111: 10n ** 17n, // Sepolia: 0.1 ETH
  10: 2n * 10n ** 16n, // OP Mainnet: 0.02 ETH
  31337: 10n ** 18n, // local anvil (the end-to-end check only)
};

const die = (code, m) => {
  console.error(`pause-job: ${m}`);
  process.exit(code);
};
const args = process.argv.slice(2);
const opt = k => {
  const i = args.indexOf(`--${k}`);
  return i >= 0 ? args[i + 1] : undefined;
};
const tilde = p => p?.replace(/^~\//, `${homedir()}/`);

/** Problems with a config object, fixed wording. Pure. */
export function configProblems(c) {
  const p = [];
  const addr = k => {
    if (!ethers.isAddress(c?.[k] ?? "")) p.push(`${k} is not an address`);
  };
  if (!c || typeof c !== "object") return ["config is not an object"];
  if (!Number.isSafeInteger(c.chainId) || !(c.chainId in CAP_CEILING))
    p.push(`chainId must be one of ${Object.keys(CAP_CEILING).join(", ")}`);
  addr("spProxy");
  addr("registry");
  if (!Number.isSafeInteger(c.startBlock) || c.startBlock < 1)
    p.push("startBlock must be a positive block (SP's deploy block)");
  for (const k of ["capWei", "gasLimitMax", "maxFeePerGasCap", "maxPriorityFeePerGas"])
    if (!/^[1-9][0-9]*$/.test(String(c[k] ?? ""))) p.push(`${k} must be a positive integer string`);
  if (p.length === 0 && BigInt(c.capWei) > CAP_CEILING[c.chainId])
    p.push(`capWei is above the ceiling for chain ${c.chainId} (${CAP_CEILING[c.chainId]})`);
  if (!Number.isSafeInteger(c.logChunk) || c.logChunk < 1 || c.logChunk > 50000)
    p.push("logChunk must be 1..50000");
  for (const k of ["stateDir", "secretsDir", "keystore"])
    if (!okDir(tilde(c[k]))) p.push(`${k} must be an absolute plain path`);
  if (c.telegram !== null && !/^-?[0-9]+$/.test(String(c.telegram?.chatId ?? "")))
    p.push("telegram must be null or { chatId }");
  if (!Number.isSafeInteger(c.realertMinutes) || c.realertMinutes < 1)
    p.push("realertMinutes must be a positive integer");
  // provider NAMES only (DSR bd595f0f: alchemy primary, infura fallback); the URLs are secret files
  const nm = /^[a-z0-9-]{1,32}$/;
  if (!nm.test(c.rpc?.primary ?? "") || !nm.test(c.rpc?.fallback ?? ""))
    p.push("rpc must be { primary, fallback } provider names");
  else if (c.rpc.primary === c.rpc.fallback)
    p.push("rpc.primary and rpc.fallback must be different providers");
  return p;
}

/** Write `obj` to `path` durably: 0600 temp file, fsync, rename, fsync the directory. */
export function writeDurable(path, obj) {
  const tmp = `${path}.tmp`;
  const fd = openSync(
    tmp,
    constants.O_WRONLY | constants.O_CREAT | constants.O_TRUNC | constants.O_NOFOLLOW,
    0o600
  );
  try {
    writeSync(fd, `${JSON.stringify(obj, null, 2)}\n`);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  renameSync(tmp, path);
  const d = openSync(dirname(path), constants.O_RDONLY);
  try {
    fsyncSync(d);
  } finally {
    closeSync(d);
  }
}

/** A JSON-RPC chain over one URL. Every error leaving here is a SafeError category (no URL). */
export function rpcChain(url) {
  const p = new ethers.JsonRpcProvider(url, undefined, {
    staticNetwork: true,
    batchMaxCount: 1,
    cacheTimeout: -1,
  });
  const send = async (m, params) => {
    try {
      return await p.send(m, params);
    } catch (e) {
      // keep the revert data (a selector) for the probe; never the message
      const err = new SafeError(safeText(m, e));
      for (const d of [e?.data, e?.info?.error?.data, e?.error?.data])
        if (typeof d === "string" && /^0x[0-9a-fA-F]*$/.test(d)) err.data = d;
      throw err;
    }
  };
  return {
    chainId: () => send("eth_chainId", []),
    blockNumber: async tag => {
      const b = await send("eth_getBlockByNumber", [tag, false]);
      if (!b) throw new SafeError(`no ${tag} block`);
      return Number(b.number);
    },
    getLogs: f => send("eth_getLogs", [f]),
    call: (tx, tag) => send("eth_call", [tx, tag]),
    nonce: (a, tag) => send("eth_getTransactionCount", [a, tag]),
    estimateGas: tx => send("eth_estimateGas", [tx]),
    fees: async () => {
      const b = await send("eth_getBlockByNumber", ["latest", false]);
      if (!b?.baseFeePerGas) throw new SafeError("no baseFeePerGas (pre-London chain?)");
      return { baseFee: BigInt(b.baseFeePerGas) };
    },
    sendRaw: raw => send("eth_sendRawTransaction", [raw]),
    receipt: h => send("eth_getTransactionReceipt", [h]),
  };
}

/** Send alerts not sent within `realertMinutes` for their key; returns the delivery result. */
async function deliver(st, alerts, cfg, token, now) {
  const due = alerts.filter(a => !(now - (st.alerts[a.key] ?? 0) < cfg.realertMinutes * 60_000));
  if (!due.length) return { sent: 0, ok: true };
  if (!cfg.telegram) {
    for (const a of due) console.error(`ALERT ${a.text}`);
    return { sent: 0, ok: false, why: "no Telegram configured" };
  }
  const text =
    `DVT pause job (chain ${st.chainId}):\n${due.map(a => `- ${a.text}`).join("\n")}`.slice(
      0,
      4000
    );
  try {
    const r = await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ chat_id: cfg.telegram.chatId, text }),
      signal: AbortSignal.timeout(15_000),
    });
    if (!r.ok) return { sent: 0, ok: false, why: `telegram HTTP ${r.status}` };
  } catch (e) {
    return { sent: 0, ok: false, why: safeText("telegram", e) };
  }
  for (const a of due) st.alerts[a.key] = now;
  return { sent: due.length, ok: true };
}

async function main() {
  const cfgPath = tilde(opt("config"));
  if (!cfgPath) die(2, "usage: pause-job.mjs --config <file> [--init]");
  let cfg;
  try {
    cfg = JSON.parse(readFileSync(cfgPath, "utf8"));
  } catch {
    die(78, "config is missing or not JSON");
  }
  const cp = configProblems(cfg);
  if (cp.length) die(78, `config: ${cp.join("; ")}`);
  const stateDir = tilde(cfg.stateDir);
  const secrets = tilde(cfg.secretsDir);
  const dp = secretsDirProblems(
    existsSync(stateDir) ? lstatSync(stateDir) : null,
    process.getuid()
  );
  if (dp.length)
    die(78, `state directory: ${dp.join("; ").replaceAll("secrets directory", "state directory")}`);
  const secret = n => {
    try {
      return readSecretFile(n, secrets);
    } catch (e) {
      die(78, e?.name === "SafeError" ? e.message : `secret ${n}: unreadable`);
    }
  };
  let wallet;
  try {
    const ks = readFileSync(tilde(cfg.keystore), "utf8");
    wallet = await ethers.Wallet.fromEncryptedJson(ks, secret(SECRET_NAMES.keystorePassword));
  } catch (e) {
    die(78, e?.name === "SafeError" ? e.message : "the keystore cannot be opened");
  }
  const providers = [
    { name: cfg.rpc.primary, url: secret(SECRET_NAMES.rpcPrimary) },
    { name: cfg.rpc.fallback, url: secret(SECRET_NAMES.rpcFallback) },
  ];
  const token = cfg.telegram ? secret(SECRET_NAMES.telegram) : null;

  // one instance: an exclusive lock file holding our pid; a dead holder's lock is taken over
  const lock = join(stateDir, "lock");
  try {
    const fd = openSync(lock, "wx", 0o600);
    writeSync(fd, String(process.pid));
    closeSync(fd);
  } catch {
    let pid = NaN;
    try {
      pid = Number(readFileSync(lock, "utf8"));
      process.kill(pid, 0);
      die(75, `another run (pid ${pid}) holds the lock`);
    } catch (e) {
      if (e?.code !== "ESRCH") die(75, "the lock is held");
      unlinkSync(lock);
      const fd = openSync(lock, "wx", 0o600);
      writeSync(fd, String(process.pid));
      closeSync(fd);
    }
  }
  const release = () => {
    try {
      unlinkSync(lock);
    } catch {
      /* gone */
    }
  };

  const statePath = join(stateDir, "state.json");
  const statusPath = join(stateDir, "status.json");
  try {
    // ONE provider for the whole round (the same-block identity check never mixes two): the
    // primary unless it fails a probe; a provider failing mid-round fails the round, never switches
    let chain = null;
    let provider = null;
    for (const pr of providers) {
      const c = rpcChain(pr.url);
      try {
        if (Number(await c.chainId()) === cfg.chainId && (await c.blockNumber("latest")) > 0) {
          chain = c;
          provider = pr.name;
          break;
        }
      } catch {
        /* try the next */
      }
    }
    if (!chain) throw new SafeError("neither RPC provider answers for this chain");
    if (args.includes("--init")) {
      if (existsSync(statePath))
        throw new SafeError("a state already exists; refusing to start a new ledger over it");
      const n = Number(await chain.nonce(wallet.address, "latest"));
      if (n !== 0)
        throw new SafeError(
          `the signer's nonce is ${n}: only a NEW key (nonce 0) may be the pause signer`
        );
      const st = emptyState({ ...cfg, signer: wallet.address, cap: cfg.capWei });
      writeDurable(statePath, st);
      console.log(`state created for signer ${wallet.address} on chain ${cfg.chainId}`);
      return 0;
    }
    const st = JSON.parse(readFileSync(statePath, "utf8"));
    const sp = stateProblems(st);
    if (sp.length) throw new SafeError(`state: ${sp.join("; ")}`);
    // the config may lower the cap; it never raises a ledger's cap beyond the ceiling
    if (BigInt(cfg.capWei) !== BigInt(st.ledger.cap))
      throw new SafeError(
        "capWei differs from the ledger's cap: a new cap is a new funding (see README)"
      );
    for (const k of ["spProxy", "registry"])
      if (st[k] !== cfg[k].toLowerCase()) throw new SafeError(`${k} differs from the state's`);
    const signer = {
      address: wallet.address,
      sign: tx => wallet.signTransaction(tx),
    };
    const now = Date.now();
    let result;
    try {
      result = await runRound(st, { chain, signer, persist: s => writeDurable(statePath, s), cfg });
    } catch (e) {
      result = {
        alerts: [{ key: "round", text: `round stopped: ${safeText("round", e)}` }],
        report: null,
      };
    }
    if (provider !== cfg.rpc.primary)
      result.alerts.push({
        key: "fallback",
        text: `the primary RPC (${cfg.rpc.primary}) failed its probe; this round used ${provider}`,
      });
    const delivery = await deliver(st, result.alerts, cfg, token, now);
    writeDurable(statePath, st);
    writeDurable(statusPath, {
      schema: "aoa-pause-job-status/1",
      at: new Date(now).toISOString(),
      chainId: st.chainId,
      provider,
      signer: st.signer,
      ledger: {
        cap: st.ledger.cap,
        spent: st.ledger.spent,
        reserved: st.ledger.reserved,
        txs: st.ledger.txs.length,
      },
      report: result.report,
      alerts: result.alerts.map(a => a.text),
      delivery,
    });
    return result.alerts.length || !delivery.ok ? 1 : 0;
  } finally {
    release();
  }
}

if (import.meta.url === `file://${process.argv[1]}`)
  main().then(
    code => process.exit(code),
    e => die(1, safeText("pause-job", e))
  );
