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
  writeSync,
} from "node:fs";
import { createServer } from "node:net";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { ethers } from "ethers";
import { emptyState, runRound, stateProblems } from "./lib/core.mjs";
import { readSecretFile, dirProblems, okDir, SECRET_NAMES } from "./lib/secrets.mjs";
import { SafeError, safeText, isOurs } from "./lib/safe-error.mjs";

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
  if (
    !Number.isSafeInteger(c.registryStartBlock) ||
    c.registryStartBlock < 1 ||
    c.registryStartBlock > c.startBlock
  )
    p.push("registryStartBlock must be the Registry's deploy block, at or before startBlock");
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
  if (!Number.isSafeInteger(c.lockPort) || c.lockPort < 1024 || c.lockPort > 65535)
    p.push("lockPort must be a port in 1024..65535");
  for (const [k, lo, hi] of [
    ["receiptWaitMs", 1000, 300_000],
    ["pollMs", 100, 60_000],
    ["bumpAfterRounds", 1, 100],
  ])
    if (c[k] !== undefined && (!Number.isSafeInteger(c[k]) || c[k] < lo || c[k] > hi))
      p.push(`${k}, when set, must be an integer in ${lo}..${hi}`);
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
  const tmp = `${path}.${process.pid}.tmp`;
  const fd = openSync(
    tmp,
    constants.O_WRONLY | constants.O_CREAT | constants.O_TRUNC | constants.O_NOFOLLOW,
    0o600
  );
  try {
    // every byte, or throw (Codex R2 P1-2): a short write never reaches the rename
    const buf = Buffer.from(`${JSON.stringify(obj, null, 2)}\n`);
    let off = 0;
    while (off < buf.length) {
      const n = writeSync(fd, buf, off, buf.length - off);
      if (!(n > 0)) throw new SafeError("state write made no progress");
      off += n;
    }
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
  // every request bounded (clestons L3: the ethers default is 300 s)
  const req = new ethers.FetchRequest(url);
  req.timeout = 30_000;
  const p = new ethers.JsonRpcProvider(req, undefined, {
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
    blockByNumber: async n => {
      const b = await send("eth_getBlockByNumber", [
        typeof n === "number" ? ethers.toQuantity(n) : n,
        false,
      ]);
      return b ? { number: Number(b.number), hash: b.hash } : null;
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
  const dp = dirProblems(
    existsSync(stateDir) ? lstatSync(stateDir) : null,
    process.getuid(),
    "state directory"
  );
  if (dp.length) die(78, `state directory: ${dp.join("; ")}`);
  const statusPath = join(stateDir, "status.json");
  // `label` is fixed text for the operator; the reason comes from our own checks (SafeError)
  const secret = (n, label) => {
    try {
      return readSecretFile(n, secrets);
    } catch (e) {
      throw new SafeError(`${label}: ${isOurs(e) ? e.message : "unreadable"}`);
    }
  };
  // failures from here on are not silent (clestons B2): a minimal status.json, and once the bot
  // token is read, a "startup:" alert (re-alerted at most every realertMinutes) before exiting
  let token = null;
  const fatal = async (code, text) => {
    try {
      writeDurable(statusPath, {
        schema: "aoa-pause-job-status/1",
        at: new Date().toISOString(),
        chainId: cfg.chainId,
        startup: text,
      });
    } catch {
      /* status is best effort; the exit code and the log still carry it */
    }
    if (token) {
      const stampPath = join(stateDir, "startup-alerts.json");
      let stamps = {};
      try {
        stamps = JSON.parse(readFileSync(stampPath, "utf8"));
      } catch {
        stamps = {};
      }
      const box = { chainId: cfg.chainId, alerts: stamps };
      await deliver(
        box,
        [{ key: `startup:${text}`, text: `startup: ${text}` }],
        cfg,
        token,
        Date.now()
      );
      try {
        writeDurable(stampPath, box.alerts);
      } catch {
        /* best effort */
      }
    }
    die(code, text);
  };
  try {
    token = cfg.telegram ? secret(SECRET_NAMES.telegram, "the alert bot token file") : null;
  } catch (e) {
    await fatal(78, safeText("secrets", e));
  }
  let wallet;
  let providers;
  try {
    const ks = readFileSync(tilde(cfg.keystore), "utf8");
    wallet = await ethers.Wallet.fromEncryptedJson(
      ks,
      secret(SECRET_NAMES.keystorePassword, "the keystore unlock file")
    );
  } catch (e) {
    await fatal(78, isOurs(e) ? e.message : "the keystore cannot be opened");
  }
  try {
    providers = [
      { name: cfg.rpc.primary, url: secret(SECRET_NAMES.rpcPrimary, "the primary RPC file") },
      { name: cfg.rpc.fallback, url: secret(SECRET_NAMES.rpcFallback, "the fallback RPC file") },
    ];
  } catch (e) {
    await fatal(78, safeText("secrets", e));
  }

  // one instance: an OS-held lock (a listening socket on 127.0.0.1:lockPort). The kernel releases
  // it when the process dies, so there is no stale lock to take over and no takeover race.
  const lockServer = createServer();
  const locked = await new Promise(resolve => {
    lockServer.once("error", () => resolve(false));
    lockServer.listen({ host: "127.0.0.1", port: cfg.lockPort, exclusive: true }, () =>
      resolve(true)
    );
  });
  if (!locked) await fatal(75, `another run holds the lock (127.0.0.1:${cfg.lockPort})`);
  let released = false;
  const release = () => {
    if (released) return;
    released = true;
    lockServer.close();
  };

  const statePath = join(stateDir, "state.json");
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
    const sp = stateProblems(st, { allowOverCap: true });
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
  } catch (e) {
    // anything before or around the round (no provider, unreadable or inconsistent state, cap or
    // address mismatch) alerts instead of exiting silently
    release();
    await fatal(1, safeText("startup", e));
  } finally {
    release();
  }
}

if (import.meta.url === `file://${process.argv[1]}`)
  main().then(
    code => process.exit(code),
    e => die(1, safeText("pause-job", e))
  );
