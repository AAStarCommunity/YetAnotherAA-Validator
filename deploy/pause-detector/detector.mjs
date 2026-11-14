#!/usr/bin/env node
// The rc.8 pause DETECTOR (DSR: "detect, then act by hand"): one read-only round of lib/detect.mjs
// per launchd start (io.aastar.dvt-pause-detector, StartInterval 3600). See README.md.
//
//   node deploy/pause-detector/detector.mjs --config ~/.aoa-pause-detector/config.json
//
// It holds NO key: there is no keystore, no signer, no signing or broadcast code, and the JSON-RPC
// client below refuses every method outside a read-only allowlist. check-pause-detector.mjs fails
// if any signing or broadcast call appears in these files.
//
// The RPC URLs and the Telegram token are 0600 files in the secrets directory (the generic
// ../pause-job/lib/secret-file.mjs with this file's own name table, DETECTOR_SECRETS); none is ever
// printed, logged or put in argv. There is no keystore or password file among them.
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
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { ethers } from "ethers";
import { emptyState, runRound, stateProblems } from "./lib/detect.mjs";
import { readSecretFile, dirProblems, okDir } from "../pause-job/lib/secret-file.mjs";
import { SafeError, safeText, isOurs } from "../pause-job/lib/safe-error.mjs";

/** The only JSON-RPC methods this process may send. Nothing here can sign or broadcast. */
export const READ_METHODS = Object.freeze([
  "eth_chainId",
  "eth_getBlockByNumber",
  "eth_getBlockByHash",
  "eth_getLogs",
  "eth_call",
  "eth_getCode",
  "eth_getStorageAt",
]);
export const CHAINS = new Set([11155111, 10, 31337]);
/** The detector's secret files: two RPC URLs and the aastar-monitor bot token. Nothing else. */
export const DETECTOR_SECRETS = Object.freeze({
  rpcPrimary: "aoa-dvt-detector-rpc-primary",
  rpcFallback: "aoa-dvt-detector-rpc-fallback",
  telegram: "aoa-dvt-alert-bot-token",
});

const die = (code, m) => {
  console.error(`pause-detector: ${m}`);
  process.exit(code);
};
const tilde = p => (typeof p === "string" ? p.replace(/^~\//, `${homedir()}/`) : undefined);
const HASH = /^0x[0-9a-fA-F]{64}$/;

/**
 * The process confinement (Codex R3: a static scan of JavaScript cannot be complete). It guards
 * against an ACCIDENTAL signing path, not a malicious dependency (Node's docs: the permission model
 * is not a security boundary against malicious code; the trust boundary is the keeper's uid). The
 * detector runs ONLY under Node's permission model, with no child processes, no workers, no native
 * addons, no WASI, and file reads limited so that no key anywhere on the host (the price keeper's
 * key.env, a foundry keystore, ...) is readable. `perm` is process.permission; `home` the home
 * directory. Returns the problems (empty = run). Pure.
 */
export function permissionProblems(perm, home) {
  if (!perm || typeof perm.has !== "function")
    return ["not running under Node's permission model (node --permission, see the plist)"];
  const p = [];
  for (const [scope, what] of [
    ["child", "child processes"],
    ["worker", "worker threads"],
    ["addon", "native addons"],
    ["wasi", "WASI"],
  ])
    if (perm.has(scope)) p.push(`${what} are allowed`);
  for (const path of ["/", home, `${home}/.config`, `${home}/.foundry`, `${home}/.ssh`])
    if (perm.has("fs.read", path)) p.push(`${path} is readable`);
  if (perm.has("fs.write", "/") || perm.has("fs.write", home)) p.push("writes are not confined");
  return p;
}

// variables through which node or the loader take options or code before the script runs: a
// NODE_OPTIONS=--allow-fs-read=<key> widens the grants without touching argv (Codex R4 P1-1)
export const INJECTION_ENV = /^(NODE_.*|DYLD_.*|BASH_ENV|ENV|BASH_FUNC_.*|SHELLOPTS|PS4)$/;

/**
 * The launch itself, exactly: node's own flags (`execArgv`) are the plist's and nothing else, and
 * no option-injecting variable is in the environment. `repo` is this checkout, `home` the home
 * directory, `envNames` the environment's variable names. Returns the problems. Pure.
 */
export function launchProblems({ execArgv, envNames, home, repo }) {
  const p = [];
  const d = `${home}/.aoa-pause-detector`;
  const flag = execArgv?.[0];
  const want = [
    flag,
    `--allow-fs-read=${repo}`,
    `--allow-fs-read=${d}`,
    `--allow-fs-write=${d}/state`,
  ];
  if (
    !Array.isArray(execArgv) ||
    !["--permission", "--experimental-permission"].includes(flag) ||
    execArgv.join("\n") !== want.join("\n")
  )
    p.push(
      "node was not started with exactly the plist's flags (--permission, reads of the repo and ~/.aoa-pause-detector, writes of its state)"
    );
  const bad = (envNames ?? []).filter(n => INJECTION_ENV.test(n));
  if (bad.length) p.push(`option-injecting variables are set: ${bad.join(", ")}`);
  return p;
}

/** Problems with a config object, fixed wording. Pure. */
export function configProblems(c) {
  if (!c || typeof c !== "object") return ["config is not an object"];
  const p = [];
  if (!CHAINS.has(c.chainId)) p.push(`chainId must be one of ${[...CHAINS].join(", ")}`);
  for (const k of ["spProxy", "registry", "implementation", "registryImplementation"])
    if (!ethers.isAddress(c[k] ?? "")) p.push(`${k} is not an address`);
  for (const k of [
    "proxyCodeHash",
    "implementationCodeHash",
    "registryCodeHash",
    "registryImplementationCodeHash",
  ])
    if (!HASH.test(c[k] ?? "")) p.push(`${k} must be a 32-byte hex hash (from the tag read-back)`);
  if (!Number.isSafeInteger(c.startBlock) || c.startBlock < 1)
    p.push("startBlock must be a positive block (SP's deploy block)");
  if (!Number.isSafeInteger(c.logChunk) || c.logChunk < 1 || c.logChunk > 50000)
    p.push("logChunk must be 1..50000");
  if (!Number.isSafeInteger(c.rescanBlocks) || c.rescanBlocks < 0 || c.rescanBlocks > 1_000_000)
    p.push("rescanBlocks must be 0..1000000 (blocks re-read behind the cursor each round)");
  for (const k of ["stateDir", "secretsDir"])
    if (!okDir(tilde(c[k]))) p.push(`${k} must be an absolute plain path`);
  if (c.telegram !== null && !/^-?[0-9]+$/.test(String(c.telegram?.chatId ?? "")))
    p.push("telegram must be null or { chatId }");
  if (!Number.isSafeInteger(c.lockPort) || c.lockPort < 1024 || c.lockPort > 65535)
    p.push("lockPort must be a port in 1024..65535");
  if (!Number.isSafeInteger(c.realertMinutes) || c.realertMinutes < 1)
    p.push("realertMinutes must be a positive integer");
  const nm = /^[a-z0-9-]{1,32}$/;
  if (!nm.test(c.rpc?.primary ?? "") || !nm.test(c.rpc?.fallback ?? ""))
    p.push("rpc must be { primary, fallback } provider names");
  else if (c.rpc.primary === c.rpc.fallback)
    p.push("rpc.primary and rpc.fallback must be different providers");
  return p;
}

/**
 * fsync, except where Node's permission model disables it (ERR_ACCESS_DENIED, Node 24): there the
 * write is still atomic (temp file + rename); a crash can lose the last write, which costs a
 * rescan and a repeated alert, never a missed one.
 */
const syncFd = fd => {
  try {
    fsyncSync(fd);
  } catch (e) {
    if (e?.code !== "ERR_ACCESS_DENIED") throw e;
  }
};

/** Write `obj` to `path`: 0600 temp file, fsync (see syncFd), rename, fsync the directory. */
export function writeDurable(path, obj) {
  const tmp = `${path}.${process.pid}.tmp`;
  const fd = openSync(
    tmp,
    constants.O_WRONLY | constants.O_CREAT | constants.O_TRUNC | constants.O_NOFOLLOW,
    0o600
  );
  try {
    const buf = Buffer.from(`${JSON.stringify(obj, null, 2)}\n`);
    let off = 0;
    while (off < buf.length) {
      const n = writeSync(fd, buf, off, buf.length - off);
      if (!(n > 0)) throw new SafeError("state write made no progress");
      off += n;
    }
    syncFd(fd);
  } finally {
    closeSync(fd);
  }
  renameSync(tmp, path);
  const d = openSync(dirname(path), constants.O_RDONLY);
  try {
    syncFd(d);
  } finally {
    closeSync(d);
  }
}

/**
 * The JSON-RPC transport: one POST per request over `url`, bounded to 30 s. It is called only by
 * readOnlyChain's `rpc`, after the method allowlist. A JSON-RPC error keeps its `data` (a revert
 * selector for the probe) and nothing else; the URL never reaches an error.
 */
export function rpcTransport(url) {
  let id = 0;
  return async (method, params) => {
    // the allowlist again, here: the transport cannot be used to send anything (Codex R2 P1-1)
    if (!READ_METHODS.includes(method))
      throw new SafeError(`refused: ${method} is not a read-only method`);
    const res = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: ++id, method, params }),
      signal: AbortSignal.timeout(30_000),
    });
    if (!res.ok) throw new SafeError(`${method}: HTTP ${res.status}`);
    let j;
    try {
      j = await res.json();
    } catch {
      throw new SafeError(`${method}: not JSON`);
    }
    if (j?.error) {
      const e = new SafeError(
        `${method}: ${j.error.code === 3 || /revert/i.test(String(j.error.message)) ? "CALL_EXCEPTION" : "SERVER_ERROR"}`
      );
      if (typeof j.error.data === "string") e.data = j.error.data;
      throw e;
    }
    if (!j || !("result" in j)) throw new SafeError(`${method}: no result`);
    return j.result;
  };
}

/**
 * A read-only JSON-RPC chain. `send` is injectable (tests); by default rpcTransport(url). Any
 * method outside READ_METHODS is refused BEFORE it reaches the transport. Every error leaving here
 * is a SafeError (fixed text, no URL), keeping a revert selector for the probe.
 */
export function readOnlyChain(url, send = null) {
  const transport = send ?? rpcTransport(url);
  const rpc = async (m, params) => {
    if (!READ_METHODS.includes(m)) throw new SafeError(`refused: ${m} is not a read-only method`);
    try {
      return await transport(m, params);
    } catch (e) {
      const err = new SafeError(safeText(m, e));
      for (const d of [e?.data, e?.info?.error?.data, e?.error?.data])
        if (typeof d === "string" && /^0x[0-9a-fA-F]*$/.test(d)) err.data = d;
      throw err;
    }
  };
  return {
    rpc,
    chainId: () => rpc("eth_chainId", []),
    blockNumber: async tag => {
      const b = await rpc("eth_getBlockByNumber", [tag, false]);
      if (!b) throw new SafeError(`no ${tag} block`);
      return Number(b.number);
    },
    blockByNumber: async n => {
      const b = await rpc("eth_getBlockByNumber", [
        typeof n === "number" ? ethers.toQuantity(n) : n,
        false,
      ]);
      return b ? { number: Number(b.number), hash: b.hash } : null;
    },
    blockByHash: async h => {
      const b = await rpc("eth_getBlockByHash", [h, false]);
      return b ? { number: Number(b.number), hash: b.hash, parentHash: b.parentHash } : null;
    },
    getLogs: f => rpc("eth_getLogs", [f]),
    call: (tx, tag) => rpc("eth_call", [tx, tag]),
    code: (a, tag) => rpc("eth_getCode", [a, tag]),
    storageAt: (a, slot, tag) => rpc("eth_getStorageAt", [a, slot, tag]),
  };
}

/** Alerts to send now: a new key, or one last sent `realertMinutes` ago or more. Pure. */
export function dueAlerts(st, alerts, realertMinutes, now) {
  return alerts.filter(
    a => !(a.key in st.alerts) || now - st.alerts[a.key] >= realertMinutes * 60_000
  );
}

/**
 * Keys alerted before that no longer hold. A key resolves only on a round that could see it:
 * `actionable:<op>` and `unknown:<op>` only when that operator was read this round at a canonical B
 * with the identity confirmed, and every other key only when it is absent from a canonical round.
 * Pure.
 */
export function resolvedKeys(st, alerts, report) {
  if (!report?.canonical) return [];
  const now = new Set(alerts.map(a => a.key));
  const seen = new Map((report.operators ?? []).map(r => [r.operator, r.status]));
  return Object.keys(st.alerts).filter(k => {
    if (now.has(k)) return false;
    const m = k.match(/^(actionable|unknown|not-configured):(0x[0-9a-fA-F]{40})$/);
    if (!m) return true;
    const s = seen.get(m[2]);
    return report.identity?.ok === true && s !== undefined && s !== "unknown";
  });
}

/** Telegram's message limit, with room for the header line. */
export const MESSAGE_CHARS = 3800;

/**
 * Split alert lines into messages of at most MESSAGE_CHARS, each line whole. A line longer than
 * the limit (not produced by this detector) is cut, and says so. Returns [{ text, items }], where
 * items are the caller's entries carried in that message. Pure.
 */
export function batches(header, entries) {
  const out = [];
  let cur = null;
  for (const e of entries) {
    let line = e.line;
    if (header.length + 1 + line.length > MESSAGE_CHARS)
      line = `${line.slice(0, MESSAGE_CHARS - header.length - 20)} …(cut)`;
    if (!cur || cur.text.length + 1 + line.length > MESSAGE_CHARS) {
      cur = { text: header, items: [] };
      out.push(cur);
    }
    cur.text += `\n${line}`;
    cur.items.push(e);
  }
  return out;
}

/**
 * Send one message. Delivered only when Telegram answers HTTP 2xx with a JSON body `ok: true`.
 * `post` is injectable (tests).
 */
export async function telegram(cfg, token, text, post = null) {
  if (!cfg.telegram) {
    console.error(`ALERT ${text}`);
    return { ok: false, why: "no Telegram configured" };
  }
  try {
    const r = post
      ? await post(text)
      : await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ chat_id: cfg.telegram.chatId, text }),
          signal: AbortSignal.timeout(15_000),
        });
    if (!r.ok) return { ok: false, why: `telegram HTTP ${r.status}` };
    let j;
    try {
      j = await r.json();
    } catch {
      return { ok: false, why: "telegram: not JSON" };
    }
    return j?.ok === true ? { ok: true } : { ok: false, why: "telegram: ok is not true" };
  } catch (e) {
    return { ok: false, why: safeText("telegram", e) };
  }
}

/**
 * Deliver due alerts and resolutions in messages of whole lines; mark sent (or delete) only the
 * entries of messages Telegram accepted. Mutates st.alerts. Returns { ok, sent, failed }.
 */
export async function deliver(st, due, resolved, header, now, send) {
  const entries = [
    ...due.map(a => ({ line: `- ${a.text}`, ack: () => (st.alerts[a.key] = now) })),
    ...resolved.map(k => ({ line: `- resolved: ${k}`, ack: () => delete st.alerts[k] })),
  ];
  let sent = 0;
  let failed = 0;
  let why;
  for (const b of batches(header, entries)) {
    const r = await send(b.text);
    if (r.ok) {
      for (const e of b.items) e.ack();
      sent += b.items.length;
    } else {
      failed += b.items.length;
      why = r.why;
    }
  }
  return { ok: failed === 0, sent, failed, ...(why ? { why } : {}) };
}

async function main() {
  // first of all: nothing else runs outside the permission model
  const pp = [
    ...permissionProblems(process.permission, homedir()),
    ...launchProblems({
      execArgv: process.execArgv,
      envNames: Object.keys(process.env),
      home: homedir(),
      repo: resolve(dirname(fileURLToPath(import.meta.url)), "../.."),
    }),
  ];
  if (pp.length) die(78, `refusing to run: ${pp.join("; ")}`);
  const args = process.argv.slice(2);
  const i = args.indexOf("--config");
  const next = i + 1;
  const cfgPath = tilde(i >= 0 ? args[next] : undefined);
  if (!cfgPath) die(2, "usage: detector.mjs --config <file>");
  let cfg;
  try {
    cfg = JSON.parse(readFileSync(cfgPath, "utf8"));
  } catch {
    die(78, "config is missing or not JSON");
  }
  const stateDir = tilde(cfg?.stateDir);
  const secrets = tilde(cfg?.secretsDir);
  const lockOk =
    Number.isSafeInteger(cfg?.lockPort) && cfg.lockPort >= 1024 && cfg.lockPort <= 65535;
  const tgOk = cfg?.telegram === null || /^-?[0-9]+$/.test(String(cfg?.telegram?.chatId ?? ""));
  if (!okDir(stateDir) || !okDir(secrets) || !lockOk || !tgOk)
    die(78, `config: ${configProblems(cfg).join("; ") || "unusable for reporting"}`);
  const dp = dirProblems(
    existsSync(stateDir) ? lstatSync(stateDir) : null,
    process.getuid(),
    "state directory"
  );
  if (dp.length) die(78, `state directory: ${dp.join("; ")}`);

  // one instance: a listening socket on 127.0.0.1:lockPort, taken first; the kernel frees it
  const lockServer = createServer();
  const locked = await new Promise(resolve => {
    lockServer.once("error", () => resolve(false));
    lockServer.listen({ host: "127.0.0.1", port: cfg.lockPort, exclusive: true }, () =>
      resolve(true)
    );
  });
  if (!locked) die(75, `another run holds the lock (127.0.0.1:${cfg.lockPort})`);

  const statusPath = join(stateDir, "status.json");
  const statePath = join(stateDir, "state.json");
  const secret = (n, label) => {
    try {
      return readSecretFile(n, secrets, { names: DETECTOR_SECRETS });
    } catch (e) {
      throw new SafeError(`${label}: ${isOurs(e) ? e.message : "unreadable"}`);
    }
  };
  let token = null;
  const fatal = async (code, text) => {
    try {
      writeDurable(statusPath, {
        schema: "aoa-pause-detector-status/1",
        at: new Date().toISOString(),
        chainId: cfg.chainId,
        clear: false,
        startup: text,
      });
    } catch {
      /* best effort: the exit code and the log still carry it */
    }
    if (token)
      await telegram(cfg, token, `DVT pause detector (chain ${cfg.chainId}): unknown: ${text}`);
    lockServer.close();
    die(code, text);
  };
  try {
    token = cfg.telegram ? secret(DETECTOR_SECRETS.telegram, "the alert bot token file") : null;
  } catch (e) {
    await fatal(78, safeText("secrets", e));
  }
  const cp = (() => {
    try {
      return configProblems(cfg);
    } catch {
      return ["config has a field of the wrong type"];
    }
  })();
  if (cp.length) await fatal(78, `config: ${cp.join("; ")}`);

  try {
    const providers = [
      { name: cfg.rpc.primary, url: secret(DETECTOR_SECRETS.rpcPrimary, "the primary RPC file") },
      {
        name: cfg.rpc.fallback,
        url: secret(DETECTOR_SECRETS.rpcFallback, "the fallback RPC file"),
      },
    ];
    // ONE provider for the whole round: the primary unless it fails a probe
    let chain = null;
    let provider = null;
    for (const pr of providers) {
      const c = readOnlyChain(pr.url);
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
    // the state is created on the first run and bound to { chainId, spProxy, startBlock }
    const st = existsSync(statePath)
      ? JSON.parse(readFileSync(statePath, "utf8"))
      : emptyState(cfg);
    const sp = stateProblems(st, cfg);
    if (sp.length)
      throw new SafeError(`state: ${sp.join("; ")} (a new deployment needs a new stateDir)`);
    const now = Date.now();
    let result;
    try {
      result = await runRound(st, { chain, cfg });
    } catch (e) {
      result = {
        alerts: [{ key: "round", text: `unknown: the round stopped (${safeText("round", e)})` }],
        report: null,
      };
    }
    if (provider !== cfg.rpc.primary)
      result.alerts.push({
        key: "fallback",
        text: `the primary RPC (${cfg.rpc.primary}) failed its probe; this round used ${provider}`,
      });
    const due = dueAlerts(st, result.alerts, cfg.realertMinutes, now);
    const resolved = resolvedKeys(st, result.alerts, result.report);
    const delivery = await deliver(
      st,
      due,
      resolved,
      `DVT pause detector (chain ${st.chainId}, block ${result.report?.block?.number ?? "?"}):`,
      now,
      text => telegram(cfg, token, text)
    );
    writeDurable(statePath, st);
    writeDurable(statusPath, {
      schema: "aoa-pause-detector-status/1",
      at: new Date(now).toISOString(),
      chainId: st.chainId,
      provider,
      clear: result.report?.clear === true,
      report: result.report,
      alerts: result.alerts.map(a => a.text),
      delivery,
    });
    return result.alerts.length || !delivery.ok ? 1 : 0;
  } catch (e) {
    await fatal(1, safeText("startup", e));
  } finally {
    lockServer.close();
  }
}

if (import.meta.url === `file://${process.argv[1]}`)
  main().then(
    code => process.exit(code),
    e => die(1, safeText("pause-detector", e))
  );
