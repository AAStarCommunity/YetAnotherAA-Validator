#!/usr/bin/env node
// Phase D pre-deploy check for the guardian watcher on the Mac Mini (M0 §5.5, §9 item 7, DSR's
// Phase D list). Read-only: it sends no transaction and writes nothing but its report.
//
//   node deploy/guardian-watcher/phase-d-check.mjs --config <phase-d.json> [--json]
//
// Every check reports PASS, FAIL or MISSING (a secret or deployment input not provided yet), and
// the script exits 0 only when every check is PASS. Secrets are never printed: an RPC URL is shown
// by its host only, and Keychain items are checked for existence (`security find-generic-password`
// without -w); the RPC URLs themselves are read from the Keychain into memory and used, never logged.
// See phase-d.example.json for the config; a placeholder value ("<...>") counts as MISSING.
import { execFileSync } from "node:child_process";
import { readFileSync, existsSync, statSync, accessSync, constants } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { ethers } from "ethers";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..", "..");
const W = join(ROOT, "services/guardian-watcher");

const args = process.argv.slice(2);
const ci = args.indexOf("--config");
if (ci < 0 || !args[ci + 1]) {
  console.error("usage: phase-d-check.mjs --config <phase-d.json> [--json]");
  process.exit(2);
}
const cfgPath = resolve(args[ci + 1]);
const cfg = JSON.parse(readFileSync(cfgPath, "utf8"));
const results = [];
const add = (id, status, detail) => results.push({ id, status, detail });
const placeholder = v =>
  v === undefined || v === null || v === "" || (typeof v === "string" && /^<.*>$/.test(v));
const host = url => {
  try {
    return new URL(url).host;
  } catch {
    return "<unparseable url>";
  }
};

/** A Keychain item exists (macOS `security`, no secret read). */
function keychainHas(service, account) {
  try {
    execFileSync(
      "security",
      ["find-generic-password", "-s", service, ...(account ? ["-a", account] : [])],
      {
        stdio: "ignore",
      }
    );
    return true;
  } catch {
    return false;
  }
}
/** A Keychain secret, into memory only (never printed). null when absent. */
function keychainRead(service, account) {
  try {
    return execFileSync(
      "security",
      ["find-generic-password", "-s", service, ...(account ? ["-a", account] : []), "-w"],
      { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }
    ).trim();
  } catch {
    return null;
  }
}

// ---- 1. Keychain items (Pinata / Filebase tokens, keystore password, Telegram, RPC URLs)
for (const k of cfg.keychain ?? []) {
  if (placeholder(k.service)) add(`keychain:${k.purpose}`, "MISSING", "service name not set");
  else
    add(
      `keychain:${k.purpose}`,
      keychainHas(k.service, k.account) ? "PASS" : "MISSING",
      `${k.service}${k.account ? ` / ${k.account}` : ""}`
    );
}

// ---- 2. Watcher config: loads with the watcher's own validation
let wcfg = null;
if (placeholder(cfg.watcherConfig)) add("watcher-config", "MISSING", "path not set");
else {
  try {
    const { loadConfig } = await import(join(W, "watcher.mjs"));
    wcfg = loadConfig(resolve(dirname(cfgPath), cfg.watcherConfig));
    accessSync(wcfg.dataDir, constants.W_OK);
    add(
      "watcher-config",
      "PASS",
      `aggregator ${wcfg.aggregator}, SP ${wcfg.roles.superPaymaster}, dataDir writable`
    );
  } catch (e) {
    add(
      "watcher-config",
      existsSync(resolve(dirname(cfgPath), cfg.watcherConfig)) ? "FAIL" : "MISSING",
      e.message
    );
  }
}

// ---- 3. Sender keystore: present, 0600, an address that is none of the guardian/owner/deployer keys
let sender = null;
if (placeholder(cfg.sender?.keystore)) add("sender-keystore", "MISSING", "keystore path not set");
else if (!existsSync(cfg.sender.keystore))
  add("sender-keystore", "MISSING", "keystore file not present");
else {
  try {
    const ks = JSON.parse(readFileSync(cfg.sender.keystore, "utf8"));
    sender = ethers.getAddress(ks.address.startsWith("0x") ? ks.address : `0x${ks.address}`);
    const mode = statSync(cfg.sender.keystore).mode & 0o777;
    const forbidden = (cfg.sender.forbidden ?? []).map(a => a.toLowerCase());
    if (mode & 0o077) add("sender-keystore", "FAIL", `mode ${mode.toString(8)}, expected 600`);
    else if (forbidden.includes(sender.toLowerCase()))
      add("sender-keystore", "FAIL", `${sender} is a guardian/owner/deployer key`);
    else
      add(
        "sender-keystore",
        "PASS",
        `${sender}, mode 600, distinct from ${forbidden.length} forbidden keys`
      );
  } catch (e) {
    add("sender-keystore", "FAIL", `unreadable keystore JSON: ${e.message.slice(0, 80)}`);
  }
}

// ---- 4. launchd: jobs that must be off stay off, the watcher job is loaded
const uid = process.getuid?.() ?? 0;
const loaded = label => {
  try {
    execFileSync("launchctl", ["print", `gui/${uid}/${label}`], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
};
for (const label of cfg.launchd?.mustBeOff ?? []) {
  if (placeholder(label)) add(`launchd-off:${label}`, "MISSING", "label not set");
  else
    add(
      `launchd-off:${label}`,
      loaded(label) ? "FAIL" : "PASS",
      loaded(label) ? "loaded" : "not loaded"
    );
}
for (const label of cfg.launchd?.mustBeOn ?? []) {
  if (placeholder(label)) add(`launchd-on:${label}`, "MISSING", "label not set");
  else
    add(
      `launchd-on:${label}`,
      loaded(label) ? "PASS" : "MISSING",
      loaded(label) ? "loaded" : "not loaded yet"
    );
}

// ---- 5. DVT nodes: slash submission off (AUDIT_ENABLED / AUDIT_EXECUTE_SLASH not "true")
for (const c of cfg.dvtNodes?.containers ?? []) {
  if (placeholder(c)) {
    add(`node-slash-off:${c}`, "MISSING", "container name not set");
    continue;
  }
  let env = null;
  try {
    env = JSON.parse(
      execFileSync("docker", ["inspect", "--format", "{{json .Config.Env}}", c], {
        encoding: "utf8",
        stdio: ["ignore", "pipe", "ignore"],
      })
    );
  } catch {
    add(`node-slash-off:${c}`, "MISSING", "container not found or docker unavailable");
    continue;
  }
  const on = ["AUDIT_ENABLED", "AUDIT_EXECUTE_SLASH"].filter(k => env.includes(`${k}=true`));
  add(
    `node-slash-off:${c}`,
    on.length ? "FAIL" : "PASS",
    on.length ? `${on.join(", ")} set` : "audit slash submission off"
  );
}

// ---- 6. RPCs: primary and second provider, both trace-verified, different operators
const rpcUrl = r =>
  placeholder(r?.keychainService) ? null : keychainRead(r.keychainService, r.keychainAccount);
// PHASE_D_RPC_PRIMARY / PHASE_D_RPC_SECOND override the Keychain for a dry run of this script only
// (an environment variable, never a file); the value is never printed either.
const primaryUrl = process.env.PHASE_D_RPC_PRIMARY || rpcUrl(cfg.rpc?.primary);
const secondUrl = process.env.PHASE_D_RPC_SECOND || rpcUrl(cfg.rpc?.second);
const site = h => h.split(".").slice(-2).join("."); // registrable domain, close enough for an operator
async function rpcCheck(id, url) {
  if (!url) return add(id, "MISSING", "RPC URL not in the Keychain");
  try {
    const p = new ethers.JsonRpcProvider(url, undefined, { staticNetwork: true });
    const net = await p.getNetwork();
    if (cfg.chainId && Number(net.chainId) !== cfg.chainId)
      return add(id, "FAIL", `${host(url)}: chainId ${net.chainId}, expected ${cfg.chainId}`);
    if (!wcfg)
      return add(
        id,
        "MISSING",
        `${host(url)}: reachable, chainId ok; trace check needs the watcher config`
      );
    const { verifyTrace } = await import(join(W, "lib/scan.mjs"));
    const fin = await p.getBlock("finalized");
    const v = await verifyTrace(p, wcfg, fin.number, { blocks: 5, maxTx: 8 });
    add(
      id,
      v.state === "verified" ? "PASS" : "FAIL",
      `${host(url)}: trace capability ${v.state}${v.reason ? ` (${v.reason})` : ""}`
    );
  } catch (e) {
    add(id, "FAIL", `${host(url)}: ${e.code ?? "error"}`);
  }
}
await rpcCheck("rpc-primary", primaryUrl);
await rpcCheck("rpc-second", secondUrl);
if (primaryUrl && secondUrl) {
  const a = site(host(primaryUrl));
  const b = site(host(secondUrl));
  add(
    "rpc-independent",
    a !== b ? "PASS" : "FAIL",
    a !== b ? `${a} vs ${b}` : `both ${a}: D-RPC2 needs a different operator`
  );
} else add("rpc-independent", "MISSING", "needs both RPC URLs");

// ---- 7. On-chain deployment facts (§9 item 7), read through the primary RPC
const C = cfg.contracts ?? {};
if (!primaryUrl) add("onchain", "MISSING", "needs the primary RPC");
else if ([C.dvtValidator, C.aggregator, C.manifestSafe].some(placeholder))
  add("onchain", "MISSING", "contract addresses not set");
else {
  const p = new ethers.JsonRpcProvider(primaryUrl, undefined, { staticNetwork: true });
  const read = async (to, sig, ret) => {
    const i = new ethers.Interface([`function ${sig} view returns (${ret})`]);
    const name = sig.slice(0, sig.indexOf("("));
    return i.decodeFunctionResult(
      name,
      await p.call({ to, data: i.encodeFunctionData(name, []) })
    )[0];
  };
  const fact = async (id, f, want, show = x => String(x)) => {
    try {
      const v = await f();
      add(id, want(v) ? "PASS" : "FAIL", show(v));
    } catch (e) {
      add(id, "FAIL", `read failed: ${e.code ?? "error"}`);
    }
  };
  await fact(
    "dvtValidator.categoryCount==0",
    () => read(C.dvtValidator, "categoryCount()", "uint256"),
    v => v === 0n
  );
  await fact(
    "aggregator.fraudProofVerifier==0",
    () => read(C.aggregator, "fraudProofVerifier()", "address"),
    v => v === ethers.ZeroAddress
  );
  await fact(
    "aggregator.owner==manifest Safe",
    () => read(C.aggregator, "owner()", "address"),
    v => v.toLowerCase() === C.manifestSafe.toLowerCase()
  );
  if (sender && cfg.sender?.minBalanceWei)
    await fact(
      "sender balance",
      () => p.getBalance(sender),
      v => v >= BigInt(cfg.sender.minBalanceWei),
      v =>
        `${ethers.formatEther(v)} ETH (min ${ethers.formatEther(BigInt(cfg.sender.minBalanceWei))})`
    );
}

// ---- 8. Release checks that run elsewhere: their recorded results must be present
for (const r of cfg.releaseEvidence ?? []) {
  if (placeholder(r.path)) add(`evidence:${r.name}`, "MISSING", "report path not set");
  else if (!existsSync(r.path)) add(`evidence:${r.name}`, "MISSING", "report not produced yet");
  else {
    try {
      const j = JSON.parse(readFileSync(r.path, "utf8"));
      // compared as JSON, so a report can require e.g. an empty gap list
      const ok = r.passWhen
        ? Object.entries(r.passWhen).every(([k, v]) => JSON.stringify(j[k]) === JSON.stringify(v))
        : true;
      add(
        `evidence:${r.name}`,
        ok ? "PASS" : "FAIL",
        ok ? `${r.path} as required` : `${r.path} does not show ${JSON.stringify(r.passWhen)}`
      );
    } catch (e) {
      add(`evidence:${r.name}`, "FAIL", `unreadable: ${e.message.slice(0, 80)}`);
    }
  }
}

const count = s => results.filter(r => r.status === s).length;
const summary = { pass: count("PASS"), fail: count("FAIL"), missing: count("MISSING") };
if (args.includes("--json")) console.log(JSON.stringify({ summary, results }, null, 2));
else {
  for (const r of results)
    console.log(`${r.status.padEnd(7)} ${r.id}${r.detail ? ` — ${r.detail}` : ""}`);
  console.log(`\n${summary.pass} PASS, ${summary.fail} FAIL, ${summary.missing} MISSING`);
}
process.exit(summary.fail || summary.missing ? 1 : 0);
