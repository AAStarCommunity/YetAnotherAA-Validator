#!/usr/bin/env node
// Phase D pre-deploy check for the guardian watcher on the Mac Mini (M0 §5.5, §9 item 7, DSR's
// Phase D list). Read-only: it sends no transaction and writes nothing but its report.
//
//   node deploy/guardian-watcher/phase-d-check.mjs --config <phase-d.json> [--json]
//
// Every check reports PASS, FAIL or MISSING (an input not provided yet), and the script exits 0 only
// when every check is PASS. The config schema is mandatory: a section or item left out is reported
// MISSING, never silently skipped. Secrets are never printed: RPC endpoints are shown by their
// configured operator label only, Keychain items are checked for existence, and error output is a
// fixed category, never an exception's text. See phase-d.example.json; a "<...>" value is MISSING.
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync, readdirSync, existsSync, statSync, accessSync, constants } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { ethers } from "ethers";
import {
  parseLaunchd,
  bindingProblems,
  liveProblems,
  parseLstart,
  staleProblems,
  importClosure,
} from "./phase-d-binding.mjs";

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
let cfg;
try {
  cfg = JSON.parse(readFileSync(cfgPath, "utf8"));
} catch {
  console.error("config: unreadable or not JSON");
  process.exit(2);
}
const results = [];
const add = (id, status, detail) => results.push({ id, status, detail });
const placeholder = v =>
  v === undefined || v === null || v === "" || (typeof v === "string" && /^<.*>$/.test(v));
const expand = p => (typeof p === "string" && p.startsWith("~/") ? join(homedir(), p.slice(2)) : p);
const isAddr = a => typeof a === "string" && ethers.isAddress(a);
const gitBlob = text => {
  const b = Buffer.from(text, "utf8");
  return createHash("sha1")
    .update(Buffer.concat([Buffer.from(`blob ${b.length}\0`), b]))
    .digest("hex");
};

// ---- 1. Keychain (DSR 0829236d: account aoa-watcher, six named services), existence only
const KEYCHAIN_ITEMS = [
  "pinata",
  "filebase",
  "keystorePassword",
  "alertBot",
  "rpcPrimary",
  "rpcSecondary",
];
const kc = cfg.keychain ?? {};
const kcAccount = kc.account;
const keychainHas = service =>
  spawnSync("security", ["find-generic-password", "-s", service, "-a", kcAccount], {
    stdio: "ignore",
  }).status === 0;
function keychainRead(service) {
  const r = spawnSync("security", ["find-generic-password", "-s", service, "-a", kcAccount, "-w"], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "ignore"],
  });
  return r.status === 0 ? r.stdout.trim() : null;
}
if (placeholder(kcAccount)) add("keychain:account", "MISSING", "keychain.account not set");
for (const item of KEYCHAIN_ITEMS) {
  const svc = kc.services?.[item];
  if (placeholder(svc) || placeholder(kcAccount))
    add(`keychain:${item}`, "MISSING", "service or account not set");
  else add(`keychain:${item}`, keychainHas(svc) ? "PASS" : "MISSING", `${svc} / ${kcAccount}`);
}
const secret = item =>
  placeholder(kc.services?.[item]) || placeholder(kcAccount)
    ? null
    : keychainRead(kc.services[item]);

// ---- 2. Watcher config: loads with the watcher's own validation; bound to the contracts below
let wcfg = null;
if (placeholder(cfg.watcherConfig)) add("watcher-config", "MISSING", "watcherConfig path not set");
else {
  const p = resolve(dirname(cfgPath), expand(cfg.watcherConfig));
  if (!existsSync(p)) add("watcher-config", "MISSING", "watcher config file not present");
  else {
    try {
      const { loadConfig } = await import(join(W, "watcher.mjs"));
      wcfg = loadConfig(p);
      accessSync(wcfg.dataDir, constants.W_OK);
      add("watcher-config", "PASS", "valid; dataDir writable");
    } catch {
      add(
        "watcher-config",
        "FAIL",
        "does not load with the watcher's validation, or dataDir not writable"
      );
    }
  }
}

// ---- 3. Sender keystore: an encrypted keystore, mode exactly 0600, whose DECRYPTED address is none
// of the forbidden keys (guardians, owner Safe, deployer)
const sender = cfg.sender ?? {};
// role-specific (Codex R2 #4): every guardian, the owner Safe and the deployer, each required; the
// on-chain SP.guardian() is checked against the sender as well (section 7)
const fb = sender.forbidden ?? {};
const guardians = Array.isArray(fb.guardians) ? fb.guardians : [];
const roleList = [
  ["guardians", guardians.length > 0 && guardians.every(isAddr)],
  ["ownerSafe", isAddr(fb.ownerSafe)],
  ["deployer", isAddr(fb.deployer)],
];
const forbiddenOk = roleList.every(([, ok]) => ok);
const forbidden = forbiddenOk ? [...guardians, fb.ownerSafe, fb.deployer] : [];
add(
  "sender-forbidden-list",
  forbiddenOk ? "PASS" : "MISSING",
  forbiddenOk
    ? `${guardians.length} guardians, owner Safe, deployer`
    : `sender.forbidden.${roleList
        .filter(([, ok]) => !ok)
        .map(([k]) => k)
        .join(", ")} not set`
);
if (
  forbiddenOk &&
  isAddr(cfg.contracts?.manifestSafe) &&
  fb.ownerSafe.toLowerCase() !== cfg.contracts.manifestSafe.toLowerCase()
)
  add(
    "sender-forbidden-list:ownerSafe",
    "FAIL",
    "sender.forbidden.ownerSafe is not contracts.manifestSafe"
  );
let senderAddr = null;
const ksPath = expand(sender.keystore);
if (placeholder(sender.keystore)) add("sender-keystore", "MISSING", "sender.keystore not set");
else if (!existsSync(ksPath)) add("sender-keystore", "MISSING", "keystore file not present");
else {
  const mode = statSync(ksPath).mode & 0o777;
  let ks = null;
  try {
    ks = JSON.parse(readFileSync(ksPath, "utf8"));
  } catch {
    ks = null;
  }
  const c = ks && (ks.crypto ?? ks.Crypto);
  if (!c || typeof c.ciphertext !== "string" || typeof c.kdf !== "string")
    add("sender-keystore", "FAIL", "not an encrypted JSON keystore");
  else if (mode !== 0o600)
    add("sender-keystore", "FAIL", `mode ${mode.toString(8).padStart(3, "0")}, required 600`);
  else {
    const pw = secret("keystorePassword");
    if (pw === null)
      add(
        "sender-keystore",
        "MISSING",
        "encrypted, mode 600; password not in the Keychain, address unverified"
      );
    else {
      try {
        senderAddr = (await ethers.Wallet.fromEncryptedJson(JSON.stringify(ks), pw)).address;
        const hit = forbidden.some(a => isAddr(a) && a.toLowerCase() === senderAddr.toLowerCase());
        if (!forbiddenOk)
          add("sender-keystore", "MISSING", `decrypts to ${senderAddr}; forbidden list not set`);
        else if (hit)
          add("sender-keystore", "FAIL", `${senderAddr} is a guardian/owner/deployer key`);
        else
          add(
            "sender-keystore",
            "PASS",
            `decrypts to ${senderAddr}, mode 600, not a forbidden key`
          );
      } catch {
        add("sender-keystore", "FAIL", "the Keychain password does not decrypt the keystore");
      }
    }
  }
}

// ---- 4. launchd: one inspection per label, in the configured domain; "not found" is told apart from
// an inspection that failed
const ld = cfg.launchd ?? {};
// required members (Codex R2 #3): whatever the config lists, these are always checked
const REQUIRED_OFF = ["io.aastar.dvt-committee-keeper", "io.aastar.dvt-apply-rotation"];
const REQUIRED_ON = ["ai.aastar.aoa-watcher", "ai.aastar.aoa-watcher-heartbeat"];
ld.mustBeOff = [
  ...new Set([...REQUIRED_OFF, ...(Array.isArray(ld.mustBeOff) ? ld.mustBeOff : [])]),
];
ld.mustBeOn = [...new Set([...REQUIRED_ON, ...(Array.isArray(ld.mustBeOn) ? ld.mustBeOn : [])])];
const domain = placeholder(ld.domain) ? `gui/${process.getuid?.() ?? 0}` : ld.domain;
const launchdOut = new Map();
function launchdState(label) {
  const r = spawnSync("launchctl", ["print", `${domain}/${label}`], { encoding: "utf8" });
  launchdOut.set(label, r.status === 0 ? (r.stdout ?? "") : null);
  // loaded is not running (Codex R3 #3): a required job must be running with a live pid
  if (r.status === 0) {
    const out = r.stdout ?? "";
    return /^\s*state = running\s*$/m.test(out) && /^\s*pid = \d+\s*$/m.test(out)
      ? "running"
      : "loaded";
  }
  if (/could not find service/i.test(`${r.stdout ?? ""}${r.stderr ?? ""}`)) return "absent";
  return "unknown";
}
const say = s =>
  ({
    running: `running in ${domain}`,
    loaded: `loaded in ${domain} but not running`,
    absent: `not loaded in ${domain}`,
  })[s] ?? "launchctl inspection failed";
if (!Array.isArray(ld.mustBeOff) || !ld.mustBeOff.length)
  add("launchd-off", "MISSING", "launchd.mustBeOff not set");
for (const label of ld.mustBeOff ?? []) {
  if (placeholder(label)) add(`launchd-off:${label}`, "MISSING", "label not set");
  else {
    const s = launchdState(label);
    add(`launchd-off:${label}`, s === "absent" ? "PASS" : "FAIL", say(s));
  }
}
if (!Array.isArray(ld.mustBeOn) || !ld.mustBeOn.length)
  add("launchd-on", "MISSING", "launchd.mustBeOn not set");
for (const label of ld.mustBeOn ?? []) {
  if (placeholder(label)) add(`launchd-on:${label}`, "MISSING", "label not set");
  else {
    const s = launchdState(label);
    add(
      `launchd-on:${label}`,
      s === "running" ? "PASS" : s === "absent" ? "MISSING" : "FAIL",
      say(s)
    );
  }
}

// ---- 4b. the running watcher job IS this deployment (Codex R6-R8): it runs exactly the configured
// wrapper, and that wrapper is byte-for-byte this checkout's run-watcher.sh with watcherConfig and
// this checkout's watcher.mjs filled in (phase-d-binding.mjs). Nothing is printed.
{
  const out = launchdOut.get("ai.aastar.aoa-watcher");
  const wrapper = placeholder(ld.watcherWrapper) ? null : resolve(expand(ld.watcherWrapper));
  const wantConfig = placeholder(cfg.watcherConfig)
    ? null
    : resolve(dirname(cfgPath), expand(cfg.watcherConfig));
  if (!wrapper)
    add("watcher-job-binding", "MISSING", "launchd.watcherWrapper (run-watcher.sh path) not set");
  else if (!out)
    add("watcher-job-binding", "MISSING", "watcher job not running, binding not checkable");
  else {
    const { program, argv, pid } = parseLaunchd(out);
    let text = null;
    try {
      text = readFileSync(wrapper, "utf8");
    } catch {
      text = null;
    }
    let template = null;
    try {
      template = readFileSync(join(HERE, "run-watcher.sh"), "utf8");
    } catch {
      template = null;
    }
    // the entry is this checkout's watcher, the same one whose loadConfig validated watcherConfig
    const problems = bindingProblems({
      program,
      argv,
      wrapper,
      text,
      template,
      wantConfig,
      wantEntry: join(W, "watcher.mjs"),
      services: kc.services,
      account: kcAccount,
    });
    // the live process, not only the files (Codex R9): what the pid actually runs, with which RPCs
    const ps = extra =>
      pid
        ? spawnSync("ps", [...extra, "-ww", "-o", "command=", "-p", String(pid)], {
            encoding: "utf8",
            stdio: ["ignore", "pipe", "ignore"],
          })
        : null;
    const c = ps([]);
    const e = ps(["-E"]);
    problems.push(
      ...liveProblems({
        pid,
        psCommand: c?.status === 0 ? c.stdout : null,
        psEnv: e?.status === 0 ? e.stdout : null,
        wantEntry: join(W, "watcher.mjs"),
        wantConfig,
        rpcPrimary: secret("rpcPrimary"),
        rpcSecondary: secret("rpcSecondary"),
      })
    );
    // what the process loaded is what Phase D checks (Codex R10): nothing changed since it started
    const st = pid
      ? spawnSync("ps", ["-o", "lstart=", "-p", String(pid)], {
          encoding: "utf8",
          env: { ...process.env, LC_ALL: "C" },
          stdio: ["ignore", "pipe", "ignore"],
        })
      : null;
    const mtime = f => {
      try {
        return statSync(f).mtimeMs;
      } catch {
        return null;
      }
    };
    const watcherFiles = [];
    const walk = (d, label) => {
      try {
        for (const e of readdirSync(d, { withFileTypes: true }))
          if (e.isDirectory()) walk(join(d, e.name), label);
          else if (/\.(mjs|json)$/.test(e.name) && !/^check-/.test(e.name))
            watcherFiles.push({ label, mtimeMs: mtime(join(d, e.name)) });
      } catch {
        watcherFiles.push({ label, mtimeMs: null });
      }
    };
    walk(W, "watcher source");
    // and every module the watcher imports, wherever it lives in the checkout (Codex R11)
    for (const m of importClosure(
      join(W, "watcher.mjs"),
      f => {
        try {
          return readFileSync(f, "utf8");
        } catch {
          return null;
        }
      },
      (from, spec) => resolve(dirname(from), spec)
    ))
      watcherFiles.push({ label: "watcher module", mtimeMs: m.missing ? null : mtime(m.path) });
    // installed packages (ethers): an npm ci after a pull changes the lockfile
    watcherFiles.push({
      label: "package-lock.json",
      mtimeMs: mtime(join(ROOT, "package-lock.json")),
    });
    problems.push(
      ...staleProblems({
        startedAtMs: st?.status === 0 ? parseLstart(st.stdout) : null,
        files: [
          { label: "watcherConfig", mtimeMs: wantConfig ? mtime(wantConfig) : null },
          { label: "wrapper", mtimeMs: mtime(wrapper) },
          ...watcherFiles,
        ],
      })
    );
    add(
      "watcher-job-binding",
      problems.length ? "FAIL" : "PASS",
      problems.length
        ? problems.join("; ")
        : "the running process is this checkout's watcher with this config and the Keychain RPCs"
    );
  }
}

// ---- 5. DVT nodes: slash submission explicitly off. In the node's NestJS ConfigModule a variable set
// in the process environment takes precedence over .env, so an explicit AUDIT_ENABLED=false and
// AUDIT_EXECUTE_SLASH=false in the container's environment are binding; an ABSENT variable could
// still be switched on by a .env file, so absence does not pass.
// required members (Codex R2 #3): every running container built from the DVT image is checked,
// whatever the config lists; a compose-defined node that is neither running nor configured is said
const composeNodes = new Set();
// the deployment's own compose file (dvtNodes.compose, required): testnet and mainnet differ
const composeFile = cfg.dvtNodes?.compose;
if (placeholder(composeFile) || !/^docker-compose\.[a-z0-9-]+\.yml$/.test(composeFile))
  add("node-compose", "MISSING", "dvtNodes.compose (the deployment's docker-compose file) not set");
for (const f of placeholder(composeFile) ? [] : [composeFile]) {
  let text = "";
  try {
    text = readFileSync(join(ROOT, f), "utf8");
  } catch {
    // an unreadable compose file is a failure, never an empty inventory (Codex R3 #2)
    add("node-compose", "FAIL", "the deployment's compose file is unreadable");
    continue;
  }
  if (!/container_name:/.test(text))
    add("node-compose", "FAIL", "the compose file names no container");
  for (const m of text.matchAll(/container_name:\s*([A-Za-z0-9_.-]*node[A-Za-z0-9_.-]*)/g))
    composeNodes.add(m[1]);
}
const runningDvt = new Set();
const allRunning = new Set();
{
  // A DVT node is recognised by what makes it one, not by an image name (Codex R4 #2): every running
  // container whose environment HAS the node's required VALIDATOR_CONTRACT_ADDRESS key (only key
  // names are read here, never values), plus any image named aastar-dvt in any registry or digest
  // form. Discovery that fails is a failure.
  const r = spawnSync("docker", ["ps", "--format", "{{.Names}}\t{{.Image}}"], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "ignore"],
  });
  if (r.status !== 0)
    add("node-discovery", "FAIL", "docker ps failed: the running DVT nodes are unknown");
  else
    for (const l of r.stdout.split("\n")) {
      const [n, img] = l.trim().split("\t");
      if (!n) continue;
      allRunning.add(n);
      if (/(^|\/)aastar-dvt(:|@|$)/.test(img ?? "")) {
        runningDvt.add(n);
        continue;
      }
      const e = spawnSync("docker", ["inspect", "--format", "{{json .Config.Env}}", n], {
        encoding: "utf8",
        stdio: ["ignore", "pipe", "ignore"],
      });
      if (e.status !== 0) {
        add(`node-discovery:${n}`, "FAIL", "running container could not be inspected");
        continue;
      }
      let keys = [];
      try {
        keys = JSON.parse(e.stdout).map(x => String(x).split("=")[0]);
      } catch {
        add(`node-discovery:${n}`, "FAIL", "running container's environment unreadable");
        continue;
      }
      if (keys.includes("VALIDATOR_CONTRACT_ADDRESS")) runningDvt.add(n);
    }
}
const nodes = [
  ...new Set([
    ...(Array.isArray(cfg.dvtNodes?.containers) ? cfg.dvtNodes.containers : []),
    ...runningDvt,
  ]),
];
// completeness (Codex R5 #2): no discovery proves it (a renamed image can take its config from a
// mounted .env), so EVERY running container must be classified: a DVT node (configured or
// discovered) or explicitly excluded in dvtNodes.notDvt. An unclassified one fails.
const notDvt = new Set(Array.isArray(cfg.dvtNodes?.notDvt) ? cfg.dvtNodes.notDvt : []);
for (const n of allRunning)
  if (!nodes.includes(n) && !notDvt.has(n))
    add(
      `node-unclassified:${n}`,
      "FAIL",
      "running container is neither a DVT node nor listed in dvtNodes.notDvt"
    );
for (const n of notDvt)
  if (nodes.includes(n))
    add(`node-unclassified:${n}`, "FAIL", "listed in dvtNodes.notDvt but discovered as a DVT node");
for (const n of composeNodes)
  if (!nodes.includes(n))
    add(`node-slash-off:${n}`, "MISSING", "defined in compose, neither running nor configured");
if (!nodes.length) add("node-slash-off", "MISSING", "no DVT node configured or running");
for (const c of nodes ?? []) {
  if (placeholder(c)) {
    add(`node-slash-off:${c}`, "MISSING", "container name not set");
    continue;
  }
  const r = spawnSync("docker", ["inspect", "--format", "{{json .Config.Env}}", c], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "ignore"],
  });
  if (r.status !== 0) {
    add(`node-slash-off:${c}`, "MISSING", "container not found or docker unavailable");
    continue;
  }
  let env;
  try {
    env = JSON.parse(r.stdout);
  } catch {
    add(`node-slash-off:${c}`, "FAIL", "docker inspect output unreadable");
    continue;
  }
  const bad = ["AUDIT_ENABLED", "AUDIT_EXECUTE_SLASH"].filter(k => !env.includes(`${k}=false`));
  add(
    `node-slash-off:${c}`,
    bad.length ? "FAIL" : "PASS",
    bad.length
      ? `${bad.join(", ")} not explicitly false`
      : "AUDIT_ENABLED=false, AUDIT_EXECUTE_SLASH=false"
  );
}

// ---- 6. RPCs: primary and second provider, chainId, trace capability positively verified, and two
// DECLARED different operators on different hosts. Shown by operator label, never by URL or host.
// Different hosts are necessary, not sufficient: the declared operator is the author's statement.
const rpcCfg = cfg.rpc ?? {};
// PHASE_D_RPC_PRIMARY / PHASE_D_RPC_SECOND override the Keychain for a dry run only (environment,
// never a file); like the Keychain values, they are never printed.
const primaryUrl = process.env.PHASE_D_RPC_PRIMARY || secret("rpcPrimary");
const secondUrl = process.env.PHASE_D_RPC_SECOND || secret("rpcSecondary");
// an override run is a dry run: it can never be a release acceptance (Codex R2 #6)
if (process.env.PHASE_D_RPC_PRIMARY || process.env.PHASE_D_RPC_SECOND)
  add("release-mode", "FAIL", "PHASE_D_RPC_* override in use: dry run, not the Keychain endpoints");
const label = which => (placeholder(rpcCfg[which]?.operator) ? which : rpcCfg[which].operator);
const errCode = e =>
  typeof e?.code === "string" && /^[A-Z_]{2,40}$/.test(e.code) ? e.code : "error";
const hostname = url => {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return null;
  }
};
if (!Number.isSafeInteger(cfg.chainId)) add("chain-id", "MISSING", "chainId not set");
async function rpcCheck(which, url) {
  const id = `rpc-${which}`;
  if (!url) return add(id, "MISSING", `${label(which)}: URL not in the Keychain`);
  if (!Number.isSafeInteger(cfg.chainId))
    return add(id, "MISSING", `${label(which)}: chainId not set`);
  try {
    const p = new ethers.JsonRpcProvider(url, undefined, { staticNetwork: true });
    const net = await p.getNetwork();
    if (Number(net.chainId) !== cfg.chainId)
      return add(id, "FAIL", `${label(which)}: chainId ${net.chainId}, expected ${cfg.chainId}`);
    if (!wcfg)
      return add(
        id,
        "MISSING",
        `${label(which)}: chainId ok; trace check needs the watcher config`
      );
    const { verifyTrace } = await import(join(W, "lib/scan.mjs"));
    const fin = await p.getBlock("finalized");
    const v = await verifyTrace(p, wcfg, fin.number, { blocks: 5, maxTx: 8 });
    add(
      id,
      v.state === "verified" ? "PASS" : "FAIL",
      `${label(which)}: trace capability ${v.state}`
    );
  } catch (e) {
    add(id, "FAIL", `${label(which)}: ${errCode(e)}`);
  }
}
await rpcCheck("primary", primaryUrl);
await rpcCheck("second", secondUrl);
{
  const opA = rpcCfg.primary?.operator;
  const opB = rpcCfg.second?.operator;
  if (placeholder(opA) || placeholder(opB))
    add("rpc-independent", "MISSING", "declare rpc.primary.operator and rpc.second.operator");
  else if (!primaryUrl || !secondUrl) add("rpc-independent", "MISSING", "needs both RPC URLs");
  else {
    const hA = hostname(primaryUrl);
    const hB = hostname(secondUrl);
    if (opA.trim().toLowerCase() === opB.trim().toLowerCase())
      add("rpc-independent", "FAIL", `both declared as ${opA}`);
    else if (!hA || !hB || hA === hB) add("rpc-independent", "FAIL", "both endpoints on one host");
    else add("rpc-independent", "PASS", `declared operators ${opA} and ${opB}, different hosts`);
  }
}

// ---- 7. On-chain facts (§9 item 7), bound to the watcher config, read through the primary RPC
const C = cfg.contracts ?? {};
if ([C.dvtValidator, C.aggregator, C.manifestSafe].some(a => !isAddr(a)))
  add("onchain", "MISSING", "contracts.dvtValidator / aggregator / manifestSafe not set");
else if (!wcfg) add("onchain", "MISSING", "needs the watcher config");
else if (C.aggregator.toLowerCase() !== String(wcfg.aggregator).toLowerCase())
  add(
    "onchain:binding",
    "FAIL",
    "contracts.aggregator is not the aggregator the watcher config watches"
  );
else if (C.dvtValidator.toLowerCase() !== String(wcfg.forwarders?.dvtValidator ?? "").toLowerCase())
  add(
    "onchain:binding",
    "FAIL",
    "contracts.dvtValidator is not the watcher config's forwarders.dvtValidator"
  );
else if (!primaryUrl) add("onchain", "MISSING", "needs the primary RPC");
else {
  add("onchain:binding", "PASS", "contracts.aggregator and dvtValidator equal the watcher config");
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
    } catch {
      add(id, "FAIL", "read failed");
    }
  };
  // the validator checked is the one the aggregator executes through (Codex R2 #5)
  await fact(
    "aggregator.DVT_VALIDATOR==dvtValidator",
    () => read(C.aggregator, "DVT_VALIDATOR()", "address"),
    v => v.toLowerCase() === C.dvtValidator.toLowerCase()
  );
  await fact(
    "sender!=SP.guardian",
    () => read(wcfg.roles.superPaymaster, "guardian()", "address"),
    v => !!senderAddr && v.toLowerCase() !== senderAddr.toLowerCase(),
    v => (senderAddr ? `SP.guardian() ${v}` : "sender address not verified yet")
  );
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
  if (!/^[0-9]+$/.test(String(sender.minBalanceWei ?? "")))
    add("sender-balance", "MISSING", "sender.minBalanceWei not set");
  else if (!senderAddr) add("sender-balance", "MISSING", "sender address not verified yet");
  else
    await fact(
      "sender-balance",
      () => p.getBalance(senderAddr),
      v => v >= BigInt(sender.minBalanceWei),
      v => `${ethers.formatEther(v)} ETH (min ${ethers.formatEther(BigInt(sender.minBalanceWei))})`
    );
}

// ---- 8. Release reports, bound to this release: the predicates are fixed here, not configurable
const relCommit = /^[0-9a-f]{40}$/.test(cfg.release?.spCommit ?? "") ? cfg.release.spCommit : null;
if (!relCommit) add("release:spCommit", "MISSING", "release.spCommit (the rc.8 commit) not set");
const ev = cfg.releaseEvidence ?? {};
const fixtureBlob = gitBlob(
  readFileSync(join(ROOT, "contracts/test/fixtures/evidence-vectors.json"), "utf8")
);
const rulesetBlob = gitBlob(readFileSync(join(W, "ruleset.json"), "utf8"));
const empty = x => Array.isArray(x) && x.length === 0;
const PREDICATES = {
  spParity: j =>
    j.schema === "aoa-sp-evidence-parity/2" &&
    j.entry === "contracts/src/modules/monitoring/DVTValidator.sol" &&
    Array.isArray(j.compiledInputs?.validatorAt) &&
    j.compiledInputs.validatorAt.length === 1 &&
    j.compiledInputs.validatorAt[0] === j.entry &&
    j.parity === "PASS" &&
    j.control === "FAILED (as required)" &&
    j.spCommit === relCommit &&
    j.fixture?.blob === fixtureBlob &&
    empty(j.compiledInputs?.unknown) &&
    empty(j.compiledInputs?.mismatched) &&
    empty(j.compiledInputs?.notCompiled),
  a3: j =>
    j.schema === "aoa-a3-emissions/2" &&
    j.inventoryChecked?.selectors > 0 &&
    Array.isArray(j.inventoryChecked?.required) &&
    j.inventoryChecked.required.includes("SuperPaymaster") &&
    j.spCommit === relCommit &&
    j.rulesetBlob === rulesetBlob &&
    empty(j.missingFunctions) &&
    empty(j.missingEvents) &&
    empty(j.restrictedOnPublicRoute),
};
for (const [name, pred] of Object.entries(PREDICATES)) {
  const p = expand(ev[name]);
  if (placeholder(ev[name])) add(`evidence:${name}`, "MISSING", `releaseEvidence.${name} not set`);
  else if (!existsSync(p)) add(`evidence:${name}`, "MISSING", "report not produced yet");
  else {
    let j = null;
    try {
      j = JSON.parse(readFileSync(p, "utf8"));
    } catch {
      j = null;
    }
    if (!j) add(`evidence:${name}`, "FAIL", "report unreadable");
    else if (!relCommit) add(`evidence:${name}`, "MISSING", "release.spCommit not set");
    else
      add(
        `evidence:${name}`,
        pred(j) ? "PASS" : "FAIL",
        pred(j)
          ? "passing, for this release, fixture and ruleset"
          : "not a passing report for this release, fixture and ruleset"
      );
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
