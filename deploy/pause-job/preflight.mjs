#!/usr/bin/env node
// Host preflight of the pause job on the Mac Mini (DSR 502ccd64, 4019916a condition 7). These are
// the three Phase D items that look at DVT's own host and containers, which SP's step-13 manifest
// gate cannot see. Until this PR merges they are manual launch-checklist items.
//
//   node deploy/pause-job/preflight.mjs [--nodes dvt-node-1,dvt-node-2,dvt-node-3]
//                                       [--detector-status <path to the detector's status.json>]
//
// launchd-on    (rc.8, DSR: "detect, then act by hand") the read-only pause detector and the price
//               keeper ARE loaded; the committee keeper, apply-rotation and the retired D2 pause job
//               are NOT; and no other loaded job of this user runs a DVT transaction-sending script
//               (by its ProgramArguments, not its label: a job's name is not what it runs). The
//               price keeper is the one approved sender and is not scanned; the detector is.
// detector-args the loaded detector runs the pinned node under --permission, exactly as its plist
// detector-bundle ~/.aoa-pause-detector/app is exactly its manifest; no symlink under the directory
// pause-detector its last round's status.json is fresh (at most two intervals old): the trigger
//               fired, not just the job loaded
// node-slash-off every DVT node container has AUDIT_ENABLED and AUDIT_EXECUTE_SLASH absent or exactly
//               "false" (the node arms only on exactly "true", src/config/configuration.ts:206/265;
//               anything else is refused here, fail closed)
// spParity      MANUAL: SP's DVTValidator is not on SP main yet (DSR 48be82a3); check:sp-parity is
//               run by hand against the pinned SP commit and recorded on the launch checklist
// Exit 0 only when no item FAILs. MANUAL items never count as PASS.
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { closeSync, openSync, readdirSync, readFileSync, readSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { join, posix } from "node:path";
import {
  DIR as DETECTOR_DIR,
  ENV_OK as DETECTOR_ENV_OK,
  bundleProblems as detectorBundle,
  symlinkProblems as detectorSymlinks,
} from "../pause-detector/lib/guard.mjs";

export const DETECTOR_LABEL = "io.aastar.dvt-pause-detector";
export const KEEPER_LABEL = "io.aastar.price-keeper";
export const REQUIRED_LABELS = [DETECTOR_LABEL, KEEPER_LABEL];
export const FORBIDDEN_LABELS = [
  "io.aastar.dvt-committee-keeper",
  "io.aastar.dvt-apply-rotation",
  // the D2 pause job is retired (DSR fae09c1e): its signer was refunded and deleted
  "io.aastar.dvt-pause-job",
];
// DVT scripts that send transactions; a loaded job running any of them (other than ours) fails
export const SENDING_SCRIPTS = [
  "committee-keeper.mjs",
  "pause-job.mjs",
  "apply-verifier-rotation.mjs",
  "reregister-guardians.mjs",
  "register-node.mjs",
  "x402-register-operators.sh",
  "x402-provision.sh",
];

// paths a script may execute: tokens that look like a script file, absolute, relative with a
// directory, or bare (`bash inner.sh`, Codex R4 P2-1)
const SCRIPT_TOKEN =
  /(?:^|[\s"'=(;|&`])((?:\.{1,2}\/|\/)?[A-Za-z0-9_./-]*[A-Za-z0-9_-]\.(?:sh|bash|zsh|command|mjs|cjs|js|ts|py))(?=$|[\s"');|&`])/gm;
const JS_FILE = /\.(mjs|cjs|js|ts)$/;
// any absolute path in a script, with or without an extension (clestons L4): followed when it is
// a text file; binaries and non-files are skipped by readText
const REL_TOKEN =
  /(?:^|[\s"'=(;|&`])((?:\.{1,2}\/|[A-Za-z0-9_-]+\/)[A-Za-z0-9_./-]*[A-Za-z0-9_-])(?=$|[\s"');|&`])/gm;
// an interpreter (bare or by absolute path) or exec/source, then flags, then a script name,
// possibly quoted (Codex R8 P2)
const INTERPRETER = "(?:\\/[A-Za-z0-9_./-]*\\/)?(?:bash|sh|zsh|dash|ksh|node|python3?)";
const INTERP_TOKEN = new RegExp(
  `(?:^|[\\s;|&(\`])(?:${INTERPRETER}|exec|source|\\.)\\s+(?:-[A-Za-z]+\\s+)*["']?([A-Za-z0-9_][A-Za-z0-9_.-]*)["']?(?=$|[\\s"');|&\`])`,
  "gm"
);
const INTERPRETER_ARG = new RegExp(`^${INTERPRETER}$`);
const ABS_TOKEN = /(?:^|[\s"'=(;|&`])(\/[A-Za-z0-9_./-]+)(?=$|[\s"');|&`])/gm;

/**
 * The text of a script with only ITS language's whole-line comments removed (Codex R4 P2-2): a
 * shell script keeps `/*` and `*\/` (globs such as `ls /tmp/*`), only `#` lines go; a JS file
 * loses `//` lines and block comments. An extensionless file is JS only with a node shebang.
 * Pure.
 */
export function codeOf(path, text) {
  const js = JS_FILE.test(path) || /^#!.*\bnode\b/.test(text);
  const t = js ? text.replace(/\/\*[\s\S]*?\*\//g, " ") : text;
  const comment = js ? /^\s*\/\// : /^\s*#(?!!)/;
  return t
    .split("\n")
    .filter(l => !comment.test(l))
    .join("\n");
}

/**
 * Does a job run a DVT sending script? A sending script's name ANYWHERE in an argument counts
 * (`sh -c "node …/committee-keeper.mjs"`). Every script path in an argument, absolute, relative to
 * the job's working directory, or inside a command string (`sh -c "exec /repo/inner.sh"`), is read
 * when it is text (binaries by magic are skipped), and the scripts it references are followed in
 * turn, relative to the working directory and to the referring file, up to `depth` levels. A file
 * that exists but cannot be read is unknown (fail closed). Paths built at run time ($VAR) cannot be
 * followed: a residual stated in the README. Pure given readText.
 */
export function runsSender(args, readText = () => ({ kind: "none" }), cwd = null, depth = 4) {
  const hits = new Set();
  const seen = new Set();
  const resolve = (x, base) =>
    x.startsWith("/") ? x : base ? posix.normalize(`${base}/${x}`) : null;
  const follow = (text, level, dir) => {
    for (const m of text.matchAll(SCRIPT_TOKEN)) {
      visit(resolve(m[1], cwd), level);
      if (dir) visit(resolve(m[1], dir), level);
    }
    for (const m of text.matchAll(ABS_TOKEN)) visit(m[1], level);
    // relative paths without an extension (`exec ./bin/run-keeper`), against the working
    // directory and the referring file (Codex R6 P2)
    // a bare script after an interpreter or `exec`/`source` (`bash inner`, Codex R7 P2)
    for (const m of text.matchAll(INTERP_TOKEN)) {
      visit(resolve(m[1], cwd), level);
      if (dir) visit(resolve(m[1], dir), level);
    }
    for (const m of text.matchAll(REL_TOKEN)) {
      visit(resolve(m[1], cwd), level);
      if (dir) visit(resolve(m[1], dir), level);
    }
  };
  const visit = (path, level) => {
    if (!path || seen.has(path)) return;
    // a wrapper chain deeper than we follow is not certified clean (Codex R7 P2)
    if (level > depth) {
      // readable or not, a file there is not certified (Codex R8 P2)
      if (readText(path).kind !== "none") hits.add(`<not followed past depth ${depth}: ${path}>`);
      return;
    }
    seen.add(path);
    const t = readText(path);
    if (t.kind === "unreadable") hits.add(`<unreadable file ${path}>`);
    if (t.kind !== "text") return;
    const code = codeOf(path, t.text);
    for (const s of SENDING_SCRIPTS) if (code.includes(s)) hits.add(s);
    follow(code, level + 1, posix.dirname(path));
  };
  // argv itself: [interpreter, flags..., script, ...]: the script may be a bare, extensionless name
  // resolved against the working directory (`["/bin/bash", "inner"]`, Codex R8 P2)
  if (args.length > 1 && INTERPRETER_ARG.test(args[0])) {
    const script = args.slice(1).find(a => !a.startsWith("-"));
    if (script && !script.startsWith("/") && !/\s/.test(script)) visit(resolve(script, cwd), 0);
  }
  for (const a of args) {
    for (const s of SENDING_SCRIPTS) if (a.includes(s)) hits.add(s);
    if (a.startsWith("/")) visit(a, 0);
    else if (cwd && /[/.]/.test(a) && !a.startsWith("-") && !/\s/.test(a))
      visit(resolve(a, cwd), 0);
    // a command string (`-c "…"`) or any argument naming scripts: follow what it names
    follow(a, 0, null);
  }
  return [...hits];
}

/** { args, env, inherited, cwd } from `launchctl print` output; env is null when absent. Pure. */
export function parseLaunchctlPrint(out) {
  const m = out.match(/arguments = \{([^}]*)\}/);
  const prog = out.match(/^\s*program = (.*)$/m);
  const a = m
    ? m[1]
        .split("\n")
        .map(x => x.trim())
        .filter(Boolean)
    : [];
  if (prog && a[0] !== prog[1].trim()) a.unshift(prog[1].trim());
  const block = name => {
    const b = out.match(new RegExp(`^\\t${name} = \\{\\n([\\s\\S]*?)^\\t\\}`, "m"));
    return b ? [...b[1].matchAll(/^\t\t([^\s=]+) =>/gm)].map(x => x[1]) : null;
  };
  const cwd = out.match(/^\s*working directory = (.*)$/m);
  return {
    args: a,
    env: block("environment"),
    inherited: block("inherited environment") ?? [],
    cwd: cwd ? cwd[1].trim() : null,
  };
}

// launchd adds these to every job's environment; they are not the job's configuration
const LAUNCHD_ENV = new Set(["OSLogRateLimit", "XPC_SERVICE_NAME"]);
// variables bash or sh read to run code before the script (fail closed if inherited)
// and the runtime-injection variables of node and the dynamic loader (clestons L4)
const STARTUP_ENV =
  /^(BASH_ENV|ENV|BASH_FUNC_.*|SHELLOPTS|BASHOPTS|PS4|NODE_OPTIONS|NODE_PATH|DYLD_.*)$/;

/**
 * Why a loaded job does NOT match its reviewed entry (preflight-reviewed.json, DSR bc3be95b); an
 * empty list means it is the reviewed, non-sending job. Everything must match exactly:
 *   - the label, and a plist in ~/Library/LaunchAgents for it;
 *   - the plist's FULL ProgramArguments: [interpreter, <repo>/<wrapper>, ...args] (no Program key);
 *   - what launchd LOADED: the same arguments, and the same environment variable names (minus the
 *     two launchd adds), with no shell start-up variable inherited (Codex R3 P2-2: a stale loaded
 *     BASH_ENV is caught even when the plist on disk no longer has it);
 *   - the plist's environment variable NAMES exactly;
 *   - the sha256 of every file the mode runs, hashed at the paths the plist resolves (<repo>/<rel>).
 * `loaded` is { args, env, inherited } from launchctl print. Pure given shaOf.
 */
export function reviewProblems(r, plist, loaded, shaOf) {
  const p = [];
  if (!plist) return [`${r.label}: no plist for the reviewed job in ~/Library/LaunchAgents`];
  if (plist.Label !== r.label) p.push(`${r.label}: plist label differs`);
  if (plist.Program !== undefined) p.push(`${r.label}: plist has a Program key`);
  const pa = (plist.ProgramArguments ?? []).map(String);
  const repoPath = pa[1] ?? "";
  const repo = repoPath.endsWith(`/${r.wrapper}`)
    ? repoPath.slice(0, -(r.wrapper.length + 1))
    : null;
  if (
    pa.length !== r.args.length + 2 ||
    pa[0] !== r.interpreter ||
    !repo ||
    !repo.startsWith("/") ||
    repo.includes("/../") ||
    pa.slice(2).some((a, i) => a !== r.args[i])
  )
    p.push(
      `${r.label}: ProgramArguments are not exactly [${r.interpreter}, <repo>/${r.wrapper}, ${r.args.join(", ")}]`
    );
  const want = [...r.envKeys].sort().join();
  const la = loaded?.args;
  if (!la || la.length !== pa.length || la.some((a, i) => a !== pa[i]))
    p.push(`${r.label}: the arguments launchd loaded differ from the plist's`);
  if (!loaded?.env || !loaded?.inherited)
    p.push(`${r.label}: the loaded environment cannot be read`);
  else {
    const le = loaded.env
      .filter(n => !LAUNCHD_ENV.has(n))
      .sort()
      .join();
    if (le !== want)
      p.push(
        `${r.label}: the LOADED environment variable names are not exactly ${r.envKeys.join(", ")}`
      );
    const bad = [...loaded.env, ...loaded.inherited].filter(n => STARTUP_ENV.test(n));
    if (bad.length)
      p.push(
        `${r.label}: a shell start-up variable is in the loaded environment (${bad.join(", ")})`
      );
  }
  const env = Object.keys(plist.EnvironmentVariables ?? {}).sort();
  if (env.join() !== want)
    p.push(`${r.label}: environment variable names are not exactly ${r.envKeys.join(", ")}`);
  if (repo)
    for (const [rel, sha] of Object.entries(r.files))
      if (shaOf(`${repo}/${rel}`) !== sha)
        p.push(`${r.label}: ${rel} does not hash to the reviewed sha256`);
  return p;
}

// programOf may return an argument array (tests) or { args, env, inherited, cwd } (launchctl)
const asLoaded = x => (x === null || x === undefined ? null : Array.isArray(x) ? { args: x } : x);

/**
 * launchd-on. `plists` maps a label to its LaunchAgents plist (parsed) or is missing it. Pure
 * given the injected readers.
 */
export function launchdOff(
  labels,
  programOf,
  readText = () => ({ kind: "none" }),
  reviewed = [],
  shaOf = () => null,
  plists = {}
) {
  const p = [];
  for (const f of FORBIDDEN_LABELS) if (labels.includes(f)) p.push(`${f} is loaded`);
  for (const q of REQUIRED_LABELS) if (!labels.includes(q)) p.push(`${q} is not loaded`);
  const cleared = new Set();
  for (const r of reviewed) {
    if (FORBIDDEN_LABELS.includes(r.label) || REQUIRED_LABELS.includes(r.label)) {
      p.push(`${r.label} cannot be a reviewed exception`);
      continue;
    }
    if (!labels.includes(r.label)) continue;
    const why = reviewProblems(r, plists[r.label], asLoaded(programOf(r.label)), shaOf);
    if (why.length) p.push(...why);
    else cleared.add(r.label);
  }
  for (const l of labels) {
    if (l === KEEPER_LABEL || cleared.has(l)) continue;
    const loaded = asLoaded(programOf(l));
    const args = loaded?.args ?? null;
    if (args === null) {
      // Apple's XPC services are listed but not printable in the gui domain; anything else that
      // cannot be read fails closed (an installed agent is still read from its plist)
      if (!l.startsWith("com.apple.")) p.push(`${l}: its ProgramArguments cannot be read`);
    } else for (const s of runsSender(args, readText, loaded.cwd ?? null)) p.push(`${l} runs ${s}`);
    const d = plists[l];
    if (d) {
      const a = [...(d.ProgramArguments ?? []), ...(d.Program ? [d.Program] : [])].map(String);
      for (const s of runsSender(a, readText, d.WorkingDirectory ?? null))
        p.push(`${l} (plist) runs ${s}`);
    }
  }
  return [...new Set(p)];
}

/** The pinned node the detector runs under (the dedicated install, not Homebrew's). */
export const DETECTOR_NODE = ".local/keeper-node/node-v24.21.0/bin/node";

/**
 * detector-args: the LOADED detector job runs exactly
 *   [<home>/<DETECTOR_NODE>, --permission, --allow-fs-read=<repo>,
 *    --allow-fs-read=<home>/.aoa-pause-detector, --allow-fs-write=<home>/.aoa-pause-detector/state,
 *    <repo>/deploy/pause-detector/detector.mjs, --config, <home>/.aoa-pause-detector/config.json]
 * so it is under the permission model with nothing more allowed (no --allow-child-process, no
 * wider read or write). `args` is what launchd loaded (null when unreadable). Pure.
 */
export function detectorArgsProblems(args, home, env = [], inherited = []) {
  if (!Array.isArray(args)) return ["the detector's loaded arguments cannot be read"];
  // NODE_OPTIONS=--allow-fs-read=<key> would widen the grants with the arguments unchanged
  // (Codex R4 P1-1): no option-injecting variable, set or inherited
  const inj = [...(env ?? []), ...(inherited ?? [])].filter(
    n => STARTUP_ENV.test(n) || /^NODE_/.test(n)
  );
  if (inj.length)
    return [`the detector's environment has option-injecting variables: ${inj.join(", ")}`];
  // the same allowlist the detector enforces at startup (Codex R8 P1-2)
  const extra = [...(env ?? []), ...(inherited ?? [])].filter(n => !DETECTOR_ENV_OK.has(n));
  if (extra.length)
    return [`the detector's environment has variables outside the allowlist: ${extra.join(", ")}`];
  if (env === null) return ["the detector's loaded environment cannot be read"];
  const d = `${home}/.aoa-pause-detector`;
  // the bundle, never a repository checkout (which may hold keys; Codex R7 P1-1)
  const want = [
    `${home}/${DETECTOR_NODE}`,
    "--permission",
    `--allow-fs-read=${d}`,
    `--allow-fs-write=${d}/state`,
    `${d}/app/deploy/pause-detector/detector.mjs`,
    "--config",
    `${d}/config.json`,
  ];
  if (args.join("\n") !== want.join("\n"))
    return [
      "the detector does not run exactly as its plist: the pinned node, --permission, reads of ~/.aoa-pause-detector only, writes of its state only, from its bundle",
    ];
  return [];
}

/** detector-bundle: no symlink under ~/.aoa-pause-detector, and the bundle exactly its manifest. */
export function detectorBundleItem(home) {
  const dd = join(home, DETECTOR_DIR);
  return [...detectorSymlinks(dd), ...detectorBundle(join(dd, "app"))];
}

/**
 * pause-detector: the detector's last status.json (`text`, or null when missing) is fresh: written
 * at most `maxAgeMs` before `now`, by the detector. Returns { problems, note }. Pure.
 */
export function detectorFresh(text, now, maxAgeMs = 2 * 3600_000 + 600_000) {
  if (text === null) return { problems: ["the detector has written no status.json"], note: "" };
  let j;
  try {
    j = JSON.parse(text);
  } catch {
    return { problems: ["the detector's status.json is not JSON"], note: "" };
  }
  if (j?.schema !== "aoa-pause-detector-status/1")
    return { problems: ["status.json is not the detector's"], note: "" };
  const at = Date.parse(j.at);
  if (!Number.isFinite(at)) return { problems: ["status.json has no time"], note: "" };
  if (now - at > maxAgeMs)
    return {
      problems: [`the detector's last round is ${Math.round((now - at) / 60_000)} min old`],
      note: "",
    };
  // written on this host by this host's clock: any time after now is a rolled-back clock or a
  // forged file, never fresh (Codex R1 P1-6)
  if (at > now) return { problems: ["status.json is dated in the future"], note: "" };
  // a fresh file is not a healthy detector (clestons #434 F2, B1): a run that failed at startup,
  // alerts that never reached Telegram, and a "clear" read on an old head all FAIL
  if (typeof j.startup === "string")
    return { problems: [`the detector's last run failed at startup: ${j.startup}`], note: "" };
  const n = Array.isArray(j.alerts) ? j.alerts.length : 0;
  if (n > 0 && j.delivery?.ok !== true)
    return { problems: [`the last round's ${n} alert(s) were not delivered`], note: "" };
  if (j.clear === true) {
    const ts = Number(j.report?.block?.timestamp);
    if (!Number.isSafeInteger(ts) || now - ts * 1000 > maxAgeMs)
      return {
        problems: ["the last round reads clear on a head that is old or undated"],
        note: "",
      };
  }
  return {
    problems: [],
    note: j.clear === true ? "last round clear" : `last round NOT clear (${n} alert(s))`,
  };
}

/** node-slash-off from each container's environment (array of "K=V"). Pure. */
export function nodeSlashOff(envOf, nodes, running = null) {
  const p = [];
  if (!nodes.length) p.push("no DVT node containers given");
  // every running DVT node container must be in the inventory checked here
  if (running)
    for (const r of running)
      if (/^dvt-node-/.test(r) && !nodes.includes(r)) p.push(`${r} is running but not checked`);
  for (const n of nodes) {
    const env = envOf(n);
    if (env === null) {
      p.push(`${n}: not found or not inspectable`);
      continue;
    }
    for (const k of ["AUDIT_ENABLED", "AUDIT_EXECUTE_SLASH"]) {
      const hits = env.filter(e => e.startsWith(`${k}=`));
      if (hits.length > 1) p.push(`${n}: ${k} set more than once`);
      const v = hits.length ? hits[hits.length - 1].slice(k.length + 1) : null;
      if (v !== null && v !== "false") p.push(`${n}: ${k} is not "false"`);
    }
  }
  return p;
}

const BINARY_MAGIC = [
  "cffaedfe",
  "cefaedfe",
  "feedfacf",
  "feedface",
  "cafebabe",
  "bebafeca",
  "7f454c46",
];
const readText = path => {
  let st;
  try {
    st = statSync(path);
  } catch (e) {
    return { kind: e?.code === "ENOENT" || e?.code === "ENOTDIR" ? "none" : "unreadable" };
  }
  if (!st.isFile()) return { kind: "none" };
  // the magic first: a binary of any size is a binary; only a large TEXT file is unknown
  let fd;
  try {
    fd = openSync(path, "r");
    const head = Buffer.alloc(4);
    readSync(fd, head, 0, 4, 0);
    if (BINARY_MAGIC.includes(head.toString("hex"))) return { kind: "binary" };
    if (st.size > 4 << 20) return { kind: "unreadable" };
    return { kind: "text", text: readFileSync(path, "utf8") };
  } catch {
    return { kind: "unreadable" };
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
};
const run = (cmd, a) => {
  try {
    return execFileSync(cmd, a, { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] });
  } catch {
    return null;
  }
};

if (import.meta.url === `file://${process.argv[1]}`) {
  const argv = process.argv.slice(2);
  const i = argv.indexOf("--nodes");
  const nodes = (i >= 0 ? argv[i + 1] : "dvt-node-1,dvt-node-2,dvt-node-3")
    .split(",")
    .filter(Boolean);
  const results = [];
  const list = run("launchctl", ["list"]);
  if (list === null) results.push(["launchd-on", "FAIL", ["launchctl list failed"]]);
  else {
    const labels = list
      .split("\n")
      .slice(1)
      .map(l => l.split("\t")[2])
      .filter(Boolean);
    const uid = process.getuid();
    const programOf = l => {
      const out = run("launchctl", ["print", `gui/${uid}/${l}`]);
      return out === null ? null : parseLaunchctlPrint(out);
    };
    const reviewed = JSON.parse(
      readFileSync(new URL("./preflight-reviewed.json", import.meta.url), "utf8")
    ).jobs;
    const shaOf = path => {
      try {
        return createHash("sha256").update(readFileSync(path)).digest("hex");
      } catch {
        return null;
      }
    };
    // the installed agents, read from their plists: a job named com.apple.* (unprintable above)
    // is still caught by what its plist runs
    const dir = join(homedir(), "Library/LaunchAgents");
    const plists = {};
    const extra = [];
    let files = [];
    try {
      files = readdirSync(dir).filter(f => f.endsWith(".plist"));
    } catch {
      extra.push("~/Library/LaunchAgents cannot be listed");
    }
    for (const f of files) {
      const j = run("plutil", ["-convert", "json", "-o", "-", join(dir, f)]);
      let d = null;
      try {
        d = j === null ? null : JSON.parse(j);
      } catch {
        d = null;
      }
      // an emptied plist with no Label cannot be loaded by launchd: nothing to check (clestons L4)
      if (d && d.Label === undefined && !d.ProgramArguments && !d.Program) continue;
      if (!d || typeof d.Label !== "string") extra.push(`${f}: cannot be read as a plist`);
      else if (plists[d.Label]) extra.push(`${d.Label}: more than one plist`);
      else plists[d.Label] = d;
    }
    const p = [...extra, ...launchdOff(labels, programOf, readText, reviewed, shaOf, plists)];
    results.push(["launchd-on", p.length ? "FAIL" : "PASS", p]);
    const dl = programOf(DETECTOR_LABEL);
    const da = detectorArgsProblems(
      dl?.args ?? null,
      homedir(),
      dl?.env ?? null,
      dl?.inherited ?? []
    );
    results.push(["detector-args", da.length ? "FAIL" : "PASS", da]);
    // the bundle is exactly its manifest and nothing under ~/.aoa-pause-detector is a symlink:
    // checked here from outside the permission model too, so the entry file itself is covered
    const db = detectorBundleItem(homedir());
    results.push(["detector-bundle", db.length ? "FAIL" : "PASS", db.slice(0, 5)]);
  }
  const di = argv.indexOf("--detector-status");
  const statusPath =
    di >= 0 ? argv[di + 1] : join(homedir(), ".aoa-pause-detector/state/status.json");
  let statusText = null;
  try {
    statusText = readFileSync(statusPath, "utf8");
  } catch {
    statusText = null;
  }
  const fr = detectorFresh(statusText, Date.now());
  results.push([
    "pause-detector",
    fr.problems.length ? "FAIL" : "PASS",
    fr.problems.length ? fr.problems : [fr.note],
  ]);
  const envOf = n => {
    const out = run("docker", ["inspect", n, "--format", "{{json .Config.Env}}"]);
    try {
      return out === null ? null : JSON.parse(out);
    } catch {
      return null;
    }
  };
  const ps = run("docker", ["ps", "--format", "{{.Names}}"]);
  const ns =
    ps === null ? ["docker ps failed"] : nodeSlashOff(envOf, nodes, ps.split("\n").filter(Boolean));
  results.push(["node-slash-off", ns.length ? "FAIL" : "PASS", ns]);
  results.push([
    "spParity",
    "MANUAL",
    ["run check:sp-parity against the pinned SP commit; record it on the launch checklist"],
  ]);
  for (const [k, v, why] of results)
    console.log(`${v.padEnd(6)} ${k}${why.length ? `: ${why.join("; ")}` : ""}`);
  process.exit(results.some(r => r[1] === "FAIL") ? 1 : 0);
}
