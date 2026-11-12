#!/usr/bin/env node
// Host preflight of the pause job on the Mac Mini (DSR 502ccd64, 4019916a condition 7). These are
// the three Phase D items that look at DVT's own host and containers, which SP's step-13 manifest
// gate cannot see. Until this PR merges they are manual launch-checklist items.
//
//   node deploy/pause-job/preflight.mjs [--nodes dvt-node-1,dvt-node-2,dvt-node-3]
//
// launchd-off   the committee keeper and apply-rotation are not loaded, the pause job IS loaded, and
//               no other loaded job of this user runs a DVT transaction-sending script (by its
//               ProgramArguments, not its label: a job's name is not what it runs)
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
import { join } from "node:path";

export const PAUSE_LABEL = "io.aastar.dvt-pause-job";
export const FORBIDDEN_LABELS = ["io.aastar.dvt-committee-keeper", "io.aastar.dvt-apply-rotation"];
// DVT scripts that send transactions; a loaded job running any of them (other than ours) fails
export const SENDING_SCRIPTS = [
  "committee-keeper.mjs",
  "apply-verifier-rotation.mjs",
  "reregister-guardians.mjs",
];

/**
 * Does a job's argument list run a DVT sending script? A name ANYWHERE in an argument counts
 * (`sh -c "node …/committee-keeper.mjs"`), and an argument that is a readable text file (a wrapper
 * script) is searched too; `readText(path)` returns its text, or null when it is not a file. A
 * wrapper that cannot be read is reported as unknown (fail closed). Pure given readText.
 */
export function runsSender(args, readText = () => ({ kind: "none" })) {
  const hits = new Set();
  for (const a of args) {
    for (const s of SENDING_SCRIPTS) if (a.includes(s)) hits.add(s);
    // ANY absolute path that is a text file is read as a possible wrapper, with or without an
    // extension (Codex R2 P2-5); binaries (Mach-O, ELF) and paths that are not files are skipped;
    // a file that exists but cannot be read is unknown (fail closed)
    if (a.startsWith("/")) {
      const t = readText(a);
      if (t.kind === "unreadable") hits.add(`<unreadable file ${a}>`);
      else if (t.kind === "text")
        for (const s of SENDING_SCRIPTS) if (t.text.includes(s)) hits.add(s);
    }
  }
  return [...hits];
}

/**
 * Why a loaded job does NOT match its reviewed entry (preflight-reviewed.json, DSR bc3be95b); an
 * empty list means it is the reviewed, non-sending job. Everything must match exactly:
 *   - the label, and a plist in ~/Library/LaunchAgents for it (the source of args and env);
 *   - the plist's FULL ProgramArguments: [interpreter, <repo>/<wrapper>, ...args] (no Program key);
 *   - the arguments launchd actually loaded equal the plist's;
 *   - the plist's environment variable NAMES exactly (bash runs $BASH_ENV, so nothing extra);
 *   - the sha256 of every file the mode runs, hashed at the paths the plist resolves (<repo>/<rel>).
 * Pure given shaOf.
 */
export function reviewProblems(r, plist, loadedArgs, shaOf) {
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
  if (!loadedArgs || loadedArgs.length !== pa.length || loadedArgs.some((a, i) => a !== pa[i]))
    p.push(`${r.label}: the arguments launchd loaded differ from the plist's`);
  const env = Object.keys(plist.EnvironmentVariables ?? {}).sort();
  if (env.join() !== [...r.envKeys].sort().join())
    p.push(`${r.label}: environment variable names are not exactly ${r.envKeys.join(", ")}`);
  if (repo)
    for (const [rel, sha] of Object.entries(r.files))
      if (shaOf(`${repo}/${rel}`) !== sha)
        p.push(`${r.label}: ${rel} does not hash to the reviewed sha256`);
  return p;
}

/**
 * launchd-off. `plists` maps a label to its LaunchAgents plist (parsed) or is missing it. Pure
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
  if (!labels.includes(PAUSE_LABEL)) p.push(`${PAUSE_LABEL} is not loaded`);
  const cleared = new Set();
  for (const r of reviewed) {
    if (FORBIDDEN_LABELS.includes(r.label) || r.label === PAUSE_LABEL) {
      p.push(`${r.label} cannot be a reviewed exception`);
      continue;
    }
    if (!labels.includes(r.label)) continue;
    const why = reviewProblems(r, plists[r.label], programOf(r.label), shaOf);
    if (why.length) p.push(...why);
    else cleared.add(r.label);
  }
  for (const l of labels) {
    if (l === PAUSE_LABEL || cleared.has(l)) continue;
    const args = programOf(l);
    if (args === null) {
      // Apple's XPC services are listed but not printable in the gui domain; anything else that
      // cannot be read fails closed (an installed agent is still read from its plist)
      if (!l.startsWith("com.apple.")) p.push(`${l}: its ProgramArguments cannot be read`);
    } else for (const s of runsSender(args, readText)) p.push(`${l} runs ${s}`);
    const d = plists[l];
    if (d) {
      const a = [...(d.ProgramArguments ?? []), ...(d.Program ? [d.Program] : [])].map(String);
      for (const s of runsSender(a, readText)) p.push(`${l} (plist) runs ${s}`);
    }
  }
  return [...new Set(p)];
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
  if (list === null) results.push(["launchd-off", "FAIL", ["launchctl list failed"]]);
  else {
    const labels = list
      .split("\n")
      .slice(1)
      .map(l => l.split("\t")[2])
      .filter(Boolean);
    const uid = process.getuid();
    const programOf = l => {
      const out = run("launchctl", ["print", `gui/${uid}/${l}`]);
      if (out === null) return null;
      const m = out.match(/arguments = \{([^}]*)\}/);
      const prog = out.match(/^\s*program = (.*)$/m);
      const a = m
        ? m[1]
            .split("\n")
            .map(s => s.trim())
            .filter(Boolean)
        : [];
      if (prog && a[0] !== prog[1].trim()) a.unshift(prog[1].trim());
      return a;
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
      if (!d || typeof d.Label !== "string") extra.push(`${f}: cannot be read as a plist`);
      else if (plists[d.Label]) extra.push(`${d.Label}: more than one plist`);
      else plists[d.Label] = d;
    }
    const p = [...extra, ...launchdOff(labels, programOf, readText, reviewed, shaOf, plists)];
    results.push(["launchd-off", p.length ? "FAIL" : "PASS", p]);
  }
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
