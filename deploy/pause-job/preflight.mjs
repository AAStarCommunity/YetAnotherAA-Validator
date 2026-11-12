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
import { readdirSync } from "node:fs";
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

/** launchd-off from `launchctl list` labels and each loaded job's ProgramArguments. Pure. */
export function launchdOff(labels, programOf) {
  const p = [];
  for (const f of FORBIDDEN_LABELS) if (labels.includes(f)) p.push(`${f} is loaded`);
  if (!labels.includes(PAUSE_LABEL)) p.push(`${PAUSE_LABEL} is not loaded`);
  for (const l of labels) {
    if (l === PAUSE_LABEL) continue;
    const args = programOf(l);
    if (args === null) {
      // Apple's XPC services are listed but not printable in the gui domain; anything else that
      // cannot be read fails closed
      if (!l.startsWith("com.apple.")) p.push(`${l}: its ProgramArguments cannot be read`);
      continue;
    }
    for (const s of SENDING_SCRIPTS)
      if (args.some(a => a.endsWith(`/${s}`) || a === s)) p.push(`${l} runs ${s}`);
  }
  return p;
}

/** node-slash-off from each container's environment (array of "K=V"). Pure. */
export function nodeSlashOff(envOf, nodes) {
  const p = [];
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
      if (prog) a.push(prog[1].trim());
      return a;
    };
    const p = launchdOff(labels, programOf);
    // the installed agents, read from their plists: a job named com.apple.* (skipped above when
    // unprintable) is still caught here by what it runs
    const dir = join(homedir(), "Library/LaunchAgents");
    let files = [];
    try {
      files = readdirSync(dir).filter(f => f.endsWith(".plist"));
    } catch {
      p.push("~/Library/LaunchAgents cannot be listed");
    }
    for (const f of files) {
      const j = run("plutil", ["-convert", "json", "-o", "-", join(dir, f)]);
      let d = null;
      try {
        d = j === null ? null : JSON.parse(j);
      } catch {
        d = null;
      }
      if (!d) {
        p.push(`${f}: cannot be read as a plist`);
        continue;
      }
      if (d.Label === PAUSE_LABEL || !labels.includes(d.Label)) continue;
      const a = [...(d.ProgramArguments ?? []), ...(d.Program ? [d.Program] : [])].map(String);
      for (const s of SENDING_SCRIPTS)
        if (a.some(x => x.endsWith(`/${s}`) || x === s)) p.push(`${d.Label} (${f}) runs ${s}`);
    }
    results.push(["launchd-off", p.length ? "FAIL" : "PASS", [...new Set(p)]]);
  }
  const envOf = n => {
    const out = run("docker", ["inspect", n, "--format", "{{json .Config.Env}}"]);
    try {
      return out === null ? null : JSON.parse(out);
    } catch {
      return null;
    }
  };
  const ns = nodeSlashOff(envOf, nodes);
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
