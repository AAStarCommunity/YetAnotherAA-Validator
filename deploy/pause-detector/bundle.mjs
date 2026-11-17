#!/usr/bin/env node
// Build the pause detector's BUNDLE: the only tree the detector may read code from (Codex R7 P1-1:
// a repository checkout may hold node_state.json, .env.sepolia or .keys/, so the detector is never
// granted one). Run on the Mini from a clean checkout at the reviewed commit:
//
//   node deploy/pause-detector/bundle.mjs --out ~/.aoa-pause-detector/app
//
// It copies exactly:
//   - every module the detector reaches from detector.mjs (the no-signing scan's own walk, so the
//     bundle and the scan cannot drift), and ../pause-job/sp-pin.json, which detect.mjs reads;
//   - the ethers package and its runtime dependency closure, each at the path Node resolves it to
//     in this checkout (type-only @types/* packages left out);
// and writes MANIFEST.json: { schema, commit, files: { path: sha256 } }. detector.mjs refuses to
// run unless the bundle is exactly that manifest. This tool is not part of the detector (it uses
// git) and is never in the bundle.
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  copyFileSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  writeFileSync,
} from "node:fs";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { scanTree } from "./no-signing-scan.mjs";
import { MANIFEST } from "./lib/guard.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, "../..");
const die = m => {
  console.error(`bundle: ${m}`);
  process.exit(1);
};
const args = process.argv.slice(2);
const oi = args.indexOf("--out");
const out = oi >= 0 ? resolve(args[oi + 1] ?? "") : null;
if (!out) die("usage: bundle.mjs --out <new directory> [--allow-dirty]");
if (existsSync(out)) die("the output exists; a bundle is written once, into a new directory");

// 1. the detector's own modules, by the scan's walk; the scan must be clean
const seen = new Set();
// both entries: the detector and its dead-man check
const problems = [
  ...scanTree(join(HERE, "detector.mjs"), undefined, seen),
  ...scanTree(join(HERE, "deadman.mjs"), undefined, seen),
];
if (problems.length) die(`the no-signing scan fails: ${problems.slice(0, 3).join("; ")}`);
const own = [...seen].map(f => relative(REPO, f));
own.push("deploy/pause-job/sp-pin.json");
for (const f of own)
  if (f.startsWith("..") || !lstatSync(join(REPO, f)).isFile())
    die(`${f} is not a file of the repo`);

const commit = execFileSync("git", ["-C", REPO, "rev-parse", "HEAD"], { encoding: "utf8" }).trim();
const dirty = execFileSync("git", ["-C", REPO, "status", "--porcelain", "--", ...own], {
  encoding: "utf8",
}).trim();
if (dirty && !args.includes("--allow-dirty"))
  die(`the detector's files differ from ${commit}: commit them, or bundle from a clean checkout`);

// 2. ethers and its runtime dependency closure, each where Node resolves it from its dependent
const resolvePkg = (name, fromDir) => {
  for (let d = fromDir; d.startsWith(REPO); d = dirname(d)) {
    const c = join(d, "node_modules", ...name.split("/"));
    if (existsSync(join(c, "package.json"))) return c;
    if (d === REPO) break;
  }
  return die(`${name} cannot be resolved from ${relative(REPO, fromDir) || "."}`);
};
// every bundled package must be exactly what package-lock.json describes at that path (Daybreak H5b,
// DSR 2026-11-17): a node_modules that is stale or was not installed with `npm ci` is refused
let lock;
try {
  lock = JSON.parse(readFileSync(join(REPO, "package-lock.json"), "utf8"));
} catch {
  die("package-lock.json cannot be read");
}
if (lock?.lockfileVersion < 2 || !lock?.packages)
  die("package-lock.json has no packages map (lockfile v2+)");
const pkgs = new Set();
const visit = dir => {
  if (pkgs.has(dir)) return;
  pkgs.add(dir);
  const pj = JSON.parse(readFileSync(join(dir, "package.json"), "utf8"));
  const key = relative(REPO, dir).split(sep).join("/");
  const locked = lock.packages[key];
  if (!locked) die(`${key} is not in package-lock.json: install with npm ci`);
  if (locked.version !== pj.version)
    die(`${key} is ${pj.version}, package-lock.json says ${locked.version}: install with npm ci`);
  if (typeof locked.integrity !== "string" || !locked.integrity)
    die(`${key} has no integrity in package-lock.json`);
  for (const dep of Object.keys(pj.dependencies ?? {})) {
    if (dep.startsWith("@types/")) continue; // type declarations only, nothing to run
    visit(resolvePkg(dep, dir));
  }
};
visit(resolvePkg("ethers", REPO));

// 3. the file list: our modules, and every file of each package (not its nested node_modules,
//    which the closure covers package by package). A symlink anywhere is refused.
const files = new Set(own);
const listPkg = dir => {
  const stack = [dir];
  while (stack.length) {
    const d = stack.pop();
    const st = lstatSync(d);
    if (st.isSymbolicLink()) die(`${relative(REPO, d)} is a symlink; a bundle holds none`);
    if (st.isDirectory()) {
      for (const n of readdirSync(d))
        if (!(d === dir && n === "node_modules")) stack.push(join(d, n));
    } else if (st.isFile()) files.add(relative(REPO, d));
  }
};
for (const p of pkgs) listPkg(p);

// 4. copy and write the manifest
mkdirSync(out, { recursive: true, mode: 0o755 });
// files that differ from `commit` (allowed only with --allow-dirty, for tests) are recorded: the
// detector and preflight refuse such a bundle, so it can never pass as built from `commit`
// (Daybreak H4, DSR 2026-11-17)
const manifest = {
  schema: "aoa-pause-detector-bundle/1",
  commit,
  ...(dirty ? { dirty: true } : {}),
  files: {},
};
for (const f of [...files].sort()) {
  const to = join(out, f);
  mkdirSync(dirname(to), { recursive: true, mode: 0o755 });
  copyFileSync(join(REPO, f), to);
  const key = f.split(sep).join("/");
  manifest.files[key] = createHash("sha256").update(readFileSync(to)).digest("hex");
}
const manifestText = `${JSON.stringify(manifest, null, 2)}\n`;
writeFileSync(join(out, MANIFEST), manifestText, { mode: 0o644 });
// the detector's identity, for the deploy log and SP's step-13 manifest (DSR): the manifest's
// sha256 and the source commit
const manifestSha = createHash("sha256").update(manifestText).digest("hex");
console.log(
  `bundle: ${Object.keys(manifest.files).length} files (${own.length} detector, ${pkgs.size} packages) -> ${out}`
);
console.log(
  `bundle: source commit ${commit}${dirty ? " (DIRTY: a test bundle, refused at runtime)" : ""}`
);
console.log(`bundle: MANIFEST.json sha256 ${manifestSha}`);
