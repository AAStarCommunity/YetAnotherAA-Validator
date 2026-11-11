#!/usr/bin/env node
// Standing check (DSR 8c5f68e5): run SuperPaymaster's own DVTValidator._checkEvidence against this
// repo's M0 §3.1 vectors (contracts/test/fixtures/evidence-vectors.json), byte for byte.
//
//   node scripts/disclosure/sp-evidence-parity.mjs <SP commit SHA> [--repo owner/name] [--out empty-dir]
//
// Everything is read through the GitHub API (gh), at that exact commit, never from a local checkout
// of SP. DVTValidator.sol and its whole import closure are resolved with SP's own foundry.toml
// remappings (OpenZeppelin included: SP vendors it under singleton-paymaster/lib), so the compiled
// code is SP's, not a stand-in. A fresh scratch Foundry project then:
//   1. builds a harness that inherits DVTValidator unchanged and only exposes _checkEvidence,
//      registering the vectors' categories with an always-accept checker (the encoding is under
//      test, not a category's check);
//   2. proves what was compiled: every source in the compiler input is either a fetched SP file whose
//      content has that file's git blob SHA, forge-std, or the harness; anything else fails;
//   3. asserts, for every vector, SP's TAG_EVIDENCE, its decode of our evidence blob, and that its
//      evidenceHash equals ours (read from forge's JSON results, with the vector count logged);
//   4. reruns with one vector's evidenceHash altered: the same test must FAIL, on the evidenceHash
//      assertion (a control, so a pass is never vacuous).
// Exit 0 only if 2 and 3 pass and 4 fails as required; 1 on a parity or control failure; 3 on an
// infrastructure failure (fetch, compile, forge itself). The report (stdout, JSON) records the SP
// commit, solc, every fetched file's blob SHA (foundry.toml included) and the fixture's blob SHA.
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  mkdirSync,
  mkdtempSync,
  writeFileSync,
  readFileSync,
  existsSync,
  readdirSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname, posix, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..", "..");
const ENTRY = "contracts/src/modules/monitoring/DVTValidator.sol";
const TEST = "parity/SpEvidenceParity.t.sol";
const TEST_KEY = `${TEST}:SpEvidenceParityTest`;
const TEST_FN = "test_spDvtValidatorMatchesDvtVectors()";

const args = process.argv.slice(2);
const sha = args[0];
const opt = k => {
  const i = args.indexOf(`--${k}`);
  return i > 0 ? args[i + 1] : undefined;
};
const repo = opt("repo") ?? "AAStarCommunity/SuperPaymaster";
const infra = msg => {
  console.error(`infrastructure failure: ${msg}`);
  process.exit(3);
};
if (!/^[0-9a-f]{40}$/.test(sha ?? "")) {
  console.error(
    "usage: sp-evidence-parity.mjs <full 40-hex SP commit SHA> [--repo owner/name] [--out empty-dir]"
  );
  process.exit(2);
}
const forge = existsSync(join(process.env.HOME ?? "", ".foundry/bin/forge"))
  ? join(process.env.HOME, ".foundry/bin/forge")
  : "forge";

/** git's blob id of a text: sha1("blob <bytes>\0" + content). */
const gitBlob = text => {
  const b = Buffer.from(text, "utf8");
  return createHash("sha1")
    .update(Buffer.concat([Buffer.from(`blob ${b.length}\0`), b]))
    .digest("hex");
};

/** A file of `repo` at `sha` through the contents API: { text, sha } (git blob SHA, checked). */
function fetchFile(path) {
  let out;
  try {
    out = execFileSync("gh", ["api", `repos/${repo}/contents/${path}?ref=${sha}`], {
      encoding: "utf8",
      maxBuffer: 64 << 20,
    });
  } catch {
    infra(`gh api could not fetch ${path} at ${sha}`);
  }
  const j = JSON.parse(out);
  if (j.type !== "file" || j.encoding !== "base64") infra(`${path}: not a plain file at ${sha}`);
  const text = Buffer.from(j.content, "base64").toString("utf8");
  if (gitBlob(text) !== j.sha) infra(`${path}: fetched content does not hash to its blob ${j.sha}`);
  return { text, sha: j.sha };
}

/** SP's [profile.default] remappings and compiler settings, from its foundry.toml at `sha`. Only the
 * forms this check understands are accepted; anything else is refused rather than guessed. */
function spConfig(toml) {
  const def = toml.split(/^\[profile\./m).find(s => s.startsWith("default]"));
  if (!def) infra("foundry.toml has no [profile.default]");
  const block = def.match(/^remappings\s*=\s*\[([\s\S]*?)\]/m);
  if (!block) infra("foundry.toml [profile.default] has no remappings array");
  const remappings = [];
  for (const raw of block[1].split("\n")) {
    const line = raw.replace(/#.*$/, "").trim().replace(/,$/, "").trim();
    if (!line) continue;
    const m = line.match(/^(["'])([^"']+)\1$/);
    if (!m) infra(`foundry.toml remapping not understood: ${line.slice(0, 80)}`);
    const body = m[2];
    if (/^[^=]*:/.test(body.split("=")[0])) infra(`contextual remapping not supported: ${body}`);
    const eq = body.indexOf("=");
    if (eq <= 0) infra(`remapping without '=': ${body}`);
    remappings.push([body.slice(0, eq), body.slice(eq + 1)]);
  }
  const val = k => def.match(new RegExp(`^${k}\\s*=\\s*["']?([^"'\\n#]+)["']?`, "m"))?.[1]?.trim();
  return {
    remappings,
    solc: val("solc_version"),
    viaIr: val("via_ir") === "true",
    optimizer: val("optimizer") === "true",
    runs: val("optimizer_runs"),
    evm: val("evm_version"),
  };
}

/** Import paths of a Solidity source, every form, outside comments and strings' contents. */
export function importsOf(text) {
  // drop comments first (block and line), keeping string literals intact
  let s = "";
  for (let i = 0; i < text.length;) {
    const c = text[i];
    if (c === '"' || c === "'") {
      let k = i + 1;
      while (k < text.length && text[k] !== c) k += text[k] === "\\" ? 2 : 1;
      s += text.slice(i, k + 1);
      i = k + 1;
    } else if (text.startsWith("//", i)) {
      while (i < text.length && text[i] !== "\n") i++;
    } else if (text.startsWith("/*", i)) {
      const e = text.indexOf("*/", i + 2);
      i = e < 0 ? text.length : e + 2;
    } else {
      s += c;
      i++;
    }
  }
  const out = [];
  // import "x"; import "x" as A; import * as A from "x"; import {a, b as c} from "x";
  for (const m of s.matchAll(/(?:^|[;{}\s])import\s+([^;]*?)["']([^"']+)["']([^;]*);/g))
    out.push(m[2]);
  return out;
}

/** The repository path an import resolves to, as forge would: longest remapping prefix first. */
function resolveImport(fromPath, spec, remappings) {
  if (spec.startsWith("./") || spec.startsWith("../"))
    return posix.normalize(posix.join(posix.dirname(fromPath), spec));
  const hit = remappings
    .filter(([p]) => spec.startsWith(p))
    .sort((a, b) => b[0].length - a[0].length)[0];
  if (!hit) infra(`import ${spec} (in ${fromPath}) matches no SP remapping`);
  return posix.normalize(hit[1] + spec.slice(hit[0].length));
}

// ---- fetch: foundry.toml and the import closure of DVTValidator.sol
const tomlFile = fetchFile("foundry.toml");
const cfg = spConfig(tomlFile.text);
if (!cfg.solc) infra("SP foundry.toml names no solc_version");
const files = new Map(); // repo path -> { text, sha }
const todo = [ENTRY];
while (todo.length) {
  const p = todo.pop();
  if (files.has(p)) continue;
  const f = fetchFile(p);
  files.set(p, f);
  for (const spec of importsOf(f.text)) todo.push(resolveImport(p, spec, cfg.remappings));
}

// ---- a fresh, empty project mirroring SP's tree layout, so SP's remappings apply unchanged
const outArg = opt("out");
if (outArg && existsSync(outArg) && readdirSync(outArg).length)
  infra(`--out ${outArg} is not empty`);
const out = outArg ? resolve(outArg) : mkdtempSync(join(tmpdir(), "sp-evidence-parity-"));
mkdirSync(out, { recursive: true });
for (const [p, f] of files) {
  mkdirSync(join(out, dirname(p)), { recursive: true });
  writeFileSync(join(out, p), f.text);
}
const fixturePath = join(ROOT, "contracts/test/fixtures/evidence-vectors.json");
const fixture = readFileSync(fixturePath, "utf8");
const fixtureBlob = gitBlob(fixture);
const nVectors = JSON.parse(fixture).vectors.length;
const forgeStd = join(ROOT, "contracts/lib/forge-std");
if (!existsSync(join(forgeStd, "src/Test.sol")))
  infra("contracts/lib/forge-std is empty: run `git submodule update --init`");
mkdirSync(join(out, "fixtures"), { recursive: true });
mkdirSync(join(out, "parity"), { recursive: true });
mkdirSync(join(out, "lib"), { recursive: true });
writeFileSync(
  join(out, "foundry.toml"),
  `[profile.default]
src = "contracts/src"
test = "parity"
libs = ["lib"]
solc_version = "${cfg.solc}"
optimizer = ${cfg.optimizer}
optimizer_runs = ${cfg.runs ?? 200}
via_ir = ${cfg.viaIr}
evm_version = "${cfg.evm ?? "cancun"}"
fs_permissions = [{ access = "read", path = "./fixtures" }]
remappings = [
${cfg.remappings.map(([a, b]) => `  "${a}=${b}",`).join("\n")}
  "forge-std/=${forgeStd}/src/",
]
`
);
// the harness imports the fetched entry by its repo path, not through a remapping
writeFileSync(
  join(out, TEST),
  `// SPDX-License-Identifier: Apache-2.0
pragma solidity ${cfg.solc};

import "forge-std/Test.sol";
import {DVTValidator} from "../${ENTRY}";

/// Accepts every body: the encoding is under test, not a category's check.
contract AcceptAll {
    function check(address, uint8, uint256, bytes calldata) external pure returns (bool) {
        return true;
    }
}

/// SP's DVTValidator unchanged; only its internal _checkEvidence is exposed.
contract DVTValidatorHarness is DVTValidator {
    constructor(bytes32[] memory cats, address[] memory checkers) DVTValidator(address(0xBEEF), 1, cats, checkers) {}

    function checkEvidence(address operator, uint8 level, uint256 epoch, bytes calldata evidence)
        external
        view
        returns (bytes32)
    {
        return _checkEvidence(operator, level, epoch, evidence);
    }
}

contract SpEvidenceParityTest is Test {
    function ${TEST_FN.replace("()", "")}() public {
        string memory json = vm.readFile(string.concat(vm.projectRoot(), "/fixtures/evidence-vectors.json"));
        bytes32[] memory cats = new bytes32[](2);
        cats[0] = vm.parseJsonBytes32(json, ".categories['DVT.Evidence.OverIssue.v1']");
        cats[1] = vm.parseJsonBytes32(json, ".categories['DVT.Evidence.AuditSlash.v1']");
        address[] memory checkers = new address[](2);
        checkers[0] = address(new AcceptAll());
        checkers[1] = address(new AcceptAll());
        DVTValidatorHarness v = new DVTValidatorHarness(cats, checkers);
        assertEq(v.TAG_EVIDENCE(), vm.parseJsonBytes32(json, ".tagEvidence"), "TAG_EVIDENCE");
        uint256 n;
        for (n = 0; vm.keyExistsJson(json, string.concat(".vectors[", vm.toString(n), "]")); n++) {
            string memory p = string.concat(".vectors[", vm.toString(n), "]");
            bytes memory evidence = vm.parseJsonBytes(json, string.concat(p, ".evidence"));
            assertEq(
                v.checkEvidence(address(0x1), 1, 42, evidence),
                vm.parseJsonBytes32(json, string.concat(p, ".evidenceHash")),
                "evidenceHash"
            );
            (bytes32 c, bytes memory b) = abi.decode(evidence, (bytes32, bytes));
            assertEq(c, vm.parseJsonBytes32(json, string.concat(p, ".category")), "category");
            assertEq(b, vm.parseJsonBytes(json, string.concat(p, ".body")), "body");
        }
        assertEq(n, ${nVectors}, "vector count");
        console.log("vectors", n);
    }
}
`
);
const harnessText = readFileSync(join(out, TEST), "utf8");

/** forge test --json, parsed: { ran, status, reason, logs } of our one test, or an infra failure. */
function runForge() {
  let stdout = "";
  try {
    stdout = execFileSync(forge, ["test", "--json", "--build-info", "-vv"], {
      cwd: out,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      maxBuffer: 256 << 20,
    });
  } catch (e) {
    // forge exits 1 when a test fails; that output is still a result. Anything without a parseable
    // result for our test is an infrastructure failure, never counted as a control failure.
    if (typeof e.status !== "number" || !e.stdout) infra("forge did not run");
    stdout = e.stdout;
  }
  const line = stdout.split("\n").find(l => l.trim().startsWith("{"));
  if (!line) infra("forge printed no JSON result (compile failure?)");
  let j;
  try {
    j = JSON.parse(line);
  } catch {
    infra("forge JSON result did not parse");
  }
  const t = j?.[TEST_KEY]?.test_results?.[TEST_FN];
  if (!t) infra(`forge result has no ${TEST_KEY} ${TEST_FN}`);
  return { status: t.status, reason: t.reason ?? null, logs: t.decoded_logs ?? [] };
}

/** Every source the compiler saw is a fetched SP file (by blob), forge-std, or the harness. */
function verifyInputs() {
  const dir = join(out, "out", "build-info");
  if (!existsSync(dir)) infra("no build-info written");
  const unknown = [];
  const mismatched = [];
  const seen = new Set();
  for (const f of readdirSync(dir).filter(n => n.endsWith(".json"))) {
    const bi = JSON.parse(readFileSync(join(dir, f), "utf8"));
    for (const [path, src] of Object.entries(bi.input?.sources ?? {})) {
      const rel = path.startsWith(out) ? path.slice(out.length + 1) : path;
      if (rel === TEST) {
        if (src.content !== undefined && src.content !== harnessText) mismatched.push(rel);
        continue;
      }
      if (rel.includes("forge-std/src/")) continue;
      const fetched = files.get(rel);
      if (!fetched) {
        unknown.push(rel);
        continue;
      }
      seen.add(rel);
      const text = src.content ?? readFileSync(join(out, rel), "utf8");
      if (gitBlob(text) !== fetched.sha) mismatched.push(rel);
    }
  }
  const notCompiled = [...files.keys()].filter(p => !seen.has(p));
  return { unknown, mismatched, notCompiled };
}

writeFileSync(join(out, "fixtures/evidence-vectors.json"), fixture);
const real = runForge();
const inputs = verifyInputs();
const vectorsLogged = real.logs.map(l => String(l).match(/^vectors (\d+)$/)?.[1]).find(Boolean);
const realOk =
  real.status === "Success" &&
  Number(vectorsLogged) === nVectors &&
  !inputs.unknown.length &&
  !inputs.mismatched.length &&
  !inputs.notCompiled.length;

// control: one evidenceHash altered must fail, on the evidenceHash assertion
const tampered = JSON.parse(fixture);
const last = tampered.vectors.length - 1;
const h = tampered.vectors[last].evidenceHash;
tampered.vectors[last].evidenceHash = h.slice(0, -1) + (h.endsWith("0") ? "1" : "0");
writeFileSync(
  join(out, "fixtures/evidence-vectors.json"),
  JSON.stringify(tampered, null, 2) + "\n"
);
const control = runForge();
writeFileSync(join(out, "fixtures/evidence-vectors.json"), fixture);
const controlOk = control.status === "Failure" && /evidenceHash/.test(control.reason ?? "");

const solcVersion = (() => {
  try {
    const dir = join(out, "out", "build-info");
    const f = readdirSync(dir).find(n => n.endsWith(".json"));
    return JSON.parse(readFileSync(join(dir, f), "utf8")).solcLongVersion ?? cfg.solc;
  } catch {
    return cfg.solc;
  }
})();
const report = {
  spRepo: repo,
  spCommit: sha,
  solc: solcVersion,
  compiler: { viaIr: cfg.viaIr, optimizer: cfg.optimizer, runs: cfg.runs, evm: cfg.evm },
  foundryToml: tomlFile.sha,
  files: Object.fromEntries([...files].map(([p, f]) => [p, f.sha]).sort()),
  compiledInputs: inputs,
  fixture: {
    path: "contracts/test/fixtures/evidence-vectors.json",
    blob: fixtureBlob,
    vectors: nVectors,
  },
  vectorsChecked: vectorsLogged ? Number(vectorsLogged) : null,
  parity: realOk ? "PASS" : "FAIL",
  parityDetail: realOk ? null : { status: real.status, reason: real.reason },
  control: controlOk ? "FAILED (as required)" : "DID NOT FAIL AS REQUIRED",
  controlDetail: { status: control.status, reason: control.reason },
  workdir: out,
};
console.log(JSON.stringify(report, null, 2));
process.exit(realOk && controlOk ? 0 : 1);
