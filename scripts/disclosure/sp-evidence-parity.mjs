#!/usr/bin/env node
// Standing check (DSR 8c5f68e5): run SuperPaymaster's own DVTValidator._checkEvidence against this
// repo's M0 §3.1 vectors (contracts/test/fixtures/evidence-vectors.json), byte for byte.
//
//   node scripts/disclosure/sp-evidence-parity.mjs <SP commit SHA> [--repo owner/name] [--out dir]
//
// Everything is read through the GitHub API (gh), at that exact commit, never from a local checkout
// of SP. DVTValidator.sol and its whole import closure are resolved with SP's own foundry.toml
// remappings (OpenZeppelin included: SP vendors it under singleton-paymaster/lib), so the compiled
// code is SP's, not a stand-in. A scratch Foundry project then:
//   1. deploys a harness that inherits DVTValidator unchanged and only exposes _checkEvidence,
//      registering the vectors' categories with an always-accept checker (the encoding is under
//      test, not a category's check);
//   2. asserts, for every vector, SP's TAG_EVIDENCE, its decode of our evidence blob, and that its
//      evidenceHash equals ours;
//   3. reruns with one vector's evidenceHash altered, which must FAIL (a control, so a pass is
//      never vacuous).
// The report (stdout, JSON) records the SP commit, the solc version, every fetched file's git blob
// SHA and the fixture's blob SHA. Exit 0 only if (2) passes and (3) fails.
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname, posix } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..", "..");
const ENTRY = "contracts/src/modules/monitoring/DVTValidator.sol";

const args = process.argv.slice(2);
const sha = args[0];
const opt = k => {
  const i = args.indexOf(`--${k}`);
  return i > 0 ? args[i + 1] : undefined;
};
const repo = opt("repo") ?? "AAStarCommunity/SuperPaymaster";
if (!/^[0-9a-f]{40}$/.test(sha ?? "")) {
  console.error(
    "usage: sp-evidence-parity.mjs <full 40-hex SP commit SHA> [--repo owner/name] [--out dir]"
  );
  process.exit(2);
}
const forge = existsSync(join(process.env.HOME ?? "", ".foundry/bin/forge"))
  ? join(process.env.HOME, ".foundry/bin/forge")
  : "forge";

/** A file of `repo` at `sha` through the contents API: { text, sha } (git blob SHA). */
function fetchFile(path) {
  const out = execFileSync("gh", ["api", `repos/${repo}/contents/${path}?ref=${sha}`], {
    encoding: "utf8",
    maxBuffer: 64 << 20,
  });
  const j = JSON.parse(out);
  if (j.type !== "file" || j.encoding !== "base64")
    throw new Error(`${path}: not a plain file at ${sha} (type ${j.type})`);
  return { text: Buffer.from(j.content, "base64").toString("utf8"), sha: j.sha };
}

/** SP's [profile.default] remappings and compiler settings, from its foundry.toml at `sha`. */
function spConfig() {
  const toml = fetchFile("foundry.toml").text;
  const def = toml.split(/^\[profile\./m).find(s => s.startsWith("default]"));
  if (!def) throw new Error("foundry.toml has no [profile.default]");
  const block = def.match(/remappings\s*=\s*\[([\s\S]*?)\]/);
  const remappings = [...(block?.[1] ?? "").matchAll(/"([^"=]+)=([^"]*)"/g)].map(m => [m[1], m[2]]);
  const val = k => def.match(new RegExp(`^${k}\\s*=\\s*"?([^"\\n]+)"?`, "m"))?.[1]?.trim();
  return {
    remappings,
    solc: val("solc_version"),
    viaIr: val("via_ir") === "true",
    optimizer: val("optimizer") === "true",
    runs: val("optimizer_runs"),
    evm: val("evm_version"),
  };
}

/** The repository path an import resolves to, as forge would: longest remapping prefix first. */
function resolveImport(fromPath, spec, remappings) {
  if (spec.startsWith("./") || spec.startsWith("../"))
    return posix.normalize(posix.join(posix.dirname(fromPath), spec));
  const hit = remappings
    .filter(([p]) => spec.startsWith(p))
    .sort((a, b) => b[0].length - a[0].length)[0];
  if (!hit) throw new Error(`import ${spec} (in ${fromPath}) matches no SP remapping`);
  return posix.normalize(hit[1] + spec.slice(hit[0].length));
}

const cfg = spConfig();
if (!cfg.solc) throw new Error("SP foundry.toml names no solc_version");

// the import closure of DVTValidator.sol, fetched file by file
const files = new Map(); // repo path -> { text, sha }
const todo = [ENTRY];
while (todo.length) {
  const p = todo.pop();
  if (files.has(p)) continue;
  const f = fetchFile(p);
  files.set(p, f);
  for (const m of f.text.matchAll(/^\s*import\s+(?:[^"';]*\s+from\s+)?["']([^"']+)["']\s*;/gm))
    todo.push(resolveImport(p, m[1], cfg.remappings));
}

// the scratch project mirrors SP's tree layout, so SP's remappings apply unchanged
const out = opt("out") ?? mkdtempSync(join(tmpdir(), "sp-evidence-parity-"));
for (const [p, f] of files) {
  mkdirSync(join(out, dirname(p)), { recursive: true });
  writeFileSync(join(out, p), f.text);
}
const fixturePath = join(ROOT, "contracts/test/fixtures/evidence-vectors.json");
const fixture = readFileSync(fixturePath, "utf8");
const fixtureBlob = execFileSync("git", ["hash-object", fixturePath], { encoding: "utf8" }).trim();
mkdirSync(join(out, "fixtures"), { recursive: true });
mkdirSync(join(out, "parity"), { recursive: true });
const forgeStd = join(ROOT, "contracts/lib/forge-std");
if (!existsSync(join(forgeStd, "src/Test.sol")))
  throw new Error("contracts/lib/forge-std is empty: run `git submodule update --init` first");
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
writeFileSync(
  join(out, "parity/SpEvidenceParity.t.sol"),
  `// SPDX-License-Identifier: Apache-2.0
pragma solidity ${cfg.solc};

import "forge-std/Test.sol";
import "src/modules/monitoring/DVTValidator.sol";

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
    function test_spDvtValidatorMatchesDvtVectors() public {
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
        assertGt(n, 0, "no vectors");
        console.log("vectors", n);
    }
}
`
);
mkdirSync(join(out, "lib"), { recursive: true });

const runForge = () => {
  try {
    const o = execFileSync(forge, ["test", "-vv"], {
      cwd: out,
      encoding: "utf8",
      stdio: "pipe",
      maxBuffer: 64 << 20,
    });
    return { ok: true, out: o };
  } catch (e) {
    return { ok: false, out: `${e.stdout ?? ""}${e.stderr ?? ""}` };
  }
};
writeFileSync(join(out, "fixtures/evidence-vectors.json"), fixture);
const real = runForge();
// control: one evidenceHash altered must fail
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

const solcLine = (real.out.match(/Solc ([0-9.]+)/) ?? [])[1] ?? cfg.solc;
const vectors = Number((real.out.match(/vectors (\d+)/) ?? [])[1] ?? NaN);
const report = {
  spRepo: repo,
  spCommit: sha,
  solc: solcLine,
  compiler: { viaIr: cfg.viaIr, optimizer: cfg.optimizer, runs: cfg.runs, evm: cfg.evm },
  files: Object.fromEntries([...files].map(([p, f]) => [p, f.sha]).sort()),
  fixture: { path: "contracts/test/fixtures/evidence-vectors.json", blob: fixtureBlob },
  vectors,
  parity: real.ok ? "PASS" : "FAIL",
  control: control.ok ? "PASSED (BAD: the comparison is vacuous)" : "FAILED (as required)",
  workdir: out,
};
console.log(JSON.stringify(report, null, 2));
if (!real.ok)
  console.error(
    real.out
      .split("\n")
      .filter(l => /FAIL|Error|error/.test(l))
      .slice(0, 20)
      .join("\n")
  );
process.exit(real.ok && !control.ok ? 0 : 1);
