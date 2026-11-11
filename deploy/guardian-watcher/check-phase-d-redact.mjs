// Self-test: Phase D never prints a URL-like fragment, even when an operator label (public data by
// contract) is an honest mistake holding a credential-bearing RPC URL. Runs the real
// phase-d-check.mjs on the example config with such labels and inspects everything it prints.
// Run: node deploy/guardian-watcher/check-phase-d-redact.mjs
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const cfg = JSON.parse(readFileSync(join(here, "phase-d.example.json"), "utf8"));
cfg.rpc.primary.operator = "https://eth-sepolia.example/v2/SECRETKEY_A";
cfg.rpc.second.operator = "wss://rpc.example/SECRETKEY_B";
// the id channel too (#408 N1): a launchd label is interpolated into the line id
cfg.launchd.mustBeOff = [...(cfg.launchd.mustBeOff ?? []), "https://x.example/SECRETKEY_ID"];
const d = mkdtempSync(join(tmpdir(), "pd-redact-"));
writeFileSync(join(d, "phase-d.json"), JSON.stringify(cfg));
const r = spawnSync(
  process.execPath,
  [join(here, "phase-d-check.mjs"), "--config", join(d, "phase-d.json")],
  {
    encoding: "utf8",
    env: { ...process.env, PHASE_D_RPC_PRIMARY: "", PHASE_D_RPC_SECOND: "" },
    timeout: 240_000,
  }
);
const out = `${r.stdout}\n${r.stderr}`;
const cells = [
  ["the check ran and reported the RPC lines", /rpc-primary/.test(out)],
  ["no secret from an operator label or a launchd label is printed", !/SECRETKEY/.test(out)],
  ["no URL scheme is printed", !/[a-z][a-z0-9+.-]*:\/\//i.test(out)],
  ["the replacement wording is shown instead", /\(a URL: not shown\)/.test(out)],
];
let failed = 0;
for (const [name, ok] of cells) {
  console.log(`${ok ? "ok  " : "FAIL"} ${name}`);
  if (!ok) failed++;
}
if (failed) console.log(out.slice(0, 2000));
console.log(`\n${cells.length - failed}/${cells.length} cells`);
process.exit(failed ? 1 : 0);
