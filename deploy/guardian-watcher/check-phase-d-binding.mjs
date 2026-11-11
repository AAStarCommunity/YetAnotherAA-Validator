// Self-test of the Phase D watcher-job binding predicate (phase-d-binding.mjs), including the
// Codex R7 and R8 counterexamples. Run: node deploy/guardian-watcher/check-phase-d-binding.mjs
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { parseLaunchd, bindingProblems, canonicalWrapper } from "./phase-d-binding.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const W = "/Users/op/.aoa-watcher/run-watcher.sh";
const CFG = "/Users/op/.aoa-watcher/config.json";
const ENTRY = "/Users/op/.aoa-watcher/repo/services/guardian-watcher/watcher.mjs";
const template = readFileSync(join(here, "run-watcher.sh"), "utf8");
const installed = canonicalWrapper(template, { config: CFG, entry: ENTRY });
const base = {
  wrapper: W,
  text: installed,
  template,
  wantConfig: CFG,
  wantEntry: ENTRY,
  services: { rpcPrimary: "aoa-dvt-rpc-primary", rpcSecondary: "aoa-dvt-rpc-secondary" },
  account: "aoa-watcher",
};
const ld = (program, argv) =>
  `gui/501/ai.aastar.aoa-watcher = {\n\tprogram = ${program}\n\targuments = {\n${argv
    .map(a => `\t\t${a}`)
    .join("\n")}\n\t}\n\tstate = running\n}\n`;
const run = (out, over = {}) => bindingProblems({ ...base, ...parseLaunchd(out), ...over });
const ok1 = ld(W, [W]);
const edit = (from, to) => ({ text: installed.replace(from, to) });
const EXEC = 'exec node "$WATCHER_ENTRY" --config "$WATCHER_CONFIG"';

const results = [];
const cell = (name, got, wantPass, needle) => {
  const ok = wantPass
    ? got.length === 0
    : got.length > 0 && (!needle || got.some(p => p.includes(needle)));
  results.push({ name, ok, got });
};
const NOT_CANON = "not this checkout's run-watcher.sh";

cell("the canonical wrapper run directly passes", run(ok1), true);
cell(
  "/bin/bash running the canonical wrapper passes",
  run(ld("/bin/bash", ["/bin/bash", W])),
  true
);
// R7 #1: program / argv
cell(
  "R7 #1: Program=/bin/sleep, argv=[wrapper, 3600] fails",
  run(ld("/bin/sleep", [W, "3600"])),
  false,
  "does not run exactly"
);
cell(
  "the wrapper with extra arguments fails",
  run(ld(W, [W, "--x"])),
  false,
  "does not run exactly"
);
cell(
  "/bin/bash running another script fails",
  run(ld("/bin/bash", ["/bin/bash", "/tmp/o.sh"])),
  false,
  "does not run exactly"
);
cell(
  "bash -c with the wrapper fails",
  run(ld("/bin/bash", ["/bin/bash", "-c", W])),
  false,
  "does not run exactly"
);
// R7 #2: Keychain identities
cell(
  "R7 #2: Phase D names other RPC services than the wrapper reads: fails",
  run(ok1, { services: { rpcPrimary: "alt-a", rpcSecondary: "alt-b" } }),
  false,
  "Keychain items"
);
cell(
  "R7 #2: another Keychain account: fails",
  run(ok1, { account: "someone" }),
  false,
  "Keychain items"
);
cell(
  "primary and secondary swapped in Phase D: fails",
  run(ok1, {
    services: { rpcPrimary: "aoa-dvt-rpc-secondary", rpcSecondary: "aoa-dvt-rpc-primary" },
  }),
  false,
  "Keychain items"
);
// R8 #1: text present but not what executes
cell(
  "R8 #1: exec /bin/sleep before the expected lines fails",
  run(ok1, edit("set -euo pipefail\n", "set -euo pipefail\nexec /bin/sleep 3600\n")),
  false,
  NOT_CANON
);
cell(
  "R8 #1: the expected lines inside an unused here-document fails",
  run(ok1, {
    text: installed
      .replace(/^RPC_URL=/m, ": <<'X'\nRPC_URL=")
      .replace(EXEC, `${EXEC}\nX\nexec sleep 9`),
  }),
  false,
  NOT_CANON
);
cell(
  "R8 #1: WATCHER_CONFIG reassigned before the exec fails",
  run(ok1, edit(EXEC, `WATCHER_CONFIG="/Users/op/other.json"\n${EXEC}`)),
  false,
  NOT_CANON
);
cell(
  "a commented-out exec fails",
  run(ok1, edit(EXEC, `# ${EXEC}\nexec sleep 3600`)),
  false,
  NOT_CANON
);
cell("a trailing line fails", run(ok1, { text: installed + "echo hi\n" }), false, NOT_CANON);
cell(
  "a wrapper holding a URL fails",
  run(ok1, { text: installed + "# https://rpc.example\n" }),
  false,
  NOT_CANON
);
// R8 #2: entry bound
cell(
  "R8 #2: WATCHER_ENTRY pointing at an unrelated program fails",
  run(ok1, edit(`WATCHER_ENTRY="${ENTRY}"`, 'WATCHER_ENTRY="/Users/op/unrelated.mjs"')),
  false,
  NOT_CANON
);
cell(
  "another watcherConfig fails",
  run(ok1, { wantConfig: "/Users/op/other.json" }),
  false,
  NOT_CANON
);
cell(
  "a config path with shell characters cannot be placed",
  run(ok1, { wantConfig: "/Users/op/$(id).json" }),
  false,
  "cannot be placed"
);
cell("an unreadable wrapper fails", run(ok1, { text: null }), false, "unreadable");
cell("an unreadable template fails", run(ok1, { template: null }), false, "template unreadable");

let failed = 0;
for (const r of results) {
  console.log(
    `${r.ok ? "ok  " : "FAIL"} ${r.name}${r.ok ? "" : `\n     got ${JSON.stringify(r.got)}`}`
  );
  if (!r.ok) failed++;
}
console.log(`\n${results.length - failed}/${results.length} cells`);
process.exit(failed ? 1 : 0);
