// Self-test of the Phase D watcher-job binding predicate (phase-d-binding.mjs), including the
// Codex R7 counterexamples. Run: node deploy/guardian-watcher/check-phase-d-binding.mjs
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { parseLaunchd, bindingProblems } from "./phase-d-binding.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const W = "/Users/op/.aoa-watcher/run-watcher.sh";
const CFG = "/Users/op/.aoa-watcher/config.json";
const template = readFileSync(join(here, "run-watcher.sh"), "utf8");
const installed = template
  .replace("__WATCHER_CONFIG__", CFG)
  .replace("__WATCHER_ENTRY__", "/Users/op/.aoa-watcher/repo/deploy/guardian-watcher/watcher.mjs");
const SERVICES = { rpcPrimary: "aoa-dvt-rpc-primary", rpcSecondary: "aoa-dvt-rpc-secondary" };
const base = {
  wrapper: W,
  text: installed,
  wantConfig: CFG,
  services: SERVICES,
  account: "aoa-watcher",
  ok: v => typeof v === "string" && v.length > 0 && !v.startsWith("<"),
};
const ld = (program, argv) =>
  `gui/501/ai.aastar.aoa-watcher = {\n\tprogram = ${program}\n\targuments = {\n${argv
    .map(a => `\t\t${a}`)
    .join("\n")}\n\t}\n\tstate = running\n}\n`;
const run = (out, over = {}) => bindingProblems({ ...base, ...parseLaunchd(out), ...over });

const results = [];
const cell = (name, got, wantPass, needle) => {
  const ok = wantPass
    ? got.length === 0
    : got.length > 0 && (!needle || got.some(p => p.includes(needle)));
  results.push({ name, ok, got });
};

cell("the wrapper run directly passes", run(ld(W, [W])), true);
cell("/bin/bash running the wrapper passes", run(ld("/bin/bash", ["/bin/bash", W])), true);
cell(
  "R7 #1: Program=/bin/sleep with ProgramArguments=[wrapper, 3600] fails",
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
  run(ld("/bin/bash", ["/bin/bash", "/tmp/other.sh"])),
  false,
  "does not run exactly"
);
cell(
  "bash -c with the wrapper as an argument fails",
  run(ld("/bin/bash", ["/bin/bash", "-c", W])),
  false,
  "does not run exactly"
);
cell(
  "R7 #2: Phase D config names other RPC services than the wrapper reads: fails",
  run(ld(W, [W]), { services: { rpcPrimary: "alt-rpc-a", rpcSecondary: "alt-rpc-b" } }),
  false,
  "Keychain items this check verified"
);
cell(
  "R7 #2: Phase D config names another Keychain account: fails",
  run(ld(W, [W]), { account: "someone-else" }),
  false,
  "Keychain items this check verified"
);
cell(
  "primary and secondary swapped in the wrapper fails",
  run(ld(W, [W]), {
    text: installed
      .replace("-s aoa-dvt-rpc-primary", "-s TMPSWAP")
      .replace("-s aoa-dvt-rpc-secondary", "-s aoa-dvt-rpc-primary")
      .replace("-s TMPSWAP", "-s aoa-dvt-rpc-secondary"),
  }),
  false,
  "Keychain items this check verified"
);
cell(
  "a wrapper that reads a third Keychain item fails",
  run(ld(W, [W]), {
    text: installed.replace(
      "export RPC_URL RPC_URL_2",
      'X="$(security find-generic-password -s aoa-dvt-pinata-jwt -a aoa-watcher -w)"\nexport RPC_URL RPC_URL_2'
    ),
  }),
  false,
  "more Keychain items"
);
cell(
  "a wrapper that names another config fails",
  run(ld(W, [W]), { wantConfig: "/Users/op/other.json" }),
  false,
  "another config"
);
cell(
  "a wrapper holding a URL fails",
  run(ld(W, [W]), { text: installed + "# https://rpc.example\n" }),
  false,
  "holds a URL"
);
cell(
  "a commented-out exec does not count",
  run(ld(W, [W]), {
    text: installed.replace(
      'exec node "$WATCHER_ENTRY" --config "$WATCHER_CONFIG"',
      '# exec node "$WATCHER_ENTRY" --config "$WATCHER_CONFIG"\nexec sleep 3600'
    ),
  }),
  false,
  "does not exec"
);
cell("an unreadable wrapper fails", run(ld(W, [W]), { text: null }), false, "unreadable");
cell(
  "placeholder services fail",
  run(ld(W, [W]), { services: { rpcPrimary: "<x>", rpcSecondary: "<y>" } }),
  false,
  "Keychain items"
);

let failed = 0;
for (const r of results) {
  console.log(
    `${r.ok ? "ok  " : "FAIL"} ${r.name}${r.ok ? "" : `\n     got ${JSON.stringify(r.got)}`}`
  );
  if (!r.ok) failed++;
}
console.log(`\n${results.length - failed}/${results.length} cells`);
process.exit(failed ? 1 : 0);
