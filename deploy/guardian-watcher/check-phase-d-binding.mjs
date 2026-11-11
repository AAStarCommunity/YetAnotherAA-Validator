// Self-test of the Phase D watcher-job binding predicate (phase-d-binding.mjs), including the
// Codex R7 and R8 counterexamples. Run: node deploy/guardian-watcher/check-phase-d-binding.mjs
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn, spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import {
  parseLaunchd,
  bindingProblems,
  canonicalWrapper,
  liveProblems,
} from "./phase-d-binding.mjs";

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

// R9: the live process. Synthetic ps text first, then a real process inspected with real ps.
const P1 = "https://p.example/k1";
const P2 = "https://s.example/k2";
const lv = (cmd, env, over = {}) =>
  liveProblems({
    pid: 42,
    psCommand: cmd,
    psEnv: env === undefined ? cmd : `${cmd.trim()} ${env}`,
    wantEntry: ENTRY,
    wantConfig: CFG,
    rpcPrimary: P1,
    rpcSecondary: P2,
    ...over,
  });
const CMD = `node ${ENTRY} --config ${CFG}`;
cell(
  "live: the watcher with the Keychain RPCs passes",
  lv(CMD, `HOME=/x RPC_URL=${P1} RPC_URL_2=${P2}`),
  true
);
cell(
  "R9 #1: BASH_ENV hang: the pid is still bash running the wrapper: fails",
  lv(`/bin/bash ${W}`, `BASH_ENV=$(exec /bin/sleep 3600) RPC_URL=${P1} RPC_URL_2=${P2}`),
  false,
  "not the watcher"
);
cell(
  "R9 #2: the wrapper replaced after start, pid runs sleep: fails",
  lv("/bin/sleep 3600", ""),
  false,
  "not the watcher"
);
cell(
  "live: another config fails",
  lv(`node ${ENTRY} --config /Users/op/old.json`, `RPC_URL=${P1} RPC_URL_2=${P2}`),
  false,
  "not the watcher"
);
cell(
  "live: an old entry fails",
  lv(`node /Users/op/old/watcher.mjs --config ${CFG}`, `RPC_URL=${P1} RPC_URL_2=${P2}`),
  false,
  "not the watcher"
);
cell(
  "live: other RPC URLs fail",
  lv(CMD, `RPC_URL=https://other RPC_URL_2=${P2}`),
  false,
  "RPC URLs"
);
cell(
  "live: a duplicated RPC_URL fails",
  lv(CMD, `RPC_URL=x RPC_URL=${P1} RPC_URL_2=${P2}`),
  false,
  "RPC URLs"
);
cell("live: no RPC env fails", lv(CMD, "HOME=/x"), false, "RPC URLs");
cell("live: no pid fails", lv(CMD, "", { pid: null }), false, "no pid");
cell(
  "live: Keychain values missing fail",
  lv(CMD, `RPC_URL=${P1} RPC_URL_2=${P2}`, { rpcPrimary: null }),
  false,
  "not checkable"
);
{
  // a real process: node <entry> --config <config> with the RPC env, inspected through ps as Phase D does
  const d = mkdtempSync(join(tmpdir(), "pdb-"));
  const entry = join(d, "watcher.mjs");
  const conf = join(d, "config.json");
  writeFileSync(entry, "setTimeout(() => {}, 20000);\n");
  writeFileSync(conf, "{}\n");
  const child = spawn(process.execPath, [entry, "--config", conf], {
    env: { PATH: process.env.PATH, RPC_URL: P1, RPC_URL_2: P2 },
    stdio: "ignore",
  });
  await new Promise(r => setTimeout(r, 500));
  const ps = extra =>
    spawnSync("ps", [...extra, "-ww", "-o", "command=", "-p", String(child.pid)], {
      encoding: "utf8",
    });
  const c = ps([]);
  const e = ps(["-E"]);
  const real = over =>
    liveProblems({
      pid: child.pid,
      psCommand: c.status === 0 ? c.stdout : null,
      psEnv: e.status === 0 ? e.stdout : null,
      wantEntry: entry,
      wantConfig: conf,
      rpcPrimary: P1,
      rpcSecondary: P2,
      ...over,
    });
  // ps shows the full node path as argv[0]; the wrapper's exec uses "node" from PATH: both end in node
  const inspectable = process.platform === "darwin" && /(^|\/)node$/.test(process.execPath);
  if (inspectable) {
    cell("live (real ps): the running node process with the Keychain RPCs passes", real({}), true);
    cell(
      "live (real ps): a different expected RPC fails",
      real({ rpcSecondary: "https://x" }),
      false,
      "RPC URLs"
    );
    cell(
      "live (real ps): a different expected config fails",
      real({ wantConfig: "/other.json" }),
      false,
      "not the watcher"
    );
  }
  child.kill();
}

let failed = 0;
for (const r of results) {
  console.log(
    `${r.ok ? "ok  " : "FAIL"} ${r.name}${r.ok ? "" : `\n     got ${JSON.stringify(r.got)}`}`
  );
  if (!r.ok) failed++;
}
console.log(`\n${results.length - failed}/${results.length} cells`);
process.exit(failed ? 1 : 0);
