// Cells for the checks a7-fork.mjs makes around the anvil it starts (#412 review M1, DSR): F2 (the
// upstream is the read-back's chain and has the fork block), N1 (nothing already on --port; the
// anvil this tool started is the one answering, up to the verdict), and the exit codes.
// Run: node deploy/guardian-watcher/check-a7-fork.mjs
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  EXIT,
  preflight,
  anvilBuild,
  waitForAnvil,
  startFailure,
  verdict,
} from "./a7-fork-checks.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const results = [];
const cell = (name, ok, got) =>
  results.push({ name, ok: !!ok, got: ok ? "" : JSON.stringify(got) });

// ---- F2 / N1: preflight, with an injected JSON-RPC
const FORK = "https://fork.invalid/KEY";
const H = { chainId: 11155111, forkBlock: 1000, port: 8546 };
// an explicit undefined means "no result" (so no destructuring defaults)
const rpcOf = (o = {}) => {
  const chain = Object.hasOwn(o, "chain") ? o.chain : "0xaa36a7";
  const head = Object.hasOwn(o, "head") ? o.head : "0x3e8";
  const local = o.local;
  const calls = [];
  const rpc = async (url, method) => {
    calls.push(`${url === FORK ? "up" : url}:${method}`);
    if (url === FORK) return method === "eth_chainId" ? chain : head;
    return local; // something on 127.0.0.1:<port>, or undefined
  };
  return { rpc, calls };
};
const pre = o => preflight({ ...H, forkUrl: FORK, ...o });
{
  const { rpc, calls } = rpcOf();
  const f = await pre({ rpc });
  cell(
    "F2: the right upstream chain, the fork block reached, the port free: passes",
    f === null &&
      calls.join(",") === "up:eth_chainId,up:eth_blockNumber,http://127.0.0.1:8546:eth_chainId",
    { f, calls }
  );
}
{
  const f = await pre({ rpc: rpcOf({ chain: "0x1" }).rpc });
  cell(
    "F2: an upstream on another chain: STOP (exit 1), fixed wording",
    f?.code === EXIT.STOP && f.msg === "the fork RPC is not the read-back's chain (eth_chainId)",
    f
  );
}
{
  const f = await pre({ rpc: rpcOf({ chain: undefined }).rpc });
  cell(
    "F2: an upstream that does not answer eth_chainId: no verdict (exit 3)",
    f?.code === EXIT.NO_VERDICT && f.msg === "the fork RPC does not answer eth_chainId",
    f
  );
}
{
  // "11155111" is the right number in decimal, but a JSON-RPC quantity is hex: refused
  const f = await pre({ rpc: rpcOf({ chain: "11155111" }).rpc });
  const g = await pre({ rpc: rpcOf({ chain: "aa36a7" }).rpc });
  cell(
    "F2: a chain id that is not a hex quantity (decimal, bare hex): STOP",
    f?.code === EXIT.STOP && g?.code === EXIT.STOP,
    { f, g }
  );
}
{
  // declared tightenings over the inline code: a null chain id is no answer (exit 3; it was 1);
  // a head that is not a hex quantity is refused (a non-numeric one used to pass: NaN < n is false)
  const nullChain = await pre({ rpc: rpcOf({ chain: null }).rpc });
  const decimalHead = await pre({ rpc: rpcOf({ head: "1000" }).rpc });
  const junkHead = await pre({ rpc: rpcOf({ head: "latest" }).rpc });
  cell(
    "F2 (declared): a null chain id is no verdict (exit 3); a decimal or non-numeric head is STOP",
    nullChain?.code === EXIT.NO_VERDICT &&
      decimalHead?.code === EXIT.STOP &&
      junkHead?.code === EXIT.STOP,
    { nullChain, decimalHead, junkHead }
  );
}
{
  const below = await pre({ rpc: rpcOf({ head: "0x3e7" }).rpc }); // 999 < 1000
  const at = await pre({ rpc: rpcOf({ head: "0x3e8" }).rpc }); // 1000
  const none = await pre({ rpc: rpcOf({ head: undefined }).rpc });
  cell(
    "F2: an upstream below header.forkBlock (or without a head): STOP; at the fork block: passes",
    below?.code === EXIT.STOP &&
      below.msg === "the fork RPC does not have header.forkBlock yet" &&
      at === null &&
      none?.code === EXIT.STOP,
    { below, at, none }
  );
}
{
  const f = await pre({ rpc: rpcOf({ local: "0x7a69" }).rpc });
  const f0 = await pre({ rpc: rpcOf({ local: null }).rpc });
  cell(
    "N1: something already answering on --port (any result, null included): STOP before anvil starts",
    f?.code === EXIT.STOP &&
      f.msg === "something already listens on --port 8546: refusing to compare against it" &&
      f0?.code === EXIT.STOP,
    { f, f0 }
  );
}
{
  // the upstream URL never appears in any message
  const fails = await Promise.all([
    pre({ rpc: rpcOf({ chain: "0x1" }).rpc }),
    pre({ rpc: rpcOf({ chain: undefined }).rpc }),
    pre({ rpc: rpcOf({ head: "0x1" }).rpc }),
    pre({ rpc: rpcOf({ local: "0x1" }).rpc }),
  ]);
  cell(
    "F2/N1: no message carries the fork URL",
    fails.every(f => f && !f.msg.includes("fork.invalid") && !f.msg.includes("KEY")),
    fails
  );
}

// ---- the anvil build
const PIN = "4e8874b2bdc840929585ca73e170993c50a4a531";
const V = "anvil Version: 1.8.7-nightly";
const text = (commit = PIN, first = V) => `${first}\nCommit SHA: ${commit}\nBuild Timestamp: x\n`;
{
  const ok = anvilBuild(text(), { pinnedCommit: PIN, headerVersion: V });
  const other = anvilBuild(text("a".repeat(40)), { pinnedCommit: PIN, headerVersion: V });
  const none = anvilBuild(`${V}\n`, { pinnedCommit: PIN, headerVersion: V });
  const ver = anvilBuild(text(PIN, "anvil Version: 1.8.6"), {
    pinnedCommit: PIN,
    headerVersion: V,
  });
  const gone = anvilBuild(null, { pinnedCommit: PIN, headerVersion: V });
  cell(
    "anvil build: the pinned commit and header.anvilVersion pass; another commit, no commit or another version STOP; not runnable is no verdict",
    ok.fail === null &&
      ok.commit === PIN &&
      ok.version === V &&
      other.fail?.code === EXIT.STOP &&
      none.fail?.code === EXIT.STOP &&
      /unknown/.test(none.fail.msg) &&
      ver.fail?.code === EXIT.STOP &&
      ver.fail.msg === "anvil --version differs from the read-back's header.anvilVersion" &&
      gone.fail?.code === EXIT.NO_VERDICT,
    { ok, other, none, ver, gone }
  );
}

// ---- N1: waiting for the anvil this tool started
const sleep = async () => {};
{
  const proc = { exitCode: null };
  let n = 0;
  const up = await waitForAnvil({
    proc,
    sleep,
    ping: async () => {
      if (++n < 3) throw new Error("starting");
    },
  });
  cell("N1: a running anvil that comes up: up", up === true && n === 3, { up, n });
}
{
  // anvil exited (e.g. "Address already in use"), but SOMETHING answers on the port
  const proc = { exitCode: 1 };
  let pinged = 0;
  const up = await waitForAnvil({ proc, sleep, ping: async () => void pinged++ });
  cell(
    "N1: an anvil that exited is never up, even when the port answers (another process)",
    up === false && pinged === 0,
    { up, pinged }
  );
}
{
  // the ping succeeds just as anvil exits: the answer was not from the process this tool runs
  const proc = { exitCode: null };
  const up = await waitForAnvil({
    proc,
    sleep,
    ping: async () => {
      proc.exitCode = 1;
    },
  });
  cell("N1: anvil exiting while the port answers: not up", up === false, up);
}
{
  // a child killed by a signal keeps exitCode null and sets signalCode (Codex M1 R1)
  let pinged = 0;
  const killed = await waitForAnvil({
    proc: { exitCode: null, signalCode: "SIGTERM" },
    sleep,
    ping: async () => void pinged++,
  });
  const proc = { exitCode: null, signalCode: null };
  const late = await waitForAnvil({
    proc,
    sleep,
    ping: async () => {
      proc.signalCode = "SIGKILL";
    },
  });
  cell(
    "N1: an anvil killed by a signal is never up (before or while the port answers)",
    killed === false && pinged === 0 && late === false,
    { killed, pinged, late }
  );
}
{
  const up = await waitForAnvil({
    proc: { exitCode: null },
    sleep,
    tries: 5,
    ping: async () => {
      throw new Error("no");
    },
  });
  cell("N1: an anvil that never answers within the tries: not up", up === false, up);
}
{
  const cats = [
    ["thread 'main' panicked at ...", "it crashed: this build cannot run the read-back's hardfork"],
    ["failed to connect to https://x.invalid/KEY", "cannot reach or read the fork RPC"],
    ["error: unknown argument --foo", "rejected an argument"],
    ["", "no RPC"],
  ];
  const got = cats.map(([e]) => startFailure(e));
  cell(
    "start failure: exit 3, a fixed category, never anvil's own text",
    got.every(
      (g, i) =>
        g.code === EXIT.NO_VERDICT &&
        g.msg === `anvil did not start (${cats[i][1]})` &&
        !g.msg.includes("x.invalid")
    ),
    got
  );
}

// ---- the verdict and its exit code
{
  const good = [{ ok: true }, { ok: true }];
  const live = { exitCode: null, signalCode: null };
  const same = verdict({ cmp: good, unverified: [], anvil: live });
  const exited = verdict({ cmp: good, unverified: [], anvil: { exitCode: 0, signalCode: null } });
  const signalled = verdict({
    cmp: good,
    unverified: [],
    anvil: { exitCode: null, signalCode: "SIGTERM" },
  });
  const bad = verdict({
    cmp: [{ ok: true }, { path: "x", ok: false }],
    unverified: [],
    anvil: live,
  });
  const unv = verdict({ cmp: good, unverified: ["y"], anvil: live });
  cell(
    "verdict: SAME STATE (exit 0) only with every comparison ok, nothing unverified and anvil still running",
    same.proven && same.exitCode === EXIT.SAME_STATE && same.failed.length === 0,
    same
  );
  cell(
    "N1: anvil exited, or was killed by a signal, before the verdict: STOP (exit 1) with that line",
    [exited, signalled].every(
      v =>
        !v.proven &&
        v.exitCode === EXIT.STOP &&
        v.failed.some(f => f.path === "anvil exited before the verdict")
    ),
    { exited, signalled }
  );
  cell(
    "verdict: a failed comparison or an unverified field: STOP (exit 1)",
    !bad.proven &&
      bad.exitCode === EXIT.STOP &&
      bad.failed.length === 1 &&
      !unv.proven &&
      unv.exitCode === EXIT.STOP,
    { bad, unv }
  );
}
cell(
  "exit codes are the documented ones",
  EXIT.SAME_STATE === 0 && EXIT.STOP === 1 && EXIT.USAGE === 2 && EXIT.NO_VERDICT === 3,
  EXIT
);

// ---- usage exit codes: the real script, before anything is read or started
const run = (argv, env = {}) => {
  const r = spawnSync(process.execPath, [join(here, "a7-fork.mjs"), ...argv], {
    env: { PATH: process.env.PATH, HOME: process.env.HOME, ...env },
    encoding: "utf8",
    timeout: 30_000,
  });
  return { status: r.status, err: r.stderr.trim() };
};
const okArgs = [
  "--dump",
  "/nonexistent",
  "--dump-sha256",
  "ab".repeat(32),
  "--readback",
  "/nonexistent",
  "--fund",
  "0x" + "11".repeat(20),
];
{
  const noArgs = run([], { A7_FORK_URL: FORK });
  const badSha = run(
    okArgs.map(a => (a === "ab".repeat(32) ? "xyz" : a)),
    { A7_FORK_URL: FORK }
  );
  const badFund = run(
    okArgs.map(a => (a.startsWith("0x11") ? "0x1" : a)),
    { A7_FORK_URL: FORK }
  );
  const noUrl = run(okArgs);
  const urlProvider = run([...okArgs, "--fork-provider", "https://x.invalid/KEY"], {
    A7_FORK_URL: FORK,
  });
  cell(
    "usage (exit 2): no arguments, a bad --dump-sha256, a bad --fund, A7_FORK_URL unset, a URL as --fork-provider",
    [noArgs, badSha, badFund, noUrl, urlProvider].every(r => r.status === EXIT.USAGE) &&
      /usage:/.test(noArgs.err) &&
      /A7_FORK_URL .* is not set/.test(noUrl.err) &&
      /--fork-provider must be a plain provider name/.test(urlProvider.err) &&
      !urlProvider.err.includes("x.invalid"),
    { noArgs, badSha, badFund, noUrl, urlProvider }
  );
}
{
  // past usage, the first input that cannot be read is exit 1 (not 3: it is the operator's file)
  const r = run([...okArgs, "--schema", "/nonexistent"], { A7_FORK_URL: FORK });
  cell(
    "an unreadable operator input (--schema): exit 1, fixed wording",
    r.status === EXIT.STOP && r.err === "a7-fork: cannot read --schema",
    r
  );
}

// ---- end to end: the real script, past its inputs, against a local fake upstream and a fake
// anvil (no network beyond 127.0.0.1, no real RPC, nothing sent)
{
  const { createServer } = await import("node:http");
  const { spawn } = await import("node:child_process");
  const { createHash } = await import("node:crypto");
  const fs = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { ABI_FILES } = await import("./a7-readback.mjs");
  const d = fs.mkdtempSync(join(tmpdir(), "a7fork-"));
  const servers = [];
  const anvilLog = join(d, "anvil.log");
  const anvilPids = join(d, "anvil.pids");
  const anvilRpc = join(d, "anvil.rpc");
  const rpcCalls = () =>
    fs.existsSync(anvilRpc)
      ? fs
          .readFileSync(anvilRpc, "utf8")
          .split("\n")
          .filter(Boolean)
          .map(l => JSON.parse(l))
      : [];
  const readLog = () => (fs.existsSync(anvilLog) ? fs.readFileSync(anvilLog, "utf8") : "");
  const startedPids = () =>
    fs.existsSync(anvilPids)
      ? fs.readFileSync(anvilPids, "utf8").split("\n").filter(Boolean).map(Number)
      : [];
  const alive = pid => {
    try {
      process.kill(pid, 0);
      return true;
    } catch {
      return false;
    }
  };
  const killAnvils = () => {
    for (const pid of startedPids())
      try {
        process.kill(pid, "SIGKILL");
      } catch {
        // already gone
      }
  };
  process.on("exit", killAnvils); // the harness interrupted: no fake anvil survives it
  const serve = handler =>
    new Promise(res => {
      const srv = createServer((req, rsp) => {
        let b = "";
        req.on("data", c => (b += c));
        req.on("end", () => {
          let m;
          try {
            m = JSON.parse(b);
          } catch {
            m = {};
          }
          rsp.setHeader("content-type", "application/json");
          rsp.end(JSON.stringify({ jsonrpc: "2.0", id: m.id ?? 1, result: handler(m.method) }));
        });
      });
      servers.push(srv);
      srv.listen(0, "127.0.0.1", () => res(srv.address().port));
    });
  const freePort = () =>
    new Promise(res => {
      const srv = createServer();
      srv.listen(0, "127.0.0.1", () => {
        const port = srv.address().port;
        srv.close(() => res(port));
      });
    });
  const runAsync = (argv, env) =>
    new Promise(res => {
      const c = spawn(process.execPath, [join(here, "a7-fork.mjs"), ...argv], {
        env: { PATH: process.env.PATH, HOME: process.env.HOME, ...env },
        stdio: ["ignore", "pipe", "pipe"],
      });
      let out = "";
      let err = "";
      c.stdout.on("data", x => (out += x));
      c.stderr.on("data", x => (err += x));
      // on timeout the script and every anvil it started are killed (SIGKILL skips its cleanup)
      const t = setTimeout(() => {
        c.kill("SIGKILL");
        killAnvils();
      }, 90_000);
      // "close": after the child exited AND its stdout/stderr were drained (Codex M1 R2)
      c.on("close", status => {
        clearTimeout(t);
        res({ status, err: err.trim(), out });
      });
    });
  try {
    const dump = join(d, "dump.json");
    fs.writeFileSync(dump, '{"fake":"dump"}');
    const dumpSha = createHash("sha256").update(fs.readFileSync(dump)).digest("hex");
    const rb = JSON.parse(
      fs.readFileSync(join(here, "fixtures/a7/aoa-a7-readback-1.example.json"), "utf8")
    );
    rb.header.dumpSha256 = dumpSha;
    const rbPath = join(d, "readback.json");
    fs.writeFileSync(rbPath, JSON.stringify(rb));
    const abiDir = join(d, "abis");
    fs.mkdirSync(abiDir);
    for (const f of Object.values(ABI_FILES)) if (f) fs.writeFileSync(join(abiDir, f), "[]");
    const fakeAnvil = join(d, "anvil");
    fs.writeFileSync(
      fakeAnvil,
      `#!${process.execPath}
const a = process.argv.slice(2);
const fs = await import("node:fs");
// every invocation is logged, so a case can prove anvil was never reached (Codex M1 R1 #2)
fs.appendFileSync(process.env.FAKE_ANVIL_LOG, (a.includes("--version") ? "version" : "start") + "\\n");
if (!a.includes("--version")) {
  fs.appendFileSync(process.env.FAKE_ANVIL_PIDS, process.pid + "\\n");
  // never outlives the a7-fork that started it, nor a hard deadline (Codex M1 R1 #1)
  const parent = process.ppid;
  setInterval(() => {
    try {
      process.kill(parent, 0);
    } catch {
      process.exit(0);
    }
  }, 200).unref();
  setTimeout(() => process.exit(0), 60_000).unref();
}
if (a.includes("--version")) {
  process.stdout.write(process.env.FAKE_ANVIL_VERSION);
  process.exit(0);
}
if (process.env.FAKE_ANVIL_SERVE) {
  // answers like a fork whose head is the read-back block; every other read is "nothing there"
  const { createServer } = await import("node:http");
  const port = Number(a[a.indexOf("--port") + 1]);
  const h = JSON.parse(process.env.FAKE_ANVIL_SERVE);
  createServer((req, rsp) => {
    let b = "";
    req.on("data", c => (b += c));
    req.on("end", () => {
      const all = [].concat(JSON.parse(b));
      for (const m of all)
        fs.appendFileSync(process.env.FAKE_ANVIL_RPCLOG, JSON.stringify([m.method, m.params ?? []]) + "\\n");
      const one = m => {
        const r =
          m.method === "eth_blockNumber"
            ? "0x" + h.readbackBlock.toString(16)
            : m.method === "eth_getBlockByNumber"
              ? { number: "0x" + h.readbackBlock.toString(16), hash: h.readbackBlockHash }
              : m.method === "eth_chainId"
                ? "0x" + h.chainId.toString(16)
                : m.method === "eth_call" || m.method === "eth_getCode"
                  ? "0x"
                  : m.method === "eth_getStorageAt"
                    ? "0x" + "0".repeat(64)
                    : m.method === "eth_getLogs"
                      ? []
                      : m.method === "evm_snapshot"
                        ? "0x1"
                        : m.method === "evm_revert"
                          ? true
                          : null;
        return { jsonrpc: "2.0", id: m.id, result: r };
      };
      rsp.setHeader("content-type", "application/json");
      const out = all.map(one);
      rsp.end(JSON.stringify(Array.isArray(JSON.parse(b)) ? out : out[0]));
    });
  }).listen(port, "127.0.0.1");
  setInterval(() => {}, 1000); // keep serving until killed or orphaned
} else {
  process.stderr.write(process.env.FAKE_ANVIL_ERR ?? "");
  process.exit(1);
}
`
    );
    fs.chmodSync(fakeAnvil, 0o755);
    const goodVersion = `anvil Version: 1.8.7-nightly\nCommit SHA: ${PIN}\n`;
    const args = port => [
      "--dump",
      dump,
      "--dump-sha256",
      dumpSha,
      "--readback",
      rbPath,
      "--fund",
      "0x" + "11".repeat(20),
      "--schema",
      join(here, "fixtures/a7/aoa-a7-readback-1.schema.json"),
      "--abi-dir",
      abiDir,
      "--port",
      String(port),
    ];
    const sepolia = await serve(m =>
      m === "eth_chainId"
        ? "0xaa36a7"
        : m === "eth_blockNumber"
          ? "0x" + (rb.header.forkBlock - 1).toString(16)
          : null
    ); // one below forkBlock
    const sepoliaAt = await serve(m =>
      m === "eth_chainId"
        ? "0xaa36a7"
        : m === "eth_blockNumber"
          ? "0x" + rb.header.forkBlock.toString(16)
          : null
    ); // at forkBlock
    const mainnet = await serve(m =>
      m === "eth_chainId" ? "0x1" : "0x" + rb.header.forkBlock.toString(16)
    );
    const busy = await serve(() => "0x7a69");
    const url = p => `http://127.0.0.1:${p}/KEY`;
    const fakeEnv = {
      FAKE_ANVIL_LOG: anvilLog,
      FAKE_ANVIL_PIDS: anvilPids,
      FAKE_ANVIL_RPCLOG: anvilRpc,
    };
    const clearLog = () => fs.rmSync(anvilLog, { force: true });
    const p1 = await freePort();

    clearLog();
    const wrongChain = await runAsync([...args(p1), "--anvil", fakeAnvil], {
      A7_FORK_URL: url(mainnet),
      FAKE_ANVIL_VERSION: goodVersion,
      ...fakeEnv,
    });
    wrongChain.anvilLog = readLog();
    cell(
      "e2e F2: the script stops (exit 1) on an upstream of another chain, before anvil",
      wrongChain.anvilLog === "" &&
        wrongChain.status === EXIT.STOP &&
        wrongChain.err === "a7-fork: the fork RPC is not the read-back's chain (eth_chainId)",
      wrongChain
    );
    clearLog();
    const early = await runAsync([...args(p1), "--anvil", fakeAnvil], {
      A7_FORK_URL: url(sepolia),
      FAKE_ANVIL_VERSION: goodVersion,
      ...fakeEnv,
    });
    early.anvilLog = readLog();
    cell(
      "e2e F2: the script stops (exit 1) on an upstream below header.forkBlock",
      early.anvilLog === "" &&
        early.status === EXIT.STOP &&
        early.err === "a7-fork: the fork RPC does not have header.forkBlock yet",
      early
    );
    clearLog();
    const occupied = await runAsync([...args(busy), "--anvil", fakeAnvil], {
      A7_FORK_URL: url(sepoliaAt),
      FAKE_ANVIL_VERSION: goodVersion,
      ...fakeEnv,
    });
    occupied.anvilLog = readLog();
    cell(
      "e2e N1: the script stops (exit 1) when --port already answers, before anvil",
      occupied.anvilLog === "" &&
        occupied.status === EXIT.STOP &&
        occupied.err ===
          `a7-fork: something already listens on --port ${busy}: refusing to compare against it`,
      occupied
    );
    const noAnvil = await runAsync([...args(p1), "--anvil", join(d, "missing")], {
      A7_FORK_URL: url(sepoliaAt),
    });
    cell(
      "e2e: an anvil that cannot run is no verdict (exit 3)",
      noAnvil.status === EXIT.NO_VERDICT &&
        noAnvil.err === "a7-fork: anvil not runnable (--anvil <path>)",
      noAnvil
    );
    const otherBuild = await runAsync([...args(p1), "--anvil", fakeAnvil], {
      A7_FORK_URL: url(sepoliaAt),
      FAKE_ANVIL_VERSION: `anvil Version: 1.8.7-nightly\nCommit SHA: ${"a".repeat(40)}\n`,
      ...fakeEnv,
    });
    cell(
      "e2e: another anvil build is refused (exit 1)",
      otherBuild.status === EXIT.STOP && /anvil commit is a{40}, required/.test(otherBuild.err),
      otherBuild
    );
    const crashed = await runAsync([...args(p1), "--anvil", fakeAnvil], {
      A7_FORK_URL: url(sepoliaAt),
      FAKE_ANVIL_VERSION: goodVersion,
      FAKE_ANVIL_ERR: `thread 'main' panicked; fork ${url(sepoliaAt)}`,
      ...fakeEnv,
    });
    cell(
      "e2e N1: the pinned anvil exiting at start is no verdict (exit 3), a fixed category, nothing of its output",
      crashed.status === EXIT.NO_VERDICT &&
        crashed.err ===
          "a7-fork: anvil did not start (it crashed: this build cannot run the read-back's hardfork)" &&
        !crashed.err.includes("KEY") &&
        crashed.out === "",
      crashed
    );
    const pidsBefore = startedPids().length;
    const full = await runAsync([...args(await freePort()), "--anvil", fakeAnvil], {
      A7_FORK_URL: url(sepoliaAt),
      FAKE_ANVIL_VERSION: goodVersion,
      FAKE_ANVIL_SERVE: JSON.stringify(rb.header),
      ...fakeEnv,
    });
    // the anvil the full run started is gone once a7-fork exits (its exit handler, or orphan exit)
    const deadline = Date.now() + 5_000;
    while (startedPids().some(alive) && Date.now() < deadline)
      await new Promise(r => setTimeout(r, 100));
    const leftover = startedPids().filter(alive);
    let rec = null;
    try {
      rec = JSON.parse(full.out);
    } catch {
      // not a record
    }
    cell(
      "e2e: a full run on a fork that is not SP's state ends in the verdict: STOP, exit 1, nothing funded, no URL or key in the record",
      full.status === EXIT.STOP &&
        rec?.verdict === "STOP: the fork is not proven to be SP's state" &&
        rec.funded === null &&
        rec.rpc === null &&
        (rec.failed.length > 0 || rec.unverified.length > 0) &&
        !full.out.includes("KEY") &&
        !full.out.includes("127.0.0.1") &&
        startedPids().length === pidsBefore + 1 &&
        rpcCalls().length > 0 &&
        !rpcCalls().some(([m]) => m === "anvil_setBalance"),
      leftover.length === 0,
      {
        status: full.status,
        err: full.err,
        verdict: rec?.verdict,
        leftover,
        newPids: startedPids().length - pidsBefore,
        setBalance: rpcCalls().filter(([m]) => m === "anvil_setBalance"),
      }
    );
  } finally {
    killAnvils();
    for (const s of servers) s.close();
    fs.rmSync(d, { recursive: true, force: true });
  }
}

// ---- the one wiring the e2e cells cannot reach deterministically (anvil exiting between the
// last read and the verdict is a race): the verdict is given the live child process, and the
// script's exit status is the verdict's
{
  const src = readFileSync(join(here, "a7-fork.mjs"), "utf8");
  const exits = src.match(/process\.exit\([^)]*\)/g) ?? [];
  cell(
    "wiring (structural): verdict gets the anvil child process; the only exits are die()'s and the verdict's",
    /verdict\(\{ cmp, unverified, anvil \}\)/.test(src) &&
      exits.length === 2 &&
      exits.includes("process.exit(code)") &&
      exits.includes("process.exit(exitCode)"),
    exits
  );
}

let failed = 0;
for (const r of results) {
  console.log(`${r.ok ? "ok  " : "FAIL"} ${r.name}${r.ok ? "" : `\n     got ${r.got}`}`);
  if (!r.ok) failed++;
}
console.log(`\n${results.length - failed}/${results.length} cells`);
process.exit(failed ? 1 : 0);
