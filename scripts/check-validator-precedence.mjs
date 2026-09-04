// Validator-resolution precedence: the three committee tools must agree on WHICH CONTRACT
// they are watching, in every configuration.
//
// WHY THIS EXISTS
//
// #283 removed a hard-coded fallback to 0x1A8Db639…cd64 — by then the RETIRED pre-D2 validator —
// from committee-keeper.mjs and committee-proofgen.mjs, and replaced it with one rule:
//
//     EXPLICIT (process environment / --validator)  >  derived from the router  >  env FILE  >  fail
//
// The rule is deliberate in both directions. A validator set in the ENVIRONMENT is a deliberate act
// and outranks a router. One left behind in an env FILE is not: deleting a repository variable does
// not reach a stale .env.sepolia sitting next to a developer, and letting that quietly win
// reintroduces "pinned to an address nobody mounts" — harder to see, because the router would look
// configured. The tool that follows a stale value is the one that SENDS TRANSACTIONS.
//
// That rule is hand-copied into three files with three different shapes, and it was verified ONCE,
// by hand, in the PR that introduced it. That is not a regression test — it is an anecdote. The same
// PR proves the point twice over:
//
//   * the first attempt let an env-FILE value outrank the router in the keeper while the PR body
//     claimed it mirrored committee-health.mjs, which does the opposite. Caught by review, not by
//     anything in the repo;
//   * the two resolvers were byte-identical one commit, and 822-vs-773 characters the next, because
//     FatalConfigError was added to one of them. Caught by a one-time manual diff.
//
// Nothing turns red when they drift. This does.
//
// WHAT IT MEASURES, AND HOW
//
// Not the source text — the BEHAVIOUR. Each tool runs as a real subprocess against a stub JSON-RPC
// server that records the address of every contract it dials. The resolved validator is therefore
// observed from the wire, the same way the chain would see it, rather than parsed out of a log line
// each tool happens to format differently (proofgen does not log it at all).
//
// Six cells, and cells 1, 5 and 6 are the controls. Without cell 5 this check would pass if someone
// "fixed" the precedence by ignoring the env file entirely; without cells 1 and 6 it would pass if a
// hard-coded default came back.
//
// Usage: node scripts/check-validator-precedence.mjs   (exit 0 = the three agree everywhere)
import { createServer } from "http";
import { mkdtempSync, writeFileSync, rmSync } from "fs";
import { tmpdir } from "os";
import { join, resolve, dirname } from "path";
import { fileURLToPath } from "url";
import { spawn } from "child_process";

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "..");

// Distinct, recognisable, and deliberately NOT any address the repo would produce on its own, so a
// tool that resolves one of these can only have got it from the cell's configuration.
const V_ENV = "0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE";
const V_FILE = "0xfF11ff11ff11fF11Ff11FF11ff11Ff11FF11fF11";
const V_ROUTER = "0x7ac7E9D4c9dD0F6c6C1b0F0A3Ab2cf4E5D6a7b8c";
const ROUTER = "0x1111111111111111111111111111111111111111";
const ROUTER_EMPTY = "0x2222222222222222222222222222222222222222";
// The address #283 removed. It must never be reachable again from an unconfigured run.
const RETIRED = "0x1A8Db639b5d8Bd5742edB083656EDD56f416cd64";

const SEL_GET_ALGORITHM = "0xacfff8f6"; // getAlgorithm(uint8)
const SEL_EPOCH_LENGTH = "0x57d775f8"; // epochLength()

const word = hex => hex.replace(/^0x/, "").toLowerCase().padStart(64, "0");
const addrWord = a => "0x" + word(a);
const ZERO32 = "0x" + "0".repeat(64);

/// Stub chain. It answers just enough for each tool to get PAST resolution and dial the validator —
/// epochLength() returns 0 ("committee mode OFF"), which every tool treats as a clean idle, so no
/// cell needs a funded key, a real contract, or the network.
function startStubRpc() {
  const dialed = [];
  const server = createServer((req, res) => {
    let body = "";
    req.on("data", c => (body += c));
    req.on("end", () => {
      let reqs;
      try {
        reqs = JSON.parse(body);
      } catch {
        res.writeHead(400).end("{}");
        return;
      }
      const one = r => {
        const { method, params = [], id } = r;
        const ok = result => ({ jsonrpc: "2.0", id, result });
        switch (method) {
          case "eth_chainId":
            return ok("0xaa36a7");
          case "net_version":
            return ok("11155111");
          case "eth_blockNumber":
            return ok("0x1000");
          case "eth_getBlockByNumber":
          case "eth_getBlockByHash":
            return ok({
              number: "0x1000",
              hash: "0x" + "ab".repeat(32),
              parentHash: "0x" + "cd".repeat(32),
              timestamp: "0x66000000",
              transactions: [],
              gasLimit: "0x1c9c380",
              gasUsed: "0x0",
              miner: "0x" + "00".repeat(20),
              extraData: "0x",
              baseFeePerGas: "0x1",
            });
          case "eth_getCode":
            // Non-empty so ethers does not shortcut, and deliberately WITHOUT the D2 selector, so
            // the keeper takes its legacy branch. Which branch it takes is irrelevant here; that it
            // asked about a particular ADDRESS is the measurement.
            dialed.push({ kind: "getCode", to: (params[0] || "").toLowerCase() });
            return ok("0x60006000fd");
          case "eth_call": {
            const to = (params[0]?.to || "").toLowerCase();
            const data = params[0]?.data || "0x";
            const sel = data.slice(0, 10);
            dialed.push({ kind: "call", to, sel });
            if (sel === SEL_GET_ALGORITHM) {
              // The router under test resolves algId 0x01; the "empty" router mounts nothing.
              if (to === ROUTER.toLowerCase()) return ok(addrWord(V_ROUTER));
              if (to === ROUTER_EMPTY.toLowerCase()) return ok(ZERO32);
              return ok(ZERO32);
            }
            if (sel === SEL_EPOCH_LENGTH) return ok(ZERO32); // committee OFF -> every tool idles
            return ok(ZERO32);
          }
          default:
            return ok(null);
        }
      };
      const out = Array.isArray(reqs) ? reqs.map(one) : one(reqs);
      res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify(out));
    });
  });
  return new Promise(r =>
    server.listen(0, "127.0.0.1", () =>
      r({ url: `http://127.0.0.1:${server.address().port}`, dialed, close: () => server.close() })
    )
  );
}

function run(cmd, args, { cwd, env }) {
  return new Promise(done => {
    const p = spawn(cmd, args, {
      cwd,
      env,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let out = "";
    p.stdout.on("data", d => (out += d));
    p.stderr.on("data", d => (out += d));
    // Nothing here should take long: every cell either fails on configuration or idles on
    // epochLength == 0. A cell that hangs is a failure, not something to wait out.
    const kill = setTimeout(() => p.kill("SIGKILL"), 25000);
    p.on("close", code => {
      clearTimeout(kill);
      done({ code, out });
    });
  });
}

/// The validator a tool actually watched: the first address it dialed that is not a router. Reading
/// it from the wire rather than from stdout is what makes this uniform across the three tools.
function resolvedFrom(dialed) {
  const routers = new Set([ROUTER.toLowerCase(), ROUTER_EMPTY.toLowerCase()]);
  const hit = dialed.find(d => d.to && !routers.has(d.to));
  return hit ? hit.to : null;
}

const CELLS = [
  {
    name: "1. nothing configured -> fails loudly, and the RETIRED default does not come back",
    file: {},
    penv: {},
    expect: null,
  },
  {
    name: "2. router only -> all three derive algId 0x01",
    file: {},
    penv: { COMMITTEE_ROUTER: ROUTER },
    expect: V_ROUTER,
  },
  {
    name: "3. process-env validator + router -> the explicit one wins",
    file: {},
    penv: { COMMITTEE_VALIDATOR: V_ENV, COMMITTEE_ROUTER: ROUTER },
    expect: V_ENV,
  },
  {
    name: "4. env-FILE validator + router -> the ROUTER wins (the #283 regression)",
    file: { COMMITTEE_VALIDATOR: V_FILE },
    penv: { COMMITTEE_ROUTER: ROUTER },
    expect: V_ROUTER,
  },
  {
    name: "5. CONTROL: env-FILE validator, no router -> the file value IS used",
    file: { COMMITTEE_VALIDATOR: V_FILE },
    penv: {},
    expect: V_FILE,
  },
  {
    name: "6. CONTROL: router with nothing mounted at 0x01 -> fails loudly, no fallback",
    file: {},
    penv: { COMMITTEE_ROUTER: ROUTER_EMPTY },
    expect: null,
  },
];

const rpc = await startStubRpc();
const failures = [];
// Guard against a check that proves nothing because every cell reached the same answer, or because
// no cell ever resolved anything at all.
const observed = new Set();

console.log(`stub chain on ${rpc.url}\n`);

for (const cell of CELLS) {
  console.log(cell.name);
  const dir = mkdtempSync(join(tmpdir(), "dvt-precedence-"));
  writeFileSync(
    join(dir, ".env.sepolia"),
    // KEEPER_PRIVATE_KEY is a well-known throwaway (hardhat account #0). The keeper builds a Wallet
    // before it resolves, so a cell without one would die on ethers rather than on precedence.
    [
      `SEPOLIA_RPC_URL=${rpc.url}`,
      "KEEPER_PRIVATE_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
      ...Object.entries(cell.file).map(([k, v]) => `${k}=${v}`),
    ].join("\n") + "\n"
  );

  // The three tools do not take their configuration the same way, and that asymmetry is itself worth
  // stating: keeper and proofgen read `.env.sepolia` RELATIVE TO CWD and offer no override, while
  // health resolves it next to the script and accepts --env. So each is given its env file the only
  // way it accepts one -- if that ever unifies, this is the only place that needs to change.
  const base = { ...process.env };
  for (const k of [
    "COMMITTEE_VALIDATOR",
    "COMMITTEE_ROUTER",
    "SEPOLIA_RPC_URL",
    "ETH_RPC_URL",
    "RPC_URL",
    "DVT_ENV_FILE",
  ])
    delete base[k];
  const env = { ...base, ...cell.penv };

  const tools = [
    { tool: "keeper", cwd: dir, args: [join(REPO, "deploy/committee-keeper.mjs")] },
    { tool: "proofgen", cwd: dir, args: [join(REPO, "deploy/committee-proofgen.mjs"), "0"] },
    {
      tool: "health",
      cwd: REPO,
      args: [join(REPO, "deploy/committee-health.mjs"), "--env", join(dir, ".env.sepolia")],
    },
  ];

  const answers = {};
  for (const t of tools) {
    rpc.dialed.length = 0;
    const { code, out } = await run(process.execPath, t.args, { cwd: t.cwd, env });
    const got = resolvedFrom(rpc.dialed);
    answers[t.tool] = got;
    if (got) observed.add(got);

    const want = cell.expect ? cell.expect.toLowerCase() : null;
    const shown = got ?? "(none — resolution refused)";
    let verdict;
    if (want === null) {
      // "Fails loudly" is two claims: it dialed no validator, AND it did not exit 0 pretending
      // everything was fine. committee-health signals a configuration problem as UNKNOWN/exit 2.
      const loud = got === null && code !== 0;
      verdict = loud ? "ok  " : "FAIL";
      if (!loud)
        failures.push(
          `${cell.name}\n    ${t.tool}: expected a loud refusal, got validator=${shown} exit=${code}\n${out.trim().slice(0, 600)}`
        );
    } else {
      const match = got === want;
      verdict = match ? "ok  " : "FAIL";
      if (!match)
        failures.push(
          `${cell.name}\n    ${t.tool}: expected ${cell.expect}, watched ${shown} (exit ${code})\n${out.trim().slice(0, 600)}`
        );
    }
    // The retired address must not appear on the wire OR in the output, in any cell that did not
    // ask for it. A tool that merely PRINTS it is a monitor lying about its observation target.
    if (out.toLowerCase().includes(RETIRED.toLowerCase()) || got === RETIRED.toLowerCase()) {
      failures.push(`${cell.name}\n    ${t.tool}: the RETIRED validator ${RETIRED} came back`);
      verdict = "FAIL";
    }
    console.log(`  ${verdict} ${t.tool.padEnd(9)} -> ${shown}  (exit ${code})`);
  }

  // The point of the rule is AGREEMENT. A cell where all three are wrong in the same way is caught
  // by the expectation above; this catches the case the expectation cannot see -- three tools that
  // each look defensible alone and disagree with each other.
  const distinct = new Set(Object.values(answers).map(v => v ?? "none"));
  if (distinct.size !== 1) {
    failures.push(`${cell.name}\n    the three tools DISAGREE: ${JSON.stringify(answers)}`);
    console.log(`  FAIL agreement -> ${JSON.stringify(answers)}`);
  }

  rmSync(dir, { recursive: true, force: true });
  console.log("");
}

rpc.close();

// A green run must have exercised the machinery, not just found six ways to refuse.
if (observed.size < 3) {
  failures.push(
    `the check proved nothing: only ${observed.size} distinct validator(s) were ever resolved ` +
      `(${[...observed].join(", ") || "none"}). Expected the env, file and router answers to differ.`
  );
}

if (failures.length) {
  console.error(`\n✗ validator-precedence check FAILED (${failures.length})\n`);
  for (const f of failures) console.error(`  - ${f}\n`);
  process.exit(1);
}
console.log(
  `validator-precedence check OK — 6 cells x 3 tools, ${observed.size} distinct answers observed, ` +
    `keeper/proofgen/health agree in every cell.`
);
