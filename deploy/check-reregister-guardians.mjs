// Cells for deploy/reregister-guardians.mjs that need no chain (DSR 2026-11-18, after Daybreak on
// 63a484d0 found a High in the --broadcast path, which is now disabled).
//
// The pinned property: with --broadcast anywhere on the command line the script exits 1 with the
// "disabled" message BEFORE it reads any file (env file, deployment file, node files with their BLS
// secrets) and before it sends any RPC request. A preload wraps fs.readFileSync / fs.openSync and
// records every path it is asked for; a local HTTP server counts every request it receives.
// The CONTROL runs the same command without --broadcast and must show both recorders working: the
// env and deployment files are read and the RPC server receives requests.
import { spawn } from "child_process";
import { createServer } from "http";
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from "fs";
import { tmpdir } from "os";
import { dirname, join, resolve } from "path";
import { fileURLToPath } from "url";

import * as acorn from "acorn";
import * as walk from "acorn-walk";
import { keyEnds, fieldShape, pubKeyShape, nodeNameShape } from "./lib/redact.mjs";
import { aggregatorSourceVersion } from "./lib/sp-source.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const SCRIPT = join(HERE, "reregister-guardians.mjs");
const REPO = dirname(HERE);
// the script's local imports, loaded as modules
const LOCAL_IMPORTS = new Set([
  join(HERE, "lib", "redact.mjs"),
  join(HERE, "lib", "sp-source.mjs"),
]);
let pass = 0;
let fail = 0;
const cell = (name, ok, detail = "") => {
  if (ok) pass++;
  else fail++;
  console.log(`${ok ? "PASS" : "FAIL"} ${name}${ok || !detail ? "" : `\n     ${detail}`}`);
};

const dir = mkdtempSync(join(tmpdir(), "check-reregister-"));
const readsLog = join(dir, "reads.log");
// Preload: record every path any public fs read/open API is asked for — sync, callback and promise
// forms, string, Buffer or URL paths (Codex on the #444 delta, M2) — then make the ESM named imports
// of "fs" and "fs/promises" see the wrapped functions (syncBuiltinESMExports).
const preload = join(dir, "record-reads.mjs");
writeFileSync(
  preload,
  `import fs from "fs";
import { fileURLToPath } from "url";
import { syncBuiltinESMExports } from "module";
const log = ${JSON.stringify(readsLog)};
const append = fs.appendFileSync;
const asPath = p =>
  typeof p === "string" ? p : p instanceof URL ? fileURLToPath(p) : Buffer.isBuffer(p) ? p.toString() : null;
const wrap = (obj, names) => {
  for (const name of names) {
    const orig = obj[name];
    if (typeof orig !== "function") continue;
    obj[name] = function (p, ...rest) {
      const s = asPath(p);
      if (s !== null && s !== log) append(log, s + "\\n");
      return orig.call(this, p, ...rest);
    };
  }
};
wrap(fs, ["readFileSync", "openSync", "readFile", "open", "createReadStream", "readdirSync", "readdir", "opendirSync", "opendir", "statSync", "stat", "lstatSync", "lstat", "existsSync", "accessSync", "access"]);
wrap(fs.promises, ["readFile", "open", "readdir", "opendir", "stat", "lstat", "access"]);
syncBuiltinESMExports();
`
);

const requests = [];
const server = createServer((req, res) => {
  let body = "";
  req.on("data", c => (body += c));
  req.on("end", () => {
    requests.push(body);
    // ethers batches requests: answer each. Chain 1, never the expected 31337, so a control run
    // stops at the network gate and sends nothing.
    const answer = one => {
      const m = one?.method ?? "";
      const result = m === "eth_chainId" ? "0x1" : m === "net_version" ? "1" : "0x1";
      return { jsonrpc: "2.0", id: one?.id ?? 1, result };
    };
    let reply;
    try {
      const j = JSON.parse(body);
      reply = Array.isArray(j) ? j.map(answer) : answer(j);
    } catch {
      reply = answer(null);
    }
    res.setHeader("content-type", "application/json");
    res.end(JSON.stringify(reply));
  });
});
await new Promise(r => server.listen(0, "127.0.0.1", r));
const rpc = `http://127.0.0.1:${server.address().port}`;

const envFile = join(dir, "test.env");
// A throwaway value only, never a real key (anvil's well-known account 0, chain 31337).
writeFileSync(
  envFile,
  `RPC_URL=${rpc}\nREREGISTER_OWNER_PRIVATE_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80\n`,
  { mode: 0o600 }
);
const deployment = join(dir, "deployment.json");
writeFileSync(
  deployment,
  JSON.stringify({
    dvtValidator: "0x00000000000000000000000000000000000000d1",
    blsAggregator: "0x00000000000000000000000000000000000000a1",
  })
);
const nodeFile = join(dir, "node_test_1.json");
writeFileSync(nodeFile, "{}", { mode: 0o600 });

// Async, so the local RPC server can answer while the script runs.
const run = args =>
  new Promise(res => {
    rmSync(readsLog, { force: true });
    requests.length = 0;
    const c = spawn(process.execPath, ["--import", preload, SCRIPT, ...args], {
      env: { PATH: process.env.PATH, HOME: dir },
      // cwd is the temp dir, so the script's relative defaults (.env.sepolia, node_dev_00N.json)
      // resolve there and are recorded like any other read
      cwd: dir,
    });
    let stderr = "";
    let stdout = "";
    c.stderr.on("data", d => (stderr += d));
    c.stdout.on("data", d => (stdout += d));
    const t = setTimeout(() => c.kill("SIGKILL"), 60_000);
    c.on("close", status => {
      clearTimeout(t);
      let reads = [];
      try {
        reads = readFileSync(readsLog, "utf8").split("\n").filter(Boolean);
      } catch {
        reads = [];
      }
      res({ status, stderr, stdout, reads, rpcRequests: requests.length });
    });
  });
const common = [
  "--deployment",
  deployment,
  "--env",
  envFile,
  "--nodes",
  nodeFile,
  "--chain-id",
  "31337",
  "--expect-versions",
  "BLSAggregator-4.14.2,DVTValidator-0.9.0",
  "--expect-owner",
  "0x00000000000000000000000000000000000000e1",
];
const ours = r => r.reads.filter(p => p.startsWith(dir) && p !== preload);
// Every path except module loading, which node's loader does through the same wrapped fs: the script
// itself, its one local import deploy/lib/redact.mjs, and node_modules. Nothing else in the repository is exempt, so a read of an in-repo env or
// node file by absolute path still counts (Codex on the #444 delta, round 2).
// Paths are resolved first, against the child's cwd (the temp dir), so neither
// "node_modules/../.env.sepolia" nor a relative "node_modules/x.json" is exempt (Codex, rounds 3-4).
const isModuleLoad = p => {
  const r = resolve(dir, p);
  return r === SCRIPT || LOCAL_IMPORTS.has(r) || r.startsWith(join(REPO, "node_modules") + "/");
};
const notCode = r => r.reads.filter(p => p !== preload && !isModuleLoad(p));

for (const [what, args] of [
  ["first", ["--broadcast", ...common]],
  ["last", [...common, "--broadcast"]],
  ["with --export-pop", [...common, "--export-pop", join(dir, "out.json"), "--broadcast"]],
]) {
  const r = await run(args);
  cell(
    `--broadcast (${what}) exits 1 with the rc.8 "disabled" message`,
    r.status === 1 && /--broadcast is disabled in rc\.8/.test(r.stderr),
    `status ${r.status} stderr ${r.stderr.slice(0, 300)}`
  );
  cell(
    `--broadcast (${what}) reads no file at all (env, deployment, node files or any other path)`,
    notCode(r).length === 0,
    `read: ${notCode(r).join(", ")}`
  );
  cell(
    `--broadcast (${what}) sends no RPC request`,
    r.rpcRequests === 0,
    `${r.rpcRequests} request(s)`
  );
}

// clestons #444 Low 3: a zero --expect-owner stops at the argument checks, before any read.
{
  const args = common.map(a =>
    a === "0x00000000000000000000000000000000000000e1"
      ? "0x0000000000000000000000000000000000000000"
      : a
  );
  const r = await run(args);
  cell(
    "--expect-owner 0x0 exits 1 before reading any file or sending any RPC request",
    r.status === 1 &&
      /--expect-owner needs a non-zero address/.test(r.stderr) &&
      notCode(r).length === 0 &&
      r.rpcRequests === 0,
    `status ${r.status} stderr ${r.stderr.slice(0, 200)} read ${notCode(r).join(", ")}`
  );
}

// CONTROL: the same command without --broadcast. Both recorders must see the run.
{
  const r = await run(common);
  const mine = ours(r);
  cell(
    "CONTROL without --broadcast the read recorder sees the env and deployment files",
    mine.includes(envFile) && mine.includes(deployment),
    `read: ${mine.join(", ")}`
  );
  cell(
    "CONTROL without --broadcast the RPC server receives requests, and the run stops at the network gate",
    r.rpcRequests > 0 && /wrong network: connected to chainId 1, expected 31337/.test(r.stderr),
    `${r.rpcRequests} request(s), status ${r.status}, stderr ${r.stderr.slice(0, 300)}`
  );
  cell(
    "CONTROL nothing from the env file but the RPC url is printed (the throwaway key is not)",
    !/ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80/i.test(r.stderr + r.stdout),
    (r.stderr + r.stdout).slice(0, 300)
  );
}

// CONTROL for the exemption: in-repository data files are not exempt, only module loading is.
cell(
  "CONTROL the module-load exemption does not cover in-repository env or node files",
  notCode({
    reads: [
      join(REPO, ".env.sepolia"),
      join(REPO, "node_dev_001.json"),
      join(REPO, "deploy", "x.json"),
      `${REPO}/node_modules/../.env.sepolia`,
      "node_modules/data.json",
      "deploy/reregister-guardians.mjs",
      SCRIPT,
      join(REPO, "node_modules", "ethers", "package.json"),
    ],
  }).length === 6
);

// CONTROL for the recorder itself: a probe reads three fixture files through fs/promises, the
// callback form and a URL path; each must be recorded (otherwise "reads no file" could be vacuous).
{
  const probe = join(dir, "probe.mjs");
  const [a, b, c] = ["p1.txt", "p2.txt", "p3.txt"].map(f => join(dir, f));
  for (const f of [a, b, c]) writeFileSync(f, "x");
  writeFileSync(
    probe,
    `import { readFile } from "fs/promises";
import * as fs from "fs";
import { pathToFileURL } from "url";
await readFile(${JSON.stringify(a)});
await new Promise(r => fs.readFile(${JSON.stringify(b)}, r));
fs.readFileSync(pathToFileURL(${JSON.stringify(c)}));
`
  );
  rmSync(readsLog, { force: true });
  const r = await new Promise(res => {
    const ch = spawn(process.execPath, ["--import", preload, probe], { cwd: dir });
    ch.on("close", status => res(status));
  });
  let reads = [];
  try {
    reads = readFileSync(readsLog, "utf8").split("\n").filter(Boolean);
  } catch {
    reads = [];
  }
  cell(
    "CONTROL the recorder sees fs/promises, callback and URL reads",
    r === 0 && [a, b, c].every(f => reads.includes(f)),
    `status ${r}, recorded ${reads.filter(x => x.startsWith(dir)).join(", ")}`
  );
}

// What a node-file value may print as (clestons #460 Lows 1-2): no part of a pasted secret, through
// any of the shapes, and no raw node-file field interpolated anywhere in the script.
{
  const secret = "0x" + "3f9a1c7e5b2d4086".repeat(4); // a throwaway 32-byte value
  const body = secret.slice(2);
  const pieces = [];
  for (let i = 0; i + 6 <= body.length; i++) pieces.push(body.slice(i, i + 6));
  const leaks = out => pieces.some(p => out.toLowerCase().includes(p));
  const outs = [
    fieldShape(secret),
    fieldShape(body),
    pubKeyShape(secret),
    nodeNameShape(secret),
    fieldShape(secret + secret),
    nodeNameShape("\u001b[2J" + secret),
  ];
  cell(
    "redact: a 32-byte secret in any node-file field prints no 6-hex-digit piece of it",
    outs.every(o => !leaks(o)),
    outs.join(" | ")
  );
  const pk = "0x" + "ab".repeat(128);
  cell(
    "redact: a well-formed 128-byte public key prints its ends only; small slots and names as they are",
    pubKeyShape(pk) === keyEnds(pk) &&
      pubKeyShape(pk).length < 40 &&
      fieldShape(2) === "2" &&
      fieldShape("3") === '"3"' &&
      nodeNameShape("dev-1") === "dev-1" &&
      nodeNameShape(undefined) === "?",
    `${pubKeyShape(pk)} ${fieldShape(2)} ${fieldShape("3")} ${nodeNameShape("dev-1")}`
  );
  cell(
    "redact: other types and control characters print only their shape",
    [true, null, { k: secret }, [secret], 1e21, 12345, "a\u202eb", "x\u009b"].every(v =>
      /^<\w+(, value withheld| chars, value withheld)>$|^<\d+ chars, value withheld>$/.test(
        fieldShape(v)
      )
    ) && nodeNameShape("n\u001b[2Jx") === "<6 chars, value withheld>",
    [true, null, 1e21, "a\u202eb"].map(fieldShape).join(" | ")
  );
  // Structural (Codex on this PR, rounds 1-2): parse the script and look at every call that prints
  // or writes — die(), fail(), console.*(), new Error(), writeFileSync(). Inside their arguments,
  // every use of the node-file object `node` must sit inside a redact.mjs shape call. This sees
  // interpolation, concatenation, bracket access, extra arguments and JSON.stringify alike. It does
  // NOT follow aliases (`const x = node.privateKey; die(x)`), and it trusts the shape names without
  // resolving their bindings (a local function shadowing `fieldShape` would pass); both are left to
  // review.
  const leaksIn = code => {
    const ast = acorn.parse(code, { ecmaVersion: "latest", sourceType: "module" });
    const found = [];
    const SHAPE = new Set(["fieldShape", "pubKeyShape", "nodeNameShape", "keyEnds"]);
    const isSink = n =>
      (n.type === "CallExpression" &&
        ((n.callee.type === "Identifier" &&
          ["die", "fail", "writeFileSync"].includes(n.callee.name)) ||
          (n.callee.type === "MemberExpression" &&
            n.callee.object.type === "Identifier" &&
            n.callee.object.name === "console"))) ||
      (n.type === "NewExpression" && n.callee.type === "Identifier" && n.callee.name === "Error");
    walk.fullAncestor(ast, (n, _state, ancestors) => {
      if (n.type !== "Identifier" || n.name !== "node") return;
      const path = ancestors.slice(0, -1);
      const sinkAt = path.findLastIndex(isSink);
      if (sinkAt < 0) return;
      // only inside the sink's arguments, not its callee (console[node.x](…) prints no node value)
      if (!(path[sinkAt].arguments ?? []).includes(path[sinkAt + 1] ?? n)) return;
      const inShape = path
        .slice(sinkAt + 1)
        .some(
          a =>
            a.type === "CallExpression" &&
            a.callee.type === "Identifier" &&
            SHAPE.has(a.callee.name)
        );
      if (!inShape) found.push(code.slice(path[sinkAt].start, path[sinkAt].end).slice(0, 80));
    });
    return found;
  };
  const found = leaksIn(readFileSync(SCRIPT, "utf8"));
  cell(
    "redact: reregister-guardians.mjs passes no node-file value to an output call except through a redact.mjs shape (AST)",
    found.length === 0,
    found.join(" | ")
  );
  // CONTROL: each form, on its own, is caught; a shape-wrapped one is not.
  const forms = {
    interpolation: "die(`x ${node.privateKey}`)",
    "shape then raw in one interpolation": "die(`x ${(fieldShape(node.slot), node.privateKey)}`)",
    bracket: "die(`x ${node[k]}`)",
    "concatenation, node first": 'die(node.privateKey + " suffix")',
    "concatenation, node second": 'die("x " + node.slot)',
    "extra console argument": 'console.log("node:", node.privateKey)',
    "console of the object": "console.error(node)",
    "JSON.stringify inside a sink": "writeFileSync(f, JSON.stringify(node))",
    "new Error": "throw new Error(`bad ${node.slot}`)",
  };
  const notLeaks = [
    'console[node.k]("constant")',
    "die(`x ${fieldShape(node.slot)} ${nodeNameShape(node.nodeName)}`)",
  ];
  const missed = Object.entries(forms)
    .filter(([, c]) => leaksIn(c).length === 0)
    .map(([k]) => k);
  cell(
    "CONTROL the AST scan catches each raw form on its own, and passes a shape-wrapped one",
    missed.length === 0 && notLeaks.every(c => leaksIn(c).length === 0),
    `missed: ${missed.join(", ")}; flagged: ${notLeaks.filter(c => leaksIn(c).length).join(", ")}`
  );
}

// --plan's two input shapes (DSR 2026-11-18): SP's manifest plan (no schema, pin.oldAggregator) and
// DeployLive's deploylive-pop-request/1 (fresh deploy). These checks run before any chain read, so
// the local RPC (chain 1) is enough; each request must stop for its own reason.
{
  const COMMIT = "ab".repeat(20);
  const A = n => "0x" + String(n).repeat(40);
  const base = () => ({
    schema: "deploylive-pop-request/1",
    chainId: 1,
    spCommit: COMMIT,
    addresses: { BLSAggregator: A(1), DVTValidator: A(2), Registry: A(3) },
    pin: {
      block: 1,
      blockHash: "0x" + "11".repeat(32),
      senders: { deployer: { address: A(4), nonce: 0 } },
    },
    guardianCount: 1,
  });
  const cases = {
    "another schema": [
      r => ((r.schema = "deploylive-pop-request/2"), r),
      /is not "deploylive-pop-request\/1"/,
    ],
    "a fresh request with pin.oldAggregator": [
      r => ((r.pin.oldAggregator = A(5)), r),
      /has no pin\.oldAggregator/,
    ],
    "a fresh request without addresses.Registry": [
      r => (delete r.addresses.Registry, r),
      /addresses must have exactly the keys BLSAggregator, DVTValidator, Registry/,
    ],
    "another chainId": [r => ((r.chainId = 11155111), r), /but this RPC is chain 1/],
    "another spCommit": [r => ((r.spCommit = "cd".repeat(20)), r), /but --sp-commit is/],
    "the same spCommit in uppercase (popContext must echo it exactly)": [
      r => ((r.spCommit = COMMIT.toUpperCase()), r),
      /but --sp-commit is/,
    ],
    "guardianCount 0": [r => ((r.guardianCount = 0), r), /not an integer in 1\.\.13/],
    "guardianCount 2 with 1 node file": [
      r => ((r.guardianCount = 2), r),
      /guardianCount is 2, --nodes names 1/,
    ],
    "a manifest plan (no schema) naming addresses.Registry": [
      r => (delete r.schema, (r.pin.oldAggregator = A(5)), r),
      /belongs to a deploylive-pop-request\/1 request; this plan has no schema/,
    ],
  };
  const failed = [];
  for (const [name, [mutate, want]] of Object.entries(cases)) {
    const req = join(dir, `request-${Object.keys(cases).indexOf(name)}.json`);
    writeFileSync(req, JSON.stringify(mutate(base())));
    const r = await run([
      "--plan",
      req,
      "--sp-aggregator-source",
      join(dir, "absent.sol"),
      "--sp-commit",
      COMMIT,
      "--nodes",
      nodeFile,
      "--env",
      envFile,
      "--chain-id",
      "1",
      "--export-pop",
      join(dir, "out.json"),
    ]);
    if (!(r.status === 1 && want.test(r.stderr)))
      failed.push(`${name}: ${r.stderr.trim().split("\n")[0]}`);
  }
  cell(
    "plan: each malformed fresh-deploy request (or a schema-less plan naming a Registry) stops for its own reason",
    failed.length === 0,
    failed.join(" | ")
  );
  // CONTROL: the well-formed request passes every shape check and stops later, at the source file.
  const okReq = join(dir, "request-ok.json");
  writeFileSync(okReq, JSON.stringify(base()));
  const ok = await run([
    "--plan",
    okReq,
    "--sp-aggregator-source",
    join(dir, "absent.sol"),
    "--sp-commit",
    COMMIT,
    "--nodes",
    nodeFile,
    "--env",
    envFile,
    "--chain-id",
    "1",
    "--export-pop",
    join(dir, "out.json"),
  ]);
  cell(
    "CONTROL a well-formed deploylive-pop-request/1 passes the shape checks (it stops later, at the source file)",
    ok.status === 1 && /cannot read --sp-aggregator-source/.test(ok.stderr),
    ok.stderr.trim().split("\n")[0]
  );
}

// --plan fresh deploy against a FAKE CHAIN (clestons #466 Low 4): eth_getCode answers code only for
// chosen addresses, so the two decisions the shape cells cannot reach are pinned in CI: a request
// whose Registry alone has code stops at gate 1, and a passing export echoes the request exactly.
{
  const { bls12_381: bls } = await import("@noble/curves/bls12-381.js");
  const { ethers } = await import("ethers");
  const BH = "0x" + "22".repeat(32);
  const fake = { code: new Set() };
  const chain = createServer((req, res) => {
    let body = "";
    req.on("data", c => (body += c));
    req.on("end", () => {
      const one = q => {
        const m = q?.method;
        const prm = q?.params ?? [];
        let result = null;
        if (m === "eth_chainId") result = "0x1";
        else if (m === "net_version") result = "1";
        else if (m === "eth_blockNumber") result = "0x10";
        else if (m === "eth_getCode")
          result = fake.code.has(String(prm[0]).toLowerCase()) ? "0x6001" : "0x";
        else if (m === "eth_getTransactionCount") result = "0x5";
        else if (m === "eth_getBlockByNumber")
          result = {
            number: prm[0],
            hash: BH,
            parentHash: "0x" + "33".repeat(32),
            timestamp: "0x1",
            nonce: "0x0000000000000000",
            difficulty: "0x0",
            gasLimit: "0x1c9c380",
            gasUsed: "0x0",
            miner: "0x" + "00".repeat(20),
            extraData: "0x",
            baseFeePerGas: "0x1",
            transactions: [],
          };
        return { jsonrpc: "2.0", id: q?.id ?? 1, result };
      };
      let reply;
      try {
        const j = JSON.parse(body);
        reply = Array.isArray(j) ? j.map(one) : one(j);
      } catch {
        reply = one(null);
      }
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify(reply));
    });
  });
  await new Promise(r => chain.listen(0, "127.0.0.1", r));
  const chainEnv = join(dir, "chain.env");
  writeFileSync(chainEnv, `RPC_URL=http://127.0.0.1:${chain.address().port}\n`, { mode: 0o600 });
  const src = join(dir, "BLSAggregator.sol");
  writeFileSync(
    src,
    `contract BLSAggregator {\n  bytes32 public constant DOMAIN_NAME = keccak256("Test.Domain");\n  bytes32 public constant TAG_POP = keccak256("Test.Pop");\n  function version() external pure returns (string memory) {\n    return "BLSAggregator-4.14.2";\n  }\n}\n`
  );
  const enc = p => {
    const o = new Uint8Array(128),
      a = p.toAffine();
    o.set(ethers.getBytes("0x" + a.x.toString(16).padStart(96, "0")), 16);
    o.set(ethers.getBytes("0x" + a.y.toString(16).padStart(96, "0")), 80);
    return ethers.hexlify(o);
  };
  const nodes = [1, 2].map(i => {
    const sk = bls.utils.randomSecretKey(); // throwaway, generated per run
    const f = join(dir, `fresh_node_${i}.json`);
    writeFileSync(
      f,
      JSON.stringify({
        nodeName: `t${i}`,
        operator: ethers.Wallet.createRandom().address,
        privateKey: ethers.hexlify(sk),
        publicKeyEip2537: enc(bls.longSignatures.getPublicKey(sk)),
      }),
      { mode: 0o600 }
    );
    return f;
  });
  const COMMIT = "ef".repeat(20);
  const addr = n => "0x" + n.repeat(20); // lowercase on purpose: the echo must not re-case it
  const request = () => ({
    schema: "deploylive-pop-request/1",
    chainId: 1,
    spCommit: COMMIT,
    addresses: { BLSAggregator: addr("a1"), DVTValidator: addr("d1"), Registry: addr("e1") },
    pin: { block: 7, blockHash: BH, senders: { deployer: { address: addr("0f"), nonce: 5 } } },
    guardianCount: 2,
  });
  const exportWith = async (req, out) => {
    const f = join(dir, "fresh-request.json");
    writeFileSync(f, JSON.stringify(req));
    return run([
      "--plan",
      f,
      "--sp-aggregator-source",
      src,
      "--sp-commit",
      COMMIT,
      "--nodes",
      nodes.join(","),
      "--env",
      chainEnv,
      "--chain-id",
      "1",
      "--export-pop",
      out,
    ]);
  };
  fake.code = new Set([addr("e1")]);
  const regOnly = await exportWith(request(), join(dir, "fresh-out-1.json"));
  cell(
    "plan (fake chain): a fresh request whose Registry alone has code stops at the no-code gate",
    regOnly.status === 1 && /Registry \(fresh deploy\).*already has code/.test(regOnly.stderr),
    regOnly.stderr.trim().split("\n").slice(-1)[0]
  );
  fake.code = new Set();
  const outFile = join(dir, "fresh-out-2.json");
  const okRun = await exportWith(request(), outFile);
  let ctx = null;
  try {
    ctx = JSON.parse(readFileSync(outFile, "utf8"));
  } catch {
    ctx = null;
  }
  const q = request();
  const c = ctx?.popContext;
  cell(
    "plan (fake chain): a passing fresh export echoes the request exactly (lowercase addresses kept), slots 1..2",
    okRun.status === 0 &&
      c?.aggregator === q.addresses.BLSAggregator &&
      c?.dvt === q.addresses.DVTValidator &&
      c?.registry === q.addresses.Registry &&
      c?.deployerAddress === q.pin.senders.deployer.address &&
      c?.deployerNonce === 5 &&
      c?.pinBlock === 7 &&
      c?.pinBlockHash === BH &&
      c?.spCommit === COMMIT &&
      c?.chainId === 1 &&
      ctx.pop.every(e => e.aggregator === q.addresses.BLSAggregator) &&
      ctx.pop.map(e => e.slot).join() === "1,2" &&
      ctx.aggregatorSourceVersion === "BLSAggregator-4.14.2",
    `status ${okRun.status} ${okRun.stderr.trim().split("\n").slice(-1)[0]} ${JSON.stringify(c)}`
  );
  const dup = request();
  dup.addresses.Registry = dup.addresses.BLSAggregator;
  const extra = request();
  extra.extra = 1;
  const noPrefix = request();
  noPrefix.addresses.Registry = "e1".repeat(20);
  const dvtIsAgg = request();
  dvtIsAgg.addresses.DVTValidator = dvtIsAgg.addresses.BLSAggregator;
  const bad = [];
  for (const [name, req, want] of [
    ["Registry == aggregator", dup, /equals another predicted address/],
    ["an unknown top-level key", extra, /must have exactly the keys/],
    ["an address without 0x", noPrefix, /0x followed by 40 hex digits/],
    [
      "DVTValidator == aggregator",
      dvtIsAgg,
      /addresses\.DVTValidator equals addresses\.BLSAggregator/,
    ],
  ]) {
    const r = await exportWith(req, join(dir, "fresh-out-x.json"));
    if (!(r.status === 1 && want.test(r.stderr)))
      bad.push(`${name}: ${r.stderr.trim().split("\n").slice(-1)[0]}`);
  }
  cell(
    "plan (fake chain): duplicate addresses (incl. DVTValidator == aggregator), unknown keys and un-prefixed addresses stop (clestons #466)",
    bad.length === 0,
    bad.join(" | ")
  );
  chain.close();
}

// --plan's aggregatorSourceVersion (DSR 2026-11-18; Codex): BLSAggregator's own version() body,
// with comments ignored; anything but one plain string-literal return stops the export.
{
  const fn = ret =>
    `  function version() external pure override returns (string memory) {\n    ${ret}\n  }\n`;
  const agg = (ret, extra = "") =>
    `contract BLSAggregator is X {\n  uint256 a;\n${extra}${fn(ret)}}\n`;
  const good = {
    "a plain return": [agg('return "BLSAggregator-4.14.2";'), "BLSAggregator-4.14.2"],
    "a -tag": [agg('return "BLSAggregator-5.0.0-rc.1";'), "BLSAggregator-5.0.0-rc.1"],
    "single quotes": [agg("return 'BLSAggregator-4.14.2';"), "BLSAggregator-4.14.2"],
    "a commented-out old return": [
      agg('// return "BLSAggregator-4.14.1";\n    return "BLSAggregator-4.14.2";'),
      "BLSAggregator-4.14.2",
    ],
    "an inline comment": [
      agg('return /* release */ "BLSAggregator-4.14.2";'),
      "BLSAggregator-4.14.2",
    ],
    "override(IVersioned)": [
      agg('return "BLSAggregator-4.14.2";').replace(
        "override returns",
        "override(IVersioned) returns"
      ),
      "BLSAggregator-4.14.2",
    ],
    "override(A, B) and CRLF line ends": [
      agg('return "BLSAggregator-4.14.2";')
        .replace("override returns", "override(IVersioned, IFoo) returns")
        .replace(/\n/g, "\r\n"),
      "BLSAggregator-4.14.2",
    ],
    "another contract's version() first": [
      `contract DVTValidator {\n${fn('return "BLSAggregator-9.9.9";')}}\n` +
        agg('return "BLSAggregator-4.14.2";'),
      "BLSAggregator-4.14.2",
    ],
    "a // with quotes in a doc comment": [
      `/// says "BLSAggregator-1.0.0"; and 'x'\n` + agg('return "BLSAggregator-4.14.2";'),
      "BLSAggregator-4.14.2",
    ],
  };
  const wrong = Object.entries(good).filter(
    ([, [src, want]]) => aggregatorSourceVersion(src) !== want
  );
  cell(
    "sp-source: BLSAggregator's version() literal is read; comments and other contracts are ignored",
    wrong.length === 0,
    wrong.map(([k, [src]]) => `${k} -> ${aggregatorSourceVersion(src)}`).join(", ")
  );
  const bad = {
    none: "contract BLSAggregator {}",
    "no contract": fn('return "BLSAggregator-4.14.2";'),
    "two contracts": agg('return "BLSAggregator-4.14.2";') + agg('return "BLSAggregator-4.14.1";'),
    "two version()": agg('return "BLSAggregator-4.14.2";', fn('return "BLSAggregator-4.14.1";')),
    concatenation: agg('return string.concat("BLSAggregator-", "4.14.1");'),
    "decoy comment + concatenation": agg(
      '// return "BLSAggregator-4.14.2";\n    return string.concat("BLSAggregator-", "4.14.1");'
    ),
    "a constant": agg("return VERSION;"),
    "no patch": agg('return "BLSAggregator-4.14";'),
    "another contract's prefix": agg('return "DVTValidator-0.9.0";'),
    "trailing text": agg('return "BLSAggregator-4.14.2 beta";'),
    "only in a block comment": `/* contract BLSAggregator {\n${fn('return "BLSAggregator-4.14.2";')}} */`,
    "not a string": null,
    "a body-less version() before another member": `contract BLSAggregator is X {\n  function version() external virtual returns (string memory);\n  function other() external pure returns (string memory) {\n    return "BLSAggregator-9.9.9";\n  }\n}\n`,
    "a $-suffixed contract name only": agg('return "BLSAggregator-4.14.2";').replace(
      "contract BLSAggregator",
      "contract BLSAggregator$Other"
    ),
    "an unterminated block comment": agg('return "BLSAggregator-4.14.2";') + "/* unterminated",
    "an unterminated string": agg('return "BLSAggregator-4.14.2";') + '"unterminated',
    "a modifier spelled like two keywords (publicpure)": agg(
      'return "BLSAggregator-4.14.2";'
    ).replace("external pure override", "external pure publicpure"),
    "a bare CR ending a // comment (solc ends it there)": agg(
      '// note\r    return "BLSAggregator-4.14.3";\n    return "BLSAggregator-4.14.2";'
    ),
    "a version(uint256) overload": `contract BLSAggregator is X {\n  function version(uint256) external pure returns (string memory) {\n    return "BLSAggregator-9.9.9";\n  }\n}\n`,
    "a modifier on version()": `contract BLSAggregator is X {\n  function version() external pure onlyX returns (string memory) {\n    return "BLSAggregator-9.9.9";\n  }\n}\n`,
  };
  const passed = Object.entries(bad).filter(([, src]) => aggregatorSourceVersion(src) !== null);
  cell(
    "sp-source: no/two contracts or version(), a non-literal return, or a malformed string gives null (the export stops)",
    passed.length === 0,
    passed.map(([k]) => k).join(", ")
  );
}

server.close();
rmSync(dir, { recursive: true, force: true });
console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
