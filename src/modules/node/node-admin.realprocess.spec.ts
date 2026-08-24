import { jest } from "@jest/globals";
import { ChildProcess, execFileSync, spawn } from "child_process";
import { createServer, Server } from "http";
import { Agent, request as httpRequest } from "http";
import { existsSync, mkdtempSync, rmSync, statSync, readdirSync } from "fs";
import { networkInterfaces } from "os";
import { AddressInfo, connect, createServer as createTcpServer, Server as TcpServer } from "net";
import { join, dirname, resolve } from "path";
import { fileURLToPath } from "url";
import { HEADER_AUTH, RepCreditExperimentGuard } from "../repcredit/repcredit-experiment.guard.js";

/**
 * REAL-PROCESS regression tests for the node-admin gate (CC-49 round-4 HIGH-1).
 *
 * Why a real process and not a Nest testing module: the finding this file exists for was
 * invisible to unit tests. `POST /node/register` returned HTTP 200 with the provider's own
 * error text in the body, and the same text in the node log — and it only does that when a
 * REAL ethers provider fails against a REAL URL carrying credentials, inside the REAL express
 * pipeline with the global scrubbing filter installed. Every layer that mattered (the guard
 * wiring, `main.ts`'s filter, ethers' error shape, what actually reaches stdout) is skipped by
 * an in-process mock, which is precisely why four review rounds passed over it.
 *
 * The fixture:
 *   - a fake JSON-RPC endpoint on loopback that answers 401 to everything, reached through a
 *     URL that carries a credential in userinfo, in the path AND in the query string;
 *   - the built `dist/main.js` spawned as its own process with that URL as ETH_RPC_URL;
 *   - assertions on the HTTP response bodies AND on everything the process wrote to
 *     stdout/stderr.
 */

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, "../../..");
const MAIN = join(REPO_ROOT, "dist", "main.js");

/** Credential fragments planted in ETH_RPC_URL. None of them may appear anywhere, ever. */
const RPC_USER = "rpcuserlongenough";
const RPC_PASS = "P4ssw0rdUserInfoSecret";
const RPC_PATH_KEY = "APIKEYPATHSECRET0123";
const RPC_QUERY_KEY = "QUERYSECRETVALUE4567";
const CREDENTIAL_FRAGMENTS = [RPC_USER, RPC_PASS, RPC_PATH_KEY, RPC_QUERY_KEY];

const ADMIN_TOKEN = "example-real-process-node-admin-token";

jest.setTimeout(180_000);

interface Response {
  status: number;
  body: string;
  json: any;
}

async function freePort(): Promise<number> {
  return new Promise(resolvePort => {
    const probe = createServer();
    probe.listen(0, "127.0.0.1", () => {
      const { port } = probe.address() as AddressInfo;
      probe.close(() => resolvePort(port));
    });
  });
}

function send(
  port: number,
  method: string,
  path: string,
  headers: Record<string, string> = {},
  host = "127.0.0.1",
  body?: string
): Promise<Response> {
  return new Promise((resolveReq, rejectReq) => {
    const allHeaders =
      body === undefined
        ? headers
        : {
            ...headers,
            "Content-Type": "application/json",
            "Content-Length": String(Buffer.byteLength(body)),
          };
    const req = httpRequest({ host, port, method, path, headers: allHeaders }, res => {
      let body = "";
      res.on("data", chunk => (body += chunk));
      res.on("end", () => {
        let json: any = null;
        try {
          json = JSON.parse(body);
        } catch {
          /* non-JSON (e.g. the HTML dashboard) — assertions use `body` then */
        }
        resolveReq({ status: res.statusCode ?? 0, body, json });
      });
    });
    req.on("error", rejectReq);
    if (body !== undefined) req.write(body);
    req.end();
  });
}

/** Resident set size of a live pid, in KiB, straight from the OS. */
function rssKib(pid: number): number {
  const out = execFileSync("ps", ["-o", "rss=", "-p", String(pid)]).toString().trim();
  const value = Number(out);
  if (!Number.isFinite(value) || value <= 0) throw new Error(`could not read RSS of ${pid}`);
  return value;
}

/**
 * Fire `count` anonymous requests carrying DISTINCT forged `X-Forwarded-For` values, over
 * keep-alive connections, and report how long the batch took plus the status histogram.
 * This is the round-6 MEDIUM-3 attack: one host, one socket, an unbounded supply of bucket keys.
 */
async function forgedForwardedBatch(
  port: number,
  offset: number,
  count: number,
  agent: Agent
): Promise<{ ms: number; statuses: Record<number, number> }> {
  const statuses: Record<number, number> = {};
  const started = process.hrtime.bigint();
  const CONCURRENCY = 32;
  let next = offset;
  const end = offset + count;
  await Promise.all(
    Array.from({ length: CONCURRENCY }, async () => {
      for (;;) {
        const i = next++;
        if (i >= end) return;
        const forged = `10.${(i >> 16) & 0xff}.${(i >> 8) & 0xff}.${i & 0xff}`;
        const status = await new Promise<number>((done, fail) => {
          const req = httpRequest(
            {
              host: "127.0.0.1",
              port,
              method: "POST",
              path: "/node/register",
              headers: { "X-Forwarded-For": forged },
              agent,
            },
            res => {
              res.resume();
              res.on("end", () => done(res.statusCode ?? 0));
            }
          );
          req.on("error", fail);
          req.end();
        });
        statuses[status] = (statuses[status] ?? 0) + 1;
      }
    })
  );
  return { ms: Number(process.hrtime.bigint() - started) / 1e6, statuses };
}

/** A provider that fails every call the way a revoked/rate-limited API key does. */
function fakeRpc(): Promise<{ server: Server; port: number }> {
  return new Promise(resolveRpc => {
    const server = createServer((_req, res) => {
      res.writeHead(401, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Unauthorized: invalid project id" }));
    });
    server.listen(0, "127.0.0.1", () =>
      resolveRpc({ server, port: (server.address() as AddressInfo).port })
    );
  });
}

/** Build only when `dist` is missing or older than `src`, so the suite is self-sufficient. */
function ensureBuilt(): void {
  const newestSource = newestMtime(join(REPO_ROOT, "src"));
  if (existsSync(MAIN) && statSync(MAIN).mtimeMs >= newestSource) return;
  execFileSync("npm", ["run", "build"], { cwd: REPO_ROOT, stdio: "ignore" });
}

function newestMtime(dir: string): number {
  let newest = 0;
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    newest = Math.max(newest, entry.isDirectory() ? newestMtime(path) : statSync(path).mtimeMs);
  }
  return newest;
}

interface Node {
  port: number;
  /** OS pid of the spawned node — the round-6 MEDIUM-3 test reads its RSS through `ps`. */
  pid: number;
  log: () => string;
  stop: () => void;
}

async function startNode(env: Record<string, string>, rpcPort: number): Promise<Node> {
  const cwd = mkdtempSync(join(REPO_ROOT, "node_modules", ".dvt-realproc-"));
  // A real, freshly generated identity via the supported path — never a committed key.
  execFileSync("node", [join(REPO_ROOT, "scripts", "gen-node-state.mjs"), "realproc"], {
    cwd,
    stdio: "ignore",
  });

  const port = await freePort();
  let log = "";
  const child = spawn("node", [MAIN], {
    cwd,
    env: {
      ...process.env,
      PORT: String(port),
      ETH_RPC_URL: `http://${RPC_USER}:${RPC_PASS}@127.0.0.1:${rpcPort}/v2/${RPC_PATH_KEY}?apikey=${RPC_QUERY_KEY}`,
      VALIDATOR_CONTRACT_ADDRESS: "0x1A8Db6390000000000000000000000000000dEaD",
      // A funded-looking signer so `isConfigured()` is true and registration really tries the
      // chain — that RPC attempt is what used to leak the credential into the 200 body.
      ETH_PRIVATE_KEY: `0x${"11".repeat(32)}`,
      GOSSIP_ENABLED: "false",
      ...env,
    },
  });
  child.stdout.on("data", d => (log += d.toString()));
  child.stderr.on("data", d => (log += d.toString()));

  const deadline = Date.now() + 60_000;
  for (;;) {
    if (child.exitCode !== null) {
      throw new Error(`node exited early (${child.exitCode}):\n${log}`);
    }
    try {
      const health = await send(port, "GET", "/node/health");
      if (health.status === 200) break;
    } catch {
      /* not listening yet */
    }
    if (Date.now() > deadline) throw new Error(`node did not become ready:\n${log}`);
    await new Promise(r => setTimeout(r, 200));
  }

  return {
    port,
    pid: child.pid ?? -1,
    log: () => log,
    stop: () => {
      stopChild(child);
      rmSync(cwd, { recursive: true, force: true });
    },
  };
}

function stopChild(child: ChildProcess): void {
  if (child.exitCode === null) child.kill("SIGKILL");
}

/**
 * Start the node and expect it NOT to come up. Returns the exit code and everything it wrote,
 * so a test can assert that a mis-declared network topology is a BOOT failure and not a
 * warning the operator scrolls past.
 */
async function startNodeExpectingExit(
  env: Record<string, string>,
  rpcPort: number
): Promise<{ code: number | null; log: string }> {
  const cwd = mkdtempSync(join(REPO_ROOT, "node_modules", ".dvt-realproc-"));
  execFileSync("node", [join(REPO_ROOT, "scripts", "gen-node-state.mjs"), "realproc"], {
    cwd,
    stdio: "ignore",
  });
  const port = await freePort();
  let log = "";
  const child = spawn("node", [MAIN], {
    cwd,
    env: {
      ...process.env,
      PORT: String(port),
      ETH_RPC_URL: `http://127.0.0.1:${rpcPort}`,
      VALIDATOR_CONTRACT_ADDRESS: "0x1A8Db6390000000000000000000000000000dEaD",
      GOSSIP_ENABLED: "false",
      ...env,
    },
  });
  child.stdout.on("data", d => (log += d.toString()));
  child.stderr.on("data", d => (log += d.toString()));
  const code = await new Promise<number | null>((done, fail) => {
    const timer = setTimeout(() => {
      stopChild(child);
      fail(new Error(`node did NOT exit within 60s — it booted with a bad config:\n${log}`));
    }, 60_000);
    child.on("exit", exitCode => {
      clearTimeout(timer);
      done(exitCode);
    });
  });
  rmSync(cwd, { recursive: true, force: true });
  return { code, log };
}

/**
 * A REAL same-host TCP reverse proxy — the shape cloudflared has on dvt1/2/3. It listens on
 * every interface and back-connects to `127.0.0.1:<node port>`, so the node's socket peer is
 * loopback for EVERY caller, including one arriving from off-box. This is what made the
 * round-4 loopback gate inert, and it is why these cases must run against a real process:
 * no in-process mock reproduces "the peer address is genuinely 127.0.0.1".
 */
function sameHostProxy(nodePort: number): Promise<{ server: TcpServer; port: number }> {
  return new Promise(resolveProxy => {
    const server = createTcpServer(client => {
      const upstream = connect(nodePort, "127.0.0.1");
      client.pipe(upstream);
      upstream.pipe(client);
      const drop = () => {
        client.destroy();
        upstream.destroy();
      };
      client.on("error", drop);
      upstream.on("error", drop);
    });
    server.listen(0, "0.0.0.0", () =>
      resolveProxy({ server, port: (server.address() as AddressInfo).port })
    );
  });
}

/** The one assertion every single case repeats: no credential fragment, anywhere. */
function expectNoCredential(text: string, where: string): void {
  for (const fragment of CREDENTIAL_FRAGMENTS) {
    expect([where, fragment, text.includes(fragment)]).toEqual([where, fragment, false]);
  }
}

/** A non-loopback address of this machine, if it has one (CI containers sometimes do not). */
function localRemoteAddress(): string | null {
  for (const addresses of Object.values(networkInterfaces())) {
    for (const address of addresses ?? []) {
      if (address.family === "IPv4" && !address.internal) return address.address;
    }
  }
  return null;
}

let rpc: { server: Server; port: number };

beforeAll(async () => {
  ensureBuilt();
  rpc = await fakeRpc();
});

afterAll(async () => {
  await new Promise(done => rpc.server.close(() => done(null)));
});

describe("real process: state-changing endpoints are closed by default (CC-49 round-4 HIGH-1)", () => {
  let node: Node;

  beforeAll(async () => {
    node = await startNode({}, rpc.port); // NODE_ADMIN_ENABLED deliberately unset
  });
  afterAll(() => node?.stop());

  const CLOSED: Array<[string, string]> = [
    ["POST", "/node/register"],
    ["POST", "/dashboard/nodes"],
    ["POST", "/dashboard/import-node"],
    ["DELETE", "/dashboard/current-node"],
    ["POST", "/gossip/data"],
  ];

  it.each(CLOSED)("%s %s answers 403 NODE_ADMIN_DISABLED unauthenticated", async (method, path) => {
    const res = await send(node.port, method, path);
    expect([path, res.status]).toEqual([path, 403]);
    expect(res.json).toMatchObject({
      errorCode: "NODE_ADMIN_DISABLED",
      category: "auth",
      errorCodeVersion: 1,
    });
    expectNoCredential(res.body, `${method} ${path} body`);
  });

  it("does not touch the chain for a rejected caller", async () => {
    // The refusal must happen in the guard, before any RPC read — otherwise an anonymous
    // caller can still make the node spend provider quota.
    await send(node.port, "POST", "/node/register");
    expect(node.log()).not.toMatch(/Registering node .* on-chain/);
  });

  it("keeps the public read endpoints open (no collateral lockout)", async () => {
    for (const path of ["/node/info", "/node/health", "/identity", "/gossip/peers"]) {
      const res = await send(node.port, "GET", path);
      expect([path, res.status]).toEqual([path, 200]);
      expectNoCredential(res.body, `GET ${path} body`);
    }
  });

  it("never wrote a credential fragment to the log", () => {
    expectNoCredential(node.log(), "node log");
    // …and it did print the endpoint, scrubbed to host:port, so operators keep the signal.
    expect(node.log()).toMatch(/ETH RPC URL: http:\/\/127\.0\.0\.1:\d+/);
  });
});

describe("real process: node-admin gate when enabled (CC-49 round-4 HIGH-1)", () => {
  let node: Node;

  beforeAll(async () => {
    node = await startNode(
      {
        NODE_ADMIN_ENABLED: "true",
        NODE_ADMIN_TOKEN: ADMIN_TOKEN,
        NODE_ADMIN_NETWORK_MODE: "direct",
        NODE_ADMIN_RATE_MAX: "100",
      },
      rpc.port
    );
  });
  afterAll(() => node?.stop());

  it("401s a missing token and 403s a wrong one", async () => {
    const missing = await send(node.port, "POST", "/node/register");
    expect(missing.status).toBe(401);
    expect(missing.json).toMatchObject({ errorCode: "NODE_ADMIN_TOKEN_MISSING" });

    const wrong = await send(node.port, "POST", "/node/register", {
      "X-Node-Admin-Token": `${ADMIN_TOKEN}x`,
    });
    expect(wrong.status).toBe(403);
    expect(wrong.json).toMatchObject({ errorCode: "NODE_ADMIN_TOKEN_INVALID" });
  });

  it("rejects a non-loopback caller even with the correct token", async () => {
    const remote = localRemoteAddress();
    if (!remote) {
      // Never silently pass: say so, and rely on node-admin.guard.spec.ts for this axis.
      console.warn("no non-loopback IPv4 on this host — remote-source case not exercised here");
      return;
    }
    const res = await send(
      node.port,
      "POST",
      "/node/register",
      { "X-Node-Admin-Token": ADMIN_TOKEN },
      remote
    );
    expect(res.status).toBe(403);
    expect(res.json).toMatchObject({ errorCode: "NODE_ADMIN_REMOTE_FORBIDDEN" });
  });

  it("THE REGRESSION: an authenticated register against a failing provider leaks nothing", async () => {
    const res = await send(node.port, "POST", "/node/register", {
      "X-Node-Admin-Token": ADMIN_TOKEN,
    });
    // Was: 200 {"success":false,"message":"Registration failed: server response 401 …
    //      requestUrl: http://user:pass@host/v2/KEY?apikey=KEY …"}
    expect(res.status).toBe(502);
    expect(res.json).toMatchObject({
      errorCode: "NODE_REGISTER_UPSTREAM_FAILED",
      category: "infrastructure",
    });
    expectNoCredential(res.body, "authenticated register body");
    // No provider text at all — not just no credential.
    expect(res.body).not.toMatch(/requestUrl|server response 401/);
    // The operator still gets a usable, scrubbed log line.
    expect(node.log()).toMatch(/Failed to register node on-chain:/);
    expectNoCredential(node.log(), "node log after authenticated register");
  });

  it("leaves the whole process log credential-free after the full sequence", () => {
    expectNoCredential(node.log(), "node log (final)");
  });
});

describe("real process: node-admin throttle (CC-49 round-4 HIGH-1)", () => {
  let node: Node;

  beforeAll(async () => {
    node = await startNode(
      {
        NODE_ADMIN_ENABLED: "true",
        NODE_ADMIN_TOKEN: ADMIN_TOKEN,
        NODE_ADMIN_NETWORK_MODE: "direct",
        NODE_ADMIN_RATE_MAX: "2",
      },
      rpc.port
    );
  });
  afterAll(() => node?.stop());

  it("bounds token guessing per source IP", async () => {
    const attempt = () =>
      send(node.port, "POST", "/node/register", { "X-Node-Admin-Token": "guess" });
    expect((await attempt()).status).toBe(403);
    expect((await attempt()).status).toBe(403);
    const limited = await attempt();
    expect(limited.status).toBe(429);
    expect(limited.json).toMatchObject({ errorCode: "NODE_ADMIN_RATE_LIMITED" });
  });
});

/**
 * CC-49 round-5 MEDIUM-1 / MEDIUM-2, through a REAL same-host reverse proxy.
 *
 * The round-5 reviewer's repro, verbatim: start the built `dist/main.js`, put a same-host TCP
 * reverse proxy in front of it, and observe that a public caller reaches the node from
 * 127.0.0.1 — so the "loopback only" gate never fired and the "the token is the only barrier"
 * warning never printed, on precisely the deployment this repo documents (cloudflared).
 */
describe("real process: proxied network mode (CC-49 round-5 MEDIUM-1)", () => {
  let node: Node;
  let proxy: { server: TcpServer; port: number };

  afterEach(async () => {
    node?.stop();
    if (proxy) await new Promise(done => proxy.server.close(() => done(null)));
  });

  it("keeps the endpoints CLOSED behind a proxy until NODE_ADMIN_ALLOW_PROXIED is set", async () => {
    node = await startNode(
      {
        NODE_ADMIN_ENABLED: "true",
        NODE_ADMIN_TOKEN: ADMIN_TOKEN,
        NODE_ADMIN_NETWORK_MODE: "proxied",
        // NODE_ADMIN_ALLOW_PROXIED deliberately unset.
      },
      rpc.port
    );
    proxy = await sameHostProxy(node.port);

    for (const host of ["127.0.0.1", localRemoteAddress()].filter(Boolean) as string[]) {
      const res = await send(
        proxy.port,
        "POST",
        "/node/register",
        { "X-Node-Admin-Token": ADMIN_TOKEN },
        host
      );
      expect([host, res.status]).toEqual([host, 403]);
      expect([host, res.json?.errorCode]).toEqual([host, "NODE_ADMIN_PROXIED_NOT_ALLOWED"]);
    }
    expect(node.log()).toMatch(/stay DISABLED/);
    expect(node.log()).toMatch(/NODE_ADMIN_ALLOW_PROXIED=true/);
  });

  it("warns at boot that the token is the only barrier, and never claims loopback as one", async () => {
    node = await startNode(
      {
        NODE_ADMIN_ENABLED: "true",
        NODE_ADMIN_TOKEN: ADMIN_TOKEN,
        NODE_ADMIN_NETWORK_MODE: "proxied",
        NODE_ADMIN_ALLOW_PROXIED: "true",
        NODE_ADMIN_RATE_MAX: "50",
      },
      rpc.port
    );
    proxy = await sameHostProxy(node.port);

    // THE WARNING THAT WAS MISSING IN ROUND 4: it fires for the tunnel deployment itself.
    expect(node.log()).toMatch(/ONLY NETWORK BARRIER/);
    expect(node.log()).toMatch(/NODE_ADMIN_NETWORK_MODE=proxied/);

    // Anonymous through the proxy: 401, i.e. the token — never 403 "loopback only", which
    // round 4 would also have answered 401 while CLAIMING the source was checked.
    const anonymous = await send(proxy.port, "POST", "/node/register");
    expect(anonymous.status).toBe(401);
    expect(anonymous.json).toMatchObject({ errorCode: "NODE_ADMIN_TOKEN_MISSING" });

    // Wrong token through the proxy: 403 on the credential, not on the source.
    const wrong = await send(proxy.port, "POST", "/node/register", {
      "X-Node-Admin-Token": `${ADMIN_TOKEN}x`,
    });
    expect(wrong.json).toMatchObject({ errorCode: "NODE_ADMIN_TOKEN_INVALID" });

    // Correct token through the proxy reaches the handler (502 from the failing fake RPC),
    // and still leaks no provider credential.
    const authenticated = await send(proxy.port, "POST", "/node/register", {
      "X-Node-Admin-Token": ADMIN_TOKEN,
    });
    expect(authenticated.status).toBe(502);
    expect(authenticated.json).toMatchObject({ errorCode: "NODE_REGISTER_UPSTREAM_FAILED" });
    expectNoCredential(authenticated.body, "proxied authenticated register body");
    expectNoCredential(node.log(), "node log (proxied run)");
  });

  it("pins what `direct` mode actually means, which is why the mode must be DECLARED", async () => {
    // This is the round-5 finding reproduced, and it is NOT a bug in `direct` mode: `direct`
    // is the operator ASSERTING that no proxy fronts the node. If that assertion is wrong,
    // the loopback gate is inert — a caller through a same-host proxy reaches the handler on
    // the token alone. The fix is that the assertion is now explicit and the wrong one
    // (proxied) is fail-closed, not that `direct` somehow detects a proxy it was told is
    // absent. Left as an executable statement of the contract so it cannot drift silently.
    node = await startNode(
      {
        NODE_ADMIN_ENABLED: "true",
        NODE_ADMIN_TOKEN: ADMIN_TOKEN,
        NODE_ADMIN_NETWORK_MODE: "direct",
        NODE_ADMIN_RATE_MAX: "50",
      },
      rpc.port
    );
    proxy = await sameHostProxy(node.port);

    // Direct, off-box, no proxy: the loopback gate does its job.
    const remote = localRemoteAddress();
    if (remote) {
      const direct = await send(
        node.port,
        "POST",
        "/node/register",
        { "X-Node-Admin-Token": ADMIN_TOKEN },
        remote
      );
      expect(direct.status).toBe(403);
      expect(direct.json).toMatchObject({ errorCode: "NODE_ADMIN_REMOTE_FORBIDDEN" });
    } else {
      console.warn("no non-loopback IPv4 on this host — direct off-box case not exercised here");
    }
    // Same request through the same-host proxy: the socket peer is 127.0.0.1, so it passes
    // the source gate and only the token stands. Hence `proxied` must be declared, and when
    // it is, the node stops pretending the source gate means anything.
    const throughProxy = await send(proxy.port, "POST", "/node/register", {
      "X-Node-Admin-Token": ADMIN_TOKEN,
    });
    expect(throughProxy.status).toBe(502);
    expect(throughProxy.json).toMatchObject({ errorCode: "NODE_REGISTER_UPSTREAM_FAILED" });
  });

  it("refuses to boot when the mode is MISSING, not just when it is wrong (round-6 MEDIUM-1)", async () => {
    // The round-5 hole reachable by doing nothing at all: NODE_ADMIN_ENABLED=true with no mode
    // ran in `direct`, printed "loopback callers only" three times, and reached the handler
    // through a same-host proxy anyway. Declaring the topology is now part of enabling it.
    const undeclared = await startNodeExpectingExit(
      { NODE_ADMIN_ENABLED: "true", NODE_ADMIN_TOKEN: ADMIN_TOKEN },
      rpc.port
    );
    expect(undeclared.code).not.toBe(0);
    expect(undeclared.log).toMatch(/NODE_ADMIN_NETWORK_MODE must be declared/);
    // …and it never claimed a source restriction on the way out.
    expect(undeclared.log).not.toMatch(/loopback callers only/);

    // Leaving the endpoints DISABLED still needs no declaration — dvt1/2/3 are untouched.
    const disabled = await startNode({ NODE_ADMIN_ENABLED: "false" }, rpc.port);
    try {
      const res = await send(disabled.port, "POST", "/node/register");
      expect(res.json).toMatchObject({ errorCode: "NODE_ADMIN_DISABLED" });
    } finally {
      disabled.stop();
    }
  });

  it("refuses to boot on an undeclared mode or a half-declared proxy topology", async () => {
    const bad = await startNodeExpectingExit(
      {
        NODE_ADMIN_ENABLED: "true",
        NODE_ADMIN_TOKEN: ADMIN_TOKEN,
        NODE_ADMIN_NETWORK_MODE: "tunnel",
      },
      rpc.port
    );
    expect(bad.code).not.toBe(0);
    expect(bad.log).toMatch(/NODE_ADMIN_NETWORK_MODE must be one of/);

    const half = await startNodeExpectingExit(
      {
        NODE_ADMIN_ENABLED: "true",
        NODE_ADMIN_TOKEN: ADMIN_TOKEN,
        NODE_ADMIN_NETWORK_MODE: "proxied",
        NODE_ADMIN_ALLOW_PROXIED: "true",
        NODE_ADMIN_TRUSTED_PROXY_CIDRS: "127.0.0.0/8",
        // NODE_ADMIN_TRUSTED_PROXY_HOPS deliberately unset — that would mean keying rate
        // limits on a header the caller controls.
      },
      rpc.port
    );
    expect(half.code).not.toBe(0);
    expect(half.log).toMatch(/must be set TOGETHER/);
  });
});

describe("real process: an anonymous flood cannot lock the operator out (CC-49 round-5 MEDIUM-2)", () => {
  let node: Node;
  let proxy: { server: TcpServer; port: number };

  beforeAll(async () => {
    node = await startNode(
      {
        NODE_ADMIN_ENABLED: "true",
        NODE_ADMIN_TOKEN: ADMIN_TOKEN,
        NODE_ADMIN_NETWORK_MODE: "proxied",
        NODE_ADMIN_ALLOW_PROXIED: "true",
        // Behind a tunnel every caller shares one source key, so these are the budgets that
        // an attacker and the operator would have shared before the fix.
        NODE_ADMIN_RATE_MAX: "5",
        NODE_ADMIN_ANON_GLOBAL_RATE_MAX: "5",
        NODE_ADMIN_OPERATOR_RATE_MAX: "20",
      },
      rpc.port
    );
    proxy = await sameHostProxy(node.port);
  });
  afterAll(async () => {
    node?.stop();
    if (proxy) await new Promise(done => proxy.server.close(() => done(null)));
  });

  it("THE REGRESSION: after an anonymous flood spends the brute-force budget, the correct token still reaches the handler", async () => {
    // 12 unauthenticated requests through the proxy — the round-4 guard needed ~10/min to
    // hold the admin plane shut for everyone, operator included.
    const anonymous: number[] = [];
    for (let i = 0; i < 12; i++) {
      anonymous.push((await send(proxy.port, "POST", "/node/register")).status);
    }
    expect(anonymous.slice(0, 5)).toEqual([401, 401, 401, 401, 401]);
    expect(anonymous.slice(5)).toEqual(Array(7).fill(429));

    // The anonymous ledger is spent, and a wrong token is bounded WITH it…
    const guess = await send(proxy.port, "POST", "/node/register", {
      "X-Node-Admin-Token": "guess",
    });
    expect(guess.status).toBe(429);
    expect(guess.json).toMatchObject({ errorCode: "NODE_ADMIN_RATE_LIMITED" });

    // …while the operator, on the SAME shared proxy source key, is not affected at all.
    for (let i = 0; i < 3; i++) {
      const operator = await send(proxy.port, "POST", "/node/register", {
        "X-Node-Admin-Token": ADMIN_TOKEN,
      });
      // 502 = it ran the handler and the fake RPC refused. Anything but 429 is the assertion.
      expect([i, operator.status]).toEqual([i, 502]);
      expect([i, operator.json?.errorCode]).toEqual([i, "NODE_REGISTER_UPSTREAM_FAILED"]);
    }
  });

  it("never wrote the admin token to the log while rejecting all of that", () => {
    expect(node.log()).not.toContain(ADMIN_TOKEN);
    expect(node.log()).not.toContain("guess");
    expectNoCredential(node.log(), "node log (flood run)");
  });
});

describe("real process: ONE throttle ledger for every guarded route (CC-49 round-6 MEDIUM-2)", () => {
  // The finding: `@UseGuards(NodeAdminGuard)` makes Nest build one guard instance per MODULE,
  // so /node, /dashboard and /gossip each had their own copy of every ledger — the "global"
  // anonymous budget was really 3x the configured value, and the boot banner printed 3 times.
  // Every assertion below crosses a module boundary, which is precisely what the 623 in-process
  // tests could not see: they all exercised a single route.
  const ROUTES: Array<[string, string]> = [
    ["POST", "/dashboard/nodes"],
    ["POST", "/node/register"],
    ["POST", "/gossip/data"],
  ];

  it("announces the enabled posture exactly ONCE per process", async () => {
    const node = await startNode(
      {
        NODE_ADMIN_ENABLED: "true",
        NODE_ADMIN_TOKEN: ADMIN_TOKEN,
        NODE_ADMIN_NETWORK_MODE: "direct",
      },
      rpc.port
    );
    try {
      const banners = node.log().match(/Node admin HTTP endpoints are ENABLED/g) ?? [];
      // Was 3 — one per module-scoped guard instance, which is what gave the ledgers away.
      expect(banners).toHaveLength(1);
    } finally {
      node.stop();
    }
  });

  it("spends ONE global anonymous budget across /dashboard, /node and /gossip", async () => {
    const node = await startNode(
      {
        NODE_ADMIN_ENABLED: "true",
        NODE_ADMIN_TOKEN: ADMIN_TOKEN,
        NODE_ADMIN_NETWORK_MODE: "proxied",
        NODE_ADMIN_ALLOW_PROXIED: "true",
        NODE_ADMIN_TRUSTED_PROXY_CIDRS: "127.0.0.0/8",
        NODE_ADMIN_TRUSTED_PROXY_HOPS: "1",
        NODE_ADMIN_RATE_MAX: "100", // per-source is generous: the GLOBAL ledger is the bound
        NODE_ADMIN_ANON_GLOBAL_RATE_MAX: "4",
      },
      rpc.port
    );
    try {
      // Four distinct client addresses, spread over all three modules: the global budget is
      // spent by the fourth wherever it was spent, and the fifth is 429 on a FOURTH route.
      const statuses: number[] = [];
      for (let i = 0; i < 4; i++) {
        const [method, path] = ROUTES[i % ROUTES.length];
        const res = await send(node.port, method, path, { "X-Forwarded-For": `203.0.113.${i}` });
        statuses.push(res.status);
      }
      expect(statuses).toEqual([401, 401, 401, 401]);

      for (const [method, path] of ROUTES) {
        const res = await send(node.port, method, path, { "X-Forwarded-For": "198.51.100.9" });
        // Before the fix: 401 on the two modules that had not spent their own copy yet.
        expect([path, res.status]).toEqual([path, 429]);
        expect([path, res.json?.errorCode]).toEqual([path, "NODE_ADMIN_RATE_LIMITED"]);
      }
    } finally {
      node.stop();
    }
  });

  it("spends ONE per-source and ONE operator budget across the same three modules", async () => {
    const node = await startNode(
      {
        NODE_ADMIN_ENABLED: "true",
        NODE_ADMIN_TOKEN: ADMIN_TOKEN,
        NODE_ADMIN_NETWORK_MODE: "proxied",
        NODE_ADMIN_ALLOW_PROXIED: "true",
        NODE_ADMIN_TRUSTED_PROXY_CIDRS: "127.0.0.0/8",
        NODE_ADMIN_TRUSTED_PROXY_HOPS: "1",
        NODE_ADMIN_RATE_MAX: "2",
        NODE_ADMIN_ANON_GLOBAL_RATE_MAX: "1000", // per-source is the bound here
        NODE_ADMIN_OPERATOR_RATE_MAX: "2",
      },
      rpc.port
    );
    try {
      const client = { "X-Forwarded-For": "203.0.113.50" };
      // Per-source: two attempts on /dashboard, and the SAME source is out of budget on /node.
      expect((await send(node.port, "POST", "/dashboard/nodes", client)).status).toBe(401);
      expect((await send(node.port, "POST", "/gossip/data", client)).status).toBe(401);
      const spent = await send(node.port, "POST", "/node/register", client);
      expect(spent.status).toBe(429);
      expect(spent.json).toMatchObject({ errorCode: "NODE_ADMIN_RATE_LIMITED" });
      // A different client still has its own per-source budget (the ledger is shared, not global).
      expect(
        (await send(node.port, "POST", "/node/register", { "X-Forwarded-For": "203.0.113.51" }))
          .status
      ).toBe(401);

      // Operator: two authenticated requests across two modules, third is 429 on a third module.
      const auth = { "X-Node-Admin-Token": ADMIN_TOKEN, "X-Forwarded-For": "203.0.113.60" };
      expect((await send(node.port, "POST", "/node/register", auth)).status).toBe(502);
      expect((await send(node.port, "POST", "/gossip/data", auth)).status).not.toBe(429);
      const operatorLimited = await send(node.port, "POST", "/dashboard/nodes", auth);
      expect(operatorLimited.status).toBe(429);
      expect(operatorLimited.json).toMatchObject({ errorCode: "NODE_ADMIN_RATE_LIMITED" });
    } finally {
      node.stop();
    }
  });
});

describe("real process: a forged-header flood is bounded in memory AND time (CC-49 round-6 MEDIUM-3)", () => {
  // The finding: the throttle bounded the status code, not the work behind it. With a declared
  // trusted proxy the bucket key comes from X-Forwarded-For, so 25k forged values from ONE host
  // pushed the node's ledger (and the O(n) sweep it ran on every insert past 10k keys) without
  // limit — on the process that also runs the signing hot path. All of it while already 429ing.
  //
  // The measurement runs the SAME 25k flood against two real processes: the gated node, and a
  // control with NODE_ADMIN_ENABLED unset, where the guard answers 403 before any bookkeeping
  // at all. The control is what "this flood costs nothing but HTTP" looks like on this machine,
  // so the assertions are about the DELTA the gate adds, not about an absolute RSS number that
  // is really V8 heap growth under load (a fixed bar there measures the runtime, not this code).
  const agent = new Agent({ keepAlive: true, maxSockets: 32 });
  const FLOOD = { warmup: 200, batch: 5_000, middle: 15_000 };

  interface Run {
    grewMib: number;
    firstMs: number;
    lastMs: number;
    firstStatuses: Record<number, number>;
    lastStatuses: Record<number, number>;
  }

  /** 25k distinct forged bucket keys, with RSS sampled around the run. */
  async function flood(node: Node): Promise<Run> {
    await forgedForwardedBatch(node.port, 0, FLOOD.warmup, agent); // running, not cold
    const baseline = rssKib(node.pid);
    const first = await forgedForwardedBatch(node.port, 1_000, FLOOD.batch, agent);
    await forgedForwardedBatch(node.port, 10_000, FLOOD.middle, agent);
    const last = await forgedForwardedBatch(node.port, 40_000, FLOOD.batch, agent);
    return {
      grewMib: (rssKib(node.pid) - baseline) / 1024,
      firstMs: first.ms,
      lastMs: last.ms,
      firstStatuses: first.statuses,
      lastStatuses: last.statuses,
    };
  }

  let gated: Node;
  let control: Node;
  let gatedRun: Run;
  let controlRun: Run;

  beforeAll(async () => {
    gated = await startNode(
      {
        NODE_ADMIN_ENABLED: "true",
        NODE_ADMIN_TOKEN: ADMIN_TOKEN,
        NODE_ADMIN_NETWORK_MODE: "proxied",
        NODE_ADMIN_ALLOW_PROXIED: "true",
        // The documented "my proxy forwards the client address" posture. The proxy is supposed
        // to strip a client-supplied header; the node cannot verify that it did, which is what
        // makes the bucket key attacker-controlled in the first place.
        NODE_ADMIN_TRUSTED_PROXY_CIDRS: "127.0.0.0/8",
        NODE_ADMIN_TRUSTED_PROXY_HOPS: "1",
        NODE_ADMIN_RATE_MAX: "10",
        NODE_ADMIN_ANON_GLOBAL_RATE_MAX: "60",
        NODE_ADMIN_OPERATOR_RATE_MAX: "120",
      },
      rpc.port
    );
    control = await startNode({}, rpc.port); // NODE_ADMIN_ENABLED unset: 403 before any state
    gatedRun = await flood(gated);
    controlRun = await flood(control);
  });
  afterAll(() => {
    agent.destroy();
    gated?.stop();
    control?.stop();
  });

  it("refuses all 25,000 without allocating: no more memory than the stateless control", () => {
    // Everything past the global anonymous budget is 429 — and costs the node a bounded amount,
    // because the global ledger is charged FIRST and short-circuits, so not one of these
    // allocates or refreshes a per-source entry.
    expect(Object.keys(gatedRun.firstStatuses)).toEqual(["429"]);
    expect(Object.keys(gatedRun.lastStatuses)).toEqual(["429"]);
    expect(Object.keys(controlRun.firstStatuses)).toEqual(["403"]);

    // The gate's own footprint under the flood, over a control that keeps nothing at all. The
    // ledger is hard-capped at 1024 keys (see node-admin.guard.spec.ts), so this is small and
    // does not grow with how many headers the attacker forges.
    expect(gatedRun.grewMib).toBeLessThan(controlRun.grewMib + 24);
  });

  it("does not get slower as the number of forged keys grows", () => {
    // Was 3.4x across this shape, from the full-table sweep on every insert past 10k keys.
    // Measured against the run's own first batch, so a slow machine cannot fail it.
    expect(gatedRun.lastMs).toBeLessThan(Math.max(gatedRun.firstMs * 2.5, 1_000));
    // …and no worse than the control's own drift over the identical flood.
    expect(gatedRun.lastMs / gatedRun.firstMs).toBeLessThan(
      Math.max((controlRun.lastMs / controlRun.firstMs) * 2, 2.5)
    );
  });

  it("keeps the rejection log bounded too — one line per window, not one per request", () => {
    // 25k refused requests must not become 25k log lines: that is the same unbounded
    // per-request cost, moved to the operator's disk.
    // One window's worth of flood => a handful of lines, not 25,000. (The suppressed count is
    // reported on the next line the ledger emits, i.e. in the following window.)
    const lines = gated.log().match(/brute-force budget spent/g) ?? [];
    expect(lines.length).toBeLessThan(10);
  });

  it("leaves the legitimate operator completely unaffected by that flood", async () => {
    // Separate ledger, never charged by any of the 25k anonymous attempts above.
    for (let i = 0; i < 3; i++) {
      const res = await send(gated.port, "POST", "/node/register", {
        "X-Node-Admin-Token": ADMIN_TOKEN,
        "X-Forwarded-For": "203.0.113.200",
      });
      expect([i, res.status]).toEqual([i, 502]); // reached the handler; the fake RPC refused
      expect([i, res.json?.errorCode]).toEqual([i, "NODE_REGISTER_UPSTREAM_FAILED"]);
    }
    expect(gated.log()).not.toContain(ADMIN_TOKEN);
    expectNoCredential(gated.log(), "node log (forged-header flood run)");
  });
});

describe("real process: a RepCredit auth token is single-use in EVERY encoding (CC-49 round-4 MEDIUM-1)", () => {
  const SECRET = "example-real-process-repcredit-secret";
  const TARGET = "/repcredit/sign";
  const BODY = JSON.stringify({ proposalId: "cc49-round4" });
  let node: Node;

  beforeAll(async () => {
    node = await startNode(
      {
        REPCREDIT_EXPERIMENT_SIGNING: "true",
        REPCREDIT_EXPERIMENT_AUTH_SECRET: SECRET,
        REPCREDIT_VALIDATOR_SLOT: "1",
        REPCREDIT_BLS_AGGREGATOR_ADDRESS: "0xEE00000000000000000000000000000000000001",
        AUDIT_BLS_AGGREGATOR_ADDRESS: "0xAA00000000000000000000000000000000000002",
      },
      rpc.port
    );
  });
  afterAll(() => node?.stop());

  /** Exactly the headers a compliant orchestrator sends, from the shipped reference helper. */
  function headers(timestampMs: number) {
    return RepCreditExperimentGuard.computeHeaders(SECRET, {
      method: "POST",
      requestTarget: TARGET,
      timestampMs,
      rawBody: BODY,
    }) as Record<string, string>;
  }

  it("reproduces the reviewer's B1–B4 matrix: first use passes the gate, no variant gets a second", async () => {
    const signed = headers(Date.now());
    const canonical = signed[HEADER_AUTH];

    // B1 — verbatim, first use: admitted by the guard. It then fails DOWNSTREAM (the fake RPC
    // is 401), which is the point: `category` is not "auth", so the gate was passed.
    const first = await send(node.port, "POST", TARGET, signed, "127.0.0.1", BODY);
    expect(first.json?.category).not.toBe("auth");

    // B2 — byte-identical replay: refused. This one always worked.
    const verbatim = await send(node.port, "POST", TARGET, signed, "127.0.0.1", BODY);
    expect(verbatim.status).toBe(403);
    expect(verbatim.json).toMatchObject({ errorCode: "REPCREDIT_AUTH_TOKEN_REPLAYED" });

    // B3/B4 — the SAME token upper-cased and mixed-cased. Before the fix both were ADMITTED
    // (503 from downstream), i.e. a captured request could be replayed for extra co-signatures
    // just by changing the case of a hex string.
    const variants = {
      uppercase: canonical.toUpperCase(),
      "mixed case": canonical
        .split("")
        .map((c, i) => (i % 2 ? c.toUpperCase() : c))
        .join(""),
      "0x-prefixed": `0x${canonical}`,
    };
    for (const [name, auth] of Object.entries(variants)) {
      const res = await send(
        node.port,
        "POST",
        TARGET,
        { ...signed, [HEADER_AUTH]: auth },
        "127.0.0.1",
        BODY
      );
      expect([name, res.status]).toEqual([name, 401]);
      expect([name, res.json?.errorCode]).toEqual([name, "REPCREDIT_AUTH_TOKEN_MALFORMED"]);
    }
  });

  it("never leaks the provider credential through a RepCredit error body or the log", async () => {
    const signed = headers(Date.now());
    const res = await send(node.port, "POST", TARGET, signed, "127.0.0.1", BODY);
    expectNoCredential(res.body, "repcredit error body");
    expectNoCredential(node.log(), "node log (repcredit run)");
  });
});
