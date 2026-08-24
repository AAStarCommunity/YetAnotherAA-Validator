import { jest } from "@jest/globals";
import { ChildProcess, execFileSync, spawn } from "child_process";
import { createServer, Server } from "http";
import { request as httpRequest } from "http";
import { existsSync, mkdtempSync, rmSync, statSync, readdirSync } from "fs";
import { networkInterfaces } from "os";
import { AddressInfo } from "net";
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
      { NODE_ADMIN_ENABLED: "true", NODE_ADMIN_TOKEN: ADMIN_TOKEN, NODE_ADMIN_RATE_MAX: "2" },
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
