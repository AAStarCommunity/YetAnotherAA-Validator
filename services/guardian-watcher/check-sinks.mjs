// CI self-test for the W2b sinks against local mocks: an HTTP server standing in for Pinata,
// Filebase, the gateways and Telegram; a local bare git repo for the mirror; fake providers for the
// registry signer. No network, no real credentials. Live provider cells are separate (pre-go-live).
import { createServer } from "node:http";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
const HERE = dirname(fileURLToPath(import.meta.url));
import { ethers } from "ethers";
import { readSecret } from "./lib/keychain.mjs";
import { guarded, safeText } from "./lib/safe-error.mjs";
import { readPrice } from "./lib/scan.mjs";
import { storable } from "./lib/publish.mjs";
import { cidV1Raw, MAX_RECORD_BYTES } from "./lib/cid.mjs";
import { pinataPinner } from "./sinks/pinata.mjs";
import { filebasePinner } from "./sinks/filebase.mjs";
import { telegramSink } from "./sinks/telegram.mjs";
import { request, jsonOf } from "./sinks/http.mjs";
import { gitMirror } from "./sinks/git-mirror.mjs";
import {
  alreadyKnown,
  registrySink,
  assertWriterRole,
  actionId,
  regSinkIface,
} from "./sinks/registry.mjs";

const results = [];
const j = v => JSON.stringify(v, (_, x) => (typeof x === "bigint" ? x.toString() : x));
const cell = (name, ok, got) => results.push({ name, ok: !!ok, got: ok ? "" : j(got) });

// ---- keychain (injected runner: no real Keychain access in CI)
{
  const ok = await readSecret("svc", "acct", (_c, args, _o, cb) => cb(null, "s3cret\n"));
  cell("keychain: returns the item without its trailing newline", ok === "s3cret", ok);
  let msg = null;
  try {
    await readSecret("svc", "acct", (_c, _a, _o, cb) =>
      cb(Object.assign(new Error("x"), { code: 44 }), "")
    );
  } catch (e) {
    msg = e.message;
  }
  cell(
    "keychain: a missing item is an error naming the item",
    /svc\/acct unavailable/.test(msg ?? ""),
    msg
  );
  let args = null;
  await readSecret("a b", "c;d", (_c, a, _o, cb) => {
    args = a;
    cb(null, "v");
  });
  cell(
    "keychain: service/account passed as argv, never through a shell",
    j(args) === j(["find-generic-password", "-s", "a b", "-a", "c;d", "-w"]),
    args
  );
}

// ---- the error rule outside the sinks (Codex W2b R3)
{
  const codes = [];
  for (const code of ["RPCSECRET_0123456789", "CALL_EXCEPTION", 7]) {
    try {
      await guarded("op", async () => {
        throw Object.assign(new Error("https://rpc/v2/KEYSECRET"), {
          code,
          shortMessage: "KEYSECRET",
        });
      });
    } catch (e) {
      codes.push(e.message);
    }
  }
  cell(
    "a foreign error's code passes only if it is on the allowlist; message never",
    j(codes) === j(["op: error", "op: CALL_EXCEPTION", "op: error"]),
    codes
  );
  const pr = await readPrice(
    {
      async call() {
        throw Object.assign(new Error("x"), {
          shortMessage: "call to https://rpc/v2/KEYSECRET failed",
        });
      },
    },
    ethers.ZeroAddress,
    5
  );
  cell(
    "price read: an RPC failure is recorded as a category, never its text (records are published)",
    pr.error === "cachedPrice read: error" && !j(pr).includes("KEYSECRET"),
    pr
  );
  let km = null;
  try {
    await readSecret("svc", "acct", (_c, _a, _o, cb) =>
      cb(Object.assign(new Error("x"), { code: "KEYSECRET" }), "")
    );
  } catch (e) {
    km = e.message;
  }
  cell(
    "keychain: a non-numeric foreign code is not copied",
    /unavailable \(error\)/.test(km ?? "") && !/KEYSECRET/.test(km ?? ""),
    km
  );
  const exp = "ipfs://bafkrei" + "a".repeat(52);
  const shaped = "ipfs://b" + "keysecretkeysecretkeysecret".replace(/[^a-z2-7]/g, "a");
  const st = storable({ recordURI: shaped, recordHash: "0x" + "ab".repeat(32) }, exp);
  const st2 = storable({ recordURI: shaped + "b", recordHash: "0x" + "ab".repeat(32) }, exp);
  const ok = storable({ recordURI: exp, recordHash: "0x" + "ab".repeat(32) }, exp);
  cell(
    "conflict state keeps a URI in plain text only if it EQUALS ours; else the original's digest",
    st.recordURI === null &&
      st.recordURIKeccak === ethers.keccak256(ethers.toUtf8Bytes(shaped)) &&
      st2.recordURIKeccak !== st.recordURIKeccak &&
      !j(st).includes("keysecret") &&
      ok.recordURI === exp,
    { st, ok }
  );
  const cd = mkdtempSync(join(tmpdir(), "fatal-"));
  writeFileSync(join(cd, "config.json"), '{"aggregator": "FATALSECRET", oops');
  let out = { status: null, err: "" };
  try {
    execFileSync(
      process.execPath,
      [join(HERE, "watcher.mjs"), "--config", join(cd, "config.json"), "--once"],
      {
        env: { ...process.env, RPC_URL: "http://127.0.0.1:1/FATALSECRET" },
        stdio: "pipe",
      }
    );
  } catch (e) {
    out = { status: e.status, err: String(e.stderr) };
  }
  rmSync(cd, { recursive: true, force: true });
  cell(
    "watcher: a fatal startup error prints one category line and exits 1, no foreign text",
    out.status === 1 && out.err.trim() === "watcher fatal: error" && !/FATALSECRET/.test(out.err),
    out
  );
  void safeText;
}

// ---- local HTTP mock
const seen = [];
const BIG_CID = "bafkrei" + "a".repeat(52);
const blobs = new Map();
const srv = createServer(async (req, res) => {
  const chunks = [];
  for await (const c of req) chunks.push(c);
  const body = Buffer.concat(chunks);
  seen.push({
    method: req.method,
    url: req.url,
    auth: req.headers.authorization,
    body: body.toString("latin1"),
  });
  const fileBytes = () => {
    const s = body.toString("latin1");
    const i = s.indexOf("\r\n\r\n", s.indexOf('filename="record.json"'));
    const k = s.indexOf("\r\n--", i + 4);
    return Buffer.from(s.slice(i + 4, k), "latin1");
  };
  if (req.url === "/pinata/echo") {
    return res.end(JSON.stringify({ data: { cid: `Bearer ${req.headers.authorization}` } }));
  } else if (req.url.startsWith("/filebase/echo")) {
    return res.end(JSON.stringify({ Hash: String(req.headers.authorization) }));
  } else if (req.url === "/pinata/upload") {
    const b = fileBytes();
    const cid = cidV1Raw(b);
    blobs.set(cid, b);
    res.end(JSON.stringify({ data: { cid } }));
  } else if (req.url.startsWith("/filebase/add")) {
    const b = fileBytes();
    const cid = cidV1Raw(b);
    blobs.set(cid, b);
    res.end(JSON.stringify({ Hash: cid }));
  } else if (req.url.startsWith("/gw/ipfs/")) {
    const cid = req.url.split("/").pop();
    if (cid === BIG_CID) return res.end(Buffer.alloc(MAX_RECORD_BYTES + 10));
    const b = blobs.get(cid);
    if (!b) {
      res.statusCode = 404;
      return res.end();
    }
    res.end(b);
  } else if (req.url === "/stall") {
    res.writeHead(200, { "content-type": "application/json" });
    res.write("{");
    return; // headers sent, body never finishes
  } else if (req.url === "/huge-error") {
    res.statusCode = 500;
    const chunk = Buffer.alloc(64 * 1024, 0x41);
    let sent = 0;
    const pump = () => {
      while (sent < 64) {
        sent++;
        if (!res.write(chunk)) return res.once("drain", pump);
      }
      res.end();
    };
    pump();
    return;
  } else if (req.url.startsWith("/tgecho")) {
    // A hostile/buggy upstream that echoes the request path (with the token) everywhere.
    res.statusCode = req.url.includes("500") ? 500 : 200;
    return res.end(
      JSON.stringify({ ok: false, error_code: 401, description: `bad ${req.url}`, path: req.url })
    );
  } else if (req.url.startsWith("/tg/bot")) {
    const m = JSON.parse(body.toString());
    res.end(
      JSON.stringify(
        m.chat_id === "fail" ? { ok: false, description: "chat not found" } : { ok: true }
      )
    );
  } else {
    res.statusCode = 404;
    res.end();
  }
});
await new Promise(r => srv.listen(0, "127.0.0.1", r));
const base = `http://127.0.0.1:${srv.address().port}`;
const rec = new TextEncoder().encode('{"kind":"SLASH","key":"7"}\n');
try {
  const p = pinataPinner({
    token: "pjwt",
    gateway: `${base}/gw`,
    uploadUrl: `${base}/pinata/upload`,
  });
  const up = await p.upload(rec);
  const req = seen.find(s => s.url === "/pinata/upload");
  cell(
    "pinata: Bearer token, network=public, cid_version=v1, CID returned",
    up.cid === cidV1Raw(rec) &&
      req.auth === "Bearer pjwt" &&
      /name="network"\r\n\r\npublic/.test(req.body) &&
      /name="cid_version"\r\n\r\nv1/.test(req.body),
    { up, req: req && { auth: req.auth } }
  );
  const back = await p.fetchPublic(up.cid);
  cell(
    "pinata: public gateway fetch by CID returns the bytes",
    back && Buffer.compare(Buffer.from(back), Buffer.from(rec)) === 0,
    null
  );
  cell(
    "gateway body larger than a record is refused (bounded read)",
    (await p.fetchPublic(BIG_CID)) === null,
    null
  );
  cell(
    "gateway 404 is null, not an exception",
    (await p.fetchPublic("bafkrei" + "b".repeat(52))) === null,
    null
  );

  const f = filebasePinner({
    token: "fbtok",
    gateway: `${base}/gw`,
    rpcUrl: `${base}/filebase/add`,
  });
  const fu = await f.upload(rec);
  const freq = seen.find(s => s.url.startsWith("/filebase/add"));
  cell(
    "filebase: bucket token, cid-version=1 and raw-leaves=true requested, Hash returned",
    fu.cid === cidV1Raw(rec) &&
      freq.auth === "Bearer fbtok" &&
      /cid-version=1/.test(freq.url) &&
      /raw-leaves=true/.test(freq.url),
    { fu, url: freq?.url }
  );

  const t = telegramSink({ token: "TOK", chatId: "42", apiBase: `${base}/tg` });
  await t.send("x".repeat(5000));
  const treq = seen.find(s => s.url === "/tg/botTOK/sendMessage");
  const tb = JSON.parse(treq.body);
  cell(
    "telegram: plain text (no parse_mode), truncated to 4000, no preview",
    !("parse_mode" in tb) && tb.text.length === 4000 && tb.disable_web_page_preview === true,
    tb
  );
  let te = null;
  try {
    await telegramSink({ token: "TOK", chatId: "fail", apiBase: `${base}/tg` }).send("hi");
  } catch (e) {
    te = e.message;
  }
  cell("telegram: ok=false is an error", /ok=false/.test(te ?? ""), te);
  const errs = [];
  for (const apiBase of [`${base}/tgecho`, `${base}/tgecho500`]) {
    try {
      await telegramSink({ token: "TOKSECRET", chatId: "42", apiBase }).send("hi");
      errs.push("no error");
    } catch (e) {
      errs.push(e);
    }
  }
  cell(
    "telegram: an upstream that echoes the token (body/description, 200 and 500) never leaks it",
    errs.every(
      e =>
        e instanceof Error &&
        !/TOKSECRET/.test(e.message + String(e.stack)) &&
        e.cause === undefined
    ) && /error_code 401/.test(errs[0]?.message ?? ""),
    errs.map(e => e?.message ?? e)
  );
  let ne = null;
  try {
    await telegramSink({ token: "TOKSECRET", chatId: "42", apiBase: "http://127.0.0.1:1" }).send(
      "x"
    );
  } catch (e) {
    ne = e;
  }
  cell(
    "a network failure is a fixed error with no cause attached (no URL, no token)",
    ne &&
      /request failed/.test(ne.message) &&
      ne.cause === undefined &&
      !/TOKSECRET|127\.0\.0\.1/.test(ne.message),
    ne?.message
  );
  const t0 = Date.now();
  let se = null;
  try {
    await request("stall", `${base}/stall`, {}, { ms: 300 });
  } catch (e) {
    se = e.message;
  }
  cell(
    "the deadline covers the body: headers then a stalled body is a timeout",
    /stall: timeout/.test(se ?? "") && Date.now() - t0 < 5000,
    se
  );
  const big = await request("huge", `${base}/huge-error`, {}, { maxBytes: 1024 });
  let he = null;
  try {
    jsonOf("huge", big);
  } catch (e) {
    he = e.message;
  }
  cell(
    "an oversized error body is cut off at the cap (bytes=null), never buffered whole",
    big.bytes === null && big.status === 500 && /HTTP 500/.test(he ?? ""),
    { status: big.status, n: big.bytes?.length, he }
  );
  const echo = [];
  for (const sink of [
    pinataPinner({ token: "PINSECRET", gateway: `${base}/gw`, uploadUrl: `${base}/pinata/echo` }),
    filebasePinner({ token: "FBSECRET", gateway: `${base}/gw`, rpcUrl: `${base}/filebase/echo` }),
  ]) {
    try {
      echo.push({ accepted: await sink.upload(rec) });
    } catch (e) {
      echo.push(e.message);
    }
  }
  cell(
    "pinners: a 200 answer echoing the token as the CID is refused, without the token",
    echo.every(m => typeof m === "string" && /no valid CID/.test(m) && !/SECRET/.test(m)),
    echo
  );
  const before = seen.length;
  const odd = [await p.fetchPublic("../../admin"), await p.fetchPublic("bafy?x=1")];
  cell(
    "fetchPublic refuses anything but a base32 CIDv1 without sending a request",
    odd.every(v => v === null) && seen.length === before,
    seen.slice(before).map(x => x.url)
  );
} finally {
  srv.close();
}

// ---- git mirror against a local bare "GitHub" and a BARE watcher clone (plumbing, no worktree)
{
  const d = mkdtempSync(join(tmpdir(), "mirror-"));
  try {
    const bare = join(d, "remote.git");
    const seed = join(d, "seed");
    const clone = join(d, "clone.git");
    const other = join(d, "other");
    const g = (cwd, ...a) =>
      execFileSync("git", ["-C", cwd, "-c", "user.name=t", "-c", "user.email=t@t", ...a], {
        stdio: "pipe",
      })
        .toString()
        .trim();
    execFileSync("git", ["init", "--quiet", "--bare", bare]);
    execFileSync("git", ["clone", "--quiet", bare, seed], { stdio: "pipe" });
    g(seed, "commit", "--quiet", "--allow-empty", "-m", "init");
    // A symlink and a plain file already in the tree, for the refusal cells.
    mkdirSync(join(seed, "records"), { recursive: true });
    execFileSync("ln", ["-s", "/etc/passwd", join(seed, "records", "link.json")]);
    writeFileSync(join(seed, "records", "afile"), "x");
    g(seed, "add", "-A");
    g(seed, "commit", "--quiet", "-m", "fixtures");
    g(seed, "push", "--quiet", "origin", "HEAD:refs/heads/disclosure-records");
    execFileSync("git", ["clone", "--quiet", "--bare", bare, clone], { stdio: "pipe" });
    const m = gitMirror({ clone, repoUrl: "https://github.com/o/r" });
    const remoteHead = () => g(bare, "rev-parse", "disclosure-records");
    const r1 = await m.commit("records/bls/a.json", rec, "disclosure a");
    cell(
      "mirror: a new record is committed by plumbing in a bare clone and pushed",
      r1.commit === remoteHead() &&
        r1.url.endsWith(`/blob/${r1.commit}/records/bls/a.json`) &&
        Buffer.compare(
          execFileSync("git", ["-C", bare, "cat-file", "blob", `${r1.commit}:records/bls/a.json`]),
          Buffer.from(rec)
        ) === 0,
      { r1 }
    );
    let r2 = null;
    try {
      r2 = await m.commit("records/bls/a.json", rec, "again");
    } catch (e) {
      r2 = { error: e.message };
    }
    cell(
      "mirror: identical bytes at the same path return the existing commit (idempotent)",
      r2?.existing && r2.commit === r1.commit && remoteHead() === r1.commit,
      r2
    );
    const refuse = async (path, bytes, re) => {
      try {
        await m.commit(path, bytes, "x");
        return "accepted";
      } catch (e) {
        return re.test(e.message) ? true : e.message;
      }
    };
    const diff = await refuse(
      "records/bls/a.json",
      new TextEncoder().encode("other"),
      /different bytes/
    );
    cell(
      "mirror: different bytes at an existing path are refused, never overwritten",
      diff === true,
      diff
    );
    const escapes = [];
    for (const bad of [
      "../escape.json",
      "records/../../x.json",
      ".git/config",
      "records//a.json",
      "/abs.json",
      "records/./a.json",
      "records/a b.json",
      "-rf",
    ]) {
      const r = await refuse(bad, rec, /escapes or is not a plain record path/);
      if (r !== true) escapes.push([bad, r]);
    }
    cell(
      "mirror: escaping, .git, empty/dot segments, absolute and odd paths are refused",
      escapes.length === 0,
      escapes
    );
    let pe = null;
    try {
      await m.commit("records/../../PATHSECRET", rec, "x");
    } catch (e) {
      pe = safeText("publish", e);
    }
    cell(
      "mirror: a rejected path is not echoed, even after both error boundaries",
      /plain record path \(keccak 0x[0-9a-f]{16}\)$/.test(pe ?? "") && !/PATHSECRET/.test(pe ?? ""),
      pe
    );
    const sym = await refuse("records/link.json", rec, /exists as 120000/);
    cell("mirror: a path that is a symlink in the remote tree is refused", sym === true, sym);
    const pre = await refuse("records/afile/x.json", rec, /not a directory/);
    cell("mirror: a path under an existing file is refused", pre === true, pre);
    const cred = join(d, "cred.git");
    execFileSync("git", ["init", "--quiet", "--bare", cred]);
    execFileSync("git", [
      "-C",
      cred,
      "remote",
      "add",
      "origin",
      "https://user:GITSECRET@127.0.0.1:1/r.git",
    ]);
    let ge = null;
    try {
      await gitMirror({ clone: cred }).commit("records/bls/z.json", rec, "z");
    } catch (e) {
      ge = e.message;
    }

    cell(
      "mirror: a failing fetch from a credential-bearing remote is a fixed error, no URL/secret",
      /^mirror commit: git fetch: |^git fetch: /.test(ge ?? "") &&
        !/GITSECRET|127\.0\.0\.1|https/.test(ge ?? ""),
      ge
    );
    // Two calls at once on one clone: each has its own index; no temp index survives; after a
    // retry of whichever lost the race, both records are on the branch.
    const conc = await Promise.allSettled([
      m.commit("records/bls/p.json", new TextEncoder().encode("p"), "p"),
      m.commit("records/bls/q.json", new TextEncoder().encode("q"), "q"),
    ]);
    for (const [i, r] of conc.entries())
      if (r.status === "rejected")
        await m.commit(
          `records/bls/${i === 0 ? "p" : "q"}.json`,
          new TextEncoder().encode(i === 0 ? "p" : "q"),
          "retry"
        );
    const leftovers = execFileSync("ls", [clone])
      .toString()
      .split("\n")
      .filter(f => f.startsWith("watcher-index-"));
    const tipNow = remoteHead();
    const hasAt = path => {
      try {
        execFileSync("git", ["-C", bare, "cat-file", "-e", `${tipNow}:${path}`], { stdio: "pipe" });
        return true;
      } catch {
        return false;
      }
    };
    cell(
      "mirror: concurrent commits keep their own index, leave no temp index, and lose no record",
      leftovers.length === 0 &&
        hasAt("records/bls/p.json") &&
        hasAt("records/bls/q.json") &&
        hasAt("records/bls/a.json"),
      { leftovers, conc: conc.map(r => r.status + (r.reason ? ` ${r.reason.message}` : "")) }
    );
    // Codex R2 M4's case: two branches on one clone, committing at once. With a shared index one
    // commit could be built from the other branch's tree. Each branch must end up holding exactly
    // its own records. Repeated, since the interleaving is timing-dependent.
    g(seed, "checkout", "--quiet", "--orphan", "other-branch");
    g(seed, "rm", "-rf", "--quiet", ".");
    mkdirSync(join(seed, "records", "y"), { recursive: true });
    writeFileSync(join(seed, "records", "y", "base.json"), "y");
    g(seed, "add", "-A");
    g(seed, "commit", "--quiet", "-m", "other base");
    g(seed, "push", "--quiet", "origin", "HEAD:refs/heads/other-branch");
    const mx = gitMirror({ clone });
    const my = gitMirror({ clone, branch: "other-branch" });
    const files = br =>
      g(bare, "ls-tree", "-r", "--name-only", br).split("\n").filter(Boolean).sort();
    const xBefore = files("disclosure-records");
    const yBefore = files("other-branch");
    const added = { x: [], y: [], errors: [] };
    for (let i = 0; i < 6; i++) {
      const px = `records/bls/x${i}.json`;
      const py = `records/y/y${i}.json`;
      const rs = await Promise.allSettled([
        mx.commit(px, new TextEncoder().encode(px), px),
        my.commit(py, new TextEncoder().encode(py), py),
      ]);
      for (const r of rs) if (r.status === "rejected") added.errors.push(r.reason.message);
      added.x.push(px);
      added.y.push(py);
    }
    const wantX = [...xBefore, ...added.x].sort();
    const wantY = [...yBefore, ...added.y].sort();
    cell(
      "mirror: concurrent commits to two branches of one clone never mix their trees",
      added.errors.length === 0 &&
        j(files("disclosure-records")) === j(wantX) &&
        j(files("other-branch")) === j(wantY),
      { errors: added.errors.slice(0, 3), x: files("disclosure-records"), y: files("other-branch") }
    );
    // A concurrent writer pushes between our fetch and our push: our push is refused (nothing of
    // theirs is overwritten), and the retry appends on the new tip with both records present.
    execFileSync("git", ["clone", "--quiet", "--branch", "disclosure-records", bare, other], {
      stdio: "pipe",
    });
    let raced = false;
    const mr = gitMirror({
      clone,
      beforePush: async () => {
        if (raced) return;
        raced = true;
        writeFileSync(join(other, "records", "b.json"), "b");
        g(other, "add", "-A");
        g(other, "commit", "--quiet", "-m", "other writer");
        g(other, "push", "--quiet", "origin", "HEAD:refs/heads/disclosure-records");
      },
    });
    let race1 = null;
    try {
      race1 = await mr.commit("records/bls/c.json", rec, "c");
    } catch (e) {
      race1 = { error: e.message };
    }
    const theirs = remoteHead();
    const race2 = await mr.commit("records/bls/c.json", rec, "c");
    const has = (c, path) => {
      try {
        execFileSync("git", ["-C", bare, "cat-file", "-e", `${c}:${path}`], { stdio: "pipe" });
        return true;
      } catch {
        return false;
      }
    };
    cell(
      "mirror: a push racing another writer is refused, then the retry lands on the new tip",
      race1?.error &&
        race2.commit === remoteHead() &&
        g(bare, "rev-parse", `${race2.commit}^`) === theirs &&
        has(race2.commit, "records/b.json") &&
        has(race2.commit, "records/bls/c.json"),
      { race1, race2 }
    );
    const hook = join(bare, "hooks", "pre-receive");
    // DSR: the hook's stderr also carries a credential-bearing URL; the push must not land either
    writeFileSync(
      hook,
      "#!/bin/sh\necho 'denied by policy GITSECRET https://tok:GITSECRET@host/r' >&2\nexit 1\n"
    );
    const tipBeforeHook = remoteHead();
    execFileSync("chmod", ["+x", hook]);
    let hk = null;
    try {
      await m.commit("records/bls/h.json", rec, "h");
    } catch (e) {
      hk = e.message;
    }
    rmSync(hook);
    cell(
      "mirror: a hook rejection is 'push rejected by the remote', not 'the branch moved', no stderr",
      /push: push rejected by the remote$/.test(hk ?? "") &&
        !/GITSECRET|tok:|host\/r/.test(hk ?? "") &&
        remoteHead() === tipBeforeHook, // nothing mirrored
      hk
    );
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
}

// ---- registry signer
{
  const w = ethers.Wallet.createRandom();
  const other = ethers.Wallet.createRandom().address;
  const roles = {
    deployer: other,
    aggregatorOwner: ethers.Wallet.createRandom().address,
    guardians: [ethers.Wallet.createRandom().address, ethers.Wallet.createRandom().address],
  };
  let ok = true;
  try {
    assertWriterRole(w.address, roles);
  } catch {
    ok = false;
  }
  cell("writer role: a dedicated writer address is accepted", ok, null);
  for (const [name, r] of [
    ["deployer", { ...roles, deployer: w.address }],
    ["aggregator owner", { ...roles, aggregatorOwner: w.address }],
    ["guardian", { ...roles, guardians: [roles.guardians[0], w.address.toLowerCase()] }],
  ]) {
    let msg = null;
    try {
      assertWriterRole(w.address, r);
    } catch (e) {
      msg = e.message;
    }
    cell(
      `writer role: refused when the writer is also the ${name}`,
      new RegExp(`also the .*${name}`).test(msg ?? ""),
      msg
    );
  }
  cell(
    "actionId = keccak256(abi.encode(uint8 kind, uint256 key)) as in the registry",
    actionId(2, 5n) ===
      ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(["uint8", "uint256"], [2, 5n])),
    null
  );

  const REG = ethers.getAddress("0x" + "ab".repeat(20));
  const provider = {
    async getTransactionCount() {
      return 7;
    },
    async getFeeData() {
      return { maxFeePerGas: 1000n, maxPriorityFeePerGas: 100n };
    },
    async getNetwork() {
      return { chainId: 10n };
    },
    async estimateGas() {
      return 100000n;
    },
  };
  const fees = { maxFeePerGas: 1000n, maxPriorityFeePerGas: 100n };
  provider.getFeeData = async () => ({ ...fees });
  const sink = registrySink({ provider, wallet: w, registry: REG, fromBlock: 0, roles });
  const args = {
    signed: {
      kind: 0,
      proposalId: 7n,
      messageInputs: "0x1234",
      signerMask: 3n,
      signers: [other],
      anchor: ethers.ZeroHash,
    },
    subjectToken: ethers.ZeroAddress,
    txHash: ethers.id("tx"),
    blockNumber: 100n,
    rulesetCommit: "0x" + "ab".repeat(20),
    recordURI: "ipfs://bafkreix",
    recordHash: ethers.id("r"),
  };
  const s1 = await sink.sign(args);
  const t1 = ethers.Transaction.from(s1.raw);
  const dec = regSinkIface.parseTransaction({ data: t1.data });
  cell(
    "sign: a signed EIP-1559 tx to the registry calling disclose with the given args, nonce from the provider",
    t1.to === REG &&
      t1.from === w.address &&
      t1.nonce === 7 &&
      t1.chainId === 10n &&
      dec.name === "disclose" &&
      dec.args.recordURI === "ipfs://bafkreix" &&
      s1.hash === t1.hash &&
      t1.gasLimit === 120000n,
    { to: t1.to, nonce: t1.nonce, name: dec?.name }
  );
  // Replacement fees come from the REPLACED tx, not from the current estimate (Codex R1 H4).
  const s0 = await sink.sign(args, { nonce: 3 });
  fees.maxFeePerGas = 500n; // the estimate FELL since the original was sent
  fees.maxPriorityFeePerGas = 50n;
  const s2 = await sink.sign(args, { nonce: 3, replace: true, prevRaw: s0.raw });
  const t2 = ethers.Transaction.from(s2.raw);
  const s3 = await sink.sign(args, { nonce: 3, replace: true, prevRaw: s2.raw });
  const t3 = ethers.Transaction.from(s3.raw);
  cell(
    "sign: replacements bump from the replaced tx (ceil x1.25) even when the estimate fell, and keep rising",
    t2.nonce === 3 &&
      t2.maxFeePerGas === 1250n &&
      t2.maxPriorityFeePerGas === 125n &&
      t3.maxFeePerGas === 1563n &&
      t3.maxPriorityFeePerGas === 157n,
    {
      t2: [t2.maxFeePerGas, t2.maxPriorityFeePerGas],
      t3: [t3.maxFeePerGas, t3.maxPriorityFeePerGas],
    }
  );
  fees.maxFeePerGas = 9000n; // the estimate ROSE above the floor: the estimate wins
  fees.maxPriorityFeePerGas = 900n;
  const t4 = ethers.Transaction.from(
    (await sink.sign(args, { nonce: 3, replace: true, prevRaw: s0.raw })).raw
  );
  cell(
    "sign: a replacement uses the current estimate when it is above the bumped floor",
    t4.maxFeePerGas === 9000n && t4.maxPriorityFeePerGas === 900n,
    [t4.maxFeePerGas, t4.maxPriorityFeePerGas]
  );
  fees.maxFeePerGas = 1000n;
  fees.maxPriorityFeePerGas = 100n;
  const refusals = {};
  for (const [name, o] of [
    ["no prevRaw", { nonce: 3, replace: true }],
    ["prevRaw at another nonce", { nonce: 4, replace: true, prevRaw: s0.raw }],
    [
      "prevRaw from another key",
      {
        nonce: 3,
        replace: true,
        prevRaw: await ethers.Wallet.createRandom().signTransaction({
          to: REG,
          data: "0x",
          nonce: 3,
          chainId: 10n,
          type: 2,
          maxFeePerGas: 1000n,
          maxPriorityFeePerGas: 100n,
          gasLimit: 21000n,
        }),
      },
    ],
  ]) {
    try {
      await sink.sign(args, o);
      refusals[name] = "accepted";
    } catch (e) {
      refusals[name] = /journalled|not ours/.test(e.message) ? true : e.message;
    }
  }
  cell(
    "sign: a replacement without the replaced raw tx, at another nonce, or of another key is refused",
    Object.values(refusals).every(v => v === true),
    refusals
  );
  const leaky = registrySink({
    provider: {
      async call() {
        throw Object.assign(new Error("request to https://rpc.example/v2/RPCSECRET failed"), {
          url: "https://rpc.example/v2/RPCSECRET",
        });
      },
      async broadcastTransaction() {
        throw Object.assign(new Error("RPCSECRET nonce too low"), { code: "NONCE_EXPIRED" });
      },
    },
    wallet: w,
    registry: REG,
    fromBlock: 0,
    roles,
  });
  const le = [];
  for (const f of [() => leaky.entryOf(0, 1n), () => leaky.broadcast("0x")]) {
    try {
      await f();
      le.push("no error");
    } catch (e) {
      le.push({ m: e.message, short: e.shortMessage, cause: e.cause, url: e.url });
    }
  }
  cell(
    "registry: RPC failures leave as 'registry <op>: <code>' with no message, URL or cause",
    le[0]?.m === "registry entryOf: error" &&
      le[1]?.m === "registry broadcast: NONCE_EXPIRED" &&
      le.every(x => x.short === undefined && x.cause === undefined && x.url === undefined),
    le
  );
  const badRec = regSinkIface.encodeEventLog("Disclosed", [
    5n,
    0,
    7n,
    7n,
    ethers.id("m"),
    [other],
    [
      ethers.ZeroAddress,
      ethers.id("tx"),
      100n,
      true,
      "0x" + "00".repeat(20),
      "https://rpc/v2/KEYSECRET",
      ethers.id("r"),
    ],
  ]);
  const uriSink = registrySink({
    provider: {
      async call() {
        return ethers.AbiCoder.defaultAbiCoder().encode(["bytes32"], [ethers.id("b")]);
      },
      async getLogs({ topics }) {
        return topics[0] === regSinkIface.getEvent("Disclosed").topicHash
          ? [{ address: REG, topics: badRec.topics, data: badRec.data, blockNumber: 1, index: 0 }]
          : [];
      },
    },
    wallet: w,
    registry: REG,
    fromBlock: 0,
    roles,
  });
  const ent = await uriSink.entry(5n, { blockTag: 10 });
  cell(
    "registry entry(): an on-chain recordURI not in our form leaves the sink as a marker",
    ent.recordURI === "invalid:uri" &&
      ent.recordURIKeccak === ethers.keccak256(ethers.toUtf8Bytes("https://rpc/v2/KEYSECRET")) &&
      !j(ent).includes("KEYSECRET"),
    ent
  );
  // Writer-role separation is enforced BY THE SINK (Codex R1 H7): incomplete roles refuse
  // construction; a wallet that is a guardian is refused before anything is signed.
  const ctor = {};
  for (const [name, r] of [
    ["no roles", undefined],
    ["no guardians", { ...roles, guardians: [] }],
    ["no deployer", { ...roles, deployer: undefined }],
    ["bad owner", { ...roles, aggregatorOwner: "0x1234" }],
  ]) {
    try {
      registrySink({ provider, wallet: w, registry: REG, fromBlock: 0, roles: r });
      ctor[name] = "accepted";
    } catch (e) {
      ctor[name] = /unknown; refusing/.test(e.message) ? true : e.message;
    }
  }
  cell(
    "registrySink: unknown or incomplete roles refuse construction (fail closed)",
    Object.values(ctor).every(v => v === true),
    ctor
  );
  let gs = null;
  try {
    await registrySink({
      provider,
      wallet: w,
      registry: REG,
      fromBlock: 0,
      roles: { ...roles, guardians: [roles.guardians[0], w.address] },
    }).sign(args);
    gs = "signed";
  } catch (e) {
    gs = e.message;
  }
  cell(
    "registrySink: a wallet that is a guardian is refused at sign time",
    /also the guardian 1/.test(gs ?? ""),
    gs
  );

  // Codex W2c R4: rebroadcasting a tx the node already holds is not a failure; a real error is
  {
    const mk = err => {
      const p = {
        ...provider,
        broadcastTransaction: async () => {
          throw err;
        },
      };
      return registrySink({ provider: p, wallet: w, registry: REG, fromBlock: 0, roles });
    };
    const known = await mk(
      Object.assign(new Error("x"), { error: { message: "already known" } })
    ).broadcast("0x01");
    let real = null;
    try {
      await mk(Object.assign(new Error("boom TOKSECRET"), { code: "SERVER_ERROR" })).broadcast(
        "0x01"
      );
    } catch (e) {
      real = e.message;
    }
    cell(
      "registrySink.broadcast: 'already known' is success; any other error still fails, without the provider's text",
      known?.known === true &&
        /registry broadcast: SERVER_ERROR/.test(real ?? "") &&
        !/TOKSECRET/.test(real ?? ""),
      { known, real }
    );
  }

  {
    const E = m => Object.assign(new Error("wrapper"), { error: { message: m } });
    const yes = [
      "already known",
      "Known transaction",
      "transaction already imported",
      "rpc error: already known.",
      "known transaction: 0x" + "ab".repeat(32),
    ];
    const no = [
      "unknown transaction",
      "failed: transaction is not already known",
      "already known by nobody",
      "nonce too low",
      "replacement transaction underpriced",
    ];
    cell(
      "alreadyKnown: only whole known-tx phrasings match; 'unknown transaction' and wrapped negatives do not",
      yes.every(m => alreadyKnown(E(m))) && no.every(m => !alreadyKnown(E(m))),
      { yes: yes.map(m => alreadyKnown(E(m))), no: no.map(m => alreadyKnown(E(m))) }
    );
  }

  // Codex W2c R1 H2: roles are re-read immediately before each signature, and a failure refuses
  const late = {};
  for (const [name, cur] of [
    ["appointed since", async () => ({ ...roles, guardians: [...roles.guardians, w.address] })],
    [
      "unreadable",
      async () => {
        throw new Error("rpc down");
      },
    ],
    ["unchanged", async () => roles],
  ]) {
    let calls = 0;
    try {
      await registrySink({
        provider,
        wallet: w,
        registry: REG,
        fromBlock: 0,
        roles,
        currentRoles: () => {
          calls++;
          return cur();
        },
      }).sign(args);
      late[name] = `signed:${calls}`;
    } catch (e) {
      late[name] = `${e.message}:${calls}`;
    }
  }
  cell(
    "registrySink: roles re-read at sign time; a writer appointed since the pass's read, or unreadable roles, is refused",
    /also the guardian/.test(late["appointed since"]) &&
      /current roles unreadable; refusing to sign:1/.test(late.unreadable) &&
      late.unchanged === "signed:1",
    late
  );

  const foreign = regSinkIface.encodeEventLog("Disclosed", [
    99n,
    0,
    7n,
    7n,
    ethers.id("m"),
    [other],
    [ethers.ZeroAddress, ethers.id("tx"), 100n, true, "0x" + "00".repeat(20), "u", ethers.id("r")],
  ]);
  const ev = regSinkIface.encodeEventLog("Disclosed", [
    9n,
    0,
    7n,
    7n,
    ethers.id("m"),
    [other],
    [ethers.ZeroAddress, ethers.id("tx"), 100n, true, "0x" + "00".repeat(20), "u", ethers.id("r")],
  ]);
  const sink2 = registrySink({
    provider: {
      async getTransactionReceipt() {
        return {
          status: 1,
          blockNumber: 50,
          blockHash: ethers.id("b50"),
          logs: [
            { address: other, topics: foreign.topics, data: foreign.data },
            { address: REG, topics: ev.topics, data: ev.data },
          ],
        };
      },
    },
    wallet: w,
    registry: REG,
    fromBlock: 0,
    roles,
  });
  const rc = await sink2.receipt(ethers.id("h"));
  cell(
    "receipt: entryId from the registry's own Disclosed log; block hash carried for canonical()",
    rc.entryId === 9n && rc.blockHash === ethers.id("b50") && rc.status === 1,
    rc
  );
}

let failed = 0;
for (const r of results) {
  console.log(`${r.ok ? "ok  " : "FAIL"} ${r.name}${r.ok ? "" : `\n     got ${r.got}`}`);
  if (!r.ok) failed++;
}
console.log(`\n${results.length - failed}/${results.length} cells`);
process.exit(failed ? 1 : 0);
