// CI self-test for the W2b sinks against local mocks: an HTTP server standing in for Pinata,
// Filebase, the gateways and Telegram; a local bare git repo for the mirror; fake providers for the
// registry signer. No network, no real credentials. Live provider cells are separate (pre-go-live).
import { createServer } from "node:http";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ethers } from "ethers";
import { readSecret } from "./lib/keychain.mjs";
import { cidV1Raw, MAX_RECORD_BYTES } from "./lib/cid.mjs";
import { pinataPinner } from "./sinks/pinata.mjs";
import { filebasePinner } from "./sinks/filebase.mjs";
import { telegramSink } from "./sinks/telegram.mjs";
import { gitMirror } from "./sinks/git-mirror.mjs";
import { registrySink, assertWriterRole, actionId, regSinkIface } from "./sinks/registry.mjs";

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

// ---- local HTTP mock
const seen = [];
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
  if (req.url === "/pinata/upload") {
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
    if (cid === "big") return res.end(Buffer.alloc(MAX_RECORD_BYTES + 10));
    const b = blobs.get(cid);
    if (!b) {
      res.statusCode = 404;
      return res.end();
    }
    res.end(b);
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
    (await p.fetchPublic("big")) === null,
    null
  );
  cell(
    "gateway 404 is null, not an exception",
    (await p.fetchPublic("bafkreinothere")) === null,
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
  cell("errors never carry the token", ![te].some(m => /TOK/.test(m ?? "")), te);
} finally {
  srv.close();
}

// ---- git mirror against a local bare repo
{
  const d = mkdtempSync(join(tmpdir(), "mirror-"));
  try {
    const bare = join(d, "remote.git");
    const clone = join(d, "clone");
    const g = (cwd, ...a) =>
      execFileSync("git", ["-C", cwd, ...a], { stdio: "pipe" })
        .toString()
        .trim();
    execFileSync("git", ["init", "--quiet", "--bare", bare]);
    execFileSync("git", ["clone", "--quiet", bare, clone], { stdio: "pipe" });
    g(
      clone,
      "-c",
      "user.name=t",
      "-c",
      "user.email=t@t",
      "commit",
      "--quiet",
      "--allow-empty",
      "-m",
      "init"
    );
    g(clone, "push", "--quiet", "origin", "HEAD:refs/heads/disclosure-records");
    const m = gitMirror({ clone, repoUrl: "https://github.com/o/r" });
    const r1 = await m.commit("records/bls/a.json", rec, "disclosure a");
    const remoteHead = execFileSync("git", ["-C", bare, "rev-parse", "disclosure-records"])
      .toString()
      .trim();
    cell(
      "mirror: a new record is committed and pushed to disclosure-records",
      r1.commit === remoteHead && r1.url.endsWith(`/blob/${r1.commit}/records/bls/a.json`),
      { r1, remoteHead }
    );
    let r2 = null;
    try {
      r2 = await m.commit("records/bls/a.json", rec, "again");
    } catch (e) {
      r2 = { error: e.message };
    }
    cell(
      "mirror: identical bytes at the same path return the existing commit (idempotent)",
      r2?.existing && r2.commit === r1.commit,
      r2
    );
    let e1 = null;
    try {
      await m.commit("records/bls/a.json", new TextEncoder().encode("other"), "x");
    } catch (e) {
      e1 = e.message;
    }
    cell(
      "mirror: different bytes at an existing path are refused, never overwritten",
      /different bytes/.test(e1 ?? ""),
      e1
    );
    let e2 = null;
    try {
      await m.commit("../escape.json", rec, "x");
    } catch (e) {
      e2 = e.message;
    }
    cell("mirror: a path escaping the clone is refused", /escapes/.test(e2 ?? ""), e2);
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
  const sink = registrySink({ provider, wallet: w, registry: REG, fromBlock: 0 });
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
  const s2 = await sink.sign(args, { nonce: 3, replace: true });
  const t2 = ethers.Transaction.from(s2.raw);
  cell(
    "sign: a replacement keeps the journalled nonce and bumps both fees by 25%",
    t2.nonce === 3 && t2.maxFeePerGas === 1250n && t2.maxPriorityFeePerGas === 125n,
    { n: t2.nonce, f: t2.maxFeePerGas }
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
