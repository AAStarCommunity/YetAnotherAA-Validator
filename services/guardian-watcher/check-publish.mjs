// CI self-test for W2 publication (lib/cid.mjs, lib/record-file.mjs, lib/publish.mjs) with mock
// sinks. Live provider cells (Pinata, Filebase) are separate and wait for the author's accounts.
import { ethers } from "ethers";
import { MAX_RECORD_BYTES, cidV1Raw } from "./lib/cid.mjs";
import { recordFile, mirrorPath } from "./lib/record-file.mjs";
import { publishRecord, discloseArgs, expectedBinding, PersistError } from "./lib/publish.mjs";
import { acquireLock } from "./lib/lock.mjs";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// Mock-sink runs that do not exercise the journal say so explicitly (the library refuses otherwise).
const pub = (rec, s, prev = {}, opts = {}) =>
  publishRecord(rec, s, prev, opts.persist ? opts : { ...opts, unsafeNoJournal: true });

const results = [];
const j = v => JSON.stringify(v, (_, x) => (typeof x === "bigint" ? x.toString() : x));
const cell = (name, ok, got) => results.push({ name, ok: !!ok, got: ok ? "" : j(got) });

// ---- CID vectors, cross-checked with Kubo 0.41.0 `ipfs add --only-hash --cid-version 1 --raw-leaves`
const pattern = n => Uint8Array.from({ length: n }, (_, i) => (i * 7 + 3) % 256);
cell(
  "CID: empty file",
  cidV1Raw(new Uint8Array()) === "bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku",
  cidV1Raw(new Uint8Array())
);
cell(
  "CID: exactly 262,144 bytes (still one raw block)",
  cidV1Raw(pattern(MAX_RECORD_BYTES)) ===
    "bafkreih4mbpgbbmrcjifkrtxbk4fbp57ajbuqqkawqwr62xjkvv3vj3yjy",
  cidV1Raw(pattern(MAX_RECORD_BYTES))
);
cell(
  "CID: a 27-byte JSON record",
  cidV1Raw(new TextEncoder().encode('{"kind":"SLASH","key":"7"}\n')) ===
    "bafkreiamq5q5hxcpzjlqq5wm5uaboz5du5q22x4wqjiozhu7l7hyl2xcze",
  null
);
let refused = false;
try {
  cidV1Raw(pattern(MAX_RECORD_BYTES + 1)); // Kubo gives a dag-pb root for this size
} catch {
  refused = true;
}
cell("CID: 262,145 bytes is refused (would not be a single raw block)", refused, null);

// ---- records
const signers = [
  ethers.getAddress("0x" + "11".repeat(20)),
  ethers.getAddress("0x" + "22".repeat(20)),
];
const bls = {
  route: "bls",
  kind: "SLASH",
  key: "7",
  proposalId: "7",
  messageHash: ethers.id("m"),
  messageInputs: "0x1234",
  signerMask: "3",
  signers,
  anchor: ethers.id("anchor"),
  txHash: ethers.id("tx"),
  blockNumber: 100,
  logIndex: 0,
  ruleset: { commit: "ab".repeat(20), hash: ethers.id("rs"), verified: true },
  verdict: { flagged: true, reasons: ["BLS operator slash executed"], rule: "bls.SLASH" },
  seenAt: "2026-11-10T00:00:00Z",
};
const owner = {
  route: "owner",
  label: "owner/guardian route: not BLS, no on-chain signer verification",
  event: "OperatorSlashed",
  args: { operator: signers[0], amount: 5n, level: 1n },
  txHash: ethers.id("otx"),
  logIndex: 2,
  blockNumber: 101,
  verdict: { flagged: true, reasons: ["owner route: OperatorSlashed"] },
  seenAt: "x",
};

const f1 = recordFile(bls);
const reordered = Object.fromEntries(Object.entries(bls).reverse());
cell(
  "record bytes are deterministic (key order, local fields ignored)",
  recordFile({ ...reordered, seenAt: "other" }).cid === f1.cid,
  null
);
cell(
  "recordHash is keccak256 of the exact file bytes",
  f1.recordHash === ethers.keccak256(f1.bytes),
  null
);
cell(
  "mirror path is a function of record and CID only",
  mirrorPath(bls, f1.cid) === mirrorPath(reordered, f1.cid) &&
    mirrorPath(bls, f1.cid).endsWith(`.${f1.cid}.json`),
  mirrorPath(bls, f1.cid)
);

// ---- mock sinks
function sinks(opts = {}) {
  const calls = { telegram: 0, sign: 0, broadcast: 0, mirror: 0, uploads: {}, texts: [] };
  const stored = new Map();
  const pinOpts = { pinata: { ...(opts.pinata ?? {}) }, filebase: { ...(opts.filebase ?? {}) } };
  const mkPinner = name => ({
    name,
    async upload(bytes) {
      const o = pinOpts[name];
      calls.uploads[name] = (calls.uploads[name] ?? 0) + 1;
      if (o.fail) throw new Error(`${name} down`);
      const real = cidV1Raw(bytes);
      const cid = o.wrongCid ? "bafkreiwrong" : real; // reports a wrong CID, still serves the bytes
      stored.set(`${name}:${real}`, o.alterBytes ? Uint8Array.from([...bytes, 0x20]) : bytes);
      return { cid };
    },
    async fetchPublic(cid) {
      const o = pinOpts[name];
      if (o.private || o.gone) return null; // private upload, or unpinned later
      return stored.get(`${name}:${cid}`) ?? null;
    },
  });
  const chainState = {
    nonce: 0,
    receipts: new Map(),
    mined: opts.mine ?? "success",
    entryOf: opts.existing?.entryId,
    binding: opts.existing?.binding,
  };
  return {
    calls,
    pinOpts,
    chainState,
    pinners: [mkPinner("pinata"), mkPinner("filebase")],
    mirror: {
      async commit(path) {
        calls.mirror++;
        if (opts.mirrorFail) throw new Error("push rejected");
        return { commit: "c0ffee", url: `https://github.com/x/y/blob/c0ffee/${path}` };
      },
    },
    telegram: {
      async send(t) {
        calls.telegram++;
        calls.texts.push(t);
        if (opts.telegramAckLost && calls.telegram === 1)
          throw new Error("connection reset after delivery");
      },
    },
    registry: {
      async entryOf() {
        return chainState.entryOf ?? 0n;
      },
      async binding() {
        return chainState.binding ?? ethers.ZeroHash;
      },
      async sign(args) {
        calls.sign++;
        calls.lastArgs = args;
        const nonce = chainState.nonce;
        return { raw: `0xraw${calls.sign}`, hash: ethers.id(`disclose-${calls.sign}`), nonce };
      },
      async broadcast(raw) {
        calls.broadcast++;
        calls.lastRaw = raw;
        if (chainState.mined === "success" || chainState.mined === "revert") {
          const n = Number(raw.slice(5));
          chainState.receipts.set(ethers.id(`disclose-${n}`), {
            status: chainState.mined === "success" ? 1 : 0,
            entryId: chainState.mined === "success" ? n : null,
          });
          chainState.nonce = Math.max(chainState.nonce, 1);
        }
      },
      async receipt(hash) {
        return chainState.receipts.get(hash) ?? null;
      },
      async nonce() {
        return chainState.nonce;
      },
    },
  };
}

{
  const s = sinks();
  const r1 = await pub(bls, s);
  cell(
    "happy path: both pins current, mirror committed, published, Telegram once, registry confirmed",
    r1.state.published &&
      r1.state.pins.pinata.current &&
      r1.state.pins.filebase.current &&
      s.calls.telegram === 1 &&
      s.calls.sign === 1 &&
      r1.state.registry.phase === "confirmed" &&
      r1.alerts.length === 0,
    { st: r1.state, alerts: r1.alerts, calls: s.calls }
  );
  const a = s.calls.lastArgs;
  cell(
    "registry args: kind, id, inputs, mask, signers, anchor, ipfs:// URI, recordHash, ruleset commit",
    a.signed.kind === 0 &&
      a.signed.proposalId === 7n &&
      a.signed.signerMask === 3n &&
      a.signed.signers.length === 2 &&
      a.recordURI === `ipfs://${f1.cid}` &&
      a.recordHash === f1.recordHash &&
      a.rulesetCommit === `0x${"ab".repeat(20)}`,
    a
  );
  cell(
    "Telegram text names the record CID and the mirror URL",
    s.calls.texts[0].includes(`ipfs://${f1.cid}`) && s.calls.texts[0].includes("github.com"),
    s.calls.texts[0]
  );
  const r2 = await pub(bls, s, r1.state);
  cell(
    "re-run is idempotent: no new upload, Telegram, sign or broadcast",
    s.calls.telegram === 1 &&
      s.calls.sign === 1 &&
      s.calls.broadcast === 1 &&
      s.calls.uploads.pinata === 1 &&
      s.calls.mirror === 1 &&
      r2.state.published,
    s.calls
  );
}

{
  const s = sinks({ filebase: { fail: true } });
  const r1 = await pub(bls, s);
  cell(
    "one provider down: still published (one current pin + mirror), alerted",
    r1.state.published &&
      !r1.state.pins.filebase.current &&
      r1.alerts.some(x => /1\/2 current pins/.test(x)),
    r1
  );
  await pub(bls, s, r1.state);
  cell(
    "…the failed pin is retried, the good one is not re-uploaded",
    s.calls.uploads.filebase === 2 && s.calls.uploads.pinata === 1 && s.calls.sign === 1,
    s.calls.uploads
  );
}

{
  const s = sinks({ pinata: { wrongCid: true }, filebase: { fail: true } });
  const r = await pub(bls, s);
  cell(
    "provider returning a different CID is not a pin; nothing current -> not published, no Telegram/registry",
    !r.state.published &&
      !r.state.pins.pinata.current &&
      s.calls.telegram === 0 &&
      s.calls.sign === 0,
    r
  );
}
{
  const s = sinks({ pinata: { alterBytes: true }, filebase: { fail: true } });
  const r = await pub(bls, s);
  cell(
    "gateway serving different bytes for the CID: not a pin",
    !r.state.published && /exact bytes/.test(r.state.pins.pinata.error),
    r.state.pins
  );
}
{
  const s = sinks({ pinata: { private: true }, filebase: { fail: true } });
  const r = await pub(bls, s);
  cell(
    "uploaded but not publicly fetchable (private): not a pin",
    !r.state.published && !r.state.pins.pinata.current,
    r.state.pins
  );
}
{
  const s = sinks({ mirrorFail: true });
  const r = await pub(bls, s);
  cell(
    "mirror commit failed: not published even with both pins",
    !r.state.published &&
      r.state.pins.pinata.current &&
      s.calls.telegram === 0 &&
      s.calls.sign === 0,
    r
  );
}
{
  const s = sinks();
  const r = await pub(owner, s);
  cell(
    "owner/guardian-route record: published to IPFS+mirror+Telegram, NO registry entry",
    r.state.published &&
      s.calls.telegram === 1 &&
      s.calls.sign === 0 &&
      !r.state.registry &&
      !r.alerts.some(x => /registry/.test(x)),
    s.calls
  );
}
{
  const s = sinks({ existing: { entryId: 9n, binding: expectedBinding(bls) } });
  const r = await pub(bls, s);
  cell(
    "an entry already in the registry with this record's binding is adopted, not re-signed",
    s.calls.sign === 0 && r.state.registry.recovered && r.state.registry.entryId === "9",
    r.state.registry
  );
  const s2 = sinks({ existing: { entryId: 9n, binding: ethers.id("another action's binding") } });
  const r2 = await pub(bls, s2);
  const r3 = await pub(bls, s2, r2.state);
  cell(
    "an existing entry with a DIFFERENT binding is a conflict: not confirmed, not re-signed, re-alerted",
    r3.state.registry.phase === "conflict" &&
      s2.calls.sign === 0 &&
      r3.alerts.some(x => /different binding/.test(x)),
    { reg: r3.state.registry, alerts: r3.alerts }
  );
}
{
  const s = sinks();
  const r = await pub(bls, s, { cid: "bafkreiother" });
  cell(
    "record bytes changed after first publication: refused, alerted, nothing sent",
    s.calls.mirror === 0 && s.calls.sign === 0 && r.alerts.some(x => /changed/.test(x)),
    r
  );
}

// ---- crash points (Codex W2a review): the journal makes each stage repeatable
{
  // Crash right after broadcast: the state persisted last says "signed". On restart the SAME raw
  // tx is rebroadcast; no second signature, hence no second entry.
  const s = sinks({ mine: "pending" });
  let snapshot = null;
  let crash = true;
  const persist = async st => {
    if (crash && st.registry?.phase === "sent") throw new Error("power cut");
    snapshot = JSON.parse(j(st));
  };
  try {
    await pub(bls, s, {}, { persist });
  } catch {
    /* crashed */
  }
  cell(
    "crash after broadcast: the journal holds the signed raw tx",
    snapshot?.registry?.phase === "signed" && snapshot.registry.raw === "0xraw1",
    snapshot?.registry
  );
  crash = false;
  s.chainState.mined = "success";
  const r = await pub(bls, s, snapshot, { persist });
  cell(
    "…restart rebroadcasts the same raw tx, never signs again, and confirms on the receipt",
    s.calls.sign === 1 && s.calls.lastRaw === "0xraw1" && r.state.registry.phase === "confirmed",
    { calls: s.calls, reg: r.state.registry }
  );
}
{
  const s = sinks({ mine: "pending" });
  const r1 = await pub(bls, s);
  const r2 = await pub(bls, s, r1.state);
  cell(
    "a pending disclose tx stays pending: not confirmed, not re-signed",
    r2.state.registry.phase === "sent" && s.calls.sign === 1,
    { reg: r2.state.registry, calls: s.calls }
  );
  s.chainState.nonce = 5; // our nonce was consumed by another tx: this one was dropped/replaced
  const r3 = await pub(bls, s, r2.state);
  cell(
    "a dropped tx (nonce consumed, no receipt) is detected and re-signed once",
    s.calls.sign === 2 && r3.alerts.some(x => /dropped or replaced/.test(x)),
    { calls: s.calls, alerts: r3.alerts }
  );
}
{
  const s = sinks({ mine: "revert" });
  const r1 = await pub(bls, s);
  const r2 = await pub(bls, s, r1.state);
  const r3 = await pub(bls, s, r2.state);
  cell(
    "a reverted disclose tx: alerted, marked reverted, not blindly re-signed",
    r3.state.registry.phase === "reverted" &&
      s.calls.sign === 1 &&
      r2.alerts.some(x => /reverted/.test(x)),
    { reg: r3.state.registry, calls: s.calls, a: r2.alerts }
  );
}
{
  // A pin verified earlier no longer serves: reverify demotes it and re-uploads.
  const s = sinks();
  const r1 = await pub(bls, s);
  s.pinOpts.pinata.gone = true;
  s.pinOpts.filebase.gone = true;
  s.pinOpts.filebase.fail = true;
  const r2 = await pub(bls, s, r1.state, { reverify: true });
  cell(
    "reverify: pins that no longer serve are demoted; with none current the record is not published",
    !r2.state.pins.pinata.current &&
      !r2.state.published &&
      r2.alerts.some(x => /no longer serves/.test(x)),
    { pins: r2.state.pins, alerts: r2.alerts }
  );
  s.pinOpts.pinata.gone = false;
  const r3 = await pub(bls, s, r2.state);
  cell(
    "…and the demoted pin is uploaded again and becomes current",
    r3.state.pins.pinata.current && r3.state.published,
    r3.state.pins
  );
}
{
  // A provider no longer configured does not count.
  const s = sinks({ filebase: { fail: true } });
  s.pinners = [s.pinners[1]]; // only filebase configured now, and it fails
  const r = await pub(bls, s, { pins: { pinata: { current: true } }, cid: f1.cid });
  cell("a pin at a provider no longer configured is not counted", !r.state.published, r.state);
}
{
  // Telegram accepted the message but the ack was lost: at-least-once, re-sent marked.
  const s = sinks({ telegramAckLost: true });
  const r1 = await pub(bls, s);
  const r2 = await pub(bls, s, r1.state);
  cell(
    "Telegram ack lost: re-sent once, marked as a possible duplicate",
    s.calls.telegram === 2 && /may be a duplicate/.test(s.calls.texts[1]) && r2.state.telegram.at,
    s.calls.texts
  );
}
{
  // A revert caused by AlreadyDisclosed (another of our txs landed first): adopted, not parked.
  const s = sinks({ mine: "revert" });
  const r1 = await pub(bls, s);
  s.chainState.entryOf = 1n;
  s.chainState.binding = expectedBinding(bls);
  const r2 = await pub(bls, s, r1.state);
  cell(
    "revert because the action is already disclosed (same binding): confirmed",
    r2.state.registry.phase === "confirmed" && r2.state.registry.recovered,
    r2.state.registry
  );
}
{
  // A reverted tx stays parked and is re-alerted every run until acknowledged.
  const s = sinks({ mine: "revert" });
  const r1 = await pub(bls, s);
  const r2 = await pub(bls, s, r1.state);
  const r3 = await pub(bls, s, r2.state);
  const acked = { ...r3.state, registry: { ...r3.state.registry, ack: true } };
  const r4 = await pub(bls, s, acked);
  cell(
    "reverted: re-alerted on every run until acknowledged, then silent",
    r2.alerts.some(x => /unresolved/.test(x)) &&
      r3.alerts.some(x => /unresolved/.test(x)) &&
      !r4.alerts.some(x => /reverted/.test(x)) &&
      s.calls.sign === 1,
    { a2: r2.alerts, a3: r3.alerts, a4: r4.alerts }
  );
}
{
  let threw = null;
  try {
    await publishRecord(bls, sinks(), {});
  } catch (e) {
    threw = e.message;
  }
  cell(
    "publishing without a durable persist is refused",
    /needs opts\.persist/.test(threw ?? ""),
    threw
  );
  let pe = null;
  try {
    await publishRecord(
      bls,
      sinks(),
      {},
      {
        persist: async () => {
          throw new Error("disk full");
        },
      }
    );
  } catch (e) {
    pe = e;
  }
  cell(
    "a persist failure propagates as PersistError (not swallowed as a sink failure)",
    pe instanceof PersistError && /disk full/.test(pe.message),
    pe?.message
  );
  let pe2 = null;
  try {
    await publishRecord(
      bls,
      sinks(),
      {},
      {
        persist: async st => {
          if (st.registry) throw new Error("disk full at the journal");
        },
      }
    );
  } catch (e) {
    pe2 = e;
  }
  cell(
    "a persist failure at the registry journal also propagates (no broadcast without a journal)",
    pe2 instanceof PersistError,
    pe2?.message
  );
}
{
  const d = mkdtempSync(join(tmpdir(), "watcher-lock-"));
  try {
    const path = join(d, "publish.lock");
    const release = acquireLock(path);
    let second = null;
    try {
      acquireLock(path);
    } catch (e) {
      second = e.message;
    }
    cell(
      "single-instance lock: a second holder is refused",
      /another watcher holds/.test(second ?? ""),
      second
    );
    release();
    writeFileSync(path, JSON.stringify({ pid: 999999, startedAt: "long ago" }));
    const again = acquireLock(path);
    cell(
      "single-instance lock: a stale lock (dead pid) is reclaimed",
      typeof again === "function",
      null
    );
    again();
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
}
{
  const unverified = { ...bls, ruleset: { commit: null, hash: ethers.id("rs"), verified: false } };
  const a = discloseArgs(unverified, recordFile(unverified));
  cell(
    "unverified ruleset: rulesetCommit is zero, never a guessed commit",
    a.rulesetCommit === "0x" + "0".repeat(40),
    a.rulesetCommit
  );
  const q = discloseArgs({ ...bls, kind: "QUEUE", proposalId: "0" }, f1);
  cell(
    "QUEUE record maps to registry kind 2 with id 0",
    q.signed.kind === 2 && q.signed.proposalId === 0n,
    q.signed
  );
}

let failed = 0;
for (const r of results) {
  console.log(`${r.ok ? "ok  " : "FAIL"} ${r.name}${r.ok ? "" : `\n     got ${r.got}`}`);
  if (!r.ok) failed++;
}
console.log(`\n${results.length - failed}/${results.length} cells`);
process.exit(failed ? 1 : 0);
