// CI self-test for W2 publication (lib/cid.mjs, lib/record-file.mjs, lib/publish.mjs, lib/lock.mjs)
// with mock sinks. Live provider cells (Pinata, Filebase) are separate and wait for the author's
// accounts.
import { ethers } from "ethers";
import { MAX_RECORD_BYTES, cidV1Raw } from "./lib/cid.mjs";
import { recordFile, mirrorPath } from "./lib/record-file.mjs";
import { publishRecord, discloseArgs, expectedBinding, PersistError } from "./lib/publish.mjs";
import { acquireLock } from "./lib/lock.mjs";

const results = [];
const j = v => JSON.stringify(v, (_, x) => (typeof x === "bigint" ? x.toString() : x));
const cell = (name, ok, got) => results.push({ name, ok: !!ok, got: ok ? "" : j(got) });
// Mock-sink runs that do not exercise the journal say so explicitly (the library refuses otherwise).
const pub = (rec, s, prev = {}, opts = {}) =>
  publishRecord(rec, s, prev, opts.persist ? opts : { ...opts, unsafeNoJournal: true });
/** Run publication until the registry settles (or `max` runs), as successive watcher ticks would. */
async function settle(rec, s, prev = {}, opts = {}, max = 4) {
  let r = await pub(rec, s, prev, opts);
  for (
    let i = 1;
    i < max && !["confirmed", "conflict", "reverted"].includes(r.state.registry?.phase);
    i++
  ) {
    r = await pub(rec, s, r.state, opts);
  }
  return r;
}

// ---- CID vectors, cross-checked with Kubo 0.41.0 `ipfs add --only-hash --cid-version 1 --raw-leaves`
const pattern = n => Uint8Array.from({ length: n }, (_, i) => (i * 7 + 3) % 256);
cell(
  "CID: empty file",
  cidV1Raw(new Uint8Array()) === "bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku",
  null
);
cell(
  "CID: exactly 262,144 bytes (still one raw block)",
  cidV1Raw(pattern(MAX_RECORD_BYTES)) ===
    "bafkreih4mbpgbbmrcjifkrtxbk4fbp57ajbuqqkawqwr62xjkvv3vj3yjy",
  null
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

// ---- mock sinks. The mock registry follows DisclosureRegistry: one entry per (kind, key), the
// binding keccak256(abi.encode(kind, key, subjectToken)), entries visible at a block, finality.
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
      if (o.fetchThrows) throw new Error("gateway timeout"); // transport error, not a mismatch
      if (o.private || o.gone) return null; // private upload, or unpinned later
      return stored.get(`${name}:${cid}`) ?? null;
    },
  });
  const chain = {
    nonce: 0,
    block: 1000,
    finalizedLag: 0, // finalized = block - finalizedLag
    mined: opts.mine ?? "success", // success | revert | pending
    entries: new Map(), // id -> { binding, recordURI, recordHash, amendments, block }
    byAction: new Map(), // "kind:key" -> id
    receipts: new Map(),
    signedArgs: new Map(),
    orphans: new Set(), // block hashes no longer canonical
  };
  if (opts.existing) {
    chain.entries.set(9n, { amendments: [], block: 1, ...opts.existing });
    chain.byAction.set(`${opts.existing.kind ?? 0}:${opts.existing.key ?? 7n}`, 9n);
  }
  const bindingOf = a =>
    ethers.keccak256(
      ethers.AbiCoder.defaultAbiCoder().encode(
        ["uint8", "uint256", "address"],
        [a.signed.kind, a.signed.proposalId, a.subjectToken]
      )
    );
  return {
    calls,
    pinOpts,
    chain,
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
      async finalized() {
        return chain.block - chain.finalizedLag;
      },
      async entryOf(kind, key, { blockTag } = {}) {
        const id = chain.byAction.get(`${kind}:${key}`);
        if (!id) return 0n;
        if (opts.ignoreBlockTag) return id; // an RPC that answers head state for any blockTag
        return chain.entries.get(id).block <= (blockTag ?? chain.block) ? id : 0n;
      },
      async entry(id) {
        return chain.entries.get(BigInt(id));
      },
      async sign(args, o = {}) {
        calls.sign++;
        calls.lastArgs = args;
        calls.lastSignOpts = o;
        const raw = `0xraw${calls.sign}`;
        chain.signedArgs.set(raw, args);
        return { raw, hash: ethers.id(`disclose-${calls.sign}`), nonce: o.nonce ?? chain.nonce };
      },
      async broadcast(raw) {
        calls.broadcast++;
        calls.lastRaw = raw;
        const hash = ethers.id(`disclose-${raw.slice(5)}`);
        if (chain.mined === "pending" || chain.receipts.has(hash)) return;
        const a = chain.signedArgs.get(raw);
        const act = `${a.signed.kind}:${a.signed.proposalId}`;
        chain.block++;
        if (chain.mined === "revert" || chain.byAction.has(act)) {
          chain.receipts.set(hash, {
            status: 0,
            entryId: null,
            blockNumber: chain.block,
            blockHash: ethers.id(`b${chain.block}`),
          });
        } else {
          const id = BigInt(chain.entries.size + 1);
          chain.entries.set(id, {
            binding: bindingOf(a),
            recordURI: a.recordURI,
            recordHash: a.recordHash,
            amendments: [],
            block: chain.block,
          });
          chain.byAction.set(act, id);
          chain.receipts.set(hash, {
            status: 1,
            entryId: id,
            blockNumber: chain.block,
            blockHash: ethers.id(`b${chain.block}`),
          });
        }
        chain.nonce = Math.max(chain.nonce, 1);
      },
      async receipt(hash) {
        return chain.receipts.get(hash) ?? null;
      },
      async canonical(_n, h) {
        return !chain.orphans.has(h);
      },
      async nonce() {
        return chain.nonce;
      },
    },
  };
}

{
  const s = sinks();
  const r1 = await settle(bls, s);
  cell(
    "happy path: both pins current, mirror, published, Telegram once, registry confirmed at finality",
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
    s.calls.texts[0].includes(`ipfs://${f1.cid}`) &&
      s.calls.texts[0].includes(`https://github.com/x/y/blob/c0ffee/${mirrorPath(bls, f1.cid)}`),
    s.calls.texts[0]
  );
  const r2 = await pub(bls, s, r1.state);
  cell(
    "re-run after confirmation is idempotent: no new upload, Telegram, sign or broadcast",
    s.calls.telegram === 1 &&
      s.calls.sign === 1 &&
      s.calls.uploads.pinata === 1 &&
      s.calls.mirror === 1 &&
      r2.state.registry.phase === "confirmed",
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

// ---- adoption of an existing entry: binding AND content, at the finalized block
{
  const s = sinks({
    existing: {
      binding: expectedBinding(bls),
      recordURI: `ipfs://${f1.cid}`,
      recordHash: f1.recordHash,
    },
  });
  const r = await pub(bls, s);
  cell(
    "existing entry with this binding and this content: adopted, not re-signed",
    s.calls.sign === 0 &&
      r.state.registry.phase === "confirmed" &&
      r.state.registry.entryId === "9",
    r.state.registry
  );
}
{
  const s = sinks({
    existing: {
      binding: expectedBinding(bls),
      recordURI: "ipfs://bafkreievil",
      recordHash: ethers.id("evil"),
    },
  });
  const r1 = await pub(bls, s);
  const r2 = await pub(bls, s, r1.state);
  cell(
    "existing entry with the RIGHT binding but OTHER content (e.g. compromised writer): incident, not adopted",
    r2.state.registry.phase === "conflict" &&
      /different record content/.test(r2.state.registry.conflict) &&
      s.calls.sign === 0 &&
      r2.alerts.some(x => /INCIDENT/.test(x)),
    { reg: r2.state.registry, alerts: r2.alerts }
  );
}
{
  const s = sinks({
    existing: {
      binding: expectedBinding(bls),
      recordURI: "ipfs://bafkreitypo",
      recordHash: ethers.id("typo"),
      amendments: [{ recordURI: `ipfs://${f1.cid}`, recordHash: f1.recordHash }],
    },
  });
  const r = await pub(bls, s);
  cell(
    "an amended entry is compared on its effective (amended) content: adopted",
    r.state.registry.phase === "confirmed",
    r.state.registry
  );
}
{
  const s = sinks({
    existing: {
      binding: ethers.id("another action"),
      recordURI: `ipfs://${f1.cid}`,
      recordHash: f1.recordHash,
    },
  });
  const r = await pub(bls, s);
  cell(
    "existing entry with a DIFFERENT binding: incident",
    r.state.registry.phase === "conflict" && /different binding/.test(r.state.registry.conflict),
    r.state.registry
  );
}
{
  // Entry exists but only above the finalized block: not adopted yet.
  const s = sinks({
    existing: {
      binding: expectedBinding(bls),
      recordURI: `ipfs://${f1.cid}`,
      recordHash: f1.recordHash,
      block: 5000,
    },
  });
  s.chain.finalizedLag = 10; // head 1000, finalized 990: the entry at 995 is on chain but not final
  s.chain.entries.get(9n).block = 995;
  const r = await pub(bls, s);
  cell(
    "an entry not yet finalized is not adopted (a reorg could remove it)",
    r.state.registry?.phase !== "confirmed",
    r.state.registry
  );
}

// ---- finality, revert, drop, stuck
{
  // #409 review M1: the receipt's own block must be final before it is confirmed, even when an RPC
  // already shows the entry at the finalized tag (it answers head state for any blockTag)
  const s = sinks({ ignoreBlockTag: true });
  s.chain.finalizedLag = 100;
  const r1 = await settle(bls, s, {}, {}, 3);
  cell(
    "a receipt above the finalized block stays 'landed' even if the RPC shows the entry at that tag",
    r1.state.registry.phase === "landed",
    r1.state.registry
  );
  s.chain.finalizedLag = 0;
  const r2 = await pub(bls, s, r1.state);
  cell(
    "…and settles once its block is final",
    r2.state.registry.phase === "confirmed" && s.calls.sign === 1,
    { reg: r2.state.registry, calls: s.calls }
  );
}
{
  const s = sinks();
  s.chain.finalizedLag = 100; // receipts land above the finalized block
  const r1 = await settle(bls, s, {}, {}, 3);
  cell(
    "receipt above the finalized block: 'landed', not confirmed",
    r1.state.registry.phase === "landed",
    r1.state.registry
  );
  s.chain.finalizedLag = 0;
  const r2 = await pub(bls, s, r1.state);
  cell(
    "…confirmed once final, without re-signing",
    r2.state.registry.phase === "confirmed" && s.calls.sign === 1,
    { reg: r2.state.registry, calls: s.calls }
  );
}
{
  // Crash right after broadcast: on restart the SAME raw tx is rebroadcast; no second signature.
  const s = sinks({ mine: "pending" });
  let snapshot = null;
  let crash = true;
  const persist = async st => {
    if (crash && st.registry?.phase === "sent") throw new Error("power cut");
    snapshot = JSON.parse(j(st));
  };
  try {
    await publishRecord(bls, s, {}, { persist });
  } catch {
    /* crashed */
  }
  cell(
    "crash after broadcast: the journal holds the signed raw tx",
    snapshot?.registry?.phase === "signed" && snapshot.registry.raw === "0xraw1",
    snapshot?.registry
  );
  crash = false;
  s.chain.mined = "success";
  const r = await settle(bls, s, snapshot, { persist });
  cell(
    "…restart rebroadcasts the same raw tx, never signs again, and confirms at finality",
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
  s.chain.nonce = 5; // our nonce consumed at the finalized block, no receipt: dropped/replaced
  const r3 = await pub(bls, s, r2.state);
  cell(
    "a dropped tx is detected and re-signed once (on-chain uniqueness makes this safe)",
    s.calls.sign === 2 && r3.alerts.some(x => /dropped or replaced/.test(x)),
    { calls: s.calls, alerts: r3.alerts }
  );
}
{
  // Stuck: no receipt, nonce never consumed. After maxPendingMs it is replaced at the same nonce.
  const s = sinks({ mine: "pending" });
  const r1 = await pub(bls, s, {}, { maxPendingMs: 0 });
  const r2 = await pub(bls, s, r1.state, { maxPendingMs: 0 });
  cell(
    "a stuck tx (nonce unused) is replaced at the SAME nonce, alerted, with both hashes journalled",
    s.calls.sign === 2 &&
      s.calls.lastSignOpts.replace === true &&
      s.calls.lastSignOpts.prevRaw === "0xraw1" &&
      s.calls.lastSignOpts.nonce === r1.state.registry.nonce &&
      r2.state.registry.hashes.length === 2 &&
      r2.alerts.some(x => /replacing at nonce/.test(x)),
    { calls: s.calls, reg: r2.state.registry, alerts: r2.alerts }
  );
  s.chain.mined = "success";
  const r3 = await settle(bls, s, r2.state, { maxPendingMs: 1e9 });
  cell(
    "…and whichever journalled hash lands is confirmed",
    r3.state.registry.phase === "confirmed",
    r3.state.registry
  );
}
{
  const s = sinks({ mine: "revert" });
  const r1 = await settle(bls, s);
  const r2 = await pub(bls, s, r1.state);
  const r3 = await pub(bls, s, r2.state);
  const acked = { ...r3.state, registry: { ...r3.state.registry, ack: true } };
  const r4 = await pub(bls, s, acked);
  cell(
    "reverted: parked, re-alerted on every run until acknowledged, then silent; never re-signed",
    r1.state.registry.phase === "reverted" &&
      r2.alerts.some(x => /unresolved/.test(x)) &&
      r3.alerts.some(x => /unresolved/.test(x)) &&
      !r4.alerts.some(x => /reverted/.test(x)) &&
      s.calls.sign === 1,
    { a2: r2.alerts, a3: r3.alerts, a4: r4.alerts, calls: s.calls }
  );
}
{
  // An unresolved incident is re-alerted even when publication returns early (no current pin).
  const s = sinks({ pinata: { fail: true }, filebase: { fail: true } });
  const prev = { registry: { phase: "conflict", entryId: "9", conflict: "a different binding" } };
  const r = await pub(bls, s, prev);
  cell(
    "an unresolved incident is re-alerted even when nothing can be published this run",
    !r.state.published && r.alerts.some(x => /INCIDENT/.test(x)),
    r.alerts
  );
}
{
  // A revert because the action is already disclosed by another of our txs: adopted, not parked.
  const s = sinks();
  const args = discloseArgs(bls, f1);
  s.chain.entries.set(1n, {
    binding: expectedBinding(bls),
    recordURI: args.recordURI,
    recordHash: args.recordHash,
    amendments: [],
    block: 900,
  });
  s.chain.byAction.set("0:7", 1n);
  // the journal says one of our txs was sent; the chain shows it reverted (AlreadyDisclosed)
  s.chain.receipts.set(ethers.id("disclose-x"), {
    status: 0,
    entryId: null,
    blockNumber: 999,
    blockHash: ethers.id("b999"),
  });
  const r = await pub(bls, s, {
    registry: {
      phase: "sent",
      raw: "0xrawx",
      hash: ethers.id("disclose-x"),
      hashes: [ethers.id("disclose-x")],
      nonce: 0,
      sentAt: new Date().toISOString(),
    },
  });
  cell(
    "revert because the action is already disclosed with our content: confirmed",
    r.state.registry.phase === "confirmed",
    r.state.registry
  );
}

// ---- Codex W2a R4: provisional failures, orphaned receipts, legacy journals
{
  // A failed receipt above the finalized block is not final: not parked. Once final, the
  // competing entry (AlreadyDisclosed) is adopted.
  const s = sinks();
  const args = discloseArgs(bls, f1);
  s.chain.entries.set(1n, {
    binding: expectedBinding(bls),
    recordURI: args.recordURI,
    recordHash: args.recordHash,
    amendments: [],
    block: 1001,
  });
  s.chain.byAction.set("0:7", 1n);
  s.chain.block = 1002;
  s.chain.finalizedLag = 5; // finalized 997: neither the revert nor the entry is final
  s.chain.receipts.set(ethers.id("disclose-y"), {
    status: 0,
    entryId: null,
    blockNumber: 1002,
    blockHash: ethers.id("b1002"),
  });
  const prev = {
    registry: {
      phase: "sent",
      raw: "0xrawy",
      hash: ethers.id("disclose-y"),
      hashes: [ethers.id("disclose-y")],
      nonce: 0,
      sentAt: new Date().toISOString(),
    },
  };
  const r1 = await pub(bls, s, prev);
  cell(
    "a failed receipt above the finalized block is not parked as reverted",
    r1.state.registry.phase === "sent",
    r1.state.registry
  );
  s.chain.finalizedLag = 0;
  const r2 = await pub(bls, s, r1.state);
  cell(
    "…once final, the competing entry with our content is adopted",
    r2.state.registry.phase === "confirmed",
    r2.state.registry
  );
}
{
  // An orphaned receipt is ignored: the replacement hash is checked, pending recovery resumes.
  const s = sinks();
  const args = discloseArgs(bls, f1);
  s.chain.signedArgs.set("0xraw77", args);
  s.chain.receipts.set(ethers.id("disclose-old"), {
    status: 1,
    entryId: 5n,
    blockNumber: 990,
    blockHash: ethers.id("orphan"),
  });
  s.chain.orphans.add(ethers.id("orphan"));
  const prev = {
    registry: {
      phase: "landed",
      raw: "0xraw77",
      hash: ethers.id("disclose-77"),
      hashes: [ethers.id("disclose-old"), ethers.id("disclose-77")],
      nonce: 0,
      sentAt: new Date().toISOString(),
    },
  };
  const r0 = await pub(bls, s, prev);
  cell(
    "an orphaned receipt is ignored and alerted",
    r0.alerts.some(x => /orphaned block/.test(x)),
    { a: r0.alerts, reg: r0.state.registry }
  );
  const r = await settle(bls, s, r0.state);
  cell(
    "…the other journalled hash lands and is confirmed",
    r.state.registry.phase === "confirmed",
    r.state.registry
  );
}
{
  // A legacy 'sent' journal without sentAt still reaches the stuck-tx timeout.
  const s = sinks({ mine: "pending" });
  s.chain.signedArgs.set("0xraw1", discloseArgs(bls, f1));
  const legacy = {
    registry: { phase: "sent", raw: "0xraw1", hash: ethers.id("disclose-1"), nonce: 0 },
  };
  const r1 = await pub(bls, s, legacy, { maxPendingMs: 60_000 });
  cell(
    "a legacy sent journal gets its sentAt once",
    typeof r1.state.registry.sentAt === "string",
    r1.state.registry
  );
  const old = {
    ...r1.state,
    registry: { ...r1.state.registry, sentAt: new Date(Date.now() - 120_000).toISOString() },
  };
  const r2 = await pub(bls, s, old, { maxPendingMs: 60_000 });
  cell(
    "…and is replaced once it has been pending past the timeout",
    s.calls.lastSignOpts?.replace === true && r2.state.registry.replacements === 1,
    r2.state.registry
  );
}

{
  // Codex W2a R5: a failed receipt passes canonical() while unfinalized, its branch is then reorged
  // out and the other branch finalizes. It must not be parked as reverted.
  const s = sinks();
  s.chain.receipts.set(ethers.id("disclose-z"), {
    status: 0,
    entryId: null,
    blockNumber: 995,
    blockHash: ethers.id("bz"),
  });
  let calls = 0;
  s.registry.canonical = async (_n, h) => {
    if (h !== ethers.id("bz")) return true;
    calls++;
    return calls === 1; // canonical on the first look, orphaned on the second
  };
  const prev = {
    registry: {
      phase: "sent",
      raw: "0xrawz",
      hash: ethers.id("disclose-z"),
      hashes: [ethers.id("disclose-z")],
      nonce: 0,
      sentAt: new Date().toISOString(),
    },
  };
  s.chain.signedArgs.set("0xrawz", discloseArgs(bls, f1));
  s.chain.mined = "pending";
  const r = await pub(bls, s, prev);
  cell(
    "a failed receipt reorged out between the canonical and finality reads is not parked",
    r.state.registry.phase !== "reverted" &&
      r.alerts.some(x => /reorged out before finality/.test(x)),
    { reg: r.state.registry, alerts: r.alerts }
  );
}

{
  // #409 review N2: the owner-route mirror path only from a well-formed txHash and logIndex
  const ok = { route: "owner", txHash: "0x" + "ab".repeat(32), logIndex: 3 };
  const bad = [
    { ...ok, txHash: "../../etc" },
    { ...ok, txHash: "0x" + "ab".repeat(31) },
    { ...ok, logIndex: "3/../x" },
    { ...ok, logIndex: -1 },
  ];
  let threw = 0;
  for (const r of bad) {
    try {
      mirrorPath(r, f1.cid);
    } catch {
      threw++;
    }
  }
  cell(
    "mirror path: a malformed owner-route txHash or logIndex is refused; a good one is accepted",
    threw === bad.length && mirrorPath(ok, f1.cid).startsWith("records/owner/owner-0x"),
    { threw }
  );
}

// ---- other stages
{
  // #409 review N1: a transport error while re-verifying is no evidence: the pin stays current
  const s = sinks();
  const r1 = await pub(bls, s);
  const uploads = { ...s.calls.uploads };
  s.pinOpts.pinata.fetchThrows = true;
  const r2 = await pub(bls, s, r1.state, { reverify: true });
  cell(
    "reverify: a gateway transport error keeps the pin current and the record published, alerted, no re-upload",
    r2.state.pins.pinata.current &&
      r2.state.published &&
      s.calls.uploads.pinata === uploads.pinata &&
      r2.alerts.some(x => /could not reach the gateway/.test(x)),
    {
      pins: r2.state.pins,
      published: r2.state.published,
      alerts: r2.alerts,
      uploads: s.calls.uploads,
    }
  );
}
{
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
  const s = sinks({ filebase: { fail: true } });
  s.pinners = [s.pinners[1]];
  const r = await pub(bls, s, { pins: { pinata: { current: true } }, cid: f1.cid });
  cell("a pin at a provider no longer configured is not counted", !r.state.published, r.state);
}
{
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
  const s = sinks();
  const r = await pub(bls, s, { cid: "bafkreiother" });
  cell(
    "record bytes changed after first publication: refused, alerted, nothing sent",
    s.calls.mirror === 0 && s.calls.sign === 0 && r.alerts.some(x => /changed/.test(x)),
    r
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
          throw Object.assign(new Error("disk full at /secret/path"), { code: "ENOSPC" });
        },
      }
    );
  } catch (e) {
    pe = e;
  }
  cell(
    "a persist failure propagates as PersistError (not swallowed as a sink failure)",
    pe instanceof PersistError && pe.message === "persist failed: ENOSPC",
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
{
  // Single-instance lock: an OS-held socket; a second holder is refused, release frees it.
  const port = 40000 + Math.floor(Math.random() * 5000); // never the production port 47331
  const release = await acquireLock(port);
  let second = null;
  try {
    await acquireLock(port);
  } catch (e) {
    second = e.message;
  }
  cell(
    "single-instance lock: a second holder is refused",
    /is occupied/.test(second ?? ""),
    second
  );
  await release();
  const again = await acquireLock(port);
  cell(
    "single-instance lock: free again after release (and on exit, by the kernel)",
    typeof again === "function",
    null
  );
  await again();
}

let failed = 0;
for (const r of results) {
  console.log(`${r.ok ? "ok  " : "FAIL"} ${r.name}${r.ok ? "" : `\n     got ${r.got}`}`);
  if (!r.ok) failed++;
}
console.log(`\n${results.length - failed}/${results.length} cells`);
process.exit(failed ? 1 : 0);
