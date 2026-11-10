// CI self-test for W2 publication (lib/cid.mjs, lib/record-file.mjs, lib/publish.mjs) with mock
// sinks. Live provider cells (Pinata, Filebase) are separate and wait for the author's accounts.
import { ethers } from "ethers";
import { MAX_RECORD_BYTES, cidV1Raw } from "./lib/cid.mjs";
import { recordFile, mirrorPath } from "./lib/record-file.mjs";
import { publishRecord, discloseArgs } from "./lib/publish.mjs";

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
  const calls = { telegram: 0, disclose: 0, mirror: 0, uploads: {} };
  const stored = new Map();
  const mkPinner = (name, o = {}) => ({
    name,
    async upload(bytes) {
      calls.uploads[name] = (calls.uploads[name] ?? 0) + 1;
      if (o.fail) throw new Error(`${name} down`);
      const real = cidV1Raw(bytes);
      const cid = o.wrongCid ? "bafkreiwrong" : real; // reports a wrong CID, still serves the bytes
      stored.set(`${name}:${real}`, o.alterBytes ? Uint8Array.from([...bytes, 0x20]) : bytes);
      return { cid };
    },
    async fetchPublic(cid) {
      if (o.private) return null; // e.g. a Pinata upload left at the default network=private
      return stored.get(`${name}:${cid}`) ?? null;
    },
  });
  return {
    calls,
    pinners: [mkPinner("pinata", opts.pinata), mkPinner("filebase", opts.filebase)],
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
        calls.lastText = t;
      },
    },
    registry: {
      async findEntry() {
        return opts.existing ?? null;
      },
      async disclose(args) {
        calls.disclose++;
        calls.lastArgs = args;
        return { txHash: ethers.id("disclose-tx"), entryId: 1 };
      },
    },
  };
}

{
  const s = sinks();
  const r1 = await publishRecord(bls, s);
  cell(
    "happy path: both pins verified, mirror committed, published, Telegram and registry once",
    r1.state.published &&
      r1.state.pins.pinata.ok &&
      r1.state.pins.filebase.ok &&
      s.calls.telegram === 1 &&
      s.calls.disclose === 1 &&
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
    s.calls.lastText.includes(`ipfs://${f1.cid}`) && s.calls.lastText.includes("github.com"),
    s.calls.lastText
  );
  const r2 = await publishRecord(bls, s, r1.state);
  cell(
    "re-run is idempotent: no new upload, Telegram or disclose",
    s.calls.telegram === 1 &&
      s.calls.disclose === 1 &&
      s.calls.uploads.pinata === 1 &&
      s.calls.mirror === 1 &&
      r2.state.published,
    s.calls
  );
}

{
  const s = sinks({ filebase: { fail: true } });
  const r1 = await publishRecord(bls, s);
  cell(
    "one provider down: still published (one verified pin + mirror), alerted",
    r1.state.published && !r1.state.pins.filebase.ok && r1.alerts.some(x => /1\/2 pins/.test(x)),
    r1
  );
  const r2 = await publishRecord(bls, s, r1.state);
  cell(
    "…the failed pin is retried, the good one is not re-uploaded",
    s.calls.uploads.filebase === 2 && s.calls.uploads.pinata === 1 && s.calls.disclose === 1,
    s.calls.uploads
  );
  void r2;
}

{
  const s = sinks({ pinata: { wrongCid: true }, filebase: { fail: true } });
  const r = await publishRecord(bls, s);
  cell(
    "provider returning a different CID is not a pin; nothing verified -> not published, no Telegram/registry",
    !r.state.published &&
      !r.state.pins.pinata.ok &&
      s.calls.telegram === 0 &&
      s.calls.disclose === 0,
    r
  );
}
{
  const s = sinks({ pinata: { alterBytes: true }, filebase: { fail: true } });
  const r = await publishRecord(bls, s);
  cell(
    "gateway serving different bytes for the CID: not a pin",
    !r.state.published && /exact bytes/.test(r.state.pins.pinata.error),
    r.state.pins
  );
}
{
  const s = sinks({ pinata: { private: true }, filebase: { fail: true } });
  const r = await publishRecord(bls, s);
  cell(
    "uploaded but not publicly fetchable (private): not a pin",
    !r.state.published && !r.state.pins.pinata.ok,
    r.state.pins
  );
}
{
  const s = sinks({ mirrorFail: true });
  const r = await publishRecord(bls, s);
  cell(
    "mirror commit failed: not published even with both pins",
    !r.state.published &&
      r.state.pins.pinata.ok &&
      s.calls.telegram === 0 &&
      s.calls.disclose === 0,
    r
  );
}
{
  const s = sinks();
  const r = await publishRecord(owner, s);
  cell(
    "owner/guardian-route record: published to IPFS+mirror+Telegram, NO registry entry",
    r.state.published &&
      s.calls.telegram === 1 &&
      s.calls.disclose === 0 &&
      !r.state.registry &&
      !r.alerts.some(x => /registry/.test(x)),
    s.calls
  );
}
{
  const s = sinks({ existing: { entryId: 9, txHash: ethers.id("earlier") } });
  const r = await publishRecord(bls, s);
  cell(
    "an entry already in the registry (crash after broadcast) is recovered, not re-sent",
    s.calls.disclose === 0 && r.state.registry.recovered && r.state.registry.entryId === 9,
    r.state.registry
  );
}
{
  const s = sinks();
  const r = await publishRecord(bls, s, { cid: "bafkreiother" });
  cell(
    "record bytes changed after first publication: refused, alerted, nothing sent",
    s.calls.mirror === 0 && s.calls.disclose === 0 && r.alerts.some(x => /changed/.test(x)),
    r
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

let failed = 0;
for (const r of results) {
  console.log(`${r.ok ? "ok  " : "FAIL"} ${r.name}${r.ok ? "" : `\n     got ${r.got}`}`);
  if (!r.ok) failed++;
}
console.log(`\n${results.length - failed}/${results.length} cells`);
process.exit(failed ? 1 : 0);
