// Shared fixtures for the W2 self-tests (check-publish, check-loop): sample records and mock sinks
// that follow the real sink contracts (lib/publish.mjs header). Test-only.
import { ethers } from "ethers";
import { cidV1Raw } from "./lib/cid.mjs";

// ---- records
export const signers = [
  ethers.getAddress("0x" + "11".repeat(20)),
  ethers.getAddress("0x" + "22".repeat(20)),
];
export const bls = {
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
export const owner = {
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

// ---- mock sinks. The mock registry follows DisclosureRegistry: one entry per (kind, key), the
// binding keccak256(abi.encode(kind, key, subjectToken)), entries visible at a block, finality.
export function sinks(opts = {}) {
  const calls = {
    telegram: 0,
    sign: 0,
    broadcast: 0,
    mirror: 0, // commit() calls
    mirrorCommits: 0, // new commits only: like the real sink, identical bytes at a path are a no-op
    uploads: {},
    texts: [],
  };
  const mirrored = new Map(); // path -> bytes (hex)
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
      calls.fetches = (calls.fetches ?? 0) + 1;
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
    known: new Set(), // tx hashes some node accepted
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
      async commit(path, bytes) {
        calls.mirror++;
        if (opts.mirrorFail) throw new Error("push rejected");
        const hex = bytes ? Buffer.from(bytes).toString("hex") : "";
        if (mirrored.has(path)) {
          if (mirrored.get(path) !== hex) throw new Error("different bytes at an existing path");
          return {
            commit: "c0ffee",
            url: `https://github.com/x/y/blob/c0ffee/${path}`,
            existing: true,
          };
        }
        mirrored.set(path, hex);
        calls.mirrorCommits++;
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
        // deterministicSign: the same args and nonce sign to the same tx (a flat estimate)
        const raw = opts.deterministicSign ? `0xraw0` : `0xraw${calls.sign}`;
        chain.signedArgs.set(raw, args);
        return {
          raw,
          hash: ethers.id(`disclose-${opts.deterministicSign ? 0 : calls.sign}`),
          nonce: o.nonce ?? chain.nonce,
        };
      },
      async broadcast(raw) {
        calls.broadcast++;
        calls.lastRaw = raw;
        const hash = ethers.id(`disclose-${raw.slice(5)}`);
        if (opts.rejectBroadcast || opts.rejectRaw?.(raw)) {
          // a node refusing every broadcast (e.g. a writer without funds): never known
          const e = new Error("insufficient funds for gas * price + value");
          e.code = "INSUFFICIENT_FUNDS";
          throw e;
        }
        chain.known.add(hash);
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
      async knows(hash) {
        return chain.known.has(hash);
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
