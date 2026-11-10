// CI self-test for scripts/disclosure/recheck-lib.mjs against a stub chain (no RPC, no anvil).
//
// The stub aggregator derives its commitment the way SP's BLSAggregator does (mask bit i -> slot
// i+1 -> validatorAtSlot, insertion sort ascending), written out here with explicit abi types and NOT
// through recheck-lib's expectedCommitment, so a recheck that merely agrees with itself cannot pass.
//
// Each case is a control cell: correct entries must PASS and every forged entry must FAIL, and each
// failing case asserts WHICH check fired, so a recheck that fails for the wrong reason is caught too.
import { ethers } from "ethers";
import { Kind, aggIface, regIface, recheckEntry } from "./recheck-lib.mjs";

const ABI = ethers.AbiCoder.defaultAbiCoder();
const AGG = ethers.getAddress("0x00000000000000000000000000000000000a6600");
const REG = ethers.getAddress("0x00000000000000000000000000000000000d1500");
const WRAPPER = ethers.getAddress("0x00000000000000000000000000000000000bad00");
const WATCHER = ethers.getAddress("0x0000000000000000000000000000000000000777");
const SAFE = ethers.getAddress("0x0000000000000000000000000000000000005afe");
const DS = ethers.id("stub-domain-separator");

const addr = s => ethers.getAddress(ethers.dataSlice(ethers.id(s), 12));
const G = [addr("g1"), addr("g2"), addr("g3")]; // unsorted by construction of keccak
const G_NEW = addr("g2-replacement");

// ------------------------------------------------------------------ independent SP-side derivation
function spMessageHash(kind, id, f) {
  if (kind === Kind.SLASH)
    return ethers.keccak256(
      ABI.encode(
        ["bytes32", "bytes32", "uint256", "address", "uint8", "uint256", "bytes32"],
        [
          DS,
          ethers.id("SuperPaymaster.BLS.ExecuteSlash.v1"),
          id,
          f.operator,
          f.slashLevel,
          f.epoch,
          f.evidenceHash,
        ]
      )
    );
  if (kind === Kind.GENERIC)
    return ethers.keccak256(
      ABI.encode(
        ["bytes32", "bytes32", "uint256", "address", "bytes32", "uint256"],
        [
          DS,
          ethers.id("SuperPaymaster.BLS.Proposal.v1"),
          id,
          f.target,
          ethers.keccak256(f.callData),
          f.requiredThreshold,
        ]
      )
    );
  if (kind === Kind.QUEUE)
    return ethers.keccak256(
      ABI.encode(
        ["bytes32", "bytes32", "address", "uint8", "uint256"],
        [DS, ethers.id("SuperPaymaster.BLS.QueueSlash.v1"), f.operator, f.slashLevel, f.epoch]
      )
    );
  return ethers.keccak256(
    ABI.encode(
      ["bytes32", "bytes32", "uint256", "address[]", "uint256[]", "uint256"],
      [DS, ethers.id("SuperPaymaster.BLS.Reputation.v1"), id, f.users, f.newScores, f.epoch]
    )
  );
}
function spKey(kind, id, mh) {
  if (kind === Kind.GENERIC)
    return BigInt(
      ethers.keccak256(
        ABI.encode(["bytes32", "uint256"], [ethers.id("SuperPaymaster.BLS.Proposal.v1"), id])
      )
    );
  if (kind === Kind.QUEUE) return BigInt(mh);
  return BigInt(id);
}
function spSigners(slots, mask) {
  const s = [];
  for (let slot = 1; slot <= 255; slot++) if ((mask >> BigInt(slot - 1)) & 1n) s.push(slots[slot]);
  for (let i = 1; i < s.length; i++) {
    const k = s[i];
    let j = i;
    while (j > 0 && BigInt(s[j - 1]) > BigInt(k)) {
      s[j] = s[j - 1];
      j--;
    }
    s[j] = k;
  }
  return s;
}

// ------------------------------------------------------------------ stub chain
function makeChain() {
  const blocks = new Map(); // number -> { hash, slots }
  const txs = new Map(); // hash -> { tx, receipt }
  const commitments = new Map(); // key -> [{ block, value }] (historical, like real state)
  const commitAt = (key, tag) => {
    const at = tag === "latest" ? head : Number(tag);
    const hist = (commitments.get(key) ?? []).filter(h => h.block <= at);
    return hist.length ? hist[hist.length - 1].value : ethers.ZeroHash;
  };
  const setCommit = (key, block, value) =>
    commitments.set(key, [...(commitments.get(key) ?? []), { block, value }]);
  let onCommitRead = null; // one-shot hook: runs while a check is in flight
  const logs = [];
  let head = 100;
  let slots = { 1: G[0], 2: G[1], 3: G[2] };
  const snapshot = () => ({ ...slots });
  for (let n = 0; n <= head; n++)
    blocks.set(n, {
      hash: ethers.id(`block-${n}`),
      parentHash: n ? ethers.id(`block-${n - 1}`) : ethers.ZeroHash,
      slots: snapshot(),
    });

  const mine = () => {
    head++;
    blocks.set(head, {
      hash: ethers.id(`block-${head}`),
      parentHash: blocks.get(head - 1).hash,
      slots: snapshot(),
    });
    return head;
  };
  const slotsAt = tag => blocks.get(tag === "latest" ? head : Number(tag)).slots;
  let maxRange = Infinity; // emulate a range-capped RPC
  let getLogsCalls = 0;
  let onReceipt = null; // one-shot hook around the next receipt fetch
  let onEntryCountRead = null; // one-shot hook right after a by-hash eth_call returns
  let afterSends = null; // { left, fn }: run fn once `left` more raw sends have returned

  const chain = {
    async getTransaction(h) {
      return txs.get(h)?.tx ?? null;
    },
    async getTransactionReceipt(h) {
      if (onReceipt) {
        const f = onReceipt;
        onReceipt = null;
        return f(h);
      }
      return txs.get(h)?.receipt ?? null;
    },
    async getBlock(n) {
      const b = blocks.get(Number(n));
      return b ? { ...b } : null; // a copy, as a real provider returns: reorgs replace, never mutate
    },
    async getBlockNumber() {
      return head;
    },
    /** Raw JSON-RPC, never cached (what an ethers provider's `send` is). */
    async send(method, params) {
      if (method === "eth_call") {
        // EIP-1898: state at the block with this hash; unknown (orphaned) hash => error, as a node does.
        const [{ to, data }, { blockHash }] = params;
        const n = [...blocks.entries()].find(([, b]) => b.hash === blockHash)?.[0];
        if (n === undefined) throw new Error("header not found");
        const out = await chain.call({ to, data, blockTag: n });
        if (onEntryCountRead) {
          const f = onEntryCountRead;
          onEntryCountRead = null;
          f();
        }
        return out;
      }
      if (method !== "eth_getBlockByNumber") throw new Error(`stub send: ${method}`);
      const b = blocks.get(Number(params[0]));
      const out = b ? { hash: b.hash, parentHash: b.parentHash } : null;
      if (afterSends && --afterSends.left === 0) {
        const f = afterSends.fn;
        afterSends = null;
        f();
      }
      return out;
    },
    async getLogs({ address, topics, fromBlock, toBlock }) {
      getLogsCalls++;
      if (toBlock - fromBlock + 1 > maxRange) throw new Error("block range too large");
      return logs.filter(
        l =>
          l.address === address &&
          l.blockNumber >= fromBlock &&
          l.blockNumber <= toBlock &&
          topics.every((t, i) => t == null || l.topics[i] === t)
      );
    },
    async call({ to, data, blockTag }) {
      if (to === REG) {
        const q = regIface.parseTransaction({ data });
        if (q.name === "entryCount")
          return regIface.encodeFunctionResult(q.name, [BigInt(entryCount)]);
        throw new Error(`stub registry: ${q.name}`);
      }
      if (to !== AGG) throw new Error("call to unknown contract");
      const p = aggIface.parseTransaction({ data });
      if (p.name === "domainSeparator") return aggIface.encodeFunctionResult(p.name, [DS]);
      if (p.name === "validatorAtSlot")
        return aggIface.encodeFunctionResult(p.name, [
          slotsAt(blockTag)[Number(p.args[0])] ?? ethers.ZeroAddress,
        ]);
      if (p.name === "proposalSignersCommitment") {
        const v = commitAt(BigInt(p.args[0]), blockTag);
        if (onCommitRead) {
          const f = onCommitRead;
          onCommitRead = null;
          f();
        }
        return aggIface.encodeFunctionResult(p.name, [v]);
      }
      throw new Error(`stub: ${p.name}`);
    },
  };

  /** Execute one action as SP would: commitment over pre-block slots, SignersCommitted log. */
  function execute(kind, id, f, mask, { to = AGG, from = SAFE, midSlots, status = 1 } = {}) {
    const n = mine();
    // midSlots: the slot table as an earlier tx in this block left it and a later one undid it.
    const pre = midSlots ?? blocks.get(n - 1).slots;
    const mh = spMessageHash(kind, id, f);
    const key = spKey(kind, id, mh);
    const signers = spSigners(pre, mask);
    const anchor = blocks.get(n - 1).hash;
    setCommit(
      key,
      n,
      ethers.keccak256(
        ABI.encode(
          ["bytes32", "bytes32", "uint256", "bytes32", "uint256", "address[]", "bytes32"],
          [DS, ethers.id("SuperPaymaster.BLS.SignersCommitment.v1"), key, mh, mask, signers, anchor]
        )
      )
    );
    let data;
    if (kind === Kind.SLASH)
      data = aggIface.encodeFunctionData("verifyAndExecute", [
        id,
        f.operator,
        f.slashLevel,
        [],
        [],
        f.epoch,
        f.evidenceHash,
        "0x",
      ]);
    if (kind === Kind.REPUTATION)
      data = aggIface.encodeFunctionData("verifyAndExecute", [
        id,
        ethers.ZeroAddress,
        0,
        f.users,
        f.newScores,
        f.epoch,
        ethers.ZeroHash,
        "0x",
      ]);
    if (kind === Kind.GENERIC)
      data = aggIface.encodeFunctionData("executeProposal", [
        id,
        f.target,
        f.callData,
        f.requiredThreshold,
        "0x",
      ]);
    if (kind === Kind.QUEUE)
      data = aggIface.encodeFunctionData("queueSlashWithConsensus", [
        f.operator,
        f.slashLevel,
        f.epoch,
        "0x",
      ]);
    if (to !== AGG) data = ethers.concat(["0xdeadbeef", data]); // a wrapper contract's own calldata
    const hash = ethers.id(`action-${n}-${kind}-${id}`);
    const ev = aggIface.encodeEventLog("SignersCommitted", [key, mask]);
    txs.set(hash, {
      tx: { hash, to, from, data },
      receipt: {
        status,
        blockNumber: n,
        blockHash: blocks.get(n).hash,
        logs: [{ address: AGG, topics: ev.topics, data: ev.data }],
      },
    });
    return { hash, key, mh, signers, anchor, block: n, mask };
  }

  /** Write an entry as the watcher would (honest unless `forge` overrides fields). */
  let entryCount = 0;
  function disclose(kind, id, inputs, act, forge = {}) {
    const n = mine();
    const entryId = BigInt(++entryCount);
    const e = {
      kind,
      key: act.key,
      proposalId: kind === Kind.QUEUE ? 0n : id,
      messageHash: act.mh,
      signers: act.signers,
      subjectToken: ethers.ZeroAddress,
      txHash: act.hash,
      blockNumber: act.block,
      blockVerified: true,
      rulesetCommit: "0x" + "ab".repeat(20),
      recordURI: "ipfs://record",
      recordHash: ethers.id("record"),
      ...forge,
    };
    const s = {
      kind,
      proposalId: e.proposalId,
      messageInputs: inputs,
      signerMask: forge.signerMask ?? act.mask,
      signers: e.signers,
      anchor: forge.anchor ?? act.anchor,
    };
    const ev = regIface.encodeEventLog("Disclosed", [
      entryId,
      e.kind,
      e.key,
      e.proposalId,
      e.messageHash,
      e.signers,
      e.subjectToken,
      e.txHash,
      e.blockNumber,
      e.blockVerified,
      e.rulesetCommit,
      e.recordURI,
      e.recordHash,
    ]);
    const hash = ethers.id(`disclose-${entryId}`);
    const data = regIface.encodeFunctionData("disclose", [
      s,
      e.subjectToken,
      e.txHash,
      e.blockNumber,
      e.rulesetCommit,
      e.recordURI,
      e.recordHash,
    ]);
    txs.set(hash, {
      tx: { hash, to: REG, from: WATCHER, data },
      receipt: { status: 1, blockNumber: n, blockHash: blocks.get(n).hash, logs: [] },
    });
    logs.push({
      address: REG,
      topics: ev.topics,
      data: ev.data,
      transactionHash: hash,
      blockNumber: n,
      blockHash: blocks.get(n).hash,
    });
    return entryId;
  }

  return {
    chain,
    execute,
    disclose,
    setSlot: (s, v) => (slots[s] = v),
    /** Replace block `n` with a sibling: same number, new hash (receipts fetched before keep the old one). */
    /** Drop the parentHash from block n's header (an RPC that omits it). */
    dropParentHash: n => blocks.set(n, { ...blocks.get(n), parentHash: undefined }),
    /** During the next receipt fetch: replace the listed blocks (a reorg) and answer null. */
    reorgDuringReceipt: ns =>
      (onReceipt = () => {
        for (const n of ns) blocks.set(n, { ...blocks.get(n), hash: ethers.id(`rcpt-reorg-${n}`) });
        return null;
      }),
    /** Replace block n and return a reverted receipt from the orphaned branch. */
    revertedOnOrphan: (hash, n) =>
      (onReceipt = () => {
        blocks.set(n, { ...blocks.get(n), hash: ethers.id(`orphan-${n}`) });
        return { ...txs.get(hash).receipt, status: 0 };
      }),
    /** After `k` more raw block reads, replace block n (a reorg at an exact point in the check). */
    reorgAfterSends: (k, n) =>
      (afterSends = {
        left: k,
        fn: () => blocks.set(n, { ...blocks.get(n), hash: ethers.id(`late-reorg-${n}`) }),
      }),
    /** Replace the head block right after the next by-hash counter read. */
    reorgHeadAfterCountRead: () =>
      (onEntryCountRead = () =>
        blocks.set(head, { ...blocks.get(head), hash: ethers.id(`head-reorg-${head}`) })),
    /** Make the next receipt fetch answer without a status field. */
    receiptWithoutStatus: () =>
      (onReceipt = h => {
        const r = { ...txs.get(h).receipt };
        r.status = null;
        return r;
      }),
    reorg: n => blocks.set(n, { ...blocks.get(n), hash: ethers.id(`reorged-${n}`) }),
    disclosureBlock: entryId => logs.find(l => BigInt(l.topics[1]) === BigInt(entryId)).blockNumber,
    capRange: r => (maxRange = r),
    /** Overwrite the commitment at `key` in a new block (what a key collision would do). */
    overwrite: key => setCommit(key, mine(), ethers.id(`overwrite-${key}`)),
    mineEmpty: () => mine(),
    reorgDuringNextCheck: n =>
      (onCommitRead = () => blocks.set(n, { ...blocks.get(n), hash: ethers.id(`mid-reorg-${n}`) })),
    logCalls: () => getLogsCalls,
    head: () => head,
  };
}

// ------------------------------------------------------------------ fixtures
const slashF = {
  operator: addr("op"),
  slashLevel: 1,
  epoch: 42n,
  evidenceHash: ethers.id("evidence"),
};
const slashIn = ABI.encode(
  ["address", "uint8", "uint256", "bytes32"],
  [slashF.operator, slashF.slashLevel, slashF.epoch, slashF.evidenceHash]
);
const genF = { target: addr("registry"), callData: "0x12345678", requiredThreshold: 3n };
const genIn = ABI.encode(
  ["address", "bytes32", "uint256"],
  [genF.target, ethers.keccak256(genF.callData), genF.requiredThreshold]
);
const qF = { operator: addr("op"), slashLevel: 2, epoch: 43n };
const qIn = ABI.encode(["address", "uint8", "uint256"], [qF.operator, qF.slashLevel, qF.epoch]);
const repF = { users: [addr("u1"), addr("u2")], newScores: [10n, 20n], epoch: 44n };
const repIn = ABI.encode(
  ["address[]", "uint256[]", "uint256"],
  [repF.users, repF.newScores, repF.epoch]
);

/**
 * What an ethers v6 provider does by default: identical requests within the cache window return the
 * first answer. Wraps every typed read; `send` stays raw, as in ethers.
 */
function withRequestCache(chain) {
  const cache = new Map();
  const cached =
    name =>
    async (...args) => {
      const k = `${name}:${JSON.stringify(args, (_, v) => (typeof v === "bigint" ? v.toString() : v))}`;
      if (!cache.has(k)) cache.set(k, await chain[name](...args));
      return cache.get(k);
    };
  return {
    getBlock: cached("getBlock"),
    getTransaction: cached("getTransaction"),
    getTransactionReceipt: cached("getTransactionReceipt"),
    getLogs: cached("getLogs"),
    call: cached("call"),
    getBlockNumber: () => chain.getBlockNumber(),
    send: (...a) => chain.send(...a),
  };
}

// ------------------------------------------------------------------ cases
const {
  chain,
  execute,
  disclose,
  setSlot,
  reorg,
  disclosureBlock,
  capRange,
  logCalls,
  overwrite,
  mineEmpty,
  reorgDuringNextCheck,
  head: headNow,
  dropParentHash,
  reorgDuringReceipt,
  revertedOnOrphan,
  reorgAfterSends,
  reorgHeadAfterCountRead,
  receiptWithoutStatus,
} = makeChain();
const results = [];
// want: "PASS" | { diff } (MISMATCH on that field) | { status, reason } | { unverified: {...} } (MATCH,
// with those claims reported back verbatim as unverified).
async function expectCase(name, entryId, want, opts = {}) {
  let r;
  try {
    r = await recheckEntry(opts.chain ?? chain, {
      registry: REG,
      aggregator: AGG,
      entryId,
      page: opts.page,
      fromBlock: opts.fromBlock ?? 0,
      confirmations: opts.confirmations ?? 0,
    });
  } catch (e) {
    r = { status: "THREW", ok: false, reasons: [`${e.name}: ${e.message}`], diffs: [] };
  }
  let ok;
  if (want === "PASS") ok = r.status === "MATCH" && r.ok;
  else if (want.unverified)
    ok =
      r.status === "MATCH" &&
      Object.entries(want.unverified).every(
        ([k, v]) => r.unverified?.[k]?.toLowerCase() === v.toLowerCase()
      );
  else if (want.diff)
    ok = r.status === "MISMATCH" && !r.ok && r.diffs.some(d => d.field === want.diff);
  else ok = r.status === want.status && !r.ok && r.reasons.some(x => x.includes(want.reason));
  results.push({
    name,
    ok,
    want: JSON.stringify(want),
    got: JSON.stringify({ status: r.status, reasons: r.reasons, diffs: r.diffs.map(d => d.field) }),
  });
}

const aS = execute(Kind.SLASH, 7n, slashF, 0b011n);
const aG = execute(Kind.GENERIC, 5n, genF, 0b111n);
const aQ = execute(Kind.QUEUE, 0n, qF, 0b110n);
const aR = execute(Kind.REPUTATION, 9n, repF, 0b111n);
await expectCase("honest SLASH entry", disclose(Kind.SLASH, 7n, slashIn, aS), "PASS");
await expectCase("honest GENERIC entry", disclose(Kind.GENERIC, 5n, genIn, aG), "PASS");
await expectCase("honest QUEUE entry", disclose(Kind.QUEUE, 0n, qIn, aQ), "PASS");
await expectCase("honest REPUTATION entry", disclose(Kind.REPUTATION, 9n, repIn, aR), "PASS");

// Slots change after execution: the recheck must use historical slot state, not latest.
setSlot(2, G_NEW);
const aS2 = execute(Kind.SLASH, 8n, slashF, 0b011n); // mined after the change; G_NEW signs this one
await expectCase(
  "slot re-registered after execution (historical state used)",
  disclose(Kind.SLASH, 7n, slashIn, aS),
  "PASS"
);
await expectCase(
  "honest entry after the slot change",
  disclose(Kind.SLASH, 8n, slashIn, aS2),
  "PASS"
);

// Forged entries: each must be caught, by the check named.
await expectCase(
  "forged txHash (points at another action)",
  disclose(Kind.SLASH, 7n, slashIn, aS, { txHash: aG.hash }),
  { status: "MISMATCH", reason: "no SignersCommitted for key" }
);
await expectCase(
  "forged blockNumber",
  disclose(Kind.SLASH, 7n, slashIn, aS, { blockNumber: aS.block + 1 }),
  { diff: "blockNumber" }
);
await expectCase(
  "forged signer list",
  disclose(Kind.SLASH, 7n, slashIn, aS, { signers: [G[2], G[0]].sort() }),
  { diff: "signers" }
);
await expectCase(
  "forged messageHash",
  disclose(Kind.SLASH, 7n, slashIn, aS, { messageHash: ethers.id("x") }),
  { diff: "messageHash" }
);
await expectCase("forged proposalId", disclose(Kind.SLASH, 7n, slashIn, aS, { proposalId: 70n }), {
  diff: "proposalId",
});
await expectCase("forged kind", disclose(Kind.SLASH, 7n, slashIn, aS, { kind: Kind.REPUTATION }), {
  diff: "kind",
});
await expectCase("forged messageInputs in disclose calldata", disclose(Kind.SLASH, 7n, qIn, aS), {
  diff: "signed.messageInputs",
});
await expectCase(
  "forged anchor in disclose calldata",
  disclose(Kind.SLASH, 7n, slashIn, aS, { anchor: ethers.id("y") }),
  { diff: "signed.anchor" }
);
await expectCase("never-issued entry id is MISMATCH", 999n, {
  status: "MISMATCH",
  reason: "not issued as of block",
});

const aW = execute(Kind.SLASH, 11n, slashF, 0b011n, { to: WRAPPER });
await expectCase("wrapped action call is INCONCLUSIVE", disclose(Kind.SLASH, 11n, slashIn, aW), {
  status: "INCONCLUSIVE",
  reason: "wrapped",
});

// Codex M1: subjectToken is a claim. A MATCH must hand it back as unverified, never as verified.
const OTHER_TOKEN = addr("unrelated-community-token");
await expectCase(
  "unrelated subjectToken is reported unverified, not verified",
  disclose(Kind.SLASH, 7n, slashIn, aS, { subjectToken: OTHER_TOKEN }),
  { unverified: { subjectToken: OTHER_TOKEN } }
);

// Codex M3: a slot assignment that existed only inside the block (set by an earlier tx, undone by a
// later one) is in neither snapshot. Undecidable from snapshots: INCONCLUSIVE, not MISMATCH.
const aMid = execute(Kind.SLASH, 12n, slashF, 0b011n, {
  midSlots: { 1: G[0], 2: addr("transient") },
});
await expectCase(
  "intra-block slot change is INCONCLUSIVE",
  disclose(Kind.SLASH, 12n, slashIn, aMid),
  {
    status: "INCONCLUSIVE",
    reason: "inside the block",
  }
);

// Codex M2: reorgs. The action's block replaced by a sibling, and the disclosure's block replaced.
const aRe = execute(Kind.SLASH, 13n, slashF, 0b011n);
const eRe = disclose(Kind.SLASH, 13n, slashIn, aRe);
reorg(aRe.block);
await expectCase("action block reorged out is INCONCLUSIVE", eRe, {
  status: "INCONCLUSIVE",
  reason: "action receipt is not in the canonical chain",
});
const aRe2 = execute(Kind.SLASH, 14n, slashF, 0b011n);
const eRe2 = disclose(Kind.SLASH, 14n, slashIn, aRe2);
reorg(disclosureBlock(eRe2));
await expectCase("disclosure block reorged out is INCONCLUSIVE", eRe2, {
  status: "INCONCLUSIVE",
  reason: "Disclosed log is not in the canonical chain",
});

// Codex M2 (cont.): a reorg that happens WHILE the check runs is caught by the closing re-check.
const aRe3 = execute(Kind.SLASH, 15n, slashF, 0b011n);
const eRe3 = disclose(Kind.SLASH, 15n, slashIn, aRe3);
reorgDuringNextCheck(aRe3.block);
await expectCase("reorg during the check is INCONCLUSIVE", eRe3, {
  status: "INCONCLUSIVE",
  reason: "canonical chain changed during the check",
});

// All state is read at one snapshot (head - confirmations): a commitment overwritten after the
// snapshot does not change the verdict, and a pointer to an action newer than the snapshot is not
// judged on unconfirmed data.
const aSnap = execute(Kind.SLASH, 16n, slashF, 0b011n);
const eSnap = disclose(Kind.SLASH, 16n, slashIn, aSnap);
mineEmpty();
overwrite(aSnap.key);
await expectCase("reads pinned to the snapshot, not latest", eSnap, "PASS", { confirmations: 2 });
// Entry written at block D that points at an action executed later, at A = D + 1. With the snapshot
// at D (confirmations = 1) the action is not yet confirmed: INCONCLUSIVE, not judged on it.
{
  const D = headNow() + 1;
  const A = D + 1;
  const id = 18n;
  const mh = spMessageHash(Kind.SLASH, id, slashF);
  const placeholder = {
    hash: ethers.id(`action-${A}-${Kind.SLASH}-${id}`),
    key: id,
    mh,
    signers: [],
    anchor: ethers.ZeroHash,
    block: A,
    mask: 0b011n,
  };
  const eFwd = disclose(Kind.SLASH, id, slashIn, placeholder);
  const aFwd = execute(Kind.SLASH, id, slashF, 0b011n);
  if (aFwd.hash !== placeholder.hash)
    throw new Error("self-test setup: predicted action hash wrong");
  await expectCase(
    "entry pointing at an action newer than the snapshot is INCONCLUSIVE",
    eFwd,
    { status: "INCONCLUSIVE", reason: "newer than the confirmed snapshot" },
    { confirmations: 1 }
  );
}

// Codex round 2, M1: the closing canonical re-check must not be answered from a request cache.
const aC = execute(Kind.SLASH, 19n, slashF, 0b011n);
const eC = disclose(Kind.SLASH, 19n, slashIn, aC);
reorgDuringNextCheck(aC.block);
await expectCase(
  "mid-check reorg caught through a caching provider",
  eC,
  { status: "INCONCLUSIVE", reason: "canonical chain changed during the check" },
  { chain: withRequestCache(chain) }
);

// Codex round 2, M2: a provable contradiction must not hide behind INCONCLUSIVE.
const aW2 = execute(Kind.SLASH, 20n, slashF, 0b011n, { to: WRAPPER });
await expectCase(
  "wrapped action + wrong blockNumber is MISMATCH, not INCONCLUSIVE",
  disclose(Kind.SLASH, 20n, slashIn, aW2, { blockNumber: 0 }),
  { diff: "blockNumber" }
);
const aMid2 = execute(Kind.SLASH, 21n, slashF, 0b011n, {
  midSlots: { 1: G[0], 2: addr("transient2") },
});
await expectCase(
  "intra-block slots + wrong proposalId is MISMATCH, not INCONCLUSIVE",
  disclose(Kind.SLASH, 21n, slashIn, aMid2, { proposalId: 22n }),
  { diff: "proposalId" }
);

// Codex round 2, M3: an honest entry that is not yet confirmations-deep is pending, not wrong.
const aP = execute(Kind.SLASH, 23n, slashF, 0b011n);
await expectCase(
  "honest entry inside the unconfirmed tail is INCONCLUSIVE",
  disclose(Kind.SLASH, 23n, slashIn, aP),
  { status: "INCONCLUSIVE", reason: "not yet 3 confirmations deep" },
  { confirmations: 3 }
);

// Codex round 2, L4: invalid paging/range inputs are refused before any RPC, not looped on.
await expectCase(
  "page 0 is refused",
  1n,
  { status: "THREW", reason: "page must be a positive" },
  { page: 0 }
);
await expectCase(
  "negative confirmations refused",
  1n,
  { status: "THREW", reason: "confirmations must be" },
  { confirmations: -1 }
);

// Codex round 3, M1: absence and orphaned evidence are not accusations.
{
  const aX = execute(Kind.SLASH, 24n, slashF, 0b011n);
  const eX = disclose(Kind.SLASH, 24n, slashIn, aX, { txHash: ethers.id("no-such-tx") });
  await expectCase("entry naming a tx this RPC does not have is INCONCLUSIVE", eX, {
    status: "INCONCLUSIVE",
    reason: "not available from this RPC",
  });
  const aY = execute(Kind.SLASH, 25n, slashF, 0b011n);
  const eY = disclose(Kind.SLASH, 25n, slashIn, aY);
  reorgDuringReceipt([aY.block, disclosureBlock(eY)]);
  await expectCase("reorg while fetching the receipt (null) is INCONCLUSIVE", eY, {
    status: "INCONCLUSIVE",
    reason: "not available from this RPC",
  });
  const aZ = execute(Kind.SLASH, 26n, slashF, 0b011n);
  const eZ = disclose(Kind.SLASH, 26n, slashIn, aZ);
  revertedOnOrphan(aZ.hash, aZ.block);
  await expectCase("reverted receipt from an orphaned block is INCONCLUSIVE", eZ, {
    status: "INCONCLUSIVE",
    reason: "not in the canonical chain",
  });
  const aRv = execute(Kind.SLASH, 27n, slashF, 0b011n, { status: 0 });
  await expectCase(
    "canonical reverted action is MISMATCH",
    disclose(Kind.SLASH, 27n, slashIn, aRv),
    {
      status: "MISMATCH",
      reason: "action tx reverted",
    }
  );
  // An issued entry whose log the search window misses is not proof it is absent.
  await expectCase(
    "issued entry outside the searched range is INCONCLUSIVE",
    1n,
    { status: "INCONCLUSIVE", reason: "but no Disclosed log was found" },
    { fromBlock: headNow() }
  );
}

// A MISMATCH found on the action side is re-confirmed: reads 1 = disclosure log, 2 = action
// header; a reorg right after read 2 must turn the verdict INCONCLUSIVE, whichever block moved.
{
  const aM = execute(Kind.SLASH, 29n, slashF, 0b011n);
  const eM = disclose(Kind.SLASH, 29n, slashIn, aM, { txHash: aG.hash }); // provably wrong pointer
  reorgAfterSends(2, aG.block);
  await expectCase("action reorged after a MISMATCH was found is INCONCLUSIVE", eM, {
    status: "INCONCLUSIVE",
    reason: "canonical chain changed during the check",
  });
  const aOther = execute(Kind.GENERIC, 30n, genF, 0b111n); // fresh target: the cell above reorged aG
  const eM2 = disclose(Kind.SLASH, 29n, slashIn, aM, { txHash: aOther.hash });
  reorgAfterSends(2, disclosureBlock(eM2));
  await expectCase("disclosure reorged after a MISMATCH was found is INCONCLUSIVE", eM2, {
    status: "INCONCLUSIVE",
    reason: "canonical chain changed during the check",
  });
}

// Codex round 3, M2: a missing parent header is a missing fact, not an anchor contradiction.
{
  const aH = execute(Kind.SLASH, 28n, slashF, 0b011n, { to: WRAPPER });
  const eH = disclose(Kind.SLASH, 28n, slashIn, aH);
  dropParentHash(aH.block);
  await expectCase("wrapped action with no parent header is INCONCLUSIVE, not MISMATCH", eH, {
    status: "INCONCLUSIVE",
    reason: "no parentHash",
  });
}

// Codex round 4: the "not issued" verdict is reorg-safe; a missing receipt status or a missing
// parentHash on a TOP-LEVEL action is missing data, never an accusation or a crash.
reorgHeadAfterCountRead();
await expectCase("reorg during the entryCount read is INCONCLUSIVE", 998n, {
  status: "INCONCLUSIVE",
  reason: "canonical chain changed during the check",
});
{
  const aN = execute(Kind.SLASH, 31n, slashF, 0b011n);
  const eN = disclose(Kind.SLASH, 31n, slashIn, aN);
  receiptWithoutStatus();
  await expectCase("receipt without status is INCONCLUSIVE, not 'reverted'", eN, {
    status: "INCONCLUSIVE",
    reason: "no valid status",
  });
  const aT = execute(Kind.SLASH, 32n, slashF, 0b011n);
  const eT = disclose(Kind.SLASH, 32n, slashIn, aT);
  dropParentHash(aT.block);
  await expectCase("top-level action with no parent header is INCONCLUSIVE", eT, {
    status: "INCONCLUSIVE",
    reason: "no parentHash",
  });
  const aT2 = execute(Kind.SLASH, 33n, slashF, 0b011n);
  const eT2 = disclose(Kind.SLASH, 33n, slashIn, aT2, { proposalId: 34n });
  dropParentHash(aT2.block);
  await expectCase("…and a wrong proposalId there is still MISMATCH", eT2, { diff: "proposalId" });
}

// Codex L4: a range-capped RPC still finds the entry (pages halve until they fit), across pages.
capRange(16);
const before = logCalls();
await expectCase("range-capped RPC: paged log search finds the entry", 1n, "PASS", { page: 64 });
const paged = logCalls() - before;
results.push({
  name: "paging actually split the range",
  ok: paged > 2,
  want: ">2 getLogs calls",
  got: String(paged),
});
capRange(Infinity);

let failed = 0;
for (const r of results) {
  console.log(
    `${r.ok ? "ok  " : "FAIL"} ${r.name}${r.ok ? "" : `\n     want ${r.want}\n     got  ${r.got}`}`
  );
  if (!r.ok) failed++;
}
const honest = results.filter(r => r.want === '"PASS"' || r.want.includes('"unverified"')).length;
console.log(
  `\n${results.length - failed}/${results.length} cells (${honest} must-pass, ${results.length - honest} must-fail)`
);
if (honest === 0 || honest === results.length) {
  console.log("FAIL: a recheck self-test needs both pass and fail cells");
  process.exit(1);
}
process.exit(failed ? 1 : 0);
