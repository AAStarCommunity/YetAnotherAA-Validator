// CI self-test for scripts/disclosure/recheck-lib.mjs against a stub chain (no RPC, no anvil).
//
// The stub aggregator derives its commitment the way SP's BLSAggregator does (mask bit i -> slot
// i+1 -> validatorAtSlot, insertion sort ascending), written out here with explicit abi types and NOT
// through recheck-lib's expectedCommitment, so a recheck that merely agrees with itself cannot pass.
//
// Each case is a control cell: correct entries must PASS and every forged entry must FAIL, and each
// failing case asserts WHICH check fired, so a recheck that fails for the wrong reason is caught too.
import { ethers } from "ethers";
import { Kind, aggIface, dvtIface, regIface, safeIface, recheckEntry } from "./recheck-lib.mjs";

const ABI = ethers.AbiCoder.defaultAbiCoder();
const AGG = ethers.getAddress("0x00000000000000000000000000000000000a6600");
const REG = ethers.getAddress("0x00000000000000000000000000000000000d1500");
const WRAPPER = ethers.getAddress("0x00000000000000000000000000000000000bad00");
const WATCHER = ethers.getAddress("0x0000000000000000000000000000000000000777");
const SAFE = ethers.getAddress("0x0000000000000000000000000000000000005afe");
const DVT = ethers.getAddress("0x00000000000000000000000000000000000d7700");
const MULTISEND = ethers.getAddress("0x0000000000000000000000000000000000035e00");
const FAKE_DVT = ethers.getAddress("0x00000000000000000000000000000000000fa4e0");
/** What a release manifest pins for the forwarder roles. */
const FORWARDERS = { dvtValidator: DVT, ownerSafe: SAFE, multiSendCallOnly: MULTISEND };
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
  const proposals = new Map(); // DVTValidator id -> { block, operator, slashLevel, evidenceHash }
  const traces = new Map(); // tx hash -> callTracer frame
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
      if (method === "debug_traceTransaction") {
        const t = traces.get(params[0]);
        if (!t) throw new Error("the method debug_traceTransaction does not exist");
        return t;
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
      if (to === DVT) {
        const q = dvtIface.parseTransaction({ data });
        if (q.name !== "proposals") throw new Error(`stub dvt: ${q.name}`);
        const pr = proposals.get(BigInt(q.args[0]));
        const at = blockTag === "latest" ? head : Number(blockTag);
        const live = pr && pr.block <= at;
        return dvtIface.encodeFunctionResult("proposals", [
          live ? pr.operator : ethers.ZeroAddress,
          live ? pr.slashLevel : 0,
          "",
          false,
          !!live,
          live ? pr.evidenceHash : ethers.ZeroHash,
        ]);
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

  /** Calldata for an action routed through a forwarder (DVTValidator, the owner Safe, MultiSend). */
  function wrapVia(via, kind, id, f, aggData, n) {
    const dvtData = () =>
      kind === Kind.QUEUE
        ? dvtIface.encodeFunctionData("queueSlashWithProof", [
            f.operator,
            f.slashLevel,
            f.epoch,
            "0x",
          ])
        : dvtIface.encodeFunctionData("executeWithProof", [
            id,
            kind === Kind.REPUTATION ? f.users : [],
            kind === Kind.REPUTATION ? f.newScores : [],
            f.epoch,
            "0x",
          ]);
    const safeExec = (target, data, op) =>
      safeIface.encodeFunctionData("execTransaction", [
        target,
        0,
        data,
        op,
        0,
        0,
        0,
        ethers.ZeroAddress,
        ethers.ZeroAddress,
        "0x",
      ]);
    const packed = subs =>
      ethers.concat(
        subs.map(x =>
          ethers.solidityPacked(
            ["uint8", "address", "uint256", "uint256", "bytes"],
            [x.op, x.to, 0, ethers.dataLength(x.data), x.data]
          )
        )
      );
    const dvtCallFrame = () => ({
      type: "CALL",
      to: DVT,
      input: dvtData(),
      calls: [{ type: "CALL", to: AGG, input: aggData }],
    });
    switch (via.route) {
      case "dvt":
        // A reputation proposal is created with operator 0 / level 0 (the aggregator requires both
        // zero for a batch); a slash proposal stores its own fields.
        if (kind !== Kind.QUEUE)
          proposals.set(
            BigInt(id),
            kind === Kind.REPUTATION
              ? {
                  block: via.createdAt ?? n - 1,
                  operator: ethers.ZeroAddress,
                  slashLevel: 0,
                  evidenceHash: ethers.ZeroHash,
                }
              : { block: via.createdAt ?? n - 1, ...(via.overrideProposal ?? f) }
          );
        return { to: DVT, data: dvtData() };
      case "fake-dvt": // DVTValidator calldata at an address the manifest does not pin
        if (kind !== Kind.QUEUE) proposals.set(BigInt(id), { block: n - 1, ...f });
        return { to: FAKE_DVT, data: dvtData() };
      case "safe": // `inner` replaces the Safe's inner call (e.g. a different message under the same key)
        return { to: SAFE, data: safeExec(AGG, via.inner ?? aggData, 0) };
      case "safe-delegate":
        return { to: SAFE, data: safeExec(WRAPPER, aggData, 1) };
      case "multisend":
        return {
          to: SAFE,
          data: safeExec(
            MULTISEND,
            safeIface.encodeFunctionData("multiSend", [
              packed([
                { op: 0, to: addr("unrelated"), data: "0x1234" },
                ...via.subs.map(op => ({ op, to: AGG, data: aggData })),
                ...(via.extraAgg ? [{ op: 0, to: AGG, data: via.extraAgg }] : []),
                ...(via.extraSub ? [via.extraSub] : []),
              ]),
            ]),
            1
          ),
        };
      case "trace-delegate": // unpinned wrapper -> DELEGATECALL (not MultiSendCallOnly) -> aggregator
        return {
          to: WRAPPER,
          data: "0xdeadbeef",
          trace: {
            type: "CALL",
            to: WRAPPER,
            input: "0xdeadbeef",
            calls: [
              {
                type: "DELEGATECALL",
                to: addr("some-library"),
                input: "0x01",
                calls: [{ type: "CALL", to: AGG, input: aggData }],
              },
            ],
          },
        };
      case "trace-module": // unpinned wrapper -> pinned Safe module route -> aggregator, seen by trace
        return {
          to: WRAPPER,
          data: "0xdeadbeef",
          trace: {
            type: "CALL",
            to: WRAPPER,
            input: "0xdeadbeef",
            calls: [
              {
                type: "CALL",
                to: SAFE,
                input: safeIface.encodeFunctionData("execTransactionFromModule", [
                  AGG,
                  0,
                  aggData,
                  0,
                ]),
                calls: [{ type: "CALL", to: AGG, input: aggData }],
              },
            ],
          },
        };
      case "module":
        return {
          to: SAFE,
          data: safeIface.encodeFunctionData("execTransactionFromModule", [AGG, 0, aggData, 0]),
        };
      case "trace": // an unpinned wrapper; the RPC offers a callTracer trace
        if (via.dvt) proposals.set(BigInt(id), { block: n - 1, ...f });
        return {
          to: WRAPPER,
          data: "0xdeadbeef",
          trace: {
            type: "CALL",
            to: WRAPPER,
            input: "0xdeadbeef",
            calls: [
              via.dvt ? dvtCallFrame() : { type: via.frameType ?? "CALL", to: AGG, input: aggData },
            ],
          },
        };
      default:
        throw new Error(`unknown route ${via.route}`);
    }
  }

  /** Execute one action as SP would: commitment over pre-block slots, SignersCommitted log. */
  function execute(kind, id, f, mask, { to = AGG, from = SAFE, midSlots, status = 1, via } = {}) {
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
    let trace = null;
    if (via) ({ to, data, trace } = wrapVia(via, kind, id, f, data, n));
    else if (to !== AGG) data = ethers.concat(["0xdeadbeef", data]); // a wrapper contract's own calldata
    const hash = ethers.id(`action-${n}-${kind}-${id}`);
    if (trace) traces.set(hash, trace);
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
      [
        e.subjectToken,
        e.txHash,
        e.blockNumber,
        e.blockVerified,
        e.rulesetCommit,
        e.recordURI,
        e.recordHash,
      ],
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
      forwarders: opts.forwarders ?? FORWARDERS,
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

// Codex round 5, L1: a provider without raw send cannot prove absence by counter.
{
  const noSend = { ...chain };
  delete noSend.send;
  await expectCase(
    "never-issued id through a provider without send is INCONCLUSIVE",
    997n,
    { status: "INCONCLUSIVE", reason: "cannot read state by block hash" },
    { chain: noSend }
  );
  await expectCase(
    "entry id 0 is MISMATCH on any provider",
    0n,
    { status: "MISMATCH", reason: "entry id 0" },
    { chain: noSend }
  );
}

// ---------------------------------------------------------------- forwarder routes (M0 §4.4, DSR)
// A real action is almost never a top-level aggregator call: slash/queue go through DVTValidator,
// the owner route through the Safe. Each route is followed only at its manifest-pinned address.
{
  const r = (route, extra = {}) => ({ via: { route, ...extra } });
  const aD = execute(Kind.SLASH, 40n, slashF, 0b011n, r("dvt"));
  await expectCase(
    "DVTValidator.executeWithProof route (fields from proposals@N-1)",
    disclose(Kind.SLASH, 40n, slashIn, aD),
    "PASS"
  );
  const aDq = execute(Kind.QUEUE, 0n, { ...qF, epoch: 50n }, 0b110n, r("dvt"));
  const qIn50 = ABI.encode(["address", "uint8", "uint256"], [qF.operator, qF.slashLevel, 50n]);
  await expectCase(
    "DVTValidator.queueSlashWithProof route",
    disclose(Kind.QUEUE, 0n, qIn50, aDq),
    "PASS"
  );
  const aDr = execute(Kind.REPUTATION, 41n, repF, 0b111n, r("dvt"));
  await expectCase(
    "DVTValidator route, reputation batch",
    disclose(Kind.REPUTATION, 41n, repIn, aDr),
    "PASS"
  );
  const aDf = execute(Kind.SLASH, 42n, slashF, 0b011n, r("dvt"));
  await expectCase(
    "DVTValidator route + forged messageInputs is MISMATCH",
    disclose(
      Kind.SLASH,
      42n,
      ABI.encode(
        ["address", "uint8", "uint256", "bytes32"],
        [slashF.operator, 2, slashF.epoch, slashF.evidenceHash]
      ),
      aDf
    ),
    { diff: "signed.messageInputs" }
  );
  const aDs = execute(Kind.SLASH, 43n, slashF, 0b011n, r("dvt", { createdAt: headNow() + 1 }));
  await expectCase(
    "DVTValidator proposal created in the same block is INCONCLUSIVE",
    disclose(Kind.SLASH, 43n, slashIn, aDs),
    {
      status: "INCONCLUSIVE",
      reason: "did not exist at block",
    }
  );
  const aFk = execute(Kind.SLASH, 44n, slashF, 0b011n, r("fake-dvt"));
  await expectCase(
    "DVTValidator selector at an UNPINNED address is INCONCLUSIVE",
    disclose(Kind.SLASH, 44n, slashIn, aFk),
    {
      status: "INCONCLUSIVE",
      reason: "not pin",
    }
  );
  const aDu = execute(Kind.SLASH, 45n, slashF, 0b011n, r("dvt"));
  await expectCase(
    "DVTValidator route with the forwarder NOT pinned is INCONCLUSIVE",
    disclose(Kind.SLASH, 45n, slashIn, aDu),
    { status: "INCONCLUSIVE", reason: "not pin" },
    { forwarders: { ownerSafe: SAFE } }
  );
  const aS1 = execute(Kind.GENERIC, 46n, genF, 0b111n, r("safe"));
  await expectCase(
    "owner Safe execTransaction (CALL) route",
    disclose(Kind.GENERIC, 46n, genIn, aS1),
    "PASS"
  );
  const aS2 = execute(Kind.SLASH, 47n, slashF, 0b011n, r("safe-delegate"));
  await expectCase(
    "Safe DELEGATECALL (not MultiSendCallOnly) is INCONCLUSIVE",
    disclose(Kind.SLASH, 47n, slashIn, aS2),
    {
      status: "INCONCLUSIVE",
      reason: "DELEGATECALL",
    }
  );
  const aM1 = execute(Kind.GENERIC, 48n, genF, 0b111n, r("multisend", { subs: [0] }));
  await expectCase(
    "Safe -> pinned MultiSendCallOnly, all CALL sub-txs",
    disclose(Kind.GENERIC, 48n, genIn, aM1),
    "PASS"
  );
  // A batch that also carries an unrelated aggregator call: only the call whose key matches counts.
  const otherCall = aggIface.encodeFunctionData("executeProposal", [
    99n,
    genF.target,
    "0xabcdef",
    3n,
    "0x",
  ]);
  const aM3 = execute(
    Kind.GENERIC,
    54n,
    genF,
    0b111n,
    r("multisend", { subs: [0], extraAgg: otherCall })
  );
  await expectCase(
    "MultiSend with a second, non-matching aggregator call",
    disclose(Kind.GENERIC, 54n, genIn, aM3),
    "PASS"
  );
  // Codex review of 022d80db.
  // H: a Safe inner call is not proven (execTransaction does not revert on inner failure). One
  // carrying a different message under the honest action's key must not accuse the honest entry.
  const otherMsg = aggIface.encodeFunctionData("executeProposal", [
    60n,
    genF.target,
    "0x99",
    3n,
    "0x",
  ]);
  const aH = execute(Kind.GENERIC, 60n, genF, 0b111n, r("safe", { inner: otherMsg }));
  await expectCase(
    "unauthenticated Safe inner call cannot accuse an honest entry",
    disclose(Kind.GENERIC, 60n, genIn, aH),
    {
      status: "INCONCLUSIVE",
      reason: "no recovered call is authenticated",
    }
  );
  // M1: two candidates under one key, only one authenticates -> that one is used. The second is a
  // nested Safe execTransaction whose inner call fails: with a nonzero safeTxGas (Safe v1.3.0
  // GnosisSafe.sol L168-170 reverts GS013 only when safeTxGas == 0 && gasPrice == 0) it returns
  // false without reverting, so the batch (and the honest call before it) still succeeds.
  const nestedFail = {
    op: 0,
    to: SAFE,
    data: safeIface.encodeFunctionData("execTransaction", [
      AGG,
      0,
      aggIface.encodeFunctionData("executeProposal", [61n, genF.target, "0x77", 3n, "0x"]),
      0,
      100000,
      0,
      0,
      ethers.ZeroAddress,
      ethers.ZeroAddress,
      "0x",
    ]),
  };
  const aTwo = execute(
    Kind.GENERIC,
    61n,
    genF,
    0b111n,
    r("multisend", { subs: [0], extraSub: nestedFail })
  );
  await expectCase(
    "same-key candidates (one inside a failing nested Safe call): the authenticated one is used",
    disclose(Kind.GENERIC, 61n, genIn, aTwo),
    "PASS"
  );
  // M3: a batch with any non-CALL sub-tx is skipped whole (MultiSendCallOnly would revert it).
  const aMix = execute(Kind.GENERIC, 62n, genF, 0b111n, r("multisend", { subs: [0, 1] }));
  await expectCase(
    "mixed CALL/DELEGATECALL MultiSend batch is skipped whole",
    disclose(Kind.GENERIC, 62n, genIn, aMix),
    {
      status: "INCONCLUSIVE",
      reason: "batch skipped",
    }
  );
  // M2: the trace walk enforces the module-route rule too.
  const aTm = execute(Kind.GENERIC, 63n, genF, 0b111n, r("trace-module"));
  await expectCase(
    "trace through a Safe module route is INCONCLUSIVE",
    disclose(Kind.GENERIC, 63n, genIn, aTm),
    {
      status: "INCONCLUSIVE",
      reason: "module route not followed",
    }
  );
  // Codex R2 Medium: a DVTValidator-derived candidate is not proven (its BLS_AGGREGATOR is mutable),
  // so when it does not reproduce the commitment it must not accuse: INCONCLUSIVE, not MISMATCH.
  {
    const aDv = execute(
      Kind.SLASH,
      65n,
      slashF,
      0b011n,
      r("dvt", { overrideProposal: { ...slashF, slashLevel: 2 } })
    );
    await expectCase(
      "unauthenticated DVTValidator candidate cannot accuse an honest entry",
      disclose(Kind.SLASH, 65n, slashIn, aDv),
      {
        status: "INCONCLUSIVE",
        reason: "no recovered call is authenticated",
      }
    );
  }
  const aTdg = execute(Kind.GENERIC, 64n, genF, 0b111n, r("trace-delegate"));
  await expectCase(
    "trace: aggregator call under a non-MultiSend DELEGATECALL is INCONCLUSIVE",
    disclose(Kind.GENERIC, 64n, genIn, aTdg),
    {
      status: "INCONCLUSIVE",
      reason: "DELEGATECALL subtree not followed",
    }
  );
  const aM2 = execute(Kind.GENERIC, 49n, genF, 0b111n, r("multisend", { subs: [1] }));
  await expectCase(
    "MultiSend sub-tx by DELEGATECALL is INCONCLUSIVE",
    disclose(Kind.GENERIC, 49n, genIn, aM2),
    {
      status: "INCONCLUSIVE",
      reason: "DELEGATECALL is not followed",
    }
  );
  const aMo = execute(Kind.GENERIC, 50n, genF, 0b111n, r("module"));
  await expectCase("Safe module route is INCONCLUSIVE", disclose(Kind.GENERIC, 50n, genIn, aMo), {
    status: "INCONCLUSIVE",
    reason: "module route",
  });
  const aT = execute(Kind.SLASH, 51n, slashF, 0b011n, r("trace"));
  await expectCase(
    "unpinned wrapper + callTracer frame to the aggregator",
    disclose(Kind.SLASH, 51n, slashIn, aT),
    "PASS"
  );
  const aTd = execute(Kind.SLASH, 52n, slashF, 0b011n, r("trace", { dvt: true }));
  await expectCase(
    "unpinned wrapper + trace through the pinned DVTValidator",
    disclose(Kind.SLASH, 52n, slashIn, aTd),
    "PASS"
  );
  const aTs = execute(Kind.SLASH, 53n, slashF, 0b011n, r("trace", { frameType: "STATICCALL" }));
  await expectCase(
    "trace frame that is not a CALL is not decoded",
    disclose(Kind.SLASH, 53n, slashIn, aTs),
    {
      status: "INCONCLUSIVE",
      reason: "no aggregator call recoverable",
    }
  );
}

// DSR follow-up to #396: an entry logged in the pre-#396 flat 13-argument event shape is never
// returned by the topic filter (INCONCLUSIVE, never MATCH), and its data does not decode.
{
  const OLD = new ethers.Interface([
    "event Disclosed(uint256 indexed entryId, uint8 indexed kind, uint256 indexed key, uint256 proposalId, bytes32 messageHash, address[] signers, address subjectToken, bytes32 txHash, uint64 blockNumber, bool blockVerified, bytes20 rulesetCommit, string recordURI, bytes32 recordHash)",
  ]);
  const oldTopic = OLD.getEvent("Disclosed").topicHash;
  results.push({
    name: "old flat event topic differs from the current one",
    ok: oldTopic !== regIface.getEvent("Disclosed").topicHash,
    want: "different topics",
    got: oldTopic,
  });
  const ev = OLD.encodeEventLog("Disclosed", [
    1n,
    0,
    7n,
    7n,
    ethers.id("m"),
    [],
    ethers.ZeroAddress,
    ethers.id("tx"),
    5n,
    true,
    "0x" + "ab".repeat(20),
    "u",
    ethers.id("r"),
  ]);
  let threw = false;
  try {
    regIface.decodeEventLog("Disclosed", ev.data, [
      regIface.getEvent("Disclosed").topicHash,
      ...ev.topics.slice(1),
    ]);
  } catch {
    threw = true;
  }
  results.push({
    name: "old flat event data does not decode as the current event",
    ok: threw,
    want: "throws",
    got: String(threw),
  });
  const oldOnly = {
    ...chain,
    async getLogs({ topics }) {
      return [
        {
          address: REG,
          topics: ev.topics,
          data: ev.data,
          blockNumber: 5,
          blockHash: ethers.id("block-5"),
          transactionHash: ethers.id("d"),
        },
      ].filter(l => l.topics[0] === topics[0] && l.topics[1] === topics[1]);
    },
  };
  await expectCase(
    "an old-shape log is never treated as an entry",
    1n,
    { status: "INCONCLUSIVE", reason: "no Disclosed log was found" },
    { chain: oldOnly }
  );
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
