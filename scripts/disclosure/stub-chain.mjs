// Stub chain shared by the disclosure self-tests (check-recheck.mjs) and the guardian watcher's
// self-test (services/guardian-watcher/check-watcher.mjs). No RPC, no anvil.
//
// The stub aggregator derives its commitment the way SP's BLSAggregator does (mask bit i -> slot
// i+1 -> validatorAtSlot, insertion sort ascending), written out here with explicit abi types and NOT
// through recheck-lib's expectedCommitment, so a recheck that merely agrees with itself cannot pass.
import { ethers } from "ethers";
import { Kind, aggIface, dvtIface, regIface, safeIface } from "./recheck-lib.mjs";
import { spIface } from "../../services/guardian-watcher/lib/sp-abi.mjs";
import { bloomOf } from "../../services/guardian-watcher/lib/bloom.mjs";

const ABI = ethers.AbiCoder.defaultAbiCoder();
const AGG = ethers.getAddress("0x00000000000000000000000000000000000a6600");
const REG = ethers.getAddress("0x00000000000000000000000000000000000d1500");
const WRAPPER = ethers.getAddress("0x00000000000000000000000000000000000bad00");
const WATCHER = ethers.getAddress("0x0000000000000000000000000000000000000777");
const SAFE = ethers.getAddress("0x0000000000000000000000000000000000005afe");
const DVT = ethers.getAddress("0x00000000000000000000000000000000000d7700");
const MULTISEND = ethers.getAddress("0x0000000000000000000000000000000000035e00");
const FAKE_DVT = ethers.getAddress("0x00000000000000000000000000000000000fa4e0");
const SP = ethers.getAddress("0x00000000000000000000000000000000005b0000");
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
  const laggingBlocks = new Set(); // range getLogs omits these blocks' logs (a lagging node)
  const laggingTopics = new Map(); // block -> topic0 that the range getLogs omits
  let lagByHash = false; // ... and a by-hash re-read fails too (the node lacks the block)
  let noBloom = false; // headers without logsBloom
  const txPatch = new Map(); // hash -> fields a mixed backend answers for getTransaction
  const receiptPatch = new Map(); // hash -> fields a stale backend answers differently
  const receiptLogs = new Map(); // hash -> logs a (inconsistent) RPC returns in the receipt instead
  const rawResults = []; // non-log values a broken RPC returns once in a range getLogs answer
  let upperTopics = false; // a client answering getLogs topics in upper-case hex
  let traceMode = "ok"; // ok | unsupported (no debug namespace) | noLogs (withLog ignored)
  const txFailures = new Map(); // hash -> remaining getTransaction failures
  let priceFailures = 0; // next N cachedPrice reads fail
  const forcedBlooms = new Map(); // block -> bloom hex (to model a bloom false positive)
  let finalityLag = 0; // "finalized" = head - finalityLag
  const storage = new Map(); // `${address}:${slot}` -> [{ block, word }] (block-versioned)
  const prestates = new Map(); // tx hash -> prestateTracer result
  const prices = []; // SuperPaymaster cachedPrice history: [{ block, price }]
  /** Append a tx's receipt logs to the chain-wide log index (getLogs), with positions. */
  const indexLogs = (hash, n, rlogs) =>
    rlogs.forEach((l, i) =>
      logs.push({
        ...l,
        blockNumber: n,
        blockHash: blocks.get(n).hash,
        transactionHash: hash,
        index: i, // as an ethers v6 Log names it (not logIndex)
      })
    );
  const proposals = new Map(); // DVTValidator id -> { block, operator, slashLevel, evidenceHash }
  const traces = new Map(); // tx hash -> callTracer frame
  let onEntryCountRead = null; // one-shot hook right after a by-hash eth_call returns
  let afterSends = null; // { left, fn }: run fn once `left` more raw sends have returned

  const chain = {
    async getTransaction(h) {
      const left = txFailures.get(h) ?? 0;
      if (left > 0) {
        txFailures.set(h, left - 1);
        throw new Error("transient: tx lookup failed");
      }
      const tx = txs.get(h)?.tx ?? null;
      return tx && txPatch.has(h) ? { ...tx, ...txPatch.get(h) } : tx;
    },
    async getTransactionReceipt(h) {
      if (onReceipt) {
        const f = onReceipt;
        onReceipt = null;
        return f(h);
      }
      const base = txs.get(h)?.receipt ?? null;
      const rc = base ? { transactionHash: h, ...base, ...(receiptPatch.get(h) ?? {}) } : null; // a real receipt names its tx
      return rc && receiptLogs.has(h) ? { ...rc, logs: receiptLogs.get(h) } : rc;
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
      if (method === "eth_getStorageAt") {
        const [who, slot, tag] = params;
        const at = tag === undefined || tag === "latest" ? head : Number(tag);
        const hist = (storage.get(`${ethers.getAddress(who)}:${BigInt(slot)}`) ?? []).filter(
          h => h.block <= at
        );
        return hist.length ? hist[hist.length - 1].word : ethers.ZeroHash;
      }
      if (method === "debug_traceTransaction" && params[1]?.tracer === "prestateTracer") {
        const pre = prestates.get(params[0]);
        if (!pre) throw new Error("prestate unavailable");
        return pre;
      }
      if (method === "debug_traceTransaction") {
        if (traceMode === "unsupported")
          throw Object.assign(new Error("the method debug_traceTransaction does not exist"), {
            error: { code: -32601, message: "the method debug_traceTransaction does not exist" },
          });
        if (!txs.has(params[0])) throw new Error("transaction not found");
        const t = traces.get(params[0]);
        if (!t) throw new Error("trace unavailable"); // a transient failure for this tx
        if (traceMode === "noLogs") {
          const strip = n => ({ ...n, logs: undefined, calls: (n.calls ?? []).map(strip) });
          return strip(t);
        }
        return t;
      }
      if (method !== "eth_getBlockByNumber") throw new Error(`stub send: ${method}`);
      const num =
        params[0] === "finalized"
          ? head - finalityLag
          : params[0] === "latest"
            ? head
            : Number(params[0]);
      const b = blocks.get(num);
      const out = b
        ? {
            hash: b.hash,
            parentHash: b.parentHash,
            number: ethers.toQuantity(num),
            transactions: [...txs]
              .filter(([, v]) => Number(v.receipt?.blockNumber) === num)
              .map(([h]) => h),
            ...(noBloom
              ? {}
              : {
                  logsBloom:
                    forcedBlooms.get(num) ?? bloomOf(logs.filter(l => l.blockNumber === num)),
                }),
          }
        : null;
      if (afterSends && --afterSends.left === 0) {
        const f = afterSends.fn;
        afterSends = null;
        f();
      }
      return out;
    },
    async getLogs({ address, topics, fromBlock, toBlock, blockHash }) {
      getLogsCalls++;
      if (blockHash !== undefined) {
        // EIP-234: a node without the block errors; one with it answers exactly.
        const n = [...blocks.entries()].find(([, b]) => b.hash === blockHash)?.[0];
        if (n === undefined || (lagByHash && laggingBlocks.has(n)))
          throw new Error("unknown block");
        fromBlock = n;
        toBlock = n;
      } else if (toBlock - fromBlock + 1 > maxRange) throw new Error("block range too large");
      const up = x => "0x" + x.slice(2).toUpperCase();
      return logs
        .filter(
          l =>
            l.address === address &&
            l.blockNumber >= fromBlock &&
            l.blockNumber <= toBlock &&
            (blockHash !== undefined || !laggingBlocks.has(l.blockNumber)) &&
            (blockHash !== undefined || laggingTopics.get(l.blockNumber) !== l.topics[0]) &&
            topics.every(
              (t, i) =>
                t == null || (Array.isArray(t) ? t.includes(l.topics[i]) : l.topics[i] === t)
            )
        )
        .map(l => (upperTopics ? { ...l, topics: l.topics.map(up) } : l))
        .concat(
          blockHash === undefined
            ? (() => {
                const mine = rawResults.filter(r => r.address === address);
                for (const r of mine) rawResults.splice(rawResults.indexOf(r), 1);
                return mine.map(r => r.value);
              })()
            : []
        );
    },
    async call({ to, data, blockTag }) {
      if (to === SP) {
        const q = spIface.parseTransaction({ data });
        if (q.name !== "cachedPrice") throw new Error(`stub sp: ${q.name}`);
        if (priceFailures > 0) {
          priceFailures--;
          throw new Error("transient: price read failed");
        }
        const at = blockTag === "latest" ? head : Number(blockTag);
        const hist = prices.filter(x => x.block <= at);
        const pr = hist.length ? hist[hist.length - 1].price : 0n;
        return spIface.encodeFunctionResult("cachedPrice", [pr, at, 0, 8]);
      }
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
  function execute(
    kind,
    id,
    f,
    mask,
    { to = AGG, from = SAFE, midSlots, status = 1, via, spLogs = [], price } = {}
  ) {
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
    const rlogs = [
      { address: AGG, topics: ev.topics, data: ev.data },
      ...spLogs.map(x => ({ address: SP, ...spIface.encodeEventLog(x.name, x.args) })),
    ];
    rlogs.forEach((l, i) => (l.index = i)); // receipt logs carry their position, as in ethers
    if (price !== undefined) prices.push({ block: n, price });
    txs.set(hash, {
      tx: { hash, to, from, data },
      receipt: { status, blockNumber: n, blockHash: blocks.get(n).hash, logs: rlogs },
    });
    if (status === 1) indexLogs(hash, n, rlogs);
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
    /** A tx straight to the SuperPaymaster proxy (owner/guardian route): SP events, no BLS. */
    /**
     * A non-BLS tx emitting SP events. By default the owner Safe calls SP directly with `data`
     * (no selector: "0x"); `to`/`data` model a keeper's direct call, or a call through a contract
     * (then attribution needs a trace: setTrace).
     */
    ownerTx: (spLogsIn, { from = SAFE, price, to = SP, data = "0x", trace } = {}) => {
      const n = mine();
      const hash = ethers.id(`owner-${n}`);
      const rlogs = spLogsIn.map(x => ({ address: SP, ...spIface.encodeEventLog(x.name, x.args) }));
      rlogs.forEach((l, i) => (l.index = i)); // receipt logs carry their position, as in ethers
      if (price !== undefined) prices.push({ block: n, price });
      txs.set(hash, {
        tx: { hash, to, from, data },
        receipt: { status: 1, blockNumber: n, blockHash: blocks.get(n).hash, logs: rlogs },
      });
      indexLogs(hash, n, rlogs);
      // A direct call to SP gets the trace a tracing node would return, unless trace === false.
      if (to === SP && trace !== false)
        traces.set(hash, {
          type: "CALL",
          from,
          to: SP,
          input: data,
          logs: rlogs.map(l => ({ address: l.address, topics: l.topics, data: l.data })),
        });
      return { hash, block: n };
    },
    setPrice: (block, price) => prices.push({ block, price }),
    /** Range getLogs omits block n's logs (a lagging node); byHashFails: the re-read errors too. */
    lagBlock: (n, { byHashFails = false } = {}) => {
      laggingBlocks.add(n);
      lagByHash = byHashFails;
    },
    lagTopic: (n, topic) => laggingTopics.set(n, topic),
    clearLag: () => {
      laggingTopics.clear();
      laggingBlocks.clear();
      lagByHash = false;
    },
    setNoBloom: v => (noBloom = v),
    failTx: (hash, times) => txFailures.set(hash, times),
    setTraceMode: m => (traceMode = m),
    setUpperTopics: v => (upperTopics = v),
    /** Make the next range getLogs for `address` also return `value` (e.g. null). */
    injectRawResult: (address, value) => rawResults.push({ address, value }),
    /** Patch the getLogs copy of a tx's logs (e.g. a contradictory position), not its receipt. */
    patchLogs: (hash, patch) => {
      for (const l of logs) if (l.transactionHash === hash) Object.assign(l, patch);
    },
    /** A raw (possibly malformed) log the RPC returns from getLogs, at block n. */
    injectLog: (n, raw) =>
      logs.push({ blockNumber: n, blockHash: blocks.get(n).hash, index: 0, ...raw }),
    setReceiptLogs: (hash, l) => receiptLogs.set(hash, l),
    patchReceipt: (hash, p) => receiptPatch.set(hash, p),
    patchTx: (hash, p) => txPatch.set(hash, p),
    failPriceReads: n => (priceFailures = n),
    /** Make block n's header bloom claim these logs ({ address, topics }) without them existing. */
    forceBloom: (n, fake) => forcedBlooms.set(n, bloomOf(fake)),
    mine: () => mine(),
    /** Install a callTracer trace for a tx (frames may carry `logs`, as with withLog). */
    // A real callTracer root always names the tx: from, to and input default to the tx's own.
    setTrace: (hash, frame) => {
      const tx = txs.get(hash)?.tx;
      traces.set(hash, tx ? { from: tx.from, to: tx.to, input: tx.data, ...frame } : frame);
    },
    /** Install a prestateTracer result for a tx ({ address: { storage: { slot: word } } }). */
    setPrestate: (hash, pre) => prestates.set(hash, pre),
    setFinalityLag: k => (finalityLag = k),
    setStorage: (who, slot, word, fromBlock = 0) => {
      const k = `${ethers.getAddress(who)}:${BigInt(slot)}`;
      storage.set(
        k,
        [...(storage.get(k) ?? []), { block: fromBlock, word }].sort((a, b) => a.block - b.block)
      );
    },
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

export {
  ABI,
  AGG,
  REG,
  WRAPPER,
  WATCHER,
  SAFE,
  DVT,
  MULTISEND,
  FAKE_DVT,
  SP,
  FORWARDERS,
  DS,
  addr,
  G,
  G_NEW,
  spMessageHash,
  spKey,
  spSigners,
  makeChain,
  slashF,
  slashIn,
  genF,
  genIn,
  qF,
  qIn,
  repF,
  repIn,
  withRequestCache,
};
