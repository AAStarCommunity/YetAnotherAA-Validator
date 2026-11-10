// One watcher tick (M0 §5.2): scan finalized blocks for BLS-executed actions (SignersCommitted on
// the pinned aggregator) and for owner/guardian-route actions on the SuperPaymaster proxy, build a
// record for each, apply the pinned ruleset, and store it. No sending: disclosure sinks are W2.
import { ethers } from "ethers";
import {
  KIND_NAME,
  aggIface,
  rebuildFromAction,
} from "../../../scripts/disclosure/recheck-lib.mjs";
import { spIface, SP_WATCHED_EVENTS } from "./sp-abi.mjs";
import { evaluate, wantsPrice, publicFunction, ambiguousEvents } from "./rules.mjs";
import { attributeLogs } from "./attribute.mjs";
import { mayHaveLog } from "./bloom.mjs";

export const MAX_DEADLETTER_ATTEMPTS = 20;

async function header(chain, tag) {
  const b = await chain.send("eth_getBlockByNumber", [
    typeof tag === "number" ? ethers.toQuantity(tag) : tag,
    false,
  ]);
  if (!b || !b.hash) throw new Error(`block ${tag} unavailable`);
  return { number: Number(b.number), hash: b.hash, logsBloom: b.logsBloom };
}

/** getLogs over [from, to], paged; a failing page halves down to one block before giving up. */
export async function pagedLogs(chain, address, topics, from, to, page = 5_000) {
  const out = [];
  let a = from;
  let size = page;
  while (a <= to) {
    const b = Math.min(to, a + size - 1);
    try {
      out.push(...(await chain.getLogs({ address, topics, fromBlock: a, toBlock: b })));
      a = b + 1;
      size = page;
    } catch (e) {
      if (size === 1) throw e;
      size = Math.max(1, Math.floor(size / 2));
    }
  }
  return out;
}

async function readPrice(chain, sp, blockTag) {
  try {
    const ret = await chain.call({
      to: sp,
      data: spIface.encodeFunctionData("cachedPrice", []),
      blockTag,
    });
    const r = spIface.decodeFunctionResult("cachedPrice", ret);
    return { price: r.price.toString(), updatedAt: r.updatedAt.toString(), block: blockTag };
  } catch (e) {
    return { error: e.shortMessage ?? e.message, block: blockTag };
  }
}

function decodeSp(log) {
  try {
    const p = spIface.parseLog(log);
    return p
      ? {
          event: p.name,
          args: Object.fromEntries(p.fragment.inputs.map((inp, i) => [inp.name, p.args[i]])),
        }
      : null;
  } catch {
    return null;
  }
}

/** ethers v6 `Log` carries its position as `index`; other providers use `logIndex`. */
export function logPos(l) {
  const v = l.index ?? l.logIndex;
  const n = typeof v === "string" ? Number(BigInt(v)) : Number(v);
  if (!Number.isSafeInteger(n) || n < 0)
    throw new Error(`log without a valid position in tx ${l.transactionHash}`);
  return n;
}

/** Full receipt + callTracer (withLog) trace of a tx, for attribution; null parts when unavailable. */
async function traceAndReceipt(chain, txHash) {
  let trace = null;
  let rc = null;
  try {
    rc = await chain.getTransactionReceipt(txHash);
  } catch {
    rc = null;
  }
  if (typeof chain.send === "function") {
    try {
      trace = await chain.send("debug_traceTransaction", [
        txHash,
        { tracer: "callTracer", tracerConfig: { withLog: true } },
      ]);
    } catch {
      trace = null;
    }
  }
  return { trace, logs: rc?.logs ?? null };
}

/** Build the record for one SignersCommitted log. Returns { record } or { deadLetter }. */
async function blsRecord(chain, cfg, rs, ctx, log, spEvents, snapshot) {
  const key = BigInt(log.topics[1]);
  const signerMask = BigInt(
    aggIface.decodeEventLog("SignersCommitted", log.data, log.topics).signerMask
  );
  const base = {
    route: "bls",
    key: key.toString(),
    signerMask: signerMask.toString(),
    txHash: log.transactionHash,
    blockNumber: Number(log.blockNumber),
    logIndex: logPos(log),
    ruleset: ctx.ruleset,
    seenAt: ctx.now,
  };
  let r;
  try {
    r = await rebuildFromAction(
      chain,
      cfg.aggregator,
      log.transactionHash,
      key,
      snapshot,
      cfg.forwarders
    );
  } catch (e) {
    // One action that cannot be rebuilt must not stop the scan: keep it, retry it, move on.
    return {
      deadLetter: {
        ...base,
        status: "ERROR",
        reasons: [`rebuild failed: ${e.shortMessage ?? e.message}`],
        verdict: evaluate(rs, cfg.roles, { ...base, kind: undefined }),
        spEvents,
      },
    };
  }
  const facts = r.facts;
  // A record needs the message AND the signer set verified against the commitment (M0 §5.2).
  if (r.status || !facts || facts.kind === undefined || !facts.signers) {
    return {
      deadLetter: {
        ...base,
        status: r.status ?? (facts?.kind === undefined ? "INCONCLUSIVE" : "SIGNERS_UNVERIFIED"),
        reasons: [r.reason, ...(facts?.incomplete ?? [])].filter(Boolean),
        verdict: evaluate(rs, cfg.roles, { ...base, kind: undefined }),
        spEvents,
      },
    };
  }
  const rec = {
    ...base,
    kind: KIND_NAME[facts.kind],
    proposalId: facts.proposalId.toString(),
    messageHash: facts.messageHash,
    messageInputs: facts.messageInputs,
    fields: facts.fields,
    signers: facts.signers,
    anchor: facts.anchor,
    blockHash: facts.blockHash,
    caller: facts.caller,
    callRoute: facts.route,
    spEvents,
  };
  rec.verdict = evaluate(rs, cfg.roles, rec);
  if (wantsPrice(rs, cfg.roles, rec)) {
    rec.price = await pricePair(chain, cfg, rec.blockNumber);
    // A failed price read is transient: retry rather than store the gap forever (#400 Low). The
    // authenticated record rides along, so exhaustion still yields it, marked priceUnavailable.
    if (rec.price.error)
      return {
        deadLetter: {
          ...base,
          status: "PRICE_UNAVAILABLE",
          reasons: ["price read failed"],
          verdict: evaluate(rs, cfg.roles, { ...base, kind: undefined }),
          spEvents,
          pendingRecord: { ...rec, price: undefined },
        },
      };
  }
  return { record: rec };
}

function note(summary, res, rec) {
  if (res === "new") summary.newRecords++;
  if (res === "upgraded") summary.upgraded++;
  if (rec.verdict.flagged && (res === "new" || res === "upgraded")) summary.flagged.push(rec);
}

/** cachedPrice before and after `block`; { error } if either read failed. */
async function pricePair(chain, cfg, block) {
  const before = await readPrice(chain, cfg.roles.superPaymaster, block - 1);
  const after = await readPrice(chain, cfg.roles.superPaymaster, block);
  return before.error || after.error ? { error: true, before, after } : { before, after };
}

const SIGNERS_COMMITTED = () => aggIface.getEvent("SignersCommitted").topicHash;
const spTopics = () => SP_WATCHED_EVENTS.map(n => spIface.getEvent(n).topicHash);
const lcEq = (a, b) => String(a).toLowerCase() === String(b).toLowerCase();
/** A 4-byte selector, or null (calldata "0x" or shorter than a selector proves no function). */
const selectorOf = data =>
  typeof data === "string" && /^0x[0-9a-fA-F]{8}/.test(data)
    ? data.slice(0, 10).toLowerCase()
    : null;

/** Split a tx's logs into watched aggregator / SuperPaymaster logs. */
function splitLogs(logs, cfg, block) {
  const t = { block, agg: [], sp: [] };
  const spT = new Set(spTopics());
  for (const l of logs) {
    if (lcEq(l.address, cfg.aggregator) && l.topics?.[0] === SIGNERS_COMMITTED()) t.agg.push(l);
    else if (lcEq(l.address, cfg.roles.superPaymaster) && spT.has(l.topics?.[0])) t.sp.push(l);
  }
  return t;
}

/**
 * The records of one transaction: one per SignersCommitted (BLS route) and one per SuperPaymaster
 * event that is not proven to be a BLS action's effect. Such an event is classified by the SP call
 * that emitted it (#400 M1): its selector and msg.sender, from the tx itself when the tx calls SP
 * directly, else from the callTracer frame aligned with the receipt. A permissionless selector
 * (ruleset publicRoute) gives the public route; any other selector the owner route. An event a
 * permissionless function can also emit, whose call cannot be determined, is never guessed: the tx
 * becomes a dead letter and is retried (route "tx").
 */
async function processTx(chain, cfg, rs, ctx, store, summary, txHash, t, snapshot) {
  t.sp.sort((a, b) => logPos(a) - logPos(b));
  const SP = cfg.roles.superPaymaster;
  let tx;
  try {
    tx = await chain.getTransaction(txHash);
  } catch {
    tx = undefined;
  }
  const direct = tx && tx.to && lcEq(tx.to, SP);
  // SP events of a BLS tx count as an action's effects only when the trace, aligned log by log
  // with the receipt, places them inside THAT action's aggregator call. Everything else is a
  // record of its own, never swallowed and never shared between actions.
  let attr = { aligned: false, owner: new Map(), spCall: new Map(), why: "not traced" };
  const amb = ambiguousEvents(rs);
  const decoded = t.sp.map(l => ({ l, d: decodeSp(l) })).filter(x => x.d);
  // The emitting call decides an ambiguous event's route (#400 M1). A direct tx's calldata names
  // only the ROOT call; a nested SP call inside it would emit under another selector. So the trace
  // is asked for whenever an ambiguous event is present, direct or not (Codex #400-fix H1).
  const needFrame = decoded.some(x => amb.has(x.d.event));
  if ((t.agg.length && t.sp.length) || needFrame) {
    const { trace, logs } = await traceAndReceipt(chain, txHash);
    attr = logs
      ? attributeLogs(trace, logs, cfg.aggregator, SP)
      : { aligned: false, owner: new Map(), spCall: new Map(), why: "receipt unavailable" };
  }
  const commitCall = new Map(
    t.agg.map(l => [logPos(l), attr.aligned ? attr.owner.get(logPos(l)) : undefined])
  );
  const callsWithCommit = new Set(
    [...commitCall.values()].filter(v => v !== undefined && v !== null)
  );
  const effectsOf = new Map(); // aggCall -> [sp event]
  const independent = [];
  for (const { l, d } of decoded) {
    const ev = { ...d, logIndex: logPos(l) };
    const call = attr.aligned ? attr.owner.get(logPos(l)) : undefined;
    if (call !== undefined && call !== null && callsWithCommit.has(call)) {
      effectsOf.set(call, [...(effectsOf.get(call) ?? []), ev]);
    } else independent.push(ev);
  }
  for (const l of t.agg) {
    if (store.hasBlsRecord(BigInt(l.topics[1]))) continue; // completed before (tx retry, M5)
    const call = commitCall.get(logPos(l));
    const out = await blsRecord(chain, cfg, rs, ctx, l, effectsOf.get(call) ?? [], snapshot);
    if (out.record) note(summary, store.putRecord(out.record), out.record);
    else {
      store.putDeadLetter(out.deadLetter);
      summary.deadLetters++;
    }
  }
  const txDl = `tx-${String(txHash).toLowerCase()}`;
  if (!independent.length) {
    store.resolveDeadLetter(txDl); // all SP events proved to be BLS effects (Codex #400-fix M5)
    return { done: true };
  }

  const fail = (reason, pendingRecords) => {
    store.putDeadLetter({
      route: "tx",
      txHash,
      blockNumber: t.block,
      status: "ERROR",
      reasons: [reason],
      events: independent,
      // Records already classified, missing only their price (Codex #400-fix M3): exhaustion
      // keeps their route, caller and verdict, marked price.unavailable.
      ...(pendingRecords ? { pendingRecords } : {}),
      ruleset: ctx.ruleset,
      seenAt: ctx.now,
    });
    summary.deadLetters++;
    return { done: false };
  };
  if (tx === undefined || tx === null) return fail("transaction unavailable");
  // Root-call attribution without a trace is accepted only when it is consistent: the root
  // selector is a permissionless function and EVERY SP event of the tx is one it can emit, so no
  // nested call can be hiding behind it (Codex #400-fix H1). A privileged root is the owner route
  // whoever it calls. Otherwise only the aligned trace frame attributes an ambiguous event.
  const rootSel = direct ? selectorOf(tx.data) : null;
  const rootPub = rootSel ? publicFunction(rs, rootSel) : null;
  const rootConsistent =
    direct && rootSel && (!rootPub || decoded.every(x => rootPub[1].events.includes(x.d.event)));
  const directFrame = rootConsistent ? { from: tx.from, selector: rootSel } : null;
  const traced = e => (attr.aligned ? (attr.spCall.get(e.logIndex) ?? null) : null);
  const frameOf = e => traced(e) ?? directFrame;
  // Events emitted by the same SP call, for verdicts that depend on what else the call did.
  const byFrame = new Map();
  for (const e of independent) {
    const f = frameOf(e);
    if (f) byFrame.set(f, [...(byFrame.get(f) ?? []), e.event]);
  }
  const recs = [];
  let priceFailed = false;
  for (const e of independent) {
    const f = frameOf(e);
    if (amb.has(e.event) && !selectorOf(f?.selector ?? ""))
      return fail(
        `caller of ${e.event} undeterminable (${direct ? "no selector" : (attr.why ?? "trace unaligned")})`
      );
    const pub = f ? publicFunction(rs, f.selector) : null;
    const rec = {
      route: pub ? "public" : "owner",
      label: pub ? rs.publicRoute.label : rs.ownerRoute.label,
      event: e.event,
      args: e.args,
      txHash,
      logIndex: e.logIndex,
      blockNumber: t.block,
      from: tx.from ? ethers.getAddress(tx.from) : null,
      to: tx.to ? ethers.getAddress(tx.to) : null,
      caller: f?.from ? ethers.getAddress(f.from) : null,
      selector: f?.selector ?? null,
      callerSource: traced(e) ? "trace" : f ? "tx" : "unknown",
      ...(pub ? { function: pub[0], callEvents: byFrame.get(f) ?? [e.event] } : {}),
      ruleset: ctx.ruleset,
      seenAt: ctx.now,
    };
    if (t.agg.length) {
      // Same tx as a BLS action, not proven to be its effect: keep it, and say what is unknown.
      rec.routeUncertain = attr.aligned
        ? "same tx as a BLS action; the trace places it outside that action's aggregator call"
        : `same tx as a BLS action; not attributable (${attr.why}), so whether it is that action's effect is unproven`;
    }
    rec.verdict = evaluate(rs, cfg.roles, rec);
    if (wantsPrice(rs, cfg.roles, rec)) {
      rec.price = await pricePair(chain, cfg, t.block);
      if (rec.price.error) {
        priceFailed = true;
        rec.price = undefined;
      }
    }
    recs.push(rec);
  }
  if (priceFailed) return fail("price read failed", recs);
  for (const rec of recs) note(summary, store.putRecord(rec), rec);
  store.resolveDeadLetter(txDl);
  return { done: true };
}

/** A dead letter that has used every retry becomes a record, so nothing BLS-executed or watched
 * is left without one (M0 §5.2, #400 Low): an unauthenticated BLS action is UNRECOVERED; an SP
 * event whose call could not be determined is "unattributed" (nobody accused). */
function exhaust(store, rs, cfg, ctx, summary, dl) {
  if (dl.route === "tx" && dl.pendingRecords) {
    for (const r of dl.pendingRecords) {
      const rec = { ...r, price: { unavailable: true }, exhaustedAfter: dl.attempts };
      note(summary, store.putRecord(rec), rec);
    }
  } else if (dl.route === "tx") {
    const amb = ambiguousEvents(rs);
    for (const e of dl.events ?? []) {
      const rec = {
        route: amb.has(e.event) ? "unattributed" : "owner",
        label: amb.has(e.event) ? "caller not determined" : rs.ownerRoute.label,
        event: e.event,
        args: e.args,
        txHash: dl.txHash,
        logIndex: e.logIndex,
        blockNumber: dl.blockNumber,
        caller: null,
        callerSource: "unknown",
        exhaustedAfter: dl.attempts,
        lastReasons: dl.reasons,
        ruleset: dl.ruleset ?? ctx.ruleset,
        seenAt: ctx.now,
      };
      rec.verdict = evaluate(rs, cfg.roles, rec);
      note(summary, store.putRecord(rec), rec);
    }
  } else if (dl.pendingRecord) {
    const rec = { ...dl.pendingRecord, price: { unavailable: true }, exhaustedAfter: dl.attempts };
    note(summary, store.putRecord(rec), rec);
  } else {
    const { status, reasons, attempts, firstSeen, id, verdict, ...base } = dl;
    void verdict;
    void id;
    const rec = {
      ...base,
      kind: undefined,
      unrecoveredStatus: status,
      lastReasons: reasons,
      firstSeen,
      exhaustedAfter: attempts,
      seenAt: ctx.now,
    };
    rec.verdict = evaluate(rs, cfg.roles, rec);
    note(summary, store.putRecord(rec), rec);
  }
  store.retireDeadLetter(dl.id);
  summary.exhausted++;
}

/**
 * Cross-check getLogs against each scanned block's logsBloom (DSR, #400). A block whose bloom says
 * a watched log may be present, but for which no such log came back, is re-queried by block hash
 * (EIP-234): a node without that block errors instead of answering empty, so a lagging node behind
 * a load balancer surfaces as a failed read (the tick throws, the cursor stays, it is retried).
 * Logs that come back are merged in; an empty answer by hash confirms a bloom false positive.
 */
async function bloomCheck(chain, cfg, from, to, aggLogs, spLogs, summary) {
  const have = (logs, n) => logs.some(l => Number(l.blockNumber) === n);
  const extraAgg = [];
  const extraSp = [];
  for (let a = from; a <= to; a += 100) {
    const nums = [];
    for (let n = a; n <= Math.min(to, a + 99); n++) nums.push(n);
    const hdrs = await Promise.all(nums.map(n => header(chain, n)));
    for (const h of hdrs) {
      const n = h.number;
      for (const [addr, topics, logs, extra] of [
        [cfg.aggregator, [SIGNERS_COMMITTED()], aggLogs, extraAgg],
        [cfg.roles.superPaymaster, spTopics(), spLogs, extraSp],
      ]) {
        // Per (address, topic): one returned topic must not mask another missing one in the same
        // block (Codex #400-fix M6). A missing SECOND log of a topic already present cannot be
        // seen in a bloom at all; that limit is documented (M0 §5.2b).
        const missing = [];
        let unchecked = false;
        for (const topic of topics) {
          const may = mayHaveLog(h.logsBloom, addr, [topic]);
          if (may === null) {
            unchecked = true;
            break;
          }
          if (may && !logs.some(l => Number(l.blockNumber) === n && l.topics?.[0] === topic))
            missing.push(topic);
        }
        if (unchecked) {
          summary.bloomUnchecked++;
          continue;
        }
        if (!missing.length) continue;
        let got;
        try {
          got = await chain.getLogs({ address: addr, topics: [topics], blockHash: h.hash });
        } catch {
          throw new Error(
            `block ${n}: logsBloom shows a watched log that getLogs did not return, and the by-hash re-read failed; retrying`
          );
        }
        const fresh = got.filter(
          g => !logs.some(l => l.transactionHash === g.transactionHash && logPos(l) === logPos(g))
        );
        if (fresh.length) {
          extra.push(...fresh);
          summary.bloomRecovered++;
        }
        if (missing.some(topic => !got.some(g => g.topics?.[0] === topic)))
          summary.bloomFalsePositives++;
      }
    }
  }
  return { extraAgg, extraSp };
}

/**
 * Scan (cursor, finalized] (at most cfg.maxBlocksPerTick blocks) and store what it finds.
 * Throws only when the scan itself cannot proceed (header or log fetch): the caller records it, the
 * cursor has not moved, nothing is skipped. A single action that fails is a dead letter instead.
 */
export async function tick(chain, cfg, store, rs, ctx) {
  const fin = await header(chain, "finalized");
  const cursor = store.getCursor();
  if (cursor) {
    // Finalized blocks cannot reorg; if the cursor's block changed anyway, stop and say so.
    const now = await header(chain, cursor.block);
    if (now.hash.toLowerCase() !== String(cursor.hash).toLowerCase()) {
      throw new Error(
        `cursor block ${cursor.block} hash changed (${cursor.hash} -> ${now.hash}): finality violated, not advancing`
      );
    }
  }
  const from = cursor ? cursor.block + 1 : cfg.startBlock;
  const to = Math.min(fin.number, from + cfg.maxBlocksPerTick - 1);
  const summary = {
    from,
    to,
    finalized: fin.number,
    newRecords: 0,
    deadLetters: 0,
    upgraded: 0,
    exhausted: 0,
    bloomUnchecked: 0,
    bloomRecovered: 0,
    bloomFalsePositives: 0,
    flagged: [],
  };

  // Retry dead letters first (a trace, a slot read or an RPC that failed may now answer). One that
  // has used every attempt becomes a record (exhaust), never silently dropped.
  for (const dl of store.listDeadLetters()) {
    if (dl.attempts >= MAX_DEADLETTER_ATTEMPTS) {
      exhaust(store, rs, cfg, ctx, summary, dl);
      continue;
    }
    if (dl.route === "tx") {
      let rc = null;
      try {
        rc = await chain.getTransactionReceipt(dl.txHash);
      } catch {
        rc = null;
      }
      if (!rc?.logs) {
        store.putDeadLetter({ ...dl, reasons: ["receipt unavailable"] });
        continue;
      }
      await processTx(
        chain,
        cfg,
        rs,
        ctx,
        store,
        summary,
        dl.txHash,
        splitLogs(rc.logs, cfg, dl.blockNumber),
        fin.number
      );
      continue;
    }
    if (dl.pendingRecord) {
      // Authenticated already; only the price is missing. Retry just that, and keep the verified
      // evidence whatever else fails (Codex #400-fix M4).
      const price = await pricePair(chain, cfg, dl.pendingRecord.blockNumber);
      if (price.error) store.putDeadLetter({ ...dl, reasons: ["price read failed"] });
      else {
        const rec = { ...dl.pendingRecord, price };
        note(summary, store.putRecord(rec), rec);
        store.resolveDeadLetter(dl.id);
      }
      continue;
    }
    const log = {
      topics: [SIGNERS_COMMITTED(), ethers.toBeHex(BigInt(dl.key), 32)],
      data: ethers.AbiCoder.defaultAbiCoder().encode(["uint256"], [BigInt(dl.signerMask)]),
      transactionHash: dl.txHash,
      blockNumber: dl.blockNumber,
      index: dl.logIndex,
    };
    const out = await blsRecord(chain, cfg, rs, ctx, log, dl.spEvents ?? [], fin.number);
    if (out.record) note(summary, store.putRecord(out.record), out.record);
    else store.putDeadLetter(out.deadLetter);
  }

  if (from > to) return summary;

  const aggLogs = await pagedLogs(chain, cfg.aggregator, [SIGNERS_COMMITTED()], from, to, cfg.page);
  const spLogs = await pagedLogs(chain, cfg.roles.superPaymaster, [spTopics()], from, to, cfg.page);
  const { extraAgg, extraSp } = await bloomCheck(chain, cfg, from, to, aggLogs, spLogs, summary);

  const byTx = new Map();
  for (const l of [...aggLogs, ...extraAgg, ...spLogs, ...extraSp]) {
    const t = byTx.get(l.transactionHash) ?? { block: Number(l.blockNumber), agg: [], sp: [] };
    const list = lcEq(l.address, cfg.aggregator) ? t.agg : t.sp;
    if (!list.some(x => logPos(x) === logPos(l))) list.push(l);
    byTx.set(l.transactionHash, t);
  }
  const ordered = [...byTx.entries()].sort((a, b) => a[1].block - b[1].block);
  for (const [txHash, t] of ordered)
    await processTx(chain, cfg, rs, ctx, store, summary, txHash, t, fin.number);

  const toHdr = await header(chain, to);
  store.setCursor({ block: to, hash: toHdr.hash });
  return summary;
}
