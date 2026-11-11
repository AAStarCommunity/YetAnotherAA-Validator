// One watcher tick (M0 §5.2): scan finalized blocks for BLS-executed actions (SignersCommitted on
// the pinned aggregator) and for owner/guardian-route actions on the SuperPaymaster proxy, build a
// record for each, apply the pinned ruleset, and store it. No sending: disclosure sinks are W2.
import { createHash } from "node:crypto";
import { ethers } from "ethers";
import {
  KIND_NAME,
  aggIface,
  rebuildFromAction,
} from "../../../scripts/disclosure/recheck-lib.mjs";
import { spIface, SP_WATCHED_EVENTS } from "./sp-abi.mjs";
import { evaluate, wantsPrice, publicFunction, ambiguousEvents } from "./rules.mjs";
import { attributeLogs, receiptPos, validLog, parsePosition, traceDepthOk } from "./attribute.mjs";
import { mayHaveLog } from "./bloom.mjs";
import { Store } from "./store.mjs";
import { SafeError, safeText, guarded } from "./safe-error.mjs";

// Chain data in our own error text only when it is a well-formed hash (RPC answers are untrusted).
const hx = v => (/^0x[0-9a-fA-F]{64}$/.test(String(v)) ? String(v) : "<malformed>");

export const MAX_DEADLETTER_ATTEMPTS = 20;

async function header(chain, tag) {
  // Each RPC stage is named (Codex W2b R4): status says WHICH read failed and its allowlisted code.
  const b = await guarded("block header read", () =>
    chain.send("eth_getBlockByNumber", [
      typeof tag === "number" ? ethers.toQuantity(tag) : tag,
      false,
    ])
  );
  if (!b || !b.hash) throw new SafeError(`block ${tag} unavailable`);
  // A header is accepted only with a 32-byte hash and a parseable height: a malformed one fails the
  // tick (the cursor is never set from it) and is never interpolated (Codex follow-up R10).
  const number = parsePosition(b.number);
  if (typeof b.hash !== "string" || !/^0x[0-9a-fA-F]{64}$/.test(b.hash) || number === null)
    throw new SafeError("malformed block header");
  if (typeof tag === "number" && number !== tag)
    throw new SafeError("block header for another height");
  return { number, hash: b.hash, logsBloom: b.logsBloom };
}

/**
 * eth_getLogs through raw `send`, never the provider's getLogs (#403 review M-1): ethers formats
 * every log of the answer and throws on one it cannot format (a null entry, a bad index, a short
 * address, a missing hash), which would stop the whole tick before the per-tx isolation could
 * see the item. The raw answer reaches intake() and the isolation instead. Only a non-array
 * answer is an error here (the tick fails and is retried).
 */
export async function rawGetLogs(chain, { address, topics, fromBlock, toBlock, blockHash }) {
  const filter =
    blockHash !== undefined
      ? { address, topics, blockHash }
      : {
          address,
          topics,
          fromBlock: ethers.toQuantity(fromBlock),
          toBlock: ethers.toQuantity(toBlock),
        };
  const r = await chain.send("eth_getLogs", [filter]);
  // our own wording, so it survives sanitising (W2b SafeError rule)
  if (!Array.isArray(r)) throw new SafeError("eth_getLogs answer is not an array");
  return r;
}

/** getLogs over [from, to], paged; a failing page halves down to one block before giving up. */
export async function pagedLogs(chain, address, topics, from, to, page = 5_000) {
  const out = [];
  let a = from;
  let size = page;
  while (a <= to) {
    const b = Math.min(to, a + size - 1);
    try {
      // appended one by one: spreading a huge answer into push() overflows the call stack before
      // any entry reaches the isolation (#403 follow-up, Codex R1)
      for (const l of await rawGetLogs(chain, { address, topics, fromBlock: a, toBlock: b }))
        out.push(l);
      a = b + 1;
      size = page;
    } catch (e) {
      if (size === 1) throw e;
      size = Math.max(1, Math.floor(size / 2));
    }
  }
  return out;
}

export async function readPrice(chain, sp, blockTag) {
  try {
    const ret = await chain.call({
      to: sp,
      data: spIface.encodeFunctionData("cachedPrice", []),
      blockTag,
    });
    const r = spIface.decodeFunctionResult("cachedPrice", ret);
    return { price: r.price.toString(), updatedAt: r.updatedAt.toString(), block: blockTag };
  } catch (e) {
    return { error: safeText("cachedPrice read", e), block: blockTag };
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
  const n = receiptPos(l); // strict, and `index` / `logIndex` must agree when both are present
  if (n === null)
    throw new SafeError(`log without a valid position in tx ${hx(l.transactionHash)}`);
  return n;
}

const TRACE_OPTS = { tracer: "callTracer", tracerConfig: { withLog: true } };

/** Whether a debug_traceTransaction error says this node lacks the method or the tracer option
 * (not a transient failure). JSON-RPC -32601 is "method not found". */
export function traceUnsupported(e) {
  const codes = [e?.error?.code, e?.info?.error?.code, e?.code];
  if (codes.includes(-32601)) return true;
  const msg = [e?.error?.message, e?.info?.error?.message, e?.shortMessage, e?.message]
    .filter(x => typeof x === "string")
    .join(" ");
  return /(method|namespace)\b.{0,60}\b(not found|does not exist|not available|not supported|unsupported|disabled|not allowed)|unknown tracer|tracer\b.{0,30}\bnot (found|supported)/i.test(
    msg
  );
}

/** The identity sameLog compares, as one string (null for an invalid position): two logs are
 * sameLog-equal exactly when their keys are equal. */
export function sameLogKey(l) {
  const p = receiptPos(l);
  if (p === null) return null;
  const h = x => str(x).toLowerCase();
  const t = Array.isArray(l.topics) ? l.topics : (l.topics ?? []);
  const topics = [];
  for (let i = 0; i < t.length; i++) topics.push(h(t[i]));
  return JSON.stringify([p, h(l.address), topics, h(l.data)]);
}

/** The same log: position, address, every topic and the data (case-insensitive hex). */
export function sameLog(a, b) {
  const h = x => str(x).toLowerCase();
  const ta = a.topics ?? [];
  const tb = b.topics ?? [];
  const pa = receiptPos(a);
  // An invalid position is a mismatch, never an exception (Codex #400-fix R12).
  return (
    pa !== null &&
    pa === receiptPos(b) &&
    h(a.address) === h(b.address) &&
    ta.length === tb.length &&
    ta.every((t, i) => h(t) === h(tb[i])) &&
    h(a.data) === h(b.data)
  );
}

/** Whether any frame of a callTracer trace carries a log (withLog honoured). */
function traceHasLogs(node) {
  if (!node || typeof node !== "object") return false;
  if (Array.isArray(node.logs) && node.logs.length) return true;
  return (Array.isArray(node.calls) ? node.calls : []).some(traceHasLogs);
}

/**
 * Positive verification of the RPC's trace capability (DSR, #400; Codex #400-fix R4): ambiguous SP
 * events are attributed only by the trace, so the watcher must KNOW the node returns callTracer
 * traces whose logs (withLog) align with the receipt. A lookup miss proves nothing (a node resolves
 * the tx before it builds the tracer), so a real transaction with logs is traced, from the newest
 * `blocks` finalized blocks, at most `maxTx` of them. Returns { state, reason?, txHash?, block? }:
 *   "verified"    a trace aligned log by log with its receipt;
 *   "unsupported" the method or tracer is missing, or a trace of a tx with logs carries none
 *                 (withLog not honoured);
 *   "unverified"  nothing conclusive (no sample, transient failures, misaligned traces).
 */
export async function verifyTrace(
  chain,
  cfg,
  fromBlock,
  { blocks = 5, maxTx = 8, sampleTx = null, perBlock = 40 } = {}
) {
  // Every receipt lookup counts, with or without logs (follow-up #2 R11): at most `perBlock`
  // transactions of each sampled block are looked at, so an answer listing 20 000 transactions
  // costs a bounded number of requests, not one each.
  if (typeof chain.send !== "function") return { state: "unsupported", reason: "no send()" };
  let tried = 0;
  let failed = 0;
  let why = "no transaction with logs in the sampled blocks";
  // One candidate: null = not a usable sample (no receipt logs), else a verdict or "keep looking".
  const check = async (hash, blockOf = null) => {
    let rc = null;
    try {
      rc = await chain.getTransactionReceipt(hash);
    } catch {
      rc = null;
    }
    if (!rc?.logs?.length) return null;
    tried++;
    let trace;
    try {
      trace = await chain.send("debug_traceTransaction", [hash, TRACE_OPTS]);
    } catch (e) {
      if (traceUnsupported(e)) return { state: "unsupported", reason: "method or tracer missing" };
      failed++;
      why = "trace call failed";
      return { state: "next" };
    }
    if (!trace || typeof trace !== "object" || !traceDepthOk(trace)) {
      failed++;
      why = "malformed trace response";
      return { state: "next" };
    }
    let tx = null;
    try {
      tx = await chain.getTransaction(hash);
    } catch {
      tx = null;
    }
    let at = blockOf ?? null;
    if (!at && rc?.blockNumber !== undefined && rc?.blockNumber !== null) {
      // the stored sample: its receipt's block must still be the canonical one
      try {
        const h = await header(chain, Number(rc.blockNumber));
        at = { blockNumber: Number(rc.blockNumber), blockHash: h.hash };
      } catch {
        at = null;
      }
    }
    const env = !tx
      ? "transaction unavailable"
      : !at
        ? "sample block unavailable"
        : envelopeProblem(hash, tx, rc, trace, at);
    if (env) {
      why = `sample not usable (${env})`;
      return { state: "next" };
    }
    if (!traceHasLogs(trace))
      return {
        state: "unsupported",
        reason: "trace of a tx with logs carries none (withLog not honoured)",
        txHash: hash,
      };
    const a = attributeLogs(trace, rc.logs, cfg.aggregator, cfg.roles.superPaymaster);
    if (a.aligned) return { state: "verified", txHash: hash, block: Number(rc.blockNumber) };
    why = `trace does not align with its receipt (${a.why})`;
    return { state: "next" };
  };
  const done = r => r && r.state !== "next";
  // The stored sample first (Codex #400-fix R5): a quiet chain can still re-prove the capability.
  if (typeof sampleTx === "string" && /^0x[0-9a-fA-F]{64}$/.test(sampleTx)) {
    const r = await check(sampleTx);
    if (done(r)) return { ...r, tried, failed };
  }
  for (let b = fromBlock; b > fromBlock - blocks && b >= 0 && tried < maxTx; b--) {
    let blk = null;
    try {
      blk = await chain.send("eth_getBlockByNumber", [ethers.toQuantity(b), false]);
    } catch {
      why = "sample block unavailable";
      continue;
    }
    const list = Array.isArray(blk?.transactions) ? blk.transactions : [];
    let looked = 0;
    for (const t of list) {
      if (tried >= maxTx || looked >= perBlock) break;
      looked++;
      const hash = typeof t === "string" ? t : t?.hash;
      if (typeof hash !== "string" || hash === sampleTx) continue;
      const r = await check(hash, { blockNumber: b, blockHash: blk.hash });
      if (done(r)) return { ...r, tried, failed };
    }
  }
  return { state: "unverified", reason: why, tried, failed };
}

/** Full receipt + callTracer (withLog) trace of a tx, for attribution; null parts when unavailable.
 * `stats` counts outcomes for status: ok, unsupported, failed, noLogs (a trace without any log
 * while the receipt has some: withLog ignored, so nothing can be aligned). */
async function traceAndReceipt(chain, txHash, stats = {}, expectLogs = false) {
  let trace = null;
  let rc = null;
  try {
    rc = await chain.getTransactionReceipt(txHash);
  } catch {
    rc = null;
  }
  if (typeof chain.send === "function") {
    try {
      trace = await chain.send("debug_traceTransaction", [txHash, TRACE_OPTS]);
      // getLogs already saw watched logs in this tx: a trace without any log proves withLog is not
      // honoured, whatever the receipt says (Codex #400-fix R6).
      // A null or non-object answer is a malformed response, inconclusive (Codex #400-fix R11).
      // deeper than the EVM call-depth limit: not a real trace, refused before any walk (R8)
      if (!trace || typeof trace !== "object" || !traceDepthOk(trace)) {
        trace = null;
        stats.failed = (stats.failed ?? 0) + 1;
      } else if ((expectLogs || rc?.logs?.length) && !traceHasLogs(trace))
        stats.noLogs = (stats.noLogs ?? 0) + 1;
      else stats.ok = (stats.ok ?? 0) + 1;
    } catch (e) {
      trace = null;
      if (traceUnsupported(e)) stats.unsupported = (stats.unsupported ?? 0) + 1;
      else stats.failed = (stats.failed ?? 0) + 1;
    }
  } else stats.unsupported = (stats.unsupported ?? 0) + 1;
  return { trace, logs: rc?.logs ?? null, rc };
}

// Success must be explicit: a missing or unrecognized status is not success (Codex #400-fix R12).
const okStatus = s => s === 1 || s === "0x1" || s === 1n || s === "1";

/**
 * Cross-checks of a receipt and a trace against the tx they claim to describe (an honest but
 * inconsistent RPC: lagging backends, mixed responses; Codex #400-fix R11). null when consistent,
 * else the reason. The trace root must be the tx itself: its sender, destination (CREATE when the
 * tx has none) and full input.
 */
export function envelopeProblem(txHash, tx, rc, trace, at = {}) {
  // Inclusion: the receipt, its logs and the tx must all name the same block, and that block must
  // be the one the watched evidence came from (a stale backend can answer from an orphaned earlier
  // inclusion with identical payloads; Codex #400-fix R13).
  const present = x => x !== undefined && x !== null;
  const num = x => (present(x) ? Number(x) : undefined);
  const sources = [["receipt", rc], ["tx", tx], ...(rc?.logs ?? []).map(l => ["receipt log", l])];
  const want = {
    number: present(at.blockNumber) ? Number(at.blockNumber) : num(rc?.blockNumber),
  };
  if (present(at.blockHash) && rc && !present(rc.blockHash))
    return "receipt does not name its block";
  let firstHash = present(at.blockHash) ? str(at.blockHash) : null;
  for (const [what, o] of sources) {
    if (!o) continue;
    if (present(o.blockNumber) && present(want.number) && num(o.blockNumber) !== want.number)
      return `${what} is from another block`;
    if (present(o.blockHash)) {
      if (firstHash === null) firstHash = str(o.blockHash);
      else if (!lcEq(o.blockHash, firstHash)) return `${what} is from another block`;
    }
  }
  if (rc) {
    // ethers v6 names the receipt's tx `hash`; raw JSON-RPC names it `transactionHash`.
    const ids = [rc.transactionHash, rc.hash].filter(x => x !== undefined && x !== null);
    if (!ids.length) return "receipt does not name its tx";
    if (!ids.every(x => lcEq(x, txHash))) return "receipt names another tx";
    if (!okStatus(rc.status)) return "receipt is not an explicit success";
    for (const l of rc.logs ?? []) {
      if (l?.transactionHash && !lcEq(l.transactionHash, txHash))
        return "receipt log of another tx";
      if (l?.removed === true) return "receipt log marked removed";
    }
  }
  if (trace && tx) {
    if (!tx.from || !lcEq(trace.from, tx.from)) return "trace root sender differs from the tx";
    if (tx.to ? !lcEq(trace.to, tx.to) : !/^CREATE2?$/i.test(str(trace.type)))
      return "trace root destination differs from the tx";
    if (str(trace.input).toLowerCase() !== str(tx.data ?? tx.input).toLowerCase())
      return "trace root input differs from the tx";
  }
  return null;
}

/**
 * The chain as BLS reconstruction sees it, with every tx and receipt response checked against the
 * request (Codex follow-up R6): reconstruction fetches its own copies, and a mixed backend must
 * not hand it another tx's sender. A response that names another tx, or no tx, or (for the
 * action's own block) another block, throws: the action becomes a retried dead letter.
 */
function identityGuard(chain, block) {
  const same = (got, want) => typeof got === "string" && lcEq(got, want);
  const inBlock = o =>
    o?.blockNumber === undefined ||
    o?.blockNumber === null ||
    parsePosition(o.blockNumber) === block;
  return new Proxy(chain, {
    get(target, prop) {
      if (prop === "getTransaction")
        return async h => {
          const tx = await target.getTransaction(h);
          if (tx && (!same(tx.hash, h) || !inBlock(tx)))
            throw new SafeError("transaction response names another tx or block");
          return tx;
        };
      if (prop === "getTransactionReceipt")
        return async h => {
          const rc = await target.getTransactionReceipt(h);
          if (rc) {
            const ids = [rc.transactionHash, rc.hash].filter(x => x !== undefined && x !== null);
            if (!ids.length || !ids.every(x => same(x, h)) || !inBlock(rc))
              throw new SafeError("receipt names another tx or block");
          }
          return rc;
        };
      const v = target[prop];
      return typeof v === "function" ? v.bind(target) : v;
    },
  });
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
  // The commitment getLogs reported must be in the receipt reconstruction will read, identical
  // (position, emitter, key, mask): a backend answering the two differently must not let one
  // mask be recorded with the signers authenticated for another (Codex follow-up R7).
  const guarded = identityGuard(chain, Number(log.blockNumber));
  let commitInReceipt = false;
  try {
    const rc = await guarded.getTransactionReceipt(log.transactionHash);
    commitInReceipt = !!rc?.logs?.some(x => sameLog(x, log));
  } catch {
    commitInReceipt = false;
  }
  if (!commitInReceipt)
    return {
      deadLetter: {
        ...base,
        status: "ERROR",
        reasons: ["commitment log not found unchanged in the tx receipt"],
        verdict: evaluate(rs, cfg.roles, { ...base, kind: undefined }),
        spEvents,
      },
    };
  let r;
  try {
    r = await rebuildFromAction(
      guarded,
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
        reasons: [`rebuild failed: ${safeText("rebuild", e)}`],
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
// RPC values are compared WITHOUT coercion (Codex follow-up R9): String() on an object whose
// toString is not callable throws, and that must never happen outside the per-tx isolation.
const str = x => (typeof x === "string" ? x : "");
const lcEq = (a, b) =>
  typeof a === "string" && typeof b === "string" && a.toLowerCase() === b.toLowerCase();
/** A 4-byte selector, or null (calldata "0x" or shorter than a selector proves no function). */
const selectorOf = data =>
  typeof data === "string" && /^0x[0-9a-fA-F]{8}/.test(data)
    ? data.slice(0, 10).toLowerCase()
    : null;

/** A watched log as stored evidence (plain JSON, full contents and position). */
function evidenceLog(l, source, range) {
  // Best effort: a malformed log is kept as evidence as far as it can be (an isolated tx keeps
  // what the RPC said: #400 review L1), never a reason to lose the dead letter.
  // The RAW position fields and `removed` are kept as the RPC gave them: normalising here would
  // turn contradictory evidence (index 0, logIndex 99) into valid evidence on retry (Codex
  // follow-up R1).
  // stored evidence that could not be kept as JSON is already final: kept as is, so a retry keeps
  // one identity for it (follow-up #2 R6)
  if (l?.raw === DEEP_PLACEHOLDER && typeof l.rawSha256 === "string") return { ...l };
  // present = an own property, whatever its value (null, false, 0, ""): the stored observation is
  // the received one, and validation stays separate from serialisation (follow-up #2 R11)
  const has = k => !!l && typeof l === "object" && Object.hasOwn(l, k);
  return {
    address: l?.address,
    topics: Array.isArray(l?.topics) ? [...l.topics] : l?.topics,
    data: l?.data,
    ...(has("index") ? { index: l.index } : {}),
    ...(has("logIndex") ? { logIndex: l.logIndex } : {}),
    ...(has("removed") ? { removed: l.removed } : {}),
    blockNumber: l?.blockNumber, // raw: an invalid height stays as the RPC gave it
    ...(has("blockHash") ? { blockHash: l.blockHash } : {}),
    transactionHash: l?.transactionHash,
    // which query returned it (aggregator or SuperPaymaster): a retry classifies by this, never by
    // re-filtering a possibly malformed log out of existence (Codex follow-up R2)
    ...(source ? { source } : {}),
    // the query range this observation came from (kept per observation: Codex follow-up R7)
    ...(Array.isArray(l?.range) ? { range: l.range } : range ? { range } : {}),
  };
}

/** Observations of one tx, merged: every distinct observation (content and query range) is kept,
 * so a later sighting never replaces an earlier one (Codex follow-up R7). */
function mergeEvidence(a, b) {
  // identity = raw contents, the query that returned it, and its range (Codex follow-up R8)
  // A deep observation and the placeholder it is stored as share one identity, the sha256 of its
  // full text, so a retry neither duplicates it nor collapses two distinct deep ones (R6).
  const key = e => {
    if (e?.raw === DEEP_PLACEHOLDER && typeof e.rawSha256 === "string")
      return `deep:${e.rawSha256}`;
    // stored as a placeholder (too deep for any real log): keyed as that placeholder will be
    if (deeperThan(e, MAX_EVIDENCE_DEPTH) || largerThan(e, MAX_EVIDENCE_BYTES))
      try {
        return `deep:${deepDigest(e)}`;
      } catch {
        // keyed below
      }
    const k = rawLogKey(e) + safeJson([e?.source ?? null, e?.range ?? null]) + str(e?.raw);
    if (!k.includes("<unserialisable")) return k;
    try {
      return `deep:${deepDigest(e)}`;
    } catch {
      return k;
    }
  };
  // each key computed once, a Set for membership: linear, whatever the flood (follow-up #2 R2)
  const out = [];
  const seen = new Set();
  for (const part of [a ?? [], b ?? []])
    for (const e of part) {
      const k = key(e);
      if (!seen.has(k)) {
        seen.add(k);
        out.push(e);
      }
    }
  return out;
}

/** Evidence of a tx: its aggregator and SP logs, each tagged with its source query. */
const evidenceOf = t => [
  ...t.agg.map(l => evidenceLog(l, "agg", t.range)),
  ...t.sp.map(l => evidenceLog(l, "sp", t.range)),
];

/** The tx shape of stored evidence: by source when recorded; legacy evidence is split by
 * address/topic, and any log that would fall out of that split marks the tx malformed. */
export function txOfEvidence(watched, cfg, block) {
  if (watched.every(w => w.source === "agg" || w.source === "sp"))
    return {
      block,
      agg: watched.filter(w => w.source === "agg"),
      sp: watched.filter(w => w.source === "sp"),
    };
  const t = splitLogs(watched, cfg, block);
  if (t.agg.length + t.sp.length !== watched.length) t.malformed = true;
  return t;
}

/** A safe reason for an exception thrown while processing one tx: our own wording and the error's
 * category, never a foreign message (RPC answers are untrusted text). */
function isolatedReason(e) {
  // our own wording (a SafeError never carries foreign text: lib/safe-error.mjs) is kept as is
  if (e instanceof SafeError) return `tx processing failed: ${e.message}`;
  const code = typeof e?.code === "string" && /^[A-Z_]{2,40}$/.test(e.code) ? e.code : null;
  const name = typeof e?.name === "string" && /^[A-Za-z]{2,40}$/.test(e.name) ? e.name : "Error";
  return `tx processing failed (${code ?? name})`;
}

/**
 * Process one tx in isolation (#400 review L1, DSR): any exception, for example a malformed RPC
 * answer, becomes that tx's dead letter with its watched evidence, so the retry cap applies and the
 * scan (and its cursor) moves on. At the cap the dead letter becomes an unattributed record.
 */
async function processTxIsolated(chain, cfg, rs, ctx, store, summary, txHash, t, snapshot, prev) {
  try {
    return await processTx(chain, cfg, rs, ctx, store, summary, txHash, t, snapshot);
  } catch (e) {
    summary.isolated = (summary.isolated ?? 0) + 1;
    summary.txIsolations = (summary.txIsolations ?? 0) + 1;
    // what this tx's dead letter already holds is merged with this observation, never replaced
    const okH = /^0x[0-9a-fA-F]{64}$/.test(str(txHash));
    const existing = prev ?? (okH ? store.getDeadLetter(`tx-${str(txHash).toLowerCase()}`) : null);
    let watched = [];
    try {
      watched = mergeEvidence(nativeEvidence(existing?.watched), evidenceOf(t));
    } catch {
      // never only the old evidence: this observation is kept too, unmerged if need be (R10)
      let incoming;
      try {
        incoming = evidenceOf(t);
      } catch {
        incoming = [{ raw: safeJson([t.agg, t.sp]), source: "unmerged" }];
      }
      watched = [...(nativeEvidence(existing?.watched) ?? []), ...incoming];
    }
    // An item without a usable tx hash gets a quarantine identity derived from its evidence: it
    // is retried and counted, never attributed to any tx (Codex follow-up R2).
    const okHash = /^0x[0-9a-fA-F]{64}$/.test(str(txHash));
    const qid = okHash ? null : ethers.keccak256(ethers.toUtf8Bytes(safeJson(watched)));
    store.putDeadLetter({
      ...(existing ?? {}),
      route: "tx",
      txHash: okHash ? txHash : qid,
      ...(okHash ? {} : { quarantine: true }),
      blockNumber: t.block,
      status: "ERROR",
      reasons: [isolatedReason(e)],
      ...(t.range ? { range: t.range } : {}),
      events: existing?.events ?? [],
      watched: typedEvidence(watched),
      ruleset: ctx.ruleset,
      seenAt: ctx.now,
    });
    summary.deadLetters++;
    return { done: false };
  }
}

/** Entries that cannot be handled per tx (not a log object, no valid tx hash, or past a cap): one
 * final quarantine record per answer, keyed by its contents. */
/** JSON text of a parsed JSON-RPC value without recursion, so nesting depth can never overflow the
 * stack (follow-up #2 R5): a 10 000-deep array is encoded in full, never replaced by a placeholder.
 * BigInt (not JSON, but a stub or a client may hand one over) is tagged as safeJson tags it. */
class JsonLit {
  constructor(s) {
    this.s = s;
  }
}
export function iterJson(root) {
  const out = [];
  const st = [root];
  while (st.length) {
    const x = st.pop();
    if (x instanceof JsonLit) out.push(x.s);
    else if (x === null || typeof x === "boolean") out.push(String(x));
    else if (typeof x === "number") out.push(Number.isFinite(x) ? String(x) : "null");
    else if (typeof x === "string") out.push(JSON.stringify(x));
    else if (typeof x === "bigint") out.push(`{"$bigint":${JSON.stringify(x.toString())}}`);
    else if (Array.isArray(x)) {
      out.push("[");
      st.push(new JsonLit("]"));
      for (let k = x.length - 1; k >= 0; k--) {
        st.push(x[k]);
        if (k > 0) st.push(new JsonLit(","));
      }
    } else if (typeof x === "object") {
      const keys = Object.keys(x);
      out.push("{");
      st.push(new JsonLit("}"));
      for (let k = keys.length - 1; k >= 0; k--) {
        st.push(x[keys[k]]);
        st.push(new JsonLit(`${JSON.stringify(keys[k])}:`));
        if (k > 0) st.push(new JsonLit(","));
      }
    } else out.push("null"); // undefined, function, symbol: what JSON would make of them
  }
  return out.join("");
}
const QUARANTINE_SAMPLE_CHARS = 2048;

function quarantineRaw(store, rs, ctx, summary, bad, source, from, to, why = "not a log") {
  // Bounded (#403 follow-up, Codex R1): all set-aside entries of one query answer become ONE
  // quarantine record, with the total, up to QUARANTINE_SAMPLES distinct raw values (each with its
  // count) and the sha256 of the whole raw payload, so the gap can be audited without storing it.
  // It is final at once (DSR log 2892c30f): it names no tx, so a retry could never read more; it is
  // unattributed and never an accusation (follow-up #2 R4).
  const counts = new Map();
  const hash = createHash("sha256");
  for (const x of bad) {
    // the full text of every entry is hashed (never a placeholder), whatever its depth
    const raw = iterJson(x);
    hash.update(raw);
    hash.update("\n");
    counts.set(raw, (counts.get(raw) ?? 0) + 1);
  }
  const payloadSha256 = `0x${hash.digest("hex")}`;
  // samples are bounded independently: a long entry keeps its first characters, its full length
  // and its own sha256, so distinct entries stay distinct and each can be checked
  const evidence = [...counts.entries()].slice(0, QUARANTINE_SAMPLES).map(([raw, count]) => ({
    raw: raw.length > QUARANTINE_SAMPLE_CHARS ? raw.slice(0, QUARANTINE_SAMPLE_CHARS) : raw,
    ...(raw.length > QUARANTINE_SAMPLE_CHARS
      ? {
          truncated: true,
          rawLength: raw.length,
          rawSha256: `0x${createHash("sha256").update(raw).digest("hex")}`,
        }
      : {}),
    count,
    source,
    range: [from, to],
  }));
  const distinct = counts.size;
  const qid = ethers.keccak256(
    ethers.toUtf8Bytes(safeJson([source, from, to, why, bad.length, payloadSha256]))
  );
  summary.isolated = (summary.isolated ?? 0) + bad.length;
  const rec = {
    route: "unattributed",
    label: "RPC answer quarantined (not a tx; nobody accused)",
    event: "UNREADABLE",
    txHash: qid,
    quarantine: true,
    logIndex: "unreadable",
    blockNumber: from,
    caller: null,
    callerSource: "unknown",
    source,
    range: [from, to],
    entries: bad.length,
    distinct,
    payloadSha256,
    lastReasons: [
      `${bad.length} returned entr${bad.length === 1 ? "y is" : "ies are"} ${why} (${distinct} distinct${distinct > QUARANTINE_SAMPLES ? `, first ${QUARANTINE_SAMPLES} kept` : ""})`,
    ],
    evidence: typedEvidence(evidence),
    ruleset: ctx.ruleset,
    seenAt: ctx.now,
    verdict: {
      flagged: !!rs.publicRoute?.unattributed?.flag,
      rule: "watcher.UNREADABLE",
      reasons: ["an RPC answer could not be read (malformed or inconsistent); nobody accused"],
    },
  };
  const res = store.putRecord(rec);
  note(summary, res, rec);
  // a re-read of the same answer (a tick retried after a later failure) is the same record
  if (res !== "same") summary.quarantined = (summary.quarantined ?? 0) + 1;
}
const QUARANTINE_SAMPLES = 10;
const MAX_PER_TX_ISOLATIONS = 100;

/** Isolations (dead letters, amendments, patches) one block may write. Under an honest RPC an
 * isolation is a rare transient failure, so a real block comes nowhere near this; the cap bounds what
 * a misbehaving answer can make the watcher write, and the excess joins the bounded quarantine.
 * Records do not count (#404 review B1). */
const MAX_TXS_PER_BLOCK = 2000;
/** More SignersCommitted logs in one tx than a 30M-gas block can BLS-verify (each needs a pairing
 * check, well over 100 000 gas): such a tx cannot be real. */
const MAX_COMMITS_PER_TX = 300;
/** More watched logs in one tx than a real admin or aggregator tx emits (the watched SP events are
 * privileged state changes); bounds the records one tx can write (follow-up #2 R7). */
const MAX_LOGS_PER_TX = 2000;
const OVERSIZED_TX = `in a tx with more than ${MAX_COMMITS_PER_TX} commitments or ${MAX_LOGS_PER_TX} watched logs`;
const RESERVED = ["source", "range", "raw", "count", "quarantine"];

/** A fresh RPC log never brings our own evidence fields (a returned `range` must not stand in for
 * the query's: follow-up #2 R3). */
function stripReserved(l) {
  if (!RESERVED.some(k => Object.hasOwn(l, k))) return l;
  const out = {};
  // own data properties only: assigning a key named __proto__ would replace the copy's prototype
  // and make nested fields look like log fields (follow-up #2 R11)
  for (const [k, v] of Object.entries(l))
    if (!RESERVED.includes(k))
      Object.defineProperty(out, k, {
        value: v,
        enumerable: true,
        writable: true,
        configurable: true,
      });
  return out;
}

/** JSON that never throws on RPC values: a BigInt keeps its type in the text, so identities
 * built from it stay distinct and stable (Codex follow-up R10). */
export function safeJson(v) {
  try {
    // collision-free: a BigInt becomes { $bigint }, and a plain object that itself uses one of the
    // tag keys is escaped as { $obj: {...} }, so a literal never equals a tag (Codex follow-up R12)
    // The escape's own inner copy is recognised by identity, never by its parent's keys: a parent
    // that merely HAS a `$obj` key (it came from the RPC) must not switch escaping off below it
    // (follow-up #2 R10).
    const escaped = new WeakSet();
    return JSON.stringify(v, function (k, x) {
      if (typeof x === "bigint") return { $bigint: x.toString() };
      if (
        x &&
        typeof x === "object" &&
        !Array.isArray(x) &&
        !escaped.has(x) &&
        (Object.hasOwn(x, "$bigint") || Object.hasOwn(x, "$obj"))
      ) {
        const inner = { ...x };
        escaped.add(inner);
        return { $obj: inner };
      }
      return x;
    });
  } catch {
    // too deep for JSON.stringify: an identity from the full text, so distinct deep values stay
    // distinct wherever this is used as a key (follow-up #2 R6)
    try {
      return `<unserialisable ${typeof v} ${deepDigest(v)}>`;
    } catch {
      return `<unserialisable ${typeof v}>`;
    }
  }
}

/** sha256 of a value's full JSON text, encoded without recursion. */
function deepDigest(v) {
  return `0x${createHash("sha256").update(iterJson(v)).digest("hex")}`;
}
const DEEP_PLACEHOLDER = "<evidence too deep or too large to serialise>";

/** Evidence as it is persisted: BigInt values tagged ({ $bigint }) rather than flattened to
 * strings, so a stored observation keeps the identity it had when seen (1n and "1" stay two
 * observations through a retry: Codex follow-up R11). */
export function typedEvidence(watched) {
  // Never the original object as a fallback: a value that cannot be serialised (nested too deep,
  // say) would then throw in the dead-letter write, outside the isolation (follow-up #2 R2). Each
  // item that cannot be encoded, or is nested deeper than any real log (MAX_EVIDENCE_DEPTH), becomes
  // a placeholder that keeps its query and range. The depth bound matters: state files are
  // indented, so a stored value's size grows with the square of its depth (a 6000-deep value of
  // 42 KB was a 72 MB dead letter, rewritten on every retry: follow-up #2 R7).
  const items = Array.isArray(watched) ? watched : [watched];
  const tooBig = it => deeperThan(it, MAX_EVIDENCE_DEPTH) || largerThan(it, MAX_EVIDENCE_BYTES);
  if (!items.some(tooBig))
    try {
      return JSON.parse(safeJson(watched));
    } catch {
      // fall through to the per-item encoding
    }
  return items.map(item => {
    if (!tooBig(item))
      try {
        return JSON.parse(safeJson(item));
      } catch {
        // a placeholder below
      }
    return deepPlaceholder(item);
  });
}

/** Whether a value nests deeper than `max` levels (arrays and objects), found without recursion
 * and stopping at the first such path. */
function deeperThan(v, max) {
  const st = [[v, 0]];
  while (st.length) {
    const [x, d] = st.pop();
    if (!x || typeof x !== "object") continue;
    if (d >= max) return true;
    for (const c of Array.isArray(x) ? x : Object.values(x)) st.push([c, d + 1]);
  }
  return false;
}
const MAX_EVIDENCE_DEPTH = 64;
/** A stored evidence item's JSON is at most this many characters (a real watched log is under
 * 1 KB): a larger one is kept as a placeholder with its prefix, full length and sha256, so a
 * retry never rewrites a huge value (follow-up #2 R11). */
const MAX_EVIDENCE_BYTES = 65_536;

/** Whether a value's JSON text is longer than `max` characters, measured without recursion and
 * stopping as soon as it is (strings by length, other leaves by a small bound). */
function largerThan(v, max) {
  let n = 0;
  const st = [v];
  while (st.length) {
    const x = st.pop();
    // the string's encoded size: JSON escapes and UTF-8 bytes, not its character count (R12)
    if (typeof x === "string") n += Buffer.byteLength(JSON.stringify(x), "utf8");
    else if (x && typeof x === "object") {
      const keys = Array.isArray(x) ? null : Object.keys(x);
      n += 2;
      if (keys)
        for (const k of keys) {
          n += Buffer.byteLength(JSON.stringify(k), "utf8") + 2;
          st.push(x[k]);
        }
      else
        for (const c of x) {
          n += 1;
          st.push(c);
        }
    } else n += 24;
    if (n > max) return true;
  }
  return false;
}

/** The stored form of an evidence item too deep or too large to keep as JSON. */
function deepPlaceholder(item) {
  // what cannot be stored as JSON is kept as its full text's prefix, length and sha256
  // (follow-up #2 R5), so distinct items stay distinct and each can be checked
  let text = null;
  try {
    text = iterJson(item);
  } catch {
    text = null;
  }
  return {
    raw: DEEP_PLACEHOLDER,
    ...(text === null
      ? {}
      : {
          rawPrefix: text.slice(0, QUARANTINE_SAMPLE_CHARS),
          rawLength: text.length,
          rawSha256: `0x${createHash("sha256").update(text).digest("hex")}`, // = deepDigest(item)
        }),
    source: typeof item?.source === "string" ? item.source : null,
    range:
      Array.isArray(item?.range) &&
      item.range.length === 2 &&
      item.range.every(n => Number.isSafeInteger(n))
        ? [item.range[0], item.range[1]]
        : null,
  };
}

/** Stored evidence back to the values it was seen with (the inverse of typedEvidence): every read of
 * persisted evidence decodes, every write encodes, so persistence is idempotent and an observation
 * keeps one identity across any number of retries (Codex follow-up R12). */
export function nativeEvidence(watched) {
  // Iterative (follow-up #2 R7): stored evidence may be nested thousands deep, and a recursive
  // decoder would overflow on every retry, outside the isolation.
  const conv = x => {
    if (Array.isArray(x)) return [new Array(x.length), x.map((v, k) => [k, v])];
    if (!x || typeof x !== "object") return [x, null];
    const keys = Object.keys(x);
    if (keys.length === 1 && keys[0] === "$bigint" && typeof x.$bigint === "string")
      try {
        return [BigInt(x.$bigint), null];
      } catch {
        return [x, null];
      }
    const src =
      keys.length === 1 && keys[0] === "$obj" && x.$obj && typeof x.$obj === "object" ? x.$obj : x;
    return [{}, Object.entries(src)];
  };
  const set = (target, k, v) =>
    Array.isArray(target)
      ? (target[k] = v)
      : // defineProperty, never assignment: a key named __proto__ stays a plain key
        Object.defineProperty(target, k, {
          value: v,
          enumerable: true,
          writable: true,
          configurable: true,
        });
  const dec = root => {
    const [out, children] = conv(root);
    const st = children ? [[out, children]] : [];
    while (st.length) {
      const [target, ch] = st.pop();
      for (const [k, v] of ch) {
        const [r, cc] = conv(v);
        set(target, k, r);
        if (cc) st.push([r, cc]);
      }
    }
    return out;
  };
  return Array.isArray(watched) ? watched.map(dec) : watched;
}

/** A log's raw identity for de-duplication: every field as the RPC gave it, never parsed, so only
 * identical copies collapse and conflicting ones at one position survive (Codex follow-up R2). */
export function rawLogKey(l) {
  // case-folded only where case carries no meaning (valid hex); a malformed string is kept exactly,
  // so "BAD" and "bad" stay two observations (follow-up #2 R11)
  const h = x => (typeof x === "string" && /^0x[0-9a-fA-F]*$/.test(x) ? x.toLowerCase() : x);
  // Each field with its presence: a missing field and an explicit null are two observations
  // (follow-up #2 R12). "Present" = an own property whose value is not undefined, which is what
  // survives storage, so a stored observation keeps the identity it was seen with.
  const f = (k, map = x => x) =>
    l && typeof l === "object" && Object.hasOwn(l, k) && l[k] !== undefined ? [1, map(l[k])] : [0];
  return safeJson([
    f("address", h),
    f("topics", t => (Array.isArray(t) ? t.map(h) : t)),
    f("data", h),
    f("index"),
    f("logIndex"),
    f("removed"),
    f("transactionHash", h),
    // block identity too: copies that disagree on their block are a conflict, not duplicates
    // (Codex follow-up R3)
    f("blockHash", h),
    f("blockNumber"),
  ]);
}

/** The watched logs of one tx, re-read from its block by hash (for dead letters without stored
 * evidence). Throws when the block cannot be read. */
async function watchedLogsOf(chain, cfg, txHash, blockNumber) {
  const h = await header(chain, blockNumber);
  const out = [];
  for (const [address, topics] of [
    [cfg.aggregator, [SIGNERS_COMMITTED()]],
    [cfg.roles.superPaymaster, spTopics()],
  ]) {
    const got = await rawGetLogs(chain, { address, topics: [topics], blockHash: h.hash });
    for (const l of got)
      if (lcEq(l.transactionHash, txHash))
        out.push(evidenceLog(l, lcEq(address, cfg.aggregator) ? "agg" : "sp"));
  }
  return out;
}

/** Split a tx's logs into watched aggregator / SuperPaymaster logs. */
function splitLogs(logs, cfg, block) {
  const t = { block, agg: [], sp: [] };
  // Topics compared case-insensitively: hex case is not content (Codex #400-fix R9).
  const spT = new Set(spTopics().map(x => x.toLowerCase()));
  const agT = SIGNERS_COMMITTED().toLowerCase();
  for (const l of logs) {
    const t0 = str(l?.topics?.[0]).toLowerCase();
    if (lcEq(l.address, cfg.aggregator) && t0 === agT) t.agg.push(l);
    else if (lcEq(l.address, cfg.roles.superPaymaster) && spT.has(t0)) t.sp.push(l);
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
  // A watched log must be well formed, and an aggregator log must carry its 32-byte key: anything
  // else is a malformed RPC answer, isolated by the caller (#400 review L1).
  if (t.malformed) throw new SafeError("malformed or unclassifiable watched log");
  if (!Number.isSafeInteger(t.block) || t.block < 0) throw new SafeError("invalid block number");
  for (const l of [...t.agg, ...t.sp])
    if (parsePosition(l.blockNumber) !== t.block)
      throw new SafeError("watched logs name different blocks");
  if (!/^0x[0-9a-fA-F]{64}$/.test(str(txHash)))
    throw new SafeError("watched log without a tx hash");
  for (const l of [...t.agg, ...t.sp])
    if (!validLog(l)) throw new SafeError("malformed watched log");
  // a log the RPC marks removed is never evidence, on any path (Codex follow-up R2)
  for (const l of [...t.agg, ...t.sp])
    if (l.removed === true) throw new SafeError("removed watched log");
  for (const l of t.agg)
    if (l.topics.length < 2) throw new SafeError("aggregator log without a key");
  // a log must match the query that returned it: the configured emitter and a watched topic
  // (an RPC whose address filter is wrong must not get another contract's event attributed)
  const spT = new Set(spTopics().map(x => x.toLowerCase()));
  for (const l of t.agg)
    if (!lcEq(l.address, cfg.aggregator) || !lcEq(l.topics[0], SIGNERS_COMMITTED()))
      throw new SafeError("aggregator query returned a log of another emitter or topic");
  for (const l of t.sp)
    if (!lcEq(l.address, cfg.roles.superPaymaster) || !spT.has(str(l.topics[0]).toLowerCase()))
      throw new SafeError("SP query returned a log of another emitter or topic");
  // positions are judged here, inside the isolation, for every watched log
  {
    // one position, one log: conflicting copies at a position are a malformed answer
    const pos = [...t.agg, ...t.sp].map(l => logPos(l));
    if (new Set(pos).size !== pos.length)
      throw new SafeError("conflicting watched logs at one position");
  }
  // a watched SP log must decode against the pinned ABI: one that does not (a recognised topic
  // but missing indexed topics, say) is a malformed answer, isolated, never silently dropped
  for (const l of t.sp) if (!decodeSp(l)) throw new SafeError("watched SP log does not decode");
  t.sp.sort((a, b) => logPos(a) - logPos(b));
  // Inclusion, on every path (Codex follow-up R5): the block must be inside the range that was
  // asked for and not past the finalized block, and every log must name the CANONICAL block at
  // that height (a stale fork, or a backend lagging behind another, is refused here).
  if (t.block > snapshot) throw new SafeError("watched log beyond the finalized block");
  if (t.range && (t.block < t.range[0] || t.block > t.range[1]))
    throw new SafeError("watched log outside the requested range");
  // each observation also against the range it came from (merged evidence keeps one per log)
  for (const l of [...t.agg, ...t.sp])
    if (Array.isArray(l.range) && (t.block < l.range[0] || t.block > l.range[1]))
      throw new SafeError("watched log outside the requested range");
  const canon = (await header(chain, t.block)).hash;
  for (const l of [...t.agg, ...t.sp])
    if (l.blockHash !== undefined && l.blockHash !== null && !lcEq(l.blockHash, canon))
      throw new SafeError("watched log from a non-canonical block");
  const SP = cfg.roles.superPaymaster;
  let tx;
  try {
    tx = await chain.getTransaction(txHash);
  } catch {
    tx = undefined;
  }
  // The tx response must be this tx, in this block: its sender, target and calldata are used for
  // attribution on the direct path, where no receipt or trace cross-check runs.
  if (tx) {
    // a response must name this tx: one without a hash is not trusted either (Codex follow-up R6)
    if (typeof tx.hash !== "string" || !lcEq(tx.hash, txHash))
      throw new SafeError("transaction response names another tx");
    if (tx.blockHash !== undefined && tx.blockHash !== null && !lcEq(tx.blockHash, canon))
      throw new SafeError("transaction response from another block");
    if (
      tx.blockNumber !== undefined &&
      tx.blockNumber !== null &&
      parsePosition(tx.blockNumber) !== t.block
    )
      throw new SafeError("transaction response from another block");
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
    const watched = [...t.agg, ...t.sp];
    const stats = (summary.trace ??= {});
    const { trace, logs, rc } = await traceAndReceipt(chain, txHash, stats, watched.length > 0);
    // The inclusion is the canonical header at that height (every watched log was checked against
    // it above), never the evidence's own claim (Codex follow-up R5).
    const envelope = logs
      ? envelopeProblem(txHash, tx, rc, trace, { blockNumber: t.block, blockHash: canon })
      : null;
    // The receipt must contain every watched log getLogs returned for this tx, identical (address,
    // every topic, data) at the same position: an inconsistent receipt aligns with nothing it
    // should (Codex #400-fix R5, R6), and it is a health finding, not only a retry.
    // Exact: the receipt's watched logs (by address and topic) are the getLogs evidence, one to
    // one, no more and no fewer (Codex #400-fix R8: an extra log at a taken position must fail).
    const rs2 = logs ? splitLogs(logs, cfg, t.block) : { agg: [], sp: [] };
    const rw = [...rs2.agg, ...rs2.sp];
    const rpos = logs ? logs.map(receiptPos) : [];
    const rwKeys = new Set();
    for (const r of rw) {
      const k = sameLogKey(r);
      if (k !== null) rwKeys.add(k);
    }
    const consistent =
      !!logs &&
      !envelope &&
      !watched.some(w => w.removed === true) &&
      rw.length === watched.length &&
      // keyed as sameLog compares (position, address, topics, data; hex case-insensitive): linear
      watched.every(w => {
        const k = sameLogKey(w);
        return k !== null && rwKeys.has(k);
      }) &&
      rpos.every(p => p !== null) &&
      new Set(rpos).size === logs.length;
    if (logs && !consistent) stats.inconsistent = (stats.inconsistent ?? 0) + 1;
    attr = !logs
      ? { aligned: false, owner: new Map(), spCall: new Map(), why: "receipt unavailable" }
      : !consistent
        ? {
            aligned: false,
            owner: new Map(),
            spCall: new Map(),
            why: envelope ?? "receipt disagrees with getLogs",
          }
        : trace && !tx
          ? // the root cannot be checked yet: retried, not attributed (and not a health finding)
            { aligned: false, owner: new Map(), spCall: new Map(), why: "transaction unavailable" }
          : attributeLogs(trace, logs, cfg.aggregator, SP);
    // Consistent + aligned implies the receipt holds the watched logs and the trace carries them,
    // so an empty or log-less pair can never count as proof.
    if (consistent && trace && tx && !attr.aligned) {
      // A consistent receipt whose trace still does not align (noncontiguous positions, malformed
      // trace logs, ambiguous positionless order): a health finding, so a stored proof cannot keep
      // the watcher "healthy" while attribution fails (Codex #400-fix R12).
      stats.unaligned = (stats.unaligned ?? 0) + 1;
      stats.unalignedWhy = attr.why;
    }
    if (attr.aligned && trace) {
      // A real trace aligned with its receipt is positive proof of the capability (status.trace).
      summary.trace.verified = (summary.trace.verified ?? 0) + 1;
      summary.trace.verifiedTx = txHash;
    }
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
      const list = effectsOf.get(call) ?? [];
      list.push(ev); // push, never a copy of the growing list (follow-up #2 R9)
      effectsOf.set(call, list);
    } else independent.push(ev);
  }
  for (const l of t.agg) {
    if (store.hasBlsRecord(BigInt(l.topics[1]))) {
      // Completed before (tx retry, M5). Effects the trace proves only now are kept beside the
      // record, not lost when the tx dead letter resolves (#400 review L4).
      const effects = effectsOf.get(commitCall.get(logPos(l))) ?? [];
      const am =
        effects.length &&
        store.putBlsAmendment(BigInt(l.topics[1]), {
          key: BigInt(l.topics[1]).toString(),
          txHash,
          provenBy: "trace",
          provenAt: ctx.now,
          spEvents: effects,
          ruleset: ctx.ruleset,
        });
      // every write counts towards the per-block cap (follow-up #2 R9)
      if (am && am !== "same" && am !== "conflict-same")
        summary.otherWrites = (summary.otherWrites ?? 0) + 1;
      // a different valid proof already stands for this action: both kept, and counted
      if (am === "conflict") summary.amendmentConflicts = (summary.amendmentConflicts ?? 0) + 1;
      continue;
    }
    // A BLS action with an open dead letter is retried by that dead letter only, once per tick,
    // never rebuilt here as well (a rebuild failure must not replace verified evidence: R2 M4; and
    // two retries per tick would halve the attempt cap: #400 review L2).
    const pend = store.getDeadLetter(
      Store.recordId({ route: "bls", key: BigInt(l.topics[1]).toString(), kind: undefined })
    );
    if (pend) {
      // ...but effects the trace proves now go into that dead letter, so its own retry (and its
      // record) carries them (#400 review L4). No attempt is spent.
      const effects = effectsOf.get(commitCall.get(logPos(l))) ?? [];
      if (effects.length && !(pend.spEvents ?? []).length) {
        summary.otherWrites = (summary.otherWrites ?? 0) + 1;
        store.patchDeadLetter(pend.id, {
          spEvents: effects,
          ...(pend.pendingRecord && !(pend.pendingRecord.spEvents ?? []).length
            ? { pendingRecord: { ...pend.pendingRecord, spEvents: effects } }
            : {}),
        });
      }
      continue;
    }
    const call = commitCall.get(logPos(l));
    const out = await blsRecord(chain, cfg, rs, ctx, l, effectsOf.get(call) ?? [], snapshot);
    if (out.record) note(summary, store.putRecord(out.record), out.record);
    else {
      store.putDeadLetter(out.deadLetter);
      summary.deadLetters++;
    }
  }
  const txDl = `tx-${str(txHash).toLowerCase()}`;
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
      // The watched logs exactly as getLogs returned them: a retry is judged against THIS
      // evidence, never against a receipt that may be the thing in dispute (Codex #400-fix R7).
      watched: typedEvidence(
        mergeEvidence(nativeEvidence(store.getDeadLetter(txDl)?.watched), evidenceOf(t))
      ),
      // Records already classified, missing only their price (Codex #400-fix M3): exhaustion
      // keeps their route, caller and verdict, marked price.unavailable.
      ...(pendingRecords ? { pendingRecords } : {}),
      // the query range the evidence came from, restored on every retry (Codex follow-up R6)
      ...(t.range ? { range: t.range } : {}),
      // What is known of the tx itself, kept for an unattributed record at exhaustion (#400 review
      // nit): its sender, target and root selector (not the emitting call's).
      // First write wins (#403 review L-1; #404 review L3): what an earlier lookup established is
      // kept, whether a later one answers nothing or a different tx; only the first lookup that
      // names the tx sets them.
      ...(() => {
        const prior = store.getDeadLetter(txDl);
        if (prior && "txFrom" in prior)
          return { txFrom: prior.txFrom, txTo: prior.txTo, rootSelector: prior.rootSelector };
        return tx
          ? {
              txFrom: tx.from ? ethers.getAddress(tx.from) : null,
              txTo: tx.to ? ethers.getAddress(tx.to) : null,
              rootSelector: selectorOf(tx.data),
            }
          : {};
      })(),
      ruleset: ctx.ruleset,
      seenAt: ctx.now,
    });
    summary.deadLetters++;
    return { done: false };
  };
  if (tx === undefined || tx === null) return fail("transaction unavailable");
  // An ambiguous event is attributed ONLY by its aligned emitting frame in the trace (Codex
  // #400-fix R2 H1): a tx's calldata names the root call, and matching event names cannot prove
  // that no nested SP call emitted the same event type. Without that frame, the tx is retried.
  // For an event only privileged functions can emit, the root call is recorded as best-known
  // caller information (the route is the owner route whoever called).
  const rootSel = direct ? selectorOf(tx.data) : null;
  const directFrame = rootSel ? { from: tx.from, selector: rootSel } : null;
  const traced = e => (attr.aligned ? (attr.spCall.get(e.logIndex) ?? null) : null);
  const frameOf = e => (amb.has(e.event) ? traced(e) : (traced(e) ?? directFrame));
  // Events emitted by the same SP call, for verdicts that depend on what else the call did.
  const byFrame = new Map();
  for (const e of independent) {
    const f = frameOf(e);
    if (f) {
      // push, never a copy of the growing list: linear in the events (follow-up #2 R7)
      // the call's DISTINCT event names, in first-seen order: bounded by the ABI however many
      // events the call emitted, so a record never carries a list as long as the tx (R9)
      const list = byFrame.get(f) ?? [];
      if (!list.includes(e.event)) list.push(e.event);
      byFrame.set(f, list);
    }
  }
  const recs = [];
  let priceFailed = false;
  for (const e of independent) {
    const f = frameOf(e);
    if (amb.has(e.event) && !selectorOf(f?.selector ?? ""))
      return fail(
        `caller of ${e.event} undeterminable (${attr.why && attr.why !== "not traced" ? attr.why : direct ? "no selector" : "trace unaligned"})`
      );
    // Only an ambiguous event can be public: an event no permissionless function emits is the owner
    // route whatever the root call was (Codex #400-fix R3 H1: a root updatePrice() selector must not
    // turn a nested GuardianSet into unflagged public activity).
    const pub = f && amb.has(e.event) ? publicFunction(rs, f.selector) : null;
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
        rec.priceMissing = true;
      }
    }
    recs.push(rec);
  }
  if (priceFailed) return fail("price read failed", recs);
  for (const rec of recs) note(summary, store.putRecord(rec), rec);
  store.resolveDeadLetter(txDl);
  return { done: true };
}

/** Whether a pending SP record still lacks a price it needs: marked so, or (a record persisted
 * without the marker) the ruleset wants one and no valid pair is present (Codex #400-fix R3 M). */
function priceStillMissing(rs, cfg, r) {
  if (r.priceMissing) return true;
  if (!wantsPrice(rs, cfg.roles, r)) return false;
  return !(r.price && typeof r.price === "object" && !r.price.error && !r.price.unavailable);
}

/** A dead letter that has used every retry becomes a record, so nothing BLS-executed or watched
 * is left without one (M0 §5.2, #400 Low): an unauthenticated BLS action is UNRECOVERED; an SP
 * event whose call could not be determined is "unattributed" (nobody accused). */
function exhaust(store, rs, cfg, ctx, summary, dl) {
  if (dl.route === "tx" && dl.pendingRecords) {
    for (const r of dl.pendingRecords) {
      const { priceMissing, ...rest } = r;
      void priceMissing;
      const rec = {
        ...rest,
        ...(priceStillMissing(rs, cfg, r) ? { price: { unavailable: true } } : {}),
        exhaustedAfter: dl.attempts,
      };
      note(summary, store.putRecord(rec), rec);
    }
  } else if (dl.route === "tx" && !(dl.events ?? []).length) {
    // An isolated tx whose answers never became readable (#400 review L1, DSR): one unattributed
    // record, nobody accused, carrying the stored evidence and the last reasons.
    const rec = {
      route: "unattributed",
      label: dl.quarantine
        ? "RPC answer unreadable (no tx hash; quarantine id, not a tx)"
        : "RPC answer unreadable",
      event: "UNREADABLE",
      txHash: dl.txHash,
      logIndex: "unreadable",
      blockNumber: dl.blockNumber,
      caller: null,
      callerSource: "unknown",
      evidence: dl.watched ?? [],
      exhaustedAfter: dl.attempts,
      lastReasons: dl.reasons,
      ruleset: dl.ruleset ?? ctx.ruleset,
      seenAt: ctx.now,
    };
    // its own verdict: not the SP-event wording of the unattributed rule (it can be an aggregator
    // log, or no log at all), flagged as that rule flags, nobody accused (#403 review L-4)
    rec.verdict = {
      flagged: !!rs.publicRoute?.unattributed?.flag,
      rule: "watcher.UNREADABLE",
      reasons: ["an RPC answer could not be read (malformed or inconsistent); nobody accused"],
    };
    note(summary, store.putRecord(rec), rec);
    summary.unreadable = (summary.unreadable ?? 0) + 1;
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
        // known of the tx itself, not of the emitting call (so never the caller)
        from: dl.txFrom ?? null,
        to: dl.txTo ?? null,
        rootSelector: dl.rootSelector ?? null,
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
          if (
            may &&
            !logs.some(l => parsePosition(l?.blockNumber) === n && lcEq(l?.topics?.[0], topic))
          )
            missing.push(topic);
        }
        if (unchecked) {
          summary.bloomUnchecked++;
          continue;
        }
        if (!missing.length) continue;
        let got;
        try {
          got = await rawGetLogs(chain, { address: addr, topics: [topics], blockHash: h.hash });
        } catch {
          throw new SafeError(
            `block ${n}: logsBloom shows a watched log that getLogs did not return, and the by-hash re-read failed; retrying`
          );
        }
        // raw comparison: a malformed position must not throw here, outside the per-tx isolation
        const have = new Set(logs.map(rawLogKey));
        const fresh = got.filter(g => !have.has(rawLogKey(g)));
        if (fresh.length) {
          for (const x of fresh) extra.push(x);
          summary.bloomRecovered++;
        }
        if (missing.some(topic => !got.some(g => lcEq(g?.topics?.[0], topic))))
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
    if (!lcEq(now.hash, cursor.hash)) {
      throw new SafeError(
        `cursor block ${cursor.block} hash changed (${hx(cursor.hash)} -> ${hx(now.hash)}): finality violated, not advancing`
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
    trace: {},
    flagged: [],
  };

  // Retry dead letters first (a trace, a slot read or an RPC that failed may now answer). One that
  // has used every attempt becomes a record (exhaust), never silently dropped.
  // Ids first, each dead letter re-read just before it is handled: an earlier retry in this loop
  // may have patched it (later-proven effects), and a stale snapshot must not overwrite that
  // (Codex follow-up R2).
  store.listDeadLetters(); // counts corrupt files for status
  for (const dlId of store.listDeadLetterIds()) {
    const dl = store.getDeadLetter(dlId);
    if (!dl) continue;
    if (dl.attempts >= MAX_DEADLETTER_ATTEMPTS) {
      exhaust(store, rs, cfg, ctx, summary, dl);
      continue;
    }
    if (dl.route === "tx" && dl.pendingRecords) {
      // Classified already; only prices are missing. Retry just those (R2 M3).
      const done = [];
      let failed = false;
      for (const r of dl.pendingRecords) {
        if (!priceStillMissing(rs, cfg, r)) {
          done.push(r);
          continue;
        }
        const price = await pricePair(chain, cfg, r.blockNumber);
        if (price.error) {
          failed = true;
          break;
        }
        const { priceMissing, ...rest } = r;
        void priceMissing;
        done.push({ ...rest, price });
      }
      if (failed) store.putDeadLetter({ ...dl, reasons: ["price read failed"] });
      else {
        for (const rec of done) note(summary, store.putRecord(rec), rec);
        store.resolveDeadLetter(dl.id);
      }
      continue;
    }
    if (dl.route === "tx" && dl.quarantine) {
      // no tx to look at: it only waits for its cap, then becomes an UNREADABLE record
      store.putDeadLetter({ ...dl, reasons: dl.reasons });
      continue;
    }
    if (dl.route === "tx") {
      // The watched logs come from the dead letter's own getLogs evidence; a dead letter written
      // without it re-reads them from its block by hash (EIP-234), never from the receipt.
      let watched = null;
      try {
        watched =
          Array.isArray(dl.watched) && dl.watched.length ? nativeEvidence(dl.watched) : null;
      } catch {
        // stored evidence that cannot be decoded spends an attempt, so the cap still ends it
        // (follow-up #2 R7); it is never a reason for the tick to fail
        store.putDeadLetter({ ...dl, reasons: ["stored evidence unreadable"] });
        continue;
      }
      if (!watched) {
        try {
          watched = await watchedLogsOf(chain, cfg, dl.txHash, dl.blockNumber);
        } catch {
          watched = null;
        }
      }
      if (!watched?.length) {
        store.putDeadLetter({ ...dl, reasons: ["watched logs unavailable"] });
        continue;
      }
      const rt = {
        ...txOfEvidence(watched, cfg, dl.blockNumber),
        ...(dl.range ? { range: dl.range } : {}),
      };
      // the same admission limits as fresh evidence (follow-up #2 R9): a re-fetch past them is a
      // bounded quarantine, never one write per log
      if (rt.agg.length > MAX_COMMITS_PER_TX || rt.agg.length + rt.sp.length > MAX_LOGS_PER_TX) {
        const [qf, qt] = Array.isArray(dl.range) ? dl.range : [dl.blockNumber, dl.blockNumber];
        for (const source of ["agg", "sp"])
          if (rt[source].length)
            quarantineRaw(store, rs, ctx, summary, rt[source], source, qf, qt, OVERSIZED_TX);
        store.resolveDeadLetter(dl.id);
        continue;
      }
      await processTxIsolated(chain, cfg, rs, ctx, store, summary, dl.txHash, rt, fin.number, dl);
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
      address: cfg.aggregator,
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

  // A returned entry that is not even an object cannot be grouped or bloom-checked: it is
  // quarantined at once with its raw value and query, never a reason to stop (Codex follow-up R3).
  const intake = (raw, source) => {
    const ok = [];
    const bad = [];
    for (const x of raw ?? []) {
      // An entry that is not an object, or names no valid tx, cannot be handled per tx: it joins
      // the bounded quarantine. Every other log is grouped by its tx; the per-tick isolation budget
      // (below) bounds the work, never by dropping evidence (follow-up #2 R3).
      if (!(x && typeof x === "object" && !Array.isArray(x))) bad.push(x);
      else if (!/^0x[0-9a-fA-F]{64}$/.test(str(x.transactionHash))) bad.push(x);
      else ok.push(stripReserved(x));
    }
    if (bad.length) quarantineRaw(store, rs, ctx, summary, bad, source, from, to);
    return ok;
  };
  // The bloom check compares against the RAW answers (quarantined entries included), so an entry
  // set aside at intake is not mistaken for a missing log and read again (follow-up #2 R3). Each
  // read is guarded (W2b): a failure surfaces only the watcher's own wording.
  const rawAgg = await guarded("aggregator log read", () =>
    pagedLogs(chain, cfg.aggregator, [SIGNERS_COMMITTED()], from, to, cfg.page)
  );
  const rawSp = await guarded("superpaymaster log read", () =>
    pagedLogs(chain, cfg.roles.superPaymaster, [spTopics()], from, to, cfg.page)
  );
  const bc = await bloomCheck(chain, cfg, from, to, rawAgg, rawSp, summary);
  const aggLogs = intake(rawAgg.concat(bc.extraAgg), "agg");
  const spLogs = intake(rawSp.concat(bc.extraSp), "sp");
  const extraAgg = [];
  const extraSp = [];

  const byTx = new Map();
  // Each log is grouped by the query that returned it (aggregator or SP), never by re-reading its
  // own address: whether it really matches its query is judged inside the isolation (Codex
  // follow-up R4). Valid tx hashes are canonicalised (lower case) so one tx is one group, whatever
  // casing the RPC used; the original hash stays in the evidence. Heights are parsed without
  // coercion (a value that is not a number never throws here).
  const groupKey = h =>
    typeof h === "string" && /^0x[0-9a-fA-F]{64}$/.test(h) ? h.toLowerCase() : h;
  for (const [l, source] of [
    ...aggLogs.map(x => [x, "agg"]),
    ...extraAgg.map(x => [x, "agg"]),
    ...spLogs.map(x => [x, "sp"]),
    ...extraSp.map(x => [x, "sp"]),
  ]) {
    const k = groupKey(l.transactionHash);
    const t = byTx.get(k) ?? {
      block: parsePosition(l.blockNumber) ?? NaN,
      range: [from, to],
      agg: [],
      sp: [],
    };
    const list = source === "agg" ? t.agg : t.sp;
    // Grouping never throws on log contents: a malformed position is judged inside the per-tx
    // isolation (Codex follow-up R1). Duplicates (bloom-recovered copies) are dropped by their
    // raw position fields.
    const key = `${source}|${rawLogKey(l)}`; // one log from both queries is two observations (R8)
    t.keys ??= new Set();
    if (!t.keys.has(key)) {
      t.keys.add(key);
      list.push(l);
    }
    byTx.set(k, t);
  }
  // Txs without a usable height go last (a NaN comparison would leave the order undefined).
  // In height order without sorting the answer (follow-up #2 R9): groups are bucketed by their
  // height inside [from, to], visited block by block; groups outside the range or without a height
  // follow in arrival order (they are handled in this tick whatever the stop).
  const inRangeGroups = new Map();
  const outsideGroups = [];
  for (const entry of byTx.entries()) {
    const h = entry[1].block;
    if (Number.isSafeInteger(h) && h >= from && h <= to) {
      const list = inRangeGroups.get(h) ?? [];
      list.push(entry);
      inRangeGroups.set(h, list);
    } else outsideGroups.push(entry);
  }
  const ordered = [];
  for (let h = from; h <= to; h++) for (const e of inRangeGroups.get(h) ?? []) ordered.push(e);
  for (const e of outsideGroups) ordered.push(e);
  // The isolation budget is enforced where isolations happen (follow-up #2 R3): once
  // MAX_PER_TX_ISOLATIONS txs of this range were isolated, the current block is finished and the
  // cursor stops there; the later blocks of the range are read again next tick. Only a height inside
  // [from, to] can set that stop, so the cursor always advances at least one block (follow-up #2
  // R4). Txs whose height is missing or outside the range belong to no later block: they are
  // handled in this tick whatever the stop (never deferred into a range that will not return them),
  // sharing one capped bucket. Within a bucket, isolations beyond what any real block can hold
  // join the bounded quarantine.
  const inRange = b => b !== null && b >= from && b <= to;
  let stopAt = null;
  // Only isolations of in-range txs count towards the stop: dead-letter retries above are bounded
  // by the open dead letters, and the outside bucket by its own cap; counting either would let a
  // backlog or a repeated junk answer hold the cursor to one block per tick.
  let inRangeIsolations = 0;
  const perBucket = new Map();
  const overflow = { agg: [], sp: [] };
  const impossible = { agg: [], sp: [] };
  for (const [txHash, t] of ordered) {
    const b = Number.isSafeInteger(t.block) ? t.block : null;
    if (stopAt !== null && inRange(b) && b > stopAt) continue; // read again next tick
    const bucket = inRange(b) ? b : "outside";
    if ((perBucket.get(bucket) ?? 0) >= MAX_TXS_PER_BLOCK) {
      for (const l of t.agg) overflow.agg.push(l);
      for (const l of t.sp) overflow.sp.push(l);
      continue;
    }
    // Any dead letter this tx wrote counts, thrown or not: a lookup that answers null writes one
    // through fail() without throwing, and must spend the budget too (follow-up #2 R5).
    // A tx with more commitments than a block's gas could verify is not a real tx: its logs join
    // the bounded quarantine instead of one dead letter per commitment (follow-up #2 R6).
    if (t.agg.length > MAX_COMMITS_PER_TX || t.agg.length + t.sp.length > MAX_LOGS_PER_TX) {
      for (const l of t.agg) impossible.agg.push(l);
      for (const l of t.sp) impossible.sp.push(l);
      continue;
    }
    // Every dead letter written counts towards the budget (one tx can write several: one per
    // commitment), and dead letters plus amendment/patch writes count towards the per-block cap.
    // RECORDS NEVER COUNT (#404 review B1): a healthy record is the watcher doing its job, and
    // counting them let 2000 public PriceUpdated records crowd a later owner action of the same
    // block into a quarantine that accuses nobody. Records are bounded per tx (MAX_LOGS_PER_TX)
    // and by the chain's own gas.
    const before = summary.deadLetters;
    const otherBefore = summary.otherWrites ?? 0;
    await processTxIsolated(chain, cfg, rs, ctx, store, summary, txHash, t, fin.number, null);
    const writes = summary.deadLetters - before;
    const abnormal = writes + (summary.otherWrites ?? 0) - otherBefore;
    if (abnormal > 0) perBucket.set(bucket, (perBucket.get(bucket) ?? 0) + abnormal);
    if (writes > 0 && inRange(b)) inRangeIsolations += writes;
    if (stopAt === null && inRange(b) && inRangeIsolations >= MAX_PER_TX_ISOLATIONS) stopAt = b;
  }
  const cutoff = stopAt ?? to;
  // Evidence keeps the query that returned it; the reason names the overflow.
  for (const source of ["agg", "sp"])
    if (overflow[source].length)
      quarantineRaw(
        store,
        rs,
        ctx,
        summary,
        overflow[source],
        source,
        from,
        cutoff,
        `past ${MAX_TXS_PER_BLOCK} isolating txs in one block (or with no usable height)`
      );
  for (const source of ["agg", "sp"])
    if (impossible[source].length)
      quarantineRaw(
        store,
        rs,
        ctx,
        summary,
        impossible[source],
        source,
        from,
        cutoff,
        OVERSIZED_TX
      );
  if (cutoff < to || overflow.agg.length || overflow.sp.length) summary.budgetStop = true;
  summary.to = cutoff;
  if (cutoff < to) summary.stoppedEarly = true;
  const toHdr = await header(chain, cutoff);
  store.setCursor({ block: cutoff, hash: toHdr.hash });
  return summary;
}
