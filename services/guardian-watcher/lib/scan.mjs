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
import { attributeLogs, receiptPos, validLog, parsePosition } from "./attribute.mjs";
import { mayHaveLog } from "./bloom.mjs";
import { Store } from "./store.mjs";

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
  const n = receiptPos(l); // strict, and `index` / `logIndex` must agree when both are present
  if (n === null) throw new Error(`log without a valid position in tx ${l.transactionHash}`);
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

/** The same log: position, address, every topic and the data (case-insensitive hex). */
export function sameLog(a, b) {
  const h = x => String(x ?? "").toLowerCase();
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
  return (node.calls ?? []).some(traceHasLogs);
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
  { blocks = 5, maxTx = 8, sampleTx = null } = {}
) {
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
    if (!trace || typeof trace !== "object") {
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
    for (const t of blk?.transactions ?? []) {
      if (tried >= maxTx) break;
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
      if (!trace || typeof trace !== "object") {
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
  let firstHash = present(at.blockHash) ? String(at.blockHash) : null;
  for (const [what, o] of sources) {
    if (!o) continue;
    if (present(o.blockNumber) && present(want.number) && num(o.blockNumber) !== want.number)
      return `${what} is from another block`;
    if (present(o.blockHash)) {
      if (firstHash === null) firstHash = String(o.blockHash);
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
    if (tx.to ? !lcEq(trace.to, tx.to) : !/^CREATE2?$/i.test(String(trace.type)))
      return "trace root destination differs from the tx";
    if (String(trace.input ?? "").toLowerCase() !== String(tx.data ?? tx.input ?? "").toLowerCase())
      return "trace root input differs from the tx";
  }
  return null;
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

/** A watched log as stored evidence (plain JSON, full contents and position). */
function evidenceLog(l, source) {
  // Best effort: a malformed log is kept as evidence as far as it can be (an isolated tx keeps
  // what the RPC said: #400 review L1), never a reason to lose the dead letter.
  // The RAW position fields and `removed` are kept as the RPC gave them: normalising here would
  // turn contradictory evidence (index 0, logIndex 99) into valid evidence on retry (Codex
  // follow-up R1).
  const has = k => l?.[k] !== undefined && l?.[k] !== null;
  return {
    address: l?.address,
    topics: Array.isArray(l?.topics) ? [...l.topics] : l?.topics,
    data: l?.data,
    ...(has("index") ? { index: l.index } : {}),
    ...(has("logIndex") ? { logIndex: l.logIndex } : {}),
    ...(has("removed") ? { removed: l.removed } : {}),
    blockNumber: l?.blockNumber, // raw: an invalid height stays as the RPC gave it
    ...(l?.blockHash ? { blockHash: l.blockHash } : {}),
    transactionHash: l?.transactionHash,
    // which query returned it (aggregator or SuperPaymaster): a retry classifies by this, never by
    // re-filtering a possibly malformed log out of existence (Codex follow-up R2)
    ...(source ? { source } : {}),
  };
}

/** Evidence of a tx: its aggregator and SP logs, each tagged with its source query. */
const evidenceOf = t => [
  ...t.agg.map(l => evidenceLog(l, "agg")),
  ...t.sp.map(l => evidenceLog(l, "sp")),
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
    let watched = [];
    try {
      watched = evidenceOf(t);
    } catch {
      watched = prev?.watched ?? [];
    }
    // An item without a usable tx hash gets a quarantine identity derived from its evidence: it
    // is retried and counted, never attributed to any tx (Codex follow-up R2).
    const okHash = /^0x[0-9a-fA-F]{64}$/.test(String(txHash));
    const qid = okHash ? null : ethers.keccak256(ethers.toUtf8Bytes(JSON.stringify(watched)));
    store.putDeadLetter({
      ...(prev ?? {}),
      route: "tx",
      txHash: okHash ? txHash : qid,
      ...(okHash ? {} : { quarantine: true }),
      blockNumber: t.block,
      status: "ERROR",
      reasons: [isolatedReason(e)],
      events: prev?.events ?? [],
      watched: prev?.watched?.length ? prev.watched : watched,
      ruleset: ctx.ruleset,
      seenAt: ctx.now,
    });
    summary.deadLetters++;
    return { done: false };
  }
}

/** A returned entry that is not a log object at all: a quarantine dead letter keyed by its raw value
 * and query, retried to the cap, then an UNREADABLE record that names no tx. */
function quarantineRaw(store, ctx, summary, x, source, from, to) {
  let raw;
  try {
    raw = JSON.stringify(x) ?? String(x);
  } catch {
    raw = String(x);
  }
  const evidence = [{ raw, source, range: [from, to] }];
  const qid = ethers.keccak256(ethers.toUtf8Bytes(JSON.stringify(evidence)));
  summary.isolated = (summary.isolated ?? 0) + 1;
  store.putDeadLetter({
    route: "tx",
    txHash: qid,
    quarantine: true,
    blockNumber: from,
    status: "ERROR",
    reasons: ["returned entry is not a log"],
    events: [],
    watched: evidence,
    ruleset: ctx.ruleset,
    seenAt: ctx.now,
  });
  summary.deadLetters++;
}

/** A log's raw identity for de-duplication: every field as the RPC gave it, never parsed, so only
 * identical copies collapse and conflicting ones at one position survive (Codex follow-up R2). */
export function rawLogKey(l) {
  const h = x => (typeof x === "string" ? x.toLowerCase() : x);
  return JSON.stringify([
    h(l?.address),
    Array.isArray(l?.topics) ? l.topics.map(h) : l?.topics,
    h(l?.data),
    l?.index ?? null,
    l?.logIndex ?? null,
    l?.removed ?? null,
    h(l?.transactionHash),
    // block identity too: copies that disagree on their block are a conflict, not duplicates
    // (Codex follow-up R3)
    h(l?.blockHash),
    l?.blockNumber ?? null,
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
    const got = await chain.getLogs({ address, topics: [topics], blockHash: h.hash });
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
    const t0 = String(l.topics?.[0] ?? "").toLowerCase();
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
  if (t.malformed) throw new Error("malformed or unclassifiable watched log");
  if (!Number.isSafeInteger(t.block) || t.block < 0) throw new Error("invalid block number");
  for (const l of [...t.agg, ...t.sp])
    if (parsePosition(l.blockNumber) !== t.block)
      throw new Error("watched logs name different blocks");
  if (!/^0x[0-9a-fA-F]{64}$/.test(String(txHash))) throw new Error("watched log without a tx hash");
  for (const l of [...t.agg, ...t.sp]) if (!validLog(l)) throw new Error("malformed watched log");
  // a log the RPC marks removed is never evidence, on any path (Codex follow-up R2)
  for (const l of [...t.agg, ...t.sp])
    if (l.removed === true) throw new Error("removed watched log");
  for (const l of t.agg) if (l.topics.length < 2) throw new Error("aggregator log without a key");
  // a log must match the query that returned it: the configured emitter and a watched topic
  // (an RPC whose address filter is wrong must not get another contract's event attributed)
  const spT = new Set(spTopics().map(x => x.toLowerCase()));
  for (const l of t.agg)
    if (!lcEq(l.address, cfg.aggregator) || !lcEq(l.topics[0], SIGNERS_COMMITTED()))
      throw new Error("aggregator query returned a log of another emitter or topic");
  for (const l of t.sp)
    if (!lcEq(l.address, cfg.roles.superPaymaster) || !spT.has(String(l.topics[0]).toLowerCase()))
      throw new Error("SP query returned a log of another emitter or topic");
  // positions are judged here, inside the isolation, for every watched log
  {
    // one position, one log: conflicting copies at a position are a malformed answer
    const pos = [...t.agg, ...t.sp].map(l => logPos(l));
    if (new Set(pos).size !== pos.length)
      throw new Error("conflicting watched logs at one position");
  }
  // a watched SP log must decode against the pinned ABI: one that does not (a recognised topic
  // but missing indexed topics, say) is a malformed answer, isolated, never silently dropped
  for (const l of t.sp) if (!decodeSp(l)) throw new Error("watched SP log does not decode");
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
    const watched = [...t.agg, ...t.sp];
    const stats = (summary.trace ??= {});
    const { trace, logs, rc } = await traceAndReceipt(chain, txHash, stats, watched.length > 0);
    // The watched evidence fixes the inclusion: every watched log must name one block (Codex R13).
    const wHashes = [
      ...new Set(
        watched
          .map(w => w.blockHash)
          .filter(Boolean)
          .map(h => h.toLowerCase())
      ),
    ];
    // Evidence without a block hash (a dead letter stored before it was kept): anchor on the
    // canonical header at that height, never on whatever the receipt says (Codex #400-fix R14).
    let anchor = wHashes[0] ?? null;
    if (logs && !anchor && wHashes.length === 0) {
      try {
        anchor = (await header(chain, t.block)).hash;
      } catch {
        anchor = null;
      }
    }
    const envelope = !logs
      ? null
      : wHashes.length > 1
        ? "watched logs name different blocks"
        : !anchor
          ? "evidence block unavailable"
          : envelopeProblem(txHash, tx, rc, trace, { blockNumber: t.block, blockHash: anchor });
    // The receipt must contain every watched log getLogs returned for this tx, identical (address,
    // every topic, data) at the same position: an inconsistent receipt aligns with nothing it
    // should (Codex #400-fix R5, R6), and it is a health finding, not only a retry.
    // Exact: the receipt's watched logs (by address and topic) are the getLogs evidence, one to
    // one, no more and no fewer (Codex #400-fix R8: an extra log at a taken position must fail).
    const rs2 = logs ? splitLogs(logs, cfg, t.block) : { agg: [], sp: [] };
    const rw = [...rs2.agg, ...rs2.sp];
    const rpos = logs ? logs.map(receiptPos) : [];
    const consistent =
      !!logs &&
      !envelope &&
      !watched.some(w => w.removed === true) &&
      rw.length === watched.length &&
      watched.every(w => rw.some(r => sameLog(r, w))) &&
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
      effectsOf.set(call, [...(effectsOf.get(call) ?? []), ev]);
    } else independent.push(ev);
  }
  for (const l of t.agg) {
    if (store.hasBlsRecord(BigInt(l.topics[1]))) {
      // Completed before (tx retry, M5). Effects the trace proves only now are kept beside the
      // record, not lost when the tx dead letter resolves (#400 review L4).
      const effects = effectsOf.get(commitCall.get(logPos(l))) ?? [];
      if (
        effects.length &&
        store.putBlsAmendment(BigInt(l.topics[1]), {
          key: BigInt(l.topics[1]).toString(),
          txHash,
          provenBy: "trace",
          provenAt: ctx.now,
          spEvents: effects,
          ruleset: ctx.ruleset,
        }) === "conflict"
      )
        // a different valid proof already stands for this action: both kept, and counted
        summary.amendmentConflicts = (summary.amendmentConflicts ?? 0) + 1;
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
      if (effects.length && !(pend.spEvents ?? []).length)
        store.patchDeadLetter(pend.id, {
          spEvents: effects,
          ...(pend.pendingRecord && !(pend.pendingRecord.spEvents ?? []).length
            ? { pendingRecord: { ...pend.pendingRecord, spEvents: effects } }
            : {}),
        });
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
      // The watched logs exactly as getLogs returned them: a retry is judged against THIS
      // evidence, never against a receipt that may be the thing in dispute (Codex #400-fix R7).
      watched: evidenceOf(t),
      // Records already classified, missing only their price (Codex #400-fix M3): exhaustion
      // keeps their route, caller and verdict, marked price.unavailable.
      ...(pendingRecords ? { pendingRecords } : {}),
      // What is known of the tx itself, kept for an unattributed record at exhaustion (#400 review
      // nit): its sender, target and root selector (not the emitting call's).
      ...(tx
        ? {
            txFrom: tx.from ? ethers.getAddress(tx.from) : null,
            txTo: tx.to ? ethers.getAddress(tx.to) : null,
            rootSelector: selectorOf(tx.data),
          }
        : {}),
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
    if (f) byFrame.set(f, [...(byFrame.get(f) ?? []), e.event]);
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
    rec.verdict = evaluate(rs, cfg.roles, rec);
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
            !logs.some(
              l => parsePosition(l.blockNumber) === n && lcEq(String(l.topics?.[0] ?? ""), topic)
            )
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
          got = await chain.getLogs({ address: addr, topics: [topics], blockHash: h.hash });
        } catch {
          throw new Error(
            `block ${n}: logsBloom shows a watched log that getLogs did not return, and the by-hash re-read failed; retrying`
          );
        }
        // raw comparison: a malformed position must not throw here, outside the per-tx isolation
        const fresh = got.filter(g => !logs.some(l => rawLogKey(l) === rawLogKey(g)));
        if (fresh.length) {
          extra.push(...fresh);
          summary.bloomRecovered++;
        }
        if (missing.some(topic => !got.some(g => lcEq(String(g?.topics?.[0] ?? ""), topic))))
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
      let watched = Array.isArray(dl.watched) && dl.watched.length ? dl.watched : null;
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
      await processTxIsolated(
        chain,
        cfg,
        rs,
        ctx,
        store,
        summary,
        dl.txHash,
        txOfEvidence(watched, cfg, dl.blockNumber),
        fin.number,
        dl
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

  // A returned entry that is not even an object cannot be grouped or bloom-checked: it is
  // quarantined at once with its raw value and query, never a reason to stop (Codex follow-up R3).
  const intake = (raw, source) => {
    const ok = [];
    for (const x of raw ?? []) {
      if (x && typeof x === "object" && !Array.isArray(x)) ok.push(x);
      else quarantineRaw(store, ctx, summary, x, source, from, to);
    }
    return ok;
  };
  const aggLogs = intake(
    await pagedLogs(chain, cfg.aggregator, [SIGNERS_COMMITTED()], from, to, cfg.page),
    "agg"
  );
  const spLogs = intake(
    await pagedLogs(chain, cfg.roles.superPaymaster, [spTopics()], from, to, cfg.page),
    "sp"
  );
  const bc = await bloomCheck(chain, cfg, from, to, aggLogs, spLogs, summary);
  const extraAgg = intake(bc.extraAgg, "agg");
  const extraSp = intake(bc.extraSp, "sp");

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
    const t = byTx.get(k) ?? { block: parsePosition(l.blockNumber) ?? NaN, agg: [], sp: [] };
    const list = source === "agg" ? t.agg : t.sp;
    // Grouping never throws on log contents: a malformed position is judged inside the per-tx
    // isolation (Codex follow-up R1). Duplicates (bloom-recovered copies) are dropped by their
    // raw position fields.
    if (!list.some(x => rawLogKey(x) === rawLogKey(l))) list.push(l);
    byTx.set(k, t);
  }
  const ordered = [...byTx.entries()].sort((a, b) => a[1].block - b[1].block);
  for (const [txHash, t] of ordered)
    await processTxIsolated(chain, cfg, rs, ctx, store, summary, txHash, t, fin.number, null);

  const toHdr = await header(chain, to);
  store.setCursor({ block: to, hash: toHdr.hash });
  return summary;
}
