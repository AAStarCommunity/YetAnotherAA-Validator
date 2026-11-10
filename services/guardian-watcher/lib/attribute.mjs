// Attribution of SuperPaymaster logs to the BLS action that caused them (M0 §5.2), from a
// callTracer trace (withLog). Pure: trace + receipt logs in, mapping out.
//
// The trace is flattened in execution order (each frame's logs interleaved with its child calls by
// `position`, reverted frames dropped with their whole subtree, as the receipt drops their logs) and
// must align 1:1 with the receipt's logs (address, topics, data). Only then does each receipt log
// get an owner: the nearest enclosing error-free CALL into the pinned aggregator. Any doubt - no
// trace, a log without `position` in a frame that has subcalls, a length or content mismatch -
// returns aligned = false, and nothing is attributed.

const lc = x => String(x).toLowerCase();

/**
 * Scope (M0 §5.2a): these checks defend against an RPC that is honest but inconsistent, lagging or
 * only partly supporting the tracer, and against client format differences. They do not defend
 * against an RPC that fabricates a well-formed trace: such an RPC could equally omit events from
 * getLogs. The RPC is a deployment trust assumption (operator-chosen node).
 */

const isAddr = a => /^0x[0-9a-fA-F]{40}$/.test(a);

/** A well-formed log: 20-byte address, at most four 32-byte topics, even-length hex data. */
export function validLog(l) {
  return (
    !!l &&
    typeof l.address === "string" &&
    /^0x[0-9a-fA-F]{40}$/.test(l.address) &&
    Array.isArray(l.topics) &&
    l.topics.length <= 4 &&
    l.topics.every(t => typeof t === "string" && /^0x[0-9a-fA-F]{64}$/.test(t)) &&
    typeof l.data === "string" &&
    /^0x([0-9a-fA-F]{2})*$/.test(l.data)
  );
}

/** A log position: a non-negative safe integer, or a decimal / 0x-hex string of one. */
export function parsePosition(v) {
  if (typeof v === "number") return Number.isSafeInteger(v) && v >= 0 ? v : null;
  if (typeof v !== "string" || !/^(0x[0-9a-fA-F]+|[0-9]+)$/.test(v)) return null;
  const n = Number(v);
  return Number.isSafeInteger(n) ? n : null;
}

/** A receipt / getLogs log's position (`index` in ethers v6, `logIndex` elsewhere); both present
 * must agree. null when absent, malformed or contradictory. */
export function receiptPos(l) {
  const has = k => l?.[k] !== undefined && l?.[k] !== null;
  const a = has("index") ? parsePosition(l.index) : undefined;
  const b = has("logIndex") ? parsePosition(l.logIndex) : undefined;
  if (a === null || b === null) return null;
  if (a !== undefined && b !== undefined && a !== b) return null;
  return a ?? b ?? null;
}

const same = (t, r) =>
  validLog(t) &&
  validLog(r) &&
  lc(t.address) === lc(r.address) &&
  lc(t.data) === lc(r.data) &&
  (t.topics || []).length === (r.topics || []).length &&
  (t.topics || []).every((x, i) => lc(x) === lc(r.topics[i]));

/**
 * Flatten a trace into [{ address, topics, data, aggCall, spCall }] in emission order, or null if
 * unsure. spCall is the nearest enclosing error-free CALL into `sp` (the SuperPaymaster proxy):
 * { from, selector } of the call that emitted the log, i.e. who called SP and which function
 * (#400 M1). A DELEGATECALL from SP into its own module is not a new entry and is looked through.
 */
export function flattenTraceLogs(trace, aggregator, sp) {
  let nextId = 0;
  let unsure = false;
  const walk = (f, aggCall, spCall) => {
    if (!f || f.error) return [];
    const isCall = String(f.type).toUpperCase() === "CALL";
    // A frame's addresses are used for attribution: malformed ones make the trace unusable rather
    // than throwing later (#400 review L1).
    const addrOk = a => a === undefined || a === null || (typeof a === "string" && isAddr(a));
    if (!addrOk(f.from) || !addrOk(f.to)) unsure = true;
    const here = isCall && lc(f.to) === lc(aggregator) ? nextId++ : aggCall;
    const spHere =
      sp && isCall && lc(f.to) === lc(sp)
        ? {
            from: f.from,
            selector: typeof f.input === "string" ? f.input.slice(0, 10).toLowerCase() : null,
          }
        : spCall;
    const logs = Array.isArray(f.logs) ? f.logs : [];
    const calls = Array.isArray(f.calls) ? f.calls : [];
    // Children first, in order (aggregator call ids stay in execution order): their surviving
    // logs decide whether a positionless log here is ambiguous.
    const childOut = calls.map(c => walk(c, here, spHere));
    const missing = l => l.position === undefined || l.position === null;
    // A log without `position` is placed after the children. That is unambiguous only when no
    // child subtree has a surviving log (geth before positions existed: Codex #400-fix R11).
    if (logs.some(missing) && childOut.some(o => o.length)) unsure = true;
    // An explicit position must place the log between child calls: an integer in
    // [0, calls.length], given as a number or a decimal/0x string (no booleans, arrays, empty
    // strings), and a frame's positions never decrease in emission order. Anything else is a
    // malformed trace, never silently repaired (Codex #400-fix R9, R10).
    let prev = 0;
    for (const l of logs) {
      if (missing(l)) continue;
      const p = parsePosition(l.position);
      if (p === null || p > calls.length || p < prev) unsure = true;
      else prev = p;
    }
    const at = k =>
      logs.filter(l => (missing(l) ? k === calls.length : parsePosition(l.position) === k));
    const out = [];
    for (let k = 0; k <= calls.length; k++) {
      for (const l of at(k))
        out.push({
          address: l.address,
          topics: l.topics,
          data: l.data,
          aggCall: here,
          spCall: spHere,
        });
      if (k < calls.length) out.push(...childOut[k]);
    }
    return out;
  };
  const seq = walk(trace, null, null);
  return unsure ? null : seq;
}

/**
 * Map receipt logs to aggregator calls and to the SP call that emitted them. `receiptLogs` are the
 * tx's full receipt logs; each needs a position (`index` or `logIndex`). Returns
 * { aligned, owner: Map(logPosition -> aggCall | null), spCall: Map(logPosition -> {from, selector} | null) }.
 */
export function attributeLogs(trace, receiptLogs, aggregator, sp) {
  const owner = new Map();
  const spCall = new Map();
  if (!trace || typeof trace !== "object")
    return { aligned: false, owner, spCall, why: "no trace" };
  // Every receipt log needs its own position, strictly parsed, and the tx's logs are contiguous
  // (receipt indices are block-global, so the first may be nonzero): a duplicated, malformed or
  // missing one would let a later log's frame overwrite an earlier one's (Codex #400-fix R8, R11).
  const pos = receiptLogs.map(receiptPos);
  const valid = pos.every(p => p !== null) && new Set(pos).size === pos.length;
  if (!valid || (pos.length && Math.max(...pos) - Math.min(...pos) + 1 !== pos.length))
    return { aligned: false, owner, spCall, why: "receipt log positions invalid or duplicated" };
  const seq = flattenTraceLogs(trace, aggregator, sp);
  if (!seq) return { aligned: false, owner, spCall, why: "trace logs lack positions" };
  const rl = [...receiptLogs].sort((a, b) => receiptPos(a) - receiptPos(b));
  if (seq.length !== rl.length)
    return {
      aligned: false,
      owner,
      spCall,
      why: `trace has ${seq.length} logs, receipt ${rl.length}`,
    };
  for (let i = 0; i < rl.length; i++) {
    if (!same(seq[i], rl[i]))
      return {
        aligned: false,
        owner: new Map(),
        spCall: new Map(),
        why: `log ${i} differs between trace and receipt`,
      };
    owner.set(receiptPos(rl[i]), seq[i].aggCall);
    spCall.set(receiptPos(rl[i]), seq[i].spCall);
  }
  return { aligned: true, owner, spCall };
}
