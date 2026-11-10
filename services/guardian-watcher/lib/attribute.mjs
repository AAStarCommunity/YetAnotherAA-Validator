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
const same = (t, r) =>
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
    const here = isCall && lc(f.to) === lc(aggregator) ? nextId++ : aggCall;
    const spHere =
      sp && isCall && lc(f.to) === lc(sp)
        ? {
            from: f.from,
            selector: typeof f.input === "string" ? f.input.slice(0, 10).toLowerCase() : null,
          }
        : spCall;
    const logs = f.logs || [];
    const calls = f.calls || [];
    if (calls.length && logs.some(l => l.position === undefined || l.position === null))
      unsure = true;
    const at = k => logs.filter(l => Number(l.position ?? calls.length) === k);
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
      if (k < calls.length) out.push(...walk(calls[k], here, spHere));
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
  if (!trace) return { aligned: false, owner, spCall, why: "no trace" };
  const seq = flattenTraceLogs(trace, aggregator, sp);
  if (!seq) return { aligned: false, owner, spCall, why: "trace logs lack positions" };
  const rl = [...receiptLogs].sort(
    (a, b) => Number(a.index ?? a.logIndex) - Number(b.index ?? b.logIndex)
  );
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
    owner.set(Number(rl[i].index ?? rl[i].logIndex), seq[i].aggCall);
    spCall.set(Number(rl[i].index ?? rl[i].logIndex), seq[i].spCall);
  }
  return { aligned: true, owner, spCall };
}
