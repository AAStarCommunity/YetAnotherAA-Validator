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

/** Flatten a trace into [{ address, topics, data, aggCall }] in emission order, or null if unsure. */
export function flattenTraceLogs(trace, aggregator) {
  let nextId = 0;
  let unsure = false;
  const walk = (f, aggCall) => {
    if (!f || f.error) return [];
    const here =
      String(f.type).toUpperCase() === "CALL" && lc(f.to) === lc(aggregator) ? nextId++ : aggCall;
    const logs = f.logs || [];
    const calls = f.calls || [];
    if (calls.length && logs.some(l => l.position === undefined || l.position === null))
      unsure = true;
    const at = k => logs.filter(l => Number(l.position ?? calls.length) === k);
    const out = [];
    for (let k = 0; k <= calls.length; k++) {
      for (const l of at(k))
        out.push({ address: l.address, topics: l.topics, data: l.data, aggCall: here });
      if (k < calls.length) out.push(...walk(calls[k], here));
    }
    return out;
  };
  const seq = walk(trace, null);
  return unsure ? null : seq;
}

/**
 * Map receipt logs to aggregator calls. `receiptLogs` are the tx's full receipt logs; each needs a
 * position (`index` or `logIndex`). Returns { aligned, owner: Map(logPosition -> aggCall | null) }.
 */
export function attributeLogs(trace, receiptLogs, aggregator) {
  const owner = new Map();
  if (!trace) return { aligned: false, owner, why: "no trace" };
  const seq = flattenTraceLogs(trace, aggregator);
  if (!seq) return { aligned: false, owner, why: "trace logs lack positions" };
  const rl = [...receiptLogs].sort(
    (a, b) => Number(a.index ?? a.logIndex) - Number(b.index ?? b.logIndex)
  );
  if (seq.length !== rl.length)
    return { aligned: false, owner, why: `trace has ${seq.length} logs, receipt ${rl.length}` };
  for (let i = 0; i < rl.length; i++) {
    if (!same(seq[i], rl[i]))
      return {
        aligned: false,
        owner: new Map(),
        why: `log ${i} differs between trace and receipt`,
      };
    owner.set(Number(rl[i].index ?? rl[i].logIndex), seq[i].aggCall);
  }
  return { aligned: true, owner };
}
