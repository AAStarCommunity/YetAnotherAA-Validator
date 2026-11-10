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
import { evaluate, wantsPrice } from "./rules.mjs";

export const MAX_DEADLETTER_ATTEMPTS = 20;

async function header(chain, tag) {
  const b = await chain.send("eth_getBlockByNumber", [
    typeof tag === "number" ? ethers.toQuantity(tag) : tag,
    false,
  ]);
  if (!b || !b.hash) throw new Error(`block ${tag} unavailable`);
  return { number: Number(b.number), hash: b.hash };
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

/**
 * SP logs of `txHash` that a trace proves were emitted inside a successful CALL into the pinned
 * aggregator (callTracer withLog). Returns a Set of "topics|data" keys, or null with no trace.
 * Co-occurrence in a tx proves nothing; only the call tree does.
 */
async function blsAttributedSpLogs(chain, cfg, txHash) {
  if (typeof chain.send !== "function") return null;
  let trace;
  try {
    trace = await chain.send("debug_traceTransaction", [
      txHash,
      { tracer: "callTracer", tracerConfig: { withLog: true } },
    ]);
  } catch {
    return null;
  }
  if (!trace) return null;
  const sp = cfg.roles.superPaymaster.toLowerCase();
  const agg = cfg.aggregator.toLowerCase();
  const out = new Set();
  const collect = f => {
    if (!f || f.error) return;
    for (const l of f.logs || []) {
      if (String(l.address).toLowerCase() === sp)
        out.add(`${(l.topics || []).join(",").toLowerCase()}|${String(l.data).toLowerCase()}`);
    }
    for (const c of f.calls || []) collect(c);
  };
  const walk = f => {
    if (!f || f.error) return;
    if (String(f.type).toUpperCase() === "CALL" && String(f.to).toLowerCase() === agg)
      return collect(f);
    for (const c of f.calls || []) walk(c);
  };
  walk(trace);
  return out;
}

const spLogKey = l => `${l.topics.join(",").toLowerCase()}|${String(l.data).toLowerCase()}`;

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
    rec.price = {
      before: await readPrice(chain, cfg.roles.superPaymaster, rec.blockNumber - 1),
      after: await readPrice(chain, cfg.roles.superPaymaster, rec.blockNumber),
    };
  }
  return { record: rec };
}

function note(summary, res, rec) {
  if (res === "new") summary.newRecords++;
  if (res === "upgraded") summary.upgraded++;
  if (rec.verdict.flagged && (res === "new" || res === "upgraded")) summary.flagged.push(rec);
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
    flagged: [],
  };

  // Retry dead letters first (a trace, a slot read or an RPC that failed may now answer).
  for (const dl of store.listDeadLetters()) {
    if (dl.attempts >= MAX_DEADLETTER_ATTEMPTS) continue;
    const log = {
      topics: [aggIface.getEvent("SignersCommitted").topicHash, ethers.toBeHex(BigInt(dl.key), 32)],
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

  const aggLogs = await pagedLogs(
    chain,
    cfg.aggregator,
    [aggIface.getEvent("SignersCommitted").topicHash],
    from,
    to,
    cfg.page
  );
  const spTopics = SP_WATCHED_EVENTS.map(n => spIface.getEvent(n).topicHash);
  const spLogs = await pagedLogs(chain, cfg.roles.superPaymaster, [spTopics], from, to, cfg.page);

  const byTx = new Map();
  for (const l of [...aggLogs, ...spLogs]) {
    const t = byTx.get(l.transactionHash) ?? { block: Number(l.blockNumber), agg: [], sp: [] };
    (l.address.toLowerCase() === cfg.aggregator.toLowerCase() ? t.agg : t.sp).push(l);
    byTx.set(l.transactionHash, t);
  }
  const ordered = [...byTx.entries()].sort((a, b) => a[1].block - b[1].block);

  for (const [txHash, t] of ordered) {
    t.sp.sort((a, b) => logPos(a) - logPos(b));
    // SP events of a BLS tx count as that action's effects only when a trace places them inside
    // the aggregator call; everything else is an owner/guardian-route record of its own.
    let attributed = new Set();
    let traced = false;
    if (t.agg.length && t.sp.length) {
      const a = await blsAttributedSpLogs(chain, cfg, txHash);
      if (a) {
        attributed = a;
        traced = true;
      }
    }
    const effects = [];
    const independent = [];
    for (const l of t.sp) {
      const d = decodeSp(l);
      if (!d) continue;
      const ev = { ...d, logIndex: logPos(l) };
      if (t.agg.length && attributed.has(spLogKey(l))) effects.push(ev);
      else independent.push(ev);
    }
    for (const l of t.agg) {
      const out = await blsRecord(chain, cfg, rs, ctx, l, effects, fin.number);
      if (out.record) note(summary, store.putRecord(out.record), out.record);
      else {
        store.putDeadLetter(out.deadLetter);
        summary.deadLetters++;
      }
    }
    if (!independent.length) continue;
    let tx = null;
    try {
      tx = await chain.getTransaction(txHash);
    } catch {
      tx = null;
    }
    for (const e of independent) {
      const rec = {
        route: "owner",
        label: rs.ownerRoute.label,
        event: e.event,
        args: e.args,
        txHash,
        logIndex: e.logIndex,
        blockNumber: t.block,
        from: tx?.from ? ethers.getAddress(tx.from) : null,
        to: tx?.to ? ethers.getAddress(tx.to) : null,
        ruleset: ctx.ruleset,
        seenAt: ctx.now,
      };
      if (t.agg.length) {
        // Same tx as a BLS action, not proven to be its effect: keep it, and say what is unknown.
        rec.routeUncertain = traced
          ? "same tx as a BLS action; the trace places it outside the aggregator call"
          : "same tx as a BLS action; no trace, so whether it is that action's effect is unproven";
      }
      rec.verdict = evaluate(rs, cfg.roles, rec);
      if (wantsPrice(rs, cfg.roles, rec)) {
        rec.price = {
          before: await readPrice(chain, cfg.roles.superPaymaster, t.block - 1),
          after: await readPrice(chain, cfg.roles.superPaymaster, t.block),
        };
      }
      note(summary, store.putRecord(rec), rec);
    }
  }

  const toHdr = await header(chain, to);
  store.setCursor({ block: to, hash: toHdr.hash });
  return summary;
}
