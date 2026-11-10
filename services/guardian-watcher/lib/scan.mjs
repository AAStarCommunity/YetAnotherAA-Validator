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
    logIndex: Number(log.logIndex),
    rulesetCommit: ctx.rulesetCommit,
    seenAt: ctx.now,
  };
  const r = await rebuildFromAction(
    chain,
    cfg.aggregator,
    log.transactionHash,
    key,
    snapshot,
    cfg.forwarders
  );
  const facts = r.facts;
  if (r.status || !facts || facts.kind === undefined) {
    const v = evaluate(rs, cfg.roles, { ...base, kind: undefined });
    return {
      deadLetter: {
        ...base,
        status: r.status ?? "INCONCLUSIVE",
        reasons: [r.reason, ...(facts?.incomplete ?? [])].filter(Boolean),
        verdict: v,
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
    signers: facts.signers ?? null,
    signersVerified: !!facts.signers,
    anchor: facts.anchor ?? null,
    blockHash: facts.blockHash,
    caller: facts.caller,
    callRoute: facts.route,
    incomplete: facts.incomplete,
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

/**
 * Scan (cursor, finalized] (at most cfg.maxBlocksPerTick blocks) and store what it finds.
 * Returns a summary; throws on an RPC failure (the caller records it and retries next tick, and the
 * cursor has not moved, so nothing is skipped).
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

  // Retry dead letters first (e.g. a trace that was unavailable may now answer).
  for (const dl of store.listDeadLetters()) {
    if (dl.attempts >= MAX_DEADLETTER_ATTEMPTS) continue;
    const log = {
      topics: [aggIface.getEvent("SignersCommitted").topicHash, ethers.toBeHex(BigInt(dl.key), 32)],
      data: ethers.AbiCoder.defaultAbiCoder().encode(["uint256"], [BigInt(dl.signerMask)]),
      transactionHash: dl.txHash,
      blockNumber: dl.blockNumber,
      logIndex: dl.logIndex,
    };
    const out = await blsRecord(chain, cfg, rs, ctx, log, dl.spEvents ?? [], fin.number);
    if (out.record) {
      if (store.putRecord(out.record) === "upgraded") summary.upgraded++;
      if (out.record.verdict.flagged) summary.flagged.push(out.record);
    } else {
      store.putDeadLetter(out.deadLetter);
    }
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
    const spEvents = t.sp
      .sort((a, b) => Number(a.logIndex) - Number(b.logIndex))
      .map(l => ({ ...decodeSp(l), logIndex: Number(l.logIndex) }))
      .filter(x => x.event);
    if (t.agg.length) {
      // BLS-executed: the SP events in the same tx are its effects, recorded as context.
      for (const l of t.agg) {
        const out = await blsRecord(chain, cfg, rs, ctx, l, spEvents, fin.number);
        if (out.record) {
          const res = store.putRecord(out.record);
          if (res === "new") summary.newRecords++;
          if (res === "upgraded") summary.upgraded++;
          if (out.record.verdict.flagged && res !== "same") summary.flagged.push(out.record);
        } else {
          store.putDeadLetter(out.deadLetter);
          summary.deadLetters++;
        }
      }
      continue;
    }
    // No BLS commitment in this tx: every watched SP event is an owner/guardian-route action.
    const tx = await chain.getTransaction(txHash);
    for (const e of spEvents) {
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
        rulesetCommit: ctx.rulesetCommit,
        seenAt: ctx.now,
      };
      rec.verdict = evaluate(rs, cfg.roles, rec);
      if (wantsPrice(rs, cfg.roles, rec)) {
        rec.price = {
          before: await readPrice(chain, cfg.roles.superPaymaster, t.block - 1),
          after: await readPrice(chain, cfg.roles.superPaymaster, t.block),
        };
      }
      const res = store.putRecord(rec);
      if (res === "new") summary.newRecords++;
      if (rec.verdict.flagged && res !== "same") summary.flagged.push(rec);
    }
  }

  const toHdr = await header(chain, to);
  store.setCursor({ block: to, hash: toHdr.hash });
  return summary;
}
