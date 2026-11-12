// The pause job's round (D2, DSR 4019916a). One round, every 10 minutes, under launchd:
//   1. settle the in-flight transaction (at most one) and check the signer's nonce history;
//   2. extend the operator inventory from SuperPaymaster's OperatorConfigured logs (emitted by the
//      SP PROXY), only over finalized ranges whose getLogs succeeded; a failed range is retried,
//      never skipped;
//   3. pin one block B and, at B, prove the signer is no privileged identity (fail closed);
//   4. at B, eth_call pauseUnderstakedOperator(op) from the signer for every operator: success
//      means "configured and understaked"; then read operators(op).isPaused at B. OperatorPaused is
//      never decoded (condition 6): the decision is the call and the flag only;
//   5. for an understaked, unpaused operator, reserve gasLimit x maxFee against the cumulative
//      per-chain cap (reserved + spent <= cap), persist the signed transaction, then broadcast.
// An understaked operator still unpaused for 2 or more consecutive rounds raises "pause timeout".
//
// Everything outside is injected: `chain` (JSON-RPC reads/writes), `signer` (address + sign),
// `persist` (durable state write). This file holds no key and does no I/O of its own.
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { ethers } from "ethers";
import { SafeError, safeText } from "./safe-error.mjs";

// every ABI fragment and the ROLE_* set come from SP at one commit (gen-sp-pin.mjs), never by hand
export const PIN = JSON.parse(
  readFileSync(join(dirname(fileURLToPath(import.meta.url)), "../sp-pin.json"), "utf8")
);
export const spIface = new ethers.Interface(PIN.abi.superPaymaster);
export const regIface = new ethers.Interface(PIN.abi.registry);
export const PINNED_ROLE_IDS = Object.values(PIN.roles);
export const OPERATOR_CONFIGURED = spIface.getEvent("OperatorConfigured").topicHash;
export const ROLE_CONFIGURED = regIface.getEvent("RoleConfigured").topicHash;
const SEL_NOT_CONFIGURED = spIface.getError("OperatorNotConfigured").selector;
const SEL_MEETS = spIface.getError("OperatorMeetsMinimumStake").selector;
const ZERO = ethers.ZeroAddress;
const lc = a => String(a).toLowerCase();
const hex = n => ethers.toQuantity(n);

/** A fresh state. `cap` is the cumulative spend cap in wei for this chain (decimal string). */
export function emptyState({ chainId, signer, spProxy, registry, startBlock, cap }) {
  return {
    schema: "aoa-pause-job-state/1",
    chainId,
    signer: lc(signer),
    spProxy: lc(spProxy),
    registry: lc(registry),
    // last block whose logs are fully in the inventory; startBlock - 1 = nothing scanned yet
    cursor: { operators: startBlock - 1, roles: startBlock - 1 },
    operators: {}, // addr -> { since, understakedRounds }
    roles: {}, // roleId -> first block seen in RoleConfigured
    ledger: { cap: String(cap), spent: "0", reserved: "0", txs: [] },
    alerts: {}, // key -> last alert time (ms), for the re-alert interval
  };
}

const big = s => BigInt(s);

/** Problems with the state itself (shape and bookkeeping invariants). Pure. */
export function stateProblems(st) {
  const p = [];
  if (st?.schema !== "aoa-pause-job-state/1") return ["unknown state schema"];
  const l = st.ledger;
  let reserved = 0n;
  let spent = 0n;
  let open = 0;
  for (const t of l.txs) {
    if (t.status === "signed" || t.status === "sent") {
      reserved += big(t.reserve);
      open++;
    } else if (t.status === "mined") spent += big(t.cost);
    else p.push(`a transaction has an unknown status`);
  }
  if (open > 1) p.push("more than one transaction in flight");
  if (reserved !== big(l.reserved)) p.push("reserved does not equal the open reservations");
  if (spent !== big(l.spent)) p.push("spent does not equal the mined costs");
  if (spent + reserved > big(l.cap)) p.push("spent + reserved exceeds the cap");
  l.txs.forEach((t, i) => {
    if (t.nonce !== i) p.push("transaction nonces are not 0, 1, 2, ... in order");
  });
  return p;
}

/** Split [from, to] into chunks of at most `size` blocks. Pure. */
export function ranges(from, to, size) {
  const out = [];
  for (let a = from; a <= to; a += size) out.push([a, Math.min(to, a + size - 1)]);
  return out;
}

/**
 * Extend one inventory (operators or roles) up to the finalized block. The cursor moves past a
 * range only after its getLogs succeeded; the first failure stops the extension for this round.
 * Returns { ok, failed } and mutates st.
 */
async function extend(st, chain, which, finalized, cfg) {
  const address = which === "operators" ? st.spProxy : st.registry;
  const topic = which === "operators" ? OPERATOR_CONFIGURED : ROLE_CONFIGURED;
  for (const [a, b] of ranges(st.cursor[which] + 1, finalized, cfg.logChunk)) {
    let logs;
    try {
      logs = await chain.getLogs({ address, topics: [topic], fromBlock: hex(a), toBlock: hex(b) });
    } catch (e) {
      return { ok: false, failed: [a, b], why: safeText(`getLogs ${which}`, e) };
    }
    for (const lg of logs) {
      if (lc(lg.address) !== address || lg.topics?.[0] !== topic || lg.removed)
        return { ok: false, failed: [a, b], why: `getLogs ${which}: a log outside the filter` };
      const n = Number(lg.blockNumber);
      if (!(n >= a && n <= b))
        return { ok: false, failed: [a, b], why: `getLogs ${which}: a log outside the range` };
      const key = lc(ethers.dataSlice(lg.topics[1], 12));
      if (which === "operators")
        st.operators[ethers.getAddress(key)] ??= { since: n, understakedRounds: 0 };
      else st.roles[lg.topics[1]] ??= n;
    }
    st.cursor[which] = b;
  }
  return { ok: true };
}

/**
 * Every privileged identity at block B, and whether the signer is one of them. Any read that
 * fails, and any configured role outside the pinned ROLE_* set, fails closed (condition 4).
 * `roleIds` is the pinned set (roles.json, derived from the Registry source at the pin).
 */
export async function identityCheck(st, chain, B, roleIds, logChunk = 5000) {
  const tag = hex(B);
  const call = async (to, iface, fn, args = []) => {
    const out = await chain.call({ to, data: iface.encodeFunctionData(fn, args) }, tag);
    return iface.decodeFunctionResult(fn, out);
  };
  const problems = [];
  const signer = st.signer;
  const pinned = new Set(roleIds.map(lc));
  // the inventory holds finalized roles only; a role configured in (cursor, B] is read here too,
  // for this round only, so a fresh role cannot slip past the check (any failure fails closed)
  const seen = new Set(Object.keys(st.roles).map(lc));
  try {
    for (const [a, b] of ranges(st.cursor.roles + 1, B, logChunk)) {
      const logs = await chain.getLogs({
        address: st.registry,
        topics: [ROLE_CONFIGURED],
        fromBlock: hex(a),
        toBlock: hex(b),
      });
      for (const lg of logs) {
        if (lc(lg.address) !== st.registry || lg.topics?.[0] !== ROLE_CONFIGURED)
          throw new SafeError("a role log outside the filter");
        if (!lg.removed) seen.add(lc(lg.topics[1]));
      }
    }
  } catch (e) {
    return { ok: false, problems: [safeText("identity: recent RoleConfigured", e)] };
  }
  for (const id of seen)
    if (!pinned.has(id))
      problems.push(`role ${id} is configured on chain but not in the pinned ROLE_* set`);
  const named = [];
  try {
    const reg = lc((await call(st.spProxy, spIface, "REGISTRY"))[0]);
    if (reg !== st.registry)
      problems.push("SuperPaymaster.REGISTRY() is not the configured Registry");
    for (const fn of ["owner", "pendingOwner", "guardian", "BLS_AGGREGATOR"])
      named.push([`SuperPaymaster.${fn}`, lc((await call(st.spProxy, spIface, fn))[0])]);
    for (const fn of ["owner", "pendingOwner", "blsAggregator"])
      named.push([`Registry.${fn}`, lc((await call(st.registry, regIface, fn))[0])]);
    for (const id of new Set([...roleIds.map(lc), ...seen])) {
      if ((await call(st.registry, regIface, "hasRole", [id, signer]))[0])
        problems.push(`the signer holds role ${id}`);
      const cfg = (await call(st.registry, regIface, "getRoleConfig", [id]))[0];
      named.push([`Registry role ${id} owner`, lc(cfg.owner)]);
    }
    if ((await call(st.registry, regIface, "isReputationSource", [signer]))[0])
      problems.push("the signer is a reputation source");
  } catch (e) {
    return { ok: false, problems: [safeText("identity read", e)] };
  }
  for (const [what, a] of named)
    if (a === signer && a !== lc(ZERO)) problems.push(`the signer is ${what}`);
  return { ok: problems.length === 0, problems };
}

/**
 * The pause decision for one operator at B, from the call and the flag only.
 * Returns "understaked" | "meets" | "not-configured" | { error }.
 */
export async function probe(st, chain, B, op) {
  const tag = hex(B);
  try {
    await chain.call(
      {
        to: st.spProxy,
        from: st.signer,
        data: spIface.encodeFunctionData("pauseUnderstakedOperator", [op]),
      },
      tag
    );
  } catch (e) {
    const data = revertData(e);
    if (data === SEL_MEETS) return "meets";
    if (data === SEL_NOT_CONFIGURED) return "not-configured";
    return { error: safeText("probe", e) };
  }
  return "understaked";
}

/** The revert data of a failed eth_call, when the error carries exactly a 4-byte selector. */
export function revertData(e) {
  for (const d of [e?.data, e?.info?.error?.data, e?.error?.data])
    if (typeof d === "string" && /^0x[0-9a-fA-F]{8}$/.test(d)) return d.toLowerCase();
  return null;
}

async function isPaused(st, chain, B, op) {
  const out = await chain.call(
    { to: st.spProxy, data: spIface.encodeFunctionData("operators", [op]) },
    hex(B)
  );
  return spIface.decodeFunctionResult("operators", out).isPaused;
}

/**
 * Settle the in-flight transaction, if any. Every hash ever signed for its nonce is looked up (a
 * replacement may be the one that mined). Not mined: the current bytes are sent again; and at the
 * start of a round (`bump`), after cfg.bumpAfterRounds rounds pending, it is REPLACED at the same
 * nonce with fees x1.25 (at least the current 2 x baseFee + tip), the extra reservation held against
 * the cap first and the new bytes journalled before broadcast. Returns an alert or null.
 */
async function settle(st, chain, persist, { signer, cfg, bump = false } = {}) {
  const t = st.ledger.txs.find(x => x.status === "signed" || x.status === "sent");
  if (!t) return null;
  const hashes = t.hashes ?? [t.hash];
  let r = null;
  try {
    for (const h of hashes) {
      r = await chain.receipt(h);
      if (r) break;
    }
  } catch (e) {
    return { key: "receipt", text: safeText("receipt", e) };
  }
  if (r) {
    const cost = big(r.gasUsed) * big(r.effectiveGasPrice);
    t.status = "mined";
    t.minedHash = r.transactionHash;
    t.cost = String(cost);
    t.ok = Number(r.status) === 1;
    t.block = Number(r.blockNumber);
    st.ledger.reserved = String(big(st.ledger.reserved) - big(t.reserve));
    st.ledger.spent = String(big(st.ledger.spent) + cost);
    await persist(st);
    return t.ok
      ? null
      : {
          key: `reverted:${t.operator}`,
          text: `pause of ${t.operator} reverted on chain (tx ${r.transactionHash})`,
        };
  }
  if (bump) {
    t.pendingRounds = (t.pendingRounds ?? 0) + 1;
    if (t.pendingRounds > (cfg.bumpAfterRounds ?? 3)) {
      const a = await replace(st, t, { chain, signer, persist, cfg });
      if (a) return a;
    }
  }
  // not mined: send the CURRENT signed bytes again (idempotent; the reservation stays)
  try {
    await chain.sendRaw(t.raw);
  } catch {
    // "already known" / "nonce too low" and the like: the receipts decide
  }
  if (t.status === "signed") t.status = "sent";
  await persist(st);
  return null;
}

async function replace(st, t, { chain, signer, persist, cfg }) {
  let fee;
  try {
    fee = await chain.fees();
  } catch (e) {
    return { key: `replace:${t.operator}`, text: safeText("replace fees", e) };
  }
  const tip = (big(t.maxPriorityFeePerGas) * 125n) / 100n + 1n;
  let maxFee = (big(t.maxFeePerGas) * 125n) / 100n + 1n;
  const floor = big(fee.baseFee) * 2n + tip;
  if (maxFee < floor) maxFee = floor;
  if (maxFee > big(cfg.maxFeePerGasCap))
    return {
      key: `stuck:${t.operator}`,
      text: `pause of ${t.operator} (nonce ${t.nonce}) pending ${t.pendingRounds} rounds; a replacement needs max fee ${maxFee} above the cap ${cfg.maxFeePerGasCap}`,
    };
  const reserve = big(t.gasLimit) * maxFee;
  const extra = reserve - big(t.reserve);
  const l = st.ledger;
  const remaining = big(l.cap) - big(l.spent) - big(l.reserved);
  if (extra > remaining)
    return {
      key: "cap",
      text: `remaining cap insufficient: replacing the stuck pause of ${t.operator} needs ${extra} more wei, ${remaining} left of ${l.cap}`,
    };
  const raw = await signer.sign({
    type: 2,
    chainId: st.chainId,
    nonce: t.nonce,
    to: st.spProxy,
    data: t.data,
    value: 0n,
    gasLimit: big(t.gasLimit),
    maxFeePerGas: maxFee,
    maxPriorityFeePerGas: tip,
  });
  // durable BEFORE broadcast; every earlier hash stays looked up
  t.hashes = [...(t.hashes ?? [t.hash]), ethers.keccak256(raw)];
  t.hash = t.hashes[t.hashes.length - 1];
  t.raw = raw;
  t.maxFeePerGas = String(maxFee);
  t.maxPriorityFeePerGas = String(tip);
  l.reserved = String(big(l.reserved) + extra);
  t.reserve = String(reserve);
  t.pendingRounds = 0;
  await persist(st);
  return null;
}

/**
 * One round. cfg: { logChunk, gasLimitMax, maxFeePerGasCap, maxPriorityFeePerGas }.
 * Returns { alerts, report } and mutates st (persisting at every durable step).
 */
export async function runRound(st, { chain, signer, persist, cfg }) {
  const alerts = [];
  const sp = stateProblems(st);
  if (sp.length) throw new SafeError(`state: ${sp.join("; ")}`);
  if (lc(signer.address) !== st.signer)
    throw new SafeError("the keystore is not the state's signer");
  const chainId = Number(await chain.chainId());
  if (chainId !== st.chainId) throw new SafeError(`chain id ${chainId}, expected ${st.chainId}`);

  // 1. in-flight transaction, then the signer's history: every consumed nonce is one we journalled
  const s = await settle(st, chain, persist, { signer, cfg, bump: true });
  if (s) alerts.push(s);
  const latestNonce = Number(await chain.nonce(st.signer, "latest"));
  const mined = st.ledger.txs.filter(t => t.status === "mined").length;
  const open = st.ledger.txs.length - mined;
  if (latestNonce < mined || latestNonce > mined + open)
    throw new SafeError(
      `signer nonce ${latestNonce} does not match the journal (${mined} mined, ${open} in flight): another use of the key`
    );

  // 2. inventories, finalized only
  const finalized = Number(await chain.blockNumber("finalized"));
  for (const which of ["operators", "roles"]) {
    const r = await extend(st, chain, which, finalized, cfg);
    if (!r.ok)
      alerts.push({
        key: `inventory:${which}`,
        text: `${r.why} (blocks ${r.failed[0]}-${r.failed[1]}, retried next round)`,
      });
  }
  await persist(st);

  // 3. one block for every read of this round
  const B = Number(await chain.blockNumber("latest"));
  const id = await identityCheck(st, chain, B, PINNED_ROLE_IDS, cfg.logChunk);
  const report = { block: B, finalized, cursor: { ...st.cursor }, identity: id, operators: [] };
  if (!id.ok)
    alerts.push({
      key: "identity",
      text: `identity check failed at ${B}, nothing sent: ${id.problems.join("; ")}`,
    });

  // 4. decide per operator
  const candidates = [];
  for (const op of Object.keys(st.operators).sort()) {
    const o = st.operators[op];
    const d = await probe(st, chain, B, op);
    let paused = null;
    if (d === "understaked") {
      try {
        paused = await isPaused(st, chain, B, op);
      } catch (e) {
        alerts.push({ key: `read:${op}`, text: safeText(`isPaused ${op}`, e) });
      }
    }
    if (typeof d === "object") alerts.push({ key: `probe:${op}`, text: `${op}: ${d.error}` });
    if (d === "not-configured")
      alerts.push({
        key: `unconfigured:${op}`,
        text: `${op} has OperatorConfigured but is not configured at ${B}`,
      });
    const understakedUnpaused = d === "understaked" && paused === false;
    o.understakedRounds = understakedUnpaused ? o.understakedRounds + 1 : 0;
    if (o.understakedRounds >= 2)
      alerts.push({
        key: `timeout:${op}`,
        text: `pause timeout: ${op} understaked and unpaused for ${o.understakedRounds} rounds`,
      });
    if (understakedUnpaused) candidates.push(op);
    report.operators.push({
      operator: op,
      decision: typeof d === "object" ? "error" : d,
      paused,
      understakedRounds: o.understakedRounds,
    });
  }
  await persist(st);

  // 5. send in turn, one transaction in flight at most: each must be mined (receipt within
  // cfg.receiptWaitMs) before the next is signed; one that is not stays in flight for next round
  report.sent = [];
  if (id.ok) {
    for (const op of candidates) {
      if (st.ledger.txs.some(t => t.status !== "mined")) break;
      const r = await send(st, { chain, signer, persist, cfg }, op);
      if (r) {
        alerts.push(r);
        if (!st.ledger.txs.some(t => t.status !== "mined" && t.operator === op)) break; // not signed
      }
      report.sent.push(op);
      const until = Date.now() + (cfg.receiptWaitMs ?? 90_000);
      while (st.ledger.txs.some(t => t.status !== "mined") && Date.now() < until) {
        const sa = await settle(st, chain, persist);
        if (sa) alerts.push(sa);
        if (st.ledger.txs.some(t => t.status !== "mined"))
          await new Promise(res => setTimeout(res, cfg.pollMs ?? 3000));
      }
      if (st.ledger.txs.some(t => t.status !== "mined")) break;
    }
  }
  return { alerts, report };
}

async function send(st, { chain, signer, persist, cfg }, op) {
  const data = spIface.encodeFunctionData("pauseUnderstakedOperator", [op]);
  let gas;
  let fee;
  try {
    gas = big(await chain.estimateGas({ from: st.signer, to: st.spProxy, data }));
    fee = await chain.fees();
  } catch (e) {
    return { key: `estimate:${op}`, text: safeText(`estimate ${op}`, e) };
  }
  const gasLimit = (gas * 12n) / 10n;
  if (gasLimit > big(cfg.gasLimitMax))
    return {
      key: `gas:${op}`,
      text: `gas ${gasLimit} above the limit ${cfg.gasLimitMax}, not sent`,
    };
  const tip = big(cfg.maxPriorityFeePerGas);
  const maxFee = big(fee.baseFee) * 2n + tip;
  if (maxFee > big(cfg.maxFeePerGasCap))
    return {
      key: `fee:${op}`,
      text: `max fee ${maxFee} above the cap ${cfg.maxFeePerGasCap}, not sent`,
    };
  const reserve = gasLimit * maxFee;
  const l = st.ledger;
  const remaining = big(l.cap) - big(l.spent) - big(l.reserved);
  if (reserve > remaining)
    return {
      key: "cap",
      text: `remaining cap insufficient: ${remaining} wei left of ${l.cap}, a pause needs ${reserve}; not sent, fund a new cap`,
    };
  const nonce = l.txs.length;
  const raw = await signer.sign({
    type: 2,
    chainId: st.chainId,
    nonce,
    to: st.spProxy,
    data,
    value: 0n,
    gasLimit,
    maxFeePerGas: maxFee,
    maxPriorityFeePerGas: tip,
  });
  const hash = ethers.keccak256(raw);
  // durable BEFORE broadcast: a crash after this point resends the same bytes
  l.txs.push({
    nonce,
    operator: op,
    hash,
    hashes: [hash],
    raw,
    data,
    gasLimit: String(gasLimit),
    maxFeePerGas: String(maxFee),
    maxPriorityFeePerGas: String(tip),
    reserve: String(reserve),
    status: "signed",
  });
  l.reserved = String(big(l.reserved) + reserve);
  await persist(st);
  try {
    await chain.sendRaw(raw);
  } catch (e) {
    return { key: `send:${op}`, text: `${safeText(`send ${op}`, e)} (kept; resent next round)` };
  }
  l.txs[nonce].status = "sent";
  await persist(st);
  return null;
}
