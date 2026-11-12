// The pause job's round (D2, DSR 4019916a). One round, every 10 minutes, under launchd:
//   1. reconcile (reads only, nothing is broadcast): each journalled transaction's receipt; a
//      receipt makes it `included` (its reservation KEPT), a reorged one goes back to `sent`, and
//      only an inclusion at or below the finalized block, on the canonical chain, makes it `final`
//      and moves its cost (execution + OP L1/operator fees) from reserved to spent; then the
//      signer's nonce history;
//   2. extend the operator inventory from SuperPaymaster's OperatorConfigured logs (emitted by the
//      SP PROXY), and the role inventory from RoleConfigured, only over finalized ranges whose
//      getLogs succeeded; a failed range is retried, never skipped;
//   3. pin ONE block B by hash; every read of the round is at B (EIP-1898 for eth_call), and B is
//      re-checked canonical after the reads: a reorg under B voids the round's decisions;
//   4. at B, prove the signer is no privileged identity (fail closed), then for every operator
//      eth_call pauseUnderstakedOperator(op) from the signer and read operators(op).isPaused.
//      OperatorPaused is never decoded (condition 6);
//   5. ONLY if the identity check passed: rebroadcast (or replace, if stuck) what is pending, then
//      send new pauses in turn, reserving gasLimit x maxFee (+ OP fees) against the cumulative
//      per-chain cap (reserved + spent <= cap), the signed bytes journalled before broadcast.
// An understaked operator still unpaused for 2 or more consecutive rounds raises "pause timeout".
//
// Everything outside is injected: `chain` (JSON-RPC), `signer` (address + sign), `persist` (durable
// state write). This file holds no key and does no I/O of its own.
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
const big = s => BigInt(s);

// OP Stack: L1 data fee and operator fee are charged on top of execution gas. They are read from
// the chain's own GasPriceOracle predeploy, never computed here from a formula we would have to
// keep in step with OP upgrades.
export const OP_CHAINS = new Set([10, 11155420]);
export const GAS_PRICE_ORACLE = "0x420000000000000000000000000000000000000F";
const gpo = new ethers.Interface([
  "function getL1Fee(bytes) view returns (uint256)",
  "function getOperatorFee(uint256) view returns (uint256)",
]);

const PENDING = new Set(["signed", "sent"]);
const HELD = new Set(["signed", "sent", "included"]); // reservation held

/** A fresh state. `cap` is the cumulative spend cap in wei for this chain (decimal string). */
export function emptyState({
  chainId,
  signer,
  spProxy,
  registry,
  startBlock,
  registryStartBlock,
  cap,
}) {
  return {
    schema: "aoa-pause-job-state/2",
    chainId,
    signer: lc(signer),
    spProxy: lc(spProxy),
    registry: lc(registry),
    // last block whose logs are fully in the inventory; startBlock - 1 = nothing scanned yet
    // roles from the Registry's OWN deployment block (it may predate SP; Codex R2 P1-3)
    cursor: { operators: startBlock - 1, roles: (registryStartBlock ?? startBlock) - 1 },
    operators: {}, // addr -> { since, understakedRounds }
    roles: {}, // roleId -> first block seen in RoleConfigured
    ledger: { cap: String(cap), spent: "0", reserved: "0", txs: [] },
    alerts: {}, // key -> last alert time (ms), for the re-alert interval
  };
}

/** Problems with the state itself (shape and bookkeeping invariants). Pure. */
/**
 * Problems with the state itself. A budget breach (spent + reserved > cap) is NOT an
 * inconsistency once an inclusion-time OP fee overran a reservation: with { allowOverCap } it is
 * left to overCap(), and the job records the real cost and stops broadcasting (Codex R3 P1).
 */
export function stateProblems(st, { allowOverCap = false } = {}) {
  const p = [];
  if (st?.schema !== "aoa-pause-job-state/2") return ["unknown state schema"];
  const l = st.ledger;
  let reserved = 0n;
  let spent = 0n;
  let seenPending = false;
  l.txs.forEach((t, i) => {
    if (t.nonce !== i) p.push("transaction nonces are not 0, 1, 2, ... in order");
    if (HELD.has(t.status)) reserved += big(t.reserve);
    else if (t.status === "final") spent += big(t.cost);
    else p.push("a transaction has an unknown status");
    // pending transactions are a suffix: nothing included or final after one that is not
    if (PENDING.has(t.status)) seenPending = true;
    else if (seenPending) p.push("an included or final transaction after a pending one");
  });
  if (reserved !== big(l.reserved)) p.push("reserved does not equal the held reservations");
  if (spent !== big(l.spent)) p.push("spent does not equal the final costs");
  if (!allowOverCap && spent + reserved > big(l.cap)) p.push("spent + reserved exceeds the cap");
  return p;
}

/** spent + reserved > cap: the job records it and broadcasts nothing more. */
export function overCap(st) {
  const l = st.ledger;
  return big(l.spent) + big(l.reserved) > big(l.cap);
}

/** Split [from, to] into chunks of at most `size` blocks. Pure. */
export function ranges(from, to, size) {
  const out = [];
  for (let a = from; a <= to; a += size) out.push([a, Math.min(to, a + size - 1)]);
  return out;
}

/**
 * The full cost of a final transaction. `opFees` is { l1Fee, operatorFee } read from the
 * GasPriceOracle at the inclusion block (OP chains only). The receipt's own l1Fee, when present, is
 * taken if larger (never undercount). Pure.
 */
export function costOf(receipt, chainId, opFees = null) {
  const exec = big(receipt.gasUsed) * big(receipt.effectiveGasPrice);
  if (!OP_CHAINS.has(chainId)) return exec;
  if (!opFees) throw new SafeError("an OP receipt needs the GasPriceOracle fees");
  const rl1 = receipt.l1Fee != null ? big(receipt.l1Fee) : 0n;
  const l1 = opFees.l1Fee > rl1 ? opFees.l1Fee : rl1;
  return exec + l1 + opFees.operatorFee;
}

/** The OP fees of `raw` (signed bytes) for `gas` gas at `blockTag`; null on L1. */
async function opFeesAt(st, chain, raw, gas, blockTag) {
  if (!OP_CHAINS.has(st.chainId)) return null;
  // the oracle is given the UNSIGNED serialization (it adds the signature's size itself), so no
  // signed bytes reach the RPC before they are journalled (clestons #432 L1)
  const unsigned = ethers.Transaction.from(raw).unsignedSerialized;
  const c = async (fn, a) =>
    gpo.decodeFunctionResult(
      fn,
      await chain.call({ to: GAS_PRICE_ORACLE, data: gpo.encodeFunctionData(fn, a) }, blockTag)
    )[0];
  return { l1Fee: await c("getL1Fee", [unsigned]), operatorFee: await c("getOperatorFee", [gas]) };
}

/**
 * Extend one inventory (operators or roles) up to the finalized block. The cursor moves past a
 * range only after its getLogs succeeded; the first failure stops the extension for this round.
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
    }
    for (const lg of logs) {
      const n = Number(lg.blockNumber);
      if (which === "operators")
        st.operators[ethers.getAddress(ethers.dataSlice(lg.topics[1], 12))] ??= {
          since: n,
          understakedRounds: 0,
        };
      else st.roles[lc(lg.topics[1])] ??= n;
    }
    st.cursor[which] = b;
  }
  return { ok: true };
}

/** The EIP-1898 block parameter for B: by hash, canonical required. */
const at = B => ({ blockHash: B.hash, requireCanonical: true });

/**
 * Every privileged identity at block B, and whether the signer is one of them. Any read that
 * fails, and any configured role outside the pinned ROLE_* set, fails closed (condition 4).
 */
export async function identityCheck(st, chain, B, roleIds, logChunk = 5000) {
  const call = async (to, iface, fn, args = []) =>
    iface.decodeFunctionResult(
      fn,
      await chain.call({ to, data: iface.encodeFunctionData(fn, args) }, at(B))
    );
  const problems = [];
  const signer = st.signer;
  const pinned = new Set(roleIds.map(lc));
  // the inventory holds finalized roles only; a role configured in (cursor, B] is read here too,
  // for this round only, so a fresh role cannot slip past the check (any failure fails closed);
  // B is re-checked canonical after all reads (runRound), which covers these logs too
  const seen = new Set(Object.keys(st.roles).map(lc));
  try {
    for (const [a, b] of ranges(st.cursor.roles + 1, B.number, logChunk)) {
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
  try {
    await chain.call(
      {
        to: st.spProxy,
        from: st.signer,
        data: spIface.encodeFunctionData("pauseUnderstakedOperator", [op]),
      },
      at(B)
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
    at(B)
  );
  return spIface.decodeFunctionResult("operators", out).isPaused;
}

/** The receipt of any hash ever signed for `t`'s nonce, or null. */
async function receiptOf(chain, t) {
  const ours = new Set(t.hashes.map(lc));
  for (const h of t.hashes) {
    const r = await chain.receipt(h);
    if (!r) continue;
    // a receipt is believed only for a hash we signed, with a plausible gas figure (clestons L2)
    if (!ours.has(lc(r.transactionHash)))
      throw new SafeError("a receipt for a transaction we did not sign");
    if (!(big(r.gasUsed) > 0n) || big(r.gasUsed) > big(t.gasLimit))
      throw new SafeError("a receipt with an implausible gasUsed");
    return r;
  }
  return null;
}

/**
 * Reconcile the journal with the chain. READS ONLY: nothing is signed or broadcast here.
 * Returns alerts; mutates st and persists.
 */
async function reconcile(stLive, chain, persist, finalized) {
  // work on a copy; it replaces the live state only if the result is coherent, so a receipt seen
  // mid-reorg or an RPC failure halfway never persists a state that blocks the next round
  const st = structuredClone(stLive);
  const alerts = [];
  const l = st.ledger;
  const include = (t, r) => {
    t.status = "included";
    t.includedHash = r.transactionHash;
    t.includedBlock = Number(r.blockNumber);
    t.includedBlockHash = r.blockHash;
    t.pendingRounds = 0;
  };
  for (const t of l.txs) {
    if (!HELD.has(t.status)) continue;
    const r = await receiptOf(chain, t);
    if (t.status === "included" && (!r || lc(r.blockHash) !== lc(t.includedBlockHash))) {
      // reorged out (or re-included elsewhere): the reservation stays held throughout
      alerts.push({
        key: `reorg:${t.nonce}`,
        text: `pause of ${t.operator} (nonce ${t.nonce}) left its block in a reorg; resent`,
      });
      t.status = "sent";
      delete t.includedHash;
      delete t.includedBlock;
      delete t.includedBlockHash;
    }
    if (PENDING.has(t.status) && r) include(t, r);
    if (t.status !== "included" || t.includedBlock > finalized) continue;
    // final only at or below finalized AND on the canonical chain
    const blk = await chain.blockByNumber(t.includedBlock);
    if (!blk || lc(blk.hash) !== lc(t.includedBlockHash)) continue; // decided next round
    const raw = t.raws[t.hashes.map(lc).indexOf(lc(t.includedHash))];
    const fees = await opFeesAt(st, chain, raw, big(r.gasUsed), {
      blockHash: t.includedBlockHash,
      requireCanonical: true,
    });
    const cost = costOf(r, st.chainId, fees);
    t.status = "final";
    t.cost = String(cost);
    t.ok = Number(r.status) === 1;
    l.reserved = String(big(l.reserved) - big(t.reserve));
    l.spent = String(big(l.spent) + cost);
    if (cost > big(t.reserve))
      alerts.push({
        key: `overrun:${t.nonce}`,
        text: `pause of ${t.operator} cost ${cost} wei, more than its reservation ${t.reserve}`,
      });
    if (!t.ok)
      alerts.push({
        key: `reverted:${t.nonce}`,
        text: `pause of ${t.operator} reverted on chain (tx ${t.includedHash})`,
      });
  }
  const bad = stateProblems(st, { allowOverCap: true });
  if (bad.length) {
    alerts.push({
      key: "reconcile",
      text: `receipts were inconsistent this round (${bad.join("; ")}); kept the previous journal, retried next round`,
    });
    return alerts;
  }
  stLive.ledger = st.ledger;
  await persist(stLive);
  return alerts;
}

/** Fees for a new or replacing transaction: maxFee = max(2 x baseFee + tip, floor). */
function feesFor(baseFee, tip, floorMaxFee = 0n) {
  let maxFee = baseFee * 2n + tip;
  if (maxFee < floorMaxFee) maxFee = floorMaxFee;
  return maxFee;
}

/** Reservation for gasLimit x maxFee, plus OP fees (x2 margin) for the signed bytes. */
async function reservationFor(st, chain, raw, gasLimit, maxFee) {
  const op = await opFeesAt(st, chain, raw, gasLimit, "latest");
  return gasLimit * maxFee + (op ? 2n * (op.l1Fee + op.operatorFee) : 0n);
}

/**
 * Rebroadcast what is pending; a transaction pending at the start of more than
 * cfg.bumpAfterRounds rounds is first REPLACED at the same nonce (fees x1.25, never below the
 * current 2 x baseFee + tip) when the cap and the fee ceiling allow; whether or not it could be
 * replaced, its current bytes are sent again. Called only after the identity check passed.
 */
async function pushPending(st, { chain, signer, persist, cfg }) {
  const alerts = [];
  const l = st.ledger;
  for (const t of l.txs.filter(x => PENDING.has(x.status))) {
    if ((t.pendingRounds ?? 0) > (cfg.bumpAfterRounds ?? 3)) {
      const a = await replace(st, t, { chain, signer, persist, cfg });
      if (a) alerts.push(a);
    }
    // OP: the L1/operator fees are charged at inclusion and are not bounded by the transaction, so
    // the reservation is re-priced from the oracle before every broadcast and only grows; when the
    // cap cannot cover it the bytes are NOT rebroadcast (a copy already in a mempool may still land:
    // README, residual)
    if (OP_CHAINS.has(st.chainId)) {
      let need;
      try {
        need = await reservationFor(st, chain, t.raw, big(t.gasLimit), big(t.maxFeePerGas));
      } catch (e) {
        alerts.push({ key: `reprice:${t.nonce}`, text: safeText("re-price", e) });
        continue;
      }
      if (need > big(t.reserve)) {
        const extra = need - big(t.reserve);
        const remaining = big(l.cap) - big(l.spent) - big(l.reserved);
        if (extra > remaining) {
          alerts.push({
            key: "cap",
            text: `remaining cap insufficient: re-pricing the pause of ${t.operator} needs ${extra} more wei, ${remaining} left of ${l.cap}; not rebroadcast`,
          });
          continue;
        }
        l.reserved = String(big(l.reserved) + extra);
        t.reserve = String(need);
        await persist(st);
      }
    }
    try {
      await chain.sendRaw(t.raw);
    } catch {
      // "already known" / "replacement underpriced" / "nonce too low": the receipts decide
    }
    if (t.status === "signed") t.status = "sent";
    await persist(st);
  }
  return alerts;
}

async function replace(st, t, { chain, signer, persist, cfg }) {
  let fee;
  try {
    fee = await chain.fees();
  } catch (e) {
    return { key: `replace:${t.nonce}`, text: safeText("replace fees", e) };
  }
  const tip = (big(t.maxPriorityFeePerGas) * 125n) / 100n + 1n;
  const maxFee = feesFor(big(fee.baseFee), tip, (big(t.maxFeePerGas) * 125n) / 100n + 1n);
  if (maxFee > big(cfg.maxFeePerGasCap))
    return {
      key: `stuck:${t.nonce}`,
      text: `pause of ${t.operator} (nonce ${t.nonce}) pending ${t.pendingRounds} rounds; a replacement needs max fee ${maxFee} above the ceiling ${cfg.maxFeePerGasCap}; the current bytes are resent`,
    };
  const tx = {
    type: 2,
    chainId: st.chainId,
    nonce: t.nonce,
    to: st.spProxy,
    data: t.data,
    value: 0n,
    gasLimit: big(t.gasLimit),
    maxFeePerGas: maxFee,
    maxPriorityFeePerGas: tip,
  };
  const raw = await signer.sign(tx);
  let reserve;
  try {
    reserve = await reservationFor(st, chain, raw, big(t.gasLimit), maxFee);
  } catch (e) {
    return { key: `replace:${t.nonce}`, text: safeText("replace reservation", e) };
  }
  const l = st.ledger;
  // the reservation never shrinks: either hash may be the one that lands
  const extra = reserve > big(t.reserve) ? reserve - big(t.reserve) : 0n;
  const remaining = big(l.cap) - big(l.spent) - big(l.reserved);
  if (extra > remaining)
    return {
      key: "cap",
      text: `remaining cap insufficient: replacing the stuck pause of ${t.operator} needs ${extra} more wei, ${remaining} left of ${l.cap}; the current bytes are resent`,
    };
  // durable BEFORE broadcast; every earlier hash stays looked up
  t.hashes.push(ethers.keccak256(raw));
  t.raws.push(raw);
  t.hash = t.hashes[t.hashes.length - 1];
  t.raw = raw;
  t.maxFeePerGas = String(maxFee);
  t.maxPriorityFeePerGas = String(tip);
  l.reserved = String(big(l.reserved) + extra);
  t.reserve = String(big(t.reserve) + extra);
  t.pendingRounds = 0;
  await persist(st);
  return null;
}

/**
 * One round. cfg: { logChunk, gasLimitMax, maxFeePerGasCap, maxPriorityFeePerGas, receiptWaitMs,
 * pollMs, bumpAfterRounds }. Returns { alerts, report } and mutates st (persisting at every
 * durable step).
 */
export async function runRound(st, { chain, signer, persist, cfg }) {
  const alerts = [];
  const sp = stateProblems(st, { allowOverCap: true });
  if (sp.length) throw new SafeError(`state: ${sp.join("; ")}`);
  if (lc(signer.address) !== st.signer)
    throw new SafeError("the keystore is not the state's signer");
  const chainId = Number(await chain.chainId());
  if (chainId !== st.chainId) throw new SafeError(`chain id ${chainId}, expected ${st.chainId}`);

  // 1. reconcile (reads only), then the signer's history: every consumed nonce is one we journalled
  const finalized = Number(await chain.blockNumber("finalized"));
  alerts.push(...(await reconcile(st, chain, persist, finalized)));
  for (const t of st.ledger.txs)
    if (PENDING.has(t.status)) t.pendingRounds = (t.pendingRounds ?? 0) + 1;
  const sp2 = stateProblems(st, { allowOverCap: true });
  if (sp2.length) throw new SafeError(`state after reconcile: ${sp2.join("; ")}`);
  const latestNonce = Number(await chain.nonce(st.signer, "latest"));
  const firstPending = st.ledger.txs.findIndex(t => PENDING.has(t.status));
  const landed = firstPending < 0 ? st.ledger.txs.length : firstPending;
  if (latestNonce < landed || latestNonce > st.ledger.txs.length)
    throw new SafeError(
      `signer nonce ${latestNonce} does not match the journal (${landed} landed of ${st.ledger.txs.length}): another use of the key`
    );
  // every nonce consumed beyond `landed` must be one of OUR journalled transactions: one with no
  // receipt for any hash we signed was taken by a transaction we did not journal (clestons B3)
  for (let n = landed; n < latestNonce; n++) {
    const r = await receiptOf(chain, st.ledger.txs[n]);
    if (!r)
      throw new SafeError(
        `signer nonce ${n} was consumed by a transaction the job did not journal: another use of the key`
      );
  }

  // 2. inventories, finalized only
  for (const which of ["operators", "roles"]) {
    const r = await extend(st, chain, which, finalized, cfg);
    if (!r.ok)
      alerts.push({
        key: `inventory:${which}`,
        text: `${r.why} (blocks ${r.failed[0]}-${r.failed[1]}, retried next round)`,
      });
  }
  await persist(st);

  // 3. one block, by hash, for every read of this round
  const head = await chain.blockByNumber("latest");
  if (!head?.hash) throw new SafeError("no latest block");
  const B = { number: Number(head.number), hash: head.hash };
  let id = await identityCheck(st, chain, B, PINNED_ROLE_IDS, cfg.logChunk);

  // 4. decide per operator
  const decisions = [];
  for (const op of Object.keys(st.operators).sort()) {
    const d = await probe(st, chain, B, op);
    let paused = null;
    if (d === "understaked") {
      try {
        paused = await isPaused(st, chain, B, op);
      } catch (e) {
        alerts.push({ key: `read:${op}`, text: safeText(`isPaused ${op}`, e) });
      }
    }
    decisions.push({ op, d, paused });
  }
  // B must still be canonical after every read; otherwise nothing of this round is acted on
  const again = await chain.blockByNumber(B.number).catch(() => null);
  if (!again || lc(again.hash) !== lc(B.hash)) {
    id = { ok: false, problems: [`block ${B.number} left the canonical chain during the round`] };
    decisions.length = 0;
  }
  const report = { block: B, finalized, cursor: { ...st.cursor }, identity: id, operators: [] };
  if (!id.ok)
    alerts.push({
      key: "identity",
      text: `identity check failed at ${B.number}, nothing broadcast: ${id.problems.join("; ")}`,
    });
  const candidates = [];
  for (const { op, d, paused } of decisions) {
    const o = st.operators[op];
    if (typeof d === "object") alerts.push({ key: `probe:${op}`, text: `${op}: ${d.error}` });
    if (d === "not-configured")
      alerts.push({
        key: `unconfigured:${op}`,
        text: `${op} has OperatorConfigured but is not configured at ${B.number}`,
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

  // 5. broadcast ONLY after the identity check passed at a canonical B
  report.sent = [];
  if (!id.ok) return { alerts, report };
  // a recorded overrun (spent + reserved > cap) stops every broadcast until a new funding
  if (overCap(st)) {
    alerts.push({
      key: "cap",
      text: `remaining cap insufficient: spent ${st.ledger.spent} + reserved ${st.ledger.reserved} exceeds the cap ${st.ledger.cap}; nothing broadcast until a new funding`,
    });
    return { alerts, report };
  }
  // the funding IS the hard bound (DSR 65db9e38: fund exactly the cap, never top up without a go),
  // enforced here (Codex R7 P1): the signer may hold no more than the budget left, cap - spent. A
  // balance above it means a top-up; nothing is broadcast. Total spend can then never exceed the
  // cap, even when an OP inclusion-time fee overruns a reservation.
  let balance;
  try {
    balance = big(await chain.balance(st.signer, at(B)));
  } catch (e) {
    alerts.push({ key: "balance", text: safeText("signer balance", e) });
    return { alerts, report };
  }
  report.balance = String(balance);
  const budgetLeft = big(st.ledger.cap) - big(st.ledger.spent);
  if (balance > budgetLeft) {
    alerts.push({
      key: "topup",
      text: `the signer holds ${balance} wei, more than the budget left (${budgetLeft} of cap ${st.ledger.cap}): a top-up without a DSR go; nothing broadcast`,
    });
    return { alerts, report };
  }
  const pending = () => st.ledger.txs.some(t => PENDING.has(t.status));
  // wait for inclusion (not finality) of whatever is pending, before signing a new nonce
  const waitIncluded = async () => {
    const until = Date.now() + (cfg.receiptWaitMs ?? 90_000);
    while (pending() && Date.now() < until) {
      const t = st.ledger.txs.find(x => PENDING.has(x.status));
      const rc = await receiptOf(chain, t).catch(() => null);
      if (rc) {
        t.status = "included";
        t.includedHash = rc.transactionHash;
        t.includedBlock = Number(rc.blockNumber);
        t.includedBlockHash = rc.blockHash;
        t.pendingRounds = 0;
        await persist(st);
      } else await new Promise(res => setTimeout(res, cfg.pollMs ?? 3000));
    }
  };
  if (pending()) {
    alerts.push(...(await pushPending(st, { chain, signer, persist, cfg })));
    await waitIncluded();
  }
  for (const op of candidates) {
    if (pending()) break;
    if (st.ledger.txs.some(t => HELD.has(t.status) && t.operator === op)) continue; // on its way
    const r = await send(st, { chain, signer, persist, cfg }, op);
    if (r) alerts.push(r);
    if (!st.ledger.txs.some(t => PENDING.has(t.status) && t.operator === op)) {
      // an operator-specific refusal (estimate, gas) moves on; a chain-wide one (cap, fee) stops
      if (r && (r.key === "cap" || r.key.startsWith("fee:"))) break;
      continue;
    }
    report.sent.push(op);
    await waitIncluded();
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
  const maxFee = feesFor(big(fee.baseFee), tip);
  if (maxFee > big(cfg.maxFeePerGasCap))
    return {
      key: `fee:${op}`,
      text: `max fee ${maxFee} above the ceiling ${cfg.maxFeePerGasCap}, not sent`,
    };
  const l = st.ledger;
  const nonce = l.txs.length;
  const tx = {
    type: 2,
    chainId: st.chainId,
    nonce,
    to: st.spProxy,
    data,
    value: 0n,
    gasLimit,
    maxFeePerGas: maxFee,
    maxPriorityFeePerGas: tip,
  };
  const raw = await signer.sign(tx);
  let reserve;
  try {
    reserve = await reservationFor(st, chain, raw, gasLimit, maxFee);
  } catch (e) {
    return { key: `estimate:${op}`, text: safeText(`reservation ${op}`, e) };
  }
  const remaining = big(l.cap) - big(l.spent) - big(l.reserved);
  if (reserve > remaining)
    return {
      key: "cap",
      text: `remaining cap insufficient: ${remaining} wei left of ${l.cap}, a pause needs ${reserve}; not sent, fund a new cap`,
    };
  const hash = ethers.keccak256(raw);
  // durable BEFORE broadcast: a crash after this point resends the same bytes
  l.txs.push({
    nonce,
    operator: op,
    hash,
    hashes: [hash],
    raw,
    raws: [raw],
    data,
    gasLimit: String(gasLimit),
    maxFeePerGas: String(maxFee),
    maxPriorityFeePerGas: String(tip),
    reserve: String(reserve),
    status: "signed",
    pendingRounds: 0,
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
