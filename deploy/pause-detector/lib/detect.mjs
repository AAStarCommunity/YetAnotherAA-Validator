// The rc.8 pause DETECTOR's round (DSR: "detect, then act by hand"). It is D2's read path
// (deploy/pause-job @2da78342) with every send path removed: no key, no keystore, no signing, no
// broadcast. A person pauses, with the exact command the alert gives.
//
// One round, hourly under launchd:
//   1. extend the operator inventory from the SP proxy's OperatorConfigured logs, finalized ranges
//      only; the cursor moves past a range only after its getLogs succeeded (a failure is retried
//      next round, never skipped);
//   2. pin ONE block B by hash; every read of the round is at B (EIP-1898, requireCanonical);
//   3. at B, the deployment identity: SP.REGISTRY() is the configured Registry, the EIP-1967
//      implementation slot of BOTH proxies (SP and Registry) holds the configured implementation,
//      and every proxy's and implementation's code hashes to the configured value. Any mismatch or failed read: nothing of
//      the round is reported as clear;
//   4. operators configured in (cursor, B] are read for this round too (not persisted);
//   5. per operator at B: operators(op).{isConfigured,isPaused}, and the three Registry reads of
//      SuperPaymasterStorage._hasEffectiveSuperStake (hasRole, getRoleConfig.minStake,
//      getEffectiveStake), cross-checked with an eth_call of pauseUnderstakedOperator(op). A read
//      that fails, or a cross-check that disagrees, is "unknown", never "clear";
//   6. B is re-checked canonical after every read; if it left the chain, the round is unknown.
//
// Everything outside is injected: `chain` (read-only JSON-RPC). This file does no I/O.
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { ethers } from "ethers";
import { SafeError, safeText } from "../../pause-job/lib/safe-error.mjs";

// the ABI fragments and the ROLE_* set come from SP at one commit (gen-sp-pin.mjs), never by hand
export const PIN = JSON.parse(
  readFileSync(join(dirname(fileURLToPath(import.meta.url)), "../../pause-job/sp-pin.json"), "utf8")
);
export const spIface = new ethers.Interface(PIN.abi.superPaymaster);
export const regIface = new ethers.Interface(PIN.abi.registry);
export const ROLE_PAYMASTER_SUPER = PIN.roles.ROLE_PAYMASTER_SUPER;
export const OPERATOR_CONFIGURED = spIface.getEvent("OperatorConfigured").topicHash;
const SEL_NOT_CONFIGURED = spIface.getError("OperatorNotConfigured").selector;
const SEL_MEETS = spIface.getError("OperatorMeetsMinimumStake").selector;
// EIP-1967: bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1)
export const IMPL_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";
const lc = a => String(a).toLowerCase();
const hex = n => ethers.toQuantity(n);

/** The most blocks above finalized whose ancestry a round walks by hash. */
export const MAX_UNFINALIZED = 2048;
/** The most getLogs chunks one scan may make (a full rescan of Sepolia at logChunk 5000 is ~400). */
export const MAX_CHUNKS = 200_000;
const height = (n, what) => {
  if (!Number.isSafeInteger(n) || n < 0) throw new SafeError(`${what} is not a block number`);
  return n;
};

/**
 * Reset state times after `now` (a clock that was ahead): lastFullScan to 0, alert stamps to 0.
 * Returns whether anything changed. Mutates st.
 */
export function normalizeClock(st, now) {
  let changed = false;
  if (st.lastFullScan > now) {
    st.lastFullScan = 0;
    changed = true;
  }
  for (const k of Object.keys(st.alerts))
    if (st.alerts[k] > now) {
      st.alerts[k] = 0;
      changed = true;
    }
  return changed;
}

/** A fresh state, bound to { chainId, spProxy, startBlock }. */
export function emptyState({ chainId, spProxy, startBlock }) {
  return {
    schema: "aoa-pause-detector-state/1",
    chainId,
    spProxy: lc(spProxy),
    startBlock,
    cursor: startBlock - 1, // last block whose OperatorConfigured logs are in the inventory
    lastFullScan: 0, // ms of the last successful rescan from startBlock (daily)
    operators: {}, // checksummed addr -> first block seen (only ever grows: a superset is safe)
    disputed: {}, // block -> hash: blocks whose by-hash and by-range answers differed, until they agree
    alerts: {}, // key -> last alert time (ms)
  };
}

const plainObject = o => o !== null && typeof o === "object" && !Array.isArray(o); // the state is JSON: an object or an array

/** Problems of a loaded state against the config it must belong to. Pure. */
export function stateProblems(st, cfg) {
  if (st?.schema !== "aoa-pause-detector-state/1") return ["unknown state schema"];
  const p = [];
  if (st.chainId !== cfg.chainId) p.push("the state belongs to another chain");
  if (st.spProxy !== lc(cfg.spProxy)) p.push("the state belongs to another SuperPaymaster");
  if (st.startBlock !== cfg.startBlock) p.push("the state has another startBlock");
  if (!Number.isSafeInteger(st.cursor) || st.cursor < st.startBlock - 1)
    p.push("the state cursor is not a block at or after startBlock - 1");
  if (!Number.isFinite(st.lastFullScan) || st.lastFullScan < 0)
    p.push("the state has no lastFullScan time");
  // a JSON array here would silently drop every operator on the next write (Codex R1 P1-4)
  if (!plainObject(st.operators)) p.push("the state's operators is not a plain map");
  else
    for (const [k, v] of Object.entries(st.operators)) {
      let ok = false;
      try {
        ok = ethers.getAddress(k) === k;
      } catch {
        ok = false;
      }
      // (not bounded by the cursor: a disagreement moves the cursor back below known operators)
      if (!ok || !Number.isSafeInteger(v) || v < st.startBlock) {
        p.push("the state's operators has an entry that is not <checksummed address>: <block>");
        break;
      }
    }
  if (!plainObject(st.disputed)) p.push("the state's disputed is not a plain map");
  else if (
    Object.entries(st.disputed).some(
      ([k, v]) => !/^[0-9]+$/.test(k) || Number(k) < st.startBlock || !HASH32.test(String(v))
    )
  )
    p.push("the state's disputed has an entry that is not <block>: <hash>");
  if (!plainObject(st.alerts)) p.push("the state's alerts is not a plain map");
  else if (Object.values(st.alerts).some(v => !Number.isFinite(v)))
    p.push("the state's alerts has a time that is not a number");
  return p;
}

/** Split [from, to] into chunks of at most `size` blocks. Pure. */
export function ranges(from, to, size) {
  // heights come from an RPC answer: never trust them to bound a loop (Codex R3 P2)
  if (![from, to, size].every(Number.isSafeInteger) || size < 1)
    throw new SafeError("a block range is not made of block numbers");
  if (to >= from && (to - from) / size > MAX_CHUNKS)
    throw new SafeError(`a block range of ${to - from + 1} blocks is too many getLogs calls`);
  const out = [];
  for (let a = from; a <= to; a += size) out.push([a, Math.min(to, a + size - 1)]);
  return out;
}

// an ABI-encoded address topic: 12 zero bytes, then the address (Codex R1 P1-3)
const ADDRESS_TOPIC = /^0x0{24}[0-9a-fA-F]{40}$/;
const HASH32 = /^0x[0-9a-fA-F]{64}$/;

/**
 * Check every log of a getLogs answer: our address and topic, not removed, in the range, an
 * address topic, and its blockHash the CANONICAL hash of its block number (Codex R1 P1-2: a stale
 * or forked backend's logs are not accepted). `canon(n)` answers the canonical hash of block n.
 */
async function checkLogs(logs, spProxy, a, b, canon) {
  if (!Array.isArray(logs)) throw new SafeError(`getLogs: not a list (blocks ${a}-${b})`);
  for (const lg of logs) {
    if (lc(lg?.address) !== spProxy || lg.topics?.[0] !== OPERATOR_CONFIGURED || lg.removed)
      throw new SafeError(`getLogs: a log outside the filter (blocks ${a}-${b})`);
    const n = Number(lg.blockNumber);
    if (!(Number.isSafeInteger(n) && n >= a && n <= b))
      throw new SafeError(`getLogs: a log outside the range (blocks ${a}-${b})`);
    if (typeof lg.topics[1] !== "string" || !ADDRESS_TOPIC.test(lg.topics[1]))
      throw new SafeError(
        `getLogs: a log whose operator topic is not an address (blocks ${a}-${b})`
      );
    if (typeof lg.blockHash !== "string" || !HASH32.test(lg.blockHash))
      throw new SafeError(`getLogs: a log without a block hash (blocks ${a}-${b})`);
    if (lc(await canon(n)) !== lc(lg.blockHash))
      throw new SafeError(`getLogs: a log from block ${n} that is not on the canonical chain`);
  }
}

/** The operators of OperatorConfigured logs over [from, to]; every log checked. Throws a SafeError. */
async function operatorLogs(chain, spProxy, from, to, size, each, canon) {
  for (const [a, b] of ranges(from, to, size)) {
    let logs;
    try {
      logs = await chain.getLogs({
        address: spProxy,
        topics: [OPERATOR_CONFIGURED],
        fromBlock: hex(a),
        toBlock: hex(b),
      });
    } catch (e) {
      throw new SafeError(`${safeText("getLogs", e)} (blocks ${a}-${b})`);
    }
    await checkLogs(logs, spProxy, a, b, canon);
    each(logs, b, a);
  }
}

const opOf = topic => ethers.getAddress(ethers.dataSlice(topic, 12));

/** The EIP-1898 block parameter for B: by hash, canonical required. */
export const at = B => ({ blockHash: B.hash, requireCanonical: true });

/** The revert data of a failed eth_call, when it is exactly a 4-byte selector. */
export function revertData(e) {
  for (const d of [e?.data, e?.info?.error?.data, e?.error?.data])
    if (typeof d === "string" && /^0x[0-9a-fA-F]{8}$/.test(d)) return d.toLowerCase();
  return null;
}

/** The deployment identity at B. { ok, problems }. Any failed read fails closed. */
export async function identityAt(chain, B, cfg) {
  const problems = [];
  try {
    const out = await chain.call(
      { to: cfg.spProxy, data: spIface.encodeFunctionData("REGISTRY", []) },
      at(B)
    );
    const reg = lc(spIface.decodeFunctionResult("REGISTRY", out)[0]);
    if (reg !== lc(cfg.registry))
      problems.push("SuperPaymaster.REGISTRY() is not the configured Registry");
    // both are ERC-1967 proxies with the SAME proxy bytecode (Sepolia 5.4.2 read 11-14): the code
    // hash of a proxy identifies nothing, its implementation does
    const implOf = async proxy => {
      const slot = await chain.storageAt(proxy, IMPL_SLOT, at(B));
      if (typeof slot !== "string" || !/^0x[0-9a-fA-F]{1,64}$/.test(slot))
        throw new SafeError("an implementation slot is not a word");
      const word = ethers.toBeHex(BigInt(slot), 32);
      if (!/^0x0{24}/.test(word)) throw new SafeError("an implementation slot is not an address");
      return lc(`0x${word.slice(-40)}`);
    };
    if ((await implOf(cfg.spProxy)) !== lc(cfg.implementation))
      problems.push("the SuperPaymaster proxy's EIP-1967 implementation is not the configured one");
    if ((await implOf(cfg.registry)) !== lc(cfg.registryImplementation))
      problems.push("the Registry proxy's EIP-1967 implementation is not the configured one");
    const codeHash = async a => {
      const code = await chain.code(a, at(B));
      if (typeof code !== "string" || !/^0x[0-9a-fA-F]*$/.test(code))
        throw new SafeError("eth_getCode: not hex");
      if (code === "0x") return null;
      return lc(ethers.keccak256(code));
    };
    if ((await codeHash(cfg.spProxy)) !== lc(cfg.proxyCodeHash))
      problems.push("the SuperPaymaster proxy's code hash is not the configured one");
    if ((await codeHash(cfg.implementation)) !== lc(cfg.implementationCodeHash))
      problems.push("the SuperPaymaster implementation's code hash is not the configured one");
    if ((await codeHash(cfg.registry)) !== lc(cfg.registryCodeHash))
      problems.push("the Registry's code hash is not the configured one");
    if ((await codeHash(cfg.registryImplementation)) !== lc(cfg.registryImplementationCodeHash))
      problems.push("the Registry implementation's code hash is not the configured one");
  } catch (e) {
    return { ok: false, problems: [safeText("identity read", e)] };
  }
  return { ok: problems.length === 0, problems };
}

/**
 * One operator at B. Returns { status, ... } where status is
 *   "actionable"   configured, understaked, NOT paused: a person should pause it
 *   "paused"       configured, understaked, already paused
 *   "ok"           configured and meets the minimum stake
 *   "not-configured"
 *   "unknown"      a read failed, or the reads and the eth_call cross-check disagree (`why`)
 */
export async function operatorAt(chain, B, cfg, op) {
  const call = async (to, iface, fn, args) =>
    iface.decodeFunctionResult(
      fn,
      await chain.call({ to, data: iface.encodeFunctionData(fn, args) }, at(B))
    );
  let o, has, minStake, eff;
  let step = "SuperPaymaster.operators";
  try {
    o = await call(cfg.spProxy, spIface, "operators", [op]);
    step = "Registry.hasRole";
    has = (await call(cfg.registry, regIface, "hasRole", [ROLE_PAYMASTER_SUPER, op]))[0];
    step = "Registry.getRoleConfig";
    minStake = (await call(cfg.registry, regIface, "getRoleConfig", [ROLE_PAYMASTER_SUPER]))[0]
      .minStake;
    step = "Registry.getEffectiveStake";
    eff = (await call(cfg.registry, regIface, "getEffectiveStake", [op, ROLE_PAYMASTER_SUPER]))[0];
  } catch (e) {
    return { status: "unknown", why: `${op}: ${step} failed (${safeText(step, e)})` };
  }
  const isConfigured = Boolean(o.isConfigured);
  const isPaused = Boolean(o.isPaused);
  // SuperPaymasterStorage._hasEffectiveSuperStake, read for read
  const meets = Boolean(has) && BigInt(eff) >= BigInt(minStake);
  const reads = !isConfigured ? "not-configured" : meets ? "meets" : "understaked";
  // the cross-check: SP's own decision, simulated (an eth_call broadcasts nothing). `from` is the
  // zero address: the function is permissionless, so the caller cannot change the answer
  let sim;
  try {
    const out = await chain.call(
      {
        from: ethers.ZeroAddress,
        to: cfg.spProxy,
        data: spIface.encodeFunctionData("pauseUnderstakedOperator", [op]),
      },
      at(B)
    );
    // pauseUnderstakedOperator returns nothing: success is exactly "0x". Anything else (null, a
    // word, not hex) is not SP's answer (Codex R5 P1-2)
    if (out !== "0x")
      return {
        status: "unknown",
        why: `${op}: the pauseUnderstakedOperator simulation returned something other than empty data`,
      };
    sim = "understaked";
  } catch (e) {
    const d = revertData(e);
    sim = d === SEL_MEETS ? "meets" : d === SEL_NOT_CONFIGURED ? "not-configured" : null;
    if (sim === null)
      return {
        status: "unknown",
        why: `${op}: the pauseUnderstakedOperator simulation reverted without a known error (${safeText("simulate", e)}); is it deployed?`,
      };
  }
  const detail = {
    isConfigured,
    isPaused,
    hasRole: Boolean(has),
    effectiveStake: String(eff),
    minStake: String(minStake),
  };
  if (sim !== reads)
    return {
      status: "unknown",
      why: `${op}: the Registry reads say ${reads}, SuperPaymaster's own check says ${sim}`,
      ...detail,
    };
  if (reads === "not-configured") return { status: "not-configured", ...detail };
  if (reads === "meets") return { status: "ok", ...detail };
  return { status: isPaused ? "paused" : "actionable", ...detail };
}

/** The exact command a person runs to pause `op` (they add their own RPC and signer flags). */
export const pauseCommand = (spProxy, op) =>
  `cast send ${ethers.getAddress(spProxy)} "pauseUnderstakedOperator(address)" ${ethers.getAddress(op)}`;

/**
 * One round. Mutates st (cursor, inventory). Returns { alerts, report }. An alert is { key, text };
 * the caller delivers them. `clear` in the report is true ONLY when every read succeeded at a
 * canonical B with the identity confirmed and no operator is actionable or unknown.
 */
export async function runRound(st, { chain, cfg, now = Date.now() }) {
  const alerts = [];
  const sp = stateProblems(st, cfg);
  if (sp.length) throw new SafeError(`state: ${sp.join("; ")}`);
  if (!Number.isSafeInteger(cfg.rescanBlocks) || cfg.rescanBlocks < 0)
    throw new SafeError("rescanBlocks is not a block count");
  if (!Number.isSafeInteger(cfg.logChunk) || cfg.logChunk < 1)
    throw new SafeError("logChunk is not a block count");
  const chainId = Number(await chain.chainId());
  if (chainId !== st.chainId) throw new SafeError(`chain id ${chainId}, expected ${st.chainId}`);
  // a state time after now (a clock that was ahead) would suppress re-alerts and the daily rescan
  // until that date: reset it, and say so (Codex R2 P2)
  if (normalizeClock(st, now))
    alerts.push({
      key: "clock",
      text: "the state held times after now (a clock that was ahead?); they were reset, so a full rescan and every alert run again",
    });

  // the canonical hash of block n, read once per round (every log is checked against it)
  const hashes = new Map();
  const canon = async n => {
    if (!hashes.has(n)) {
      const b = await chain.blockByNumber(n);
      if (!b?.hash) throw new SafeError(`no block ${n}`);
      hashes.set(n, b.hash);
    }
    return hashes.get(n);
  };

  // 1. inventory, finalized ranges only. Each round also re-reads the last `rescanBlocks` before
  //    the cursor, and once a day everything from startBlock: a lagging backend that answered []
  //    for a range it had not indexed yet cannot hide an operator for good (Codex R1 P1-2)
  const finalized = height(Number(await chain.blockNumber("finalized")), "the finalized block");
  // a cursor past the finalized block would skip discovery for good (Codex R2 P1-4)
  if (!(st.cursor <= finalized))
    throw new SafeError(
      `the state cursor ${st.cursor} is ahead of the finalized block ${finalized}: a corrupt state or another chain; move the state aside to rebuild it`
    );
  const full = now - st.lastFullScan >= 24 * 3600_000;
  const from = full ? st.startBlock : Math.max(st.startBlock, st.cursor + 1 - cfg.rescanBlocks);
  let inventoryOk = true;
  // what the number-range answers said, block by block, this round: compared below with the
  // by-hash answers for every block above finalized and for B
  const rangeOps = new Map();
  const covered = []; // [a, b] ranges whose getLogs succeeded this round
  const byRange = (logs, a, b) => {
    for (const lg of logs) {
      const n = Number(lg.blockNumber);
      if (!rangeOps.has(n)) rangeOps.set(n, new Set());
      rangeOps.get(n).add(opOf(lg.topics[1]));
    }
    covered.push([a, b]);
  };
  try {
    await operatorLogs(
      chain,
      st.spProxy,
      from,
      finalized,
      cfg.logChunk,
      (logs, b, a) => {
        byRange(logs, a, b);
        for (const lg of logs) {
          const op = opOf(lg.topics[1]);
          st.operators[op] ??= Number(lg.blockNumber);
        }
        if (b > st.cursor) st.cursor = b;
      },
      canon
    );
    if (full) st.lastFullScan = now;
  } catch (e) {
    inventoryOk = false;
    alerts.push({
      key: "inventory",
      text: `unknown: the operator inventory could not be extended (${safeText("inventory", e)}); retried next round`,
    });
  }

  // 2. one block, by hash, for every read of this round
  const head = await chain.blockByNumber("latest");
  if (!head?.hash) throw new SafeError("no latest block");
  const B = { number: height(Number(head.number), "the latest block"), hash: head.hash };
  // a backend whose latest is below what it calls finalized (or below our cursor) is lagging or
  // inconsistent: nothing it says this round is used (Codex R3 P1-3)
  if (B.number < finalized || B.number < st.cursor)
    throw new SafeError(
      `the latest block ${B.number} is below the finalized block ${finalized} or the cursor ${st.cursor}: a lagging backend`
    );
  const id = await identityAt(chain, B, cfg);

  // 4. operators configured after the cursor, up to B: this round only (not persisted). This ALWAYS
  //    runs, even when the cursor reached B (Codex R3 P1-3):
  //    - B's ancestry is walked by hash down to the finalized block and must join it (Codex R2
  //      P1-3: a load-balanced endpoint can answer numbers from another fork than B);
  //    - every block above finalized, and B itself, is asked for its logs BY HASH (EIP-234). Those
  //      operators count, and the number-range answer for each such block must say the same: a
  //      lagging or forked range backend that omits a log is caught (Codex R3 P1-2).
  // every operator seen this round by range or by hash, with its block; ALL are persisted after the
  // round: an inventory that only grows cannot lose one an incomplete answer later omits (Codex R9
  // P1). One that is not real costs a read and reads "not-configured", never a false clear.
  const recent = new Map();
  const saw = (op, n) => {
    if (!recent.has(op)) recent.set(op, n);
  };
  const mismatched = [];
  let recentOk = true;
  try {
    if (B.number - finalized > MAX_UNFINALIZED)
      throw new SafeError(`${B.number - finalized} blocks above finalized: too many to walk`);
    let h = B.hash;
    for (let n = B.number; n > finalized; n--) {
      const blk = await chain.blockByHash(h);
      if (!blk || Number(blk.number) !== n || lc(blk.hash) !== lc(h))
        throw new SafeError(`block ${n} of B's ancestry cannot be read by hash`);
      hashes.set(n, blk.hash);
      h = blk.parentHash;
    }
    if (B.number > finalized && lc(h) !== lc(await canon(finalized)))
      throw new SafeError("B does not descend from the finalized block the backend reports");
    if (B.number === finalized && lc(B.hash) !== lc(await canon(finalized)))
      throw new SafeError("B is not the finalized block the backend reports");
    hashes.set(B.number, B.hash);
    // the range answer above the cursor (B included)
    if (B.number > st.cursor)
      await operatorLogs(
        chain,
        st.spProxy,
        st.cursor + 1,
        B.number,
        cfg.logChunk,
        (logs, b, a) => {
          byRange(logs, a, b);
          for (const lg of logs) saw(opOf(lg.topics[1]), Number(lg.blockNumber));
        },
        canon
      );
    // blocks disputed in an earlier round (Codex R9 P1): released only when their by-hash and
    // by-range answers agree; one that left the canonical chain is released (its operators were
    // persisted when seen). Those above finalized are checked below with the others.
    for (const k of Object.keys(st.disputed)) {
      const n = Number(k);
      if (n > finalized) continue;
      if (lc(await canon(n)) !== lc(st.disputed[k])) {
        delete st.disputed[k];
        continue;
      }
      hashes.set(n, st.disputed[k]);
      if (!covered.some(([a, b]) => n >= a && n <= b))
        await operatorLogs(
          chain,
          st.spProxy,
          n,
          n,
          cfg.logChunk,
          (logs, b, a) => byRange(logs, a, b),
          canon
        );
    }
    const byHashBlocks = [];
    for (let n = finalized + 1; n <= B.number; n++) byHashBlocks.push(n);
    if (!byHashBlocks.includes(B.number)) byHashBlocks.push(B.number);
    for (const k of Object.keys(st.disputed))
      if (Number(k) <= finalized) byHashBlocks.push(Number(k));
    for (const n of byHashBlocks) {
      const logs = await chain.getLogs({
        address: st.spProxy,
        topics: [OPERATOR_CONFIGURED],
        blockHash: hashes.get(n),
      });
      await checkLogs(logs, st.spProxy, n, n, canon);
      const mine = new Set(logs.map(lg => opOf(lg.topics[1])));
      for (const op of mine) saw(op, n);
      // only a block some range answer of this round covered can be compared; one no range
      // answer covered is already unknown through the failed scan
      if (covered.some(([a, b]) => n >= a && n <= b)) {
        const theirs = rangeOps.get(n) ?? new Set();
        if ([...mine].sort().join() !== [...theirs].sort().join()) {
          // the range answer for n is not trusted: remember the block, and move the cursor back
          // so the next round reads it again by range (Codex R8 P1-1, R9 P1)
          const key = String(n);
          st.disputed[key] = hashes.get(n);
          if (st.cursor >= n) st.cursor = n - 1;
          mismatched.push(n);
        } else {
          const key = String(n);
          delete st.disputed[key];
        }
      }
    }
    if (mismatched.length)
      throw new SafeError(
        `the backend's logs for block(s) ${mismatched.join(", ")} differ by hash and by range`
      );
  } catch (e) {
    recentOk = false;
    alerts.push({
      key: "inventory-recent",
      text: `unknown: operators configured after block ${st.cursor} could not be read (${safeText("recent", e)})`,
    });
  }

  // the inventory only grows: every operator seen this round, whatever else failed
  for (const [op, n] of recent) st.operators[op] ??= n;

  // 5. every operator at B
  const ops = Object.keys(st.operators).sort();
  const results = [];
  for (const op of ops) results.push({ operator: op, ...(await operatorAt(chain, B, cfg, op)) });

  // 6. B must still be canonical after every read; a failed re-read is NOT canonical (fail closed)
  const again = await chain.blockByNumber(B.number).catch(() => null);
  const canonical = Boolean(again) && lc(again.hash) === lc(B.hash);

  const report = {
    block: B,
    finalized,
    cursor: st.cursor,
    identity: id,
    canonical,
    operators: results,
    clear: false,
  };
  if (!canonical) {
    alerts.push({
      key: "reorg",
      text: `unknown: block ${B.number} left the canonical chain during the round; nothing of it is reported`,
    });
    return { alerts, report };
  }
  if (!id.ok) {
    alerts.push({
      key: "identity",
      text: `unknown: the deployment identity at block ${B.number} is not confirmed (${id.problems.join("; ")}); no operator is reported clear`,
    });
  }
  for (const r of results) {
    if (r.status === "actionable" && id.ok)
      alerts.push({
        key: `actionable:${r.operator}`,
        text:
          `PAUSE NEEDED: operator ${r.operator} is understaked (effective stake ${r.effectiveStake} < min ${r.minStake}` +
          `${r.hasRole ? "" : ", no ROLE_PAYMASTER_SUPER"}) and not paused at block ${B.number}. Run:\n` +
          `${pauseCommand(cfg.spProxy, r.operator)} --rpc-url <RPC> <your signer flags>`,
      });
    else if (r.status === "unknown")
      alerts.push({ key: `unknown:${r.operator}`, text: `unknown: ${r.why}` });
    else if (r.status === "not-configured")
      alerts.push({
        key: `not-configured:${r.operator}`,
        text: `${r.operator} has OperatorConfigured but is not configured at block ${B.number}`,
      });
  }
  report.clear =
    id.ok &&
    inventoryOk &&
    recentOk &&
    results.every(r => r.status === "ok" || r.status === "paused" || r.status === "not-configured");
  return { alerts, report };
}
