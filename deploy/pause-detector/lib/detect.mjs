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

/** A fresh state, bound to { chainId, spProxy, startBlock }. */
export function emptyState({ chainId, spProxy, startBlock }) {
  return {
    schema: "aoa-pause-detector-state/1",
    chainId,
    spProxy: lc(spProxy),
    startBlock,
    cursor: startBlock - 1, // last block whose OperatorConfigured logs are in the inventory
    operators: {}, // addr -> first block seen
    alerts: {}, // key -> last alert time (ms)
  };
}

/** Problems of a loaded state against the config it must belong to. Pure. */
export function stateProblems(st, cfg) {
  if (st?.schema !== "aoa-pause-detector-state/1") return ["unknown state schema"];
  const p = [];
  if (st.chainId !== cfg.chainId) p.push("the state belongs to another chain");
  if (st.spProxy !== lc(cfg.spProxy)) p.push("the state belongs to another SuperPaymaster");
  if (st.startBlock !== cfg.startBlock) p.push("the state has another startBlock");
  if (!Number.isSafeInteger(st.cursor) || st.cursor < st.startBlock - 1)
    p.push("the state cursor is not a block at or after startBlock - 1");
  if (!st.operators || typeof st.operators !== "object") p.push("the state has no operator map");
  if (!st.alerts || typeof st.alerts !== "object") p.push("the state has no alert map");
  return p;
}

/** Split [from, to] into chunks of at most `size` blocks. Pure. */
export function ranges(from, to, size) {
  const out = [];
  for (let a = from; a <= to; a += size) out.push([a, Math.min(to, a + size - 1)]);
  return out;
}

/** The operators of OperatorConfigured logs over [from, to]; every log checked. Throws a SafeError. */
async function operatorLogs(chain, spProxy, from, to, size, each) {
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
    if (!Array.isArray(logs)) throw new SafeError(`getLogs: not a list (blocks ${a}-${b})`);
    for (const lg of logs) {
      if (lc(lg.address) !== spProxy || lg.topics?.[0] !== OPERATOR_CONFIGURED || lg.removed)
        throw new SafeError(`getLogs: a log outside the filter (blocks ${a}-${b})`);
      const n = Number(lg.blockNumber);
      if (!(n >= a && n <= b))
        throw new SafeError(`getLogs: a log outside the range (blocks ${a}-${b})`);
      if (typeof lg.topics[1] !== "string" || !/^0x[0-9a-fA-F]{64}$/.test(lg.topics[1]))
        throw new SafeError(`getLogs: a log without an operator topic (blocks ${a}-${b})`);
    }
    each(logs, b);
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
    await chain.call(
      {
        from: ethers.ZeroAddress,
        to: cfg.spProxy,
        data: spIface.encodeFunctionData("pauseUnderstakedOperator", [op]),
      },
      at(B)
    );
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
export async function runRound(st, { chain, cfg }) {
  const alerts = [];
  const sp = stateProblems(st, cfg);
  if (sp.length) throw new SafeError(`state: ${sp.join("; ")}`);
  const chainId = Number(await chain.chainId());
  if (chainId !== st.chainId) throw new SafeError(`chain id ${chainId}, expected ${st.chainId}`);

  // 1. inventory, finalized ranges only
  const finalized = Number(await chain.blockNumber("finalized"));
  let inventoryOk = true;
  try {
    await operatorLogs(chain, st.spProxy, st.cursor + 1, finalized, cfg.logChunk, (logs, b) => {
      for (const lg of logs) st.operators[opOf(lg.topics[1])] ??= Number(lg.blockNumber);
      st.cursor = b;
    });
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
  const B = { number: Number(head.number), hash: head.hash };
  const id = await identityAt(chain, B, cfg);

  // 4. operators configured after the cursor, up to B: this round only
  const recent = new Set();
  let recentOk = true;
  if (B.number > st.cursor)
    try {
      await operatorLogs(chain, st.spProxy, st.cursor + 1, B.number, cfg.logChunk, logs => {
        for (const lg of logs) recent.add(opOf(lg.topics[1]));
      });
    } catch (e) {
      recentOk = false;
      alerts.push({
        key: "inventory-recent",
        text: `unknown: operators configured after block ${st.cursor} could not be read (${safeText("recent", e)})`,
      });
    }

  // 5. every operator at B
  const ops = [...new Set([...Object.keys(st.operators), ...recent])].sort();
  const results = [];
  for (const op of ops) results.push({ operator: op, ...(await operatorAt(chain, B, cfg, op)) });

  // 6. B must still be canonical after every read
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
