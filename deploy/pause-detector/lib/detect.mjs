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
/** How many historical OperatorConfigured signatures a config may list. */
export const MAX_OPERATOR_TOPICS = 16;

/**
 * Problems with the config's `operatorConfiguredTopics`, or [] (DSR 2026-11-18). An SP proxy that
 * was upgraded in place emitted OperatorConfigured under every implementation it ever had, and the
 * event's signature changed (v5.3.x had a 4th argument, `uint256 exchangeRate`; v5.4 dropped it), so
 * its topic0 changed: filtering on the pin's topic alone silently misses every operator configured
 * under an older implementation. The list is given by SP with its source, never recalled here:
 * each entry is { signature, topic0, source }, topic0 must be keccak256(signature), the operator
 * must be the first argument (it is read from topics[1]), and the pin's own topic must be listed.
 * Pure.
 */
export function topicProblems(list) {
  if (!Array.isArray(list) || list.length < 1 || list.length > MAX_OPERATOR_TOPICS)
    return [`operatorConfiguredTopics must be a list of 1..${MAX_OPERATOR_TOPICS} entries`];
  const p = [];
  const seen = new Set();
  for (const e of list) {
    const sig = e?.signature;
    if (typeof sig !== "string" || !/^OperatorConfigured\(address(,[a-z0-9[\]]+)*\)$/.test(sig)) {
      p.push(
        `operatorConfiguredTopics: ${JSON.stringify(sig)} is not OperatorConfigured(address,...)`
      );
      continue;
    }
    if (lc(e.topic0) !== topicOf(sig))
      p.push(`operatorConfiguredTopics: ${sig}'s topic0 is not keccak256 of it`);
    if (typeof e.source !== "string" || !e.source.trim() || e.source.length > 300)
      p.push(`operatorConfiguredTopics: ${sig} has no source (who gave it, from what)`);
    if (seen.has(topicOf(sig))) p.push(`operatorConfiguredTopics: ${sig} is listed twice`);
    seen.add(topicOf(sig));
  }
  if (!seen.has(OPERATOR_CONFIGURED))
    p.push("operatorConfiguredTopics must include the pin's own OperatorConfigured signature");
  return p;
}

/** keccak256 of an event signature: its topic0 (ethers.id, from the scan's allowed utilities). */
const topicOf = sig => ethers.keccak256(new TextEncoder().encode(sig));

/** How many extra historical proxy events a config may list, and unknown topic0s a state records. */
export const MAX_KNOWN_EVENTS = 64;
export const MAX_UNKNOWN_TOPICS = 32;
/** The most blocks one round classifies (every log of the proxy, unfiltered, in logChunk ranges). */
export const CLASSIFY_MAX_BLOCKS = 2_000_000;

/**
 * Problems with cfg.knownProxyEvents (absent = none), or [] (DSR 2026-11-18). Events the proxy
 * emitted under an older implementation and the pin's ABI no longer has, each { signature, topic0,
 * source } from SP's read-back of the proxy's history. Pure.
 */
export function knownEventProblems(list) {
  if (list === undefined) return [];
  if (!Array.isArray(list) || list.length > MAX_KNOWN_EVENTS)
    return [`knownProxyEvents must be a list of at most ${MAX_KNOWN_EVENTS} entries`];
  const p = [];
  for (const e of list) {
    const sig = e?.signature;
    if (typeof sig !== "string" || !/^[A-Za-z_][A-Za-z0-9_]*\([a-z0-9,[\]()]*\)$/.test(sig)) {
      p.push(`knownProxyEvents: ${JSON.stringify(sig)} is not an event signature`);
      continue;
    }
    if (lc(e.topic0) !== topicOf(sig))
      p.push(`knownProxyEvents: ${sig}'s topic0 is not keccak256 of it`);
    // an operator configuration must be DISCOVERED, not merely known (Codex pre-PR r1)
    if (sig.startsWith("OperatorConfigured("))
      p.push(
        `knownProxyEvents: ${sig} belongs in operatorConfiguredTopics, where its operators are read`
      );
    if (typeof e.source !== "string" || !e.source.trim() || e.source.length > 300)
      p.push(`knownProxyEvents: ${sig} has no source`);
  }
  return p;
}

/**
 * Every topic0 the proxy may emit that is classified: every event of SP's full ABI in the pin, the
 * configured OperatorConfigured signatures, and the configured extra historical events. Pure.
 */
export function knownProxyTopics(cfg) {
  // every event of SP's full ABI at the pinned commit (gen-sp-pin.mjs writes them; absent, none is
  // known, so every other event is unknown: fail closed)
  const t = new Set(
    (PIN.spEvents ?? [])
      // an OperatorConfigured variant counts only when it is in the discovery set, below
      .filter(e => !String(e.signature).startsWith("OperatorConfigured("))
      .map(e => lc(e.topic0))
  );
  for (const x of operatorTopics(cfg)) t.add(x);
  for (const e of cfg.knownProxyEvents ?? []) t.add(lc(e.topic0));
  return t;
}

/** The topic0 values an OperatorConfigured log may carry, from a checked config. Pure. */
export const operatorTopics = cfg => cfg.operatorConfiguredTopics.map(e => lc(e.topic0));
const SEL_NOT_CONFIGURED = spIface.getError("OperatorNotConfigured").selector;
const SEL_MEETS = spIface.getError("OperatorMeetsMinimumStake").selector;
// EIP-1967: bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1)
export const IMPL_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";
const lc = a => String(a).toLowerCase();
const hex = n => ethers.toQuantity(n);

/** The most blocks above finalized whose ancestry a round walks by hash. */
export const MAX_UNFINALIZED = 2048;
/** The most blocks one round cross-checks (a backlog is worked off over several rounds). */
export const MAX_CHECK = 4096;
/**
 * Catch-up (DSR 2026-11-18, option (a)): while the watermark is more than MAX_CHECK blocks behind B
 * (a first sync from an old proxy's deploy block, or after a long outage), a round may check up to
 * cfg.catchUp.maxBlocksPerRound blocks, fetching `concurrency` blocks at a time, for at most
 * maxSeconds. Only HOW MANY blocks a round checks changes: every block gets exactly the same checks,
 * in the same order, and the round is unknown until the watermark reaches B. Once within MAX_CHECK
 * of B, rounds are ordinary again by themselves (the mode is decided per round from the backlog).
 * Bounds keep one round inside the hourly interval and under the head-age limit.
 */
export const CATCHUP_MAX_BLOCKS = 200_000;
export const CATCHUP_MAX_CONCURRENCY = 16;
export const CATCHUP_MAX_SECONDS = 1500;
/** The most halvings of catch-up concurrency after rate limits (DSR 2026-11-18). */
export const CATCHUP_MAX_THROTTLE = 4;
/**
 * A provider's "too many requests" (HTTP 429, JSON-RPC -32005/429, or a rate-limit message), as
 * the transport marks it. In catch-up it means WE are sending too fast: the round stops, incomplete,
 * and later rounds send less; it is not a sign that the provider is down. Pure.
 */
export const isRateLimited = e =>
  e?.rateLimited === true || /RATE_LIMITED/.test(String(e?.message ?? ""));

/**
 * The smallest classifyMaxBlocks a deployed config may set (DSR 2026-11-18, clestons #453 Low): a
 * replay segment must far outrun the blocks one hourly round adds (Sepolia about 300, OP Mainnet
 * about 1800), or the replay can never finish. Enforced on the config (configProblems); a round
 * accepts smaller values so cells can replay a short history.
 */
export const CLASSIFY_MIN_BLOCKS = 10_000;
/** A replay still unfinished after this long alerts (a warning; it does not change clear). */
export const REPLAY_ALERT_MS = 48 * 3600_000;
/** Problems with cfg.classifyMaxBlocks (absent = CLASSIFY_MAX_BLOCKS), or []. Pure. */
export function classifyMaxProblems(v, min = 1) {
  if (v === undefined) return [];
  return Number.isSafeInteger(v) && v >= min && v <= CLASSIFY_MAX_BLOCKS
    ? []
    : [`classifyMaxBlocks must be ${min}..${CLASSIFY_MAX_BLOCKS}`];
}

/** Problems with cfg.catchUp (absent = no catch-up), or []. Pure. */
export function catchUpProblems(c) {
  if (c === undefined || c === null) return [];
  const p = [];
  if (!(
    Number.isSafeInteger(c.maxBlocksPerRound) &&
    c.maxBlocksPerRound > MAX_CHECK &&
    c.maxBlocksPerRound <= CATCHUP_MAX_BLOCKS
  ))
    p.push(`catchUp.maxBlocksPerRound must be ${MAX_CHECK + 1}..${CATCHUP_MAX_BLOCKS}`);
  if (!(
    Number.isSafeInteger(c.concurrency) &&
    c.concurrency >= 1 &&
    c.concurrency <= CATCHUP_MAX_CONCURRENCY
  ))
    p.push(`catchUp.concurrency must be 1..${CATCHUP_MAX_CONCURRENCY}`);
  if (!(
    Number.isSafeInteger(c.maxSeconds) &&
    c.maxSeconds >= 60 &&
    c.maxSeconds <= CATCHUP_MAX_SECONDS
  ))
    p.push(`catchUp.maxSeconds must be 60..${CATCHUP_MAX_SECONDS}`);
  return p;
}
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
  for (const k of ["lastFullScan", "lastFallbackFullScan"])
    if (st[k] > now) {
      st[k] = 0;
      changed = true;
    }
  for (const k of Object.keys(st.alerts))
    if (st.alerts[k] > now) {
      st.alerts[k] = 0;
      changed = true;
    }
  if (st.crossCheck?.lastAttempt > now) {
    st.crossCheck.lastAttempt = 0;
    changed = true;
  }
  for (const k of Object.keys(st.replayStartedAt ?? {}))
    if (st.replayStartedAt[k] > now) {
      st.replayStartedAt[k] = now;
      changed = true;
    }
  if (st.undeliveredSince > now) {
    st.undeliveredSince = now;
    changed = true;
  }
  return changed;
}

/** Start reading and verifying again from startBlock (the inventory is kept: a superset is safe). */
function resetVerification(st, alerts, why) {
  st.cursor = st.startBlock - 1;
  st.checked = st.startBlock - 1;
  st.checkedHash = null;
  st.lastFullScan = 0;
  st.lastFallbackFullScan = 0;
  st.classifiedTo = st.startBlock - 1;
  st.replayNext = {};
  alerts.push({
    key: "reverify",
    text: `unknown: ${why}; everything is read and verified again from block ${st.startBlock}`,
  });
}

/** How far a head's timestamp may be ahead of this machine's clock (Daybreak M8, DSR 2026-11-17). */
export const MAX_FUTURE_SKEW_SEC = 300;

/**
 * Why a head block cannot be used at `nowMs`, or null: no usable timestamp, older than `maxAgeSec`,
 * or more than MAX_FUTURE_SKEW_SEC ahead of the clock. A real block is never far in the future, so
 * that means this machine's clock is behind (a frozen head would then look fresher than it is) or
 * the provider is wrong: either way the head's age is not known. Pure.
 */
export function headProblem(block, nowMs, maxAgeSec) {
  const t = Number(block?.timestamp);
  if (!Number.isSafeInteger(t) || t <= 0 || !Number.isSafeInteger(maxAgeSec))
    return "has no usable timestamp";
  // compared unrounded (clestons #448 N3): a head 300.5 s ahead or 1800.4 s old is out
  const age = nowMs / 1000 - t;
  if (-age > MAX_FUTURE_SKEW_SEC)
    return `is ${Math.round(-age)} s AHEAD of this machine's clock (max ${MAX_FUTURE_SKEW_SEC}): check the Mini's clock`;
  if (age > maxAgeSec)
    return `is ${Math.round(age)} s old (max ${maxAgeSec}): a frozen or lagging node`;
  return null;
}

/** A head block that cannot be used at `nowMs` (headProblem). Pure. */
export function headStale(block, nowMs, maxAgeSec) {
  return headProblem(block, nowMs, maxAgeSec) !== null;
}

/** A fresh state, bound to { chainId, spProxy, startBlock }. */
export function emptyState({ chainId, spProxy, startBlock }) {
  return {
    schema: "aoa-pause-detector-state/1",
    chainId,
    spProxy: lc(spProxy),
    startBlock,
    cursor: startBlock - 1, // last block whose OperatorConfigured logs are in the inventory
    lastFullScan: 0, // ms of the primary's last successful rescan from startBlock (daily)
    // the fallback's, kept apart (clestons #448 B1'', DSR 2026-11-18): a fallback rescan is done when
    // due but never stands in for the primary's (N6)
    lastFallbackFullScan: 0,
    operators: {}, // checksummed addr -> first block seen (only ever grows: a superset is safe)
    // every block at or below `checked` had its by-hash and by-range answers compared and agree;
    // it starts below startBlock, so every block is compared once (Codex R11 P1-1), and is bound to
    // the canonical hash of block `checked` (null while nothing is checked yet)
    checked: startBlock - 1,
    checkedHash: null,
    alerts: {}, // key -> last alert time (ms)
    // the proxy has no code at startBlock - 1, read once (Daybreak H2): no earlier event exists
    startBlockVerified: false,
    // every log of the proxy up to here was classified (DSR 2026-11-18): its topic0 is known
    classifiedTo: startBlock - 1,
    unknownTopics: {}, // topic0 (or "anonymous") -> first block it was seen, at most MAX_UNKNOWN_TOPICS
    unknownTopicsOverflow: false, // more distinct unknown topic0s than that cap (sticky: a new stateDir)
    // the daily replay's progress, per provider clock (clestons #453): the next block to replay, or
    // null when no replay is in progress
    replayNext: {},
    crossCheck: emptyCrossCheck(),
    undeliveredSince: null, // ms since some due alert could not be delivered (Daybreak M7), or null
  };
}

/** The daily second-provider inventory cross-check's state (Daybreak H1, DSR 2026-11-17). */
export function emptyCrossCheck() {
  return {
    lastAttempt: 0, // ms of the last daily attempt, completed or not
    lastComplete: 0, // ms of the last attempt that completed
    failedDays: 0, // consecutive daily attempts that did not complete
    lastError: null, // why the last attempt did not complete
    // the highest block a completed cross-check covered (Daybreak rerun High, DSR 2026-11-17): a
    // later one that covers less (the other provider's finalized block stalled or went back) is
    // not complete. 0 = none yet
    coveredTo: 0,
    mismatch: null, // { at, height, provider, fallbackOnly: [op], primaryOnly: [op] } or null
    // set once a comparison found more than MAX_CROSS_CHECK_ADDED could add, and NEVER cleared by the
    // detector (DSR 2026-11-18): { provider, since, maxCount }. Every round is unknown until an
    // operator replaces the fallback and starts a new stateDir
    overflow: null,
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
  if (
    st.lastFallbackFullScan !== undefined &&
    !(Number.isFinite(st.lastFallbackFullScan) && st.lastFallbackFullScan >= 0)
  )
    p.push("the state's lastFallbackFullScan is not a time");
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
  if (!Number.isSafeInteger(st.checked) || st.checked < st.startBlock - 1)
    p.push("the state's checked is not a block at or after startBlock - 1");
  if (st.checkedHash !== null && !HASH32.test(String(st.checkedHash)))
    p.push("the state's checkedHash is not a block hash");
  if (!plainObject(st.alerts)) p.push("the state's alerts is not a plain map");
  else if (Object.values(st.alerts).some(v => !Number.isFinite(v)))
    p.push("the state's alerts has a time that is not a number");
  // both are optional (a state written before Daybreak r1 has neither; they start empty)
  if (
    st.fromCrossCheck !== undefined &&
    !(
      plainObject(st.fromCrossCheck) &&
      Object.entries(st.fromCrossCheck).every(
        ([k, v]) =>
          ADDRESS.test(k) &&
          plainObject(v) &&
          typeof v.provider === "string" &&
          Number.isSafeInteger(v.block) &&
          Number.isFinite(v.at)
      )
    )
  )
    p.push("the state's fromCrossCheck is not a map of operators the cross-check added");
  if (
    st.undeliveredSince !== undefined &&
    st.undeliveredSince !== null &&
    !(Number.isFinite(st.undeliveredSince) && st.undeliveredSince >= 0)
  )
    p.push("the state's undeliveredSince is not a time");
  // the classification fields are optional (a state from before them starts at startBlock - 1)
  if (
    st.classifiedTo !== undefined &&
    !(Number.isSafeInteger(st.classifiedTo) && st.classifiedTo >= st.startBlock - 1)
  )
    p.push("the state's classifiedTo is not a block at or after startBlock - 1");
  if (
    st.unknownTopics !== undefined &&
    !(
      plainObject(st.unknownTopics) &&
      Object.keys(st.unknownTopics).length <= MAX_UNKNOWN_TOPICS &&
      Object.entries(st.unknownTopics).every(
        ([k, v]) => (HASH32.test(k) || k === "anonymous") && Number.isSafeInteger(v)
      )
    )
  )
    p.push("the state's unknownTopics is not a map of topic0 to block");
  if (st.knownSet !== undefined && !HASH32.test(String(st.knownSet)))
    p.push("the state's knownSet is not a hash");
  if (
    st.replayStartedAt !== undefined &&
    !(
      plainObject(st.replayStartedAt) &&
      Object.entries(st.replayStartedAt).every(
        ([k, v]) => (k === "lastFullScan" || k === "lastFallbackFullScan") && Number.isFinite(v)
      )
    )
  )
    p.push("the state's replayStartedAt is not a time per clock");
  if (st.topicSet !== undefined && typeof st.topicSet !== "string")
    p.push("the state's topicSet is not a string");
  if (
    st.catchUpThrottle !== undefined &&
    !(
      Number.isSafeInteger(st.catchUpThrottle) &&
      st.catchUpThrottle >= 0 &&
      st.catchUpThrottle <= CATCHUP_MAX_THROTTLE
    )
  )
    p.push("the state's catchUpThrottle is not 0..4");
  if (
    st.unknownTopicsMore !== undefined &&
    !(Number.isSafeInteger(st.unknownTopicsMore) && st.unknownTopicsMore >= 0)
  )
    p.push("the state's unknownTopicsMore is not a count");
  if (st.unknownTopicsOverflow !== undefined && typeof st.unknownTopicsOverflow !== "boolean")
    p.push("the state's unknownTopicsOverflow is not a boolean");
  if (
    st.replayNext !== undefined &&
    !(
      plainObject(st.replayNext) &&
      Object.entries(st.replayNext).every(
        ([k, v]) =>
          (k === "lastFullScan" || k === "lastFallbackFullScan") &&
          (v === null || (Number.isSafeInteger(v) && v >= st.startBlock))
      )
    )
  )
    p.push("the state's replayNext is not a replay cursor per clock");
  if (
    st.lastThrottledAt !== undefined &&
    !(Number.isFinite(st.lastThrottledAt) && st.lastThrottledAt >= 0)
  )
    p.push("the state's lastThrottledAt is not a time");
  if (st.startBlockVerified !== undefined && typeof st.startBlockVerified !== "boolean")
    p.push("the state's startBlockVerified is not a boolean");
  if (st.crossCheck !== undefined) {
    const c = st.crossCheck;
    const addrs = a => Array.isArray(a) && a.every(x => typeof x === "string" && ADDRESS.test(x));
    if (
      !plainObject(c) ||
      !["lastAttempt", "lastComplete"].every(k => Number.isFinite(c[k]) && c[k] >= 0) ||
      !Number.isSafeInteger(c.failedDays) ||
      c.failedDays < 0 ||
      !(c.coveredTo === undefined || (Number.isSafeInteger(c.coveredTo) && c.coveredTo >= 0)) ||
      // a completed record carries its coverage (Daybreak narrow rerun Medium, DSR 2026-11-17)
      (c.lastComplete > 0 && c.coveredTo === undefined) ||
      !(c.lastError === null || typeof c.lastError === "string") ||
      !(
        c.overflow === undefined ||
        c.overflow === null ||
        (plainObject(c.overflow) &&
          typeof c.overflow.provider === "string" &&
          Number.isFinite(c.overflow.since) &&
          Number.isSafeInteger(c.overflow.maxCount) &&
          c.overflow.maxCount > 0)
      ) ||
      !(
        c.mismatch === null ||
        (plainObject(c.mismatch) &&
          Number.isSafeInteger(c.mismatch.height) &&
          c.mismatch.height >= 0 &&
          addrs(c.mismatch.fallbackOnly) &&
          addrs(c.mismatch.primaryOnly) &&
          (c.mismatch.unlisted === undefined ||
            (Number.isSafeInteger(c.mismatch.unlisted) && c.mismatch.unlisted >= 0)) &&
          (c.mismatch.found === undefined ||
            (plainObject(c.mismatch.found) &&
              Object.entries(c.mismatch.found).every(
                ([k, f]) =>
                  ADDRESS.test(k) &&
                  plainObject(f) &&
                  typeof f.provider === "string" &&
                  Number.isSafeInteger(f.height) &&
                  f.height >= 0
              ))))
      )
    )
      p.push("the state's crossCheck is not a cross-check record");
  }
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
const ADDRESS = /^0x[0-9a-fA-F]{40}$/;
const HASH32 = /^0x[0-9a-fA-F]{64}$/;

/**
 * Check every log of a getLogs answer: our address and topic, not removed, in the range, an
 * address topic, and its blockHash the CANONICAL hash of its block number (Codex R1 P1-2: a stale
 * or forked backend's logs are not accepted). `canon(n)` answers the canonical hash of block n.
 */
async function checkLogs(logs, spProxy, a, b, canon, topics) {
  if (!Array.isArray(logs)) throw new SafeError(`getLogs: not a list (blocks ${a}-${b})`);
  for (const lg of logs) {
    if (lc(lg?.address) !== spProxy || !topics.includes(lc(lg.topics?.[0])) || lg.removed)
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
/** A log's topic0, lower-case, or "anonymous". Pure. */
const topic0Of = lg =>
  Array.isArray(lg?.topics) && HASH32.test(String(lg.topics[0])) ? lc(lg.topics[0]) : "anonymous";

/**
 * The operator of an unfiltered log that is a configured OperatorConfigured topic, or null (Codex
 * pre-PR r3: an index that omits it from topic-filtered answers still has it here). Throws on one
 * whose operator topic is not an address.
 */
function operatorOfAny(lg, t0, T, n) {
  if (!T.includes(t0)) return null;
  if (typeof lg.topics?.[1] !== "string" || !ADDRESS_TOPIC.test(lg.topics[1]))
    throw new SafeError(`getLogs: a log whose operator topic is not an address (block ${n})`);
  return opOf(lg.topics[1]);
}

/**
 * Record an unclassified topic0 in the state, bounded: past MAX_UNKNOWN_TOPICS distinct ones only a
 * sticky flag is kept (clestons #453 Low: a count re-counted the same topic on every re-read).
 */
function recordUnknown(st, t0, n) {
  st.unknownTopics ??= {}; // (the cross-check can run before a round initialised it: clestons #453)
  if (t0 in st.unknownTopics) return;
  if (Object.keys(st.unknownTopics).length < MAX_UNKNOWN_TOPICS) st.unknownTopics[t0] = n;
  else st.unknownTopicsOverflow = true;
}

/**
 * Every log of the proxy over [from, to], UNFILTERED (DSR 2026-11-18): each must be the proxy's, not
 * removed, in its range, and carry the hash `hashAt(n)` gives for its block. `each(lg, t0, n)` per
 * log. Throws a SafeError (keeping a rate limit's mark).
 */
async function allLogs(chain, spProxy, from, to, size, hashAt, each) {
  for (const [a, b] of ranges(from, to, size)) {
    let logs;
    try {
      logs = await chain.getLogs({ address: spProxy, fromBlock: hex(a), toBlock: hex(b) });
    } catch (e) {
      const err = new SafeError(`${safeText("getLogs", e)} (every log, blocks ${a}-${b})`);
      if (isRateLimited(e)) err.rateLimited = true;
      throw err;
    }
    if (!Array.isArray(logs))
      throw new SafeError(`getLogs: not a list (every log, blocks ${a}-${b})`);
    for (const lg of logs) {
      const n = Number(lg?.blockNumber);
      if (
        lc(lg?.address) !== spProxy ||
        lg.removed ||
        !(Number.isSafeInteger(n) && n >= a && n <= b)
      )
        throw new SafeError(`getLogs: a log outside the filter (every log, blocks ${a}-${b})`);
      const h = await hashAt(n);
      if (typeof lg.blockHash !== "string" || !h || lc(h) !== lc(lg.blockHash))
        throw new SafeError(`getLogs: a log from block ${n} that is not on the canonical chain`);
      each(lg, topic0Of(lg), n);
    }
  }
}

async function operatorLogs(chain, spProxy, from, to, size, each, canon, topics) {
  for (const [a, b] of ranges(from, to, size)) {
    let logs;
    try {
      logs = await chain.getLogs({
        address: spProxy,
        topics: [topics],
        fromBlock: hex(a),
        toBlock: hex(b),
      });
    } catch (e) {
      const err = new SafeError(`${safeText("getLogs", e)} (blocks ${a}-${b})`);
      if (isRateLimited(e)) err.rateLimited = true;
      throw err;
    }
    await checkLogs(logs, spProxy, a, b, canon, topics);
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
export async function runRound(
  st,
  { chain, cfg, now = Date.now(), clock = () => now, isPrimary = true }
) {
  // a state time after now (a clock that was ahead) would suppress re-alerts and the daily rescan
  // until that date: reset it first, so the progress snapshot below does not undo it (Codex R2 P2)
  const clockReset = normalizeClock(st, now);
  // the round's progress is committed ONLY if the round ends with B still canonical: a throw at any
  // point, or a rejected B, leaves cursor, watermark and rescan time where they were (Codex R11
  // P1-2, R12 P1-2). The inventory keeps what it saw either way: a superset is safe.
  const before = {
    cursor: st.cursor,
    checked: st.checked,
    checkedHash: st.checkedHash,
    lastFullScan: st.lastFullScan,
    lastFallbackFullScan: st.lastFallbackFullScan,
    classifiedTo: st.classifiedTo,
    topicSet: st.topicSet,
    knownSet: st.knownSet,
    replayStartedAt: st.replayStartedAt && { ...st.replayStartedAt },
    replayNext: st.replayNext && { ...st.replayNext },
    crossCheck: st.crossCheck && { ...st.crossCheck },
  };
  let result;
  try {
    result = await roundOnce(st, { chain, cfg, now, clock, isPrimary });
  } catch (e) {
    Object.assign(st, before);
    throw e;
  }
  if (!result.report?.canonical) Object.assign(st, before);
  if (clockReset)
    result.alerts.unshift({
      key: "clock",
      text: "the state held times after now (a clock that was ahead?); they were reset, so a full rescan and every alert run again",
    });
  return result;
}

async function roundOnce(st, { chain, cfg, now, clock, isPrimary = true }) {
  const alerts = [];
  const sp = stateProblems(st, cfg);
  if (sp.length) throw new SafeError(`state: ${sp.join("; ")}`);
  const tp = topicProblems(cfg.operatorConfiguredTopics);
  if (tp.length) throw new SafeError(`config: ${tp.join("; ")}`);
  const cp = catchUpProblems(cfg.catchUp);
  if (cp.length) throw new SafeError(`config: ${cp.join("; ")}`);
  const kp = [
    ...knownEventProblems(cfg.knownProxyEvents),
    ...classifyMaxProblems(cfg.classifyMaxBlocks),
  ];
  if (kp.length) throw new SafeError(`config: ${kp.join("; ")}`);
  const T = operatorTopics(cfg);
  // the inventory was built and verified with ONE set of OperatorConfigured topics: when the set
  // changes (a signature was added), nothing below the cursor was read with it, so everything is read
  // and verified again from startBlock, and the cross-check's coverage starts over (Codex pre-PR r1)
  const topicSet = [...T].sort().join(",");
  if (st.topicSet !== topicSet) {
    if (st.cursor >= st.startBlock) {
      resetVerification(st, alerts, "the configured OperatorConfigured signatures changed");
      if (st.crossCheck) {
        st.crossCheck.lastComplete = 0;
        st.crossCheck.coveredTo = 0;
        st.crossCheck.lastAttempt = 0;
      }
    }
    st.topicSet = topicSet;
  }
  if (!Number.isSafeInteger(cfg.rescanBlocks) || cfg.rescanBlocks < 0)
    throw new SafeError("rescanBlocks is not a block count");
  if (!Number.isSafeInteger(cfg.logChunk) || cfg.logChunk < 1)
    throw new SafeError("logChunk is not a block count");
  const chainId = Number(await chain.chainId());
  if (chainId !== st.chainId) throw new SafeError(`chain id ${chainId}, expected ${st.chainId}`);

  // 0. startBlock is not after SP's deployment (Daybreak H2, DSR 2026-11-17): a late startBlock
  //    would leave every earlier OperatorConfigured unread for good. The proxy having NO code at
  //    startBlock - 1 proves it did not exist yet, so no earlier event can exist. Read once per state;
  //    until it reads "0x" no round is clear.
  let startOk = st.startBlockVerified === true;
  if (!startOk) {
    try {
      const code = await chain.code(st.spProxy, hex(st.startBlock - 1));
      if (code === "0x") {
        st.startBlockVerified = true;
        startOk = true;
      } else
        alerts.push({
          key: "start-block",
          text: `unknown: SuperPaymaster already has code at block ${st.startBlock - 1}, so startBlock ${st.startBlock} is after its deployment and earlier operators are never read; set startBlock to SP's deploy block (with a new stateDir)`,
        });
    } catch (e) {
      alerts.push({
        key: "start-block",
        text: `unknown: whether SuperPaymaster existed before startBlock ${st.startBlock} could not be read (${safeText("startBlock", e)})`,
      });
    }
  }

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
  // a cursor past the finalized block would skip discovery for good (Codex R2 P1-4): the chain is
  // not the one the state was built on, so everything is read and verified again (Codex R12)
  if (!(st.cursor <= finalized))
    resetVerification(
      st,
      alerts,
      `the state cursor ${st.cursor} is ahead of the finalized block ${finalized}`
    );
  // the daily full rescan runs on whichever provider the round uses, each on its own 24 h clock
  // (clestons #448 B1'', DSR 2026-11-18): with the primary down for days the fallback still re-reads
  // everything once a day, so an operator the primary's index missed is found within a day. Only the
  // primary's rescan moves lastFullScan, so a fallback rescan never stands in for it (N6)
  const scanKey = isPrimary ? "lastFullScan" : "lastFallbackFullScan";
  const full = now - (st[scanKey] ?? 0) >= 24 * 3600_000;
  const from = full ? st.startBlock : Math.max(st.startBlock, st.cursor + 1 - cfg.rescanBlocks);
  let inventoryOk = true;
  // any rate limit this round (Codex pre-PR r2): catch-up does not start after one, and the throttle
  // never goes down in a round that met one
  let rateLimited = false;
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
      canon,
      T
    );
  } catch (e) {
    inventoryOk = false;
    if (isRateLimited(e)) rateLimited = true;
    alerts.push({
      key: "inventory",
      text: `unknown: the operator inventory could not be extended (${safeText("inventory", e)}); retried next round`,
    });
  }

  // 1b. every log of the proxy, unfiltered, over the finalized blocks not yet classified (DSR
  //     2026-11-18): each topic0 must be a known event. An unknown one may be an operator
  //     configuration under a signature nobody listed, so it keeps every round unknown until the
  //     config names it (knownProxyEvents or operatorConfiguredTopics, with SP's source). Finalized
  //     logs do not change, so this runs once per block; a reorg reset classifies again
  let classifyOk = true;
  const known = knownProxyTopics(cfg);
  st.unknownTopics ??= {};
  // a count from an earlier build of this state (unknownTopicsMore) is evidence too: kept, as the flag
  if (st.unknownTopicsMore > 0) st.unknownTopicsOverflow = true;
  delete st.unknownTopicsMore;
  st.unknownTopicsOverflow ??= false;
  st.replayNext ??= {};
  st.replayStartedAt ??= {};
  st.classifiedTo ??= st.startBlock - 1;
  // 2. the known-event set is part of what classification was done against (DSR 2026-11-18,
  //    clestons #453 Low): the pin's spEvents (a new tag), knownProxyEvents and the configured topics.
  //    When it changes, every log is classified again from startBlock; verification is not reset
  const knownSet = topicOf([...known].sort().join(","));
  if (st.knownSet !== knownSet) {
    if (st.classifiedTo >= st.startBlock) {
      st.classifiedTo = st.startBlock - 1;
      st.replayNext = {};
      st.replayStartedAt = {};
      alerts.push({
        key: "reclassify",
        text: "the known events changed (the pin's spEvents or knownProxyEvents): every log of the proxy is classified again from startBlock",
      });
    }
    st.knownSet = knownSet;
  }
  const maxClassify = cfg.classifyMaxBlocks ?? CLASSIFY_MAX_BLOCKS;
  const take = (lg, t0, n) => {
    if (!known.has(t0)) recordUnknown(st, t0, n);
    // an operator configuration seen here enters the inventory too (a superset is safe)
    const op = operatorOfAny(lg, t0, T, n);
    if (op) st.operators[op] ??= n;
  };
  let replayDone = false;
  try {
    // forward: the finalized blocks never classified yet, at most maxClassify per round
    const cFrom = st.classifiedTo + 1;
    const cTo = Math.min(finalized, cFrom + maxClassify - 1);
    if (cTo >= cFrom) {
      await allLogs(chain, st.spProxy, cFrom, cTo, cfg.logChunk, canon, take);
      st.classifiedTo = cTo;
    }
    if (st.classifiedTo < finalized)
      throw new SafeError(`classified up to block ${st.classifiedTo}, finalized is ${finalized}`);
    // the daily REPLAY (Codex pre-PR r2; clestons #453 High 1, 2): everything from startBlock again,
    // by whichever provider the round uses, so a response that omitted a log once is asked again.
    // It goes in segments of maxClassify, with its own cursor per clock; the clock moves only when
    // the replay has reached finalized and the inventory rescan succeeded, so a replay that fails
    // or is not finished is resumed next round, never counted as done
    if (full) {
      // when this clock's replay began (for the overdue alert below)
      st.replayStartedAt[scanKey] ??= now;
      const rFrom = st.replayNext[scanKey] ?? st.startBlock;
      const rTo = Math.min(finalized, rFrom + maxClassify - 1);
      if (rTo >= rFrom) await allLogs(chain, st.spProxy, rFrom, rTo, cfg.logChunk, canon, take);
      if (rTo >= finalized) {
        st.replayNext[scanKey] = null;
        replayDone = true;
      } else st.replayNext[scanKey] = rTo + 1;
    }
  } catch (e) {
    classifyOk = false;
    if (isRateLimited(e)) rateLimited = true;
    alerts.push({
      key: "events",
      text: `unknown: the proxy's logs could not all be classified (${safeText("events", e)}); retried next round`,
    });
  }
  // the daily clock: only a full round whose inventory rescan AND replay both completed
  if (full && inventoryOk && classifyOk && replayDone) {
    st[scanKey] = now;
    delete st.replayStartedAt[scanKey];
  }
  // a replay unfinished 48 h after it began (DSR 2026-11-18): a warning, clear is not changed. Both
  // clocks every round (Codex): a round on the other provider does not make the warning look resolved
  for (const [k, started] of Object.entries(st.replayStartedAt))
    if (now - started > REPLAY_ALERT_MS)
      alerts.push({
        key: `replay-overdue:${k}`,
        text: `the daily replay (${k}) started at ${new Date(started).toISOString()} and has not reached the finalized block: check classifyMaxBlocks and the provider`,
      });
  // an unknown topic0 named in the config since is known now: it is dropped
  for (const t of Object.keys(st.unknownTopics)) if (known.has(t)) delete st.unknownTopics[t];
  const unknownEvents = Object.entries(st.unknownTopics);
  if (unknownEvents.length || st.unknownTopicsOverflow)
    alerts.push({
      key: "unknown-event",
      text:
        `unknown: the SuperPaymaster proxy emitted events nobody listed: ${unknownEvents.map(([t, n]) => `${t} (first at block ${n})`).join(", ")}` +
        (st.unknownTopicsOverflow
          ? `, and more than ${MAX_UNKNOWN_TOPICS} distinct ones in all`
          : "") +
        "; one could be an operator configuration under an unlisted signature. Ask SP what each is and add it to knownProxyEvents (or operatorConfiguredTopics) with its source" +
        (st.unknownTopicsOverflow ? "; past the cap, a new stateDir is needed after that" : ""),
    });
  const eventsOk = classifyOk && !unknownEvents.length && !st.unknownTopicsOverflow;
  // (and no unclassified event above finalized: checked in step 4, required for clear below)

  // 2. one block, by hash, for every read of this round
  const head = await chain.blockByNumber("latest");
  if (!head?.hash) throw new SafeError("no latest block");
  const B = {
    number: height(Number(head.number), "the latest block"),
    hash: head.hash,
    timestamp: head.timestamp,
  };
  // a head that stopped moving is the commonest honest failure, and self-consistent: every other
  // check passes against a frozen node (clestons #434 B1). An old head stops the round.
  // checked against the clock WHEN B is accepted, not the round's start (Codex R16 P1-2)
  const hp = headProblem(head, clock(), cfg.maxHeadAgeSec);
  if (hp) throw new SafeError(`the latest block ${B.number} ${hp}`);
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
  const rangeSaw = (logs, b, a) => {
    byRange(logs, a, b);
    for (const lg of logs) saw(opOf(lg.topics[1]), Number(lg.blockNumber));
  };
  let recentOk = true;
  const recentUnknown = new Set(); // unclassified topic0s above finalized, this round only
  let catchUp = null; // { from, to, upTo } when this round ran in catch-up mode
  let caughtUp = false; // the watermark was within MAX_CHECK of B this round
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
    // every log above finalized, unfiltered, against B's own ancestry (Codex pre-PR r2): an
    // unlisted event there is unknown THIS round; it is recorded for good once finalized
    if (B.number > finalized)
      await allLogs(
        chain,
        st.spProxy,
        finalized + 1,
        B.number,
        cfg.logChunk,
        async n => hashes.get(n),
        (lg, t0, n) => {
          if (!known.has(t0)) recentUnknown.add(t0);
          // an operator configuration above finalized counts this round, like the filtered reads'
          const op = operatorOfAny(lg, t0, T, n);
          if (op) saw(op, n);
        }
      );
    // the range answer above the cursor (B included)
    if (B.number > st.cursor)
      await operatorLogs(
        chain,
        st.spProxy,
        st.cursor + 1,
        B.number,
        cfg.logChunk,
        rangeSaw,
        canon,
        T
      );
    // THE CROSS-CHECK (Codex R3, R8, R9, R10): every block in (checked, B] is asked for its logs BY
    // HASH (EIP-234) and BY RANGE, and the two must agree. `checked` is a watermark: every block at
    // or below it was compared and agreed. It advances only over contiguous agreeing blocks, and
    // never past finalized (a block above finalized can still be replaced). A failed read or a
    // disagreement stops it where it is, so the block is asked again next round, before and after
    // finalization alike, and the round is unknown until the watermark is within reach of B.
    // a watermark above finalized, or one whose block is no longer the one it was checked on, means
    // the chain under it changed: nothing below it can be assumed, so everything is verified again
    // from startBlock, cursor with it, and the alert says so (Codex R11 P1-2, R12 P1-1)
    if (
      st.checked > finalized ||
      // an advanced watermark must carry the hash it was checked on (Codex R13 P1-2)
      (st.checked >= st.startBlock && st.checkedHash === null) ||
      (st.checkedHash !== null && lc(await canon(st.checked)) !== lc(st.checkedHash))
    )
      resetVerification(
        st,
        alerts,
        `the chain under block ${st.checked} changed since it was checked`
      );
    const lo = st.checked + 1;
    // catch-up is decided from THIS round's backlog alone: once within MAX_CHECK of B, ordinary
    const behindFar = Boolean(cfg.catchUp) && B.number - st.checked > MAX_CHECK;
    caughtUp = B.number - st.checked <= MAX_CHECK;
    const catching = behindFar && !rateLimited;
    if (behindFar && rateLimited)
      catchUp = { from: lo, to: lo - 1, upTo: null, concurrency: 0, throttled: true };
    let hi = Math.min(B.number, lo + (catching ? cfg.catchUp.maxBlocksPerRound : MAX_CHECK) - 1);
    // in catch-up, the answers each block needs are fetched ahead, `concurrency` at a time, into
    // these caches (keyed by the block's hash); the loop below still checks every block itself,
    // and fetches anything not cached the ordinary way
    const ahead = { blk: new Map(), logs: new Map() };
    const t0 = clock();
    // after a rate limit, later catch-up rounds send less: concurrency halves per throttled round
    // and recovers one step per round that was not throttled (DSR 2026-11-18)
    const throttle = st.catchUpThrottle ?? 0;
    const width = catching ? Math.max(1, cfg.catchUp.concurrency >> throttle) : 1;
    let throttled = false;
    const fetchAhead = async (from, to) => {
      const ns = [];
      for (let n = from; n <= Math.min(to, finalized); n++) ns.push(n);
      let i = 0;
      const worker = async () => {
        while (i < ns.length && !throttled) {
          const k = i;
          i += 1;
          const n = ns[k];
          try {
            const h = await canon(n);
            const [b, l] = await Promise.all([
              chain.blockByHash(h),
              chain.getLogs({ address: st.spProxy, topics: [T], blockHash: h }),
            ]);
            ahead.blk.set(lc(h), b);
            ahead.logs.set(lc(h), l);
          } catch (e) {
            // a rate limit stops every worker: this round ends, incomplete, at the window's start
            if (isRateLimited(e)) throttled = true;
            /* otherwise not cached: the loop fetches it again and its error stops the round there */
          }
        }
      };
      await Promise.all(Array.from({ length: width }, worker));
    };
    if (catching) {
      catchUp = { from: lo, to: hi, upTo: null, concurrency: width, throttled: false };
    }
    const WINDOW = catching ? width * 64 : Infinity;
    // the watermark advances only along ONE chain (Codex R13 P1-1): at or below finalized, block n's
    // header is read by its hash and its parent must be the block before it (the stored
    // checkedHash, then each block of this window). Above finalized the hashes come from B's own
    // ancestry walk, which joined canon(finalized), the same hash this loop uses at finalized; so
    // the checked chain reaches B link by link, and a by-number answer from another fork breaks it.
    let prev = st.checkedHash;
    for (let n = lo; n <= hi; n++) {
      if (catching && (n - lo) % WINDOW === 0) {
        // the time budget is checked between windows: the round stops at a block boundary, with
        // the watermark wherever the contiguous checked blocks reached
        if (clock() - t0 > cfg.catchUp.maxSeconds * 1000) {
          hi = n - 1;
          break;
        }
        // this window's range answers, one getLogs per logChunk instead of one per block below, read
        // window by window after the budget check, so every window's work counts (Codex pre-PR r5)
        // (a rate limit here throws, and the catch below counts it as a throttled round)
        const wTop = Math.min(hi, n + WINDOW - 1, finalized);
        if (wTop >= n && !covered.some(([a, b]) => n >= a && wTop <= b))
          await operatorLogs(chain, st.spProxy, n, wTop, cfg.logChunk, rangeSaw, canon, T);
        await fetchAhead(n, Math.min(hi, n + WINDOW - 1));
        if (throttled) {
          // nothing of this window is checked: the round stops at its start, and is not clear
          catchUp.throttled = true;
          hi = n - 1;
          break;
        }
      }
      const hn = n > finalized ? hashes.get(n) : await canon(n);
      if (n <= finalized) {
        const blk = ahead.blk.get(lc(hn)) ?? (await chain.blockByHash(hn));
        if (!blk || Number(blk.number) !== n || lc(blk.hash) !== lc(hn))
          throw new SafeError(`block ${n} cannot be read by its hash`);
        if (prev !== null && lc(blk.parentHash) !== lc(prev))
          throw new SafeError(
            `block ${n} does not follow the checked chain (another fork answered)`
          );
      }
      // a block no range answer of this round covered gets its own
      if (!covered.some(([a, b]) => n >= a && n <= b))
        await operatorLogs(chain, st.spProxy, n, n, cfg.logChunk, rangeSaw, canon, T);
      const logs =
        ahead.logs.get(lc(hn)) ??
        (await chain.getLogs({
          address: st.spProxy,
          topics: [T],
          blockHash: hn,
        }));
      await checkLogs(logs, st.spProxy, n, n, canon, T);
      const mine = new Set(logs.map(lg => opOf(lg.topics[1])));
      for (const op of mine) saw(op, n);
      const theirs = rangeOps.get(n) ?? new Set();
      if ([...mine].sort().join() !== [...theirs].sort().join()) {
        // the range answer for n is not trusted: the cursor moves back too, so the next round's
        // range scan reads n again (Codex R8 P1-1)
        if (st.cursor >= n) st.cursor = n - 1;
        throw new SafeError(`the backend's logs for block ${n} differ by hash and by range`);
      }
      if (n <= finalized && st.checked === n - 1) {
        st.checked = n;
        st.checkedHash = hn;
      }
      prev = hn;
    }
    if (hi < B.number)
      throw new SafeError(
        `the cross-check is behind: every block is checked up to ${st.checked}, B is ${B.number}${catchUp ? (throttled ? " (catching up: the provider rate-limited us; later rounds send less)" : " (catching up)") : ""}`
      );
  } catch (e) {
    recentOk = false;
    // a rate limit anywhere in a catch-up round counts as one (Codex pre-PR r1): later rounds send less
    if (isRateLimited(e)) {
      rateLimited = true;
      if (catchUp) catchUp.throttled = true;
    }
    alerts.push({
      key: "inventory-recent",
      text: `unknown: operators configured after block ${st.cursor} could not be read (${safeText("recent", e)})`,
    });
  }

  if (recentUnknown.size)
    alerts.push({
      key: "unknown-event-recent",
      text: `unknown: the SuperPaymaster proxy emitted events nobody listed above the finalized block: ${[...recentUnknown].join(", ")}; one could be an operator configuration under an unlisted signature`,
    });

  // the catch-up throttle (DSR 2026-11-18): halved per throttled catch-up round, one step back per
  // catch-up round that was not, and gone once caught up (clestons #453 Medium: it would otherwise
  // stay armed and keep the probe from ever handing over to the fallback)
  if (catchUp) {
    const t = st.catchUpThrottle ?? 0;
    st.catchUpThrottle = catchUp.throttled
      ? Math.min(CATCHUP_MAX_THROTTLE, t + 1)
      : Math.max(0, t - 1);
    if (catchUp.throttled) st.lastThrottledAt = now;
  } else if (caughtUp) st.catchUpThrottle = 0;

  // the inventory only grows: every operator seen this round, whatever else failed
  for (const [op, n] of recent) st.operators[op] ??= n;

  // 5. every operator at B
  // the inventory, plus any operator only the second provider's cross-check found (Daybreak H1):
  // those are checked too while the disagreement stands, without entering the primary's inventory
  const ops = [
    ...new Set([...Object.keys(st.operators), ...(st.crossCheck?.mismatch?.fallbackOnly ?? [])]),
  ].sort();
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
    // where a catch-up round's contiguous checked blocks reached, whether it then threw or not
    catchUp: catchUp && { ...catchUp, upTo: st.checked },
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
  // and again before anything is called clear: a scan can outlast the head's remaining freshness
  const freshAtEnd = !headStale(B, clock(), cfg.maxHeadAgeSec);
  if (!freshAtEnd)
    alerts.push({
      key: "stale-at-end",
      text: `unknown: block ${B.number} is older than ${cfg.maxHeadAgeSec} s by the end of the round`,
    });
  report.fresh = freshAtEnd;
  // the daily cross-check's standing results (crossCheckInventory ran before this round)
  alerts.push(...crossCheckAlerts(st));
  // no round is clear before a first cross-check has completed (DSR 2026-11-17): a fresh state,
  // a first deployment or a lost state file, would otherwise read clear with nothing compared
  const crossDone = st.crossCheck?.lastComplete > 0;
  if (!crossDone)
    alerts.push({
      key: "crosscheck-pending",
      text: "unknown: no inventory cross-check with the other RPC provider has completed yet; no round is clear until one has",
    });
  // an incomplete cross-check is tolerated for at most CROSS_CHECK_ALERT_DAYS days of blocks
  // (Daybreak narrow rerun High A, DSR 2026-11-17): beyond that the inventory has outrun what was
  // compared, and the round is unknown; it turns unknown when crosscheck-incomplete starts to alert
  const behind = st.cursor - (st.crossCheck?.coveredTo ?? 0);
  const coverageOk = behind <= CROSS_CHECK_ALERT_DAYS * CROSS_CHECK_MAX_LAG_BLOCKS;
  if (crossDone && !coverageOk)
    alerts.push({
      key: "crosscheck-behind",
      text: `unknown: the inventory is ${behind} blocks past what the last cross-check covered (block ${st.crossCheck?.coveredTo}; max ${CROSS_CHECK_ALERT_DAYS * CROSS_CHECK_MAX_LAG_BLOCKS})`,
    });
  // an overflow is never settled by a later comparison (DSR 2026-11-18): past the cap the over-cap
  // operators are unnamed, and a comparison cannot tell an honest omission from a lying one
  const overflow = st.crossCheck?.overflow ?? null;
  if (overflow)
    alerts.push({
      key: "crosscheck-overflow",
      text:
        `unknown: the cross-check with ${overflow.provider} found more operators than the inventory may take from it ` +
        `(up to ${overflow.maxCount} over the cap of ${MAX_CROSS_CHECK_ADDED}, since ${new Date(overflow.since).toISOString()}); ` +
        "no round is clear until an operator resets it: 1. check that fallback provider and replace it; " +
        "2. start a new stateDir (the inventory and coveredTo are rebuilt); " +
        "3. after the restart, wait for the first cross-check to complete (rounds read unknown until then)",
    });
  const crossOk = crossDone && coverageOk && !st.crossCheck?.mismatch && !overflow;
  report.startBlockVerified = startOk;
  report.crossCheck = st.crossCheck ?? null;
  report.clear =
    freshAtEnd &&
    startOk &&
    eventsOk &&
    // a reset later in the round (the chain under the watermark changed) sends classification back
    // to startBlock: what it found earlier this round no longer covers the history (Codex pre-PR r1)
    st.classifiedTo >= finalized &&
    recentUnknown.size === 0 &&
    crossOk &&
    id.ok &&
    inventoryOk &&
    recentOk &&
    results.every(r => r.status === "ok" || r.status === "paused" || r.status === "not-configured");
  return { alerts, report };
}

/** The daily cross-check's period, and how many failed days in a row raise an alert (DSR 2026-11-17). */
export const CROSS_CHECK_MS = 24 * 3600_000;
export const CROSS_CHECK_ALERT_DAYS = 3;
/** The most inventory entries one cross-check re-asks the primary about, and per getLogs topic list. */
export const MAX_REQUERY_OPERATORS = 1000;
export const REQUERY_TOPICS = 50;
/**
 * The most operators that ever enter the inventory from cross-checks, per state (clestons #448 N8,
 * DSR 2026-11-18). Past it the rest are only counted (mismatch.unlisted) and the disagreement stands:
 * the round is never clear while any is reported. A lying fallback can therefore add at most this
 * many addresses to read, and cannot grow the state without bound.
 */
export const MAX_CROSS_CHECK_ADDED = 100;
/**
 * The most blocks the cross-check may trail the primary's cursor: one day at Sepolia's 12 s.
 * CHAIN-SPECIFIC, NOT CONFIGURED PER CHAIN (DSR 2026-11-17): the value is chosen for Sepolia's block
 * time and must be recomputed here, as (one day / block time), before the detector watches another
 * chain. On OP Mainnet's 2 s blocks one day is 43200; left at 7200 it means 4 h, stricter, costing
 * incomplete days, never a false clear.
 */
export const CROSS_CHECK_MAX_LAG_BLOCKS = 7200;

/**
 * The daily inventory cross-check against the OTHER provider (Daybreak H1, DSR 2026-11-17). Once a
 * day (and every round while a disagreement stands) the other provider is read from startBlock up to
 * H = min(the primary inventory's cursor, the other's finalized block), and its set of operators is
 * compared with the primary's inventory entries at or below H:
 *   - an operator only the other provider has: the primary's index missed it (an honest indexer gap
 *     is enough). Recorded as `fallbackOnly`; it is checked every round from then on;
 *   - an inventory entry the other lacks is asked of the primary again, by operator topic: if the
 *     primary itself has no such log at or below H, it is a harmless superset entry (a block that
 *     later left the chain), otherwise it is `primaryOnly`.
 * Either list non-empty is a disagreement: crossCheckAlerts makes every round unknown until a later
 * cross-check agrees. An attempt that cannot complete (the other provider down or wrong) records
 * the day as incomplete and does NOT make a round unknown; CROSS_CHECK_ALERT_DAYS of them in a row
 * alert. Residual (README): both providers missing the same log the same way is not found.
 * Mutates st.crossCheck. `other` is null when there is no second provider to ask.
 */
export async function crossCheckInventory(
  st,
  {
    primary,
    primaryName,
    other,
    otherName,
    cfg,
    now,
    unavailable = "no second provider to ask",
    persist = () => {},
  }
) {
  const cc = (st.crossCheck ??= emptyCrossCheck());
  const daily = now - cc.lastAttempt >= CROSS_CHECK_MS;
  if (!daily && !cc.mismatch) return { ran: false };
  // nothing of the primary's inventory to compare yet (its first round has not run): not an attempt
  if (st.cursor < st.startBlock) return { ran: false };
  if (daily) cc.lastAttempt = now;
  const canonOf = chain => {
    const m = new Map();
    return async n => {
      if (!m.has(n)) {
        const b = await chain.blockByNumber(n);
        if (!b?.hash) throw new SafeError(`no block ${n}`);
        m.set(n, b.hash);
      }
      return m.get(n);
    };
  };
  try {
    if (topicProblems(cfg.operatorConfiguredTopics).length)
      throw new SafeError("the config's operatorConfiguredTopics is not valid");
    const T = operatorTopics(cfg);
    if (!other) throw new SafeError(unavailable);
    const id = Number(await other.chainId());
    if (id !== st.chainId) throw new SafeError(`the other provider is on chain ${id}`);
    const otherFinal = height(Number(await other.blockNumber("finalized")), "its finalized block");
    const H = Math.min(st.cursor, otherFinal);
    // the comparison must keep up (Daybreak rerun High, DSR 2026-11-17): an H below what a completed
    // cross-check already covered, or more than a day of blocks behind the primary's cursor, means
    // the other provider's finalized block stalled or went back. Such an attempt is incomplete
    // nothing below startBlock can be compared: such an attempt is not a completed cross-check
    // (clestons #448 N5; it would otherwise satisfy "no clear before a first cross-check")
    if (H < st.startBlock)
      throw new SafeError(
        `the other provider's finalized block ${otherFinal} is below startBlock ${st.startBlock}: nothing to compare`
      );
    if (H < (cc.coveredTo ?? 0))
      throw new SafeError(
        `the other provider's finalized block ${otherFinal} is below block ${cc.coveredTo}, which an earlier cross-check covered`
      );
    if (st.cursor - H > CROSS_CHECK_MAX_LAG_BLOCKS)
      throw new SafeError(
        `the other provider's finalized block ${otherFinal} is ${st.cursor - H} blocks behind the inventory (max ${CROSS_CHECK_MAX_LAG_BLOCKS})`
      );
    // a standing disagreement is replaced or cleared only by a comparison that reaches its height,
    // whatever that comparison finds (Daybreak narrow rerun High B, DSR 2026-11-17): a shorter one
    // is not complete
    if (cc.mismatch && H < cc.mismatch.height)
      throw new SafeError(
        `this comparison reaches block ${H}, below the standing disagreement at block ${cc.mismatch.height}`
      );
    const mine = new Set(
      Object.entries(st.operators)
        .filter(([, n]) => n <= H)
        .map(([op]) => op)
    );
    // what the other provider reported and the inventory lacked ENTERS the inventory (clestons #448
    // B1', DSR 2026-11-17), recorded as coming from it, so the very next round checks its stake. The
    // failure direction is safe: an operator only goes into the list of addresses to read; whether it
    // is reported comes from the primary's chain reads at B and SP's own pauseUnderstakedOperator
    // simulation. One a lying provider invented reads "not-configured" (a notice), never PAUSE NEEDED.
    // - chunk by chunk, as each validated chunk arrives (Codex pre-push round 3), and so before the
    //   primary is re-asked (clestons #448 N2, DSR 2026-11-18): a later chunk or the re-query failing
    //   leaves the attempt incomplete but what was seen already checked;
    // - at most MAX_CROSS_CHECK_ADDED per state (N8); past that the overflow marker is set at once,
    //   kept for good (DSR 2026-11-18), and written to disk at once (`persist`, Codex pre-push round
    //   3): a crash later in the run cannot lose it
    st.fromCrossCheck ??= {};
    let room = MAX_CROSS_CHECK_ADDED - Object.keys(st.fromCrossCheck).length;
    const overCap = new Set();
    const markOverflow = count => {
      if (count <= (cc.overflow?.maxCount ?? 0)) return;
      cc.overflow = {
        provider: otherName,
        since: cc.overflow?.since ?? now,
        maxCount: count,
      };
      persist();
    };
    const theirs = new Map(); // operator -> first block the other provider has its log at
    // the other provider is asked BOTH ways (Codex pre-PR r2, r4): topic-filtered, as before, and
    // unfiltered, which also classifies every other topic0, so an event the round's provider once
    // omitted from classification is seen by a second provider within a day. The operators either
    // answer names are compared, as one set
    const known = knownProxyTopics(cfg);
    const otherCanon = canonOf(other);
    const take = (op, n) => {
      if (theirs.has(op)) {
        if (n < theirs.get(op)) theirs.set(op, n);
        return;
      }
      theirs.set(op, n);
      if (mine.has(op) || op in st.operators) return;
      if (room > 0) {
        st.operators[op] = n;
        st.fromCrossCheck[op] = { provider: otherName, block: n, at: now };
        room--;
      } else {
        overCap.add(op);
        markOverflow(overCap.size);
      }
    };
    if (H >= st.startBlock) {
      await operatorLogs(
        other,
        st.spProxy,
        st.startBlock,
        H,
        cfg.logChunk,
        logs => {
          for (const lg of logs) take(opOf(lg.topics[1]), Number(lg.blockNumber));
        },
        otherCanon,
        T
      );
      await allLogs(other, st.spProxy, st.startBlock, H, cfg.logChunk, otherCanon, (lg, t0, n) => {
        const op = operatorOfAny(lg, t0, T, n);
        if (op) take(op, n);
        else if (!known.has(t0)) recordUnknown(st, t0, n);
      });
    }
    // what the other provider has that the inventory lacks, each with who found it and how far
    // that comparison reached
    const found = {};
    for (const op of theirs.keys())
      if (!mine.has(op)) found[op] = { provider: otherName, height: H };
    // a standing fallback-only operator is CARRIED FORWARD (clestons #448 B1/B2/B1'): its only way
    // out of the disagreement is the inventory. A later comparison that no longer reports it, by any
    // provider, does not count: its log was seen on a finalized, hash-checked block and cannot
    // legitimately disappear; a provider that stops reporting it says less, it does not refute it
    // (DSR 2026-11-17, withdrawing the "same provider no longer reports it" exit)
    for (const [op, f] of Object.entries(cc.mismatch?.found ?? {}))
      if (!(op in found) && !(op in st.operators)) found[op] = f;
    // a mismatch from before `found` existed carries its fallback-only operators the same way
    for (const op of cc.mismatch?.found ? [] : (cc.mismatch?.fallbackOnly ?? []))
      if (!(op in found) && !(op in st.operators))
        found[op] = { provider: cc.mismatch.provider, height: cc.mismatch.height };
    // over-cap operators (not added during the scan) are dropped from `found` and only counted, so
    // the record stays bounded and the disagreement stands while they are reported
    let unlisted = 0;
    for (const op of Object.keys(found))
      if (overCap.has(op)) {
        delete found[op];
        unlisted++;
      }
    const fallbackOnly = Object.keys(found).sort();
    // what the fallback found stands as a disagreement NOW, before the fallible re-query (Codex on
    // 4e6dc27, High): an over-cap operator is only counted, so if the re-query below threw, nothing
    // would be left of it and the round could read clear. The attempt is still incomplete; the
    // re-query's outcome replaces this record when it completes. The guards above already passed,
    // so this comparison reaches any standing disagreement's height
    if (fallbackOnly.length || unlisted)
      cc.mismatch = {
        at: now,
        height: H,
        provider: otherName,
        primary: primaryName,
        fallbackOnly,
        primaryOnly: cc.mismatch?.primaryOnly ?? [],
        found,
        unlisted,
      };
    // inventory entries the other provider lacks are asked of the primary again, all at once: one
    // getLogs per chunk with the operators as an OR topic (clestons #448 N1: not operators x chunks)
    const candidates = [...mine].filter(op => !theirs.has(op)).sort();
    if (candidates.length > MAX_REQUERY_OPERATORS)
      throw new SafeError(
        `${candidates.length} inventory entries the other provider lacks (max ${MAX_REQUERY_OPERATORS} re-queried)`
      );
    const confirmed = new Set();
    const primaryCanon = canonOf(primary);
    for (let i = 0; i < candidates.length; i += REQUERY_TOPICS) {
      const group = candidates.slice(i, i + REQUERY_TOPICS);
      const want = new Set(group);
      for (const [a, b] of ranges(st.startBlock, H, cfg.logChunk)) {
        let logs;
        try {
          logs = await primary.getLogs({
            address: st.spProxy,
            topics: [T, group.map(op => ethers.zeroPadValue(op, 32))],
            fromBlock: hex(a),
            toBlock: hex(b),
          });
        } catch (e) {
          throw new SafeError(`${safeText("getLogs", e)} (primary, blocks ${a}-${b})`);
        }
        await checkLogs(logs, st.spProxy, a, b, primaryCanon, T);
        for (const lg of logs) {
          const op = opOf(lg.topics[1]);
          if (want.has(op)) confirmed.add(op);
        }
        if (group.every(op => confirmed.has(op))) break;
      }
    }
    const primaryOnly = candidates.filter(op => confirmed.has(op));
    const outcome =
      fallbackOnly.length || primaryOnly.length || unlisted
        ? {
            at: now,
            height: H,
            provider: otherName,
            primary: primaryName,
            fallbackOnly,
            primaryOnly,
            found,
            unlisted,
          }
        : null;
    cc.lastComplete = now;
    cc.failedDays = 0;
    cc.lastError = null;
    cc.coveredTo = Math.max(cc.coveredTo ?? 0, H);
    cc.mismatch = outcome;
  } catch (e) {
    if (daily) cc.failedDays += 1;
    cc.lastError = safeText("cross-check", e);
  }
  return { ran: true };
}

/** The alerts the cross-check's state raises, every round while they hold. Pure. */
export function crossCheckAlerts(st) {
  const cc = st.crossCheck;
  const out = [];
  if (cc?.mismatch) {
    const m = cc.mismatch;
    const list = a => (a.length ? a.join(", ") : "none");
    out.push({
      key: "crosscheck",
      text:
        `unknown: the two RPC providers disagree on the operator inventory up to block ${m.height} ` +
        `(only ${m.provider} has: ${list(m.fallbackOnly)}` +
        (m.unlisted
          ? `, and ${m.unlisted} more not added to the inventory (at most ${MAX_CROSS_CHECK_ADDED} are)`
          : "") +
        `; only ${m.primary ?? "the round's provider"} has: ${list(m.primaryOnly)}); ` +
        "one provider's log index is wrong; every operator either one names is checked",
    });
  }
  if (cc?.failedDays >= CROSS_CHECK_ALERT_DAYS)
    out.push({
      key: "crosscheck-incomplete",
      text: `the daily inventory cross-check with the other RPC provider has not completed for ${cc.failedDays} days (${cc.lastError ?? "?"})`,
    });
  return out;
}
