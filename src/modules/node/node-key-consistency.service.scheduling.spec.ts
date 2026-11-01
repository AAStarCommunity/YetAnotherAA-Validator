import { jest } from "@jest/globals";
import { NodeKeyConsistencyService } from "./node-key-consistency.service.js";
import { bls, sigs } from "../../utils/bls.util.js";
import { NodeState } from "../../interfaces/node.interface.js";
import { BlockchainService } from "../blockchain/blockchain.service.js";
import { BlsService } from "../bls/bls.service.js";
import { SignerService } from "../signer/signer.service.js";

/**
 * CC-36 round 2/3: the self-check is not a one-shot — it retries with bounded backoff while
 * `unknown` (an RPC blip must not freeze the node on a boot-time hiccup forever) and
 * periodically rechecks once conclusive (so a post-boot on-chain change — e.g. the
 * validator's permissionless `syncNode(nodeId)` deactivating an under-staked operator —
 * eventually surfaces in /health instead of the startup result being shown forever).
 *
 * Timing assertions use a deliberate few-second margin either side of each boundary
 * (mirroring liveness-keeper.service.spec.ts's convention) rather than asserting on the
 * exact millisecond: Jest/@sinonjs fake timers' tickAsync does not guarantee sub-second
 * precision when a timer callback itself chains further awaits before rescheduling.
 */
const realSigner = new SignerService({ get: () => undefined } as any);
const realBls = new BlsService({} as any, realSigner, { get: () => undefined } as any);

function makeKeyPair(seed: number) {
  const privBytes = new Uint8Array(32);
  privBytes[31] = seed;
  const pub = sigs.getPublicKey(privBytes);
  const compressedHex = "0x" + pub.toHex();
  const point = bls.G1.Point.fromHex(pub.toHex());
  const eip2537Hex = realBls.encodePublicKeyToEIP2537(point);
  return { privateKey: "0x" + Buffer.from(privBytes).toString("hex"), compressedHex, eip2537Hex };
}
const KEY_A = makeKeyPair(1);

function nodeState(overrides: Partial<NodeState> = {}): NodeState {
  return {
    nodeId: "0x" + "ab".repeat(32),
    nodeName: "n",
    privateKey: KEY_A.privateKey,
    publicKey: KEY_A.compressedHex,
    createdAt: new Date(0).toISOString(),
    description: "d",
    ...overrides,
  };
}

function makeChain(overrides: {
  checkNodeRegistration?: jest.Mock<() => Promise<boolean>>;
  getNodePublicKey?: jest.Mock<() => Promise<string>>;
  getBlockNumber?: jest.Mock<() => Promise<number>>;
}): BlockchainService {
  return {
    checkNodeRegistration: overrides.checkNodeRegistration ?? jest.fn(() => Promise.resolve(true)),
    getNodePublicKey:
      overrides.getNodePublicKey ?? jest.fn(() => Promise.resolve(KEY_A.eip2537Hex)),
    // Round-6 M1: checkOnchain() pins both reads to one shared block — fixed default so
    // existing assertions (which predate the blockTag param) are unaffected.
    getBlockNumber: overrides.getBlockNumber ?? jest.fn(() => Promise.resolve(12345)),
  } as unknown as BlockchainService;
}

describe("NodeKeyConsistencyService — retry/recheck scheduling (CC-36 round 2/3)", () => {
  beforeEach(() => {
    jest.useFakeTimers();
  });

  afterEach(() => {
    jest.clearAllTimers();
    jest.useRealTimers();
  });

  it("retries with bounded backoff (30s/60s/120s/240s) while stuck on unknown, then folds into the 15-minute cadence", async () => {
    const checkNodeRegistration = jest.fn(() => Promise.reject(new Error("RPC down")));
    const chain = makeChain({ checkNodeRegistration: checkNodeRegistration as any });
    const service = new NodeKeyConsistencyService(chain, realBls);

    service.start(nodeState(), "0xcontract");
    await jest.advanceTimersByTimeAsync(10); // flush the immediate boot attempt
    expect(checkNodeRegistration).toHaveBeenCalledTimes(1);
    expect(service.getLastResult()?.status).toBe("unknown");

    // 1st backoff step (~30s): not yet at 29s, fired by ~31s.
    await jest.advanceTimersByTimeAsync(29_000);
    expect(checkNodeRegistration).toHaveBeenCalledTimes(1);
    await jest.advanceTimersByTimeAsync(3_000);
    expect(checkNodeRegistration).toHaveBeenCalledTimes(2);

    // 2nd step (~60s).
    await jest.advanceTimersByTimeAsync(57_000);
    expect(checkNodeRegistration).toHaveBeenCalledTimes(2);
    await jest.advanceTimersByTimeAsync(4_000);
    expect(checkNodeRegistration).toHaveBeenCalledTimes(3);

    // 3rd step (~120s).
    await jest.advanceTimersByTimeAsync(116_000);
    expect(checkNodeRegistration).toHaveBeenCalledTimes(3);
    await jest.advanceTimersByTimeAsync(5_000);
    expect(checkNodeRegistration).toHaveBeenCalledTimes(4);

    // 4th and LAST backoff step (~240s).
    await jest.advanceTimersByTimeAsync(235_000);
    expect(checkNodeRegistration).toHaveBeenCalledTimes(4);
    await jest.advanceTimersByTimeAsync(6_000);
    expect(checkNodeRegistration).toHaveBeenCalledTimes(5);

    // Backoff exhausted: the NEXT retry folds into the regular 15-minute cadence, NOT
    // another short step — still 5 calls well past where a 5th short retry would be.
    await jest.advanceTimersByTimeAsync(10 * 60_000);
    expect(checkNodeRegistration).toHaveBeenCalledTimes(5);
    await jest.advanceTimersByTimeAsync(6 * 60_000);
    expect(checkNodeRegistration).toHaveBeenCalledTimes(6);

    service.stop();
  });

  it("rechecks periodically (every ~15 minutes) once a conclusive result is reached", async () => {
    const checkNodeRegistration = jest.fn(() => Promise.resolve(true));
    const chain = makeChain({ checkNodeRegistration: checkNodeRegistration as any });
    const service = new NodeKeyConsistencyService(chain, realBls);

    service.start(nodeState(), "0xcontract");
    await jest.advanceTimersByTimeAsync(10);
    expect(service.getLastResult()?.status).toBe("ok");
    expect(checkNodeRegistration).toHaveBeenCalledTimes(1);

    await jest.advanceTimersByTimeAsync(14 * 60_000); // well under 15 minutes
    expect(checkNodeRegistration).toHaveBeenCalledTimes(1);
    await jest.advanceTimersByTimeAsync(2 * 60_000); // push comfortably past it
    expect(checkNodeRegistration).toHaveBeenCalledTimes(2);

    service.stop();
  });

  it("a recheck RPC failure PRESERVES the prior conclusive result — never downgrades it to unknown", async () => {
    const checkNodeRegistration = jest
      .fn<() => Promise<boolean>>()
      .mockResolvedValueOnce(true) // boot: registered
      .mockRejectedValueOnce(new Error("RPC blip") as never); // 15-min recheck: fails
    const chain = makeChain({ checkNodeRegistration: checkNodeRegistration as any });
    const service = new NodeKeyConsistencyService(chain, realBls);

    service.start(nodeState(), "0xcontract");
    await jest.advanceTimersByTimeAsync(10);
    const first = service.getLastResult();
    expect(first?.status).toBe("ok");

    // Cross the ~15-minute recheck boundary WITHOUT also reaching the next (unknown-triggered)
    // 30s backoff retry — i.e. land in (900s, 930s), not "comfortably past" by minutes, or the
    // mock (deliberately configured for exactly 2 calls) would be exhausted by a 3rd attempt.
    await jest.advanceTimersByTimeAsync(14 * 60_000); // well under 900s
    expect(checkNodeRegistration).toHaveBeenCalledTimes(1);
    await jest.advanceTimersByTimeAsync(65_000); // total ~905s: past 900s, still well under 930s
    const second = service.getLastResult();
    // status/checkedAt/derivedMatches/nodeId are PRESERVED — a transient RPC failure must
    // never launder a known conclusion into "unknown".
    expect(second?.status).toBe("ok");
    expect(second?.checkedAt).toBe(first?.checkedAt);
    expect(second?.derivedMatches).toBe(first?.derivedMatches);
    // …but lastAttemptAt DID advance, proving a retry actually happened rather than the
    // loop having silently died.
    expect(second?.lastAttemptAt).not.toBe(first?.lastAttemptAt);
    expect(checkNodeRegistration).toHaveBeenCalledTimes(2);

    service.stop();
  });

  it("a recheck RPC failure must not paper over a real mismatch_onchain either", async () => {
    const checkNodeRegistration = jest.fn(() => Promise.resolve(true));
    const getNodePublicKey = jest
      .fn<() => Promise<string>>()
      .mockResolvedValueOnce("0x" + "11".repeat(128)) // boot: someone else's key registered
      .mockRejectedValueOnce(new Error("RPC blip") as never); // recheck: RPC fails
    const chain = makeChain({
      checkNodeRegistration: checkNodeRegistration as any,
      getNodePublicKey: getNodePublicKey as any,
    });
    const service = new NodeKeyConsistencyService(chain, realBls);

    service.start(nodeState(), "0xcontract");
    await jest.advanceTimersByTimeAsync(10);
    expect(service.getLastResult()?.status).toBe("mismatch_onchain");

    // Same landing window as the "ok preserved" test above — past the ~900s recheck, well
    // short of the ~930s a subsequent unknown-triggered backoff retry would add.
    await jest.advanceTimersByTimeAsync(14 * 60_000);
    expect(getNodePublicKey).toHaveBeenCalledTimes(1);
    await jest.advanceTimersByTimeAsync(65_000);
    // Still mismatch_onchain — NOT washed out to "unknown" by the failed recheck attempt.
    expect(service.getLastResult()?.status).toBe("mismatch_onchain");
    expect(getNodePublicKey).toHaveBeenCalledTimes(2);

    service.stop();
  });

  it("stop() clears the timer — no leftover handle after shutdown", async () => {
    const chain = makeChain({});
    const service = new NodeKeyConsistencyService(chain, realBls);
    service.start(nodeState(), "0xcontract");
    await jest.advanceTimersByTimeAsync(10);
    expect(jest.getTimerCount()).toBeGreaterThan(0);

    service.stop();
    expect(jest.getTimerCount()).toBe(0);
  });

  it("onModuleDestroy() also clears the timer (Nest lifecycle hook) — same guarantee as stop()", async () => {
    const chain = makeChain({});
    const service = new NodeKeyConsistencyService(chain, realBls);
    service.start(nodeState(), "0xcontract");
    await jest.advanceTimersByTimeAsync(10);

    service.onModuleDestroy();
    expect(jest.getTimerCount()).toBe(0);

    // And no further attempts happen even if time is advanced well past any cadence.
    const chainCalls = (chain.checkNodeRegistration as jest.Mock).mock.calls.length;
    await jest.advanceTimersByTimeAsync(60 * 60_000);
    expect((chain.checkNodeRegistration as jest.Mock).mock.calls.length).toBe(chainCalls);
  });

  it("start() is idempotent: calling it again restarts cleanly instead of stacking loops", async () => {
    const checkNodeRegistration = jest.fn(() => Promise.resolve(true));
    const chain = makeChain({ checkNodeRegistration: checkNodeRegistration as any });
    const service = new NodeKeyConsistencyService(chain, realBls);

    service.start(nodeState(), "0xcontract");
    await jest.advanceTimersByTimeAsync(10);
    expect(checkNodeRegistration).toHaveBeenCalledTimes(1);

    service.start(nodeState(), "0xcontract"); // restart before any timer fires
    await jest.advanceTimersByTimeAsync(10);
    expect(checkNodeRegistration).toHaveBeenCalledTimes(2); // one fresh immediate check, not two

    // Only ONE timer pending, not a second stacked loop still running from the first start().
    expect(jest.getTimerCount()).toBe(1);

    service.stop();
  });

  it("MEDIUM-4: start() while a check is in flight discards the stale check's result and does not stack timers", async () => {
    let resolveFirst!: (v: boolean) => void;
    const firstCallPromise = new Promise<boolean>(resolve => {
      resolveFirst = resolve;
    });
    const checkNodeRegistration = jest
      .fn<() => Promise<boolean>>()
      .mockImplementationOnce(() => firstCallPromise) // 1st call: hangs until resolved manually
      .mockImplementation(() => Promise.resolve(true)); // every later call: normal ok
    const chain = makeChain({ checkNodeRegistration: checkNodeRegistration as any });
    const service = new NodeKeyConsistencyService(chain, realBls);

    const oldNodeId = "0x" + "aa".repeat(32);
    const newNodeId = "0x" + "bb".repeat(32);

    service.start(nodeState({ nodeId: oldNodeId }), "0xcontract");
    await jest.advanceTimersByTimeAsync(1); // let the loop start awaiting the hung RPC call
    expect(checkNodeRegistration).toHaveBeenCalledTimes(1);
    expect(service.getLastResult()).toBeNull(); // still in flight — nothing published yet

    // Restart with a NEW identity WHILE the old check is still hanging.
    service.start(nodeState({ nodeId: newNodeId }), "0xcontract");
    await jest.advanceTimersByTimeAsync(1); // the new loop's immediate check runs and resolves
    expect(checkNodeRegistration).toHaveBeenCalledTimes(2);
    expect(service.getLastResult()?.status).toBe("ok");
    expect(service.getLastResult()?.nodeId).toBe(newNodeId);

    // NOW let the OLD hung check finally resolve.
    resolveFirst(true);
    await jest.advanceTimersByTimeAsync(1);

    // The stale result must NOT have overwritten the new identity's published result.
    expect(service.getLastResult()?.nodeId).toBe(newNodeId);
    // And only ONE timer is pending — the old (stale) loop must not have rescheduled itself.
    expect(jest.getTimerCount()).toBe(1);

    service.stop();
  });

  it("M2 (round 6): an old in-flight check that REJECTS after being superseded checks staleness FIRST — no checkerError leaks onto the new identity", async () => {
    // Codex round-3 finding: the catch in loop() called recordCheckerError() BEFORE checking
    // the generation, so a superseded (stale) attempt that eventually REJECTS (not just
    // resolves — Medium-4 only covered the resolving case) would stamp its error onto
    // whichever identity happens to be CURRENT when it settles. This spies on check() itself
    // to control exactly when the OLD attempt settles, independent of what internally causes
    // it to reject.
    const checkNodeRegistration = jest.fn(() => Promise.resolve(true));
    const chain = makeChain({ checkNodeRegistration: checkNodeRegistration as any });
    const service = new NodeKeyConsistencyService(chain, realBls);

    let rejectFirst!: (err: Error) => void;
    const firstCheckPromise = new Promise<any>((_resolve, reject) => {
      rejectFirst = reject;
    });
    const realCheck = service.check.bind(service);
    let checkCallCount = 0;
    jest.spyOn(service, "check").mockImplementation((...args: any[]) => {
      checkCallCount++;
      if (checkCallCount === 1) {
        return firstCheckPromise; // the FIRST (old-identity) attempt hangs, then rejects
      }
      return (realCheck as any)(...args);
    });

    const oldNodeId = "0x" + "aa".repeat(32);
    const newNodeId = "0x" + "bb".repeat(32);

    service.start(nodeState({ nodeId: oldNodeId }), "0xcontract");
    await jest.advanceTimersByTimeAsync(1); // loop() is now awaiting the hung first check()
    expect(service.getLastResult()).toBeNull();

    // Supersede it with a NEW identity while the old attempt is still hanging.
    service.start(nodeState({ nodeId: newNodeId }), "0xcontract");
    await jest.advanceTimersByTimeAsync(1); // the new loop's OWN check() runs for real
    expect(service.getLastResult()?.status).toBe("ok");
    expect(service.getLastResult()?.nodeId).toBe(newNodeId);

    // NOW the OLD (superseded) check() finally REJECTS.
    rejectFirst(new Error("stale RPC error from a superseded identity"));
    await jest.advanceTimersByTimeAsync(1);

    const after = service.getLastResult();
    // Untouched: still the NEW identity's clean "ok" — no checkerError leaked onto it.
    expect(after?.nodeId).toBe(newNodeId);
    expect(after?.status).toBe("ok");
    expect(after?.checkerError).toBeUndefined();
    // The stale loop must not reschedule either — only ONE timer pending.
    expect(jest.getTimerCount()).toBe(1);

    service.stop();
  });

  it("M2b (round 6): an old in-flight check that REJECTS after clearResult() must not resurrect the cleared result", async () => {
    const checkNodeRegistration = jest.fn(() => Promise.resolve(true));
    const chain = makeChain({ checkNodeRegistration: checkNodeRegistration as any });
    const service = new NodeKeyConsistencyService(chain, realBls);

    let rejectFirst!: (err: Error) => void;
    const firstCheckPromise = new Promise<any>((_resolve, reject) => {
      rejectFirst = reject;
    });
    const realCheck = service.check.bind(service);
    let checkCallCount = 0;
    jest.spyOn(service, "check").mockImplementation((...args: any[]) => {
      checkCallCount++;
      if (checkCallCount === 1) {
        return firstCheckPromise;
      }
      return (realCheck as any)(...args);
    });

    service.start(nodeState(), "0xcontract");
    await jest.advanceTimersByTimeAsync(1); // still hanging on the first (only) check()
    expect(service.getLastResult()).toBeNull();

    // Node deleted: stop + clearResult (mirrors NodeService.reloadNodeState()'s "no node" path).
    service.stop();
    service.clearResult();
    expect(service.getLastResult()).toBeNull();

    // The OLD hung check now rejects.
    rejectFirst(new Error("stale RPC error after deletion"));
    await jest.advanceTimersByTimeAsync(1);

    // Must STILL be null — the stale rejection must not resurrect anything.
    expect(service.getLastResult()).toBeNull();
    expect(jest.getTimerCount()).toBe(0);
  });

  it("HIGH-3: an unexpected throw deep inside a check() attempt never produces an unhandledRejection, and the loop survives it", async () => {
    const chain = makeChain({});
    const service = new NodeKeyConsistencyService(chain, realBls);

    // A pathological nodeState: reading .nodeId throws, simulating some future bug reading a
    // raw disk-JSON field this check doesn't (or one day might not) defensively guard. This
    // exercises the STRUCTURAL boundary (loop()'s own try/catch around check(), plus the
    // outer .catch(() => {}) at each loop() call site) rather than any one specific guard.
    const poisoned = { ...nodeState() } as NodeState;
    Object.defineProperty(poisoned, "nodeId", {
      get(): never {
        throw new Error("simulated malformed disk field");
      },
    });

    const unhandled: unknown[] = [];
    const onUnhandledRejection = (reason: unknown) => unhandled.push(reason);
    process.on("unhandledRejection", onUnhandledRejection);
    try {
      service.start(poisoned, "0xcontract");
      await jest.advanceTimersByTimeAsync(1);
      // One more flush in case anything was left dangling on a later microtask.
      await jest.advanceTimersByTimeAsync(0);

      expect(unhandled).toEqual([]);
      // The loop survived: it scheduled a next attempt instead of dying silently.
      expect(jest.getTimerCount()).toBe(1);
      // FAIL-LOUD (round-3 Medium): this is NOT silent — /health must be able to see that the
      // checker itself broke, not just that no result exists.
      expect(service.getLastResult()?.checkerError).toContain("simulated malformed disk field");
      expect(service.getLastResult()?.checkerErrorAt).toBeDefined();
    } finally {
      process.off("unhandledRejection", onUnhandledRejection);
      service.stop();
    }
  });

  it("HIGH-3 regression: a non-string node_state field (raw disk JSON) does not crash the check, and does NOT spuriously set checkerError", async () => {
    const chain = makeChain({
      checkNodeRegistration: jest.fn(() => Promise.resolve(true)) as any,
    });
    const service = new NodeKeyConsistencyService(chain, realBls);
    // Simulates a node_state.json that doesn't match the NodeState type at runtime (no schema
    // validation guards this file today) — publicKey as a number, not a string. Round-3
    // hardened parsePublicKeyPoint()/normalizeHex() handle this gracefully (return
    // null/"" rather than throw), so — unlike the poisoned-getter test above — this one
    // should NOT reach the checker-error path at all; it's a plain determinate result.
    const malformed = { ...nodeState(), publicKey: 12345 as unknown as string };

    const unhandled: unknown[] = [];
    const onUnhandledRejection = (reason: unknown) => unhandled.push(reason);
    process.on("unhandledRejection", onUnhandledRejection);
    try {
      service.start(malformed, "0xcontract");
      await jest.advanceTimersByTimeAsync(1);
      await jest.advanceTimersByTimeAsync(0);

      expect(unhandled).toEqual([]);
      expect(service.getLastResult()).not.toBeNull();
      expect(service.getLastResult()?.checkerError).toBeUndefined();
      expect(jest.getTimerCount()).toBe(1);
    } finally {
      process.off("unhandledRejection", onUnhandledRejection);
      service.stop();
    }
  });

  it("MEDIUM (round 3): a checker-internal throw preserves the prior conclusive result but stamps checkerError; clears on the next healthy attempt", async () => {
    const checkNodeRegistration = jest.fn(() => Promise.resolve(true));
    const chain = makeChain({ checkNodeRegistration: checkNodeRegistration as any });
    const service = new NodeKeyConsistencyService(chain, realBls);

    const state = nodeState();
    const originalNodeId = state.nodeId;

    service.start(state, "0xcontract");
    await jest.advanceTimersByTimeAsync(10);
    const first = service.getLastResult();
    expect(first?.status).toBe("ok");
    expect(first?.checkerError).toBeUndefined();

    // Poison nodeId AFTER the first successful attempt, so the NEXT scheduled (periodic
    // recheck) attempt throws internally — simulating a future bug, NOT an RPC blip.
    Object.defineProperty(state, "nodeId", {
      configurable: true,
      get(): never {
        throw new Error("simulated internal bug");
      },
    });

    await jest.advanceTimersByTimeAsync(14 * 60_000); // well under the ~900s recheck
    expect(checkNodeRegistration).toHaveBeenCalledTimes(1);
    await jest.advanceTimersByTimeAsync(65_000); // past it: the recheck fires and throws

    const second = service.getLastResult();
    // The prior CONCLUSIVE result is preserved — an internal bug is NOT grounds to erase it
    // (same non-downgrade principle as an RPC failure).
    expect(second?.status).toBe("ok");
    expect(second?.checkedAt).toBe(first?.checkedAt);
    // …but it is now explicitly, visibly flagged as checker-broken (fail-loud, not silent),
    // and lastAttemptAt still advanced (the loop is alive, still ticking).
    expect(second?.checkerError).toContain("simulated internal bug");
    expect(second?.checkerErrorAt).toBeDefined();
    expect(second?.lastAttemptAt).not.toBe(first?.lastAttemptAt);
    // checkNodeRegistration must NOT have been reached — the throw happens before checkOnchain.
    expect(checkNodeRegistration).toHaveBeenCalledTimes(1);

    // Un-poison — the next attempt completes normally and must clear checkerError, proving
    // it isn't a permanent scar once the checker is healthy again.
    Object.defineProperty(state, "nodeId", {
      configurable: true,
      value: originalNodeId,
      writable: true,
    });
    await jest.advanceTimersByTimeAsync(16 * 60_000); // past the next ~900s recheck

    const third = service.getLastResult();
    expect(third?.checkerError).toBeUndefined();
    expect(third?.checkerErrorAt).toBeUndefined();
    expect(third?.status).toBe("ok");
    expect(third?.checkedAt).not.toBe(second?.checkedAt); // a fresh conclusion was established
    expect(checkNodeRegistration).toHaveBeenCalledTimes(2);

    service.stop();
  });

  it("INVARIANT (round-4/7): a remote-signer node NEVER causes the checker to call fetch (no probe, no signature), across boot + several periodic rechecks — OPTIONAL mode (exercises the local_fallback derivation path)", async () => {
    // Codex + coordinator round-4: the checker must NEVER invoke the remote signer at all —
    // an earlier version probed its /sign endpoint to read a public key back, which produces
    // a REAL, unauthorized signature (see BlsService.resolveSigningPublicKey's docstring for
    // why that breaks this repo's core owner-authorization invariant). This test spies on the
    // one shared entry point any such call would have to go through (global fetch) and runs
    // the self-check through a boot attempt plus several periodic recheck cycles, asserting
    // zero calls throughout — not just on a single one-shot check().
    //
    // Round-7: this config (rustSignerUrl set, rustSignerRequired NOT set) is OPTIONAL mode,
    // and nodeState() carries a privateKey — so this now exercises the local_fallback
    // derivation path (a REAL local key check, but pure @noble/curves computation, zero
    // network I/O) on every single tick. The invariant must still hold: fetch stays at 0.
    const fetchSpy = jest.fn();
    const originalFetch = global.fetch;
    global.fetch = fetchSpy as any;
    try {
      const remoteBls = new BlsService({} as any, realSigner, {
        get: (k: string) => (k === "rustSignerUrl" ? "http://fake-signer.local" : undefined),
      } as any);
      const checkNodeRegistration = jest.fn(() => Promise.resolve(true));
      const chain = makeChain({ checkNodeRegistration: checkNodeRegistration as any });
      const service = new NodeKeyConsistencyService(chain, remoteBls);

      service.start(nodeState(), "0xcontract");
      await jest.advanceTimersByTimeAsync(10); // boot attempt
      // Optional mode + a local key + node_state internally consistent -> ok, scoped.
      expect(service.getLastResult()?.status).toBe("ok");
      expect(service.getLastResult()?.scope).toBe("local_fallback_only");

      // Several periodic recheck cycles.
      await jest.advanceTimersByTimeAsync(16 * 60_000);
      await jest.advanceTimersByTimeAsync(16 * 60_000);
      await jest.advanceTimersByTimeAsync(16 * 60_000);
      expect(checkNodeRegistration.mock.calls.length).toBeGreaterThanOrEqual(4); // boot + 3 rechecks actually ran

      expect(fetchSpy).not.toHaveBeenCalled();
      service.stop();
    } finally {
      global.fetch = originalFetch;
    }
  });

  it("INVARIANT (round-7): REQUIRED mode also never calls fetch, across boot + several periodic rechecks", async () => {
    const fetchSpy = jest.fn();
    const originalFetch = global.fetch;
    global.fetch = fetchSpy as any;
    try {
      const remoteBls = new BlsService({} as any, realSigner, {
        get: (k: string) =>
          k === "rustSignerUrl"
            ? "http://fake-signer.local"
            : k === "rustSignerRequired"
              ? true
              : undefined,
      } as any);
      const checkNodeRegistration = jest.fn(() => Promise.resolve(true));
      const chain = makeChain({ checkNodeRegistration: checkNodeRegistration as any });
      const service = new NodeKeyConsistencyService(chain, remoteBls);

      service.start(nodeState(), "0xcontract");
      await jest.advanceTimersByTimeAsync(10);
      expect(service.getLastResult()?.status).toBe("skipped_remote_signer");
      expect(service.getLastResult()?.scope).toBeUndefined();

      await jest.advanceTimersByTimeAsync(16 * 60_000);
      await jest.advanceTimersByTimeAsync(16 * 60_000);
      await jest.advanceTimersByTimeAsync(16 * 60_000);
      expect(checkNodeRegistration.mock.calls.length).toBeGreaterThanOrEqual(4);

      expect(fetchSpy).not.toHaveBeenCalled();
      service.stop();
    } finally {
      global.fetch = originalFetch;
    }
  });
});
