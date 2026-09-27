import { jest } from "@jest/globals";
import { NodeKeyConsistencyService } from "./node-key-consistency.service.js";
import { bls, sigs } from "../../utils/bls.util.js";
import { NodeState } from "../../interfaces/node.interface.js";
import { BlockchainService } from "../blockchain/blockchain.service.js";
import { BlsService } from "../bls/bls.service.js";

/**
 * CC-36 round 2: the self-check is not a one-shot — it retries with bounded backoff while
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
const realBls = new BlsService({} as any, {} as any);

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
}): BlockchainService {
  return {
    checkNodeRegistration: overrides.checkNodeRegistration ?? jest.fn(() => Promise.resolve(true)),
    getNodePublicKey:
      overrides.getNodePublicKey ?? jest.fn(() => Promise.resolve(KEY_A.eip2537Hex)),
  } as unknown as BlockchainService;
}

describe("NodeKeyConsistencyService — retry/recheck scheduling (CC-36 round 2)", () => {
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
});
