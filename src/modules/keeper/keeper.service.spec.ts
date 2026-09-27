import { jest } from "@jest/globals";
import { Logger } from "@nestjs/common";
import { KeeperService } from "./keeper.service.js";

const PAYMASTER = "0x" + "12".repeat(20);
const CHAINLINK = "0x" + "34".repeat(20);

const BASE_CONFIG: Record<string, unknown> = {
  keeperEnabled: true,
  keeperIntervalMs: 60_000,
  keeperRefreshBufferS: "300",
  keeperMaxUpdatesPerDay: 48,
  keeperMaxBaseFeeGwei: "50",
  keeperPaymasterAddress: PAYMASTER,
  keeperChainlinkFeed: CHAINLINK,
};

function makeConfig(overrides: Record<string, unknown> = {}) {
  const cfg = { ...BASE_CONFIG, ...overrides };
  return { get: (k: string) => cfg[k] } as any;
}

function makeBlockchain(
  overrides: Partial<{
    getPriceInfo: () => Promise<{ updatedAt: bigint; threshold: bigint }>;
    getChainlinkUpdatedAt: () => Promise<bigint>;
    getBaseFeeGwei: () => Promise<bigint>;
    updatePrice: () => Promise<string>;
    canUpdatePrice: () => Promise<boolean>;
  }> = {}
): any {
  return {
    getPriceInfo: overrides.getPriceInfo ?? (async () => ({ updatedAt: 1000n, threshold: 3600n })),
    getChainlinkUpdatedAt: overrides.getChainlinkUpdatedAt ?? (async () => 2000n),
    getBaseFeeGwei: overrides.getBaseFeeGwei ?? (async () => 10n),
    updatePrice: overrides.updatePrice ?? (async () => "0xabc"),
    // Default: the on-chain static-sim says the update would succeed.
    canUpdatePrice: overrides.canUpdatePrice ?? (async () => true),
  };
}

function makeNotify() {
  const sent: string[] = [];
  return {
    sent,
    sendToAccount: async (_: string, msg: string) => {
      sent.push(msg);
      return true;
    },
  } as any;
}

function makeRegistry() {
  const registered: string[] = [];
  return {
    registered,
    register: (cap: { name: string }) => registered.push(cap.name),
  } as any;
}

/** Stand-in for OpsAlertService — only `isEnabled()` matters to the self-check. */
function makeOpsAlert(configured: boolean) {
  return { isEnabled: () => configured, alert: jest.fn() } as any;
}

/** Fixed clock at t=now (unix ms). Allows overriding "now" for time-based guardrail tests. */
function clockAt(nowMs: number) {
  return () => nowMs;
}

// A "now" where the price (updatedAt=1000s, threshold=3600s) is near expiry:
// age = nowS - 1000, timeUntilStale = 3600 - age. For timeUntilStale ≤ 300 (buffer):
// nowS ≥ 1000 + 3600 - 300 = 4300 → nowMs ≥ 4_300_000
const NOW_NEAR_EXPIRY = clockAt(4_350_000); // timeUntilStale = 3600 - (4350 - 1000) = 250s ≤ 300

describe("KeeperService", () => {
  it("registers capability as disabled when KEEPER_ENABLED=false", () => {
    const registry = makeRegistry();
    new KeeperService(
      makeBlockchain(),
      makeNotify(),
      makeConfig({ keeperEnabled: false }),
      clockAt(0),
      registry
    );
    expect(registry.registered).toContain("keeper");
  });

  it("registers capability as enabled when KEEPER_ENABLED=true", () => {
    const registry = makeRegistry();
    new KeeperService(makeBlockchain(), makeNotify(), makeConfig(), clockAt(0), registry);
    expect(registry.registered).toContain("keeper");
  });

  it("tick: skips when price is still fresh (timeUntilStale > buffer)", async () => {
    // nowS=1100 → age=100 → timeUntilStale=3500 > 300 → skip
    const blockchain = makeBlockchain({
      getPriceInfo: async () => ({ updatedAt: 1000n, threshold: 3600n }),
      updatePrice: async () => {
        throw new Error("should not be called");
      },
    });
    const svc = new KeeperService(
      makeBlockchain(blockchain as any),
      makeNotify(),
      makeConfig(),
      clockAt(1_100_000)
    );
    await svc.tick();
    // no throw → update was NOT called
  });

  it("tick: skips when Chainlink has not updated since last cached price", async () => {
    const updatePriceCalled: boolean[] = [];
    const blockchain = makeBlockchain({
      getChainlinkUpdatedAt: async () => 999n, // ≤ updatedAt=1000 → skip
      updatePrice: async () => {
        updatePriceCalled.push(true);
        return "0x";
      },
    });
    const svc = new KeeperService(blockchain, makeNotify(), makeConfig(), NOW_NEAR_EXPIRY);
    await svc.tick();
    expect(updatePriceCalled).toHaveLength(0);
  });

  it("tick: skips when baseFee exceeds max", async () => {
    const updatePriceCalled: boolean[] = [];
    const blockchain = makeBlockchain({
      getBaseFeeGwei: async () => 100n, // > maxBaseFeeGwei=50
      updatePrice: async () => {
        updatePriceCalled.push(true);
        return "0x";
      },
    });
    const svc = new KeeperService(blockchain, makeNotify(), makeConfig(), NOW_NEAR_EXPIRY);
    await svc.tick();
    expect(updatePriceCalled).toHaveLength(0);
  });

  it("tick: calls updatePrice when all conditions met", async () => {
    const updatePriceCalled: string[] = [];
    const blockchain = makeBlockchain({
      updatePrice: async () => {
        updatePriceCalled.push("called");
        return "0xTXHASH";
      },
    });
    const svc = new KeeperService(blockchain, makeNotify(), makeConfig(), NOW_NEAR_EXPIRY);
    await svc.tick();
    expect(updatePriceCalled).toHaveLength(1);
  });

  it("tick: skips submit when static-sim says updatePrice would revert (another keeper won)", async () => {
    const updatePriceCalled: boolean[] = [];
    const blockchain = makeBlockchain({
      // stale + chainlink newer (would normally submit), but the pre-submit
      // static-sim reverts → another keeper already refreshed it → skip.
      canUpdatePrice: async () => false,
      updatePrice: async () => {
        updatePriceCalled.push(true);
        return "0x";
      },
    });
    const svc = new KeeperService(blockchain, makeNotify(), makeConfig(), NOW_NEAR_EXPIRY);
    await svc.tick();
    expect(updatePriceCalled).toHaveLength(0);
  });

  it("tick: skips when daily cap reached", async () => {
    const updatePriceCalled: boolean[] = [];
    const blockchain = makeBlockchain({
      updatePrice: async () => {
        updatePriceCalled.push(true);
        return "0x";
      },
    });
    const svc = new KeeperService(
      blockchain,
      makeNotify(),
      makeConfig({ keeperMaxUpdatesPerDay: 2 }),
      NOW_NEAR_EXPIRY
    );
    // Drain the cap
    await svc.tick();
    await svc.tick();
    expect(updatePriceCalled).toHaveLength(2);
    // 3rd tick should be blocked by cap
    await svc.tick();
    expect(updatePriceCalled).toHaveLength(2);
  });

  it("tick: does not throw when updatePrice fails — sends notification", async () => {
    const notify = makeNotify();
    const blockchain = makeBlockchain({
      updatePrice: async () => {
        throw new Error("reverted");
      },
    });
    const svc = new KeeperService(blockchain, notify, makeConfig(), NOW_NEAR_EXPIRY);
    await expect(svc.tick()).resolves.toBeUndefined(); // must not throw
    // give fire-and-forget a microtask to settle
    await Promise.resolve();
    expect((notify.sent as string[]).some((m: string) => m.includes("reverted"))).toBe(true);
  });

  it("tick: daily counter resets on a new day", async () => {
    const updatePriceCalled: boolean[] = [];
    const blockchain = makeBlockchain({
      updatePrice: async () => {
        updatePriceCalled.push(true);
        return "0x";
      },
    });
    // Day 0: t=4_350_000 (near expiry, day 0 = floor(4350000/86400000)=0)
    let now = 4_350_000;
    const svc = new KeeperService(
      blockchain,
      makeNotify(),
      makeConfig({ keeperMaxUpdatesPerDay: 1 }),
      () => now
    );
    await svc.tick(); // uses the cap → cap exhausted for day 0
    expect(updatePriceCalled).toHaveLength(1);
    await svc.tick(); // still day 0, cap=1 → skip
    expect(updatePriceCalled).toHaveLength(1);
    // Advance clock to day 1
    now = 86_400_000 + 4_350_000;
    await svc.tick(); // new day → counter reset → updatePrice() called again
    expect(updatePriceCalled).toHaveLength(2);
  });

  it("tick: refreshes every paymaster in a comma-separated list (independent thresholds)", async () => {
    const updated: string[] = [];
    const blockchain = makeBlockchain({
      // both stale at NOW_NEAR_EXPIRY (updatedAt=1000, threshold=3600)
      getPriceInfo: async () => ({ updatedAt: 1000n, threshold: 3600n }),
      updatePrice: async (addr?: string) => {
        updated.push(addr ?? "?");
        return "0xTX";
      },
    } as any);
    const a = "0x" + "aa".repeat(20);
    const b = "0x" + "bb".repeat(20);
    const svc = new KeeperService(
      blockchain,
      makeNotify(),
      makeConfig({ keeperPaymasterAddress: `${a}, ${b}` }),
      NOW_NEAR_EXPIRY
    );
    await svc.tick();
    expect(updated).toEqual([a, b]);
  });

  it("tick: shared daily cap stops mid-list", async () => {
    const updated: string[] = [];
    const blockchain = makeBlockchain({
      getPriceInfo: async () => ({ updatedAt: 1000n, threshold: 3600n }),
      updatePrice: async (addr?: string) => {
        updated.push(addr ?? "?");
        return "0xTX";
      },
    } as any);
    const a = "0x" + "aa".repeat(20);
    const b = "0x" + "bb".repeat(20);
    const svc = new KeeperService(
      blockchain,
      makeNotify(),
      makeConfig({ keeperPaymasterAddress: `${a},${b}`, keeperMaxUpdatesPerDay: 1 }),
      NOW_NEAR_EXPIRY
    );
    await svc.tick();
    expect(updated).toEqual([a]); // cap=1 → only the first paymaster updates
  });

  it("onApplicationShutdown clears the startup timer scheduled at bootstrap", () => {
    const svc = new KeeperService(makeBlockchain(), makeNotify(), makeConfig(), clockAt(0));
    svc.onApplicationBootstrap();
    // First tick is phase-jittered via setTimeout, so the interval timer is not
    // armed yet — the startup timer holds the pending first tick.
    expect((svc as any).startupTimer).not.toBeNull();
    expect((svc as any).timer).toBeNull();
    svc.onApplicationShutdown();
    expect((svc as any).startupTimer).toBeNull();
    expect((svc as any).timer).toBeNull();
  });

  it("computeJitterMs: phase offset stays within [0, intervalMs)", () => {
    const mk = (rand: number) =>
      new KeeperService(
        makeBlockchain(),
        makeNotify(),
        makeConfig({ keeperIntervalMs: 60_000 }),
        clockAt(0),
        undefined,
        () => rand
      );
    expect(mk(0).computeJitterMs()).toBe(0);
    expect(mk(0.5).computeJitterMs()).toBe(30_000);
    // random() is in [0,1); the offset must never reach the full interval.
    expect(mk(0.999999).computeJitterMs()).toBeLessThan(60_000);
    expect(mk(0.999999).computeJitterMs()).toBeGreaterThanOrEqual(0);
  });

  it("jitter: first tick fires after the offset, then the interval is armed", async () => {
    jest.useFakeTimers();
    try {
      const updates: boolean[] = [];
      const blockchain = makeBlockchain({
        getPriceInfo: async () => ({ updatedAt: 1000n, threshold: 3600n }),
        updatePrice: async () => {
          updates.push(true);
          return "0x";
        },
      });
      const svc = new KeeperService(
        blockchain,
        makeNotify(),
        makeConfig({ keeperIntervalMs: 60_000 }),
        NOW_NEAR_EXPIRY,
        undefined,
        () => 0.5 // jitter = 30_000ms
      );
      svc.onApplicationBootstrap();
      expect((svc as any).startupTimer).not.toBeNull();

      // advanceTimersByTimeAsync flushes the awaited microtasks in tick()
      // between timer callbacks, so the full async chain settles.
      await jest.advanceTimersByTimeAsync(30_000);
      expect(updates).toHaveLength(1);
      expect((svc as any).startupTimer).toBeNull();
      expect((svc as any).timer).not.toBeNull();

      svc.onApplicationShutdown();
      expect((svc as any).timer).toBeNull();
    } finally {
      jest.useRealTimers();
    }
  });
});

/**
 * Startup self-check: "keeper enabled but alerts unconfigured" must never go
 * unnoticed silently (the real incident that motivates this: a neighboring repo's
 * price keeper ran for 3.5 weeks, failing every tick, with a broken alert channel
 * — nobody knew). This must ONLY ever log; it must never throw or block startup.
 *
 * Scope note (see keeper.service.ts docstring): this checks CONFIGURATION
 * (OpsAlertService.isEnabled()), not deliverability — it cannot and does not
 * claim to catch a configured-but-dead transport.
 */
describe("KeeperService — startup self-check: alert configured", () => {
  let errorSpy: ReturnType<typeof jest.spyOn>;

  beforeEach(() => {
    errorSpy = jest.spyOn(Logger.prototype, "error").mockImplementation((() => undefined) as any);
  });

  afterEach(() => {
    errorSpy.mockRestore();
  });

  it("keeper enabled + alerts configured ⇒ no self-check error", () => {
    const svc = new KeeperService(
      makeBlockchain(),
      makeNotify(),
      makeConfig(),
      clockAt(0),
      makeRegistry(),
      undefined,
      makeOpsAlert(true)
    );
    svc.onApplicationBootstrap();
    svc.onApplicationShutdown();
    expect(errorSpy).not.toHaveBeenCalled();
  });

  it("keeper enabled + OpsAlertService present but disabled ⇒ logs an error at startup", () => {
    const svc = new KeeperService(
      makeBlockchain(),
      makeNotify(),
      makeConfig(),
      clockAt(0),
      makeRegistry(),
      undefined,
      makeOpsAlert(false)
    );
    svc.onApplicationBootstrap();
    svc.onApplicationShutdown();
    expect(errorSpy).toHaveBeenCalledTimes(1);
    const [msg] = errorSpy.mock.calls[0] as unknown as [string];
    expect(msg).toContain("NOT configured");
    expect(msg).toContain("OPS_ALERT_ENABLED");
  });

  it("keeper enabled + OpsAlertService not injected at all (undefined) ⇒ logs an error", () => {
    const svc = new KeeperService(
      makeBlockchain(),
      makeNotify(),
      makeConfig(),
      clockAt(0),
      makeRegistry(),
      undefined,
      undefined // no opsAlert provider in this DI graph
    );
    svc.onApplicationBootstrap();
    svc.onApplicationShutdown();
    expect(errorSpy).toHaveBeenCalledTimes(1);
  });

  it("keeper NOT enabled ⇒ no self-check noise, regardless of alert state", () => {
    const svc = new KeeperService(
      makeBlockchain(),
      makeNotify(),
      makeConfig({ keeperEnabled: false }),
      clockAt(0),
      makeRegistry(),
      undefined,
      makeOpsAlert(false)
    );
    svc.onApplicationBootstrap();
    expect(errorSpy).not.toHaveBeenCalled();
  });

  it("keeper enabled + no paymaster addresses (keeper won't actually run) ⇒ no self-check noise", () => {
    const svc = new KeeperService(
      makeBlockchain(),
      makeNotify(),
      makeConfig({ keeperPaymasterAddress: "" }),
      clockAt(0),
      makeRegistry(),
      undefined,
      makeOpsAlert(false) // alerts unconfigured too, but irrelevant — keeper never runs
    );
    svc.onApplicationBootstrap();
    // Only the existing "disabled" warn fires; the alert self-check must not.
    expect(errorSpy).not.toHaveBeenCalled();
  });

  it("self-check error does NOT stop the keeper — it still schedules and runs ticks normally", async () => {
    jest.useFakeTimers();
    try {
      const updates: boolean[] = [];
      const blockchain = makeBlockchain({
        getPriceInfo: async () => ({ updatedAt: 1000n, threshold: 3600n }),
        updatePrice: async () => {
          updates.push(true);
          return "0xTX";
        },
      });
      const svc = new KeeperService(
        blockchain,
        makeNotify(),
        makeConfig({ keeperIntervalMs: 60_000 }),
        NOW_NEAR_EXPIRY,
        makeRegistry(),
        () => 0, // no jitter — fire immediately
        makeOpsAlert(false) // unconfigured ⇒ self-check logs, but must not block anything
      );

      svc.onApplicationBootstrap();
      // The self-check fired loudly...
      expect(errorSpy).toHaveBeenCalledTimes(1);
      // ...but scheduling proceeded exactly as if alerting were fine.
      expect((svc as any).startupTimer).not.toBeNull();

      await jest.advanceTimersByTimeAsync(0);
      // The first tick actually ran and called updatePrice().
      expect(updates).toHaveLength(1);
      // The recurring interval is armed as normal.
      expect((svc as any).timer).not.toBeNull();

      svc.onApplicationShutdown();
      expect((svc as any).timer).toBeNull();
    } finally {
      jest.useRealTimers();
    }
  });
});
