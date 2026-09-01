import { jest } from "@jest/globals";
import { LivenessKeeperService } from "./liveness-keeper.service.js";

const REGISTRY = "0x1111111111111111111111111111111111111111";
const OP = "0x2222222222222222222222222222222222222222";

/** Config stub from a plain map (undefined for unset keys, like NestJS ConfigService). */
function cfg(map: Record<string, any>): any {
  return { get: (k: string) => map[k] };
}

/** BlockchainService stub — only the methods the keeper touches. */
function chain(over: Partial<Record<string, any>> = {}): any {
  return {
    getWalletAddress: () => OP,
    getAttestAnchor: jest.fn(async () => ({ number: 984, hash: "0x" + "ab".repeat(32) })),
    attestLiveness: jest.fn(async () => "0xtxhash"),
    getLivenessWindow: jest.fn(async () => 300n),
    // 100-block span, 12s blocks → 1200s apart. Keeps the default 300-block window at ~60min.
    getBlockNumber: jest.fn(async () => 1000),
    getBlockTimestamp: jest.fn(async (n: number) => 1_700_000_000 + n * 12),
    // head 1000, window 300 → budget 100 blocks. lastLive 950 = 50 spent: inside budget.
    getLastLive: jest.fn(async () => 950n),
    ...over,
  };
}

/** Boot a keeper and let the fire-and-forget window check settle. */
async function boot(bc: any, intervalMs: number, alerts?: any) {
  const k = new LivenessKeeperService(
    bc,
    cfg({
      auditAttestEnabled: true,
      auditLivenessRegistryAddress: REGISTRY,
      auditAttestIntervalMs: intervalMs,
    }),
    alerts
  );
  k.onApplicationBootstrap();
  await new Promise(r => setImmediate(r));
  await new Promise(r => setImmediate(r));
  return k;
}

describe("LivenessKeeperService", () => {
  afterEach(() => jest.clearAllMocks());

  it("stays DISABLED when AUDIT_ATTEST_ENABLED is not true (no timer, no attest)", () => {
    const bc = chain();
    const k = new LivenessKeeperService(bc, cfg({ auditAttestEnabled: false }));
    k.onApplicationBootstrap();
    expect((k as any).timer).toBeNull();
    expect(bc.attestLiveness).not.toHaveBeenCalled();
  });

  it("DISABLES when the registry address is missing/invalid", () => {
    const bc = chain();
    const k = new LivenessKeeperService(
      bc,
      cfg({ auditAttestEnabled: true, auditLivenessRegistryAddress: "not-an-address" })
    );
    k.onApplicationBootstrap();
    expect((k as any).timer).toBeNull();
    expect(bc.attestLiveness).not.toHaveBeenCalled();
  });

  it("DISABLES when there is no operator wallet", () => {
    const bc = chain({ getWalletAddress: () => null });
    const k = new LivenessKeeperService(
      bc,
      cfg({ auditAttestEnabled: true, auditLivenessRegistryAddress: REGISTRY })
    );
    k.onApplicationBootstrap();
    expect((k as any).timer).toBeNull();
  });

  it("DISABLES on a non-finite interval", () => {
    const bc = chain();
    const k = new LivenessKeeperService(
      bc,
      cfg({
        auditAttestEnabled: true,
        auditLivenessRegistryAddress: REGISTRY,
        auditAttestIntervalMs: NaN,
      })
    );
    k.onApplicationBootstrap();
    expect((k as any).timer).toBeNull();
  });

  it("when enabled+configured: boot-attests immediately and arms the interval timer", async () => {
    const bc = chain();
    const k = new LivenessKeeperService(
      bc,
      cfg({
        auditAttestEnabled: true,
        auditLivenessRegistryAddress: REGISTRY,
        auditAttestIntervalMs: 600_000,
        auditAttestAnchorDepth: 16,
      })
    );
    k.onApplicationBootstrap();
    expect((k as any).timer).not.toBeNull();
    // boot-attest is fire-and-forget (void this.tick()); let the microtask settle.
    await Promise.resolve();
    await Promise.resolve();
    expect(bc.getAttestAnchor).toHaveBeenCalledWith(16);
    expect(bc.attestLiveness).toHaveBeenCalledWith(REGISTRY, 984, "0x" + "ab".repeat(32));
    k.onApplicationShutdown();
    expect((k as any).timer).toBeNull();
  });

  it("tick() NEVER throws on an attest failure and alerts ops", async () => {
    const alert = jest.fn();
    const bc = chain({
      attestLiveness: jest.fn(async () => {
        throw new Error("StaleAnchor");
      }),
    });
    const k = new LivenessKeeperService(
      bc,
      cfg({ auditAttestEnabled: true, auditLivenessRegistryAddress: REGISTRY }),
      { alert } as any
    );
    // tick() now reports whether an attest CONFIRMED (false here — it threw and was swallowed).
    // The watchdog's suppression bound depends on this distinction; see the confirmation suite below.
    await expect(k.tick()).resolves.toBe(false);
    expect(alert).toHaveBeenCalledWith("warn", expect.stringContaining("StaleAnchor"));
  });

  it("tick() skips when a previous attest is still in-flight (no overlap)", async () => {
    let release!: () => void;
    const gate = new Promise<void>(r => (release = r));
    const bc = chain({
      attestLiveness: jest.fn(async () => {
        await gate;
        return "0xtxhash";
      }),
    });
    const k = new LivenessKeeperService(
      bc,
      cfg({ auditAttestEnabled: true, auditLivenessRegistryAddress: REGISTRY })
    );
    const first = k.tick(); // starts, blocks on gate → inFlight=true
    await Promise.resolve();
    await k.tick(); // must skip (inFlight)
    expect(bc.attestLiveness).toHaveBeenCalledTimes(1);
    release();
    await first;
  });
});

/**
 * CC-29 liveness watchdog.
 *
 * The first version of this feature STOPPED the keeper when the configured cadence was too slow for
 * the on-chain window, and called that fail-closed. It was inverted: not attesting is precisely how a
 * node gets jailed, so "protecting" it that way guaranteed the harm and removed every recovery path.
 * These tests pin the corrected direction — the keeper never stops for a configuration reason, and
 * liveness is decided from observed on-chain state rather than from an extrapolated block time.
 */
describe("LivenessKeeperService — CC-29 watchdog", () => {
  afterEach(() => jest.clearAllMocks());

  it("NEVER stops attesting because the cadence is too slow — it alerts and covers", async () => {
    const bc = chain();
    const alerts = { alert: jest.fn() };
    // window 300 x 12s = 60min, budget 20min; 2h is the misconfiguration that used to stop the keeper.
    const k = await boot(bc, 7_200_000, alerts);
    await (k as any).watchdogCycle();

    expect((k as any).timer).not.toBeNull(); // the whole point
    const [level, msg] = (alerts.alert as any).mock.calls[0];
    expect(level).toBe("critical");
    expect(msg).toContain("FIX THE SETTING");
    k.onApplicationShutdown();
  });

  it("attests EARLY when the on-chain block budget is spent, whatever the nominal cadence", async () => {
    // head 1000, lastLive 800 → 200 blocks spent of a 100-block budget (window 300 / 3).
    const bc = chain({ getLastLive: jest.fn(async () => 800n) });
    const k = await boot(bc, 21_600_000, undefined); // nominal cadence 6h
    // boot arms the watchdog at 0ms, so a cycle has already run and recorded confirmedAtBlock=1000.
    // Advance the head so the anti-grief bound is satisfied — that is the real sequence, and testing
    // it against a frozen head would only prove the suppression, not the trigger.
    bc.getBlockNumber = jest.fn(async () => 1200);
    (bc.attestLiveness as any).mockClear();
    await (k as any).watchdogCycle();
    expect(bc.attestLiveness).toHaveBeenCalledTimes(1);
    k.onApplicationShutdown();
  });

  it("does NOT attest early while inside the budget", async () => {
    const bc = chain(); // lastLive 950 → 50 of 100 spent
    const k = await boot(bc, 600_000);
    (bc.attestLiveness as any).mockClear();
    await (k as any).watchdogCycle();
    expect(bc.attestLiveness).not.toHaveBeenCalled();
    k.onApplicationShutdown();
  });

  it("treats never-attested (lastLive == 0) as already offline and attests at once", async () => {
    const bc = chain({ getLastLive: jest.fn(async () => 0n) });
    const k = await boot(bc, 600_000);
    (bc.attestLiveness as any).mockClear();
    await (k as any).watchdogCycle();
    expect(bc.attestLiveness).toHaveBeenCalledTimes(1);
    k.onApplicationShutdown();
  });

  it("keeps attesting when the window cannot be READ — unknown is not unsafe, and never a stop", async () => {
    const bc = chain({
      getLivenessWindow: jest.fn(async () => {
        throw new Error("RPC 503");
      }),
    });
    const alerts = { alert: jest.fn() };
    const k = await boot(bc, 7_200_000, alerts);
    await (k as any).watchdogCycle();
    expect((k as any).timer).not.toBeNull();
    expect(alerts.alert).not.toHaveBeenCalled();
    k.onApplicationShutdown();
  });

  it("covers a governance SHRINK to the on-chain minimum window (100 blocks)", async () => {
    // 60 blocks is below MIN_LIVENESS_WINDOW (LivenessRegistry.sol:51) and cannot occur — an earlier
    // version of this test used it and therefore proved nothing. 100 is the real floor.
    const bc = chain();
    const k = await boot(bc, 600_000);
    (bc.attestLiveness as any).mockClear();
    bc.getLivenessWindow = jest.fn(async () => 100n); // budget now 33 blocks; 50 already spent
    await (k as any).watchdogCycle();
    expect(bc.attestLiveness).toHaveBeenCalledTimes(1);
    expect((k as any).timer).not.toBeNull();
    k.onApplicationShutdown();
  });

  it("rejects a zero/backward block-time sample instead of acting on it", async () => {
    // A reorg between the two timestamp reads can produce this. It must not drive any decision.
    const bc = chain({ getBlockTimestamp: jest.fn(async () => 1_700_000_000) });
    const alerts = { alert: jest.fn() };
    const k = await boot(bc, 7_200_000, alerts);
    await (k as any).watchdogCycle();
    expect((k as any).timer).not.toBeNull();
    expect(alerts.alert).not.toHaveBeenCalled(); // unverified, so no cadence verdict
    k.onApplicationShutdown();
  });

  it("does not request block -1 near genesis", async () => {
    const bc = chain({ getBlockNumber: jest.fn(async () => 0) });
    const k = await boot(bc, 600_000);
    await (k as any).watchdogCycle();
    const asked = (bc.getBlockTimestamp as any).mock.calls.map((c: any[]) => c[0]);
    expect(asked.every((n: number) => n >= 0)).toBe(true);
    k.onApplicationShutdown();
  });

  it("does not run two watchdog cycles concurrently", async () => {
    const bc = chain();
    const k = await boot(bc, 600_000);
    (k as any).watchdogInFlight = true;
    (bc.getLivenessWindow as any).mockClear();
    await (k as any).watchdogCycle();
    expect(bc.getLivenessWindow).not.toHaveBeenCalled();
    (k as any).watchdogInFlight = false;
    k.onApplicationShutdown();
  });

  it("does no work after shutdown", async () => {
    const bc = chain();
    const k = await boot(bc, 600_000);
    k.onApplicationShutdown();
    (bc.getLivenessWindow as any).mockClear();
    await (k as any).watchdogCycle();
    expect(bc.getLivenessWindow).not.toHaveBeenCalled();
    expect((k as any).watchdog).toBeNull();
  });
});

/**
 * Round-2 review findings. Each of these is a defect that shipped in a previous commit of this
 * feature and was found by adversarial review, not by me.
 */
describe("LivenessKeeperService — watchdog hardening", () => {
  afterEach(() => jest.clearAllMocks());

  it("REARMS even when the cycle body never settles (a hung RPC must not kill the loop)", async () => {
    // The first version armed the next timer only in `finally`, so one unsettled promise left
    // watchdogInFlight true with no timer pending — the safety loop died silently.
    const bc = chain({ getBlockNumber: jest.fn(() => new Promise(() => {})) });
    const k = await boot(bc, 600_000);
    const before = (k as any).watchdog;
    void (k as any).watchdogCycle();
    await new Promise(r => setImmediate(r));
    expect((k as any).watchdog).not.toBeNull();
    expect((k as any).watchdog).not.toBe(before); // a NEW timer was armed before the await
    k.onApplicationShutdown();
  });

  it("ignores a window outside the registry's [100, 10_000_000] bounds", async () => {
    // `> 0` was not enough: a tiny positive window made every cycle pay for an attest.
    const bc = chain({
      getLivenessWindow: jest.fn(async () => 3n),
      getLastLive: jest.fn(async () => 1n),
    });
    const k = await boot(bc, 600_000);
    (bc.attestLiveness as any).mockClear();
    await (k as any).watchdogCycle();
    expect(bc.attestLiveness).not.toHaveBeenCalled();
    k.onApplicationShutdown();
  });

  it("rejects an incoherent sample where lastLive is ahead of the head", async () => {
    const bc = chain({ getLastLive: jest.fn(async () => 5000n) });
    const k = await boot(bc, 600_000);
    (bc.attestLiveness as any).mockClear();
    await (k as any).watchdogCycle();
    expect(bc.attestLiveness).not.toHaveBeenCalled();
    k.onApplicationShutdown();
  });

  it("does not pay for a repeat attest when lastLive stays stale (gas-grief bound)", async () => {
    // A stale or hostile lastLive used to make EVERY cycle conclude the budget was spent.
    const bc = chain({ getLastLive: jest.fn(async () => 800n) }); // 200 spent of a 100 budget
    const k = await boot(bc, 600_000);
    (bc.attestLiveness as any).mockClear();
    await (k as any).watchdogCycle(); // first: allowed, records confirmedAtBlock = 1000
    await (k as any).watchdogCycle(); // second: head has not advanced — suppressed
    await (k as any).watchdogCycle();
    expect(bc.attestLiveness).toHaveBeenCalledTimes(1);
    k.onApplicationShutdown();
  });

  it("alerts CRITICAL when the chain's block rate makes the window unserveable at all", async () => {
    // 100-block window on a 0.2s chain = 20s total, ~6.6s budget; one attest needs longer than that.
    // No cadence can fix it, so the keeper must say so rather than report a healthy cadence.
    const bc = chain({
      getLivenessWindow: jest.fn(async () => 100n),
      getBlockTimestamp: jest.fn(async (n: number) => 1_700_000_000 + Math.floor(n / 5)),
    });
    const alerts = { alert: jest.fn() };
    const k = await boot(bc, 600_000, alerts);
    await (k as any).watchdogCycle();
    const call = (alerts.alert as any).mock.calls.find((c: any[]) => c[1].includes("infeasible"));
    expect(call).toBeDefined();
    expect(call[0]).toBe("critical");
    k.onApplicationShutdown();
  });

  it("pins the sample: window and lastLive are read AT the observed head", async () => {
    const bc = chain();
    const k = await boot(bc, 600_000);
    (bc.getLivenessWindow as any).mockClear();
    (bc.getLastLive as any).mockClear();
    await (k as any).watchdogCycle();
    expect((bc.getLivenessWindow as any).mock.calls[0][1]).toBe(1000);
    expect((bc.getLastLive as any).mock.calls[0][2]).toBe(1000);
    k.onApplicationShutdown();
  });
});

/**
 * The anti-grief bound must never suppress an attest we actually needed — that is the same harm as
 * the v1 bug that stopped the keeper. `tick()` swallows attest errors by design, so awaiting it is
 * not evidence that anything confirmed.
 */
describe("LivenessKeeperService — suppression must follow CONFIRMATION, not attempts", () => {
  afterEach(() => jest.clearAllMocks());

  it("does not arm suppression when the attest FAILS — the retry still happens", async () => {
    const bc = chain({
      getLastLive: jest.fn(async () => 800n), // 200 spent of a 100 budget → attest wanted
      attestLiveness: jest.fn(async () => {
        throw new Error("reverted");
      }),
    });
    const k = await boot(bc, 21_600_000);
    (bc.attestLiveness as any).mockClear();
    await (k as any).watchdogCycle();
    await (k as any).watchdogCycle();
    // Both cycles must try: a failed attempt must not look like a confirmation.
    expect((bc.attestLiveness as any).mock.calls.length).toBeGreaterThanOrEqual(2);
    expect((k as any).confirmedAtBlock).toBe(0);
    k.onApplicationShutdown();
  });

  it("does not arm suppression when the tick is SKIPPED as already in-flight", async () => {
    const bc = chain({ getLastLive: jest.fn(async () => 800n) });
    const k = await boot(bc, 21_600_000);
    (k as any).confirmedAtBlock = 0;
    (k as any).inFlight = true; // a nominal attest is running: this tick returns without attesting
    await (k as any).watchdogCycle();
    expect((k as any).confirmedAtBlock).toBe(0);
    (k as any).inFlight = false;
    k.onApplicationShutdown();
  });

  it("tick() reports true only on a confirmed attest", async () => {
    const ok = chain();
    const k1 = await boot(ok, 600_000);
    await expect(k1.tick()).resolves.toBe(true);
    k1.onApplicationShutdown();

    const bad = chain({
      attestLiveness: jest.fn(async () => {
        throw new Error("not confirmed");
      }),
    });
    const k2 = await boot(bad, 600_000);
    await expect(k2.tick()).resolves.toBe(false);
    k2.onApplicationShutdown();
  });
});
