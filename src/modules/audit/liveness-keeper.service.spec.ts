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
    await expect(k.tick()).resolves.toBeUndefined();
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
 * CC-29 cadence budget. `livenessWindow` is SP-governed, in BLOCKS, changeable with immediate
 * effect; the attest interval is ours, wall-clock, per-node. Nothing linked them, so a legal config
 * could leave a healthy node permanently reading `isOffline == true` with no error anywhere.
 */
describe("LivenessKeeperService — on-chain cadence budget", () => {
  afterEach(() => {
    jest.clearAllMocks();
  });

  it("STOPS the keeper when the interval exceeds livenessWindow/3 (fail-closed)", async () => {
    const bc = chain();
    const alerts = { alert: jest.fn() };
    // window 300 blocks x 12s = 60min; safe max = 20min. 2h is the misconfiguration that used to
    // pass every check and silently jail a healthy node.
    const k = await boot(bc, 7_200_000, alerts);
    expect((k as any).timer).toBeNull();
    const [level, msg] = (alerts.alert as any).mock.calls[0];
    expect(level).toBe("critical");
    expect(msg).toContain("OFFLINE");
    k.onApplicationShutdown();
  });

  it("KEEPS RUNNING at a safe cadence, and records the check", async () => {
    const bc = chain();
    const k = await boot(bc, 600_000); // 10min vs a 20min budget
    expect((k as any).timer).not.toBeNull();
    expect((k as any).lastWindowCheckMs).toBeGreaterThan(0);
    k.onApplicationShutdown();
  });

  it("KEEPS RUNNING when the window cannot be READ — unknown is not unsafe", async () => {
    // Stopping on an unreadable window would itself make the node look offline: the exact harm the
    // budget exists to prevent. The two failure directions are deliberately opposite.
    const bc = chain({
      getLivenessWindow: jest.fn(async () => {
        throw new Error("RPC 503");
      }),
    });
    const alerts = { alert: jest.fn() };
    const k = await boot(bc, 7_200_000, alerts); // would be unsafe IF the window were readable
    expect((k as any).timer).not.toBeNull();
    expect((k as any).lastWindowCheckMs).toBe(0); // unverified, so it will retry
    expect(alerts.alert).not.toHaveBeenCalled();
    k.onApplicationShutdown();
  });

  it("KEEPS RUNNING on an implausible reading rather than acting on it", async () => {
    const bc = chain({ getLivenessWindow: jest.fn(async () => 0n) });
    const k = await boot(bc, 7_200_000);
    expect((k as any).timer).not.toBeNull();
    k.onApplicationShutdown();
  });

  it("measures block time from chain, so a fast-block chain shrinks the budget", async () => {
    // 2s blocks (an L2): the same 300-block window is only 10min, so a 10min cadence is now unsafe
    // even though it is safe on a 12s chain. This is why block time is measured, not configured.
    const bc = chain({
      getBlockTimestamp: jest.fn(async (n: number) => 1_700_000_000 + n * 2),
    });
    const k = await boot(bc, 600_000);
    expect((k as any).timer).toBeNull();
    k.onApplicationShutdown();
  });

  it("STOPS when governance SHRINKS the window after boot (a boot-only check is not enough)", async () => {
    const bc = chain();
    const alerts = { alert: jest.fn() };
    const k = await boot(bc, 600_000, alerts); // safe at boot: 10min vs a 20min budget
    expect((k as any).timer).not.toBeNull();

    // SP lowers livenessWindow 300 -> 60 blocks in one transaction. Nothing in OUR config changed.
    bc.getLivenessWindow = jest.fn(async () => 60n); // 60 x 12s = 12min; budget now 4min
    (k as any).lastWindowCheckMs = Date.now() - 7_200_000; // force the re-check window open
    await k.tick();
    await new Promise(r => setImmediate(r)); // the re-check runs fire-and-forget after the attest
    await new Promise(r => setImmediate(r));

    expect((k as any).timer).toBeNull();
    expect((alerts.alert as any).mock.calls[0][0]).toBe("critical");
    k.onApplicationShutdown();
  });
});
