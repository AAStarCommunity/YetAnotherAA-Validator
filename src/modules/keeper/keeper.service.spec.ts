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
  }> = {}
): any {
  return {
    getPriceInfo: overrides.getPriceInfo ?? (async () => ({ updatedAt: 1000n, threshold: 3600n })),
    getChainlinkUpdatedAt: overrides.getChainlinkUpdatedAt ?? (async () => 2000n),
    getBaseFeeGwei: overrides.getBaseFeeGwei ?? (async () => 10n),
    updatePrice: overrides.updatePrice ?? (async () => "0xabc"),
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
      updatePrice: async () => { throw new Error("should not be called"); },
    });
    const svc = new KeeperService(makeBlockchain(blockchain as any), makeNotify(), makeConfig(), clockAt(1_100_000));
    await svc.tick();
    // no throw → update was NOT called
  });

  it("tick: skips when Chainlink has not updated since last cached price", async () => {
    const updatePriceCalled: boolean[] = [];
    const blockchain = makeBlockchain({
      getChainlinkUpdatedAt: async () => 999n, // ≤ updatedAt=1000 → skip
      updatePrice: async () => { updatePriceCalled.push(true); return "0x"; },
    });
    const svc = new KeeperService(blockchain, makeNotify(), makeConfig(), NOW_NEAR_EXPIRY);
    await svc.tick();
    expect(updatePriceCalled).toHaveLength(0);
  });

  it("tick: skips when baseFee exceeds max", async () => {
    const updatePriceCalled: boolean[] = [];
    const blockchain = makeBlockchain({
      getBaseFeeGwei: async () => 100n, // > maxBaseFeeGwei=50
      updatePrice: async () => { updatePriceCalled.push(true); return "0x"; },
    });
    const svc = new KeeperService(blockchain, makeNotify(), makeConfig(), NOW_NEAR_EXPIRY);
    await svc.tick();
    expect(updatePriceCalled).toHaveLength(0);
  });

  it("tick: calls updatePrice when all conditions met", async () => {
    const updatePriceCalled: string[] = [];
    const blockchain = makeBlockchain({
      updatePrice: async () => { updatePriceCalled.push("called"); return "0xTXHASH"; },
    });
    const svc = new KeeperService(blockchain, makeNotify(), makeConfig(), NOW_NEAR_EXPIRY);
    await svc.tick();
    expect(updatePriceCalled).toHaveLength(1);
  });

  it("tick: skips when daily cap reached", async () => {
    const updatePriceCalled: boolean[] = [];
    const blockchain = makeBlockchain({
      updatePrice: async () => { updatePriceCalled.push(true); return "0x"; },
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
      updatePrice: async () => { throw new Error("reverted"); },
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
      updatePrice: async () => { updatePriceCalled.push(true); return "0x"; },
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

  it("onApplicationShutdown clears the timer", () => {
    const svc = new KeeperService(makeBlockchain(), makeNotify(), makeConfig(), clockAt(0));
    svc.onApplicationBootstrap();
    expect((svc as any).timer).not.toBeNull();
    svc.onApplicationShutdown();
    expect((svc as any).timer).toBeNull();
  });
});
