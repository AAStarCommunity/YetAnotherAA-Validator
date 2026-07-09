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
    ...over,
  };
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
