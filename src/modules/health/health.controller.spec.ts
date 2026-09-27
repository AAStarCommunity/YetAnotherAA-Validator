import { HealthController } from "./health.controller.js";
import { KeyConsistencyResult } from "../node/node-key-consistency.service.js";

/**
 * CC-36: /health gains an ADDITIVE `keyConsistency` field. `status`, `version` and
 * `capabilities` must stay exactly as they were — external probes depend on them.
 */
describe("HealthController", () => {
  it("omits keyConsistency entirely when no self-check has run yet (no shape change for old consumers)", () => {
    const controller = new HealthController(undefined, {
      getLastResult: () => null,
    } as any);
    const result = controller.health();
    expect(result).toEqual({ status: "ok", version: expect.any(String), capabilities: [] });
    expect("keyConsistency" in result).toBe(false);
  });

  it("omits keyConsistency when NodeKeyConsistencyService isn't wired in at all", () => {
    const controller = new HealthController(undefined, undefined);
    const result = controller.health();
    expect("keyConsistency" in result).toBe(false);
    expect(result.status).toBe("ok");
  });

  it("surfaces the self-check result additively once one has run, without touching other fields", () => {
    const fakeResult: KeyConsistencyResult = {
      status: "mismatch_onchain",
      checkedAt: "2026-01-01T00:00:00.000Z",
      lastAttemptAt: "2026-01-01T00:00:00.000Z",
      derivedMatches: true,
      nodeId: "0xabc",
    };
    const controller = new HealthController(undefined, {
      getLastResult: () => fakeResult,
    } as any);
    const result = controller.health();
    expect(result.status).toBe("ok");
    expect(result.capabilities).toEqual([]);
    expect(result.keyConsistency).toEqual(fakeResult);
  });

  it("CC-36 round-6 L2: checkerError/checkerErrorAt surface through /health when the checker itself broke", () => {
    // These fields (round-3 Medium) mark a preserved conclusive result as stale-since a
    // checker-internal bug, rather than silently looking like an unbroken fresh "ok" forever.
    // Assert them at the /health CONTRACT layer, not just inside the service's own tests.
    const fakeResult: KeyConsistencyResult = {
      status: "ok",
      checkedAt: "2026-01-01T00:00:00.000Z",
      lastAttemptAt: "2026-01-01T00:20:00.000Z",
      derivedMatches: true,
      nodeId: "0xabc",
      checkerError: "simulated internal bug",
      checkerErrorAt: "2026-01-01T00:20:00.000Z",
    };
    const controller = new HealthController(undefined, {
      getLastResult: () => fakeResult,
    } as any);
    const result = controller.health();
    expect(result.keyConsistency?.checkerError).toBe("simulated internal bug");
    expect(result.keyConsistency?.checkerErrorAt).toBe("2026-01-01T00:20:00.000Z");
    // Still additive-only — the rest of the contract is untouched.
    expect(result.status).toBe("ok");
    expect(result.capabilities).toEqual([]);
  });

  it("root() endpoint is unaffected (CC-36 only touches /health)", () => {
    const controller = new HealthController(undefined, undefined);
    const result = controller.root();
    expect(result.service).toBe("aastar-dvt-node");
    expect(result.status).toBe("ok");
    expect(result.endpoints.health).toBe("GET /health");
  });
});
