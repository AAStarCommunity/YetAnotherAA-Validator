import { jest } from "@jest/globals";
import { ConfigService } from "@nestjs/config";
import { StatusReporterService } from "./status-reporter.service.js";
import { OpsAlertService } from "./ops-alert.service.js";

/**
 * StatusReporterService (#100) — scheduled heartbeat to the ops channel. Verifies:
 * disabled when interval=0 or alerts off; on boot sends "online"; report() composes a
 * version/uptime/RPC/caps summary and pushes it via OpsAlertService.
 */
describe("StatusReporterService", () => {
  const cfg = (over: Record<string, unknown>): ConfigService =>
    ({ get: (k: string) => over[k] }) as unknown as ConfigService;

  const opsAlertStub = (enabled: boolean) => {
    const alert = jest.fn();
    return { svc: { isEnabled: () => enabled, alert } as unknown as OpsAlertService, alert };
  };

  it("does nothing on boot when interval is 0", () => {
    const { svc, alert } = opsAlertStub(true);
    const r = new StatusReporterService(svc, cfg({ opsStatusIntervalMs: 0 }));
    r.onApplicationBootstrap();
    expect(alert).not.toHaveBeenCalled();
    r.onApplicationShutdown();
  });

  it("does nothing when ops alerts are disabled", () => {
    const { svc, alert } = opsAlertStub(false);
    const r = new StatusReporterService(svc, cfg({ opsStatusIntervalMs: 1000 }));
    r.onApplicationBootstrap();
    expect(alert).not.toHaveBeenCalled();
    r.onApplicationShutdown();
  });

  it("sends an online message on boot when enabled", () => {
    const { svc, alert } = opsAlertStub(true);
    const r = new StatusReporterService(svc, cfg({ opsStatusIntervalMs: 60_000 }));
    r.onApplicationBootstrap();
    expect(alert).toHaveBeenCalledTimes(1);
    const [level, msg] = alert.mock.calls[0] as [string, string];
    expect(level).toBe("info");
    expect(msg).toContain("online");
    r.onApplicationShutdown();
  });

  it("report() composes version/uptime/RPC/caps and pushes it", async () => {
    const { svc, alert } = opsAlertStub(true);
    const blockchain = { getBaseFeeGwei: jest.fn(async () => 3n) } as any;
    const capabilities = {
      list: () => [
        { name: "keeper", enabled: true },
        { name: "relay", enabled: false },
      ],
    } as any;
    let now = 1_000_000;
    const r = new StatusReporterService(
      svc,
      cfg({ opsStatusIntervalMs: 60_000 }),
      blockchain,
      capabilities,
      () => now
    );
    r.onApplicationBootstrap(); // sets startedAt, sends online (call 1)
    now += 5 * 60_000; // +5 minutes
    await r.report(); // call 2

    const [, msg] = alert.mock.calls[1] as [string, string];
    expect(msg).toContain("up 5m");
    expect(msg).toContain("RPC ok");
    expect(msg).toContain("keeper"); // enabled cap listed
    expect(msg).not.toContain("relay"); // disabled cap omitted
    r.onApplicationShutdown();
  });

  it("report() marks RPC DOWN when the probe throws, never rejects", async () => {
    const { svc, alert } = opsAlertStub(true);
    const blockchain = {
      getBaseFeeGwei: jest.fn(async () => {
        throw new Error("rpc down");
      }),
    } as any;
    const r = new StatusReporterService(svc, cfg({ opsStatusIntervalMs: 60_000 }), blockchain);
    await expect(r.report()).resolves.toBeUndefined();
    const [, msg] = alert.mock.calls[0] as [string, string];
    expect(msg).toContain("RPC DOWN");
  });
});
