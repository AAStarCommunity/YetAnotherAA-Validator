import { jest } from "@jest/globals";
import { ConfigService } from "@nestjs/config";
import { OpsAlertService } from "./ops-alert.service.js";

/**
 * OpsAlertService (#100) — push operator alerts to aastar-monitor, opt-in and
 * fire-and-forget. Verifies: disabled = no-op, enabled = POST with payload+auth,
 * and that a delivery failure never throws into the caller.
 */
describe("OpsAlertService", () => {
  const cfg = (over: Record<string, unknown>): ConfigService =>
    ({ get: (k: string) => over[k] }) as unknown as ConfigService;

  let fetchMock: jest.Mock;
  beforeEach(() => {
    fetchMock = jest.fn(async () => ({ ok: true, status: 200 }) as any);
    (globalThis as any).fetch = fetchMock;
  });

  it("is a no-op when disabled (no fetch)", () => {
    const svc = new OpsAlertService(cfg({ opsAlertEnabled: false, opsAlertUrl: "http://m" }));
    svc.alert("critical", "boom");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("is a no-op when enabled but no URL", () => {
    const svc = new OpsAlertService(cfg({ opsAlertEnabled: true }));
    svc.alert("critical", "boom");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("POSTs a structured payload with bearer token when configured", async () => {
    const svc = new OpsAlertService(
      cfg({
        opsAlertEnabled: true,
        opsAlertUrl: "http://monitor/ingest",
        opsAlertToken: "secret",
        opsAlertNode: "dvt1",
      })
    );
    await svc.send({ node: "dvt1", level: "warn", message: "low balance", timestamp: "t" });

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0] as [string, any];
    expect(url).toBe("http://monitor/ingest");
    expect(init.method).toBe("POST");
    expect(init.headers.authorization).toBe("Bearer secret");
    const body = JSON.parse(init.body);
    expect(body).toMatchObject({ node: "dvt1", level: "warn", message: "low balance" });
  });

  it("omits the auth header when no token is set", async () => {
    const svc = new OpsAlertService(cfg({ opsAlertEnabled: true, opsAlertUrl: "http://m" }));
    await svc.send({ node: "dvt", level: "info", message: "hi", timestamp: "t" });
    const [, init] = fetchMock.mock.calls[0] as [string, any];
    expect(init.headers.authorization).toBeUndefined();
  });

  it("alert() never throws even if delivery rejects", async () => {
    fetchMock.mockRejectedValue(new Error("network down") as never);
    const svc = new OpsAlertService(cfg({ opsAlertEnabled: true, opsAlertUrl: "http://m" }));
    // Must not throw synchronously nor reject (fire-and-forget).
    expect(() => svc.alert("critical", "boom")).not.toThrow();
    // Let the detached promise settle; swallowed internally.
    await new Promise(r => setTimeout(r, 0));
  });

  it("send() throws on non-2xx (so alert() can log+swallow)", async () => {
    fetchMock.mockResolvedValue({ ok: false, status: 500 } as never);
    const svc = new OpsAlertService(cfg({ opsAlertEnabled: true, opsAlertUrl: "http://m" }));
    await expect(
      svc.send({ node: "dvt", level: "warn", message: "x", timestamp: "t" })
    ).rejects.toThrow("aastar-monitor HTTP 500");
  });
});
