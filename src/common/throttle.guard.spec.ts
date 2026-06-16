import { HttpException } from "@nestjs/common";
import { ThrottleGuard } from "./throttle.guard.js";

/** Build a fake ExecutionContext carrying a request IP. */
function ctx(ip: string): any {
  return { switchToHttp: () => ({ getRequest: () => ({ ip }) }) };
}
function make(config: Record<string, unknown>): ThrottleGuard {
  return new ThrottleGuard({ get: (k: string) => config[k] } as any);
}

describe("ThrottleGuard — per-IP rate limit (#50 ⑦)", () => {
  it("is a no-op when disabled (behavior unchanged)", () => {
    const g = make({ rateLimitEnabled: false });
    for (let i = 0; i < 1000; i++) expect(g.canActivate(ctx("1.1.1.1"))).toBe(true);
  });

  it("allows up to max then throws 429 within the window", () => {
    const g = make({ rateLimitEnabled: true, rateLimitWindowMs: 60_000, rateLimitMax: 3 });
    expect(g.canActivate(ctx("2.2.2.2"))).toBe(true);
    expect(g.canActivate(ctx("2.2.2.2"))).toBe(true);
    expect(g.canActivate(ctx("2.2.2.2"))).toBe(true);
    try {
      g.canActivate(ctx("2.2.2.2"));
      throw new Error("should have thrown");
    } catch (e: any) {
      expect(e).toBeInstanceOf(HttpException);
      expect(e.getStatus()).toBe(429);
    }
  });

  it("limits each IP independently", () => {
    const g = make({ rateLimitEnabled: true, rateLimitWindowMs: 60_000, rateLimitMax: 1 });
    expect(g.canActivate(ctx("3.3.3.3"))).toBe(true);
    expect(g.canActivate(ctx("4.4.4.4"))).toBe(true); // different IP, own budget
    expect(() => g.canActivate(ctx("3.3.3.3"))).toThrow(HttpException);
  });

  it("frees budget after the window elapses", () => {
    const g = make({ rateLimitEnabled: true, rateLimitWindowMs: 10, rateLimitMax: 1 });
    expect(g.canActivate(ctx("5.5.5.5"))).toBe(true);
    expect(() => g.canActivate(ctx("5.5.5.5"))).toThrow(HttpException);
    const t0 = Date.now();
    while (Date.now() - t0 < 15) {
      /* spin past the 10ms window */
    }
    expect(g.canActivate(ctx("5.5.5.5"))).toBe(true);
  });
});
