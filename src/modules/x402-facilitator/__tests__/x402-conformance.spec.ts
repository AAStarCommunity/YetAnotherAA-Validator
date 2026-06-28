import { readFileSync } from "fs";
import { resolve } from "path";
import { X402FacilitatorService } from "../x402-facilitator.service.js";
import { X402AuthGuard, HEADER_TIMESTAMP, HEADER_AUTH } from "../x402-auth.guard.js";

/**
 * Cross-repo conformance: drive the DVT facilitator with the GOLDEN wire vectors in
 * conformance/x402/fixtures.json — the exact `/x402/{verify,settle}` request bodies a
 * conformant SDK emits (#130 / aastar-sdk#39). Asserts the DVT derives the same nonce,
 * the same on-chain settle args, and recovers the payer from the real signature. The
 * SDK loads the same JSON to assert its createPayment produces byte-identical envelopes.
 *
 * Regenerate the fixtures with: node scripts/x402/gen-conformance-fixtures.mjs > conformance/x402/fixtures.json
 */
interface Fixture {
  config: {
    chainId: number;
    facilitatorContract: string;
    supportedAssets: string[];
    nowSecForVerify: number;
  };
  vectors: Array<{
    name: string;
    body: unknown;
    expect: {
      scheme: string;
      payer: string;
      effectiveNonce: string;
      settle: { method: string; args: string[] };
    };
  }>;
  authHeader: { secret: string; rawBody: string; headers: Record<string, string> };
}

const fixtures: Fixture = JSON.parse(
  readFileSync(resolve(process.cwd(), "conformance/x402/fixtures.json"), "utf8")
);

function makeService() {
  const cfg: Record<string, unknown> = {
    x402FacilitatorEnabled: false,
    x402ChainId: fixtures.config.chainId,
    x402FacilitatorContract: fixtures.config.facilitatorContract,
    x402SupportedAssets: fixtures.config.supportedAssets,
    x402FeeBPS: 200,
  };
  const config = { get: (k: string) => cfg[k] } as any;
  const registry = { register: () => {} } as any;
  return new X402FacilitatorService(config, registry, () => fixtures.config.nowSecForVerify * 1000);
}

/** bigint args → string so they compare against the fixture's JSON string args. */
function argsToStrings(args: unknown[]): string[] {
  return args.map(a => (typeof a === "bigint" ? a.toString() : (a as string)));
}

describe("x402 conformance (golden wire vectors)", () => {
  const svc = makeService();

  for (const v of fixtures.vectors) {
    describe(v.name, () => {
      it("normalizes to the expected scheme", () => {
        const r = svc.normalize(v.body as any);
        expect(r.ok).toBe(true);
        if (!r.ok) return;
        expect(r.payment.scheme).toBe(v.expect.scheme);
      });

      it("derives the contract-matching effective nonce", () => {
        const r = svc.normalize(v.body as any);
        if (!r.ok) throw new Error("normalize failed");
        expect(svc.effectiveNonce(r.payment)).toBe(v.expect.effectiveNonce);
      });

      it("builds the exact on-chain settle call (method + ordered args)", () => {
        const r = svc.normalize(v.body as any);
        if (!r.ok) throw new Error("normalize failed");
        const call = svc.buildSettleCall(r.payment);
        expect(call.method).toBe(v.expect.settle.method);
        expect(argsToStrings(call.args)).toEqual(v.expect.settle.args);
      });

      it("recovers the payer from the real signature", async () => {
        const r = svc.normalize(v.body as any);
        if (!r.ok) throw new Error("normalize failed");
        const verdict = await svc.verifySignatureOffChain(r.payment);
        expect(verdict).toEqual({ ok: true, payer: v.expect.payer });
      });
    });
  }

  describe("auth-header scheme (X402AuthGuard ↔ SDK createAuthHeaders)", () => {
    const { secret, rawBody, headers } = fixtures.authHeader;
    const tsMs = Number(headers[HEADER_TIMESTAMP]);

    it("the guard's reference computation matches the golden header vector", () => {
      const computed = X402AuthGuard.computeHeaders(secret, tsMs, rawBody);
      expect(computed[HEADER_AUTH]).toBe(headers[HEADER_AUTH]);
    });

    function guard() {
      const cfg: Record<string, unknown> = {
        x402AuthEnabled: true,
        x402AuthSecret: secret,
        x402AuthTtlMs: 300_000,
      };
      return new X402AuthGuard({ get: (k: string) => cfg[k] } as any, () => tsMs);
    }
    function ctx(hdrs: Record<string, string>, body: string) {
      const req = { header: (k: string) => hdrs[k], rawBody: Buffer.from(body), body: {} };
      return { switchToHttp: () => ({ getRequest: () => req }) } as any;
    }

    it("accepts a request bearing the golden headers", () => {
      expect(guard().canActivate(ctx(headers, rawBody))).toBe(true);
    });

    it("rejects a tampered body (HMAC mismatch → 403)", () => {
      expect(() => guard().canActivate(ctx(headers, rawBody + "x"))).toThrow();
    });

    it("rejects a stale timestamp (outside TTL → 401)", () => {
      const stale = new X402AuthGuard(
        {
          get: (k: string) =>
            ({ x402AuthEnabled: true, x402AuthSecret: secret, x402AuthTtlMs: 1 })[k],
        } as any,
        () => tsMs + 1_000_000
      );
      expect(() => stale.canActivate(ctx(headers, rawBody))).toThrow();
    });

    it("is a no-op when disabled", () => {
      const off = new X402AuthGuard({ get: () => undefined } as any, () => tsMs);
      expect(off.canActivate(ctx({}, rawBody))).toBe(true);
    });
  });
});
