import { ExecutionContext, HttpException, HttpStatus } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { RepCreditExperimentGuard } from "./repcredit-experiment.guard.js";

const SECRET = "experiment-secret";
const NOW = 1_800_000_000_000;
const BODY = '{"proposalId":"42"}';

function context(
  overrides: {
    ip?: string;
    socketIp?: string;
    headers?: Record<string, string>;
    rawBody?: Buffer;
    body?: unknown;
  } = {}
): ExecutionContext {
  const headers = overrides.headers ?? {};
  const req = {
    ip: overrides.ip ?? "127.0.0.1",
    socket: { remoteAddress: overrides.socketIp ?? overrides.ip ?? "127.0.0.1" },
    rawBody: overrides.rawBody ?? Buffer.from(BODY, "utf8"),
    body: overrides.body ?? JSON.parse(BODY),
    header: (name: string) => headers[name],
  };
  return { switchToHttp: () => ({ getRequest: () => req }) } as unknown as ExecutionContext;
}

function guard(config: Record<string, unknown> = {}, now: () => number = () => NOW) {
  const base = {
    repCreditExperimentSigning: true,
    repCreditExperimentAuthSecret: SECRET,
    repCreditExperimentAuthTtlMs: 120_000,
    repCreditAllowRemote: false,
    repCreditMaxBodyBytes: 65_536,
    ...config,
  } as Record<string, unknown>;
  const configService = { get: (key: string) => base[key] } as unknown as ConfigService;
  return new RepCreditExperimentGuard(configService, now);
}

function signedHeaders(timestampMs = NOW, body = BODY, secret = SECRET) {
  return RepCreditExperimentGuard.computeHeaders(secret, timestampMs, body);
}

function statusOf(fn: () => unknown): number {
  try {
    fn();
  } catch (error) {
    if (error instanceof HttpException) return error.getStatus();
    throw error;
  }
  throw new Error("expected the guard to reject, but it admitted the request");
}

describe("RepCreditExperimentGuard (CC-49 BLOCKER-1)", () => {
  it("admits a correctly signed loopback request", () => {
    expect(guard().canActivate(context({ headers: signedHeaders() }))).toBe(true);
  });

  it("rejects everything when the experiment is not armed", () => {
    expect(
      statusOf(() =>
        guard({ repCreditExperimentSigning: false }).canActivate(
          context({ headers: signedHeaders() })
        )
      )
    ).toBe(HttpStatus.FORBIDDEN);
  });

  it("refuses to serve when armed without a secret instead of degrading to no auth", () => {
    expect(
      statusOf(() =>
        guard({ repCreditExperimentAuthSecret: "" }).canActivate(
          context({ headers: signedHeaders() })
        )
      )
    ).toBe(HttpStatus.SERVICE_UNAVAILABLE);
  });

  it("rejects a non-loopback caller by default even with a valid HMAC", () => {
    expect(
      statusOf(() => guard().canActivate(context({ ip: "203.0.113.7", headers: signedHeaders() })))
    ).toBe(HttpStatus.FORBIDDEN);
  });

  it("still requires a valid HMAC when REPCREDIT_ALLOW_REMOTE is set", () => {
    const remote = guard({ repCreditAllowRemote: true });
    expect(remote.canActivate(context({ ip: "203.0.113.7", headers: signedHeaders() }))).toBe(true);
    expect(
      statusOf(() =>
        guard({ repCreditAllowRemote: true }).canActivate(
          context({ ip: "203.0.113.7", headers: signedHeaders(NOW, BODY, "wrong-secret") })
        )
      )
    ).toBe(HttpStatus.FORBIDDEN);
  });

  it("rejects an unauthenticated request (no headers)", () => {
    expect(statusOf(() => guard().canActivate(context({})))).toBe(HttpStatus.UNAUTHORIZED);
  });

  it("rejects a stale timestamp outside the TTL window", () => {
    expect(
      statusOf(() => guard().canActivate(context({ headers: signedHeaders(NOW - 200_000) })))
    ).toBe(HttpStatus.UNAUTHORIZED);
  });

  it("rejects an HMAC computed with the wrong secret", () => {
    expect(
      statusOf(() =>
        guard().canActivate(context({ headers: signedHeaders(NOW, BODY, "wrong-secret") }))
      )
    ).toBe(HttpStatus.FORBIDDEN);
  });

  it("rejects a body swapped after signing (HMAC covers the raw bytes)", () => {
    const headers = signedHeaders();
    const tampered = '{"proposalId":"43"}';
    expect(
      statusOf(() =>
        guard().canActivate(
          context({ headers, rawBody: Buffer.from(tampered, "utf8"), body: JSON.parse(tampered) })
        )
      )
    ).toBe(HttpStatus.FORBIDDEN);
  });

  it("rejects a replayed capture of a previously accepted request", () => {
    const instance = guard();
    const headers = signedHeaders();
    expect(instance.canActivate(context({ headers }))).toBe(true);
    expect(statusOf(() => instance.canActivate(context({ headers })))).toBe(HttpStatus.FORBIDDEN);
  });

  it("accepts the same auth token again only after its window has expired", () => {
    let clock = NOW;
    const instance = guard({}, () => clock);
    const headers = signedHeaders();
    expect(instance.canActivate(context({ headers }))).toBe(true);
    // The replay entry is pruned once expired, but the timestamp is then stale too, so a
    // captured request can never be re-used — the caller must sign a fresh timestamp.
    clock = NOW + 200_000;
    expect(statusOf(() => instance.canActivate(context({ headers })))).toBe(
      HttpStatus.UNAUTHORIZED
    );
    const fresh = signedHeaders(clock);
    expect(instance.canActivate(context({ headers: fresh }))).toBe(true);
  });

  it("bounds request size before doing HMAC work", () => {
    const big = Buffer.alloc(70_000, 0x61);
    expect(
      statusOf(() => guard().canActivate(context({ headers: signedHeaders(), rawBody: big })))
    ).toBe(HttpStatus.PAYLOAD_TOO_LARGE);
  });

  it("ignores a spoofed req.ip and trusts the socket peer address", () => {
    // With `trust proxy` enabled express derives req.ip from X-Forwarded-For, which a
    // caller controls. The socket address must win, so a remote peer claiming loopback
    // is still rejected.
    expect(
      statusOf(() =>
        guard().canActivate(
          context({ ip: "127.0.0.1", socketIp: "203.0.113.7", headers: signedHeaders() })
        )
      )
    ).toBe(HttpStatus.FORBIDDEN);
  });

  it("treats IPv6 and IPv4-mapped loopback as local", () => {
    for (const ip of ["::1", "::ffff:127.0.0.1"]) {
      expect(guard().canActivate(context({ ip, headers: signedHeaders() }))).toBe(true);
    }
  });
});
