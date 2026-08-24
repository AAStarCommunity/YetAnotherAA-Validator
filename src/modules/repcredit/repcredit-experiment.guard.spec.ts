import { ExecutionContext, HttpException, HttpStatus } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import {
  HEADER_AUTH,
  HEADER_SCHEME,
  RepCreditExperimentGuard,
} from "./repcredit-experiment.guard.js";

const SECRET = "experiment-secret";
const NOW = 1_800_000_000_000;
const BODY = '{"proposalId":"42"}';
const TARGET = "/repcredit/slash/sign";

function context(
  overrides: {
    ip?: string;
    socketIp?: string;
    headers?: Record<string, string>;
    rawBody?: Buffer | null;
    body?: unknown;
    method?: string;
    originalUrl?: string;
  } = {}
): ExecutionContext {
  const headers = overrides.headers ?? {};
  const req = {
    ip: overrides.ip ?? "127.0.0.1",
    socket: { remoteAddress: overrides.socketIp ?? overrides.ip ?? "127.0.0.1" },
    rawBody:
      overrides.rawBody === null ? undefined : (overrides.rawBody ?? Buffer.from(BODY, "utf8")),
    body: overrides.body ?? JSON.parse(BODY),
    method: overrides.method ?? "POST",
    originalUrl: overrides.originalUrl ?? TARGET,
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
    repCreditAuthMaxFutureSkewMs: 5_000,
    repCreditReplayCacheMax: 10_000,
    ...config,
  } as Record<string, unknown>;
  const configService = { get: (key: string) => base[key] } as unknown as ConfigService;
  return new RepCreditExperimentGuard(configService, now);
}

function signedHeaders(
  timestampMs = NOW,
  body = BODY,
  secret = SECRET,
  target = TARGET,
  method = "POST"
) {
  return RepCreditExperimentGuard.computeHeaders(secret, {
    method,
    requestTarget: target,
    timestampMs,
    rawBody: body,
  });
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

/**
 * CC-49 round-3. v2 of the preimage binds the METHOD and the REQUEST TARGET, so a captured
 * token authorises exactly one call on exactly one endpoint (round-2 LOW-D), and the raw
 * bytes are mandatory rather than falling back to a re-serialised body (round-2 LOW-F).
 */
describe("RepCreditExperimentGuard preimage v2 (CC-49 round-3 LOW-D / LOW-F)", () => {
  it("rejects a token minted for a different endpoint", () => {
    const forOtherEndpoint = signedHeaders(NOW, BODY, SECRET, "/repcredit/sign");
    expect(
      statusOf(() =>
        guard().canActivate(
          context({ headers: forOtherEndpoint, originalUrl: "/repcredit/slash/sign" })
        )
      )
    ).toBe(HttpStatus.FORBIDDEN);
  });

  it("rejects a token minted for a different method", () => {
    const forGet = signedHeaders(NOW, BODY, SECRET, TARGET, "GET");
    expect(statusOf(() => guard().canActivate(context({ headers: forGet, method: "POST" })))).toBe(
      HttpStatus.FORBIDDEN
    );
  });

  it("rejects a request that omits or misdeclares the scheme version", () => {
    const headers = signedHeaders();
    const without = { ...headers };
    delete (without as Record<string, string>)[HEADER_SCHEME];
    expect(statusOf(() => guard().canActivate(context({ headers: without })))).toBe(
      HttpStatus.UNAUTHORIZED
    );
    expect(
      statusOf(() =>
        guard().canActivate(context({ headers: { ...headers, [HEADER_SCHEME]: "v1" } }))
      )
    ).toBe(HttpStatus.UNAUTHORIZED);
  });

  it("refuses to authenticate against a re-serialised body when rawBody is unavailable", () => {
    // The v1 fallback HMAC'd JSON.stringify(req.body), i.e. a NORMALISED rendering (duplicate
    // keys collapsed, whitespace lost) rather than the bytes the caller signed.
    expect(
      statusOf(() => guard().canActivate(context({ headers: signedHeaders(), rawBody: null })))
    ).toBe(HttpStatus.UNAUTHORIZED);
  });

  it("rejects a non-hex or truncated auth header without throwing", () => {
    const headers = signedHeaders();
    for (const bad of ["", "zz", "not-hex-at-all", headers[HEADER_AUTH].slice(0, 32)]) {
      const status = statusOf(() =>
        guard().canActivate(context({ headers: { ...headers, [HEADER_AUTH]: bad } }))
      );
      expect([HttpStatus.UNAUTHORIZED, HttpStatus.FORBIDDEN]).toContain(status);
    }
  });
});

/**
 * CC-49 round-3 MEDIUM. `parseInt` yields NaN for a mistyped env value, and EVERY relational
 * comparison against NaN is false — a NaN TTL disables the staleness check and a NaN body cap
 * disables the size cap. Both layers must refuse rather than run unbounded.
 */
describe("RepCreditExperimentGuard numeric bounds (CC-49 round-3 MEDIUM)", () => {
  it("refuses to construct with a NaN or non-positive bound instead of running unbounded", () => {
    for (const key of [
      "repCreditExperimentAuthTtlMs",
      "repCreditMaxBodyBytes",
      "repCreditReplayCacheMax",
    ]) {
      for (const value of [NaN, 0, -1, 1.5, "120000"]) {
        expect(() => guard({ [key]: value })).toThrow(new RegExp(key));
      }
    }
    // The skew allowance may legitimately be zero, but never NaN or negative.
    expect(() => guard({ repCreditAuthMaxFutureSkewMs: 0 })).not.toThrow();
    expect(() => guard({ repCreditAuthMaxFutureSkewMs: NaN })).toThrow();
  });

  it("falls back to the documented default only when the key is absent", () => {
    const instance = guard({ repCreditExperimentAuthTtlMs: undefined });
    // Default TTL is 120s: a token 200s old is stale.
    expect(
      statusOf(() => instance.canActivate(context({ headers: signedHeaders(NOW - 200_000) })))
    ).toBe(HttpStatus.UNAUTHORIZED);
  });
});

/**
 * CC-49 MEDIUM-B. The first round accepted any timestamp within +/- TTL but expired the
 * replay record at ARRIVAL + TTL. A caller whose clock ran fast therefore minted tokens that
 * stayed acceptable for up to 2x TTL while their replay record was pruned after 1x TTL — a
 * captured request could be replayed in the gap. The fix is two-part: an asymmetric window
 * (full TTL backwards, a small skew allowance forwards) and a replay record anchored to the
 * SIGNED timestamp rather than to arrival.
 */
describe("RepCreditExperimentGuard replay window (CC-49 MEDIUM-B)", () => {
  const TTL = 120_000;

  it("rejects a future-dated token from a fast client clock (the 2x-TTL hole)", () => {
    // PROBE A from the post-fix review: client clock +60s, well beyond the skew allowance.
    expect(
      statusOf(() => guard().canActivate(context({ headers: signedHeaders(NOW + 60_000) })))
    ).toBe(HttpStatus.UNAUTHORIZED);
  });

  it("rejects a token stamped a full TTL into the future", () => {
    expect(
      statusOf(() => guard().canActivate(context({ headers: signedHeaders(NOW + TTL) })))
    ).toBe(HttpStatus.UNAUTHORIZED);
  });

  it("still tolerates a small forward clock skew", () => {
    for (const skew of [1, 4_999, 5_000]) {
      expect(guard().canActivate(context({ headers: signedHeaders(NOW + skew) }))).toBe(true);
    }
    expect(
      statusOf(() => guard().canActivate(context({ headers: signedHeaders(NOW + 5_001) })))
    ).toBe(HttpStatus.UNAUTHORIZED);
  });

  it("keeps the full TTL of backwards tolerance", () => {
    expect(guard().canActivate(context({ headers: signedHeaders(NOW - TTL) }))).toBe(true);
    expect(
      statusOf(() => guard().canActivate(context({ headers: signedHeaders(NOW - TTL - 1) })))
    ).toBe(HttpStatus.UNAUTHORIZED);
  });

  it("keeps the replay record alive for the token's whole acceptance window", () => {
    // PROBE B: `now === ts + TTL` is the last instant the timestamp check accepts. The record
    // must survive it; with the old `expiry <= now` prune both tests took the equality and a
    // replay slipped through on that exact tick.
    let clock = NOW;
    const instance = guard({}, () => clock);
    const headers = signedHeaders(NOW);
    expect(instance.canActivate(context({ headers }))).toBe(true);
    for (const t of [NOW + 1, NOW + TTL - 1, NOW + TTL]) {
      clock = t;
      expect(statusOf(() => instance.canActivate(context({ headers })))).toBe(HttpStatus.FORBIDDEN);
    }
    // One tick later the token is stale on its own merit, so pruning the record is safe.
    clock = NOW + TTL + 1;
    expect(statusOf(() => instance.canActivate(context({ headers })))).toBe(
      HttpStatus.UNAUTHORIZED
    );
  });

  it("anchors the record to the signed timestamp, not to arrival", () => {
    // A token signed at NOW but delivered late (arrival NOW + TTL) must not get a fresh
    // TTL of replay life from its arrival time.
    let clock = NOW + TTL;
    const instance = guard({}, () => clock);
    const headers = signedHeaders(NOW);
    expect(instance.canActivate(context({ headers }))).toBe(true);
    clock = NOW + TTL + 1;
    // Arrival-anchored expiry would have kept the record until NOW + 2*TTL; either way the
    // replay must fail, and here it fails on staleness because the token itself is expired.
    expect(statusOf(() => instance.canActivate(context({ headers })))).toBe(
      HttpStatus.UNAUTHORIZED
    );
  });

  it("admits exactly one of many interleaved requests carrying the same token", async () => {
    const instance = guard();
    const headers = signedHeaders();
    // canActivate is fully synchronous, so check-then-set cannot interleave on Node's event
    // loop. Schedule 64 activations as separate microtasks to prove no ordering admits two.
    const outcomes = await Promise.all(
      Array.from({ length: 64 }, () =>
        Promise.resolve().then(() => {
          try {
            return instance.canActivate(context({ headers })) === true;
          } catch {
            return false;
          }
        })
      )
    );
    expect(outcomes.filter(Boolean)).toHaveLength(1);
  });

  it("fails closed rather than evicting when the replay cache is full", () => {
    const instance = guard({ repCreditReplayCacheMax: 3 });
    for (let i = 0; i < 3; i++) {
      expect(instance.canActivate(context({ headers: signedHeaders(NOW - i) }))).toBe(true);
    }
    // Evicting the oldest entry to make room would re-open the window this cache closes.
    expect(statusOf(() => instance.canActivate(context({ headers: signedHeaders(NOW - 3) })))).toBe(
      HttpStatus.SERVICE_UNAVAILABLE
    );
  });
});
