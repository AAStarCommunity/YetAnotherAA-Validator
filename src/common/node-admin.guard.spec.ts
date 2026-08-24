import { ExecutionContext, HttpException, HttpStatus } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { ERROR_CODE_SCHEMA_VERSION } from "./error-codes.js";
import { HEADER_NODE_ADMIN_TOKEN, NodeAdminGuard } from "./node-admin.guard.js";

const TOKEN = "example-node-admin-token-32-chars-min";
const NOW = 1_800_000_000_000;

function context(
  overrides: { socketIp?: string; ip?: string; headers?: Record<string, string> } = {}
): ExecutionContext {
  const headers = overrides.headers ?? {};
  const req = {
    ip: overrides.ip ?? "127.0.0.1",
    socket: { remoteAddress: overrides.socketIp ?? overrides.ip ?? "127.0.0.1" },
    header: (name: string) => headers[name],
  };
  return { switchToHttp: () => ({ getRequest: () => req }) } as unknown as ExecutionContext;
}

function guard(config: Record<string, unknown> = {}, now: () => number = () => NOW) {
  const base = {
    nodeAdminEnabled: true,
    nodeAdminToken: TOKEN,
    nodeAdminAllowRemote: false,
    nodeAdminRateWindowMs: 60_000,
    nodeAdminRateMax: 10,
    ...config,
  } as Record<string, unknown>;
  const configService = { get: (key: string) => base[key] } as unknown as ConfigService;
  return new NodeAdminGuard(configService, now);
}

function envelopeOf(fn: () => unknown): { statusCode: number; errorCode: string } {
  try {
    fn();
  } catch (error) {
    if (error instanceof HttpException) {
      return error.getResponse() as { statusCode: number; errorCode: string };
    }
    throw error;
  }
  throw new Error("expected the guard to reject, but it admitted the request");
}

const withToken = (token = TOKEN) => ({ headers: { [HEADER_NODE_ADMIN_TOKEN]: token } });

describe("NodeAdminGuard (CC-49 round-4 HIGH-1)", () => {
  it("is DISABLED by default — an unset NODE_ADMIN_ENABLED rejects even a correct token", () => {
    // The pre-fix behaviour of POST /node/register was: no guard at all, on 0.0.0.0.
    const envelope = envelopeOf(() =>
      guard({ nodeAdminEnabled: undefined }).canActivate(context(withToken()))
    );
    expect(envelope.statusCode).toBe(HttpStatus.FORBIDDEN);
    expect(envelope.errorCode).toBe("NODE_ADMIN_DISABLED");
  });

  it("enabled without a token rejects every request instead of degrading to no auth", () => {
    const envelope = envelopeOf(() =>
      guard({ nodeAdminToken: "" }).canActivate(context(withToken()))
    );
    expect(envelope.statusCode).toBe(HttpStatus.SERVICE_UNAVAILABLE);
    expect(envelope.errorCode).toBe("NODE_ADMIN_TOKEN_UNSET");
  });

  it("admits a correct token from loopback", () => {
    expect(guard().canActivate(context(withToken()))).toBe(true);
  });

  it("rejects a missing token with 401 and a wrong token with 403", () => {
    const instance = guard();
    expect(envelopeOf(() => instance.canActivate(context())).errorCode).toBe(
      "NODE_ADMIN_TOKEN_MISSING"
    );
    expect(envelopeOf(() => instance.canActivate(context())).statusCode).toBe(
      HttpStatus.UNAUTHORIZED
    );
    const wrong = envelopeOf(() => instance.canActivate(context(withToken("wrong-token"))));
    expect(wrong.statusCode).toBe(HttpStatus.FORBIDDEN);
    expect(wrong.errorCode).toBe("NODE_ADMIN_TOKEN_INVALID");
  });

  it("rejects a token that is a prefix or an extension of the real one", () => {
    const instance = guard();
    for (const token of [TOKEN.slice(0, -1), `${TOKEN}x`, ` ${TOKEN}`, TOKEN.toUpperCase()]) {
      expect(envelopeOf(() => instance.canActivate(context(withToken(token)))).errorCode).toBe(
        "NODE_ADMIN_TOKEN_INVALID"
      );
    }
  });

  it("is loopback-only by default, and honours the socket peer over a spoofable req.ip", () => {
    const instance = guard();
    const remote = envelopeOf(() =>
      instance.canActivate(context({ socketIp: "203.0.113.7", ...withToken() }))
    );
    expect(remote.statusCode).toBe(HttpStatus.FORBIDDEN);
    expect(remote.errorCode).toBe("NODE_ADMIN_REMOTE_FORBIDDEN");
    // X-Forwarded-For style spoofing: express's req.ip says loopback, the socket says otherwise.
    expect(
      envelopeOf(() =>
        instance.canActivate(context({ ip: "127.0.0.1", socketIp: "203.0.113.7", ...withToken() }))
      ).errorCode
    ).toBe("NODE_ADMIN_REMOTE_FORBIDDEN");
  });

  it("accepts a remote caller only when NODE_ADMIN_ALLOW_REMOTE is armed explicitly", () => {
    const instance = guard({ nodeAdminAllowRemote: true });
    expect(instance.canActivate(context({ socketIp: "203.0.113.7", ...withToken() }))).toBe(true);
    // The token still has to be right — arming remote does not relax authentication.
    expect(
      envelopeOf(() =>
        instance.canActivate(context({ socketIp: "203.0.113.7", ...withToken("nope") }))
      ).errorCode
    ).toBe("NODE_ADMIN_TOKEN_INVALID");
  });

  it("throttles per source IP, counting wrong-token attempts, and recovers after the window", () => {
    let clock = NOW;
    const instance = guard({ nodeAdminRateMax: 3 }, () => clock);
    for (let i = 0; i < 3; i++) {
      expect(envelopeOf(() => instance.canActivate(context(withToken("wrong")))).errorCode).toBe(
        "NODE_ADMIN_TOKEN_INVALID"
      );
    }
    // Budget spent: even the CORRECT token is now refused, which is what bounds guessing.
    const limited = envelopeOf(() => instance.canActivate(context(withToken())));
    expect(limited.statusCode).toBe(HttpStatus.TOO_MANY_REQUESTS);
    expect(limited.errorCode).toBe("NODE_ADMIN_RATE_LIMITED");
    // A different source has its own budget.
    expect(
      guard({ nodeAdminRateMax: 3 }, () => clock).canActivate(
        context({ socketIp: "::1", ...withToken() })
      )
    ).toBe(true);
    clock = NOW + 60_001;
    expect(instance.canActivate(context(withToken()))).toBe(true);
  });

  it("refuses to boot when the admin token is short or reuses the RepCredit secret", () => {
    expect(() => guard({ nodeAdminToken: "short" })).toThrow(/at least 32 characters/);
    expect(() => guard({ nodeAdminToken: TOKEN, repCreditExperimentAuthSecret: TOKEN })).toThrow(
      /must not equal REPCREDIT_EXPERIMENT_AUTH_SECRET/
    );
    // Disabled: the reuse check only applies to a gate that is actually armed.
    expect(() =>
      guard({
        nodeAdminEnabled: false,
        nodeAdminToken: TOKEN,
        repCreditExperimentAuthSecret: TOKEN,
      })
    ).not.toThrow();
  });

  it("refuses to boot on an unusable throttle bound rather than silently not throttling", () => {
    // NaN would make `recent.length >= this.max` false forever, i.e. no throttle at all.
    expect(() => guard({ nodeAdminRateMax: NaN })).toThrow(/nodeAdminRateMax/);
    expect(() => guard({ nodeAdminRateWindowMs: 0 })).toThrow(/nodeAdminRateWindowMs/);
  });

  it("carries the versioned error envelope on every rejection", () => {
    const envelope = envelopeOf(() => guard().canActivate(context()));
    expect(envelope).toMatchObject({
      errorCodeVersion: ERROR_CODE_SCHEMA_VERSION,
      category: "auth",
    });
  });
});
