import { jest } from "@jest/globals";
import { ExecutionContext, HttpException, HttpStatus, Logger } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { ERROR_CODE_SCHEMA_VERSION } from "./error-codes.js";
import {
  HEADER_FORWARDED_FOR,
  HEADER_NODE_ADMIN_TOKEN,
  NodeAdminGuard,
} from "./node-admin.guard.js";

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
    nodeAdminNetworkMode: "direct",
    nodeAdminAllowProxied: false,
    nodeAdminAllowRemote: false,
    nodeAdminRateWindowMs: 60_000,
    nodeAdminRateMax: 10,
    nodeAdminAnonGlobalRateMax: 60,
    nodeAdminOperatorRateMax: 120,
    nodeAdminTrustedProxyCidrs: [],
    nodeAdminTrustedProxyHops: 0,
    ...config,
  } as Record<string, unknown>;
  const configService = { get: (key: string) => base[key] } as unknown as ConfigService;
  return new NodeAdminGuard(configService, now);
}

function envelopeOf(fn: () => unknown): { statusCode: number; errorCode: string; message: string } {
  try {
    fn();
  } catch (error) {
    if (error instanceof HttpException) {
      return error.getResponse() as { statusCode: number; errorCode: string; message: string };
    }
    throw error;
  }
  throw new Error("expected the guard to reject, but it admitted the request");
}

const withToken = (token = TOKEN) => ({ headers: { [HEADER_NODE_ADMIN_TOKEN]: token } });

/** Everything the guard writes to its logger, so tests can assert on boot warnings. */
function captureLogs(build: () => NodeAdminGuard): string[] {
  const lines: string[] = [];
  const spy = jest.spyOn(Logger.prototype, "warn").mockImplementation((...args: unknown[]) => {
    lines.push(String(args[0]));
  });
  try {
    build();
  } finally {
    spy.mockRestore();
  }
  return lines;
}

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
    expect(() => guard({ nodeAdminOperatorRateMax: -1 })).toThrow(/nodeAdminOperatorRateMax/);
    expect(() => guard({ nodeAdminAnonGlobalRateMax: 1.5 })).toThrow(/nodeAdminAnonGlobalRateMax/);
  });

  it("carries the versioned error envelope on every rejection", () => {
    const envelope = envelopeOf(() => guard().canActivate(context()));
    expect(envelope).toMatchObject({
      errorCodeVersion: ERROR_CODE_SCHEMA_VERSION,
      category: "auth",
    });
  });
});

describe("NodeAdminGuard network mode (CC-49 round-5 MEDIUM-1)", () => {
  // The finding: dvt1/2/3 sit behind cloudflared, which reaches the node FROM 127.0.0.1 —
  // so in round-4 every PUBLIC request satisfied the "loopback only" gate, and the warning
  // that says "the token is now the only barrier" never printed on exactly that deployment.
  const proxied = (config: Record<string, unknown> = {}) =>
    guard({ nodeAdminNetworkMode: "proxied", nodeAdminAllowProxied: true, ...config });

  it("refuses to boot on an undeclared network mode instead of defaulting to the loose one", () => {
    expect(() => guard({ nodeAdminNetworkMode: "tunnel" })).toThrow(/NODE_ADMIN_NETWORK_MODE/);
    expect(() => guard({ nodeAdminNetworkMode: "Direct" })).toThrow(/NODE_ADMIN_NETWORK_MODE/);
    // Absent means the SAFE mode, not "whatever the socket looks like".
    expect(() => guard({ nodeAdminNetworkMode: undefined })).not.toThrow();
  });

  it("keeps the endpoints DISABLED in proxied mode until NODE_ADMIN_ALLOW_PROXIED is set", () => {
    const envelope = envelopeOf(() =>
      guard({ nodeAdminNetworkMode: "proxied" }).canActivate(context(withToken()))
    );
    expect(envelope.statusCode).toBe(HttpStatus.FORBIDDEN);
    expect(envelope.errorCode).toBe("NODE_ADMIN_PROXIED_NOT_ALLOWED");
    // Not even from an actual loopback caller: the whole point is that loopback proves nothing.
    expect(
      envelopeOf(() =>
        guard({ nodeAdminNetworkMode: "proxied" }).canActivate(
          context({ socketIp: "127.0.0.1", ...withToken() })
        )
      ).errorCode
    ).toBe("NODE_ADMIN_PROXIED_NOT_ALLOWED");
  });

  it("never claims loopback as a boundary in proxied mode — the token is the whole gate", () => {
    const instance = proxied();
    // A loopback socket peer (i.e. the tunnel's own back-connection) is admitted on the token…
    expect(instance.canActivate(context({ socketIp: "127.0.0.1", ...withToken() }))).toBe(true);
    // …and refused without it. The gate is the token, in both directions.
    expect(
      envelopeOf(() => instance.canActivate(context({ socketIp: "127.0.0.1" }))).errorCode
    ).toBe("NODE_ADMIN_TOKEN_MISSING");
    // NODE_ADMIN_REMOTE_FORBIDDEN can never be the answer here: there is no local caller.
    expect(
      envelopeOf(() => instance.canActivate(context({ socketIp: "203.0.113.7" }))).errorCode
    ).toBe("NODE_ADMIN_TOKEN_MISSING");
  });

  it("prints the 'token is the only network barrier' warning whenever it IS the only barrier", () => {
    const armedProxied = captureLogs(() => proxied()).join("\n");
    expect(armedProxied).toMatch(/ONLY NETWORK BARRIER/);
    expect(armedProxied).toMatch(/proxied/);

    // The round-4 bug: this warning was tied to ALLOW_REMOTE, so a tunnel got nothing.
    const armedRemote = captureLogs(() => guard({ nodeAdminAllowRemote: true })).join("\n");
    expect(armedRemote).toMatch(/ONLY NETWORK BARRIER/);

    // Direct + loopback-only is the one posture where the network still adds a barrier — it
    // still announces itself, but without the alarm.
    const direct = captureLogs(() => guard()).join("\n");
    expect(direct).toMatch(/ENABLED/);
    expect(direct).not.toMatch(/ONLY NETWORK BARRIER/);

    // Disabled says nothing at all.
    expect(captureLogs(() => guard({ nodeAdminEnabled: false }))).toEqual([]);
  });

  it("says at boot that proxied endpoints stay closed until the operator opts in", () => {
    const lines = captureLogs(() => guard({ nodeAdminNetworkMode: "proxied" })).join("\n");
    expect(lines).toMatch(/stay DISABLED/);
    expect(lines).toMatch(/NODE_ADMIN_ALLOW_PROXIED=true/);
  });

  it("never lets X-Forwarded-For decide admission", () => {
    // direct mode: a remote caller claiming loopback in the header is still remote.
    expect(
      envelopeOf(() =>
        guard().canActivate(
          context({
            socketIp: "203.0.113.7",
            headers: {
              [HEADER_NODE_ADMIN_TOKEN]: TOKEN,
              [HEADER_FORWARDED_FOR]: "127.0.0.1",
            },
          })
        )
      ).errorCode
    ).toBe("NODE_ADMIN_REMOTE_FORBIDDEN");
    // proxied mode with a trusted proxy: the header only picks a bucket, it cannot authorise.
    expect(
      envelopeOf(() =>
        proxied({
          nodeAdminTrustedProxyCidrs: ["127.0.0.1"],
          nodeAdminTrustedProxyHops: 1,
        }).canActivate(
          context({ socketIp: "127.0.0.1", headers: { [HEADER_FORWARDED_FOR]: "127.0.0.1" } })
        )
      ).errorCode
    ).toBe("NODE_ADMIN_TOKEN_MISSING");
  });

  it("refuses to boot on ALLOW_PROXIED without the matching mode — the fail-OPEN direction", () => {
    // An operator who sets only ALLOW_PROXIED believes they declared the tunnel; the node
    // would still be in `direct` mode, i.e. applying an inert loopback gate. Refuse.
    expect(() => guard({ nodeAdminAllowProxied: true })).toThrow(
      /requires NODE_ADMIN_NETWORK_MODE=proxied/
    );
    expect(() => guard({ nodeAdminNetworkMode: "direct", nodeAdminAllowProxied: true })).toThrow(
      /requires NODE_ADMIN_NETWORK_MODE=proxied/
    );
  });

  it("says so when NODE_ADMIN_ALLOW_REMOTE is set but means nothing", () => {
    const lines = captureLogs(() => proxied({ nodeAdminAllowRemote: true })).join("\n");
    expect(lines).toMatch(/NODE_ADMIN_ALLOW_REMOTE is set but has no effect in proxied mode/);
  });

  it("refuses to boot on a half-declared trusted-proxy topology", () => {
    expect(() => proxied({ nodeAdminTrustedProxyCidrs: ["127.0.0.1"] })).toThrow(/TOGETHER/);
    expect(() => proxied({ nodeAdminTrustedProxyHops: 1 })).toThrow(/TOGETHER/);
    expect(() =>
      guard({ nodeAdminTrustedProxyCidrs: ["127.0.0.1"], nodeAdminTrustedProxyHops: 1 })
    ).toThrow(/NODE_ADMIN_NETWORK_MODE=proxied/);
    expect(() =>
      proxied({ nodeAdminTrustedProxyCidrs: ["not-a-cidr"], nodeAdminTrustedProxyHops: 1 })
    ).toThrow(/not a valid IP\/CIDR/);
  });

  it("rejects fail-closed when the declared proxy topology does not match the request", () => {
    const instance = proxied({
      nodeAdminTrustedProxyCidrs: ["127.0.0.0/8"],
      nodeAdminTrustedProxyHops: 1,
    });
    // Peer is not the declared proxy: something else is in the path.
    expect(
      envelopeOf(() =>
        instance.canActivate(
          context({
            socketIp: "203.0.113.7",
            headers: { [HEADER_FORWARDED_FOR]: "198.51.100.4", ...withToken().headers },
          })
        )
      ).errorCode
    ).toBe("NODE_ADMIN_UNTRUSTED_PROXY");
    // Declared proxy, but it did not append the hop it was declared to append.
    for (const forwarded of [undefined, "", "   ", "not-an-ip"]) {
      const headers: Record<string, string> = { ...withToken().headers };
      if (forwarded !== undefined) headers[HEADER_FORWARDED_FOR] = forwarded;
      expect([
        forwarded,
        envelopeOf(() => instance.canActivate(context({ socketIp: "127.0.0.1", headers })))
          .errorCode,
      ]).toEqual([forwarded, "NODE_ADMIN_FORWARDED_INVALID"]);
    }
  });

  it("buckets by the hop the trusted proxy appended, not by a client-prepended value", () => {
    // One trusted proxy: whatever the client prepends, the real client is the LAST entry.
    const instance = proxied({
      nodeAdminTrustedProxyCidrs: ["127.0.0.0/8"],
      nodeAdminTrustedProxyHops: 1,
      nodeAdminRateMax: 2,
    });
    const attempt = (forwarded: string) =>
      envelopeOf(() =>
        instance.canActivate(
          context({
            socketIp: "127.0.0.1",
            headers: {
              [HEADER_NODE_ADMIN_TOKEN]: "wrong",
              [HEADER_FORWARDED_FOR]: forwarded,
            },
          })
        )
      ).errorCode;

    // A single attacker spending its budget cannot escape it by forging extra left-hand hops.
    expect(attempt("203.0.113.9")).toBe("NODE_ADMIN_TOKEN_INVALID");
    expect(attempt("10.9.9.9, 203.0.113.9")).toBe("NODE_ADMIN_TOKEN_INVALID");
    expect(attempt("10.8.8.8, 10.9.9.9, 203.0.113.9")).toBe("NODE_ADMIN_RATE_LIMITED");
    // A genuinely different client still has its own budget.
    expect(attempt("198.51.100.4")).toBe("NODE_ADMIN_TOKEN_INVALID");
  });
});

describe("NodeAdminGuard throttle ledgers (CC-49 round-5 MEDIUM-2)", () => {
  // The finding: behind a tunnel every caller shares the source key 127.0.0.1, and the single
  // budget counted successes too — so ~10 anonymous requests/minute locked the operator out.
  const proxied = (config: Record<string, unknown> = {}) =>
    guard({ nodeAdminNetworkMode: "proxied", nodeAdminAllowProxied: true, ...config });

  it("an anonymous flood through the shared proxy bucket never 429s a correct token", () => {
    const instance = proxied({ nodeAdminRateMax: 3, nodeAdminAnonGlobalRateMax: 3 });
    for (let i = 0; i < 3; i++) {
      expect(
        envelopeOf(() => instance.canActivate(context({ socketIp: "127.0.0.1" }))).errorCode
      ).toBe("NODE_ADMIN_TOKEN_MISSING");
    }
    // Anonymous budget spent — anonymous callers are now bounded…
    const flooded = envelopeOf(() => instance.canActivate(context({ socketIp: "127.0.0.1" })));
    expect(flooded.statusCode).toBe(HttpStatus.TOO_MANY_REQUESTS);
    expect(flooded.errorCode).toBe("NODE_ADMIN_RATE_LIMITED");
    // …and a wrong token is bounded with them.
    expect(
      envelopeOf(() =>
        instance.canActivate(context({ socketIp: "127.0.0.1", ...withToken("guess") }))
      ).errorCode
    ).toBe("NODE_ADMIN_RATE_LIMITED");
    // THE REGRESSION: the operator, on the same shared bucket, still gets through.
    expect(instance.canActivate(context({ socketIp: "127.0.0.1", ...withToken() }))).toBe(true);
    expect(instance.canActivate(context({ socketIp: "127.0.0.1", ...withToken() }))).toBe(true);
  });

  it("still bounds brute force: wrong tokens are charged per source AND globally", () => {
    const instance = proxied({
      nodeAdminTrustedProxyCidrs: ["127.0.0.0/8"],
      nodeAdminTrustedProxyHops: 1,
      nodeAdminRateMax: 100, // per-source is generous here; the GLOBAL ledger is the bound
      nodeAdminAnonGlobalRateMax: 4,
    });
    const attempt = (client: string) =>
      envelopeOf(() =>
        instance.canActivate(
          context({
            socketIp: "127.0.0.1",
            headers: {
              [HEADER_NODE_ADMIN_TOKEN]: "guess",
              [HEADER_FORWARDED_FOR]: client,
            },
          })
        )
      ).errorCode;
    // Four distinct client IPs — a per-source-only bound would let this run forever.
    for (const client of ["203.0.113.1", "203.0.113.2", "203.0.113.3", "203.0.113.4"]) {
      expect([client, attempt(client)]).toEqual([client, "NODE_ADMIN_TOKEN_INVALID"]);
    }
    expect(attempt("203.0.113.5")).toBe("NODE_ADMIN_RATE_LIMITED");
    // …and the operator is STILL not affected by that global anonymous exhaustion.
    expect(
      instance.canActivate(
        context({
          socketIp: "127.0.0.1",
          headers: { [HEADER_NODE_ADMIN_TOKEN]: TOKEN, [HEADER_FORWARDED_FOR]: "203.0.113.6" },
        })
      )
    ).toBe(true);
  });

  it("bounds the operator budget too, on its own ledger, and recovers after the window", () => {
    let clock = NOW;
    const instance = guard({ nodeAdminOperatorRateMax: 2 }, () => clock);
    expect(instance.canActivate(context(withToken()))).toBe(true);
    expect(instance.canActivate(context(withToken()))).toBe(true);
    const limited = envelopeOf(() => instance.canActivate(context(withToken())));
    expect(limited.statusCode).toBe(HttpStatus.TOO_MANY_REQUESTS);
    expect(limited.errorCode).toBe("NODE_ADMIN_RATE_LIMITED");
    clock = NOW + 60_001;
    expect(instance.canActivate(context(withToken()))).toBe(true);
  });

  it("throttles anonymous attempts per source in direct mode, and recovers after the window", () => {
    let clock = NOW;
    const instance = guard({ nodeAdminRateMax: 3 }, () => clock);
    for (let i = 0; i < 3; i++) {
      expect(envelopeOf(() => instance.canActivate(context(withToken("wrong")))).errorCode).toBe(
        "NODE_ADMIN_TOKEN_INVALID"
      );
    }
    expect(envelopeOf(() => instance.canActivate(context(withToken("wrong")))).errorCode).toBe(
      "NODE_ADMIN_RATE_LIMITED"
    );
    // A different source has its own anonymous budget.
    expect(
      envelopeOf(() => instance.canActivate(context({ socketIp: "::1", ...withToken("wrong") })))
        .errorCode
    ).toBe("NODE_ADMIN_TOKEN_INVALID");
    clock = NOW + 60_001;
    expect(envelopeOf(() => instance.canActivate(context(withToken("wrong")))).errorCode).toBe(
      "NODE_ADMIN_TOKEN_INVALID"
    );
  });

  it("never puts the token in a rejection message or a log line", () => {
    const lines: string[] = [];
    const spy = jest
      .spyOn(Logger.prototype, "warn")
      .mockImplementation((...args: unknown[]) => void lines.push(String(args[0])));
    try {
      const instance = guard({ nodeAdminRateMax: 1, nodeAdminOperatorRateMax: 1 });
      const wrong = envelopeOf(() =>
        instance.canActivate(context(withToken("super-secret-guess")))
      );
      expect(instance.canActivate(context(withToken(TOKEN)))).toBe(true);
      const limited = envelopeOf(() => instance.canActivate(context(withToken(TOKEN))));
      for (const text of [wrong.message, limited.message, ...lines]) {
        expect(text).not.toContain("super-secret-guess");
        expect(text).not.toContain(TOKEN);
      }
    } finally {
      spy.mockRestore();
    }
  });
});
