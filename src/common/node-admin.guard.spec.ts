import { jest } from "@jest/globals";
import { ExecutionContext, HttpException, HttpStatus, Logger } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { ERROR_CODE_SCHEMA_VERSION } from "./error-codes.js";
import {
  HEADER_FORWARDED_FOR,
  HEADER_NODE_ADMIN_TOKEN,
  NodeAdminGuard,
  NodeAdminPolicy,
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
  // The guard is a shell around ONE application-level policy (CC-49 round-6 MEDIUM-2): Nest
  // builds a guard instance per module, so every piece of state under test lives here.
  return new NodeAdminGuard(new NodeAdminPolicy(configService, now));
}

/** How many distinct keys a ledger is holding — the round-6 MEDIUM-3 memory assertions. */
function ledgerSize(instance: NodeAdminGuard, ledger: "anonBySource" | "anonGlobal" | "operator") {
  return ((instance as any).policy[ledger] as { size: number }).size;
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
  });

  it("requires the mode to be DECLARED when enabled — absent is not `direct` (round-6 MEDIUM-1)", () => {
    // The round-5 hole reached by doing NOTHING: NODE_ADMIN_ENABLED=true with no mode ran in
    // `direct` and printed "loopback callers only" — an assertion the operator never made, and
    // a false one behind cloudflared, with no highlighted warning.
    for (const missing of [undefined, "", "   "]) {
      expect(() => guard({ nodeAdminNetworkMode: missing })).toThrow(
        /NODE_ADMIN_NETWORK_MODE must be declared/
      );
    }
    // While the endpoints are DISABLED there is nothing to reach and nothing to declare, so
    // the existing dvt1/2/3 configs (ENABLED=false) keep booting untouched.
    expect(() =>
      guard({ nodeAdminEnabled: false, nodeAdminNetworkMode: undefined })
    ).not.toThrow();
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

describe("NodeAdminGuard ledger cost (CC-49 round-6 MEDIUM-3)", () => {
  // The finding: the throttle bounded the STATUS CODE, not the work. Every anonymous request
  // — including the ones already being 429'd — allocated or refreshed a per-source entry, and
  // with a declared trusted proxy the key comes from a header, so one host forging 25k
  // X-Forwarded-For values grew RSS by 123MB and made each request 3.4x slower, on the same
  // process that runs the signing hot path.
  const proxiedWithProxy = (config: Record<string, unknown> = {}) =>
    guard({
      nodeAdminNetworkMode: "proxied",
      nodeAdminAllowProxied: true,
      nodeAdminTrustedProxyCidrs: ["127.0.0.0/8"],
      nodeAdminTrustedProxyHops: 1,
      ...config,
    });

  /** A distinct, VALID client address per index — an unparseable one is refused earlier. */
  const forgedIp = (i: number) => `10.${(i >> 16) & 0xff}.${(i >> 8) & 0xff}.${i & 0xff}`;

  const anonymousFrom = (instance: NodeAdminGuard, client: string) =>
    envelopeOf(() =>
      instance.canActivate(
        context({ socketIp: "127.0.0.1", headers: { [HEADER_FORWARDED_FOR]: client } })
      )
    ).errorCode;

  it("stops allocating per-source entries once the GLOBAL anonymous budget is spent", () => {
    const instance = proxiedWithProxy({
      nodeAdminAnonGlobalRateMax: 3,
      nodeAdminRateMax: 1_000, // deliberately generous: the global ledger is the bound
    });
    for (let i = 0; i < 3; i++) {
      expect(anonymousFrom(instance, `203.0.113.${i}`)).toBe("NODE_ADMIN_TOKEN_MISSING");
    }
    expect(ledgerSize(instance, "anonBySource")).toBe(3);

    // 5,000 forged client addresses AFTER the global budget is gone: all rejected, and not one
    // of them buys a ledger entry. Before the fix this was 5,000 new keys.
    for (let i = 0; i < 5_000; i++) {
      expect(anonymousFrom(instance, forgedIp(i))).toBe("NODE_ADMIN_RATE_LIMITED");
    }
    expect(ledgerSize(instance, "anonBySource")).toBe(3);

    // …and the operator is untouched by all of it: separate ledger, and it was never charged.
    expect(
      instance.canActivate(
        context({
          socketIp: "127.0.0.1",
          headers: { [HEADER_NODE_ADMIN_TOKEN]: TOKEN, [HEADER_FORWARDED_FOR]: "203.0.113.99" },
        })
      )
    ).toBe(true);
    expect(ledgerSize(instance, "operator")).toBe(1);
  });

  it("caps the number of tracked keys and evicts least-recently-used, never sweeping the table", () => {
    // Global budget raised far above the capacity, so the ONLY thing bounding the table here is
    // the capacity itself.
    const instance = proxiedWithProxy({
      nodeAdminAnonGlobalRateMax: 10_000,
      nodeAdminRateMax: 1,
    });
    for (let i = 0; i < 4_000; i++) {
      anonymousFrom(instance, forgedIp(i));
    }
    const size = ledgerSize(instance, "anonBySource");
    expect(size).toBeLessThanOrEqual(1_024);
    // Bounded, and still actually tracking: eviction, not a periodic wipe.
    expect(size).toBeGreaterThan(0);
    // The global ledger is one key by construction, whatever the traffic looks like.
    expect(ledgerSize(instance, "anonGlobal")).toBe(1);
  });

  it("never forgets a LIVE budget to make room: a full table denies new keys instead", () => {
    // The bound must not be self-defeating. If reaching capacity evicted a live entry, a source
    // that had spent its budget could get a fresh one just by pushing enough other keys through
    // the table — turning the memory fix into a rate-limit bypass.
    const instance = proxiedWithProxy({
      nodeAdminAnonGlobalRateMax: 10_000,
      nodeAdminRateMax: 2,
    });
    const attacker = "203.0.113.77";
    expect(anonymousFrom(instance, attacker)).toBe("NODE_ADMIN_TOKEN_MISSING");
    expect(anonymousFrom(instance, attacker)).toBe("NODE_ADMIN_TOKEN_MISSING");
    // Spent. Now push far more than the capacity of OTHER keys through, then come back.
    for (let i = 0; i < 4_000; i++) {
      anonymousFrom(instance, forgedIp(i));
    }
    expect(anonymousFrom(instance, attacker)).toBe("NODE_ADMIN_RATE_LIMITED");
    expect(ledgerSize(instance, "anonBySource")).toBeLessThanOrEqual(1_024);
  });

  it("reclaims keys once their window has passed, so a bounded table is not a permanent one", () => {
    let clock = NOW;
    const instance = guard(
      {
        nodeAdminNetworkMode: "proxied",
        nodeAdminAllowProxied: true,
        nodeAdminTrustedProxyCidrs: ["127.0.0.0/8"],
        nodeAdminTrustedProxyHops: 1,
        nodeAdminAnonGlobalRateMax: 10_000,
        nodeAdminRateMax: 1,
      },
      () => clock
    );
    for (let i = 0; i < 2_000; i++) anonymousFrom(instance, forgedIp(i));
    expect(ledgerSize(instance, "anonBySource")).toBeLessThanOrEqual(1_024);
    clock = NOW + 60_001; // every recorded attempt is now outside the window
    for (let i = 5_000; i < 5_010; i++) {
      // Fresh sources get in again — the table reclaimed the expired keys to make room.
      expect(anonymousFrom(instance, forgedIp(i))).toBe("NODE_ADMIN_TOKEN_MISSING");
    }
  });

  it("does not degrade with the number of forged keys — the flood is O(1) per request", () => {
    const instance = proxiedWithProxy({
      nodeAdminAnonGlobalRateMax: 10_000,
      nodeAdminRateMax: 1,
    });
    const batch = (offset: number, count: number) => {
      const started = process.hrtime.bigint();
      for (let i = offset; i < offset + count; i++) {
        anonymousFrom(instance, forgedIp(i));
      }
      return Number(process.hrtime.bigint() - started) / 1e6;
    };
    const first = batch(0, 5_000);
    const last = batch(20_000, 5_000); // 25k distinct keys seen in total
    // The old full-table sweep made the last batch ~3.4x the first. The bar is deliberately
    // loose (CI is noisy); a re-introduced O(n) sweep blows through it by an order of magnitude.
    expect(last).toBeLessThan(Math.max(first * 4, 250));
  });
});

describe("NodeAdminGuard source of truth for the peer address (CC-49 round-6 LOW-2)", () => {
  it("refuses a request whose socket peer cannot be read instead of falling back to req.ip", () => {
    // `req.ip` is X-Forwarded-For-derived once express `trust proxy` is on. Nothing in this
    // repo sets that today, which is why this is LOW — but the fallback was one setting away
    // from letting a header supply the address the comment calls unforgeable.
    const req = {
      ip: "127.0.0.1",
      socket: {},
      header: (name: string) => ({ [HEADER_NODE_ADMIN_TOKEN]: TOKEN })[name],
    };
    const ctx = { switchToHttp: () => ({ getRequest: () => req }) } as unknown as ExecutionContext;
    const envelope = envelopeOf(() => guard().canActivate(ctx));
    expect(envelope.statusCode).toBe(HttpStatus.FORBIDDEN);
    expect(envelope.errorCode).toBe("NODE_ADMIN_PEER_UNKNOWN");
  });
});

describe("NodeAdminGuard IPv4-mapped proxy CIDRs (CC-49 round-6 LOW-3)", () => {
  const proxied = (cidrs: string[]) =>
    guard({
      nodeAdminNetworkMode: "proxied",
      nodeAdminAllowProxied: true,
      nodeAdminTrustedProxyCidrs: cidrs,
      nodeAdminTrustedProxyHops: 1,
    });

  it("refuses to boot on an IPv6 range that can only ever match nothing", () => {
    // A dual-stack listener reports `::ffff:127.0.0.1`, which normalises to the 4-byte IPv4
    // form — so these ranges boot fine and then 403 every single request with no explanation.
    for (const cidr of ["::ffff:0:0/96", "::/0", "::ffff:0:0/64"]) {
      expect(() => proxied([cidr])).toThrow(/IPv4-mapped/);
    }
  });

  it("still accepts real IPv6 proxy ranges and the IPv4 form the message points at", () => {
    expect(() => proxied(["2001:db8::/32"])).not.toThrow();
    expect(() => proxied(["::1/128"])).not.toThrow();
    expect(() => proxied(["127.0.0.0/8"])).not.toThrow();
    // `::ffff:127.0.0.1` is parsed as the IPv4 literal it is, so it is a usable declaration.
    expect(() => proxied(["::ffff:127.0.0.1"])).not.toThrow();
  });
});
