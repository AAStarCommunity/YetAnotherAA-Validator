import {
  CanActivate,
  ExecutionContext,
  HttpException,
  HttpStatus,
  Injectable,
  Logger,
  Optional,
} from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { createHmac, timingSafeEqual } from "crypto";
import type { Request } from "express";

/** Header carrying the caller's millisecond unix timestamp. */
export const HEADER_TIMESTAMP = "X-RepCredit-Timestamp";
/** Header carrying the hex HMAC-SHA256 over {@link buildRepCreditAuthPreimage}. */
export const HEADER_AUTH = "X-RepCredit-Auth";

/**
 * Wire version of the HMAC preimage. BUMPED to v2 in CC-49 round 3: v1 signed only
 * `${timestamp}.${rawBody}`, so a captured token was, in principle, movable between the four
 * `/repcredit/*` endpoints (in practice the schemas are disjoint and the token is single-use,
 * which is why this was a LOW). v2 binds the METHOD and the REQUEST TARGET as well, so a
 * token authorises exactly one call on exactly one endpoint.
 *
 * Clients MUST send the version header; there is no v1 fallback — accepting both would leave
 * the unbound preimage reachable and defeat the change. See docs/REPCREDIT_EXPERIMENT.md for
 * the migration note handed to repo:sdk.
 */
export const REPCREDIT_AUTH_SCHEME = "v2";
/** Header carrying the preimage scheme version; must equal {@link REPCREDIT_AUTH_SCHEME}. */
export const HEADER_SCHEME = "X-RepCredit-Scheme";

/**
 * The exact bytes both sides HMAC. `\n`-joined with the raw body LAST so no field can be
 * shifted into another by choosing a value containing the separator.
 *
 *   v2 \n METHOD \n REQUEST-TARGET \n TIMESTAMP-MS \n RAW-BODY
 *
 * REQUEST-TARGET is the path (plus query string, if any) exactly as sent on the wire — i.e.
 * express's `req.originalUrl`. A client must sign the same string it puts in the request line.
 */
export function buildRepCreditAuthPreimage(input: {
  method: string;
  requestTarget: string;
  timestampMs: number | string;
  rawBody: string;
}): string {
  return [
    REPCREDIT_AUTH_SCHEME,
    String(input.method).toUpperCase(),
    input.requestTarget,
    String(input.timestampMs),
    input.rawBody,
  ].join("\n");
}

const LOOPBACK = new Set(["127.0.0.1", "::1", "::ffff:127.0.0.1"]);

/**
 * Mandatory admission gate for the RepCredit experiment endpoints (CC-49 BLOCKER-1).
 *
 * WHY THIS EXISTS. `/repcredit/slash/sign` produces a BLS signature over a preimage that
 * is byte-identical to `BLSAggregator.verifyAndExecute`'s slash-only hash, signed with this
 * node's local BLS key. That preimage contains no aggregator address and no domain tag, so
 * the resulting signature is NOT bound to the aggregator instance it was produced for: a
 * quorum of them is a byte-valid slash proof against ANY aggregator on the same chain where
 * the same keys occupy the same slots (CC-49 HIGH-A). Address isolation alone therefore does
 * not make an experiment co-signature unusable against production stake — `RepCreditService`
 * additionally refuses to sign with a key that is active on the audit aggregator, and the
 * experiment must use EPHEMERAL keys. Unlike the hardened audit path (GossipQuorumCoSigner),
 * this path does NOT re-derive the violation from chain state — it only agrees on the
 * ENCODING of caller-supplied fields. It must therefore never be reachable by an
 * unauthenticated caller, and the node listens on 0.0.0.0.
 *
 * Gate order (fail-closed; ANY failure rejects, nothing falls through):
 *   1. armed          — REPCREDIT_EXPERIMENT_SIGNING=true, else 403.
 *   2. secret present — armed without a secret rejects every request (503), never opens.
 *   3. body size      — bounded before any HMAC/parse work (413).
 *   4. source         — loopback only, unless REPCREDIT_ALLOW_REMOTE=true is set explicitly.
 *   5. HMAC           — declared scheme version + timestamp inside the asymmetric window +
 *                        constant-time HMAC over METHOD, REQUEST-TARGET and the RAW bytes.
 *                        Raw bytes unavailable → reject; never fall back to a re-serialised
 *                        body.
 *   6. replay         — a given auth token is accepted at most once, and the record of it
 *                        outlives the token's own validity (anchored to the SIGNED
 *                        timestamp, not to arrival — CC-49 MEDIUM-B).
 *
 * PRODUCTION SLASHING DOES NOT USE THIS PATH. The production quorum is
 * `GossipQuorumCoSigner` (peer-authenticated gossip transport, effective operator
 * watchlist, per-node independent on-chain violation re-verification with
 * evidenceHash === locally recomputed proofHash, severity-specific thresholds).
 * This guard exists so an experiment cannot borrow that path's authority.
 *
 * NOTE ON LOOPBACK: when a node sits behind a local reverse proxy or tunnel
 * (e.g. cloudflared → 127.0.0.1:3001) every public request also ARRIVES from
 * loopback. The loopback check is defence in depth only — the HMAC is the
 * actual authenticator, which is why the secret is mandatory rather than opt-in.
 */
@Injectable()
export class RepCreditExperimentGuard implements CanActivate {
  private readonly logger = new Logger(RepCreditExperimentGuard.name);

  private readonly armed: boolean;
  private readonly secret: string;
  private readonly ttlMs: number;
  private readonly allowRemote: boolean;
  private readonly maxBodyBytes: number;
  private readonly maxFutureSkewMs: number;
  private readonly replayCacheMax: number;
  private readonly now: () => number;

  /**
   * auth hex -> the ms after which the token itself is no longer acceptable
   * (`signedTimestamp + ttlMs`). Anchoring the entry to the SIGNED timestamp rather than to
   * arrival is what makes the record outlive the token: see `pruneSeen`.
   */
  private readonly seen = new Map<string, number>();

  private rawBodyWarned = false;

  constructor(
    config: ConfigService,
    /** Test seam for the TTL clock; @Optional so Nest DI passes undefined at runtime. */
    @Optional() now?: () => number
  ) {
    this.armed = config.get<boolean>("repCreditExperimentSigning") === true;
    this.secret = config.get<string>("repCreditExperimentAuthSecret") ?? "";
    // SECOND line of defence on the bounds (CC-49 round-3 MEDIUM). `configuration.ts` already
    // refuses to boot on a non-integer REPCREDIT_* value, but this guard must never run with a
    // NaN bound whatever hands it a config: `now - ts > NaN` and `len > NaN` are both FALSE,
    // i.e. a silently disabled staleness check and a silently disabled body cap.
    this.ttlMs = requireBound(config, "repCreditExperimentAuthTtlMs", 120_000, 1);
    this.allowRemote = config.get<boolean>("repCreditAllowRemote") === true;
    this.maxBodyBytes = requireBound(config, "repCreditMaxBodyBytes", 65_536, 1);
    this.maxFutureSkewMs = requireBound(config, "repCreditAuthMaxFutureSkewMs", 5_000, 0);
    this.replayCacheMax = requireBound(config, "repCreditReplayCacheMax", 10_000, 1);
    this.now = now ?? (() => Date.now());

    // Surface a dangerous or unusable arm at STARTUP, not on the first request.
    if (this.armed && !this.secret) {
      this.logger.warn(
        "RepCredit experiment signing is ARMED but REPCREDIT_EXPERIMENT_AUTH_SECRET is " +
          "empty — every /repcredit request will be rejected (503) until a secret is set"
      );
    }
    if (this.armed && this.allowRemote) {
      this.logger.warn(
        "RepCredit experiment signing is ARMED with REPCREDIT_ALLOW_REMOTE=true — this " +
          "node accepts slash-proof co-sign requests from non-loopback sources; the HMAC " +
          "secret is the ONLY remaining barrier to a real slash proof"
      );
    }
  }

  canActivate(context: ExecutionContext): boolean {
    // 1. Not armed → the endpoints do not exist as far as a caller is concerned.
    if (!this.armed) {
      throw new HttpException("RepCredit experiment signing is disabled", HttpStatus.FORBIDDEN);
    }

    // 2. Armed but unusable. Reject rather than degrade to no auth.
    if (!this.secret) {
      throw new HttpException(
        "RepCredit experiment signing is armed but the server secret is unset",
        HttpStatus.SERVICE_UNAVAILABLE
      );
    }

    const req = context.switchToHttp().getRequest<Request & { rawBody?: Buffer }>();

    // 3. Bound the work an unauthenticated caller can make us do. Deliberately below
    //    express's own json limit so THIS is the binding cap; a body large enough to
    //    escape the check is rejected by express first.
    if (req.rawBody !== undefined && req.rawBody.length > this.maxBodyBytes) {
      throw new HttpException(
        `request body exceeds ${this.maxBodyBytes} bytes`,
        HttpStatus.PAYLOAD_TOO_LARGE
      );
    }

    // 4. Loopback-only unless the operator explicitly opted out.
    if (!this.allowRemote) {
      // socket.remoteAddress FIRST, deliberately: express's `req.ip` honours
      // X-Forwarded-For when `trust proxy` is enabled, so a caller could spoof a
      // loopback source by setting a header. The socket peer address cannot be forged.
      const ip: string = (req as any)?.socket?.remoteAddress || (req as any)?.ip || "";
      if (!LOOPBACK.has(ip)) {
        throw new HttpException(
          "RepCredit experiment endpoints accept loopback callers only",
          HttpStatus.FORBIDDEN
        );
      }
    }

    // 5. Stateless HMAC over the exact bytes the caller signed.
    const ts = req.header?.(HEADER_TIMESTAMP);
    const auth = req.header?.(HEADER_AUTH);
    if (!ts || !auth) {
      throw new HttpException(
        `missing ${HEADER_TIMESTAMP}/${HEADER_AUTH} headers`,
        HttpStatus.UNAUTHORIZED
      );
    }
    const scheme = req.header?.(HEADER_SCHEME);
    if (scheme !== REPCREDIT_AUTH_SCHEME) {
      throw new HttpException(
        `${HEADER_SCHEME} must be "${REPCREDIT_AUTH_SCHEME}"`,
        HttpStatus.UNAUTHORIZED
      );
    }

    const now = this.now();
    const tsNum = Number(ts);
    // ASYMMETRIC window (CC-49 MEDIUM-B). Backwards: the full TTL. Forwards: only a small
    // clock-skew allowance. The previous symmetric `|now - ts| <= ttl` accepted a token
    // stamped a full TTL into the future, giving it a ~2x TTL lifetime while its replay entry
    // (keyed off arrival) expired after 1x TTL — a client whose clock merely ran fast produced
    // tokens that were replayable after their own replay record had been pruned.
    if (!Number.isFinite(tsNum) || now - tsNum > this.ttlMs || tsNum - now > this.maxFutureSkewMs) {
      throw new HttpException("auth timestamp outside the allowed window", HttpStatus.UNAUTHORIZED);
    }

    // HARD-FAIL when the raw bytes are unavailable (CC-49 round-2 LOW-F). The previous
    // fallback re-serialised `req.body` and HMAC'd THAT, i.e. it verified a normalised JSON
    // rendering (duplicate keys collapsed, whitespace lost) instead of what the caller
    // actually sent. `NestFactory.create(AppModule, { rawBody: true })` is set in main.ts, so
    // this branch is unreachable in the real app; making it an error costs nothing and
    // removes a degraded verification mode from the codebase.
    if (req.rawBody === undefined) {
      if (!this.rawBodyWarned) {
        this.rawBodyWarned = true;
        this.logger.error(
          "repcredit: req.rawBody unavailable — refusing to authenticate against a " +
            "re-serialised body. Ensure NestFactory.create(AppModule, { rawBody: true }) " +
            "is set (see main.ts)."
        );
      }
      throw new HttpException(
        "raw request body unavailable; cannot verify the request signature",
        HttpStatus.UNAUTHORIZED
      );
    }
    const rawBody = req.rawBody.toString("utf8");

    // Bind the verb and the request target too (CC-49 round-3 LOW-D): a token is valid for
    // one endpoint and one method only.
    const requestTarget: string = (req as any).originalUrl ?? (req as any).url ?? "";
    const expected = createHmac("sha256", this.secret)
      .update(
        buildRepCreditAuthPreimage({
          method: req.method ?? "",
          requestTarget,
          timestampMs: ts,
          rawBody,
        })
      )
      .digest("hex");
    if (!safeEqualHex(expected, auth)) {
      throw new HttpException("HMAC verification failed", HttpStatus.FORBIDDEN);
    }

    // 6. Single-use: a captured request cannot be replayed to farm additional
    //    co-signatures for the same proposal.
    //
    //    ATOMICITY: everything from here to the `set` below is synchronous with no `await`,
    //    so on Node's single-threaded event loop the check-then-set cannot interleave with a
    //    concurrent request. Do not introduce an await into this block.
    this.pruneSeen(now);
    if (this.seen.has(auth)) {
      throw new HttpException("auth token already used", HttpStatus.FORBIDDEN);
    }
    if (this.seen.size >= this.replayCacheMax) {
      // Fail closed. Evicting to make room would silently re-open the replay window; only an
      // already-authenticated caller can get us here.
      throw new HttpException(
        "RepCredit replay cache is full; refusing new auth tokens",
        HttpStatus.SERVICE_UNAVAILABLE
      );
    }
    // Anchored to the SIGNED timestamp: the entry lives exactly as long as the token it
    // guards. `now + ttl` (the previous value) expired the record while the token was still
    // inside its own acceptance window whenever the caller's clock ran ahead.
    this.seen.set(auth, tsNum + this.ttlMs);
    return true;
  }

  /**
   * Drop replay entries whose token is itself no longer acceptable.
   *
   * STRICTLY `<`, not `<=` (CC-49 MEDIUM-B boundary case). A token stamped `ts` is still
   * accepted at exactly `now === ts + ttl` (the staleness test rejects only `now - ts > ttl`),
   * so its record must survive that instant too. With `<=` both tests took the equality and a
   * replay slipped through on the boundary tick.
   */
  private pruneSeen(now: number): void {
    for (const [key, expiry] of this.seen) {
      if (expiry < now) this.seen.delete(key);
    }
  }

  /**
   * Reference header computation — the exact bytes a client must produce.
   *
   * BREAKING vs the v1 signature `computeHeaders(secret, timestampMs, rawBody)`: callers must
   * now pass the method and the request target as well (CC-49 round-3). repo:sdk pins this
   * function's source, so the change surfaces as a compile/pin failure rather than as an
   * opaque 403 mid-run.
   */
  static computeHeaders(
    secret: string,
    input: { method: string; requestTarget: string; timestampMs: number; rawBody: string }
  ): Record<string, string> {
    const ts = String(input.timestampMs);
    return {
      [HEADER_SCHEME]: REPCREDIT_AUTH_SCHEME,
      [HEADER_TIMESTAMP]: ts,
      [HEADER_AUTH]: createHmac("sha256", secret)
        .update(buildRepCreditAuthPreimage({ ...input, timestampMs: ts }))
        .digest("hex"),
    };
  }
}

/**
 * Read a numeric bound that MUST be usable. An absent key takes the documented default; a
 * present-but-unusable value (NaN, negative, non-integer) is a configuration error and throws
 * at construction — never silently becomes "no bound".
 */
function requireBound(config: ConfigService, key: string, fallback: number, min: number): number {
  const value = config.get<number>(key);
  if (value === undefined || value === null) return fallback;
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < min) {
    throw new Error(`RepCredit guard: ${key} must be an integer >= ${min} (got ${String(value)})`);
  }
  return value;
}

/** Constant-time hex comparison; false on any length/format mismatch. */
function safeEqualHex(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  try {
    return timingSafeEqual(Buffer.from(a, "hex"), Buffer.from(b, "hex"));
  } catch {
    return false;
  }
}
