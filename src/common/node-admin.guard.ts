import {
  CanActivate,
  ExecutionContext,
  HttpStatus,
  Injectable,
  Logger,
  Optional,
} from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { createHash, timingSafeEqual } from "crypto";
import type { Request } from "express";
import { ErrorCategory, structuredError } from "./error-codes.js";

/** Header carrying the operator's node-admin bearer token. */
export const HEADER_NODE_ADMIN_TOKEN = "X-Node-Admin-Token";

/** Shortest token this guard will accept. Below this a bearer token is not an authenticator. */
export const NODE_ADMIN_MIN_TOKEN_LENGTH = 32;

const LOOPBACK = new Set(["127.0.0.1", "::1", "::ffff:127.0.0.1"]);

/**
 * Stable machine-readable codes for the node-admin gate. See `error-codes.ts` for the contract.
 * Every one of them is `auth`: this guard only ever answers "you are not admitted".
 */
export const NODE_ADMIN_ERRORS = {
  NODE_ADMIN_DISABLED: HttpStatus.FORBIDDEN,
  NODE_ADMIN_TOKEN_UNSET: HttpStatus.SERVICE_UNAVAILABLE,
  NODE_ADMIN_REMOTE_FORBIDDEN: HttpStatus.FORBIDDEN,
  NODE_ADMIN_RATE_LIMITED: HttpStatus.TOO_MANY_REQUESTS,
  NODE_ADMIN_TOKEN_MISSING: HttpStatus.UNAUTHORIZED,
  NODE_ADMIN_TOKEN_INVALID: HttpStatus.FORBIDDEN,
} as const;

export type NodeAdminErrorCode = keyof typeof NODE_ADMIN_ERRORS;

const CATEGORY: ErrorCategory = "auth";

function adminError(code: NodeAdminErrorCode, message: string) {
  return structuredError(NODE_ADMIN_ERRORS[code], code, CATEGORY, message);
}

/**
 * Admission gate for the node's STATE-CHANGING admin endpoints (CC-49 round-4 HIGH-1).
 *
 * WHY THIS EXISTS. These endpoints were reachable by any unauthenticated caller while the
 * node listens on `0.0.0.0` behind a public tunnel (dvt1/2/3 → cloudflared):
 *
 *   POST   /node/register          — sends an on-chain transaction from the node's funded
 *                                    account, and echoed the raw provider error (i.e. the
 *                                    RPC URL, i.e. the provider API key) back in the body;
 *   POST   /dashboard/nodes        — generates and persists new BLS key material;
 *   POST   /dashboard/import-node  — accepts a BLS PRIVATE KEY and writes it to disk;
 *   DELETE /dashboard/current-node — destroys the node's key material;
 *   POST   /gossip/data            — writes into the gossip state this node republishes.
 *
 * None of them is part of the signing hot path and none is called by a peer: they are
 * operator actions. So the default is now OFF — `NODE_ADMIN_ENABLED` unset means the routes
 * answer `403` and nothing behind them runs. The supported way to register a node is the
 * controlled CLI (`scripts/register-node.mjs`), which uses the operator's own key.
 *
 * Gate order (fail-closed; ANY failure rejects, nothing falls through):
 *   1. enabled   — NODE_ADMIN_ENABLED=true, else 403.
 *   2. token set — enabled without a token rejects every request (503); never opens.
 *   3. source    — loopback only, unless NODE_ADMIN_ALLOW_REMOTE=true is set explicitly.
 *   4. throttle  — per-source-IP window, ALWAYS on (unlike the opt-in ThrottleGuard), so
 *                  token guessing is bounded even on a loopback-exposed tunnel; 429.
 *   5. token     — constant-time comparison of SHA-256(presented) vs SHA-256(configured),
 *                  so neither the value nor its LENGTH leaks through timing; 401/403.
 *
 * The token is a bearer credential rather than a request-bound HMAC (which is what
 * `/repcredit/*` uses). That is deliberate and bounded: this gate is loopback-by-default and
 * rate-limited, the actions are idempotent-or-refused operator actions, and an HMAC scheme
 * here would have to be re-implemented in the browser dashboard. It is NOT strong enough to
 * be exposed remotely over plaintext — `NODE_ADMIN_ALLOW_REMOTE` logs a warning saying so.
 *
 * SECRET SEPARATION. The token must not equal `REPCREDIT_EXPERIMENT_AUTH_SECRET`. Sharing
 * one secret between the slash-proof co-signing path and the node-admin path would mean a
 * leak of either is a compromise of both, and they have different blast radii. Reuse is a
 * BOOT failure, not a request-time warning.
 */
@Injectable()
export class NodeAdminGuard implements CanActivate {
  private readonly logger = new Logger(NodeAdminGuard.name);

  private readonly enabled: boolean;
  private readonly tokenDigest: Buffer | null;
  private readonly allowRemote: boolean;
  private readonly windowMs: number;
  private readonly max: number;
  private readonly now: () => number;

  /** source ip -> request timestamps within the current window. */
  private readonly hits = new Map<string, number[]>();

  constructor(
    config: ConfigService,
    /** Test seam for the throttle clock; @Optional so Nest DI passes undefined at runtime. */
    @Optional() now?: () => number
  ) {
    this.enabled = config.get<boolean>("nodeAdminEnabled") === true;
    const token = config.get<string>("nodeAdminToken") ?? "";
    this.allowRemote = config.get<boolean>("nodeAdminAllowRemote") === true;
    // Second line of defence on the bounds, exactly as in RepCreditExperimentGuard: a NaN
    // window or NaN max makes every `>=`/`<` comparison false, i.e. silently no throttle.
    this.windowMs = requireBound(config, "nodeAdminRateWindowMs", 60_000, 1_000);
    this.max = requireBound(config, "nodeAdminRateMax", 10, 1);
    this.now = now ?? (() => Date.now());

    if (this.enabled && token) {
      if (token.length < NODE_ADMIN_MIN_TOKEN_LENGTH) {
        throw new Error(
          `NODE_ADMIN_TOKEN must be at least ${NODE_ADMIN_MIN_TOKEN_LENGTH} characters ` +
            "— it is the only credential on endpoints that move on-chain funds and key material"
        );
      }
      const repCreditSecret = config.get<string>("repCreditExperimentAuthSecret") ?? "";
      if (repCreditSecret && token === repCreditSecret) {
        throw new Error(
          "NODE_ADMIN_TOKEN must not equal REPCREDIT_EXPERIMENT_AUTH_SECRET — the node-admin " +
            "and RepCredit experiment paths must not share a credential"
        );
      }
    }
    this.tokenDigest = token ? sha256(token) : null;

    if (this.enabled && !this.tokenDigest) {
      this.logger.warn(
        "Node admin HTTP endpoints are ENABLED but NODE_ADMIN_TOKEN is empty — every request " +
          "will be rejected (503) until a token is set"
      );
    }
    if (this.enabled && this.allowRemote) {
      this.logger.warn(
        "Node admin HTTP endpoints are ENABLED with NODE_ADMIN_ALLOW_REMOTE=true — a bearer " +
          "token is the ONLY barrier to on-chain registration and key-material changes from " +
          "any source. Front this with TLS and an IP allow-list, or prefer the CLI."
      );
    }
  }

  canActivate(context: ExecutionContext): boolean {
    // 1. Disabled → the endpoint does not act, whoever is calling.
    if (!this.enabled) {
      throw adminError(
        "NODE_ADMIN_DISABLED",
        "node admin HTTP endpoints are disabled; use the operator CLI " +
          "(scripts/register-node.mjs) or set NODE_ADMIN_ENABLED=true with NODE_ADMIN_TOKEN"
      );
    }

    // 2. Enabled but unusable. Reject rather than degrade to no auth.
    if (!this.tokenDigest) {
      throw adminError(
        "NODE_ADMIN_TOKEN_UNSET",
        "node admin endpoints are enabled but NODE_ADMIN_TOKEN is unset"
      );
    }

    const req = context.switchToHttp().getRequest<Request>();
    // socket.remoteAddress FIRST: express's `req.ip` honours X-Forwarded-For when
    // `trust proxy` is on, so a caller could otherwise claim a loopback source with a
    // header. The socket peer address cannot be forged.
    const ip: string = (req as any)?.socket?.remoteAddress || (req as any)?.ip || "";

    // 3. Loopback-only unless the operator explicitly opted out.
    if (!this.allowRemote && !LOOPBACK.has(ip)) {
      throw adminError(
        "NODE_ADMIN_REMOTE_FORBIDDEN",
        "node admin endpoints accept loopback callers only"
      );
    }

    // 4. Throttle BEFORE the comparison, so a guesser is bounded by the window and not by
    //    how fast we can hash. Counted per source IP even when the token is correct.
    this.consumeRateBudget(ip);

    // 5. Constant-time token check.
    const presented = req.header?.(HEADER_NODE_ADMIN_TOKEN);
    if (!presented) {
      throw adminError("NODE_ADMIN_TOKEN_MISSING", `missing ${HEADER_NODE_ADMIN_TOKEN} header`);
    }
    if (!timingSafeEqual(sha256(presented), this.tokenDigest)) {
      this.logger.warn(`Rejected node-admin request from ${ip}: invalid token`);
      throw adminError("NODE_ADMIN_TOKEN_INVALID", `invalid ${HEADER_NODE_ADMIN_TOKEN}`);
    }
    return true;
  }

  private consumeRateBudget(ip: string): void {
    const now = this.now();
    const key = ip || "unknown";
    const recent = (this.hits.get(key) ?? []).filter(t => now - t < this.windowMs);
    if (recent.length >= this.max) {
      this.hits.set(key, recent);
      this.logger.warn(`Node-admin rate limit exceeded for ${key} (${recent.length}/${this.max})`);
      throw adminError(
        "NODE_ADMIN_RATE_LIMITED",
        `too many node admin requests; limit is ${this.max} per ${this.windowMs}ms`
      );
    }
    recent.push(now);
    this.hits.set(key, recent);

    // Opportunistic cleanup so the map doesn't grow unbounded across idle sources.
    if (this.hits.size > 10_000) {
      for (const [k, ts] of this.hits) {
        if (ts.every(t => now - t >= this.windowMs)) this.hits.delete(k);
      }
    }
  }
}

function sha256(value: string): Buffer {
  return createHash("sha256").update(value, "utf8").digest();
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
    throw new Error(`Node admin guard: ${key} must be an integer >= ${min} (got ${String(value)})`);
  }
  return value;
}
