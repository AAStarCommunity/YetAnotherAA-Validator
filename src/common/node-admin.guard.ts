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
import { CidrRange, intersectsIpv4Mapped, ipInAnyCidr, parseCidr, parseIp } from "./cidr.js";
import { ErrorCategory, structuredError } from "./error-codes.js";

/** Header carrying the operator's node-admin bearer token. */
export const HEADER_NODE_ADMIN_TOKEN = "X-Node-Admin-Token";

/** Header the trusted-proxy bucketing reads — ONLY for rate-limit keys, never for admission. */
export const HEADER_FORWARDED_FOR = "X-Forwarded-For";

/** Shortest token this guard will accept. Below this a bearer token is not an authenticator. */
export const NODE_ADMIN_MIN_TOKEN_LENGTH = 32;

const LOOPBACK = new Set(["127.0.0.1", "::1", "::ffff:127.0.0.1"]);

/**
 * How this node is reached (CC-49 round-5 MEDIUM-1). The operator DECLARES it; the node
 * never guesses, because the two modes disagree about what a loopback socket means.
 *
 *   direct  — the listener is the network boundary. A loopback socket peer really is a
 *             process on this host, so it is usable as a source restriction.
 *   proxied — a reverse proxy / tunnel (cloudflared -> 127.0.0.1:3001) fronts the node, so
 *             EVERY public request also arrives from loopback. Loopback is not a boundary
 *             and is not consulted at all; the admin token is the only network barrier.
 */
export type NodeAdminNetworkMode = "direct" | "proxied";
export const NODE_ADMIN_NETWORK_MODES: readonly NodeAdminNetworkMode[] = ["direct", "proxied"];

/**
 * Stable machine-readable codes for the node-admin gate. See `error-codes.ts` for the contract.
 * Every one of them is `auth`: this guard only ever answers "you are not admitted".
 */
export const NODE_ADMIN_ERRORS = {
  NODE_ADMIN_DISABLED: HttpStatus.FORBIDDEN,
  NODE_ADMIN_PROXIED_NOT_ALLOWED: HttpStatus.FORBIDDEN,
  NODE_ADMIN_TOKEN_UNSET: HttpStatus.SERVICE_UNAVAILABLE,
  NODE_ADMIN_REMOTE_FORBIDDEN: HttpStatus.FORBIDDEN,
  NODE_ADMIN_PEER_UNKNOWN: HttpStatus.FORBIDDEN,
  NODE_ADMIN_UNTRUSTED_PROXY: HttpStatus.FORBIDDEN,
  NODE_ADMIN_FORWARDED_INVALID: HttpStatus.FORBIDDEN,
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
 * Admission policy for the node's STATE-CHANGING admin endpoints (CC-49 round-4 HIGH-1,
 * round-5 MEDIUM-1 / MEDIUM-2, round-6 MEDIUM-1 / MEDIUM-2 / MEDIUM-3).
 *
 * WHY THIS EXISTS. These endpoints were reachable by any unauthenticated caller while the
 * node listens on `0.0.0.0` behind a public tunnel (dvt1/2/3 -> cloudflared):
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
 * WHY THE POLICY IS A PROVIDER AND THE GUARD IS A SHELL (round-6 MEDIUM-2). `@UseGuards(Cls)`
 * makes Nest instantiate the guard class ONCE PER MODULE that declares a controller using it —
 * node, dashboard and gossip — so guard-held state was silently three-way partitioned: the
 * "global" anonymous ledger was three separate ledgers of N each (3N in effect), the per-source
 * ledger likewise, and the boot banner printed three times. The ledgers and the decision now
 * live in this ONE application-level provider (`NodeAdminModule` is `@Global`), so every route
 * spends the same budgets and announces once.
 *
 * NETWORK MODE IS DECLARED, NEVER INFERRED (round-5 MEDIUM-1, round-6 MEDIUM-1). The round-4
 * gate treated a loopback socket peer as a source restriction — but the reference deployment
 * named in this repo's own docs is cloudflared, which reaches the node FROM 127.0.0.1. Under
 * that topology the loopback gate was inert while the boot warning that says "the token is now
 * the only barrier" only fired for `NODE_ADMIN_ALLOW_REMOTE=true`, i.e. never fired exactly
 * where it was needed. So:
 *   - `NODE_ADMIN_NETWORK_MODE` is MANDATORY whenever `NODE_ADMIN_ENABLED=true`; a missing
 *     value is a boot failure, because "unset" used to mean `direct`, i.e. the node asserting
 *     "loopback callers only" on behalf of an operator who never asserted anything;
 *   - `direct` keeps the loopback restriction;
 *   - `proxied` treats EVERY request as remote, never consults loopback, ALWAYS prints the
 *     "token is the only network barrier" warning, and keeps the endpoints DISABLED until
 *     `NODE_ADMIN_ALLOW_PROXIED=true` acknowledges that explicitly.
 *
 * A CLIENT-SUPPLIED `X-Forwarded-For` IS NEVER TRUSTED. Admission always reads the socket
 * peer address, and ONLY that: there is no `req.ip` fallback, because `req.ip` is derived from
 * `X-Forwarded-For` once express `trust proxy` is on (round-6 LOW-2). A request whose socket
 * peer cannot be read is rejected, not admitted on a header-derived address. The header is
 * parsed only when the operator named the proxies (`NODE_ADMIN_TRUSTED_PROXY_CIDRS`) and the
 * exact hop count (`NODE_ADMIN_TRUSTED_PROXY_HOPS`), only when the socket peer is inside those
 * CIDRs, and only to pick a RATE-LIMIT BUCKET KEY — it can never grant access. Any
 * inconsistency (untrusted peer, too few hops, unparseable address) rejects.
 *
 * Gate order (fail-closed; ANY failure rejects, nothing falls through):
 *   1. enabled     — NODE_ADMIN_ENABLED=true, else 403.
 *   2. mode armed  — proxied without NODE_ADMIN_ALLOW_PROXIED=true stays disabled; 403.
 *   3. token set   — enabled without a token rejects every request (503); never opens.
 *   4. peer known  — an unreadable socket peer rejects; 403.
 *   5. source      — direct mode: loopback only, unless NODE_ADMIN_ALLOW_REMOTE=true; 403.
 *                    proxied mode: skipped — loopback is not a boundary here.
 *   6. bucket key  — socket peer, or the trusted-proxy-derived client IP; fail-closed; 403.
 *   7. token       — constant-time comparison of SHA-256(presented) vs SHA-256(configured),
 *                    so neither the value nor its LENGTH leaks through timing. Done BEFORE
 *                    any budget is charged, so the two classes of caller cannot share one.
 *   8. throttle    — SEPARATE budgets (round-5 MEDIUM-2):
 *                    unauthenticated -> the GLOBAL brute-force budget first, then per-source;
 *                    authenticated   -> its own, far larger, operator budget.
 *                    Exhausting the anonymous budgets can NEVER 429 a correct token; 429.
 *
 * THE THROTTLE MUST COST THE NODE A BOUNDED AMOUNT (round-6 MEDIUM-3). A rate limiter that
 * answers 429 but still allocates a ledger entry per request is not a bound: with a declared
 * trusted proxy the bucket key comes from a header, so one host forging 25k `X-Forwarded-For`
 * values grew the map (and the per-request cost of the full-table sweep) without limit — on a
 * process that also runs the signing hot path. Two rules fix that, and both are load-bearing:
 * the global anonymous budget is charged FIRST and SHORT-CIRCUITS (once it is spent no new
 * per-source entry is created or refreshed), and every ledger has a hard key capacity with
 * O(1) least-recently-used eviction instead of an O(n) sweep.
 *
 * The token is a bearer credential rather than a request-bound HMAC (which is what
 * `/repcredit/*` uses). That is deliberate and bounded: the actions are idempotent-or-refused
 * operator actions and an HMAC scheme here would have to be re-implemented in the browser
 * dashboard. It is NOT strong enough to be the sole barrier on a plaintext public path —
 * which is exactly what `proxied` mode and `NODE_ADMIN_ALLOW_REMOTE` warn about at boot.
 *
 * SECRET SEPARATION. The token must not equal `REPCREDIT_EXPERIMENT_AUTH_SECRET`. Sharing
 * one secret between the slash-proof co-signing path and the node-admin path would mean a
 * leak of either is a compromise of both, and they have different blast radii. Reuse is a
 * BOOT failure, not a request-time warning.
 */
@Injectable()
export class NodeAdminPolicy {
  private readonly logger = new Logger(NodeAdminPolicy.name);

  private readonly enabled: boolean;
  private readonly tokenDigest: Buffer | null;
  private readonly mode: NodeAdminNetworkMode;
  private readonly allowProxied: boolean;
  private readonly allowRemote: boolean;
  private readonly trustedProxies: readonly CidrRange[];
  private readonly trustedProxyHops: number;
  private readonly now: () => number;

  /** Unauthenticated attempts, per source. Small budget: this is the brute-force bound. */
  private readonly anonBySource: RollingWindow;
  /** Unauthenticated attempts, all sources together. Bounds a spread-out flood. */
  private readonly anonGlobal: RollingWindow;
  /** Authenticated requests. Its own storage, so an anonymous flood cannot spend it. */
  private readonly operator: RollingWindow;

  /** Log-rate state for the brute-force line; see `warnBudgetSpent`. */
  private lastBudgetWarnAt = 0;
  private suppressedBudgetWarns = 0;

  constructor(
    config: ConfigService,
    /** Test seam for the throttle clock; @Optional so Nest DI passes undefined at runtime. */
    @Optional() now?: () => number
  ) {
    this.enabled = config.get<boolean>("nodeAdminEnabled") === true;
    const token = config.get<string>("nodeAdminToken") ?? "";
    this.mode = requireMode(config.get<string>("nodeAdminNetworkMode"), this.enabled);
    this.allowProxied = config.get<boolean>("nodeAdminAllowProxied") === true;
    this.allowRemote = config.get<boolean>("nodeAdminAllowRemote") === true;
    this.now = now ?? (() => Date.now());

    // Second line of defence on the bounds, exactly as in RepCreditExperimentGuard: a NaN
    // window or NaN max makes every `>=`/`<` comparison false, i.e. silently no throttle.
    const windowMs = requireBound(config, "nodeAdminRateWindowMs", 60_000, 1_000);
    this.anonBySource = new RollingWindow(
      windowMs,
      requireBound(config, "nodeAdminRateMax", 10, 1)
    );
    // One key, ever. Capacity 1 keeps that a structural fact rather than a convention.
    this.anonGlobal = new RollingWindow(
      windowMs,
      requireBound(config, "nodeAdminAnonGlobalRateMax", 60, 1),
      1
    );
    this.operator = new RollingWindow(
      windowMs,
      requireBound(config, "nodeAdminOperatorRateMax", 120, 1)
    );

    // The dangerous half-declaration: an operator who sets ALLOW_PROXIED intending "yes, I am
    // behind cloudflared, that is fine" but forgets NODE_ADMIN_NETWORK_MODE=proxied would run
    // in `direct` mode — i.e. back in the round-4 hole, while believing they had declared the
    // proxy. Refuse to boot rather than run under an assertion the operator did not mean.
    if (this.allowProxied && this.mode !== "proxied") {
      throw new Error(
        "NODE_ADMIN_ALLOW_PROXIED=true requires NODE_ADMIN_NETWORK_MODE=proxied — otherwise the " +
          "node is still asserting that no reverse proxy fronts it, and the loopback source " +
          "restriction it applies would be inert behind one"
      );
    }

    const { ranges, hops } = requireTrustedProxies(config, this.mode);
    this.trustedProxies = ranges;
    this.trustedProxyHops = hops;

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

    this.announce();
  }

  /**
   * Say, at boot, exactly what is armed. The round-4 version only warned for
   * `ALLOW_REMOTE=true`, so the tunnel deployment — the one where the token really is the
   * only barrier — got no warning at all. Now every ENABLED posture warns, and the two
   * network-exposed postures warn loudly. Printed ONCE per process: this provider is a
   * singleton, unlike the per-module guard instances that used to print it three times.
   */
  private announce(): void {
    if (!this.enabled) return;

    if (this.mode === "proxied" && !this.allowProxied) {
      this.logger.warn(
        "Node admin HTTP endpoints stay DISABLED: NODE_ADMIN_NETWORK_MODE=proxied means every " +
          "request reaches this node through a reverse proxy / tunnel and is therefore remote. " +
          "Set NODE_ADMIN_ALLOW_PROXIED=true to accept that, or prefer the CLI " +
          "(scripts/register-node.mjs)."
      );
      return;
    }
    if (!this.tokenDigest) {
      this.logger.warn(
        "Node admin HTTP endpoints are ENABLED but NODE_ADMIN_TOKEN is empty — every request " +
          "will be rejected (503) until a token is set"
      );
      return;
    }

    const exposed = this.mode === "proxied" || this.allowRemote;
    const posture =
      this.mode === "proxied"
        ? "NODE_ADMIN_NETWORK_MODE=proxied (a reverse proxy / tunnel fronts this node, so a " +
          "loopback socket peer is NOT a boundary and is not checked)"
        : this.allowRemote
          ? "NODE_ADMIN_NETWORK_MODE=direct with NODE_ADMIN_ALLOW_REMOTE=true"
          : "NODE_ADMIN_NETWORK_MODE=direct, loopback callers only";

    const line = `Node admin HTTP endpoints are ENABLED — ${posture}.`;
    if (!exposed) {
      this.logger.warn(
        `${line} The NODE_ADMIN_TOKEN bearer credential is the only authentication on ` +
          "endpoints that move on-chain funds and key material."
      );
      return;
    }
    // High-visibility block: this is the posture where the token is the ONLY thing left.
    const RULE = "*".repeat(88);
    this.logger.warn(RULE);
    this.logger.warn(line);
    this.logger.warn(
      "*** THE NODE_ADMIN_TOKEN IS THE ONLY NETWORK BARRIER *** to on-chain registration and " +
        "BLS key-material creation/import/destruction. Front this with TLS and an IP " +
        "allow-list, keep the token per-node and CSPRNG-generated, or prefer the CLI " +
        "(scripts/register-node.mjs) and leave NODE_ADMIN_ENABLED unset."
    );
    if (this.mode === "proxied" && this.allowRemote) {
      this.logger.warn(
        "NODE_ADMIN_ALLOW_REMOTE is set but has no effect in proxied mode — every caller is " +
          "already treated as remote. Remove it so the config says what it does."
      );
    }
    if (this.mode === "proxied" && this.trustedProxyHops === 0) {
      this.logger.warn(
        "No NODE_ADMIN_TRUSTED_PROXY_CIDRS/_HOPS configured: every proxied caller shares one " +
          "brute-force bucket (the per-source budget cannot distinguish them). Authenticated " +
          "requests use a separate budget and are unaffected."
      );
    }
    if (this.trustedProxyHops > 0) {
      this.logger.warn(
        "A trusted reverse proxy is declared, so EVERY admin request must arrive through it " +
          "with a valid X-Forwarded-For — including one made on this host straight to the " +
          "listener, which is answered 403 NODE_ADMIN_FORWARDED_INVALID. There is no local " +
          "escape hatch on the HTTP path; the CLI (scripts/register-node.mjs) is it."
      );
    }
    this.logger.warn(RULE);
  }

  /** Decide whether `req` may reach a node-admin handler. Throws the structured 4xx/5xx. */
  authorize(req: Request): boolean {
    // 1. Disabled -> the endpoint does not act, whoever is calling.
    if (!this.enabled) {
      throw adminError(
        "NODE_ADMIN_DISABLED",
        "node admin HTTP endpoints are disabled; use the operator CLI " +
          "(scripts/register-node.mjs) or set NODE_ADMIN_ENABLED=true with NODE_ADMIN_TOKEN"
      );
    }

    // 2. Proxied deployments are remote by construction. Enabling the endpoints is not enough:
    //    the operator has to acknowledge that separately, or they stay closed.
    if (this.mode === "proxied" && !this.allowProxied) {
      throw adminError(
        "NODE_ADMIN_PROXIED_NOT_ALLOWED",
        "node admin HTTP endpoints are disabled in proxied network mode; every caller is " +
          "remote here, so set NODE_ADMIN_ALLOW_PROXIED=true to accept that explicitly"
      );
    }

    // 3. Enabled but unusable. Reject rather than degrade to no auth.
    if (!this.tokenDigest) {
      throw adminError(
        "NODE_ADMIN_TOKEN_UNSET",
        "node admin endpoints are enabled but NODE_ADMIN_TOKEN is unset"
      );
    }

    // 4. The socket peer, and NOTHING else. There is deliberately no `req.ip` fallback: with
    //    express `trust proxy` enabled `req.ip` is derived from X-Forwarded-For, so falling
    //    back to it would let a header decide what the code calls "the unforgeable peer".
    //    No peer -> no decision -> reject (round-6 LOW-2).
    const peer: string = (req as any)?.socket?.remoteAddress || "";
    if (!peer) {
      throw adminError(
        "NODE_ADMIN_PEER_UNKNOWN",
        "node admin endpoints could not read the socket peer address of this request; " +
          "refusing rather than falling back to a header-derived one"
      );
    }

    // 5. Loopback-only — ONLY in direct mode, where the socket peer really is a boundary.
    if (this.mode === "direct" && !this.allowRemote && !LOOPBACK.has(peer)) {
      throw adminError(
        "NODE_ADMIN_REMOTE_FORBIDDEN",
        "node admin endpoints accept loopback callers only in direct network mode"
      );
    }

    // 6. Throttle bucket key. Never an admission decision — see resolveSourceKey.
    const sourceKey = this.resolveSourceKey(req, peer);

    // 7. Constant-time token check FIRST, on a fixed-width digest, so a missing header costs
    //    the same as a wrong one and neither the value nor its length leaks through timing.
    const presented = req.header?.(HEADER_NODE_ADMIN_TOKEN) ?? "";
    const authenticated = timingSafeEqual(sha256(presented), this.tokenDigest);

    // 8. Budgets. Anonymous and authenticated callers are charged to DIFFERENT ledgers, so
    //    an anonymous flood bounds only itself and can never lock the operator out.
    if (!authenticated) {
      this.chargeAnonymous(sourceKey);
      if (!presented) {
        throw adminError("NODE_ADMIN_TOKEN_MISSING", `missing ${HEADER_NODE_ADMIN_TOKEN} header`);
      }
      this.logger.warn(`Rejected node-admin request from ${sourceKey}: invalid token`);
      throw adminError("NODE_ADMIN_TOKEN_INVALID", `invalid ${HEADER_NODE_ADMIN_TOKEN}`);
    }

    if (!this.operator.tryConsume(sourceKey, this.now())) {
      this.logger.warn(`Node-admin operator rate limit exceeded for ${sourceKey}`);
      throw adminError(
        "NODE_ADMIN_RATE_LIMITED",
        `too many authenticated node admin requests; limit is ${this.operator.max} per ` +
          `${this.operator.windowMs}ms`
      );
    }
    return true;
  }

  /**
   * Charge an unauthenticated attempt. The GLOBAL ledger is charged FIRST and short-circuits.
   *
   * Order matters twice over. Global-first means an attacker cannot keep the global ledger
   * clean by spending the cheaper per-source one — that was the round-5 requirement, and it
   * still holds because the global ledger is now the one that is ALWAYS charged. Short-circuit
   * means that once the global budget is spent the node stops doing per-request work for
   * anonymous callers entirely: no new per-source key is allocated, no existing one refreshed
   * (round-6 MEDIUM-3). Together with the ledger capacity below, the number of distinct
   * per-source keys a flood can create is bounded by the global budget per window, not by how
   * many `X-Forwarded-For` values it is willing to forge.
   */
  private chargeAnonymous(sourceKey: string): void {
    const now = this.now();
    const globalOk = this.anonGlobal.tryConsume(ANON_GLOBAL_KEY, now);
    if (!globalOk) throw this.anonymousLimitExceeded(sourceKey, true, "global");
    if (!this.anonBySource.tryConsume(sourceKey, now)) {
      throw this.anonymousLimitExceeded(sourceKey, false, "source");
    }
  }

  private anonymousLimitExceeded(sourceKey: string, global: boolean, spent: string) {
    // The source key is logged (it is an address, not a secret); the token never is. The line
    // itself is rate-limited: a flood is already being refused, so writing one log line per
    // refused request would just move the unbounded per-request cost into the log pipeline
    // (and onto the operator's disk) — round-6 MEDIUM-3 is about what the node SPENDS.
    this.warnBudgetSpent(
      `Node-admin brute-force budget spent for ${global ? "all sources" : sourceKey} (${spent})`
    );
    return adminError(
      "NODE_ADMIN_RATE_LIMITED",
      `too many unauthenticated node admin requests; limit is ${this.anonBySource.max} per ` +
        `source and ${this.anonGlobal.max} overall per ${this.anonBySource.windowMs}ms. ` +
        "A correct token is charged to a separate budget and is not affected."
    );
  }

  /** At most one brute-force line per window, with a count of what it stands for. */
  private warnBudgetSpent(message: string): void {
    const now = this.now();
    if (this.lastBudgetWarnAt !== 0 && now - this.lastBudgetWarnAt < this.anonBySource.windowMs) {
      this.suppressedBudgetWarns++;
      return;
    }
    const suppressed = this.suppressedBudgetWarns;
    this.suppressedBudgetWarns = 0;
    this.lastBudgetWarnAt = now;
    this.logger.warn(suppressed > 0 ? `${message}; ${suppressed} similar suppressed` : message);
  }

  /**
   * Pick the rate-limit bucket key. This value NEVER decides admission — step 5 already ran
   * on the unforgeable socket peer — it only decides which brute-force ledger an attempt is
   * charged to.
   *
   * In `proxied` mode every socket peer is the proxy, so without an operator-declared proxy
   * topology all callers legitimately share one bucket (that is what the global anonymous
   * ledger is for). When the operator DOES declare it, the client address is read from
   * `X-Forwarded-For` at the exact configured hop — and every inconsistency rejects:
   *   - socket peer outside the declared proxy CIDRs -> the request did not come through the
   *     declared proxy at all (or the operator mis-declared it);
   *   - fewer entries than declared hops -> the proxy did not append what it was declared to;
   *     this is also what a LOCAL caller hitting the listener directly looks like, and it is
   *     refused: declaring a proxy removes the HTTP local escape hatch (round-6 LOW-1);
   *   - the value at that hop is not an IP literal -> refuse rather than key on caller text.
   */
  private resolveSourceKey(req: Request, peer: string): string {
    if (this.trustedProxyHops === 0) {
      return this.mode === "proxied" ? PROXIED_SHARED_KEY : peer;
    }
    if (!ipInAnyCidr(peer, this.trustedProxies)) {
      throw adminError(
        "NODE_ADMIN_UNTRUSTED_PROXY",
        "node admin endpoints are configured for a trusted reverse proxy, but this request " +
          "did not arrive from one of NODE_ADMIN_TRUSTED_PROXY_CIDRS"
      );
    }
    const forwarded = (req.header?.(HEADER_FORWARDED_FOR) ?? "")
      .split(",")
      .map(entry => entry.trim())
      .filter(entry => entry.length > 0);
    const index = forwarded.length - this.trustedProxyHops;
    const client = index >= 0 ? forwarded[index] : undefined;
    if (!client || !parseIp(client)) {
      throw adminError(
        "NODE_ADMIN_FORWARDED_INVALID",
        `${HEADER_FORWARDED_FOR} does not carry a client address at the configured hop ` +
          `(NODE_ADMIN_TRUSTED_PROXY_HOPS=${this.trustedProxyHops}); the trusted proxy must ` +
          "strip or overwrite any client-supplied value and append exactly one entry"
      );
    }
    return client;
  }
}

/**
 * The route-level shell. It holds NO state: everything lives in the single application-wide
 * `NodeAdminPolicy`, because Nest builds one guard instance per module that uses it and the
 * throttle ledgers must be shared across `/node`, `/dashboard` and `/gossip` (round-6
 * MEDIUM-2).
 */
@Injectable()
export class NodeAdminGuard implements CanActivate {
  constructor(private readonly policy: NodeAdminPolicy) {}

  canActivate(context: ExecutionContext): boolean {
    return this.policy.authorize(context.switchToHttp().getRequest<Request>());
  }
}

/** Reserved bucket keys. The leading space cannot collide with any parsed IP literal. */
const ANON_GLOBAL_KEY = " global";
const PROXIED_SHARED_KEY = " proxied";

/**
 * Hard capacity of a per-key ledger, so the memory a flood can pin is a constant (round-6
 * MEDIUM-3). Reaching it reclaims keys whose window has fully passed; if they are all still
 * live the ledger DENIES the new key rather than forgetting a live budget. Reaching it at all
 * is already hard: the global anonymous budget is charged first and short-circuits, so a
 * window can only create as many per-source keys as it has global budget (default 60) — an
 * order of magnitude below this.
 */
const MAX_TRACKED_KEYS = 1024;

/**
 * A per-key sliding-window request ledger. Kept as an object rather than a method so the
 * anonymous and authenticated budgets are physically separate storage — the round-5 MEDIUM-2
 * finding was that one shared map let unauthenticated traffic spend the operator's budget.
 *
 * Bookkeeping is O(1) amortised per request: timestamps are pruned only for the key being
 * touched, and capacity is enforced by reclaiming expired keys from the front of the Map (JS
 * Maps iterate in insertion order and every touched key is re-inserted, so the front is the
 * least recently touched, i.e. the first to expire — the scan stops at the first live entry).
 * The previous version swept the WHOLE table on every insert past 10k keys, which is how 25k
 * forged bucket keys turned into a 3.4x per-request slowdown.
 */
class RollingWindow {
  private readonly hits = new Map<string, number[]>();

  constructor(
    readonly windowMs: number,
    readonly max: number,
    readonly capacity: number = MAX_TRACKED_KEYS
  ) {}

  /** Record an attempt. Returns false when the budget for `key` is already spent. */
  tryConsume(key: string, now: number): boolean {
    const existing = this.hits.get(key);
    if (!existing) {
      this.reclaimExpired(now);
      // A table full of LIVE budgets denies the new key rather than forgetting an old one:
      // eviction of a live entry would hand a source a second budget, which is exactly what
      // this ledger exists to prevent. Denying is fail-closed and cannot reach the operator,
      // whose ledger is separate storage.
      if (this.hits.size >= this.capacity) return false;
    }

    const recent = existing ? existing.filter(t => now - t < this.windowMs) : [];
    const admitted = recent.length < this.max;
    if (admitted) recent.push(now);

    // Re-insert so this key becomes the most recently used — including when it is OVER budget,
    // so an actively rejected key is the last candidate for reclamation.
    this.hits.delete(key);
    this.hits.set(key, recent);
    return admitted;
  }

  /**
   * Drop keys whose whole window has passed. Map iteration is insertion order and every touch
   * re-inserts, so the front is the least recently touched — i.e. the first to expire, so this
   * stops at the first live entry instead of scanning the table. Each deletion pairs with an
   * earlier insertion, making the cost O(1) amortised per request no matter how many distinct
   * keys a flood presents.
   */
  private reclaimExpired(now: number): void {
    while (this.hits.size >= this.capacity) {
      const front = this.hits.entries().next();
      if (front.done) return;
      const [key, timestamps] = front.value;
      if (timestamps.some(t => now - t < this.windowMs)) return;
      this.hits.delete(key);
    }
  }

  /** Number of keys currently tracked — for the capacity regression tests. */
  get size(): number {
    return this.hits.size;
  }
}

function sha256(value: string): Buffer {
  return createHash("sha256").update(value, "utf8").digest();
}

/**
 * The network mode is DECLARED. An unrecognised value is a boot failure, and so is a missing
 * one whenever the endpoints are enabled (round-6 MEDIUM-1): "unset" used to mean `direct`,
 * i.e. the node printing "loopback callers only" on behalf of an operator who never declared
 * a topology — which is false, and unwarned, on the cloudflared deployment this repo
 * documents. While the endpoints are DISABLED there is nothing to declare and nothing to
 * reach, so the value stays optional there (dvt1/2/3 are unaffected).
 */
function requireMode(value: string | undefined, enabled: boolean): NodeAdminNetworkMode {
  const declared = (value ?? "").trim();
  if (!declared) {
    if (!enabled) return "direct";
    throw new Error(
      `NODE_ADMIN_NETWORK_MODE must be declared (${NODE_ADMIN_NETWORK_MODES.join(" | ")}) ` +
        "whenever NODE_ADMIN_ENABLED=true — the node will not assume it is unproxied on your " +
        "behalf. Use `direct` if the listener itself is the network boundary, or `proxied` if " +
        "a reverse proxy / tunnel (e.g. cloudflared) fronts it, in which case every request " +
        "arrives from loopback and the admin token is the only network barrier"
    );
  }
  if ((NODE_ADMIN_NETWORK_MODES as readonly string[]).includes(declared)) {
    return declared as NodeAdminNetworkMode;
  }
  throw new Error(
    `NODE_ADMIN_NETWORK_MODE must be one of ${NODE_ADMIN_NETWORK_MODES.join(" | ")} ` +
      `(got "${declared}")`
  );
}

/**
 * Trusted-proxy topology. Reading `X-Forwarded-For` at all requires BOTH the proxy CIDRs and
 * an exact hop count, and only in `proxied` mode — a half-configured topology refuses to boot
 * instead of silently keying every caller on a header they control.
 */
function requireTrustedProxies(
  config: ConfigService,
  mode: NodeAdminNetworkMode
): { ranges: readonly CidrRange[]; hops: number } {
  const raw = config.get<string[]>("nodeAdminTrustedProxyCidrs") ?? [];
  const hops = requireBound(config, "nodeAdminTrustedProxyHops", 0, 0);
  if (raw.length === 0 && hops === 0) return { ranges: [], hops: 0 };

  if (mode !== "proxied") {
    throw new Error(
      "NODE_ADMIN_TRUSTED_PROXY_CIDRS/NODE_ADMIN_TRUSTED_PROXY_HOPS require " +
        "NODE_ADMIN_NETWORK_MODE=proxied — in direct mode there is no proxy to trust"
    );
  }
  if (raw.length === 0 || hops === 0) {
    throw new Error(
      "NODE_ADMIN_TRUSTED_PROXY_CIDRS and NODE_ADMIN_TRUSTED_PROXY_HOPS must be set TOGETHER " +
        "— naming proxies without a hop count (or vice versa) would mean keying rate limits " +
        "on a caller-controlled header"
    );
  }
  const ranges = raw.map(entry => {
    const range = parseCidr(entry);
    if (!range) {
      throw new Error(`NODE_ADMIN_TRUSTED_PROXY_CIDRS entry "${entry}" is not a valid IP/CIDR`);
    }
    // An IPv6 range that covers the IPv4-mapped block (`::ffff:0:0/96`, `::/0`, …) would parse
    // and boot, and then reject EVERY request: a dual-stack listener hands back
    // `::ffff:127.0.0.1`, which normalises to the 4-byte IPv4 form and can never be a member
    // of a 16-byte range. Fail at boot with the fix, rather than at every request with
    // `403 NODE_ADMIN_UNTRUSTED_PROXY` and no explanation (round-6 LOW-3).
    if (intersectsIpv4Mapped(range)) {
      throw new Error(
        `NODE_ADMIN_TRUSTED_PROXY_CIDRS entry "${entry}" is an IPv6 range covering ` +
          "IPv4-mapped addresses (::ffff:0:0/96). IPv4-mapped peers are normalised to their " +
          "IPv4 form, so such a range matches nothing and every request would be rejected — " +
          "declare the IPv4 CIDR instead (e.g. 127.0.0.0/8)"
      );
    }
    return range;
  });
  return { ranges, hops };
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
