import {
  CanActivate,
  ExecutionContext,
  HttpException,
  HttpStatus,
  Injectable,
} from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { createHmac, timingSafeEqual } from "crypto";
import type { Request } from "express";

/** Header carrying the client's millisecond unix timestamp. */
export const HEADER_TIMESTAMP = "X-X402-Timestamp";
/** Header carrying hex HMAC-SHA256(secret, `${timestamp}.${rawBody}`). */
export const HEADER_AUTH = "X-X402-Auth";

/**
 * Optional stateless HMAC request-auth guard for the x402 facilitator (#130).
 *
 * Designed to map 1:1 onto the SDK's `FacilitatorConfig.createAuthHeaders()` — it
 * returns per-endpoint header maps with no prior round-trip, so the auth must be
 * computable from the request alone. (This replaces the earlier challenge-response
 * HMAC: that needed a server-issued `X-Challenge` first, which `createAuthHeaders`
 * can't obtain. Settle replay is already neutralised on-chain — the X402Facilitator
 * nonce is single-use — so a TTL-bounded stateless HMAC is sufficient and simpler.)
 *
 * Scheme (applied to /x402/settle; verify + supported stay open):
 *   X-X402-Timestamp: <unix epoch ms>
 *   X-X402-Auth:      hex HMAC-SHA256(secret, `${timestamp}.${rawBody}`)
 * The server recomputes over the RAW request bytes (main.ts sets `rawBody: true`)
 * and accepts iff |now - timestamp| <= TTL and the HMAC matches (constant-time).
 *
 * Opt-in via X402_AUTH_ENABLED=true + X402_AUTH_SECRET. When disabled (default) the
 * guard is a no-op and settle behaves unchanged.
 */
@Injectable()
export class X402AuthGuard implements CanActivate {
  private readonly enabled: boolean;
  private readonly secret: string;
  private readonly ttlMs: number;
  private readonly now: () => number;

  constructor(config: ConfigService, now?: () => number) {
    this.enabled = config.get<boolean>("x402AuthEnabled") === true;
    this.secret = config.get<string>("x402AuthSecret") ?? "";
    this.ttlMs = config.get<number>("x402AuthTtlMs") ?? 300_000;
    this.now = now ?? (() => Date.now());
  }

  canActivate(context: ExecutionContext): boolean {
    if (!this.enabled) return true;
    if (!this.secret) {
      throw new HttpException(
        { success: false, errorReason: "x402 auth enabled but server secret unset" },
        HttpStatus.SERVICE_UNAVAILABLE
      );
    }

    const req = context.switchToHttp().getRequest<Request & { rawBody?: Buffer }>();
    const ts = req.header(HEADER_TIMESTAMP);
    const auth = req.header(HEADER_AUTH);
    if (!ts || !auth) {
      throw new HttpException(
        { success: false, errorReason: `missing ${HEADER_TIMESTAMP}/${HEADER_AUTH} headers` },
        HttpStatus.UNAUTHORIZED
      );
    }

    const tsNum = Number(ts);
    if (!Number.isFinite(tsNum) || Math.abs(this.now() - tsNum) > this.ttlMs) {
      throw new HttpException(
        { success: false, errorReason: "auth timestamp outside the allowed window" },
        HttpStatus.UNAUTHORIZED
      );
    }

    const rawBody = req.rawBody?.toString("utf8") ?? JSON.stringify(req.body ?? {});
    const expected = createHmac("sha256", this.secret).update(`${ts}.${rawBody}`).digest("hex");
    if (!safeEqualHex(expected, auth)) {
      throw new HttpException(
        { success: false, errorReason: "HMAC verification failed" },
        HttpStatus.FORBIDDEN
      );
    }
    return true;
  }

  /**
   * Reference header computation — the exact bytes the SDK's `createAuthHeaders`
   * must produce for a given request body. Exposed for conformance tests.
   */
  static computeHeaders(
    secret: string,
    timestampMs: number,
    rawBody: string
  ): Record<string, string> {
    const ts = String(timestampMs);
    return {
      [HEADER_TIMESTAMP]: ts,
      [HEADER_AUTH]: createHmac("sha256", secret).update(`${ts}.${rawBody}`).digest("hex"),
    };
  }
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
