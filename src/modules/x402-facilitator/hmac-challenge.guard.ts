import {
  CanActivate,
  ExecutionContext,
  HttpException,
  HttpStatus,
  Injectable,
  Logger,
} from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { createHmac, timingSafeEqual } from "crypto";
import type { Request, Response } from "express";

const CHALLENGE_TTL_MS = 300_000; // 5 minutes

/**
 * Optional stateless HMAC challenge-response guard for POST /x402/settle (#130),
 * ported from the reference node's `middleware/hmac-challenge.ts`. Recommended for
 * PUBLIC facilitator nodes to blunt replay/bot spam on the gas-spending settle path;
 * it is NOT a security gate (the on-chain X402Facilitator authorization is
 * authoritative). Opt-in via ENABLE_HMAC_CHALLENGE=true + HMAC_SECRET.
 *
 * Handshake (matches the reference flow):
 *  1. Client calls /settle with no HMAC headers → 402 carrying `X-Challenge`
 *     (`<ts>:hmac(secret, "challenge:<ts>")`, self-verifying, no server state).
 *  2. Client recomputes `X-Payment-HMAC = hmac(challenge, rawBody)` and replays
 *     with both `X-Challenge` and `X-Payment-HMAC`.
 * The HMAC covers the RAW request bytes, so main.ts enables `rawBody: true`.
 *
 * When disabled (default) the guard is a no-op and settle behaves unchanged.
 */
@Injectable()
export class HmacChallengeGuard implements CanActivate {
  private readonly logger = new Logger(HmacChallengeGuard.name);
  private readonly enabled: boolean;
  private readonly secret: string;
  private readonly now: () => number;

  constructor(config: ConfigService, now?: () => number) {
    this.enabled = config.get<boolean>("x402HmacEnabled") === true;
    this.secret = config.get<string>("x402HmacSecret") ?? "";
    this.now = now ?? (() => Date.now());
    if (this.enabled && !this.secret) {
      this.logger.warn(
        "x402: ENABLE_HMAC_CHALLENGE=true but HMAC_SECRET is empty — settle requests will be rejected"
      );
    }
  }

  canActivate(context: ExecutionContext): boolean {
    if (!this.enabled) return true;

    const http = context.switchToHttp();
    const req = http.getRequest<Request & { rawBody?: Buffer }>();
    if (!this.secret) {
      throw new HttpException(
        { success: false, errorReason: "HMAC challenge enabled but server secret unset" },
        HttpStatus.SERVICE_UNAVAILABLE
      );
    }

    const challenge = req.header("X-Challenge");
    const clientHmac = req.header("X-Payment-HMAC");

    // First contact: issue a challenge so the client can authenticate its retry.
    if (!challenge || !clientHmac) {
      const res = http.getResponse<Response>();
      res.setHeader("X-Challenge", this.generateChallenge());
      throw new HttpException(
        { success: false, errorReason: "Payment challenge required (see X-Challenge header)" },
        HttpStatus.PAYMENT_REQUIRED
      );
    }

    if (!this.verifyChallenge(challenge)) {
      throw new HttpException(
        { success: false, errorReason: "Invalid or expired challenge" },
        HttpStatus.BAD_REQUEST
      );
    }

    const rawBody = req.rawBody?.toString("utf8") ?? JSON.stringify(req.body ?? {});
    if (!this.verifyHmac(challenge, rawBody, clientHmac)) {
      throw new HttpException(
        { success: false, errorReason: "HMAC verification failed" },
        HttpStatus.FORBIDDEN
      );
    }
    return true;
  }

  /** Generate a stateless challenge token: `<ts>:hmac(secret, "challenge:<ts>")`. */
  generateChallenge(): string {
    const ts = this.now().toString();
    return `${ts}:${createHmac("sha256", this.secret).update(`challenge:${ts}`).digest("hex")}`;
  }

  private verifyChallenge(challenge: string): boolean {
    const parts = challenge.split(":");
    if (parts.length !== 2) return false;
    const [ts, mac] = parts;
    const tsNum = Number(ts);
    if (!Number.isFinite(tsNum) || this.now() - tsNum > CHALLENGE_TTL_MS) return false;
    const expected = createHmac("sha256", this.secret).update(`challenge:${ts}`).digest("hex");
    return safeEqualHex(expected, mac);
  }

  /** Client computes HMAC(challenge, rawBody); the challenge string is the HMAC key. */
  private verifyHmac(challenge: string, body: string, clientHmac: string): boolean {
    const expected = createHmac("sha256", challenge).update(body).digest("hex");
    return safeEqualHex(expected, clientHmac);
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
