import {
  CanActivate,
  ExecutionContext,
  Injectable,
  HttpException,
  HttpStatus,
  Logger,
} from "@nestjs/common";
import { ConfigService } from "@nestjs/config";

/**
 * Per-IP sliding-window rate limiter (#50 hardening ⑦).
 *
 * Guards the signature endpoints, which — even before the Stage-1 owner-auth gate
 * rejects an unauthorized caller — make on-chain RPC reads (EntryPoint.getUserOpHash,
 * account.owner()). An unauthenticated flood would therefore amplify into on-chain RPC
 * load. This caps requests per source IP so that pre-auth abuse is bounded.
 *
 * Opt-in via RATE_LIMIT_ENABLED (default off → no limiting, behavior unchanged).
 * In-memory + per-process (good enough for a single node; a multi-node deployment
 * fronts nodes with its own edge limiter). Rejects over-limit with HTTP 429.
 */
@Injectable()
export class ThrottleGuard implements CanActivate {
  private readonly logger = new Logger(ThrottleGuard.name);
  private readonly enabled: boolean;
  private readonly windowMs: number;
  private readonly max: number;
  /** ip -> request timestamps within the current window. */
  private readonly hits = new Map<string, number[]>();

  constructor(configService: ConfigService) {
    this.enabled = configService.get<boolean>("rateLimitEnabled") === true;
    this.windowMs = configService.get<number>("rateLimitWindowMs") ?? 60_000;
    this.max = configService.get<number>("rateLimitMax") ?? 30;
    if (this.enabled) {
      this.logger.log(`Rate limit ENABLED — ${this.max} req / ${this.windowMs}ms per IP`);
    }
  }

  canActivate(context: ExecutionContext): boolean {
    if (!this.enabled) return true;

    const req = context.switchToHttp().getRequest();
    const ip: string = req?.ip || req?.socket?.remoteAddress || "unknown";
    const now = Date.now();

    const recent = (this.hits.get(ip) ?? []).filter(t => now - t < this.windowMs);
    if (recent.length >= this.max) {
      this.logger.warn(`Rate limit exceeded for ${ip} (${recent.length}/${this.max})`);
      throw new HttpException("Too many requests", HttpStatus.TOO_MANY_REQUESTS);
    }
    recent.push(now);
    this.hits.set(ip, recent);

    // Opportunistic cleanup so the map doesn't grow unbounded across idle IPs.
    if (this.hits.size > 10_000) {
      for (const [k, ts] of this.hits) {
        if (ts.every(t => now - t >= this.windowMs)) this.hits.delete(k);
      }
    }
    return true;
  }
}
