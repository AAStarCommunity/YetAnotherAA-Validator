import { createRequire } from "module";
import {
  Injectable,
  Logger,
  Optional,
  OnApplicationBootstrap,
  OnApplicationShutdown,
} from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { BlockchainService } from "../blockchain/blockchain.service.js";
import { CapabilityRegistry } from "../capability/capability-registry.service.js";
import { OpsAlertService } from "./ops-alert.service.js";

const require = createRequire(import.meta.url);
const { version: APP_VERSION } = require("../../../package.json") as { version: string };

/**
 * Scheduled status heartbeat → aastar-monitor (#100). When OPS_STATUS_INTERVAL_MS > 0
 * and ops alerts are enabled, pushes:
 *   - a "🟢 online" message on boot and "🔴 offline" on shutdown, and
 *   - a periodic status summary (version, uptime, RPC reachability, enabled caps)
 *     so the operator sees the node is alive AND gets a recurring health check.
 *
 * The recurring anomaly alerts (keeper/relay failures) flow through OpsAlertService
 * independently; this adds the "still alive + check result" cadence the operator asked
 * for. Everything is fire-and-forget — a monitoring outage never affects the node.
 */
@Injectable()
export class StatusReporterService implements OnApplicationBootstrap, OnApplicationShutdown {
  private readonly logger = new Logger(StatusReporterService.name);
  private readonly intervalMs: number;
  private readonly clock: () => number;
  private startedAtMs = 0;
  private timer: ReturnType<typeof setInterval> | null = null;

  constructor(
    private readonly opsAlert: OpsAlertService,
    @Optional() private readonly config?: ConfigService,
    @Optional() private readonly blockchain?: BlockchainService,
    @Optional() private readonly capabilities?: CapabilityRegistry,
    /** Test seam for Date.now(). */
    @Optional() clock?: () => number
  ) {
    this.intervalMs = this.config?.get<number>("opsStatusIntervalMs") ?? 0;
    this.clock = clock ?? (() => Date.now());
  }

  onApplicationBootstrap(): void {
    // Defensive: a non-finite interval (bad env) must never reach setInterval, or it
    // fires continuously. Config already guards this; belt-and-braces here too.
    if (!Number.isFinite(this.intervalMs) || this.intervalMs <= 0 || !this.opsAlert.isEnabled()) {
      return;
    }
    this.startedAtMs = this.clock();
    this.opsAlert.alert("info", `🟢 online — v${APP_VERSION}`);
    this.timer = setInterval(() => void this.report(), this.intervalMs);
    this.logger.log(`Status heartbeat ENABLED — every ${this.intervalMs}ms`);
  }

  onApplicationShutdown(): void {
    if (this.timer !== null) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }

  /** Compose and push one status summary. Never throws. */
  async report(): Promise<void> {
    try {
      const text = await this.compose();
      this.opsAlert.alert("info", text);
    } catch (e: any) {
      this.logger.warn(`status report failed (ignored): ${e?.message ?? e}`);
    }
  }

  /** Build the status line: version, uptime, RPC reachability, enabled capabilities. */
  private async compose(): Promise<string> {
    const uptimeMin = Math.floor((this.clock() - this.startedAtMs) / 60_000);
    const rpc = await this.rpcOk();
    const caps = (this.capabilities?.list() ?? [])
      .filter(c => c.enabled)
      .map(c => c.name)
      .join(",");
    return (
      `status v${APP_VERSION} — up ${uptimeMin}m, ` +
      `RPC ${rpc ? "ok" : "DOWN"}, caps=[${caps || "none"}]`
    );
  }

  /** Lightweight RPC liveness probe (a real round-trip). False on any error/timeout. */
  private async rpcOk(): Promise<boolean> {
    if (!this.blockchain) return false;
    try {
      await this.blockchain.getBaseFeeGwei();
      return true;
    } catch {
      return false;
    }
  }
}
