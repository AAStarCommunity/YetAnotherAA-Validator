import { Injectable, Logger, Optional } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { CapabilityRegistry } from "../capability/capability-registry.service.js";

export type OpsAlertLevel = "info" | "warn" | "critical";

/** The JSON payload pushed to aastar-monitor. Stable contract — align the bot to this. */
export interface OpsAlertPayload {
  node: string; // which DVT node raised it (OPS_ALERT_NODE, defaults to hostname-ish)
  level: OpsAlertLevel;
  message: string;
  timestamp: string; // ISO-8601
}

/**
 * Operational alerting for the OPERATOR (issue #100 / #50 ⑦) — distinct from the
 * end-user NotificationService (large-spend alerts to account owners). This pushes
 * node-health / hot-wallet-balance / submit-failure alerts to the aastar-monitor
 * Telegram bot via its webhook.
 *
 * Hard rule (same as NotificationService): delivery is **fire-and-forget and never
 * throws / never blocks** — a monitoring outage must never affect signing or relaying.
 *
 * Opt-in via OPS_ALERT_ENABLED + AASTAR_MONITOR_URL. A bearer token
 * (AASTAR_MONITOR_TOKEN) authenticates the push if the bot requires one.
 */
@Injectable()
export class OpsAlertService {
  private readonly logger = new Logger(OpsAlertService.name);
  private readonly enabled: boolean;
  private readonly url?: string;
  private readonly token?: string;
  private readonly node: string;

  constructor(
    @Optional() configService?: ConfigService,
    @Optional() capabilityRegistry?: CapabilityRegistry
  ) {
    this.url = configService?.get<string>("opsAlertUrl");
    this.token = configService?.get<string>("opsAlertToken");
    this.node = configService?.get<string>("opsAlertNode") || "dvt";
    // Enabled only when explicitly turned on AND a destination URL is set — otherwise
    // it's a no-op, so wiring alerts into services costs nothing until configured.
    this.enabled = configService?.get<boolean>("opsAlertEnabled") === true && !!this.url;

    capabilityRegistry?.register({
      name: "ops-alert",
      class: "infra-app",
      description: "Operator alerts pushed to aastar-monitor (#100)",
      enabled: this.enabled,
    });

    if (this.enabled) {
      this.logger.log(`Ops alerts ENABLED — node=${this.node}, → ${this.url}`);
    }
  }

  /**
   * Fire an operator alert. Returns immediately; the POST runs in the background and
   * any failure is swallowed (never affects the caller's path). No-op when disabled.
   */
  alert(level: OpsAlertLevel, message: string): void {
    if (!this.enabled || !this.url) return;
    const payload: OpsAlertPayload = {
      node: this.node,
      level,
      message,
      // Injected clock would be needed for deterministic tests; `send` is what tests spy on.
      timestamp: new Date().toISOString(),
    };
    // Detach: never await, never throw into the caller.
    void this.send(payload).catch(e =>
      this.logger.warn(`ops-alert delivery failed (ignored): ${e?.message ?? e}`)
    );
  }

  /** POST the alert to aastar-monitor. Isolated + awaitable so it can be unit-tested. */
  async send(payload: OpsAlertPayload): Promise<void> {
    if (!this.url) return;
    const headers: Record<string, string> = { "content-type": "application/json" };
    if (this.token) headers.authorization = `Bearer ${this.token}`;
    const r = await fetch(this.url, {
      method: "POST",
      headers,
      body: JSON.stringify(payload),
    });
    if (!r.ok) throw new Error(`aastar-monitor HTTP ${r.status}`);
  }
}
