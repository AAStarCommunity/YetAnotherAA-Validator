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
  private readonly node: string;
  // Transport A: native Telegram bot (aastar-monitor). Takes priority when configured.
  private readonly tgToken?: string;
  private readonly tgChatId?: string;
  // Transport B: generic webhook (an aggregator/relay in front of delivery).
  private readonly url?: string;
  private readonly token?: string;

  constructor(
    @Optional() configService?: ConfigService,
    @Optional() capabilityRegistry?: CapabilityRegistry
  ) {
    this.node = configService?.get<string>("opsAlertNode") || "dvt";
    this.tgToken = configService?.get<string>("opsAlertBotToken");
    this.tgChatId = configService?.get<string>("opsAlertChatId");
    this.url = configService?.get<string>("opsAlertUrl");
    this.token = configService?.get<string>("opsAlertToken");
    // Enabled only when turned on AND a transport is fully configured (Telegram OR
    // webhook) — otherwise it's a no-op, so wiring alerts in costs nothing until set.
    const hasTelegram = !!this.tgToken && !!this.tgChatId;
    const hasWebhook = !!this.url;
    this.enabled =
      configService?.get<boolean>("opsAlertEnabled") === true && (hasTelegram || hasWebhook);

    capabilityRegistry?.register({
      name: "ops-alert",
      class: "infra-app",
      description: "Operator alerts to aastar-monitor Telegram bot (#100)",
      enabled: this.enabled,
    });

    if (this.enabled) {
      this.logger.log(
        `Ops alerts ENABLED — node=${this.node}, transport=${hasTelegram ? "telegram" : "webhook"}`
      );
    }
  }

  /** Whether alerting is active (used by the scheduled status reporter). */
  isEnabled(): boolean {
    return this.enabled;
  }

  /**
   * Fire an operator alert. Returns immediately; delivery runs in the background and
   * any failure is swallowed (never affects the caller's path). No-op when disabled.
   */
  alert(level: OpsAlertLevel, message: string): void {
    if (!this.enabled) return;
    const payload: OpsAlertPayload = {
      node: this.node,
      level,
      message,
      timestamp: new Date().toISOString(),
    };
    // Detach: never await, never throw into the caller.
    void this.send(payload).catch(e =>
      this.logger.warn(`ops-alert delivery failed (ignored): ${e?.message ?? e}`)
    );
  }

  /** Deliver the alert. Isolated + awaitable so it can be unit-tested. */
  async send(payload: OpsAlertPayload): Promise<void> {
    if (this.tgToken && this.tgChatId) {
      return this.sendTelegram(payload);
    }
    if (this.url) {
      return this.sendWebhook(payload);
    }
  }

  /** Native Telegram Bot API sendMessage → the aastar-monitor bot's chat. */
  private async sendTelegram(payload: OpsAlertPayload): Promise<void> {
    const icon = payload.level === "critical" ? "🔴" : payload.level === "warn" ? "🟠" : "🟢";
    const text = `${icon} [${payload.node}] ${payload.message}`;
    const r = await fetch(`https://api.telegram.org/bot${this.tgToken}/sendMessage`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ chat_id: this.tgChatId, text }),
    });
    if (!r.ok) throw new Error(`telegram HTTP ${r.status}`);
  }

  /** Generic webhook POST (aggregator in front of delivery). */
  private async sendWebhook(payload: OpsAlertPayload): Promise<void> {
    const headers: Record<string, string> = { "content-type": "application/json" };
    if (this.token) headers.authorization = `Bearer ${this.token}`;
    const r = await fetch(this.url!, {
      method: "POST",
      headers,
      body: JSON.stringify(payload),
    });
    if (!r.ok) throw new Error(`aastar-monitor HTTP ${r.status}`);
  }
}
