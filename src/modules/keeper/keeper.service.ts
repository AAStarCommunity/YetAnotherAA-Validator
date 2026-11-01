import {
  Injectable,
  Logger,
  Optional,
  OnApplicationBootstrap,
  OnApplicationShutdown,
} from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { BlockchainService } from "../blockchain/blockchain.service.js";
import { NotificationService } from "../notification/notification.service.js";
import { CapabilityRegistry } from "../capability/capability-registry.service.js";
import { OpsAlertService } from "../ops-alert/ops-alert.service.js";

/**
 * Price Keeper Phase 1 (#58) — keeps SuperPaymaster cachedPrice permanently fresh.
 *
 * Opt-in (KEEPER_ENABLED, default off). When enabled, runs a periodic check:
 * if the cached price is approaching its staleness threshold AND Chainlink has a
 * fresh reading, calls updatePrice() on-chain to refresh it. Without this keeper,
 * the node operator would have to manually trigger updates or wait for a user
 * transaction to refresh the price.
 *
 * Guardrails (all configurable via env):
 *   - KEEPER_REFRESH_BUFFER_S: trigger update when ≤N seconds before stale (default 300)
 *   - KEEPER_MAX_UPDATES_PER_DAY: daily cap, resets at UTC midnight (default 48)
 *   - KEEPER_MAX_BASE_FEE_GWEI: skip if network baseFee too high (default 50 gwei)
 *
 * Multi-node redundancy (3-5 keepers per chain for failover): each keeper is
 * idempotent — it checks the on-chain price first and skips if still fresh, so
 * once any keeper updates, the rest see a fresh price and skip. To stop several
 * keepers that boot together from hitting the same staleness window in the same
 * tick and firing duplicate updatePrice() txs, the first tick is phase-jittered
 * across [0, intervalMs). A coordination registry / lease is deferred until the
 * duplicate-tx rate actually warrants it.
 *
 * Phase 2 adds CEX price failover when Chainlink is stale/unresponsive.
 */
@Injectable()
export class KeeperService implements OnApplicationBootstrap, OnApplicationShutdown {
  private readonly logger = new Logger(KeeperService.name);
  private readonly enabled: boolean;
  private readonly intervalMs: number;
  private readonly refreshBufferS: bigint;
  private readonly maxUpdatesPerDay: number;
  private readonly maxBaseFeeGwei: bigint;
  /** One or more paymasters to keep fresh (KEEPER_PAYMASTER_ADDRESS, comma-separated). */
  private readonly paymasterAddresses: string[];
  private readonly chainlinkFeed: string;
  private readonly clock: () => number;
  private readonly random: () => number;

  private startupTimer: ReturnType<typeof setTimeout> | null = null;
  private timer: ReturnType<typeof setInterval> | null = null;
  private updatesToday = 0;
  private lastDayNumber = 0;

  constructor(
    private readonly blockchainService: BlockchainService,
    private readonly notificationService: NotificationService,
    private readonly config: ConfigService,
    /** Test seam: controls `Date.now()` so time-based logic is deterministic. */
    @Optional() clock?: () => number,
    @Optional() capabilityRegistry?: CapabilityRegistry,
    /** Test seam: controls the startup phase jitter (default Math.random). */
    @Optional() random?: () => number,
    /** Operator alerting → aastar-monitor (#100). Optional; no-op when unconfigured. */
    @Optional() private readonly opsAlert?: OpsAlertService
  ) {
    this.enabled = config.get<boolean>("keeperEnabled") === true;
    this.intervalMs = config.get<number>("keeperIntervalMs") ?? 60_000;
    this.refreshBufferS = BigInt(config.get<string>("keeperRefreshBufferS") ?? "300");
    this.maxUpdatesPerDay = config.get<number>("keeperMaxUpdatesPerDay") ?? 48;
    this.maxBaseFeeGwei = BigInt(config.get<string>("keeperMaxBaseFeeGwei") ?? "50");
    this.paymasterAddresses = (config.get<string>("keeperPaymasterAddress") ?? "")
      .split(",")
      .map(s => s.trim())
      .filter(s => s.length > 0);
    this.chainlinkFeed = config.get<string>("keeperChainlinkFeed") ?? "";
    this.clock = clock ?? (() => Date.now());
    this.random = random ?? (() => Math.random());

    capabilityRegistry?.register({
      name: "keeper",
      class: "infra-app",
      description:
        "Chainlink price keeper — keeps SuperPaymaster / PaymasterV4 cachedPrice fresh (#58)",
      enabled: this.enabled,
    });
  }

  onApplicationBootstrap(): void {
    if (!this.enabled) return;
    if (this.paymasterAddresses.length === 0) {
      this.logger.warn(
        "Keeper: KEEPER_ENABLED=true but KEEPER_PAYMASTER_ADDRESS not set — disabled"
      );
      return;
    }
    try {
      this.checkAlertConfigured();
    } catch {
      // Structural boundary, not a point-fix: whatever escapes checkAlertConfigured()
      // (a throwing logger, a throwing diagnostic, anything) is swallowed HERE so it
      // is structurally impossible for the self-check to abort scheduling below.
      // Intentionally do NOT log here — logging is exactly the kind of thing that
      // may have thrown; a nested catch just moves the same question one level down.
    }
    this.lastDayNumber = this.todayNumber();
    // Phase-jitter the first tick across [0, intervalMs) so redundant keepers
    // that boot together don't all fire updatePrice() in the same window.
    const jitterMs = this.computeJitterMs();
    this.startupTimer = setTimeout(() => {
      this.startupTimer = null;
      void this.tick().catch(e => this.logger.error(`Keeper tick error: ${String(e)}`));
      this.timer = setInterval(
        () => void this.tick().catch(e => this.logger.error(`Keeper tick error: ${String(e)}`)),
        this.intervalMs
      );
    }, jitterMs);
    this.logger.log(
      `Price Keeper ENABLED — interval=${this.intervalMs}ms jitter=${jitterMs}ms ` +
        `paymasters=[${this.paymasterAddresses.join(", ")}] buffer=${this.refreshBufferS}s ` +
        `cap=${this.maxUpdatesPerDay}/day maxBaseFee=${this.maxBaseFeeGwei}gwei`
    );
  }

  onApplicationShutdown(): void {
    if (this.startupTimer !== null) {
      clearTimeout(this.startupTimer);
      this.startupTimer = null;
    }
    if (this.timer !== null) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }

  /**
   * Startup self-check (real incident driven — a neighboring repo's price keeper
   * failed silently for 3.5 weeks: process alive, every tick failing, zero alerts,
   * because its alert channel was also broken and nobody knew).
   *
   * The keeper's own failure path (`refreshOne` below) only ever *tries* to raise
   * an operator alert via `this.opsAlert?.alert(...)` — that call is a silent
   * no-op whenever OpsAlertService is disabled/unconfigured, or isn't injected at
   * all. Loudly surface that combination once at startup so it isn't discovered
   * only after an updatePrice() failure goes unnoticed on that path. This
   * intentionally does NOT stop the keeper: halting on an alerting gap would
   * guarantee the exact harm (a stale price) that this keeper exists to prevent —
   * the safe response is to keep working and say so loudly, not to stop.
   *
   * Scope, precisely — two axes:
   *  - This is ONLY about the operator-alert path (`OpsAlertService`), i.e.
   *    whether an *operator* gets paged. It says nothing about
   *    `notificationService.sendToAccount(...)` in `refreshOne`'s catch block —
   *    that end-user notification path is separate and unaffected by this check.
   *  - This checks CONFIGURATION, not deliverability.
   *    `OpsAlertService.isEnabled()` — the single place that already encodes
   *    "opt-in flag AND a transport is actually configured" (see
   *    ops-alert.service.ts) — only tells us a transport was *set up*. It does
   *    not probe that transport, so a configured-but-broken transport (e.g. a
   *    revoked Telegram bot token — `Unauthorized` on every send) still reports
   *    `isEnabled() === true` and this check stays silent. That is in fact the
   *    shape of the neighboring incident this is modeled on: the token was
   *    configured, just dead. This check only catches the "never configured at
   *    all" class (this repo's `deploy/*.env.example` templates ship with no
   *    `OPS_ALERT_*` entries set, matching that state). Catching a
   *    configured-but-dead transport requires an actual delivery drill before
   *    relying on it, not a config read.
   *
   * Robustness: the probe itself must never throw into the caller — this method
   * runs before the timers are armed (see onApplicationBootstrap above), so an
   * uncaught throw here would abort scheduling entirely, which is precisely the
   * "block keeper operation" outcome the hard constraint forbids. A malformed
   * `opsAlert` (missing `isEnabled`, or one that throws/returns something odd) is
   * therefore treated the same as "not configured", never allowed to propagate.
   * Only the literal boolean `true` counts as "configured" — `isEnabled()` is
   * documented as synchronous and boolean-returning, so anything else (undefined,
   * a non-boolean, a Promise from a misbehaving mock/partial implementation,
   * which is truthy under a loose check) is read as "not configured" rather than
   * silently accepted as "probably fine". A thenable result is additionally given
   * a no-op rejection handler (never awaited — this path must stay synchronous) so
   * a mock that returns a *rejected* promise can't surface as an unhandled
   * rejection later and crash the process (Node 15+ default behavior).
   *
   * This method's own try/catch only covers the probe + rejection-consumption; it
   * does NOT try to also guarantee the diagnostic logging below can't throw — that
   * would just push the same question into a nested catch. Instead the CALLER
   * (`onApplicationBootstrap`) wraps the whole `checkAlertConfigured()` call in a
   * boundary try/catch that swallows anything, unconditionally. That is the single
   * place the "never blocks scheduling" invariant is actually enforced.
   */
  private checkAlertConfigured(): void {
    let configured: boolean;
    try {
      // Declared type is `boolean`, but a misbehaving mock can violate that at
      // runtime (that's exactly the case this guards against) — widen to
      // `unknown` so the shape checks below are honest about what's possible.
      const result: unknown = this.opsAlert?.isEnabled();
      // Consume a rejection on a misbehaving async mock so it never becomes an
      // unhandled rejection down the line. Never `await` — this must stay sync.
      if (result != null && typeof (result as { then?: unknown }).then === "function") {
        (result as Promise<unknown>).then(undefined, () => {});
      }
      configured = result === true;
    } catch (e) {
      this.logger.error(
        "Keeper: could not determine whether an operator-alert path is configured " +
          `(the probe itself threw: ${String(e)}). Treating it as NOT configured — ` +
          "failing loud, not silent. This does not stop the keeper."
      );
      return;
    }
    if (configured) return;
    this.logger.error(
      "Keeper is ENABLED but there is no configured operator-alert path — a failed " +
        "updatePrice() will NOT raise an operator alert (this is exactly how a " +
        "stale-price outage goes unnoticed). This does not stop the keeper. Configure " +
        "alerting via OPS_ALERT_ENABLED=true plus a transport: OPS_ALERT_BOT_TOKEN + " +
        "OPS_ALERT_CHAT_ID (Telegram), or AASTAR_MONITOR_URL (+ optional " +
        "AASTAR_MONITOR_TOKEN) for a webhook. Note: configured is not the same as " +
        "deliverable — a dead token/webhook still passes this check; only a real " +
        "alert drill proves delivery actually works."
    );
  }

  /** Startup phase offset in [0, intervalMs). Visible for testing. */
  computeJitterMs(): number {
    return Math.floor(this.random() * this.intervalMs);
  }

  /**
   * One keeper cycle. Called on every interval tick. Returns without throwing;
   * errors are logged and (if notify configured) delivered out-of-band.
   */
  async tick(): Promise<void> {
    // Reset daily counter at UTC midnight.
    const today = this.todayNumber();
    if (today !== this.lastDayNumber) {
      this.updatesToday = 0;
      this.lastDayNumber = today;
    }

    if (this.updatesToday >= this.maxUpdatesPerDay) {
      this.logger.debug(
        `Keeper: daily cap reached (${this.updatesToday}/${this.maxUpdatesPerDay}), skipping`
      );
      return;
    }

    // Guardrail: skip the whole tick if gas is expensive (one read per tick).
    const baseFeeGwei = await this.blockchainService.getBaseFeeGwei();
    if (baseFeeGwei > this.maxBaseFeeGwei) {
      this.logger.warn(
        `Keeper: baseFee ${baseFeeGwei} gwei > max ${this.maxBaseFeeGwei} gwei, skipping`
      );
      return;
    }

    const nowS = BigInt(Math.floor(this.clock() / 1000));
    // Each paymaster is independent (its own staleness threshold). The daily cap
    // is shared across all of them; stop once it's exhausted this tick.
    for (const addr of this.paymasterAddresses) {
      if (this.updatesToday >= this.maxUpdatesPerDay) break;
      await this.refreshOne(addr, nowS);
    }
  }

  /**
   * Refresh a single paymaster if its cached price is approaching staleness AND
   * Chainlink has a newer reading. Never throws; logs + notifies on failure.
   */
  private async refreshOne(paymaster: string, nowS: bigint): Promise<void> {
    const { updatedAt, threshold } = await this.blockchainService.getPriceInfo(paymaster);
    const timeUntilStale = threshold - (nowS - updatedAt);
    if (timeUntilStale > this.refreshBufferS) {
      this.logger.debug(
        `Keeper: ${paymaster} fresh — stale in ${timeUntilStale}s (buffer=${this.refreshBufferS}s)`
      );
      return;
    }

    // Only update if Chainlink has a reading newer than our cached price.
    const chainlinkUpdatedAt = await this.blockchainService.getChainlinkUpdatedAt(
      this.chainlinkFeed
    );
    if (chainlinkUpdatedAt <= updatedAt) {
      this.logger.debug(
        `Keeper: ${paymaster} Chainlink not updated since last price ` +
          `(chainlink=${chainlinkUpdatedAt} ≤ price=${updatedAt}), skipping`
      );
      return;
    }

    // Final guard against redundant keepers: the staleness read above is from the
    // start of the tick; another keeper may have updated the price since. Static-
    // simulate updatePrice() right before submitting — if it would revert (price
    // already fresh / not ready), skip instead of broadcasting a doomed tx that
    // burns gas and jams the operator's nonce queue.
    if (!(await this.blockchainService.canUpdatePrice(paymaster))) {
      this.logger.debug(
        `Keeper: ${paymaster} updatePrice would revert (already fresh / not ready), skipping`
      );
      return;
    }

    try {
      const txHash = await this.blockchainService.updatePrice(paymaster);
      this.updatesToday++;
      this.logger.log(
        `Keeper: ${paymaster} updatePrice() → ${txHash} (${this.updatesToday}/${this.maxUpdatesPerDay} today)`
      );
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      this.logger.error(`Keeper: ${paymaster} updatePrice() failed — ${msg}`);
      // Fire-and-forget alert (notification failure must never block the keeper loop).
      void this.notificationService
        .sendToAccount(paymaster, `[Keeper] updatePrice failed: ${msg}`)
        .catch(() => {});
      // Operator ops alert → aastar-monitor (no-op unless configured).
      this.opsAlert?.alert("critical", `keeper updatePrice failed for ${paymaster}: ${msg}`);
    }
  }

  private todayNumber(): number {
    return Math.floor(this.clock() / 86_400_000);
  }
}
