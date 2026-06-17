import { Injectable, Logger, OnApplicationBootstrap, OnApplicationShutdown } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { BlockchainService } from "../blockchain/blockchain.service.js";
import { NotificationService } from "../notification/notification.service.js";
import { CapabilityRegistry } from "../capability/capability-registry.service.js";

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
 * Multi-node dedup: rely on the on-chain gas-saving strategy (only update near
 * expiry) — two nodes rarely hit the same update window simultaneously. Phase 2
 * may add jitter or leader election if needed.
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
  private readonly paymasterAddress: string;
  private readonly chainlinkFeed: string;
  private readonly clock: () => number;

  private timer: ReturnType<typeof setInterval> | null = null;
  private updatesToday = 0;
  private lastDayNumber = 0;

  constructor(
    private readonly blockchainService: BlockchainService,
    private readonly notificationService: NotificationService,
    private readonly config: ConfigService,
    /** Test seam: controls `Date.now()` so time-based logic is deterministic. */
    clock?: () => number,
    capabilityRegistry?: CapabilityRegistry
  ) {
    this.enabled = config.get<boolean>("keeperEnabled") === true;
    this.intervalMs = config.get<number>("keeperIntervalMs") ?? 60_000;
    this.refreshBufferS = BigInt(config.get<string>("keeperRefreshBufferS") ?? "300");
    this.maxUpdatesPerDay = config.get<number>("keeperMaxUpdatesPerDay") ?? 48;
    this.maxBaseFeeGwei = BigInt(config.get<string>("keeperMaxBaseFeeGwei") ?? "50");
    this.paymasterAddress = config.get<string>("keeperPaymasterAddress") ?? "";
    this.chainlinkFeed = config.get<string>("keeperChainlinkFeed") ?? "";
    this.clock = clock ?? (() => Date.now());

    capabilityRegistry?.register({
      name: "keeper",
      class: "infra-app",
      description: "Chainlink price keeper — keeps SuperPaymaster cachedPrice fresh (#58)",
      enabled: this.enabled,
    });
  }

  onApplicationBootstrap(): void {
    if (!this.enabled) return;
    if (!this.paymasterAddress) {
      this.logger.warn("Keeper: KEEPER_ENABLED=true but KEEPER_PAYMASTER_ADDRESS not set — disabled");
      return;
    }
    this.lastDayNumber = this.todayNumber();
    this.timer = setInterval(
      () => void this.tick().catch(e => this.logger.error(`Keeper tick error: ${String(e)}`)),
      this.intervalMs
    );
    this.logger.log(
      `Price Keeper ENABLED — interval=${this.intervalMs}ms paymaster=${this.paymasterAddress} ` +
        `buffer=${this.refreshBufferS}s cap=${this.maxUpdatesPerDay}/day maxBaseFee=${this.maxBaseFeeGwei}gwei`
    );
  }

  onApplicationShutdown(): void {
    if (this.timer !== null) {
      clearInterval(this.timer);
      this.timer = null;
    }
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

    // Read on-chain price freshness.
    const { updatedAt, threshold } = await this.blockchainService.getPriceInfo(
      this.paymasterAddress
    );
    const nowS = BigInt(Math.floor(this.clock() / 1000));
    const age = nowS - updatedAt;
    const timeUntilStale = threshold - age;

    if (timeUntilStale > this.refreshBufferS) {
      this.logger.debug(
        `Keeper: price fresh — stale in ${timeUntilStale}s (buffer=${this.refreshBufferS}s)`
      );
      return;
    }

    // Only update if Chainlink has a reading newer than our cached price.
    const chainlinkUpdatedAt = await this.blockchainService.getChainlinkUpdatedAt(
      this.chainlinkFeed
    );
    if (chainlinkUpdatedAt <= updatedAt) {
      this.logger.debug(
        `Keeper: Chainlink not updated since last price (chainlink=${chainlinkUpdatedAt} ≤ price=${updatedAt}), skipping`
      );
      return;
    }

    // Guardrail: skip if gas is expensive.
    const baseFeeGwei = await this.blockchainService.getBaseFeeGwei();
    if (baseFeeGwei > this.maxBaseFeeGwei) {
      this.logger.warn(
        `Keeper: baseFee ${baseFeeGwei} gwei > max ${this.maxBaseFeeGwei} gwei, skipping`
      );
      return;
    }

    try {
      const txHash = await this.blockchainService.updatePrice(this.paymasterAddress);
      this.updatesToday++;
      this.logger.log(
        `Keeper: updatePrice() → ${txHash} (${this.updatesToday}/${this.maxUpdatesPerDay} today)`
      );
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      this.logger.error(`Keeper: updatePrice() failed — ${msg}`);
      // Fire-and-forget alert (notification failure must never block the keeper loop).
      void this.notificationService
        .sendToAccount(this.paymasterAddress, `[Keeper] updatePrice failed: ${msg}`)
        .catch(() => {});
    }
  }

  private todayNumber(): number {
    return Math.floor(this.clock() / 86_400_000);
  }
}
