import {
  Injectable,
  Logger,
  Optional,
  OnApplicationBootstrap,
  OnApplicationShutdown,
} from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { BlockchainService } from "../blockchain/blockchain.service.js";
import { OpsAlertService } from "../ops-alert/ops-alert.service.js";

/**
 * Liveness attest keeper (inc-2 C1 — SP LivenessRegistry, CC-29).
 *
 * Each DVT node IS a registered operator. SP's LivenessRegistry AUTO-JAILS an operator that is
 * `never-attested` or whose `lastLive` is older than `livenessWindow` (objective on-chain fact:
 * `block.number > lastLive + window`). A jailed operator is excluded from the active set + its fee
 * is stopped. So a node MUST periodically prove its own liveness on-chain, or the whole fleet's
 * auto-jail is meaningless — this keeper is that prover.
 *
 * It calls `LivenessRegistry.attestLiveness(anchorBlock, anchorHash)` from the OPERATOR EOA
 * (ETH_PRIVATE_KEY — the registry attests msg.sender). anchorBlock/anchorHash bind the attest to a
 * recent unpredictable blockhash (SP's M-01 fix: a pre-signed stale attest can't cover the future).
 *
 * Opt-in (AUDIT_ATTEST_ENABLED, default off). Attests once on boot (re-establish liveness fast
 * after a restart — a node may have been jailed while down) then every `intervalMs`. Fire-and-
 * forget per tick: a failure is logged/alerted and retried next tick (which re-anchors); a
 * persistently-failing node SHOULD be jailed (it genuinely can't prove liveness). This is why the
 * keeper never crashes the process on an attest failure.
 *
 * NOTE: `intervalMs` is wall-clock; set it to roughly `livenessWindow/3` worth of time for the
 * target chain (window is in BLOCKS — the keeper logs the on-chain window at boot so the operator
 * can sanity-check the cadence). Attesting every window/3 leaves 2 missed ticks of slack before an
 * operator would trip the offline threshold, absorbing RPC/gas jitter.
 */
@Injectable()
export class LivenessKeeperService implements OnApplicationBootstrap, OnApplicationShutdown {
  /** Operationally-safe cadence bounds (fail-closed outside these). */
  private static readonly MIN_INTERVAL_MS = 30_000; // 30s — below this floods RPC/gas
  /**
   * Absolute ceiling. This is a fat-finger guard ONLY — it is a static constant and therefore cannot
   * track `livenessWindow`, which lives on-chain, is denominated in BLOCKS, and SP governance can
   * change at any moment with immediate effect. 6h is >6x a 300-block (~60min) window, so passing
   * this bound proves nothing about safety. Liveness is kept by the watchdog (CC-29) instead.
   */
  private static readonly MAX_INTERVAL_MS = 21_600_000; // 6h

  /**
   * Attest once `livenessWindow/3` of the budget is spent, so two consecutive failures (RPC blip, gas
   * spike) still land inside the window. Applied in BLOCK space by the watchdog — see below.
   */
  private static readonly WINDOW_SAFETY_DIVISOR = 3;
  /** Blocks sampled to estimate block time. Advisory only: used for the warning, never for liveness. */
  private static readonly BLOCK_TIME_SAMPLE = 100;
  /** Watchdog period bounds. Self-tuned from the measured window; these are the fat-finger rails. */
  private static readonly WATCHDOG_MIN_MS = 5_000;
  private static readonly WATCHDOG_MAX_MS = 60_000;
  private static readonly WATCHDOG_FALLBACK_MS = 30_000;

  private readonly logger = new Logger(LivenessKeeperService.name);
  private readonly enabled: boolean;
  private readonly registryAddress: string;
  private readonly intervalMs: number;
  private readonly anchorDepth: number;
  private timer: ReturnType<typeof setInterval> | null = null;
  /** Guards against overlapping ticks if one attest runs longer than the interval. */
  private inFlight = false;
  /** Set on shutdown so a fired timer / in-flight boot-attest starts no NEW work. */
  private stopping = false;
  /** Independent watchdog timer — deliberately NOT driven by the attest interval. */
  private watchdog: ReturnType<typeof setTimeout> | null = null;
  /** Serialises watchdog cycles so a slow one cannot overlap or act on stale reads. */
  private watchdogInFlight = false;
  /** Latched so the "cadence too slow" alert fires once per transition, not every cycle. */
  private cadenceUnsafe = false;
  /** Last successful block-time estimate (ms). Advisory: tunes the watchdog period only. */
  private lastBlockTimeMs = 0;

  constructor(
    private readonly blockchain: BlockchainService,
    @Optional() private readonly config?: ConfigService,
    @Optional() private readonly opsAlert?: OpsAlertService
  ) {
    this.enabled = this.config?.get<boolean>("auditAttestEnabled") === true;
    this.registryAddress = this.config?.get<string>("auditLivenessRegistryAddress") ?? "";
    this.intervalMs = this.config?.get<number>("auditAttestIntervalMs") ?? 600_000;
    // Clamp anchor depth to the protocol-valid [1,255] up front, so the ENABLED log reports the depth
    // actually used (getAttestAnchor clamps too; keeping them in sync avoids a misleading log).
    const rawDepth = this.config?.get<number>("auditAttestAnchorDepth") ?? 16;
    this.anchorDepth = Number.isFinite(rawDepth)
      ? Math.min(255, Math.max(1, Math.floor(rawDepth)))
      : 16;
    if (this.anchorDepth !== rawDepth) {
      this.logger.warn(
        `AUDIT_ATTEST_ANCHOR_DEPTH ${rawDepth} out of [1,255] — clamped to ${this.anchorDepth}`
      );
    }
  }

  onApplicationBootstrap(): void {
    if (!this.enabled) return;
    if (!/^0x[0-9a-fA-F]{40}$/.test(this.registryAddress)) {
      this.logger.warn(
        "AUDIT_ATTEST_ENABLED but AUDIT_LIVENESS_REGISTRY_ADDRESS is missing/invalid — attest keeper DISABLED"
      );
      return;
    }
    if (!this.blockchain.getWalletAddress()) {
      this.logger.warn(
        "AUDIT_ATTEST_ENABLED but no operator wallet (ETH_PRIVATE_KEY) — attest keeper DISABLED"
      );
      return;
    }
    // Bound the interval to an operationally-safe range [30s, 6h]. Too small floods RPC/gas; too
    // large (or NaN/Infinity from bad env) can wrap Node's timer range to a near-immediate fire.
    // Fail-CLOSED (disable) rather than fail-open on a misconfigured cadence.
    if (
      !Number.isFinite(this.intervalMs) ||
      this.intervalMs < LivenessKeeperService.MIN_INTERVAL_MS ||
      this.intervalMs > LivenessKeeperService.MAX_INTERVAL_MS
    ) {
      this.logger.warn(
        `AUDIT_ATTEST_INTERVAL_MS (${this.intervalMs}) out of [${LivenessKeeperService.MIN_INTERVAL_MS}, ` +
          `${LivenessKeeperService.MAX_INTERVAL_MS}] — attest keeper DISABLED`
      );
      return;
    }

    this.logger.log(
      `Liveness attest keeper ENABLED — registry ${this.registryAddress}, ` +
        `every ${this.intervalMs}ms, anchor depth ${this.anchorDepth}`
    );
    // Boot-attest immediately, then on the interval. void — never block bootstrap on chain I/O.
    void this.tick();
    this.timer = setInterval(() => void this.tick(), this.intervalMs);
    // Independent of the attest interval ON PURPOSE: a 6h cadence must not mean a 6h blind spot.
    this.armWatchdog(LivenessKeeperService.WATCHDOG_FALLBACK_MS);
  }

  onApplicationShutdown(): void {
    this.stopping = true;
    if (this.timer !== null) {
      clearInterval(this.timer);
      this.timer = null;
    }
    if (this.watchdog !== null) {
      clearTimeout(this.watchdog);
      this.watchdog = null;
    }
  }

  /** One attest cycle: read a fresh anchor, send attestLiveness. Never throws. */
  async tick(): Promise<void> {
    if (this.stopping) return; // no new work during shutdown
    if (this.inFlight) {
      this.logger.debug("attest tick skipped — previous still in-flight");
      return;
    }
    this.inFlight = true;
    try {
      const anchor = await this.blockchain.getAttestAnchor(this.anchorDepth);
      if (this.stopping) return; // shutdown began during the anchor read — do not start a write
      const txHash = await this.blockchain.attestLiveness(
        this.registryAddress,
        anchor.number,
        anchor.hash
      );
      this.logger.log(`liveness attested @ anchor ${anchor.number}: ${txHash}`);
    } catch (e: any) {
      const msg = e?.shortMessage ?? e?.message ?? String(e);
      this.logger.warn(`attest failed (will retry next tick): ${msg}`);
      this.opsAlert?.alert("warn", `⚠️ DVT liveness attest failed: ${msg}`);
    } finally {
      this.inFlight = false;
    }
  }

  /**
   * CC-29 liveness watchdog — the safety net that makes the configured cadence advisory.
   *
   * ⚠️ **Design corrected after adversarial review.** The first version answered "your cadence is too
   * slow" by STOPPING the keeper, framed as fail-closed. That was inverted: a stopped keeper stops
   * attesting, so `block.number - lastLive` grows without bound and the node is jailed **for certain
   * and permanently**, with no path back — the exact outcome the check exists to prevent, made worse
   * and irreversible. There is no upside either, because the alert can be raised without stopping.
   * **Never stop attesting as a response to configuration.**
   *
   * It also predicted rather than observed: it converted `livenessWindow` (BLOCKS) into wall-clock
   * using the average of the last 100 blocks, and an average is not a bound on how fast the next
   * blocks arrive. On a bursty L2 an idle sample says 12s/block while the next 100 arrive in 20s, so
   * a "safe" cadence silently is not.
   *
   * So liveness is now decided in BLOCK space from live state: read `lastLive(op)` and the head, and
   * attest as soon as `head - lastLive` has spent `livenessWindow / 3`. Nothing is extrapolated. The
   * wall-clock interval remains as the nominal cadence; this only ever attests EARLIER.
   *
   * The watchdog runs on its OWN timer, self-tuned to `windowMs/6` within [5s, 60s]. It is not driven
   * by the attest interval, because a 6h cadence must not imply a 6h blind spot to a governance
   * change that takes effect immediately.
   */
  private armWatchdog(delayMs: number): void {
    if (this.stopping) return;
    if (this.watchdog !== null) clearTimeout(this.watchdog);
    this.watchdog = setTimeout(() => void this.watchdogCycle(), delayMs);
  }

  private async watchdogCycle(): Promise<void> {
    if (this.stopping || this.watchdogInFlight) return;
    this.watchdogInFlight = true;
    let next = LivenessKeeperService.WATCHDOG_FALLBACK_MS;
    try {
      const op = this.blockchain.getWalletAddress();
      if (!op) return;
      const [windowBlocks, head, lastLive] = await Promise.all([
        this.blockchain.getLivenessWindow(this.registryAddress),
        this.blockchain.getBlockNumber(),
        this.blockchain.getLastLive(this.registryAddress, op),
      ]);
      if (this.stopping) return;
      if (windowBlocks <= 0n) return; // implausible — leave the nominal cadence alone

      const budgetBlocks = windowBlocks / BigInt(LivenessKeeperService.WINDOW_SAFETY_DIVISOR);
      // lastLive == 0 means never attested: on-chain that is already offline, so attest at once.
      const spent = lastLive === 0n ? budgetBlocks + 1n : BigInt(head) - lastLive;
      if (spent > budgetBlocks) {
        this.logger.warn(
          `liveness budget spent (${spent}/${budgetBlocks} blocks of a ${windowBlocks}-block window) ` +
            `— attesting now, ahead of the ${this.intervalMs}ms nominal cadence`
        );
        await this.tick();
      }

      // Advisory only: warn if the CONFIGURED cadence cannot meet the budget on its own. The watchdog
      // above already keeps the node live either way, so this never changes behaviour — it tells the
      // operator their setting is wrong instead of silently carrying them.
      await this.warnIfCadenceTooSlow(windowBlocks);
      next = this.watchdogPeriodMs(windowBlocks);
    } catch (e: any) {
      // Unknown is not unsafe, and it is certainly not a reason to stop attesting. Keep the nominal
      // cadence, retry soon (fallback period, NOT the attest interval), and say so.
      this.logger.warn(
        `liveness watchdog cycle failed (${e?.shortMessage ?? e?.message ?? String(e)}) — ` +
          `nominal cadence continues, retrying in ${LivenessKeeperService.WATCHDOG_FALLBACK_MS}ms`
      );
    } finally {
      this.watchdogInFlight = false;
      this.armWatchdog(next);
    }
  }

  /** Self-tuned watchdog period: a sixth of the window, railed into [5s, 60s]. */
  private watchdogPeriodMs(windowBlocks: bigint): number {
    const blockTimeMs = this.lastBlockTimeMs;
    if (!blockTimeMs) return LivenessKeeperService.WATCHDOG_FALLBACK_MS;
    const windowMs = Number(windowBlocks) * blockTimeMs;
    return Math.min(
      LivenessKeeperService.WATCHDOG_MAX_MS,
      Math.max(LivenessKeeperService.WATCHDOG_MIN_MS, Math.floor(windowMs / 6))
    );
  }

  /**
   * Advisory cadence warning. Latched so a persistent misconfiguration alerts once per transition
   * rather than every cycle. NEVER stops the keeper — see the class note on the corrected direction.
   */
  private async warnIfCadenceTooSlow(windowBlocks: bigint): Promise<void> {
    let blockTimeMs: number;
    try {
      blockTimeMs = await this.measureBlockTimeMs();
    } catch {
      return; // unverified; the watchdog is the thing keeping us live, not this warning
    }
    if (!Number.isFinite(blockTimeMs) || blockTimeMs <= 0) return;
    this.lastBlockTimeMs = blockTimeMs;

    const windowMs = Number(windowBlocks) * blockTimeMs;
    const maxSafeMs = Math.floor(windowMs / LivenessKeeperService.WINDOW_SAFETY_DIVISOR);
    const unsafe = this.intervalMs > maxSafeMs;

    if (unsafe && !this.cadenceUnsafe) {
      const msg =
        `AUDIT_ATTEST_INTERVAL_MS (${this.intervalMs}ms) exceeds the on-chain liveness budget: ` +
        `livenessWindow ${windowBlocks} blocks x ~${Math.round(blockTimeMs)}ms = ${Math.round(windowMs)}ms, ` +
        `safe max ${maxSafeMs}ms (window/${LivenessKeeperService.WINDOW_SAFETY_DIVISOR}). ` +
        `The watchdog is covering for it by attesting early — the node stays live — but FIX THE SETTING: ` +
        `the watchdog is a safety net, not a cadence.`;
      this.logger.error(msg);
      this.opsAlert?.alert(
        "critical",
        `🛑 DVT attest cadence too slow for the on-chain window. ${msg}`
      );
    } else if (!unsafe && this.cadenceUnsafe) {
      this.logger.log(`attest cadence back within the on-chain budget (safe max ${maxSafeMs}ms)`);
    }
    this.cadenceUnsafe = unsafe;
  }

  /**
   * Average block time over a recent span, in ms. ADVISORY ONLY — it feeds the operator warning and
   * the watchdog period, never a liveness decision, because an average of past blocks is not a bound
   * on future ones. Throws on a read failure; callers treat that as "unknown", never as "unsafe".
   */
  private async measureBlockTimeMs(): Promise<number> {
    const latest = await this.blockchain.getBlockNumber();
    if (latest < 1) throw new Error("insufficient chain history to measure block time");
    const span = Math.min(LivenessKeeperService.BLOCK_TIME_SAMPLE, latest);
    const [tsLatest, tsEarlier] = await Promise.all([
      this.blockchain.getBlockTimestamp(latest),
      this.blockchain.getBlockTimestamp(latest - span),
    ]);
    const deltaMs = ((tsLatest - tsEarlier) * 1000) / span;
    if (!Number.isFinite(deltaMs) || deltaMs <= 0) {
      // Zero/backward can happen across a reorg between the two reads. Reject rather than act on it.
      throw new Error(`implausible block-time sample (${deltaMs}ms/block)`);
    }
    return deltaMs;
  }
}
