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
   * this bound proves nothing about safety. The real check is `enforceWindowBudget` (CC-29).
   */
  private static readonly MAX_INTERVAL_MS = 21_600_000; // 6h

  /**
   * The cadence must leave room to miss ticks: attest every `livenessWindow/3` worth of wall-clock so
   * two consecutive failures (RPC blip, gas spike) still land inside the window. Same ratio the
   * operator guidance always stated — now enforced instead of documented.
   */
  private static readonly WINDOW_SAFETY_DIVISOR = 3;
  /** Blocks sampled to measure real block time. Long enough that one slow block doesn't skew it. */
  private static readonly BLOCK_TIME_SAMPLE = 100;
  /** Re-check the on-chain window at most this often — it can change under us at any time. */
  private static readonly WINDOW_RECHECK_MS = 3_600_000; // 1h

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
  /** When the on-chain window was last successfully verified against the configured cadence. */
  private lastWindowCheckMs = 0;

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
    void this.enforceWindowBudget();
  }

  onApplicationShutdown(): void {
    this.stopping = true;
    if (this.timer !== null) {
      clearInterval(this.timer);
      this.timer = null;
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
    // Re-verify the cadence against the CURRENT on-chain window — governance can shrink
    // `livenessWindow` in one transaction with immediate effect, silently invalidating a cadence that
    // was safe at boot, so a boot-time check alone is not enough. Deliberately AFTER the attest and
    // fire-and-forget: this is a configuration guard, not a real-time control, and it must never
    // delay or gate the attest it protects. Acting one tick later is harmless; adding chain reads to
    // the attest path is not.
    if (
      !this.stopping &&
      Date.now() - this.lastWindowCheckMs > LivenessKeeperService.WINDOW_RECHECK_MS
    ) {
      void this.enforceWindowBudget();
    }
  }

  /**
   * CC-29 cadence budget — derive the safe attest interval from the ON-CHAIN window and stop the
   * keeper if the configured cadence cannot meet it.
   *
   * `livenessWindow` is SP-governed, denominated in BLOCKS, and changeable with immediate effect;
   * `AUDIT_ATTEST_INTERVAL_MS` is ours, wall-clock, per-node. Nothing linked them, so a legal
   * configuration could leave a perfectly healthy node reading `isOffline == true` for ever, with no
   * error anywhere — and a governance change could do the same to a node whose config nobody touched.
   *
   * Block time is MEASURED on-chain rather than configured, so this holds on any chain (a 2s L2 and a
   * 12s L1 need no separate setting).
   *
   * ⚠️ The two failure directions are deliberately OPPOSITE:
   *  - the cadence is provably too slow  ⇒ **fail-closed**: stop the keeper, alert. The operator finds
   *    out at once instead of being silently jailed.
   *  - the window cannot be READ (RPC blip, bad address) ⇒ **keep attesting**, warn only. Stopping on
   *    an unreadable value would itself make the node look offline — the exact harm this prevents.
   *    An unknown config is not a bad config.
   */
  private async enforceWindowBudget(): Promise<void> {
    let windowBlocks: bigint;
    let blockTimeMs: number;
    try {
      windowBlocks = await this.blockchain.getLivenessWindow(this.registryAddress);
      blockTimeMs = await this.measureBlockTimeMs();
    } catch (e: any) {
      // Unknown ≠ unsafe: keep attesting, say so, and retry on the next re-check.
      this.logger.warn(
        `could not verify attest cadence against the on-chain livenessWindow ` +
          `(${e?.shortMessage ?? e?.message ?? String(e)}) — keeper CONTINUES, will retry`
      );
      return;
    }

    if (windowBlocks <= 0n || !Number.isFinite(blockTimeMs) || blockTimeMs <= 0) {
      this.logger.warn(
        `implausible window/block-time reading (window=${windowBlocks} blocks, ` +
          `blockTime=${blockTimeMs}ms) — cadence unverified, keeper CONTINUES`
      );
      return;
    }

    const windowMs = Number(windowBlocks) * blockTimeMs;
    const maxSafeMs = Math.floor(windowMs / LivenessKeeperService.WINDOW_SAFETY_DIVISOR);
    this.lastWindowCheckMs = Date.now();

    if (this.intervalMs > maxSafeMs) {
      const msg =
        `AUDIT_ATTEST_INTERVAL_MS (${this.intervalMs}ms) exceeds the on-chain liveness budget: ` +
        `livenessWindow ${windowBlocks} blocks x ~${Math.round(blockTimeMs)}ms = ${Math.round(windowMs)}ms, ` +
        `safe max ${maxSafeMs}ms (window/${LivenessKeeperService.WINDOW_SAFETY_DIVISOR}). ` +
        `At this cadence the node would read as OFFLINE on-chain while perfectly healthy — ` +
        `attest keeper STOPPED (fail-closed).`;
      this.logger.error(msg);
      this.opsAlert?.alert(
        "critical",
        `🛑 DVT liveness attest cadence unsafe — keeper stopped. ${msg}`
      );
      if (this.timer !== null) {
        clearInterval(this.timer);
        this.timer = null;
      }
      return;
    }

    this.logger.log(
      `attest cadence OK — livenessWindow ${windowBlocks} blocks (~${Math.round(windowMs)}ms at ` +
        `~${Math.round(blockTimeMs)}ms/block), safe max ${maxSafeMs}ms, configured ${this.intervalMs}ms`
    );
  }

  /**
   * Average block time over the last `BLOCK_TIME_SAMPLE` blocks, in ms. Measured rather than
   * configured so the budget is chain-agnostic. Throws on a read failure — the caller treats that as
   * "unknown", not "unsafe".
   */
  private async measureBlockTimeMs(): Promise<number> {
    const latest = await this.blockchain.getBlockNumber();
    const span = Math.min(LivenessKeeperService.BLOCK_TIME_SAMPLE, Math.max(1, latest - 1));
    const [tsLatest, tsEarlier] = await Promise.all([
      this.blockchain.getBlockTimestamp(latest),
      this.blockchain.getBlockTimestamp(latest - span),
    ]);
    return ((tsLatest - tsEarlier) * 1000) / span;
  }
}
