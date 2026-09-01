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
  /** Substituted when the configured cadence is unusable — never "disabled". */
  private static readonly DEFAULT_INTERVAL_MS = 600_000;
  /** Consecutive watchdog failures before alerting: the safety net itself has gone quiet. */
  private static readonly WATCHDOG_FAIL_ALERT_AFTER = 3;
  /** Hard deadline on every watchdog RPC. Without it an unsettled promise freezes the safety loop. */
  private static readonly RPC_TIMEOUT_MS = 15_000;
  /** `LivenessRegistry.MIN_LIVENESS_WINDOW` / `MAX_LIVENESS_WINDOW` — a reading outside is not real. */
  private static readonly MIN_ONCHAIN_WINDOW = 100n;
  private static readonly MAX_ONCHAIN_WINDOW = 10_000_000n;
  /** Worst-case wall-clock for one attest to be included, used for the feasibility check. */
  private static readonly INCLUSION_ALLOWANCE_MS = 60_000;

  private readonly logger = new Logger(LivenessKeeperService.name);
  private readonly enabled: boolean;
  private readonly registryAddress: string;
  /** Mutable: a malformed value is clamped at bootstrap rather than disabling the keeper. */
  private intervalMs: number;
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
  /** Latched: this chain's block rate vs the on-chain window cannot be served safely at all. */
  private infeasibleWarned = false;
  /**
   * Head at our last LOCALLY CONFIRMED attest. Anti-grief: a stale or adversarial `lastLive` would
   * otherwise make every cycle conclude the budget is spent and pay for another transaction for ever.
   */
  private confirmedAtBlock = 0;
  /** Consecutive watchdog cycle failures — a silent safety net is worth an alert of its own. */
  private watchdogFailures = 0;
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
    // CLAMP a malformed cadence; do NOT disable on it.
    //
    // This branch used to `return`, i.e. no attest timer and no watchdog, and called that
    // fail-closed. It is the same inversion that was already removed from the window check: a keeper
    // that does not attest is a node that gets jailed, so refusing to run because an env var is
    // wrong causes the exact harm the setting exists to avoid. Fixing only the window branch left
    // this one doing it — a malformed AUDIT_ATTEST_INTERVAL_MS (NaN/Infinity from a bad env, or a
    // value outside [30s, 6h]) still silently took the node offline.
    //
    // Now: substitute the default, alert loudly, and keep running. The value still has to be bounded
    // — a non-finite one wraps Node's timer range into a near-immediate fire — but bounding it is
    // clamping, not refusing.
    if (
      !Number.isFinite(this.intervalMs) ||
      this.intervalMs < LivenessKeeperService.MIN_INTERVAL_MS ||
      this.intervalMs > LivenessKeeperService.MAX_INTERVAL_MS
    ) {
      const bad = this.intervalMs;
      this.intervalMs = LivenessKeeperService.DEFAULT_INTERVAL_MS;
      const msg =
        `AUDIT_ATTEST_INTERVAL_MS (${bad}) is outside [${LivenessKeeperService.MIN_INTERVAL_MS}, ` +
        `${LivenessKeeperService.MAX_INTERVAL_MS}] — clamped to the ${this.intervalMs}ms default and ` +
        `CONTINUING. Fix the setting: the node stays live on the default, but nobody chose it.`;
      this.logger.error(msg);
      this.opsAlert?.alert("critical", `🛑 DVT attest interval misconfigured. ${msg}`);
    }

    this.logger.log(
      `Liveness attest keeper ENABLED — registry ${this.registryAddress}, ` +
        `every ${this.intervalMs}ms, anchor depth ${this.anchorDepth}`
    );
    // Boot-attest immediately, then on the interval. void — never block bootstrap on chain I/O.
    void this.tick();
    this.timer = setInterval(() => void this.tick(), this.intervalMs);
    // Independent of the attest interval ON PURPOSE: a 6h cadence must not mean a 6h blind spot.
    this.armWatchdog(0); // immediately: a 100-block window on a fast chain can expire inside 30s
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

  /**
   * One attest cycle: read a fresh anchor, send attestLiveness. Never throws.
   *
   * Returns **true only when an attestation actually confirmed on-chain**. That distinction is
   * load-bearing for the watchdog's anti-grief bound: `blockchain.attestLiveness` does wait for
   * inclusion and throws unless `receipt.status === 1`, but this method deliberately swallows that
   * error — so a caller awaiting `tick()` alone cannot tell a confirmed attest from a failed one,
   * and would record a confirmation that never happened. That would then SUPPRESS the retry the node
   * actually needed, which is the same harm as the v1 bug that stopped the keeper outright.
   */
  async tick(): Promise<boolean> {
    if (this.stopping) return false; // no new work during shutdown
    if (this.inFlight) {
      this.logger.debug("attest tick skipped — previous still in-flight");
      return false; // skipped is NOT confirmed
    }
    this.inFlight = true;
    try {
      const anchor = await this.blockchain.getAttestAnchor(this.anchorDepth);
      if (this.stopping) return false; // shutdown began during the anchor read — no write
      const txHash = await this.blockchain.attestLiveness(
        this.registryAddress,
        anchor.number,
        anchor.hash
      );
      this.logger.log(`liveness attested @ anchor ${anchor.number}: ${txHash}`);
      return true;
    } catch (e: any) {
      const msg = e?.shortMessage ?? e?.message ?? String(e);
      this.logger.warn(`attest failed (will retry next tick): ${msg}`);
      this.opsAlert?.alert("warn", `⚠️ DVT liveness attest failed: ${msg}`);
      return false;
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

  /** Every watchdog RPC carries a deadline — an unsettled promise must never freeze the safety loop. */
  private withDeadline<T>(p: Promise<T>, what: string): Promise<T> {
    let timer: ReturnType<typeof setTimeout>;
    const deadline = new Promise<never>((_, rej) => {
      timer = setTimeout(
        () => rej(new Error(`${what} exceeded ${LivenessKeeperService.RPC_TIMEOUT_MS}ms`)),
        LivenessKeeperService.RPC_TIMEOUT_MS
      );
    });
    // Clear on settle: a race that the work wins otherwise leaves the timer pending for the full
    // deadline. NOTE this bounds the WAIT, not the operation — the underlying RPC keeps running, and
    // for a broadcast that is unavoidable: abandoning the promise cannot un-send a transaction.
    return Promise.race([p, deadline]).finally(() => clearTimeout(timer));
  }

  private async watchdogCycle(): Promise<void> {
    if (this.stopping) return;
    // A cycle already running is not a reason to drop the loop — rearm and come back.
    if (this.watchdogInFlight) {
      this.armWatchdog(LivenessKeeperService.WATCHDOG_FALLBACK_MS);
      return;
    }
    this.watchdogInFlight = true;
    // Pre-arm BEFORE any await. The previous version armed only in `finally`, so a single RPC that
    // never settled left watchdogInFlight true with no timer pending — the safety loop died silently
    // and the nominal cadence (up to 6h) became the only protection. Deadlines below make the body
    // always settle; this pre-arm is the second line of defence.
    this.armWatchdog(LivenessKeeperService.WATCHDOG_FALLBACK_MS);

    let next = LivenessKeeperService.WATCHDOG_FALLBACK_MS;
    try {
      const op = this.blockchain.getWalletAddress();
      if (!op) return;

      // PIN the sample. Read the head first, then both registry values AT that head, so the three
      // numbers describe one block. Reading them concurrently at implicit `latest` allowed a stale
      // `lastLive` + fresh head (a paid attest for nothing) or a fresh `lastLive` + stale head
      // (negative `spent`, silently read as "inside budget").
      const head = await this.withDeadline(this.blockchain.getBlockNumber(), "getBlockNumber");
      if (this.stopping) return;
      const [windowBlocks, lastLive] = await Promise.all([
        this.withDeadline(
          this.blockchain.getLivenessWindow(this.registryAddress, head),
          "getLivenessWindow"
        ),
        this.withDeadline(
          this.blockchain.getLastLive(this.registryAddress, op, head),
          "getLastLive"
        ),
      ]);
      if (this.stopping) return;

      // Validate against the CONTRACT's own bounds, not just `> 0`. An artificially small window was
      // otherwise enough to make every cycle pay for an attest.
      if (
        windowBlocks < LivenessKeeperService.MIN_ONCHAIN_WINDOW ||
        windowBlocks > LivenessKeeperService.MAX_ONCHAIN_WINDOW
      ) {
        this.logger.warn(
          `livenessWindow ${windowBlocks} is outside the registry's [100, 10000000] — ignoring this sample`
        );
        return;
      }
      if (lastLive > BigInt(head)) {
        this.logger.warn(`lastLive ${lastLive} > head ${head} — incoherent sample, ignoring`);
        return;
      }

      const budgetBlocks = windowBlocks / BigInt(LivenessKeeperService.WINDOW_SAFETY_DIVISOR);
      // lastLive == 0 means never attested: on-chain that is already offline, so attest at once.
      const spent = lastLive === 0n ? budgetBlocks + 1n : BigInt(head) - lastLive;

      // Anti-grief: only act once the chain has actually moved past our own last confirmed attest by
      // the budget. A stale or hostile `lastLive` can no longer drive an unbounded stream of paid
      // transactions, because this bound comes from a block WE saw our attest confirmed at.
      const progressed = BigInt(head) - BigInt(this.confirmedAtBlock) > budgetBlocks;
      if (spent > budgetBlocks && (this.confirmedAtBlock === 0 || progressed)) {
        this.logger.warn(
          `liveness budget spent (${spent}/${budgetBlocks} blocks of a ${windowBlocks}-block window) ` +
            `— attesting now, ahead of the ${this.intervalMs}ms nominal cadence`
        );
        const confirmed = await this.withDeadline(this.tick(), "watchdog attest");
        if (this.stopping) return;
        // ONLY on a confirmed attest. Recording it unconditionally would let a failed or skipped
        // attempt arm the suppression below and silence the very retry we need.
        //
        // `head` was read BEFORE the attest, so it is EARLIER than the block the attest actually
        // landed in. An earlier baseline makes `head - confirmedAtBlock` larger, so suppression
        // lifts SOONER, not later. (An earlier revision of this comment claimed the opposite; the
        // inequality runs the other way.) That errs toward attesting, which is the right direction
        // for liveness and a slightly weaker anti-grief bound — the trade I want, but not the one I
        // originally described. Exact would be the receipt's block, and even that is only
        // 1-confirmation deep, so a reorg can still strand it.
        if (confirmed) {
          this.confirmedAtBlock = head;
        } else {
          this.logger.warn(
            "watchdog attest did not confirm — not recording it; will retry next cycle"
          );
        }
      } else if (spent > budgetBlocks) {
        this.logger.warn(
          `budget reads as spent (${spent}/${budgetBlocks}) but the head has not advanced past our ` +
            `last confirmed attest at ${this.confirmedAtBlock} — suppressing a repeat attest (stale read?)`
        );
      }

      await this.warnIfCadenceTooSlow(windowBlocks);
      next = this.watchdogPeriodMs(windowBlocks);
      if (this.watchdogFailures >= LivenessKeeperService.WATCHDOG_FAIL_ALERT_AFTER) {
        this.logger.log(`liveness watchdog recovered after ${this.watchdogFailures} failed cycles`);
        this.opsAlert?.alert("info", "✅ DVT liveness watchdog recovered");
      }
      this.watchdogFailures = 0;
    } catch (e: any) {
      this.watchdogFailures += 1;
      const detail = e?.shortMessage ?? e?.message ?? String(e);
      this.logger.warn(
        `liveness watchdog cycle failed (${detail}) — nominal cadence continues, ` +
          `retrying in ${LivenessKeeperService.WATCHDOG_FALLBACK_MS}ms ` +
          `(consecutive failures: ${this.watchdogFailures})`
      );
      // A safety net that has gone quiet is worth its own alert: the nominal cadence may be the very
      // thing the watchdog was covering for, so "the watchdog is down" is not a log-only event.
      // Alerts once at the threshold, not every cycle.
      if (this.watchdogFailures === LivenessKeeperService.WATCHDOG_FAIL_ALERT_AFTER) {
        this.opsAlert?.alert(
          "critical",
          `🛑 DVT liveness watchdog has failed ${this.watchdogFailures} consecutive cycles ` +
            `(${detail}) — the node is running on its nominal cadence with no safety net.`
        );
      }
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
    if (this.stopping) return;
    let blockTimeMs: number;
    try {
      blockTimeMs = await this.withDeadline(this.measureBlockTimeMs(), "measureBlockTime");
      if (this.stopping) return;
    } catch {
      return; // unverified; the watchdog is the thing keeping us live, not this warning
    }
    if (!Number.isFinite(blockTimeMs) || blockTimeMs <= 0) return;
    this.lastBlockTimeMs = blockTimeMs;

    const windowMs = Number(windowBlocks) * blockTimeMs;
    const maxSafeMs = Math.floor(windowMs / LivenessKeeperService.WINDOW_SAFETY_DIVISOR);

    // FEASIBILITY, checked before the cadence verdict. On a fast chain the whole window can be
    // shorter than one attest takes to land: the registry floor is 100 blocks, so at ~0.2s/block the
    // window is ~20s and the budget ~6.6s, while the watchdog cannot poll faster than 5s and
    // inclusion needs longer still. No cadence — and no watchdog — can serve that combination. Say
    // so loudly instead of reporting a green cadence the node cannot actually meet.
    const needMs =
      LivenessKeeperService.WATCHDOG_MIN_MS + LivenessKeeperService.INCLUSION_ALLOWANCE_MS;
    if (maxSafeMs < needMs) {
      if (!this.infeasibleWarned) {
        const msg =
          `observed liveness margin is below the allowance: livenessWindow ${windowBlocks} blocks at ` +
          `~${Math.round(blockTimeMs)}ms/block leaves a ${maxSafeMs}ms budget, but one attest needs ` +
          `~${needMs}ms (${LivenessKeeperService.WATCHDOG_MIN_MS}ms minimum poll + ` +
          `${LivenessKeeperService.INCLUSION_ALLOWANCE_MS}ms inclusion allowance). Both sides are ` +
          `EMPIRICAL — the block time is a recent average, not a guaranteed bound, and the allowance ` +
          `does not cover preflight/nonce/fee work outside the receipt wait — so treat this as a ` +
          `measured margin, not a proof. On these numbers the node is likely to be intermittently ` +
          `offline whatever the cadence: raise the window on-chain, or take this chain out of scope.`;
        this.logger.error(msg);
        this.opsAlert?.alert("critical", `🛑 DVT liveness window infeasible on this chain. ${msg}`);
        this.infeasibleWarned = true;
      }
      this.cadenceUnsafe = true;
      return;
    }
    this.infeasibleWarned = false;

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
