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
  private static readonly MAX_INTERVAL_MS = 21_600_000; // 6h — above risks tripping the offline window

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
    void this.logWindow();
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
  }

  /** Log the on-chain livenessWindow at boot so the operator can sanity-check the interval. */
  private async logWindow(): Promise<void> {
    try {
      const window = await this.blockchain.getLivenessWindow(this.registryAddress);
      this.logger.log(
        `on-chain livenessWindow = ${window} blocks — set AUDIT_ATTEST_INTERVAL_MS to ~window/3 worth of wall-clock`
      );
    } catch {
      // best-effort — a read failure here must not affect attesting
    }
  }
}
