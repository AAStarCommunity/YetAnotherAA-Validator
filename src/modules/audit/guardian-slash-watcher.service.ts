import {
  Injectable,
  Logger,
  Optional,
  OnApplicationBootstrap,
  OnApplicationShutdown,
} from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { ethers } from "ethers";
import { OpsAlertService } from "../ops-alert/ops-alert.service.js";
import type { IGuardianSignerStore } from "./guardian-signer-store.js";
import { LocalGuardianSignerStore } from "./guardian-signer-store.js";
import { SLASH_EXECUTED_EVENT, buildGuardianSignerRecord } from "./guardian-slash-watcher.core.js";
import { checkAggregatorChainPolicy } from "./aggregator-bootstrap-guard.js";
import { attestDomainAgainstAggregator } from "./bls-consensus-domain.js";

/**
 * CC-89 stage-2 — guardian-slash WATCHER (the off-chain data-availability half).
 *
 * SP's A' commitment (`proposalSignersCommitment`, PR #371) is an irreversible fingerprint of a
 * slash's signer ADDRESS set. When a slash is later found fraudulent, the fraud-proof assembler
 * needs the actual `claimedSigners` that reproduce that commitment — and the commitment can't be
 * reversed. So each DVT node must capture the signer set AT execution time. This service is that
 * capture: it polls `BLSAggregator.SlashExecuted`, resolves the co-signer addresses via
 * `validatorAtSlot` pinned to the verifyAndExecute EXECUTION block, self-checks the recomputed
 * commitment against on-chain, and durably records `proposalId → {claimedSigners, ...}`.
 *
 * It runs IN-PROCESS in every DVT node — the fleet's multiple independent nodes ARE the required
 * redundancy (a slash whose set no node recorded is permanently un-attributable). It is a pure
 * OBSERVER: it never signs, files, or slashes — downstream (the assembler + on-chain verifier) do.
 *
 * DURABILITY INVARIANTS (Codex CC-89 review):
 *   - Only SELF-VERIFIED records enter the canonical store (`putVerified`); a self-check miss is
 *     QUARANTINED (`putUnverified`) + alerted, never trusted by the assembler.
 *   - A log that can't be captured at all is DEAD-LETTERED (`putFailure`) + retried each tick — a
 *     transient error self-heals; a permanent one (e.g. a wrapped/undecodable verifyAndExecute)
 *     stays VISIBLE + RECOVERABLE, never silently lost.
 *   - The scan cursor advances ONLY after a chunk is FULLY processed (every log reached a durable
 *     terminal/dead-letter state) and NOT while shutting down — so no log is ever skipped past.
 *
 * KNOWN GAP (production, not E2E): only a TOP-LEVEL `verifyAndExecute` tx decodes. A production
 * execution wrapped by DVTValidator/a relayer/multicall dead-letters (visible, not lost); resolving
 * the internal call needs trace support (debug_traceTransaction) — Phase-3.
 *
 * Opt-in (AUDIT_GUARDIAN_WATCH_ENABLED, default off) and fail-closed: disables itself if the
 * aggregator address is missing or has no on-chain code. Polling (not a ws subscription) with a
 * persisted cursor makes it restart-safe — a node that was down backfills from where it left off.
 */
@Injectable()
export class GuardianSlashWatcherService implements OnApplicationBootstrap, OnApplicationShutdown {
  private static readonly MIN_INTERVAL_MS = 5_000;
  private static readonly MAX_INTERVAL_MS = 3_600_000; // 1h
  /** Dead-letter retry cap; past this the entry is PARKED (kept durable, no longer auto-retried). */
  private static readonly MAX_CAPTURE_ATTEMPTS = 10;

  private readonly logger = new Logger(GuardianSlashWatcherService.name);
  private readonly enabled: boolean;
  private readonly aggregatorAddress: string;
  /** SP Registry — the 4th BLS-consensus domain-separator field; needed to reproduce SP's commitment. */
  private readonly registryAddress: string;
  /** AUDIT_CHAIN_ID — cross-checked against the RPC's actual chain (shared fail-closed policy). */
  private readonly expectedChainId: number;
  /** Whether AUDIT_BLS_AGGREGATOR_ADDRESS was set explicitly (guards the Sepolia default). */
  private readonly aggregatorFromEnv: boolean;
  private readonly rpcUrl: string;
  private readonly intervalMs: number;
  private readonly fromBlock: number;
  private readonly finalityConfirmations: number;
  private readonly logChunk: number;
  private readonly store: IGuardianSignerStore;

  private provider: ethers.JsonRpcProvider | null = null;
  private chainId: bigint | null = null;
  private slashExecutedTopic = "";
  private timer: ReturnType<typeof setInterval> | null = null;
  private inFlight = false;
  private stopping = false;

  constructor(
    @Optional() private readonly config?: ConfigService,
    @Optional() private readonly opsAlert?: OpsAlertService,
    @Optional() store?: IGuardianSignerStore
  ) {
    this.enabled = this.config?.get<boolean>("auditGuardianWatchEnabled") === true;
    this.aggregatorAddress = this.config?.get<string>("auditBlsAggregatorAddress") ?? "";
    this.registryAddress = this.config?.get<string>("auditRegistryAddress") ?? "";
    this.expectedChainId = this.config?.get<number>("auditChainId") ?? 0;
    this.aggregatorFromEnv = this.config?.get<boolean>("auditBlsAggregatorAddressFromEnv") === true;
    this.rpcUrl = this.config?.get<string>("ethRpcUrl") ?? "";
    this.intervalMs = this.config?.get<number>("auditGuardianWatchIntervalMs") ?? 60_000;
    this.fromBlock = this.config?.get<number>("auditGuardianWatchFromBlock") ?? 0;
    this.finalityConfirmations = this.config?.get<number>("auditFinalityConfirmations") ?? 12;
    this.logChunk = this.config?.get<number>("auditRoleLogChunk") ?? 10_000;
    this.store =
      store ??
      new LocalGuardianSignerStore(
        this.config?.get<string>("auditGuardianWatchDir") ?? "./guardian-signer-records"
      );
  }

  onApplicationBootstrap(): void {
    if (!this.enabled) return;
    if (!/^0x[0-9a-fA-F]{40}$/.test(this.aggregatorAddress)) {
      this.logger.warn(
        "AUDIT_GUARDIAN_WATCH_ENABLED but AUDIT_BLS_AGGREGATOR_ADDRESS is missing/invalid — watcher DISABLED"
      );
      return;
    }
    // The Registry is the 4th BLS-consensus domain-separator field; without it the watcher cannot
    // reproduce SP's commitment (and ethers.getAddress("") would throw per-event, dead-lettering
    // every capture). Reject a missing/invalid Registry up front (fail-closed) — the on-chain
    // Registry parity is then attested against the aggregator in bootstrapAndPoll.
    if (!/^0x[0-9a-fA-F]{40}$/.test(this.registryAddress)) {
      this.logger.warn(
        "AUDIT_GUARDIAN_WATCH_ENABLED but AUDIT_REGISTRY_ADDRESS is missing/invalid — watcher DISABLED"
      );
      return;
    }
    if (!this.rpcUrl) {
      this.logger.warn(
        "AUDIT_GUARDIAN_WATCH_ENABLED but ETH_RPC_URL is missing — watcher DISABLED"
      );
      return;
    }
    if (
      !Number.isFinite(this.intervalMs) ||
      this.intervalMs < GuardianSlashWatcherService.MIN_INTERVAL_MS ||
      this.intervalMs > GuardianSlashWatcherService.MAX_INTERVAL_MS
    ) {
      this.logger.warn(
        `AUDIT_GUARDIAN_WATCH_INTERVAL_MS (${this.intervalMs}) out of ` +
          `[${GuardianSlashWatcherService.MIN_INTERVAL_MS}, ${GuardianSlashWatcherService.MAX_INTERVAL_MS}] — watcher DISABLED`
      );
      return;
    }

    this.provider = new ethers.JsonRpcProvider(this.rpcUrl);
    // Topic0 derived from the canonical event fragment (single source of truth with the core).
    this.slashExecutedTopic = new ethers.Interface([SLASH_EXECUTED_EVENT]).getEvent(
      "SlashExecuted"
    )!.topicHash;
    this.logger.log(
      `Guardian-slash watcher ENABLED — aggregator ${this.aggregatorAddress}, ` +
        `every ${this.intervalMs}ms, from block ${this.fromBlock}, finality −${this.finalityConfirmations}`
    );
    // Verify the aggregator has code (fail-closed), then run the first tick, then poll.
    void this.bootstrapAndPoll();
  }

  onApplicationShutdown(): void {
    this.stopping = true;
    if (this.timer !== null) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }

  private async bootstrapAndPoll(): Promise<void> {
    try {
      const code = await this.provider!.getCode(this.aggregatorAddress);
      if (code === "0x") {
        this.logger.warn(
          `aggregator ${this.aggregatorAddress} has no on-chain code — watcher DISABLED`
        );
        return;
      }
      const net = await this.provider!.getNetwork();
      // Shared fail-closed policy (mirrors AuditService): reject a wrong-chain RPC or a Sepolia
      // aggregator default silently inherited off-Sepolia. getCode above only proves bytecode exists.
      const policy = checkAggregatorChainPolicy({
        expectedChainId: this.expectedChainId,
        providerChainId: Number(net.chainId),
        aggregatorFromEnv: this.aggregatorFromEnv,
        aggregatorRequired: true,
      });
      if (!policy.ok) {
        this.logger.warn(`${policy.reason} — watcher DISABLED`);
        return;
      }
      // Interface sanity-probe: statically exercise the EXACT methods this watcher calls at runtime
      // (validatorAtSlot + proposalSignersCommitment). A wrong-but-deployed address passes getCode
      // but reverts / fails to decode here → fail-closed at bootstrap, not at runtime.
      const probe = new ethers.Contract(
        this.aggregatorAddress,
        [
          "function validatorAtSlot(uint8) view returns (address)",
          "function proposalSignersCommitment(uint256) view returns (bytes32)",
        ],
        this.provider!
      );
      await probe.validatorAtSlot(1);
      await probe.proposalSignersCommitment(0);

      // Domain attestation (fail-closed): the commitment the watcher recomputes binds
      // chainId+aggregator+Registry. A missing/zero or wrong-but-valid Registry would make EVERY
      // commitment mismatch (silently quarantining every capture as commitmentVerified:false).
      // Prove the on-chain aggregator agrees with our LOCAL (chainId, aggregator, Registry) BEFORE
      // polling; a mismatch throws → DISABLED here, not silently dead-lettered per-event.
      await attestDomainAgainstAggregator(this.provider!, {
        chainId: net.chainId,
        aggregator: this.aggregatorAddress,
        registry: this.registryAddress,
      });
      this.chainId = net.chainId;
    } catch (e: any) {
      this.logger.warn(`watcher bootstrap read failed — DISABLED: ${e?.message ?? String(e)}`);
      return;
    }
    if (this.stopping) return;
    void this.tick();
    this.timer = setInterval(() => void this.tick(), this.intervalMs);
  }

  /** One cycle: retry dead-letters, then scan cursor → finalized head. Never throws. */
  async tick(): Promise<void> {
    if (this.stopping || !this.provider || this.chainId === null) return;
    if (this.inFlight) {
      this.logger.debug("watcher tick skipped — previous still in-flight");
      return;
    }
    this.inFlight = true;
    try {
      await this.retryFailures();

      const head = await this.provider.getBlockNumber();
      const safeHead = head - this.finalityConfirmations;
      if (safeHead < this.fromBlock) return; // nothing finalized to scan yet

      const cursor = await this.store.readCursor();
      let from = cursor === null ? this.fromBlock : cursor + 1;
      if (from > safeHead) return;

      while (from <= safeHead && !this.stopping) {
        const to = Math.min(from + this.logChunk - 1, safeHead);
        const completed = await this.scanRange(from, to);
        // Advance the cursor ONLY when the whole chunk was durably accounted for (every log verified,
        // quarantined, or dead-lettered) and we were not interrupted by shutdown — never skip a log.
        if (!completed) return;
        await this.store.writeCursor(to);
        from = to + 1;
      }
    } catch (e: any) {
      const msg = e?.shortMessage ?? e?.message ?? String(e);
      this.logger.warn(`watcher tick failed (will retry): ${msg}`);
      this.opsAlert?.alert("warn", `⚠️ DVT guardian-slash watcher tick failed: ${msg}`);
    } finally {
      this.inFlight = false;
    }
  }

  /**
   * Process every SlashExecuted in [from, to]. Returns true iff the whole range was processed
   * (each log reached a durable terminal/dead-letter state); false if shutdown interrupted it, so
   * the caller must NOT advance the cursor.
   */
  private async scanRange(from: number, to: number): Promise<boolean> {
    const logs = await this.provider!.getLogs({
      address: this.aggregatorAddress,
      topics: [this.slashExecutedTopic],
      fromBlock: from,
      toBlock: to,
    });
    for (const log of logs) {
      if (this.stopping) return false; // interrupted — do not advance the cursor past unscanned logs
      const proposalId = BigInt(log.topics[1]); // topic[1] = indexed proposalId
      if (await this.store.hasTerminal(proposalId)) continue; // already verified or quarantined
      // Already dead-lettered (e.g. a shutdown left this range's cursor unadvanced) — the retry loop
      // owns re-driving it; re-processing here would double-count attempts + double-alert.
      if (await this.store.hasFailure(log.blockNumber, log.index)) continue;
      await this.captureOne(proposalId, log.transactionHash, log.blockNumber, log.index);
    }
    return true;
  }

  /** Build + route one log to verified / quarantine / dead-letter. Never throws. */
  private async captureOne(
    proposalId: bigint,
    txHash: string,
    executionBlock: number,
    logIndex: number
  ): Promise<void> {
    try {
      const record = await buildGuardianSignerRecord(
        this.provider!,
        this.aggregatorAddress,
        this.registryAddress,
        this.chainId!,
        proposalId,
        txHash,
        executionBlock
      );
      if (record.commitmentVerified) {
        await this.store.putVerified(record);
        this.logger.log(
          `captured signer set for proposal ${proposalId} ` +
            `(${record.claimedSigners.length} signers, block ${executionBlock})`
        );
      } else {
        // Recorded but the recompute didn't match on-chain — QUARANTINE (never trusted by the
        // assembler) + loud alert. Not the canonical store; not a silent drop.
        await this.store.putUnverified(record);
        this.logger.warn(
          `proposal ${proposalId} QUARANTINED — commitment self-check failed (needs manual review)`
        );
        this.opsAlert?.alert(
          "warn",
          `⚠️ DVT watcher: proposal ${proposalId} signer-set commitment mismatch (quarantined, needs review)`
        );
      }
    } catch (e: any) {
      // Could not build a record at all (tx fetch error, wrapped/undecodable call, hole slot). Dead-
      // letter it so it is retried + stays visible — a missed capture erodes attribution redundancy.
      await this.deadLetter(proposalId, txHash, executionBlock, logIndex, e?.message ?? String(e));
    }
  }

  /** Record a capture failure durably (idempotent by block+logIndex; bumps attempts, parks at cap). */
  private async deadLetter(
    proposalId: bigint,
    txHash: string,
    block: number,
    logIndex: number,
    reason: string
  ): Promise<void> {
    const existing = (await this.store.listFailures()).find(
      f => f.block === block && f.logIndex === logIndex
    );
    const attempts = (existing?.attempts ?? 0) + 1;
    const parked = attempts >= GuardianSlashWatcherService.MAX_CAPTURE_ATTEMPTS;
    await this.store.putFailure({
      block,
      logIndex,
      txHash,
      proposalId: proposalId.toString(),
      reason,
      attempts,
      parked,
    });
    const tail = parked ? " — PARKED (max attempts, manual recovery needed)" : "";
    this.logger.warn(
      `could not capture proposal ${proposalId} (attempt ${attempts}) — dead-lettered: ${reason}${tail}`
    );
    this.opsAlert?.alert(
      "warn",
      `⚠️ DVT watcher: proposal ${proposalId} signer set NOT captured (attempt ${attempts})${tail} — ${reason}`
    );
  }

  /** Re-attempt each non-parked dead-letter; on success promote to verified/quarantine + remove. */
  private async retryFailures(): Promise<void> {
    const failures = await this.store.listFailures();
    for (const f of failures) {
      if (this.stopping) return;
      if (f.parked) continue;
      const proposalId = BigInt(f.proposalId);
      // Already captured elsewhere (e.g. a concurrent scan) → just clear the stale dead-letter.
      if (await this.store.hasTerminal(proposalId)) {
        await this.store.removeFailure(f.block, f.logIndex);
        continue;
      }
      // Re-drive. On STILL-failing, captureOne re-dead-letters (bumping attempts); on success it
      // persists the record and we clear the dead-letter here.
      await this.captureOne(proposalId, f.txHash, f.block, f.logIndex);
      if (await this.store.hasTerminal(proposalId)) {
        await this.store.removeFailure(f.block, f.logIndex);
      }
    }
  }
}
