import {
  Injectable,
  Logger,
  Optional,
  OnApplicationBootstrap,
  OnApplicationShutdown,
} from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { ethers } from "ethers";
import { BlockchainService } from "../blockchain/blockchain.service.js";
import { CapabilityRegistry } from "../capability/capability-registry.service.js";
import type { IProofArchive, SlashProof, EvidenceSource } from "./proof-archive.js";
import { LocalProofArchive, computeProofHash } from "./proof-archive.js";

/**
 * DVT Phase 2 (目标2) — autonomous audit of SuperPaymaster operators, increment 1.
 *
 * Each DVT node independently watches a set of operators and, without any external
 * trigger, reads their on-chain credit / reputation / stake state every tick. When an
 * operator breaches a rule, the node archives a content-addressed slash proof and files
 * a slash proposal on the DVTValidator. That proposal is the seed of the slash consensus
 * the other DVT nodes converge on.
 *
 * Opt-in (AUDIT_ENABLED, default off). When disabled, onApplicationBootstrap logs disabled
 * and never schedules a tick. Like the price keeper, the first tick is phase-jittered across
 * [0, intervalMs) so redundant auditors that boot together don't file the same proposal in
 * the same window.
 *
 * INCREMENT-1 SCOPE: only the credit-over-limit rule + LocalProofArchive + proposal-intent.
 * DEFERRED (see coordinateQuorumCoSign / IpfsProofArchive):
 *   - increment 2: multi-node BLS quorum co-sign via gossip + BLSAggregator.verifyAndExecute;
 *     the offline (gossip-heartbeat) / deposit-insufficient / token-over-issue rules.
 *   - increment 3: IPFS pinning of proofs.
 */

/** Slash severity for the credit-over-limit rule (uint8 level passed to createProposal). */
const SLASH_LEVEL_CREDIT_OVER_LIMIT = 1;
const RULE_CREDIT_OVER_LIMIT = "credit-over-limit";
/** ROLE_DVT = keccak256("DVT") — the staking role lock the audit inspects. */
const ROLE_DVT = ethers.id("DVT");
const ABI = new ethers.AbiCoder();

export interface AuditDetection {
  operator: string;
  rule: string;
  proofHash: string;
  proposalId: string;
  reason: string;
  detectedAt: number;
  /** Tx hash of the filed proposal, or null if the write failed / no wallet. */
  proposalTx: string | null;
}

@Injectable()
export class AuditService implements OnApplicationBootstrap, OnApplicationShutdown {
  private readonly logger = new Logger(AuditService.name);

  private readonly enabled: boolean;
  private readonly intervalMs: number;
  private readonly watchlist: string[];
  private readonly creditThresholdBps: bigint;
  private readonly chainId: number;
  private readonly registryAddress: string;
  private readonly superPaymasterAddress: string;
  private readonly dvtValidatorAddress: string;
  private readonly gtokenStakingAddress: string;
  private readonly archive: IProofArchive;
  private readonly clock: () => number;
  private readonly random: () => number;

  private startupTimer: ReturnType<typeof setTimeout> | null = null;
  private timer: ReturnType<typeof setInterval> | null = null;
  private lastTickAt: number | null = null;
  /** Bounded ring of the most recent detections, newest first (for GET /audit/status). */
  private readonly recentDetections: AuditDetection[] = [];
  private static readonly MAX_RECENT = 20;

  constructor(
    private readonly blockchainService: BlockchainService,
    private readonly config: ConfigService,
    @Optional() capabilityRegistry?: CapabilityRegistry,
    /** Test seam: controls `Date.now()` so time-based logic is deterministic. */
    @Optional() clock?: () => number,
    /** Test seam: controls the startup phase jitter (default Math.random). */
    @Optional() random?: () => number,
    /** Test seam: injectable archive; defaults to a LocalProofArchive at auditProofDir. */
    @Optional() archive?: IProofArchive
  ) {
    this.enabled = config.get<boolean>("auditEnabled") === true;
    this.intervalMs = config.get<number>("auditIntervalMs") ?? 60_000;
    this.watchlist = (config.get<string[]>("auditWatchlist") ?? []).map(a => a.trim()).filter(Boolean);
    this.creditThresholdBps = BigInt(config.get<number>("auditCreditThresholdBps") ?? 10_000);
    this.chainId = config.get<number>("auditChainId") ?? 11155111;
    this.registryAddress = config.get<string>("auditRegistryAddress") ?? "";
    this.superPaymasterAddress = config.get<string>("auditSuperPaymasterAddress") ?? "";
    this.dvtValidatorAddress = config.get<string>("auditDvtValidatorAddress") ?? "";
    this.gtokenStakingAddress = config.get<string>("auditGtokenStakingAddress") ?? "";
    this.clock = clock ?? (() => Date.now());
    this.random = random ?? (() => Math.random());
    this.archive =
      archive ?? new LocalProofArchive(config.get<string>("auditProofDir") ?? "./audit-proofs");

    capabilityRegistry?.register({
      name: "audit",
      class: "infra-core",
      description:
        "DVT Phase 2 (目标2) — autonomous audit of SuperPaymaster operators → slash consensus (increment 1)",
      enabled: this.enabled,
    });
  }

  onApplicationBootstrap(): void {
    if (!this.enabled) {
      this.logger.log("DVT audit DISABLED (AUDIT_ENABLED!=true) — no operators watched");
      return;
    }
    if (this.watchlist.length === 0) {
      this.logger.warn("Audit: AUDIT_ENABLED=true but AUDIT_WATCHLIST is empty — nothing to watch");
      return;
    }
    if (!this.registryAddress || !this.superPaymasterAddress) {
      this.logger.warn(
        "Audit: AUDIT_ENABLED=true but AUDIT_REGISTRY_ADDRESS / AUDIT_SUPER_PAYMASTER_ADDRESS " +
          "not set — cannot read operator credit state, disabled"
      );
      return;
    }
    // Phase-jitter the first tick across [0, intervalMs) so redundant auditors that boot
    // together don't all file the same proposal in the same window.
    const jitterMs = this.computeJitterMs();
    this.startupTimer = setTimeout(() => {
      this.startupTimer = null;
      void this.tick().catch(e => this.logger.error(`Audit tick error: ${String(e)}`));
      this.timer = setInterval(
        () => void this.tick().catch(e => this.logger.error(`Audit tick error: ${String(e)}`)),
        this.intervalMs
      );
    }, jitterMs);
    this.logger.log(
      `DVT audit ENABLED — interval=${this.intervalMs}ms jitter=${jitterMs}ms ` +
        `watchlist=[${this.watchlist.join(", ")}] creditThreshold=${this.creditThresholdBps}bps ` +
        `registry=${this.registryAddress} superPaymaster=${this.superPaymasterAddress}`
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

  /** Startup phase offset in [0, intervalMs). Visible for testing. */
  computeJitterMs(): number {
    return Math.floor(this.random() * this.intervalMs);
  }

  /**
   * One audit cycle. Called on every interval tick. Never throws; per-operator errors
   * are logged and do not abort the sweep of the remaining operators.
   */
  async tick(): Promise<void> {
    this.lastTickAt = this.clock();
    for (const operator of this.watchlist) {
      try {
        await this.auditOperator(operator);
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        this.logger.error(`Audit: ${operator} audit failed — ${msg}`);
      }
    }
  }

  /**
   * Audit a single operator: read its credit / reputation / stake state and evaluate the
   * credit-over-limit rule. On a confirmed violation, archive a proof and file a proposal.
   */
  async auditOperator(operator: string): Promise<void> {
    const creditLimit = await this.blockchainService.getCreditLimit(this.registryAddress, operator);
    const availableCredit = await this.blockchainService.getAvailableCredit(
      this.superPaymasterAddress,
      operator
    );
    // Auxiliary evidence (not part of the credit rule): reputation + DVT stake lock.
    const reputation = await this.blockchainService
      .getGlobalReputation(this.registryAddress, operator)
      .catch(() => -1n);
    const dvtStake = this.gtokenStakingAddress
      ? await this.blockchainService.getRoleLockAmount(this.gtokenStakingAddress, operator, ROLE_DVT)
      : 0n;

    // Credit-over-limit rule: debt = creditLimit − availableCredit. usageBps = debt/limit.
    // Flag when usage ≥ threshold (default 10000 bps = availableCredit exhausted).
    const debt = creditLimit > availableCredit ? creditLimit - availableCredit : 0n;
    const usageBps =
      creditLimit > 0n ? (debt * 10_000n) / creditLimit : debt > 0n ? 10_001n : 0n;

    if (usageBps < this.creditThresholdBps) {
      this.logger.debug(
        `Audit: ${operator} within credit (usage=${usageBps}bps < ${this.creditThresholdBps}bps)`
      );
      return;
    }

    const observedAt = this.clock();
    const reason =
      `${RULE_CREDIT_OVER_LIMIT}: debt ${debt} of limit ${creditLimit} ` +
      `(usage ${usageBps}bps ≥ ${this.creditThresholdBps}bps, availableCredit ${availableCredit})`;
    const sources: EvidenceSource[] = [
      { type: "view", name: "Registry.getCreditLimit", value: creditLimit.toString() },
      {
        type: "view",
        name: "SuperPaymaster.getAvailableCredit",
        value: availableCredit.toString(),
      },
      { type: "view", name: "Registry.globalReputation", value: reputation.toString() },
      { type: "view", name: "GTokenStaking.roleLocks(DVT)", value: dvtStake.toString() },
    ];

    await this.handleViolation({
      operator,
      slashLevel: SLASH_LEVEL_CREDIT_OVER_LIMIT,
      reason,
      rule: RULE_CREDIT_OVER_LIMIT,
      observed: debt.toString(),
      threshold: creditLimit.toString(),
      sources,
      observedAt,
    });
  }

  /**
   * On a confirmed violation: build the evidence proof, content-address it, file the slash
   * proposal on the DVTValidator (proposal-intent), and archive the proof. The proof is
   * archived even if the on-chain write fails, so the evidence is never lost.
   */
  private async handleViolation(v: {
    operator: string;
    slashLevel: number;
    reason: string;
    rule: string;
    observed: string;
    threshold: string;
    sources: EvidenceSource[];
    observedAt: number;
  }): Promise<AuditDetection> {
    const epoch = Math.floor(v.observedAt / 1000);
    const proposer = this.blockchainService.getWalletAddress() ?? ethers.ZeroAddress;
    // Deterministic proposal id — the same operator+epoch+rule maps to one proposal.
    const proposalId = ethers.keccak256(
      ABI.encode(
        ["address", "uint256", "uint256", "string"],
        [v.operator, this.chainId, epoch, v.rule]
      )
    );
    // The message a DVT quorum would BLS-sign over the proposal (co-sign is increment 2).
    const messageHash = ethers.keccak256(
      ABI.encode(
        ["bytes32", "address", "uint8", "uint256"],
        [proposalId, v.operator, v.slashLevel, 0]
      )
    );

    const core = {
      version: "dvt-slash-proof/1" as const,
      chainId: this.chainId,
      operator: v.operator,
      slashLevel: v.slashLevel,
      reason: v.reason,
      epoch,
      messageHash,
      evidence: {
        rule: v.rule,
        observed: v.observed,
        threshold: v.threshold,
        sources: v.sources,
        observedAt: v.observedAt,
      },
    };
    const proofHash = computeProofHash(core);

    // File the slash proposal (proposal-INTENT). Best-effort: on failure (no wallet / revert)
    // the proof is still archived so the evidence survives for a later retry.
    let proposalTx: string | null = null;
    if (this.dvtValidatorAddress) {
      try {
        proposalTx = await this.blockchainService.createSlashProposal(
          this.dvtValidatorAddress,
          v.operator,
          v.slashLevel,
          v.reason
        );
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        this.logger.error(`Audit: ${v.operator} createProposal failed — ${msg}`);
      }
    } else {
      this.logger.warn(
        `Audit: ${v.operator} violated ${v.rule} but AUDIT_DVT_VALIDATOR_ADDRESS unset — proposal not filed`
      );
    }

    const proof: SlashProof = {
      ...core,
      proposalId,
      // Quorum co-sign fields are placeholders until increment 2.
      signerMask: "0x",
      sigG2: "0x",
      proofHash,
      participants: [],
      proposer,
      penaltyAmount: "0",
      attestations: {},
      createdAt: this.clock(),
      ...(proposalTx ? { executedTx: proposalTx } : {}),
    };

    const { location } = await this.archive.put(proof);
    this.logger.warn(
      `Audit: ${v.operator} VIOLATION ${v.rule} — proof ${proofHash} archived at ${location}` +
        (proposalTx ? ` (proposal ${proposalTx})` : " (proposal NOT filed)")
    );

    // TODO(increment-2): coordinateQuorumCoSign() — gossip the proposal to the other DVT
    // nodes, collect their BLS co-signatures into an aggregate, then submit through
    // BLSAggregator.verifyAndExecute to actually execute the slash. Deferred: needs the
    // gossip aggregation layer across DVT nodes.

    const detection: AuditDetection = {
      operator: v.operator,
      rule: v.rule,
      proofHash,
      proposalId,
      reason: v.reason,
      detectedAt: v.observedAt,
      proposalTx,
    };
    this.recentDetections.unshift(detection);
    if (this.recentDetections.length > AuditService.MAX_RECENT) {
      this.recentDetections.length = AuditService.MAX_RECENT;
    }
    return detection;
  }

  /**
   * TODO(increment-2): coordinate the multi-node BLS quorum co-sign over a filed proposal
   * and submit BLSAggregator.verifyAndExecute. Deferred — requires gossip aggregation across
   * DVT nodes. Kept as a named seam so the increment-1 flow already points at where it lands.
   */
  async coordinateQuorumCoSign(): Promise<never> {
    throw new Error("coordinateQuorumCoSign deferred to increment 2 (gossip BLS aggregation)");
  }

  /** Read-only status for GET /audit/status. No secrets. */
  async getStatus(): Promise<{
    enabled: boolean;
    intervalMs: number;
    watchlist: string[];
    lastTickAt: number | null;
    recentDetections: AuditDetection[];
    archivedProofCount: number;
  }> {
    let archivedProofCount = 0;
    try {
      archivedProofCount = await this.archive.count();
    } catch {
      archivedProofCount = -1;
    }
    return {
      enabled: this.enabled,
      intervalMs: this.intervalMs,
      watchlist: this.watchlist,
      lastTickAt: this.lastTickAt,
      recentDetections: this.recentDetections,
      archivedProofCount,
    };
  }
}
