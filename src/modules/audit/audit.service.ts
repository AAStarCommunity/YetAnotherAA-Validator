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
import type { IProofArchive, SlashProof, EvidenceSource, ProofIdentity } from "./proof-archive.js";
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

  private enabled: boolean;
  private readonly intervalMs: number;
  private readonly cooldownMs: number;
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
  /** Single-flight guard: a tick is skipped while a previous one is still running. */
  private tickInFlight = false;
  /**
   * Stable-key dedup for the SAME on-chain violation@block: `chainId|operator|rule|block`.
   * Prevents re-proposing/re-archiving the identical block's violation within a process.
   */
  private readonly proposedStableKeys = new Set<string>();
  /**
   * Cooldown clock, keyed on the COARSE `chainId|operator|rule` (block-independent), holding
   * the wall-clock of the last SUCCESSFUL proposal — an ongoing violation whose block advances
   * every tick is not re-proposed until cooldownMs elapses.
   */
  private readonly lastProposalAt = new Map<string, number>();
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
    this.cooldownMs = config.get<number>("auditCooldownMs") ?? 3_600_000;
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

  async onApplicationBootstrap(): Promise<void> {
    if (!this.enabled) {
      this.logger.log("DVT audit DISABLED (AUDIT_ENABLED!=true) — no operators watched");
      return;
    }
    if (this.watchlist.length === 0) {
      this.logger.warn("Audit: AUDIT_ENABLED=true but AUDIT_WATCHLIST is empty — nothing to watch");
      return;
    }
    // FAIL-CLOSED config validation. Every required contract address must be set explicitly
    // (no silent default → no cross-chain garbage) AND must exist on-chain. Any failure
    // DISABLES the audit rather than polling wrong/empty addresses and filing false slashes.
    const missing: string[] = [];
    if (!this.registryAddress) missing.push("AUDIT_REGISTRY_ADDRESS");
    if (!this.superPaymasterAddress) missing.push("AUDIT_SUPER_PAYMASTER_ADDRESS");
    if (!this.dvtValidatorAddress) missing.push("AUDIT_DVT_VALIDATOR_ADDRESS");
    if (missing.length > 0) {
      this.enabled = false;
      this.logger.error(
        `Audit: AUDIT_ENABLED=true but ${missing.join(", ")} not set — DISABLED (fail-closed)`
      );
      return;
    }
    if (!Number.isInteger(this.chainId) || this.chainId <= 0) {
      this.enabled = false;
      this.logger.error(`Audit: invalid AUDIT_CHAIN_ID=${this.chainId} — DISABLED (fail-closed)`);
      return;
    }
    // On-chain existence check: reject any address with no deployed code (wrong chain / typo).
    const toCheck: Array<[string, string]> = [
      ["AUDIT_REGISTRY_ADDRESS", this.registryAddress],
      ["AUDIT_SUPER_PAYMASTER_ADDRESS", this.superPaymasterAddress],
      ["AUDIT_DVT_VALIDATOR_ADDRESS", this.dvtValidatorAddress],
    ];
    if (this.gtokenStakingAddress) {
      toCheck.push(["AUDIT_GTOKEN_STAKING_ADDRESS", this.gtokenStakingAddress]);
    }
    for (const [name, addr] of toCheck) {
      let code = "0x";
      try {
        code = await this.blockchainService.getCode(addr);
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        this.enabled = false;
        this.logger.error(`Audit: getCode(${name}=${addr}) failed (${msg}) — DISABLED (fail-closed)`);
        return;
      }
      if (!code || code === "0x") {
        this.enabled = false;
        this.logger.error(
          `Audit: ${name}=${addr} has no on-chain code on chainId ${this.chainId} — DISABLED (fail-closed)`
        );
        return;
      }
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
    // Single-flight: if a previous tick is still running (slow RPC), skip this one rather
    // than overlapping sweeps that would double-read and race the dedup bookkeeping.
    if (this.tickInFlight) {
      this.logger.debug("Audit: tick already in-flight — skipping this interval");
      return;
    }
    this.tickInFlight = true;
    this.lastTickAt = this.clock();
    try {
      for (const operator of this.watchlist) {
        try {
          await this.auditOperator(operator);
        } catch (err: unknown) {
          const msg = err instanceof Error ? err.message : String(err);
          this.logger.error(`Audit: ${operator} audit failed — ${msg}`);
        }
      }
    } finally {
      this.tickInFlight = false;
    }
  }

  /**
   * Audit a single operator: read its credit / reputation / stake state and evaluate the
   * credit-over-limit rule. On a confirmed violation, archive a proof and file a proposal.
   */
  async auditOperator(operator: string): Promise<void> {
    // Pin EVERY rule input to ONE block so creditLimit, availableCredit and debt can never
    // be mixed across blocks (no phantom over-limit from a mid-read state change).
    const violationBlock = await this.blockchainService.getBlockNumber();

    const creditLimit = await this.blockchainService.getCreditLimit(
      this.registryAddress,
      operator,
      violationBlock
    );
    const availableCredit = await this.blockchainService.getAvailableCredit(
      this.superPaymasterAddress,
      operator,
      violationBlock
    );
    // GENUINE over-limit needs the operator's ACTUAL debt, read directly (block-pinned).
    // getDebt is best-effort: null = getter absent / reverted → we CANNOT prove over-limit,
    // so we SKIP (fail-safe, no proposal) rather than inferring it from availableCredit==0.
    const debt = await this.readOperatorDebt(operator, violationBlock);
    if (debt === null) {
      this.logger.debug(
        `Audit: ${operator} debt unreadable (getDebt reverted/absent) — SKIP (fail-safe)`
      );
      return;
    }

    // Auxiliary evidence (not part of the credit rule): reputation + DVT stake lock.
    const reputation = await this.blockchainService
      .getGlobalReputation(this.registryAddress, operator, violationBlock)
      .catch(() => -1n);
    const dvtStake = this.gtokenStakingAddress
      ? await this.blockchainService.getRoleLockAmount(
          this.gtokenStakingAddress,
          operator,
          ROLE_DVT,
          violationBlock
        )
      : 0n;

    // STRICT credit-over-limit rule: flag ONLY a genuine breach where debt EXCEEDS the limit
    // (debt == creditLimit is AT the limit, not over → NOT a violation). creditThresholdBps is
    // an OPTIONAL additional margin on top: debt*10000/limit must also reach it (default 10000).
    const overLimit = debt > creditLimit;
    const usageBps =
      creditLimit > 0n
        ? (debt * 10_000n) / creditLimit
        : debt > 0n
          ? this.creditThresholdBps // no limit but has debt → treat as over the margin
          : 0n;

    if (!overLimit) {
      this.logger.debug(
        `Audit: ${operator} not over limit (debt=${debt} ≤ limit=${creditLimit}, usage=${usageBps}bps)`
      );
      return;
    }
    if (usageBps < this.creditThresholdBps) {
      this.logger.debug(
        `Audit: ${operator} over limit but under margin (usage=${usageBps}bps < ${this.creditThresholdBps}bps)`
      );
      return;
    }

    const observedAt = this.clock();
    const reason =
      `${RULE_CREDIT_OVER_LIMIT}: debt ${debt} EXCEEDS limit ${creditLimit} ` +
      `(usage ${usageBps}bps ≥ ${this.creditThresholdBps}bps, availableCredit ${availableCredit}, block ${violationBlock})`;
    const sources: EvidenceSource[] = [
      { type: "view", name: "Registry.getCreditLimit", value: creditLimit.toString(), block: violationBlock },
      { type: "view", name: "SuperPaymaster.getDebt", value: debt.toString(), block: violationBlock },
      {
        type: "view",
        name: "SuperPaymaster.getAvailableCredit",
        value: availableCredit.toString(),
        block: violationBlock,
      },
      { type: "view", name: "Registry.globalReputation", value: reputation.toString(), block: violationBlock },
      { type: "view", name: "GTokenStaking.roleLocks(DVT)", value: dvtStake.toString(), block: violationBlock },
    ];

    await this.handleViolation({
      operator,
      slashLevel: SLASH_LEVEL_CREDIT_OVER_LIMIT,
      reason,
      rule: RULE_CREDIT_OVER_LIMIT,
      creditLimit,
      debt,
      violationBlock,
      sources,
      observedAt,
    });
  }

  /**
   * Best-effort operator debt read (block-pinned). Tries the SuperPaymaster credit-debt
   * system first, then the Registry. Returns null only when NEITHER exposes a readable
   * getDebt — the caller treats null as "unknown" and skips (never guesses an over-limit).
   */
  private async readOperatorDebt(operator: string, blockTag: number): Promise<bigint | null> {
    const fromSp = await this.blockchainService.getDebt(this.superPaymasterAddress, operator, blockTag);
    if (fromSp !== null) return fromSp;
    return this.blockchainService.getDebt(this.registryAddress, operator, blockTag);
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
    creditLimit: bigint;
    debt: bigint;
    violationBlock: number;
    sources: EvidenceSource[];
    observedAt: number;
  }): Promise<AuditDetection | null> {
    const epoch = Math.floor(v.observedAt / 1000); // human field only — NOT hashed.
    const proposer = this.blockchainService.getWalletAddress() ?? ethers.ZeroAddress;

    // Content-address IDENTITY = ON-CHAIN facts only (no wall-clock). Two DVT nodes seeing
    // the same violation at the same block derive the same proofHash + proposalId.
    const identity: ProofIdentity = {
      chainId: this.chainId,
      operator: v.operator,
      rule: v.rule,
      creditLimit: v.creditLimit.toString(),
      debt: v.debt.toString(),
      violationBlock: v.violationBlock,
    };
    const proofHash = computeProofHash(identity);
    // Deterministic proposal id from the same stable dedup key: chainId|operator|rule|block.
    const proposalId = ethers.keccak256(
      ABI.encode(
        ["uint256", "address", "string", "uint256"],
        [this.chainId, v.operator, v.rule, v.violationBlock]
      )
    );
    // The message a DVT quorum would BLS-sign over the proposal (co-sign is increment 2).
    const messageHash = ethers.keccak256(
      ABI.encode(
        ["bytes32", "address", "uint8", "uint256"],
        [proposalId, v.operator, v.slashLevel, 0]
      )
    );

    // ── DEDUP ─────────────────────────────────────────────────────────────────────
    const stableKey = `${this.chainId}|${v.operator}|${v.rule}|${v.violationBlock}`;
    const coarseKey = `${this.chainId}|${v.operator}|${v.rule}`;
    // (a) exact same violation@block already handled (this process, or on disk from a prior run).
    if (this.proposedStableKeys.has(stableKey) || (await this.archive.has(proofHash))) {
      this.logger.debug(
        `Audit: ${v.operator} ${v.rule}@${v.violationBlock} already proposed (proof ${proofHash}) — skip`
      );
      return null;
    }
    // (b) cooldown: an ongoing violation whose block advances each tick must not re-propose
    //     every interval. Only a SUCCESSFUL proposal arms the cooldown (see below).
    const last = this.lastProposalAt.get(coarseKey);
    if (last !== undefined && this.clock() - last < this.cooldownMs) {
      this.logger.debug(
        `Audit: ${v.operator} ${v.rule} within cooldown (${this.clock() - last}ms < ${this.cooldownMs}ms) — skip`
      );
      return null;
    }

    // File the slash proposal (proposal-INTENT). Best-effort: on failure (no wallet / revert)
    // the proof is still archived so the evidence survives for a later retry.
    let proposalTx: string | null = null;
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

    const proof: SlashProof = {
      version: "dvt-slash-proof/1",
      chainId: this.chainId,
      operator: v.operator,
      slashLevel: v.slashLevel,
      reason: v.reason,
      epoch,
      messageHash,
      evidence: {
        rule: v.rule,
        observed: v.debt.toString(),
        threshold: v.creditLimit.toString(),
        sources: v.sources,
        violationBlock: v.violationBlock,
        observedAt: v.observedAt,
      },
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
      ...(proposalTx ? { proposalTx } : {}),
    };

    // Mark this exact violation@block handled BEFORE archiving so a same-block re-tick can't
    // double-file; arm the coarse cooldown only when the proposal actually landed.
    this.proposedStableKeys.add(stableKey);
    if (proposalTx) this.lastProposalAt.set(coarseKey, this.clock());

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
