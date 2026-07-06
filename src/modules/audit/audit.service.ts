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
import type { IQuorumCoSigner } from "./slash-consensus.js";
import {
  SlashLevel,
  PendingSlotCoSigner,
  buildQueueMessageHash,
  buildExecuteMessageHash,
  encodeProof,
} from "./slash-consensus.js";

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

/**
 * Slash severity for the credit-over-limit rule. Maps to the SP #329 SlashLevel enum: MINOR (=1),
 * which is 3-of-3 quorum in the N=3 bootstrap. This uint8 is the `level` passed to createProposal
 * AND the slashLevel bound into both the queue and execute co-sign preimages — they must agree.
 */
const SLASH_LEVEL_CREDIT_OVER_LIMIT = SlashLevel.MINOR;
const RULE_CREDIT_OVER_LIMIT = "credit-over-limit";
/** ROLE_DVT = keccak256("DVT") — the staking role lock the audit inspects. */
const ROLE_DVT = ethers.id("DVT");

export interface AuditDetection {
  operator: string;
  rule: string;
  proofHash: string;
  /** Real on-chain proposal id (decimal string), or null when unresolved (not filed / event absent). */
  proposalId: string | null;
  reason: string;
  detectedAt: number;
  /** Tx hash of the filed proposal, or null if the write failed / no wallet / cooldown-suppressed. */
  proposalTx: string | null;
  /** Tx hash of the STEP-1 queueSlashWithProof (armed executeSlash path), or null. */
  queueTx: string | null;
  /** Tx hash of the STEP-2 executeWithProof — the on-chain slash (armed path), or null. */
  executeTx: string | null;
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
  private readonly blsAggregatorAddress: string;
  private readonly gtokenStakingAddress: string;
  /** xPNTs token the credit-over-limit rule reads operator debt from (getDebt lives on the token). */
  private readonly apntsTokenAddress: string;
  /**
   * SECOND safety gate (increment 2). When false (default) a violation only FILES + ARCHIVES a
   * slash proposal; the two-step on-chain slash (queue → execute, quorum co-signed) fires only
   * when both auditEnabled AND this are true — so nothing is auto-slashed until explicitly enabled.
   */
  private readonly executeSlash: boolean;
  private readonly archive: IProofArchive;
  /** Quorum co-sign seam — default PendingSlotCoSigner (fails closed until SP assigns BLS slots). */
  private readonly coSigner: IQuorumCoSigner;
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
   * Maps stableKey → wall-clock of first handling so stale entries can be pruned (bounded).
   */
  private readonly proposedStableKeys = new Map<string, number>();
  /**
   * Cooldown clock, keyed on the COARSE `chainId|operator|rule` (block-independent), holding
   * the wall-clock of the last proposal ATTEMPT — an ongoing violation whose block advances
   * every tick is not re-attempted until cooldownMs elapses, even if every attempt reverts.
   * Pruned once an entry ages past cooldownMs (the cooldown has expired → entry is dead).
   */
  private readonly lastProposalAt = new Map<string, number>();
  /**
   * DURABLE (within-process) over-slash guard for the ARMED execute path, keyed on the COARSE
   * `chainId|operator|rule` (block-INDEPENDENT). Once a slash EXECUTES for an operator+rule, the
   * coarse key is recorded here and the on-chain queue+execute is NOT re-run for the same ongoing
   * condition — even after cooldownMs elapses and the violationBlock advances (which would mint a
   * fresh stableKey/proofHash/epoch every tick). The key is cleared when the operator is next
   * observed HEALTHY for that rule (condition resolved), so a genuinely NEW violation can slash
   * again. Complements the best-effort on-chain isSlashPending() (the cross-restart guard) and the
   * archive-before-execute ordering. The file-only proposal path is unaffected (keeps per-block dedup).
   */
  private readonly slashedCoarseKeys = new Set<string>();
  /** Hard ceiling on either dedup map's size — a defensive LRU-style cap against unbounded growth. */
  private static readonly MAX_DEDUP_ENTRIES = 10_000;
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
    @Optional() archive?: IProofArchive,
    /** Injected quorum co-signer; defaults to the deferred PendingSlotCoSigner (fails closed). */
    @Optional() coSigner?: IQuorumCoSigner
  ) {
    this.enabled = config.get<boolean>("auditEnabled") === true;
    this.intervalMs = config.get<number>("auditIntervalMs") ?? 60_000;
    this.cooldownMs = config.get<number>("auditCooldownMs") ?? 3_600_000;
    // Canonicalize every watched operator to its checksummed form ONCE at ingest. All downstream
    // identity/hash/key derivations (proofHash, stableKey, proposalId, proof.operator) then use the
    // identical canonical string, so two DVT nodes with differently-cased AUDIT_WATCHLIST entries
    // derive the SAME proofHash for the SAME violation (content-addressed cross-node dedup). Invalid
    // addresses are dropped with a warning rather than crashing the process.
    this.watchlist = (config.get<string[]>("auditWatchlist") ?? [])
      .map(a => a.trim())
      .filter(Boolean)
      .map(a => {
        try {
          return ethers.getAddress(a);
        } catch {
          this.logger.warn(`Audit: dropping invalid AUDIT_WATCHLIST entry "${a}" (not an address)`);
          return null;
        }
      })
      .filter((a): a is string => a !== null);
    this.creditThresholdBps = BigInt(config.get<number>("auditCreditThresholdBps") ?? 10_000);
    this.chainId = config.get<number>("auditChainId") ?? 11155111;
    this.registryAddress = config.get<string>("auditRegistryAddress") ?? "";
    this.superPaymasterAddress = config.get<string>("auditSuperPaymasterAddress") ?? "";
    this.dvtValidatorAddress = config.get<string>("auditDvtValidatorAddress") ?? "";
    this.blsAggregatorAddress = config.get<string>("auditBlsAggregatorAddress") ?? "";
    this.gtokenStakingAddress = config.get<string>("auditGtokenStakingAddress") ?? "";
    this.apntsTokenAddress = config.get<string>("auditApntsTokenAddress") ?? "";
    this.executeSlash = config.get<boolean>("auditExecuteSlash") === true;
    this.clock = clock ?? (() => Date.now());
    this.random = random ?? (() => Math.random());
    this.archive =
      archive ?? new LocalProofArchive(config.get<string>("auditProofDir") ?? "./audit-proofs");
    this.coSigner = coSigner ?? new PendingSlotCoSigner();

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
    if (!this.apntsTokenAddress) missing.push("AUDIT_APNTS_TOKEN_ADDRESS");
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
      ["AUDIT_APNTS_TOKEN_ADDRESS", this.apntsTokenAddress],
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
        `registry=${this.registryAddress} superPaymaster=${this.superPaymasterAddress} ` +
        `dvtValidator=${this.dvtValidatorAddress} blsAggregator=${this.blsAggregatorAddress} ` +
        `executeSlash=${this.executeSlash} (${this.executeSlash ? "two-step on-chain slash ARMED" : "file+archive ONLY"})`
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
   * Record a handled violation@block stable-key with the current wall-clock, keeping the map
   * bounded: entries past cooldownMs are pruned, and a hard LRU-style cap evicts the oldest if
   * the map somehow still overflows (defensive against pathological churn within one cooldown).
   */
  private recordStableKey(stableKey: string): void {
    this.proposedStableKeys.set(stableKey, this.clock());
    if (this.proposedStableKeys.size > AuditService.MAX_DEDUP_ENTRIES) {
      // Map iteration is insertion-ordered → the first key is the oldest inserted.
      const oldest = this.proposedStableKeys.keys().next().value;
      if (oldest !== undefined) this.proposedStableKeys.delete(oldest);
    }
  }

  private coarseKey(operator: string, rule: string): string {
    return `${this.chainId}|${operator}|${rule}`;
  }

  /**
   * Record that an on-chain slash EXECUTED for this operator+rule so the armed execute path does
   * not re-slash the same ongoing condition on later ticks. Bounded by a defensive LRU-style cap.
   */
  private markCoarseSlashed(coarseKey: string): void {
    this.slashedCoarseKeys.add(coarseKey);
    if (this.slashedCoarseKeys.size > AuditService.MAX_DEDUP_ENTRIES) {
      const oldest = this.slashedCoarseKeys.values().next().value;
      if (oldest !== undefined) this.slashedCoarseKeys.delete(oldest);
    }
  }

  /**
   * Clear the coarse over-slash guard once the operator is observed HEALTHY for a rule — the
   * violation has resolved, so a genuinely new future violation is allowed to slash again.
   */
  private clearCoarseSlashed(operator: string, rule: string): void {
    this.slashedCoarseKeys.delete(this.coarseKey(operator, rule));
  }

  /**
   * Evict dedup/cooldown entries that have aged past cooldownMs (they can no longer suppress
   * anything, so keeping them only leaks memory in the long-lived daemon). Called once per tick.
   */
  private pruneDedupState(): void {
    const now = this.clock();
    for (const [key, ts] of this.proposedStableKeys) {
      if (now - ts > this.cooldownMs) this.proposedStableKeys.delete(key);
    }
    for (const [key, ts] of this.lastProposalAt) {
      if (now - ts > this.cooldownMs) this.lastProposalAt.delete(key);
    }
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
    // Bound the dedup/cooldown maps so the long-lived daemon never leaks: drop entries that
    // have aged past cooldownMs (they can no longer suppress anything) before each sweep.
    this.pruneDedupState();
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

    // All per-operator reads are pinned to the SAME block; issue them concurrently (5-6 reads)
    // rather than serially. reputation + DVT stake lock are auxiliary evidence (not part of the
    // rule) → best-effort with a fallback so they never fail the audit.
    const [creditLimit, availableCredit, debt, reputation, dvtStake] = await Promise.all([
      this.blockchainService.getCreditLimit(this.registryAddress, operator, violationBlock),
      this.blockchainService.getAvailableCredit(
        this.superPaymasterAddress,
        operator,
        this.apntsTokenAddress,
        violationBlock
      ),
      // GENUINE over-limit needs the operator's ACTUAL debt, read directly (block-pinned).
      // getDebt is best-effort: null = getter absent / reverted → we CANNOT prove over-limit,
      // so we SKIP (fail-safe, no proposal) rather than inferring it from availableCredit==0.
      this.readOperatorDebt(operator, violationBlock),
      this.blockchainService
        .getGlobalReputation(this.registryAddress, operator, violationBlock)
        .catch(() => -1n),
      this.gtokenStakingAddress
        ? this.blockchainService.getRoleLockAmount(
            this.gtokenStakingAddress,
            operator,
            ROLE_DVT,
            violationBlock
          )
        : Promise.resolve(0n),
    ]);

    if (debt === null) {
      this.logger.debug(
        `Audit: ${operator} debt unreadable (getDebt reverted/absent) — SKIP (fail-safe)`
      );
      return;
    }

    // FAIL-SAFE: creditLimit == 0 means UNCONFIGURED / de-registered, NOT "over limit". Flagging
    // debt>0 against a zero limit would be an unconditional false positive → SKIP (never slash).
    if (creditLimit === 0n) {
      this.logger.debug(
        `Audit: ${operator} creditLimit=0 (unconfigured/de-registered) — SKIP (fail-safe, not over-limit)`
      );
      this.clearCoarseSlashed(operator, RULE_CREDIT_OVER_LIMIT);
      return;
    }
    // CROSS-CONTRACT AGREEMENT: both SuperPaymaster signals must agree before flagging. If
    // availableCredit > 0 the operator is still within SP's ENFORCED ceiling, so a lower/stale
    // Registry creditLimit must NOT produce a false over-limit → SKIP. Only when SP itself reports
    // the credit exhausted (availableCredit == 0) do we trust the debt>limit comparison.
    if (availableCredit > 0n) {
      this.logger.debug(
        `Audit: ${operator} availableCredit=${availableCredit}>0 (within SP ceiling) — SKIP (no false over-limit)`
      );
      this.clearCoarseSlashed(operator, RULE_CREDIT_OVER_LIMIT);
      return;
    }

    // STRICT credit-over-limit rule: flag ONLY a genuine breach where debt EXCEEDS the limit
    // (debt == creditLimit is AT the limit, not over → NOT a violation). creditThresholdBps is
    // an OPTIONAL additional margin on top: debt*10000/limit must also reach it (default 10000).
    // creditLimit > 0 is guaranteed above, so the ratio is always well-defined.
    const overLimit = debt > creditLimit;
    const usageBps = (debt * 10_000n) / creditLimit;

    if (!overLimit) {
      this.logger.debug(
        `Audit: ${operator} not over limit (debt=${debt} ≤ limit=${creditLimit}, usage=${usageBps}bps)`
      );
      this.clearCoarseSlashed(operator, RULE_CREDIT_OVER_LIMIT);
      return;
    }
    if (usageBps < this.creditThresholdBps) {
      this.logger.debug(
        `Audit: ${operator} over limit but under margin (usage=${usageBps}bps < ${this.creditThresholdBps}bps)`
      );
      this.clearCoarseSlashed(operator, RULE_CREDIT_OVER_LIMIT);
      return;
    }

    const observedAt = this.clock();
    const reason =
      `${RULE_CREDIT_OVER_LIMIT}: debt ${debt} EXCEEDS limit ${creditLimit} ` +
      `(usage ${usageBps}bps ≥ ${this.creditThresholdBps}bps, availableCredit ${availableCredit}, block ${violationBlock})`;
    const sources: EvidenceSource[] = [
      { type: "view", name: "Registry.getCreditLimit", value: creditLimit.toString(), block: violationBlock },
      {
        type: "view",
        name: `IxPNTsToken(${this.apntsTokenAddress}).getDebt`,
        value: debt.toString(),
        block: violationBlock,
      },
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
   * Best-effort operator debt read (block-pinned). Per the verified SP ABI, debt lives on the
   * xPNTs TOKEN (IxPNTsToken.getDebt(address)), NOT SuperPaymaster/Registry — so this reads the
   * aPNTs token directly. Returns null when the token's getDebt reverts / is absent — the caller
   * treats null as "unknown" and skips (never guesses an over-limit from missing data).
   */
  private async readOperatorDebt(operator: string, blockTag: number): Promise<bigint | null> {
    return this.blockchainService.getDebt(this.apntsTokenAddress, operator, blockTag);
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
    // DETERMINISTIC slash epoch = the violationBlock (an on-chain fact). Two DVT nodes observing
    // the SAME violation derive the SAME epoch, so their queue/execute co-sign preimages match and
    // the gossip BLS aggregate verifies. A wall-clock epoch (Math.floor(observedAt/1000)) would
    // diverge across nodes → divergent messageHashes → the aggregate would never verify on-chain.
    // observedAt stays a HUMAN-only field (already excluded from the content-address identity).
    const epoch = v.violationBlock;
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

    // ── DEDUP ─────────────────────────────────────────────────────────────────────
    const stableKey = `${this.chainId}|${v.operator}|${v.rule}|${v.violationBlock}`;
    const coarseKey = this.coarseKey(v.operator, v.rule);
    // Exact same violation@block already handled (this process, or on disk from a prior run).
    if (this.proposedStableKeys.has(stableKey) || (await this.archive.has(proofHash))) {
      this.logger.debug(
        `Audit: ${v.operator} ${v.rule}@${v.violationBlock} already proposed (proof ${proofHash}) — skip`
      );
      return null;
    }

    // Build the PRE-execution proof. The real proof.messageHash is the 8-field EXECUTE preimage,
    // which needs the REAL proposalId (only known AFTER createProposal) — so it is "0x" + a note
    // here and is filled in below once the proposal is filed. queueMessageHash (armed path) and
    // the co-sign material are also set post-orchestration.
    const proof: SlashProof = {
      version: "dvt-slash-proof/1",
      chainId: this.chainId,
      operator: v.operator,
      slashLevel: v.slashLevel,
      reason: v.reason,
      epoch,
      messageHash: "0x",
      messageHashNote: "pre-execution: proposalId not yet resolved",
      evidence: {
        rule: v.rule,
        observed: v.debt.toString(),
        threshold: v.creditLimit.toString(),
        sources: v.sources,
        violationBlock: v.violationBlock,
        observedAt: v.observedAt,
      },
      proposalId: null,
      signerMask: "0x",
      sigG2: "0x",
      proofHash,
      participants: [],
      proposer,
      penaltyAmount: "0",
      attestations: {},
      createdAt: this.clock(),
    };

    // ── ARCHIVE-BEFORE-EXECUTE (finding-5, evidence + intent durable first) ─────────
    // Persist the durable evidence + slash INTENT BEFORE any irreversible on-chain queue/execute,
    // so a crash mid-slash cannot lose the record. recordStableKey ONLY after a successful put so
    // an archive IO failure does not silently suppress a retry (the evidence-never-lost invariant).
    const { location } = await this.archive.put(proof);
    this.recordStableKey(stableKey);

    // ── COOLDOWN + OVER-SLASH GUARD gate the on-chain ATTEMPT (never the archival) ──
    // COOLDOWN: an ongoing violation whose block advances each tick must not re-send a tx every
    // interval (a persistently-reverting proposal would burn admin-wallet gas / churn nonces).
    const last = this.lastProposalAt.get(coarseKey);
    const withinCooldown = last !== undefined && this.clock() - last < this.cooldownMs;

    let proposalTx: string | null = null;
    let queueTx: string | null = null;
    let executeTx: string | null = null;
    let onchainProposalId: bigint | null = null;
    let proposalIdNote: string | undefined;

    if (withinCooldown) {
      this.logger.debug(
        `Audit: ${v.operator} ${v.rule} within cooldown (${this.clock() - (last as number)}ms < ` +
          `${this.cooldownMs}ms) — attempt suppressed, archiving evidence only`
      );
      proposalIdNote = "id-unresolved: proposal attempt suppressed by cooldown";
    } else if (this.executeSlash && (await this.isCoarseAlreadySlashed(coarseKey, v.operator))) {
      // ARMED path OVER-SLASH GUARD (finding-4/5): a slash already executed (in-memory) or is
      // pending on-chain for this operator+rule → do NOT queue/execute the same ongoing condition
      // again, even after cooldownMs with an advancing block. Evidence is still archived (above).
      this.logger.warn(
        `Audit: ${v.operator} ${v.rule} already slashed/pending — over-slash guard, on-chain slash SKIPPED`
      );
      proposalIdNote =
        "id-unresolved: operator already slashed/pending for this rule (over-slash guard)";
    } else {
      // Arm the cooldown on ATTEMPT (before the result) so a reverting tx still backs off.
      this.lastProposalAt.set(coarseKey, this.clock());
      // UNIFIED proposal filing (finding-6): both the armed (queue → create → execute) and the
      // file-only (create only) paths go through coordinateQuorumCoSign — one createProposalWith-
      // Evidence call site. Every step catches its own failure so the evidence stays archived and
      // the poll loop never crashes.
      const res = await this.coordinateQuorumCoSign({
        operator: v.operator,
        slashLevel: v.slashLevel,
        reason: v.reason,
        epoch,
        evidenceHash: proofHash,
      });
      proposalTx = res.proposalTx;
      onchainProposalId = res.proposalId;
      queueTx = res.queueTx;
      executeTx = res.executeTx;
      if (res.queueMessageHash) proof.queueMessageHash = res.queueMessageHash;
      if (executeTx !== null) {
        // A slash actually executed → arm the over-slash guard + record the real co-sign material.
        this.markCoarseSlashed(coarseKey);
        proof.signerMask = res.signerMask;
        proof.sigG2 = res.sigG2;
      }
      if (onchainProposalId === null) {
        proposalIdNote =
          proposalTx === null
            ? "id-unresolved: proposal write failed"
            : "id-unresolved: ProposalCreated event not found in receipt";
      }
    }

    // ── FINAL proof.messageHash = the 8-field EXECUTE preimage actually signed + submitted ──────
    // (finding-1) buildExecuteMessageHash(proposalId, operator, slashLevel, epoch, chainId,
    // evidenceHash=proofHash) — the SAME message the quorum co-signs and executeWithProof carries.
    // When the id is unresolved there is no on-chain proposal to sign over → "0x" + a clear note.
    const proposalId: string | null = onchainProposalId !== null ? onchainProposalId.toString() : null;
    if (onchainProposalId !== null) {
      proof.messageHash = buildExecuteMessageHash(
        onchainProposalId,
        v.operator,
        v.slashLevel,
        epoch,
        this.chainId,
        proofHash
      );
      delete proof.messageHashNote;
    } else {
      proof.messageHash = "0x";
      proof.messageHashNote = proposalIdNote ?? "id-unresolved: no on-chain proposal to sign over";
    }
    proof.proposalId = proposalId;
    if (proposalIdNote) proof.proposalIdNote = proposalIdNote;
    if (proposalTx) proof.proposalTx = proposalTx;
    if (queueTx) proof.queueTx = queueTx;
    if (executeTx) proof.executeTx = executeTx;

    // Update the archived proof with the on-chain results (idempotent overwrite on proofHash), so
    // the evidence now references the queue/execute txs of the slash it justified (finding-2).
    await this.archive.put(proof);
    this.logger.warn(
      `Audit: ${v.operator} VIOLATION ${v.rule} — proof ${proofHash} archived at ${location}` +
        (executeTx
          ? ` (SLASH executed ${executeTx})`
          : proposalTx
            ? ` (proposal ${proposalTx})`
            : " (proposal NOT filed)")
    );

    const detection: AuditDetection = {
      operator: v.operator,
      rule: v.rule,
      proofHash,
      proposalId,
      reason: v.reason,
      detectedAt: v.observedAt,
      proposalTx,
      queueTx,
      executeTx,
    };
    this.recentDetections.unshift(detection);
    if (this.recentDetections.length > AuditService.MAX_RECENT) {
      this.recentDetections.length = AuditService.MAX_RECENT;
    }
    return detection;
  }

  /**
   * Is a slash already in effect for this operator+rule? Checks the in-memory coarse guard first
   * (fast, within-process), then a best-effort on-chain pending-slash read (the durable, restart-
   * surviving signal). On the current SP the getter is absent so isSlashPending returns null →
   * unknown → falls back to the in-memory guard. A true on-chain flag is cached into the in-memory
   * guard so subsequent ticks short-circuit without another RPC.
   */
  private async isCoarseAlreadySlashed(coarseKey: string, operator: string): Promise<boolean> {
    if (this.slashedCoarseKeys.has(coarseKey)) return true;
    try {
      const pending = await this.blockchainService.isSlashPending(this.superPaymasterAddress, operator);
      if (pending === true) {
        this.markCoarseSlashed(coarseKey);
        return true;
      }
    } catch {
      // best-effort: getter absent / RPC error → unknown, rely on the in-memory guard only.
    }
    return false;
  }

  /**
   * The slash-consensus orchestration — the SINGLE createProposalWithEvidence call site for BOTH
   * the file-only and the armed (SP #329 two-step) paths. Runs in this exact order:
   *
   *   1. QUEUE    — (ARMED only) co-sign the 5-field queue preimage → queueSlashWithProof.
   *   2. PROPOSAL — createProposalWithEvidence(evidenceHash=proofHash) → the REAL proposal id,
   *                 binding the on-chain slash to the archived evidence. ALWAYS runs.
   *   3. EXECUTE  — (ARMED only) co-sign the 8-field execute preimage (bound to that real id +
   *                 evidenceHash) → executeWithProof (slash-only ⇒ repUsers/newScores empty).
   *                 Skipped when the proposal id is unresolved (a fabricated id would revert).
   *
   * When executeSlash is OFF (default) only step 2 runs — the file-only path: proposal filed +
   * evidence bound, nothing queued or slashed. Each step is wrapped: a co-sign or tx failure is
   * logged and swallowed so the caller still archives the evidence (evidence never lost) and the
   * poll loop never crashes. With the default PendingSlotCoSigner every co-sign throws (SP
   * validator slots pending the 24h timelock), so the armed path reduces to just the proposal.
   *
   * Returns the queue/proposal/execute tx hashes, the real proposalId, the queueMessageHash (armed
   * path, so the caller can archive the co-signed queue preimage), and the EXECUTE co-sign material
   * (signerMask hex + sigG2) — "0x"/"0x" unless a slash actually executed.
   *
   * TODO(inc-2 live): the real multi-node gossip BLS aggregation behind coSigner — collect peer
   * signatures over the messageHash, build the signerMask bitmap by SP-assigned validator slot,
   * aggregate into sigG2 — lands once SP hands out slots via registerBLSPublicKey.
   */
  async coordinateQuorumCoSign(args: {
    operator: string;
    slashLevel: number;
    reason: string;
    epoch: number;
    evidenceHash: string;
  }): Promise<{
    proposalTx: string | null;
    proposalId: bigint | null;
    queueTx: string | null;
    executeTx: string | null;
    queueMessageHash: string | null;
    signerMask: string;
    sigG2: string;
  }> {
    const { operator, slashLevel, reason, epoch, evidenceHash } = args;
    const armed = this.executeSlash;
    let queueTx: string | null = null;
    let proposalTx: string | null = null;
    let proposalId: bigint | null = null;
    let executeTx: string | null = null;
    let queueMessageHash: string | null = null;
    let signerMask = "0x";
    let sigG2 = "0x";

    // ── Step 1: QUEUE (ARMED only, quorum co-signed) ──────────────────────────────
    if (armed) {
      try {
        queueMessageHash = buildQueueMessageHash(operator, slashLevel, epoch, this.chainId);
        const cosign = await this.coSigner.coSign(queueMessageHash);
        const proof = encodeProof(cosign.signerMask, cosign.sigG2);
        queueTx = await this.blockchainService.queueSlashWithProof(
          this.dvtValidatorAddress,
          operator,
          slashLevel,
          epoch,
          proof
        );
        this.logger.warn(`Audit: ${operator} slash QUEUED (tx ${queueTx})`);
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        this.logger.error(
          `Audit: ${operator} slash queue step failed — ${msg} (evidence archived; slash not queued)`
        );
      }
    }

    // ── Step 2: file the proposal (ALWAYS — binds evidenceHash=proofHash) ──────────
    try {
      const res = await this.blockchainService.createProposalWithEvidence(
        this.dvtValidatorAddress,
        operator,
        slashLevel,
        reason,
        evidenceHash
      );
      proposalTx = res.txHash;
      proposalId = res.proposalId;
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      this.logger.error(`Audit: ${operator} createProposal failed — ${msg}`);
    }

    // ── Step 3: EXECUTE (ARMED only, quorum co-signed) — only with a REAL proposal id ──
    if (armed) {
      if (proposalId === null) {
        this.logger.error(
          `Audit: ${operator} slash execute SKIPPED — no real proposalId ` +
            `(createProposal failed or ProposalCreated absent); a fabricated id would revert`
        );
      } else {
        try {
          const execMsgHash = buildExecuteMessageHash(
            proposalId,
            operator,
            slashLevel,
            epoch,
            this.chainId,
            evidenceHash
          );
          const cosign = await this.coSigner.coSign(execMsgHash);
          const proof = encodeProof(cosign.signerMask, cosign.sigG2);
          executeTx = await this.blockchainService.executeSlashWithProof(
            this.dvtValidatorAddress,
            proposalId,
            [], // slash-only ⇒ no reputation users
            [], // slash-only ⇒ no reputation scores
            epoch,
            proof
          );
          // Record the EXECUTE co-sign material so the archived proof references the real slash.
          signerMask = ethers.toBeHex(cosign.signerMask);
          sigG2 = cosign.sigG2;
          this.logger.warn(
            `Audit: ${operator} slash EXECUTED (proposal ${proposalId}, tx ${executeTx})`
          );
        } catch (err: unknown) {
          const msg = err instanceof Error ? err.message : String(err);
          this.logger.error(
            `Audit: ${operator} slash execute step failed — ${msg} (evidence archived; slash not executed)`
          );
        }
      }
    }
    return { proposalTx, proposalId, queueTx, executeTx, queueMessageHash, signerMask, sigG2 };
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
