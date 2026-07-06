import {
  Inject,
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
import type { IQuorumCoSigner, CoSignRequest, CoSignVerifier } from "./slash-consensus.js";
import {
  SlashLevel,
  PendingSlotCoSigner,
  QUORUM_COSIGNER,
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
  /** Confirmation depth for the finalized-block fallback (finding-3, reorg-safe evidence). */
  private readonly finalityConfirmations: number;
  /** How far back to scan on-chain slash-executed events for the durable guard (finding-2). */
  private readonly slashLookbackBlocks: number;
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
    @Optional() @Inject(QUORUM_COSIGNER) coSigner?: IQuorumCoSigner
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
    this.finalityConfirmations = config.get<number>("auditFinalityConfirmations") ?? 12;
    this.slashLookbackBlocks = config.get<number>("auditSlashLookbackBlocks") ?? 50_000;
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
        this.logger.error(
          `Audit: getCode(${name}=${addr}) failed (${msg}) — DISABLED (fail-closed)`
        );
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
    // Wire the gossip quorum co-sign responder (inc-2 live). When the injected co-signer is the
    // live GossipQuorumCoSigner (armed node), hand it the independent violation verifier and let
    // it register its responder handler on GossipService, so this armed node re-verifies + co-signs
    // peer slash requests from first principles even if it never itself requests. A no-op on the
    // disarmed PendingSlotCoSigner default (no `arm` method).
    const armable = this.coSigner as Partial<{ arm: (v: CoSignVerifier) => void }>;
    if (typeof armable.arm === "function") {
      armable.arm(req => this.verifyViolationForCoSign(req));
      this.logger.log("DVT audit: gossip quorum co-sign responder ARMED");
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
   * Checksum-normalize a config address for the content-address identity so two DVT nodes with
   * differently-cased AUDIT_* addresses still derive the SAME proofHash (LOW). Falls back to the raw
   * string if it is not a valid address (bootstrap already gates existence, so this is defensive).
   */
  private normalizeAddress(addr: string): string {
    try {
      return ethers.getAddress(addr);
    } catch {
      return addr;
    }
  }

  /**
   * Record (in-memory only) that an on-chain slash EXECUTED for this operator+rule so the armed
   * execute path does not re-slash the same ongoing condition on later ticks. Bounded by a
   * defensive LRU-style cap. Durability across restart is handled separately via the archive
   * journal (recordCoarseSlashed / archive.recordSlashed).
   */
  private markCoarseSlashed(coarseKey: string): void {
    this.slashedCoarseKeys.add(coarseKey);
    if (this.slashedCoarseKeys.size > AuditService.MAX_DEDUP_ENTRIES) {
      const oldest = this.slashedCoarseKeys.values().next().value;
      if (oldest !== undefined) this.slashedCoarseKeys.delete(oldest);
    }
  }

  /**
   * Record an executed slash in BOTH the in-memory guard and the DURABLE archive journal
   * (finding-2), so an in-process restart reloads the marker and does not re-slash the same
   * sustained condition. The archive write is best-effort: a journal IO failure must not abort
   * the audit (the on-chain slash already happened; the in-memory guard still holds this run).
   */
  private async recordCoarseSlashed(coarseKey: string): Promise<void> {
    this.markCoarseSlashed(coarseKey);
    try {
      await this.archive.recordSlashed(coarseKey);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      this.logger.error(`Audit: failed to persist durable slashed marker ${coarseKey} — ${msg}`);
    }
  }

  /**
   * Clear the coarse over-slash guard (in-memory AND durable journal) once the operator is
   * observed HEALTHY for a rule — the violation has resolved, so a genuinely new future violation
   * is allowed to slash again. The durable removal is best-effort (a healthy read is not itself
   * safety-critical; the on-chain slash-executed scan remains as the conservative backstop).
   */
  private async clearCoarseSlashed(operator: string, rule: string): Promise<void> {
    const coarseKey = this.coarseKey(operator, rule);
    this.slashedCoarseKeys.delete(coarseKey);
    // A healthy read ALWAYS attempts the durable removal, regardless of the current executeSlash
    // setting. A durable marker written by an EARLIER armed run must be cleared even if the node is
    // now running disarmed — otherwise it would survive an armed→disarmed→armed restart cycle and,
    // since hasSlashed short-circuits before the on-chain scan, suppress a legitimate future slash
    // indefinitely (Codex R3 B-F3). removeSlashed on an absent key is a cheap best-effort no-op.
    try {
      await this.archive.removeSlashed(coarseKey);
    } catch {
      // best-effort — a stale durable marker is re-checked against the chain scan anyway.
    }
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
      // Resolve the finalized evidence block ONCE per tick and share it across every operator in
      // this sweep (PK perf finding): a healthy watchlist otherwise pays getViolationBlock's 1-4
      // RPC per operator. One finalized snapshot is also MORE consistent (all operators evaluated
      // against the same chain state) and cannot reorg. A failure here is a global RPC problem, not
      // per-operator, so skip the whole tick rather than hammering each operator into the same error.
      let pinnedBlock: { number: number; hash: string };
      try {
        pinnedBlock = await this.blockchainService.getViolationBlock(this.finalityConfirmations);
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        this.logger.error(`Audit: could not resolve finalized block — skipping tick (${msg})`);
        return;
      }
      for (const operator of this.watchlist) {
        try {
          await this.auditOperator(operator, pinnedBlock);
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
  async auditOperator(
    operator: string,
    pinnedBlock?: { number: number; hash: string }
  ): Promise<void> {
    // Pin EVERY rule input to ONE FINALIZED block (finding-3) so creditLimit, availableCredit and
    // debt can never be mixed across blocks (no phantom over-limit from a mid-read state change)
    // AND the block the irreversible slash is justified by cannot be undone by a reorg. The block
    // HASH is recorded in the evidence so the justification is pinned to a specific finalized block.
    // tick() resolves this ONCE and shares it across the sweep; a direct caller (tests) may omit it.
    const { number: violationBlock, hash: violationBlockHash } =
      pinnedBlock ?? (await this.blockchainService.getViolationBlock(this.finalityConfirmations));

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
      await this.clearCoarseSlashed(operator, RULE_CREDIT_OVER_LIMIT);
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
      await this.clearCoarseSlashed(operator, RULE_CREDIT_OVER_LIMIT);
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
      await this.clearCoarseSlashed(operator, RULE_CREDIT_OVER_LIMIT);
      return;
    }
    if (usageBps < this.creditThresholdBps) {
      this.logger.debug(
        `Audit: ${operator} over limit but under margin (usage=${usageBps}bps < ${this.creditThresholdBps}bps)`
      );
      await this.clearCoarseSlashed(operator, RULE_CREDIT_OVER_LIMIT);
      return;
    }

    const observedAt = this.clock();
    const reason =
      `${RULE_CREDIT_OVER_LIMIT}: debt ${debt} EXCEEDS limit ${creditLimit} ` +
      `(usage ${usageBps}bps ≥ ${this.creditThresholdBps}bps, availableCredit ${availableCredit}, block ${violationBlock})`;
    const sources: EvidenceSource[] = [
      {
        type: "view",
        name: "Registry.getCreditLimit",
        value: creditLimit.toString(),
        block: violationBlock,
      },
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
      {
        type: "view",
        name: "Registry.globalReputation",
        value: reputation.toString(),
        block: violationBlock,
      },
      {
        type: "view",
        name: "GTokenStaking.roleLocks(DVT)",
        value: dvtStake.toString(),
        block: violationBlock,
      },
    ];

    await this.handleViolation({
      operator,
      slashLevel: SLASH_LEVEL_CREDIT_OVER_LIMIT,
      reason,
      rule: RULE_CREDIT_OVER_LIMIT,
      creditLimit,
      availableCredit,
      debt,
      violationBlock,
      violationBlockHash,
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
   * Pure credit-over-limit predicate — the SINGLE rule decision shared by the audit tick's
   * detection (auditOperator) and the co-sign responder's independent re-confirmation
   * (verifyViolationForCoSign), so a peer confirms EXACTLY the condition the requester detected
   * (no rule drift). Mirrors the inline checks in auditOperator: null debt / creditLimit==0 /
   * availableCredit>0 / debt<=limit / under-margin all resolve to `false` (not a violation).
   */
  private isCreditOverLimit(
    creditLimit: bigint,
    availableCredit: bigint,
    debt: bigint | null
  ): boolean {
    if (debt === null) return false;
    if (creditLimit === 0n) return false;
    if (availableCredit > 0n) return false;
    if (!(debt > creditLimit)) return false;
    const usageBps = (debt * 10_000n) / creditLimit;
    if (usageBps < this.creditThresholdBps) return false;
    return true;
  }

  /**
   * The RESPONDER-side independent violation re-confirmation (inc-2 live). Given a peer's co-sign
   * request, re-read the operator's on-chain state PINNED at `epoch` (= the violationBlock) and
   * re-apply this node's OWN credit-over-limit rule, then re-derive the content-address. Returns
   * `{ confirmed, proofHash }`; the responder compares the proofHash against the request's
   * evidenceHash for the execute step (the innocent-operator defense). Fail-closed: an
   * un-watchlisted operator, a chain/level mismatch, an unreadable debt, or any RPC error resolves
   * to `{ confirmed: false, proofHash: null }` — this node then refuses to co-sign.
   */
  async verifyViolationForCoSign(
    req: CoSignRequest
  ): Promise<{ confirmed: boolean; proofHash: string | null }> {
    const NO = { confirmed: false, proofHash: null };
    try {
      // Bind to THIS node's chain + rule: a request for another chain or a slashLevel this node's
      // rule never assigns cannot be confirmed (the messageHash recompute already catches chain,
      // this is defense-in-depth + the queue-step level check).
      if (req.chainId !== this.chainId) return NO;
      if (req.slashLevel !== SLASH_LEVEL_CREDIT_OVER_LIMIT) return NO;

      let operator: string;
      try {
        operator = ethers.getAddress(req.operator);
      } catch {
        return NO;
      }
      if (!this.watchlist.includes(operator)) return NO;

      const blockTag = req.epoch;
      if (!Number.isInteger(blockTag) || blockTag < 0) return NO;

      // Re-read the SAME rule inputs the tick reads, pinned at the epoch block.
      const [creditLimit, availableCredit, debt] = await Promise.all([
        this.blockchainService.getCreditLimit(this.registryAddress, operator, blockTag),
        this.blockchainService.getAvailableCredit(
          this.superPaymasterAddress,
          operator,
          this.apntsTokenAddress,
          blockTag
        ),
        this.readOperatorDebt(operator, blockTag),
      ]);

      if (!this.isCreditOverLimit(creditLimit, availableCredit, debt)) return NO;

      // Re-read the pinned block's hash (part of the content-address, LOW). Fail closed if it
      // cannot be read — this node then cannot reproduce the requester's proofHash, so it refuses.
      const violationBlockHash = await this.blockchainService.getBlockHash(blockTag);
      if (!violationBlockHash) return NO;

      // Re-derive the content-address from the SAME on-chain identity (wall-clock-free), so it
      // equals the requester's proofHash for the identical violation. Every slash-critical input —
      // availableCredit, slashLevel, block hash, and the source contract/token addresses — is
      // committed, so evidenceHash is a full content address of exactly what would be slashed.
      const identity: ProofIdentity = {
        chainId: this.chainId,
        operator,
        rule: RULE_CREDIT_OVER_LIMIT,
        creditLimit: creditLimit.toString(),
        availableCredit: availableCredit.toString(),
        debt: (debt as bigint).toString(),
        violationBlock: blockTag,
        violationBlockHash,
        slashLevel: SLASH_LEVEL_CREDIT_OVER_LIMIT,
        registry: this.normalizeAddress(this.registryAddress),
        superPaymaster: this.normalizeAddress(this.superPaymasterAddress),
        dvtValidator: this.normalizeAddress(this.dvtValidatorAddress),
        apntsToken: this.normalizeAddress(this.apntsTokenAddress),
      };
      return { confirmed: true, proofHash: computeProofHash(identity) };
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      this.logger.warn(`verifyViolationForCoSign refused (indeterminate): ${msg}`);
      return NO;
    }
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
    availableCredit: bigint;
    debt: bigint;
    violationBlock: number;
    violationBlockHash: string;
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
      availableCredit: v.availableCredit.toString(),
      debt: v.debt.toString(),
      violationBlock: v.violationBlock,
      violationBlockHash: v.violationBlockHash,
      slashLevel: v.slashLevel,
      registry: this.normalizeAddress(this.registryAddress),
      superPaymaster: this.normalizeAddress(this.superPaymasterAddress),
      dvtValidator: this.normalizeAddress(this.dvtValidatorAddress),
      apntsToken: this.normalizeAddress(this.apntsTokenAddress),
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
        violationBlockHash: v.violationBlockHash,
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
    } else if (
      this.executeSlash &&
      (await this.isCoarseAlreadySlashed(coarseKey, v.operator, v.slashLevel, v.violationBlock))
    ) {
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
      // Pass the in-flight `proof` so coordinateQuorumCoSign RE-ARCHIVES it after each CONFIRMED
      // on-chain step (finding-4): a crash between a confirmed queue/execute tx and the final
      // archive below can no longer lose that tx record — durable state always reflects what was
      // actually submitted.
      const res = await this.coordinateQuorumCoSign(
        {
          operator: v.operator,
          slashLevel: v.slashLevel,
          reason: v.reason,
          epoch,
          evidenceHash: proofHash,
        },
        proof
      );
      proposalTx = res.proposalTx;
      onchainProposalId = res.proposalId;
      queueTx = res.queueTx;
      executeTx = res.executeTx;
      if (res.queueMessageHash) proof.queueMessageHash = res.queueMessageHash;
      if (executeTx !== null) {
        // A slash actually executed → arm the DURABLE over-slash guard (in-memory + archive journal,
        // finding-2) so a restart does not re-slash, and record the real co-sign material.
        await this.recordCoarseSlashed(coarseKey);
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

    // ── FINAL proof.messageHash = the 8-field EXECUTE preimage actually SUBMITTED ────────────────
    // (finding-1) buildExecuteMessageHash(proposalId, operator, slashLevel, epoch, chainId,
    // evidenceHash=proofHash) — the SAME message the quorum co-signs and executeWithProof carries.
    // (finding-5) messageHash is set ONLY when the execute tx actually landed. When the proposal id
    // resolved but NO execute was submitted (file-only path, or execute skipped/failed), the
    // computed-but-unsubmitted preimage is kept under intendedExecuteMessageHash — never conflated
    // with a submitted one. When the id is unresolved there is no preimage to compute at all → "0x".
    const proposalId: string | null =
      onchainProposalId !== null ? onchainProposalId.toString() : null;
    if (onchainProposalId !== null) {
      const executePreimage = buildExecuteMessageHash(
        onchainProposalId,
        v.operator,
        v.slashLevel,
        epoch,
        this.chainId,
        proofHash
      );
      if (executeTx !== null) {
        // The execute actually ran: this IS the submitted preimage.
        proof.messageHash = executePreimage;
        delete proof.messageHashNote;
        delete proof.intendedExecuteMessageHash;
      } else {
        // Proposal filed but nothing executed (file-only, or execute skipped/failed): the preimage
        // is only an INTENT, kept out of messageHash so the record is unambiguous (finding-5).
        proof.messageHash = "0x";
        proof.intendedExecuteMessageHash = executePreimage;
        proof.messageHashNote =
          proposalIdNote ??
          "intent-only: execute preimage computed but NOT submitted (see intendedExecuteMessageHash)";
      }
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
   * Is a slash already in effect for this operator+rule? Layered guards, cheapest → most durable:
   *
   *   1. IN-MEMORY coarse guard (fast, within-process).
   *   2. DURABLE archive journal (finding-2) — an executed-slash marker persisted to disk, so an
   *      in-process RESTART reloads it and does not re-slash a still-sustained violation. Cached
   *      back into the in-memory guard on a hit.
   *   3. ON-CHAIN slash-executed EVENTS (finding-2) — SlashExecutedWithProof / SlashExecuted within
   *      a recent block window on the BLSAggregator and SuperPaymaster. An emitted event is a
   *      permanent on-chain fact, so this is the authoritative, restart-surviving guard even if the
   *      local journal was lost. A hit is persisted to BOTH the durable journal and the memory guard.
   *   4. Best-effort on-chain PENDING flag (isSlashPending) — null ("unknown") on the current SP
   *      (private `_pendingSlash`), so it only helps a future deployment that exposes a getter.
   *   5. CONSERVATIVE fail-closed backstop — if the on-chain event scan was INDETERMINATE (provider
   *      error → null), there is no durable marker, AND the pending flag is ALSO indeterminate, we
   *      cannot positively confirm "not slashed". For an IRREVERSIBLE slash we then treat it as
   *      already-slashed and SKIP: better to miss a legitimate slash than risk a DOUBLE-slash when
   *      the chain state can't be read.
   *
   * `violationBlock` bounds the event scan window (`violationBlock - slashLookbackBlocks`); the scan
   * is narrowed to operator + `slashLevel`. A determinate remote read of "not slashed" lets the slash
   * proceed; an indeterminate read (provider error) fails CLOSED per (5) — never "safe to slash".
   */
  private async isCoarseAlreadySlashed(
    coarseKey: string,
    operator: string,
    slashLevel: number,
    violationBlock: number
  ): Promise<boolean> {
    if (this.slashedCoarseKeys.has(coarseKey)) return true;

    // (2) DURABLE journal — survives a restart within the same process/disk.
    try {
      if (await this.archive.hasSlashed(coarseKey)) {
        this.markCoarseSlashed(coarseKey); // cache in-memory (do not re-write the marker)
        return true;
      }
    } catch {
      // best-effort: journal read error → fall through to the on-chain scan.
    }

    // (3) ON-CHAIN slash-executed events — the authoritative cross-restart guard. A `null` from any
    // target means that scan was INDETERMINATE (provider error), tracked so (5) can fail closed.
    let scanIndeterminate = false;
    try {
      const fromBlock = Math.max(0, violationBlock - this.slashLookbackBlocks);
      const scanTargets = [this.blsAggregatorAddress, this.superPaymasterAddress].filter(Boolean);
      for (const target of scanTargets) {
        const hit = await this.blockchainService.getRecentSlashExecuted(
          target,
          operator,
          slashLevel,
          fromBlock
        );
        if (hit === true) {
          await this.recordCoarseSlashed(coarseKey); // persist durable + memory
          return true;
        }
        if (hit === null) scanIndeterminate = true; // provider error on this target — unconfirmable
      }
    } catch {
      // getRecentSlashExecuted threw (unexpected) → treat the whole scan as indeterminate.
      scanIndeterminate = true;
    }

    // (4) Best-effort on-chain pending flag (null/unknown on the current SP).
    let pendingIndeterminate = false;
    try {
      const pending = await this.blockchainService.isSlashPending(
        this.superPaymasterAddress,
        operator
      );
      if (pending === true) {
        this.markCoarseSlashed(coarseKey);
        return true;
      }
      if (pending === null) pendingIndeterminate = true; // no getter on this deployment → unknown
    } catch {
      pendingIndeterminate = true; // getter absent / RPC error → unknown
    }

    // (5) CONSERVATIVE fail-closed backstop. Reaching here means NO guard positively confirmed an
    // existing slash. If BOTH the on-chain event scan and the pending flag were indeterminate (and
    // there is no durable marker — else we'd have returned above), we have zero authoritative signal
    // that the operator is un-slashed. Fail CLOSED: skip the irreversible slash rather than risk a
    // double-slash on unreadable chain state. A determinate on-chain "not slashed" leaves
    // scanIndeterminate=false, so the normal armed path still slashes.
    if (scanIndeterminate && pendingIndeterminate) {
      this.logger.warn(
        `Audit: ${operator} slash-state INDETERMINATE (on-chain scan + pending flag both ` +
          `unavailable, no durable marker) — over-slash guard fails CLOSED, on-chain slash SKIPPED`
      );
      return true;
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
   *                 STRICTLY contingent on the TWO-STEP SAFETY (finding-1): it runs ONLY when the
   *                 queue step CONFIRMED (queueTx !== null) AND the proposal id resolved. If the
   *                 queue co-sign/tx failed, the whole slash aborts to file+archive only — a slash
   *                 must never execute without its confirmed queue pre-flag.
   *
   * When executeSlash is OFF (default) only step 2 runs — the file-only path: proposal filed +
   * evidence bound, nothing queued or slashed. Each step is wrapped: a co-sign or tx failure is
   * logged and swallowed so the caller still archives the evidence (evidence never lost) and the
   * poll loop never crashes. With the default PendingSlotCoSigner every co-sign throws (SP
   * validator slots pending the 24h timelock), so the armed path reduces to just the proposal.
   *
   * When `proof` is passed, it is RE-ARCHIVED after each CONFIRMED on-chain step (finding-4) so a
   * crash between a confirmed tx and the caller's final archive cannot lose that tx record.
   *
   * Returns the queue/proposal/execute tx hashes, the real proposalId, the queueMessageHash (armed
   * path, so the caller can archive the co-signed queue preimage), and the EXECUTE co-sign material
   * (signerMask hex + sigG2) — "0x"/"0x" unless a slash actually executed.
   *
   * TODO(inc-2 live): the real multi-node gossip BLS aggregation behind coSigner — collect peer
   * signatures over the messageHash, build the signerMask bitmap by SP-assigned validator slot,
   * aggregate into sigG2 — lands once SP hands out slots via registerBLSPublicKey.
   */
  async coordinateQuorumCoSign(
    args: {
      operator: string;
      slashLevel: number;
      reason: string;
      epoch: number;
      evidenceHash: string;
    },
    proof?: SlashProof
  ): Promise<{
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

    // Re-archive the in-flight proof after a CONFIRMED on-chain step (finding-4). Best-effort: a
    // journal IO error must not abort the orchestration (the on-chain tx already happened, and the
    // caller re-archives once more at the end). Idempotent on proofHash.
    const persistStep = async (): Promise<void> => {
      if (!proof) return;
      try {
        await this.archive.put(proof);
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        this.logger.error(`Audit: ${operator} per-step re-archive failed — ${msg}`);
      }
    };

    // ── Step 1: QUEUE (ARMED only, quorum co-signed) ──────────────────────────────
    if (armed) {
      try {
        queueMessageHash = buildQueueMessageHash(operator, slashLevel, epoch, this.chainId);
        const cosign = await this.coSigner.coSign({
          step: "queue",
          operator,
          slashLevel,
          epoch,
          chainId: this.chainId,
          evidenceHash,
          messageHash: queueMessageHash,
        });
        const encoded = encodeProof(cosign.signerMask, cosign.sigG2);
        queueTx = await this.blockchainService.queueSlashWithProof(
          this.dvtValidatorAddress,
          operator,
          slashLevel,
          epoch,
          encoded
        );
        this.logger.warn(`Audit: ${operator} slash QUEUED (tx ${queueTx})`);
        // Durable BEFORE execute: the confirmed queueTx is persisted now (finding-4).
        if (proof) {
          proof.queueTx = queueTx;
          proof.queueMessageHash = queueMessageHash;
          await persistStep();
        }
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

    // ── Step 3: EXECUTE (ARMED only) — TWO-STEP SAFETY: confirmed queue + real id required ──
    if (armed) {
      if (queueTx === null) {
        // finding-1: never execute a slash whose queue pre-flag did not confirm. Abort to
        // file+archive only — the evidence + proposal remain, but no irreversible slash fires.
        this.logger.error(
          `Audit: ${operator} slash execute SKIPPED — queue step did not confirm (queueTx null); ` +
            `two-step safety requires a confirmed queueSlashWithProof before executeWithProof`
        );
      } else if (proposalId === null) {
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
          const cosign = await this.coSigner.coSign({
            step: "execute",
            operator,
            slashLevel,
            epoch,
            chainId: this.chainId,
            proposalId: proposalId.toString(),
            evidenceHash,
            messageHash: execMsgHash,
          });
          const encoded = encodeProof(cosign.signerMask, cosign.sigG2);
          executeTx = await this.blockchainService.executeSlashWithProof(
            this.dvtValidatorAddress,
            proposalId,
            [], // slash-only ⇒ no reputation users
            [], // slash-only ⇒ no reputation scores
            epoch,
            encoded
          );
          // Record the EXECUTE co-sign material so the archived proof references the real slash.
          signerMask = ethers.toBeHex(cosign.signerMask);
          sigG2 = cosign.sigG2;
          this.logger.warn(
            `Audit: ${operator} slash EXECUTED (proposal ${proposalId}, tx ${executeTx})`
          );
          // Durable immediately after the irreversible slash confirms (finding-4). Set the SUBMITTED
          // execute preimage as messageHash TOGETHER with executeTx in this same write, so every
          // durable snapshot is internally consistent: a crash before the caller's final re-archive
          // can no longer persist executeTx with messageHash="0x". `execMsgHash` is the exact 8-field
          // preimage the quorum co-signed and executeWithProof carried (MEDIUM: executeTx+messageHash
          // archived together). The caller's final pass recomputes the identical value (idempotent).
          if (proof) {
            proof.executeTx = executeTx;
            proof.signerMask = signerMask;
            proof.sigG2 = sigG2;
            proof.messageHash = execMsgHash;
            delete proof.messageHashNote;
            delete proof.intendedExecuteMessageHash;
            await persistStep();
          }
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
