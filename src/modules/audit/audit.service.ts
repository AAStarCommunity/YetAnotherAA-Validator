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
import { BlockchainService, DRY_RUN_TX_SENTINEL } from "../blockchain/blockchain.service.js";
import { GossipService } from "../gossip/gossip.service.js";
import { CapabilityRegistry } from "../capability/capability-registry.service.js";
import type { IProofArchive, SlashProof, EvidenceSource, ProofIdentity } from "./proof-archive.js";
import { LocalProofArchive, computeProofHash, PROOF_SCHEMA_VERSION } from "./proof-archive.js";
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
/**
 * Rule ② offline detection. WARNING (=0) — the lowest severity (2-of-3 quorum in the N=3 bootstrap):
 * a node being offline is a recoverable operational fault, not malice, so it carries the lightest
 * penalty. Cleared when the operator is next seen online.
 */
const SLASH_LEVEL_OFFLINE = SlashLevel.WARNING;
const RULE_OFFLINE = "offline";
/**
 * Continuous-offline threshold — a VERSION-BOUND CONSTANT, NOT env (Codex/PK review M-2). It enters
 * the offline proofHash, so every DVT node MUST use the identical value or the content-address (and
 * thus the BLS quorum) diverges. A code constant tied to PROOF_SCHEMA_VERSION guarantees all
 * same-version nodes agree; tuning it is a deliberate versioned release, not a per-node env knob.
 * 10 minutes. (The effective window is this + the finality lag of the evidence block.)
 */
const OFFLINE_THRESHOLD_MS = 600_000;
/**
 * Rule ③ over-issue (CC-28). MINOR (3-of-3 quorum) — a community minting xPNTs beyond its governance
 * cap is a serious economic abuse, and the evidence is OBJECTIVE (on-chain isOverIssued() bool), so
 * the strict quorum is warranted. Slash SUBJECT = the token's communityOwner. Cleared when the token
 * is next seen within cap.
 */
const SLASH_LEVEL_OVER_ISSUE = SlashLevel.MINOR;
const RULE_OVER_ISSUE = "over-issue";
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
  /**
   * DRY-RUN drill (AUDIT_DRY_RUN). Only meaningful when ALSO armed (executeSlash). When true, the
   * full gossip quorum co-sign AND the staticCall preflight against the REAL contracts still run, but
   * the queue/execute broadcasts are SKIPPED (return the sentinel) and NO durable slashed marker is
   * written — so the drill proves the whole path end-to-end with zero real slash and is repeatable.
   */
  private readonly dryRun: boolean;
  /** Confirmation depth for the finalized-block fallback (finding-3, reorg-safe evidence). */
  private readonly finalityConfirmations: number;
  /** How far back to scan on-chain slash-executed events for the durable guard (finding-2). */
  private readonly slashLookbackBlocks: number;
  /** A1#6 — derive the effective watchlist from on-chain Registry role membership (opt-in). */
  private readonly roleDerive: boolean;
  /** bytes32 roleIds (keccak256 of the role NAMES from AUDIT_ROLE_IDS) to enumerate. */
  private readonly roleIds: string[];
  /** Event-scan lower bound (Registry deploy block) for the getRoleMembers fallback. */
  private readonly roleFromBlock: number;
  /** getLogs block-range per request for the role-event scan fallback. */
  private readonly roleLogChunk: number;
  /** How often to re-derive the on-chain role set (throttled — getLogs is heavy). */
  private readonly roleRefreshMs: number;
  /** Trust a Registry.getRoleMembers getter instead of the event scan (default off; Codex Medium-3). */
  private readonly roleUseGetter: boolean;
  /** A derived-ONLY operator is not slashed once the last success is older than this (Codex High-2). */
  private readonly roleMaxStaleMs: number;
  /** Rule ② offline detection — opt-in; audits gossip liveness of the watched operators. */
  private readonly offlineEnabled: boolean;
  /** Liveness source (GossipService.getLastSeen); null when gossip isn't wired → offline self-disables. */
  private readonly gossip: GossipService | null;
  /** Stable operator→nodeId cache (offline rule ②). A transient resolve failure keeps the cached
   *  nodeId so a still-relevant operator is never pruned from the gossip ledger on an RPC blip. */
  private readonly offlineNodeIdCache = new Map<string, string>();
  /** Rule ③ over-issue — opt-in; audits each community xPNTs token's on-chain isOverIssued() flag. */
  private readonly overIssueEnabled: boolean;
  /** Community xPNTs token addresses to check for over-issuance (checksummed at ingest). */
  private readonly xpntsTokens: string[];
  /** Last successfully-derived on-chain operator set (checksummed); UNIONed with the static list. */
  private derivedOperators: string[] = [];
  /** Wall-clock of the last SUCCESSFUL role derivation (null = never); drives freshness. */
  private lastRoleRefreshAt: number | null = null;
  /** Wall-clock of the last derivation ATTEMPT (success OR failure) — throttles getLogs frequency
   *  even under a request flood or persistent RPC failure (Codex Medium/Low). */
  private lastRoleAttemptAt: number | null = null;
  /** Single-flight guard: concurrent refresh callers await this one in-flight derivation. */
  private refreshInFlight: Promise<void> | null = null;
  /** True once role derivation has SUCCEEDED at least once — distinguishes "never derived" (fail to
   *  an empty set) from "derived, genuinely empty" so the former is never silently unaudited. */
  private roleDeriveSucceeded = false;
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
  /**
   * Stable keys whose ARMED co-sign aborted TRANSIENTLY (no gossip peers yet / quorum not reached).
   * The dedup gate bypasses these so the co-sign is re-attempted next tick even though the evidence
   * is already archived — a node that detects a violation before its gossip mesh is up must not lose
   * that block's slash forever. Cleared once the co-sign completes (queued / executed / dry-run).
   */
  private readonly coSignRetryKeys = new Set<string>();
  /**
   * COARSE-key (operator|rule) → the on-chain proposalId of an in-flight (queued, not yet executed)
   * slash. The proofHash carries `violationBlock`, so a SUSTAINED violation gets a NEW proofHash each
   * time the finalized block advances — the archived-proof reuse (keyed by proofHash) then misses the
   * prior proposal and a resume would file a fresh one every cooldown window. This coarse map lets a
   * later-block resume REUSE the original proposalId (no per-cooldown orphan). Set when createProposal
   * confirms, cleared when the slash executes. In-memory: a cross-restart cross-block resume falls back
   * to one fresh (bounded, harmless) proposal; the same-proof archived-incomplete resume still reuses.
   */
  private readonly pendingProposalIds = new Map<string, string>();
  /** Hard ceiling on either dedup map's size — a defensive LRU-style cap against unbounded growth. */
  private static readonly MAX_DEDUP_ENTRIES = 10_000;
  /** Bounded ring of the most recent detections, newest first (for GET /audit/status). */
  private readonly recentDetections: AuditDetection[] = [];
  /**
   * Cumulative monitoring counters (in-memory, since process start) — exposed via GET /audit/status
   * and mirrored to a structured `[AUDIT-EVENT] kind=…` log line at each outcome so ops can alert
   * either by scraping the log or polling the endpoint. NOT reset except on restart.
   */
  private readonly metrics = {
    detections: 0,
    slashesExecuted: 0,
    dryRunPassed: 0,
    coSignAborts: 0,
    overSlashSkips: 0,
    errors: 0,
  };

  /** Emit a structured, greppable monitoring event + bump the matching counter (best-effort). */
  private emitAuditEvent(
    kind:
      | "SLASH_EXECUTED"
      | "DRY_RUN_PASSED"
      | "COSIGN_ABORTED"
      | "OVER_SLASH_SKIP"
      | "ROLE_DERIVE_UNHEALTHY"
      | "ERROR",
    fields: Record<string, string | number | null | undefined>
  ): void {
    if (kind === "SLASH_EXECUTED") this.metrics.slashesExecuted++;
    else if (kind === "DRY_RUN_PASSED") this.metrics.dryRunPassed++;
    else if (kind === "COSIGN_ABORTED") this.metrics.coSignAborts++;
    else if (kind === "OVER_SLASH_SKIP") this.metrics.overSlashSkips++;
    else if (kind === "ERROR") this.metrics.errors++;
    const kv = Object.entries(fields)
      .filter(([, v]) => v !== undefined && v !== null)
      .map(([k, v]) => `${k}=${v}`)
      .join(" ");
    this.logger.warn(`[AUDIT-EVENT] kind=${kind} ${kv}`);
  }
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
    @Optional() @Inject(QUORUM_COSIGNER) coSigner?: IQuorumCoSigner,
    /** Liveness source for the offline rule (getLastSeen). Wired to GossipService; optional so a
     *  deployment/test without gossip simply can't run the offline rule (it self-disables). */
    @Optional() gossip?: GossipService
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
    this.dryRun = config.get<boolean>("auditDryRun") === true;
    this.finalityConfirmations = config.get<number>("auditFinalityConfirmations") ?? 12;
    this.slashLookbackBlocks = config.get<number>("auditSlashLookbackBlocks") ?? 50_000;
    this.roleDerive = config.get<boolean>("auditRoleDerive") === true;
    // Hash each role NAME ("DVT") to its bytes32 roleId (keccak256) — the config module keeps the
    // raw names to stay ethers-free; the hashing lives here where ethers is already a dependency.
    this.roleIds = (config.get<string[]>("auditRoleIds") ?? []).map(name => ethers.id(name));
    this.roleFromBlock = config.get<number>("auditRoleFromBlock") ?? 0;
    this.roleLogChunk = config.get<number>("auditRoleLogChunk") ?? 10_000;
    this.roleRefreshMs = config.get<number>("auditRoleRefreshMs") ?? 300_000;
    this.roleUseGetter = config.get<boolean>("auditRoleUseGetter") === true;
    this.roleMaxStaleMs = config.get<number>("auditRoleMaxStaleMs") ?? 900_000;
    this.offlineEnabled = config.get<boolean>("auditOfflineEnabled") === true;
    this.overIssueEnabled = config.get<boolean>("auditOverIssueEnabled") === true;
    this.xpntsTokens = (config.get<string[]>("auditXpntsTokens") ?? [])
      .map(a => a.trim())
      .filter(Boolean)
      .map(a => {
        try {
          return ethers.getAddress(a);
        } catch {
          this.logger.warn(`Audit: dropping invalid AUDIT_XPNTS_TOKENS entry "${a}"`);
          return null;
        }
      })
      .filter((a): a is string => a !== null);
    this.gossip = gossip ?? null;
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
    if (this.watchlist.length === 0 && !this.roleDerive) {
      this.logger.warn(
        "Audit: AUDIT_ENABLED=true but AUDIT_WATCHLIST is empty and AUDIT_ROLE_DERIVE!=true — nothing to watch"
      );
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
      let code: string;
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
    // A1#6 — eager first derivation so the startup log + first tick already see the on-chain set
    // (registry code was just confirmed above). Non-fatal: a failure keeps the empty set and the
    // first tick retries. When roleDerive is on but AUDIT_ROLE_IDS parsed to nothing, that's a
    // misconfig (nothing to enumerate) — warn.
    if (this.roleDerive && this.roleIds.length === 0) {
      this.logger.warn(
        "Audit: AUDIT_ROLE_DERIVE=true but AUDIT_ROLE_IDS is empty — no roles to enumerate"
      );
    } else if (this.roleDerive) {
      // FAIL-CLOSED: the event-scan fallback from block 0 is a genesis-wide getLogs DoS footgun
      // (Codex Medium-2). Require an explicit AUDIT_ROLE_FROM_BLOCK (the Registry deploy block) unless
      // the O(1) getter is enabled (which needs no scan window).
      if (!this.roleUseGetter && this.roleFromBlock === 0) {
        this.enabled = false;
        this.logger.error(
          "Audit: AUDIT_ROLE_DERIVE=true requires AUDIT_ROLE_FROM_BLOCK (the Registry deploy block) " +
            "for the event-scan — a from-genesis scan is a DoS footgun. Set it (or enable " +
            "AUDIT_ROLE_USE_GETTER against a Registry with getRoleMembers). DISABLED (fail-closed)."
        );
        return;
      }
      await this.refreshDerivedOperators(true);
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
    if (this.dryRun && !this.executeSlash) {
      // F2 (Codex #181): AUDIT_DRY_RUN only matters on the armed co-sign/slash path. When disarmed
      // the flag is a silent no-op — warn so a mis-set drill config is visible, not silently ignored.
      this.logger.warn(
        "AUDIT_DRY_RUN=true but AUDIT_EXECUTE_SLASH is not armed — DRY_RUN has NO effect " +
          "(the co-sign + staticCall path runs only when armed). Set AUDIT_EXECUTE_SLASH=true for the drill."
      );
    }
    this.logger.log(
      `DVT audit ENABLED — interval=${this.intervalMs}ms jitter=${jitterMs}ms ` +
        `watchlist=[${this.effectiveWatchlist().join(", ")}] ` +
        `(static=${this.watchlist.length}, roleDerive=${this.roleDerive ? `on:${this.derivedOperators.length}` : "off"}) ` +
        `creditThreshold=${this.creditThresholdBps}bps ` +
        `registry=${this.registryAddress} superPaymaster=${this.superPaymasterAddress} ` +
        `dvtValidator=${this.dvtValidatorAddress} blsAggregator=${this.blsAggregatorAddress} ` +
        `executeSlash=${this.executeSlash} (${
          this.executeSlash
            ? this.dryRun
              ? "DRY RUN — full co-sign + staticCall preflight, NO broadcast"
              : "two-step on-chain slash ARMED"
            : "file+archive ONLY"
        })`
    );
    // Armed, real-broadcast operators: surface the two double-slash residuals the DVT over-slash
    // guard can only PARTIALLY cover (they need operational sizing / an SP contract change — see
    // docs/RELEASE_TEST_CHECKLIST.md "double-slash residuals").
    if (this.executeSlash && !this.dryRun) {
      this.logger.warn(
        `DVT audit ARMED (real slash): the cross-node over-slash guard scans the last ` +
          `${this.slashLookbackBlocks} blocks (AUDIT_SLASH_LOOKBACK_BLOCKS). Size it to cover the ` +
          `worst-case node restart/offline horizon for a SUSTAINED violation — a peer slash that ages ` +
          `out of this window before a fresh node scans can be double-slashed. AUTHORITATIVE ` +
          `same-episode double-slash prevention requires the SuperPaymaster BLS execute path to carry ` +
          `the slash cooldown its owner path already has (executeSlashWithBLS lacks _slashCd) — tracked with @repo:sp.`
      );
    }
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
    // The slash for this coarse condition is EXECUTED (locally, durably, or observed on-chain — incl.
    // by a PEER). Drop any in-flight proposal id we were holding for reuse: it now points at an
    // executed proposal, so reusing it on a future pending resume would only staticCall-revert and
    // churn retries (Codex: stale-id poisoning). A future genuinely-new violation files a fresh one.
    this.pendingProposalIds.delete(coarseKey);
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
    // The operator is HEALTHY again → any in-flight proposal id we held is stale (the episode it
    // belonged to is over); drop it so a genuinely-new future violation files a fresh proposal rather
    // than reusing a dead id (Codex: stale-id poisoning on the healthy→re-offend path).
    this.pendingProposalIds.delete(coarseKey);
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
    // coSignRetryKeys clears on co-sign success; a permanently-partitioned node could still leak one
    // entry per finalized-block change. Coarse-cap it — the current block re-adds next tick if still
    // aborting, so dropping stale entries never loses a live retry.
    if (this.coSignRetryKeys.size > AuditService.MAX_DEDUP_ENTRIES) this.coSignRetryKeys.clear();
    // pendingProposalIds is keyed by coarse operator|rule (bounded by watchlist × rules) and clears on
    // execute; coarse-cap it defensively against operator churn. Dropping an entry only costs one fresh
    // proposal on the next resume (bounded, harmless) — never a lost slash.
    if (this.pendingProposalIds.size > AuditService.MAX_DEDUP_ENTRIES)
      this.pendingProposalIds.clear();
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
      // Resolved BEFORE the role refresh so membership is derived to the SAME block (Codex Medium-1).
      let pinnedBlock: { number: number; hash: string };
      try {
        pinnedBlock = await this.blockchainService.getViolationBlock(this.finalityConfirmations);
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        this.logger.error(`Audit: could not resolve finalized block — skipping tick (${msg})`);
        return;
      }
      // A1#6 — refresh the on-chain-derived operator set (throttled; no-op when roleDerive is off),
      // pinned to the SAME finalized block as the evidence. A derivation failure KEEPS the previous
      // set, so a transient RPC blip never silently empties the watchlist mid-sweep.
      await this.refreshDerivedOperators(false, pinnedBlock.number);
      // HEALTH (Codex High-2) — never let a role-derive deployment go SILENTLY unaudited. Surface a
      // loud, alertable event when the derived set has never been confirmed or has gone stale, so an
      // empty/stale watchlist reads as a monitored failure, not "all clear".
      if (this.roleDerive && !this.derivedSetIsFresh()) {
        const reason = !this.roleDeriveSucceeded ? "never-succeeded" : "stale";
        this.logger.warn(
          `Audit: on-chain role membership ${reason} — derived-only operators will NOT be slashed ` +
            `until it is freshly confirmed (static-listed operators unaffected)`
        );
        this.emitAuditEvent("ROLE_DERIVE_UNHEALTHY", {
          reason,
          derivedCount: this.derivedOperators.length,
          lastRoleRefreshAt: this.lastRoleRefreshAt,
        });
      }
      const operators = this.effectiveWatchlist();
      // Rule ② offline — maintain a STABLE operator→nodeId cache and push its nodeIds to the gossip
      // liveness ledger so it records ONLY audited operators' heartbeats (Codex: a Sybil can't exhaust
      // the cap). The cache is authoritative-per-operator: a transient getOperatorNodeId FAILURE keeps
      // the previously-resolved nodeId (Codex Medium: never prune a still-relevant operator on an RPC
      // blip), while an AUTHORITATIVE null (inactive / key rotated) drops it, and leaving the
      // watchlist drops it. Runs on the empty-
      // watchlist path too, so a drained set correctly clears the relevant set (Codex Low).
      if (this.offlineEnabled && this.gossip && this.blsAggregatorAddress) {
        const current = new Set(operators);
        for (const op of [...this.offlineNodeIdCache.keys()]) {
          if (!current.has(op)) this.offlineNodeIdCache.delete(op); // operator exited the watchlist
        }
        for (const operator of operators) {
          try {
            const nid = await this.blockchainService.getOperatorNodeId(
              this.blsAggregatorAddress,
              operator
            );
            if (nid) {
              this.offlineNodeIdCache.set(operator, nid); // active → update (self-heals a key rotation)
            } else {
              // AUTHORITATIVE null (inactive / no active slot / key rotated away) → DROP the stale
              // nodeId so we never audit under an old key nor reject the new node's heartbeats.
              this.offlineNodeIdCache.delete(operator);
            }
          } catch (err: unknown) {
            // TRANSIENT RPC failure (getOperatorNodeId throws) → KEEP the last-known nodeId.
            const msg = err instanceof Error ? err.message : String(err);
            this.logger.debug(`Audit: offline nodeId resolve failed for ${operator} — ${msg}`);
          }
        }
        this.gossip.setRelevantNodeIds(this.offlineNodeIdCache.values());
      }
      // Rule ③ over-issue — audits TOKENS (per community), INDEPENDENT of the operator set, so it runs
      // even when the operator watchlist is empty. One token's failure never skips another.
      if (this.overIssueEnabled) {
        for (const token of this.xpntsTokens) {
          try {
            await this.auditOverIssueForToken(token, pinnedBlock);
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            this.logger.error(`Audit: over-issue audit failed for token ${token} — ${msg}`);
            this.emitAuditEvent("ERROR", { operator: token, error: msg });
          }
        }
      }
      if (operators.length === 0) {
        this.logger.debug("Audit: no operators to watch this tick (static + derived both empty)");
        return;
      }
      for (const operator of operators) {
        try {
          await this.auditOperator(operator, pinnedBlock);
        } catch (err: unknown) {
          const msg = err instanceof Error ? err.message : String(err);
          this.logger.error(`Audit: ${operator} audit failed — ${msg}`);
          this.emitAuditEvent("ERROR", { operator, error: msg });
        }
        // Rule ② offline — independent of the credit rule: one rule's failure must not skip the other.
        if (this.offlineEnabled) {
          try {
            await this.auditOfflineForOperator(
              operator,
              pinnedBlock,
              this.offlineNodeIdCache.get(operator)
            );
          } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            this.logger.error(`Audit: ${operator} offline audit failed — ${msg}`);
            this.emitAuditEvent("ERROR", { operator, error: msg });
          }
        }
      }
    } finally {
      this.tickInFlight = false;
    }
  }

  /**
   * A1#6 — the operators actually audited this tick: the static AUDIT_WATCHLIST UNIONed with the
   * on-chain-derived role set (both checksummed at ingest). The static list is an additive manual
   * override — it never SUBTRACTS from the derived set. Deduped so an operator that is both listed
   * and on-chain-registered is audited once.
   */
  private effectiveWatchlist(): string[] {
    if (this.derivedOperators.length === 0) return this.watchlist;
    if (this.watchlist.length === 0) return this.derivedOperators;
    return [...new Set([...this.watchlist, ...this.derivedOperators])];
  }

  /**
   * A1#6 (Codex High-2) — the derived set is FRESH when derivation has SUCCEEDED at least once AND
   * the last success is within roleMaxStaleMs. When roleDerive is off there are no derived operators,
   * so freshness is N/A → true. A stale set means the on-chain membership we hold may no longer match
   * reality (a member could have exited since), so it must not drive an irreversible slash.
   */
  private derivedSetIsFresh(): boolean {
    if (!this.roleDerive) return true;
    return (
      this.roleDeriveSucceeded &&
      this.lastRoleRefreshAt !== null &&
      this.clock() - this.lastRoleRefreshAt <= this.roleMaxStaleMs
    );
  }

  /**
   * A1#6 (Codex round-3) — AUTHORITATIVE per-operator slash gate, pinned to the evidence block. The
   * cached derived set is a snapshot from an EARLIER finalized block (throttled refresh), so before an
   * IRREVERSIBLE slash we confirm the specific operator STILL holds an audited role AT the evidence
   * block via a cheap `Registry.hasRole` eth_call — closing the "membership block ≠ evidence block"
   * gap without re-scanning events every tick/request.
   *   • static-listed operator → always slashable (explicitly chosen; may not hold any role).
   *   • derived-only operator  → the SET must be fresh (derivedSetIsFresh) AND the operator must hold
   *     one of the audited roles at `blockTag` (hasRole). A member who exited between the cached
   *     derivation and the evidence block reads hasRole=false there → NOT slashed.
   * Any read error → fail-closed (unconfirmable membership must not authorize a slash).
   */
  private async confirmSlashableAtBlock(operator: string, blockTag: number): Promise<boolean> {
    if (this.watchlist.includes(operator)) return true;
    if (!this.derivedSetIsFresh()) return false;
    for (const roleId of this.roleIds) {
      try {
        if (
          await this.blockchainService.hasRole(this.registryAddress, roleId, operator, blockTag)
        ) {
          return true;
        }
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        this.logger.warn(
          `Audit: hasRole(${roleId}) check failed for ${operator} @${blockTag} — fail-closed (${msg})`
        );
        return false;
      }
    }
    return false; // not a member of any audited role at the evidence block
  }

  /**
   * A1#6 — refresh the on-chain-derived operator set, throttled to roleRefreshMs. Enumerates the
   * CURRENT members of every configured role from the Registry (getRoleMembers getter-first, role-
   * event reconstruction fallback) and caches them checksummed. On ANY derivation error the PREVIOUS
   * set is KEPT (never shrunk to empty on a transient RPC blip).
   *
   * Throttled by lastRoleAttemptAt — updated on BOTH success AND failure (Codex Medium/Low) — so a
   * peer flooding co-sign requests (each of which calls this) or a persistent RPC failure cannot
   * drive getLogs faster than roleRefreshMs. A SINGLE-FLIGHT guard (refreshInFlight) collapses truly
   * concurrent calls onto one derivation, so a later-block result can't be overwritten by an
   * in-flight earlier one. Freshness (derivedSetIsFresh) is driven by lastRoleRefreshAt (success
   * only). No-op when roleDerive is off or no roles are configured. `force` bypasses the throttle
   * (eager bootstrap). `pinnedToBlock` (the tick's finalized evidence block) aligns the membership
   * snapshot with the evidence (Codex Medium-1); omitted callers resolve their own finalized block.
   */
  private async refreshDerivedOperators(force = false, pinnedToBlock?: number): Promise<void> {
    if (!this.roleDerive || this.roleIds.length === 0) return;
    const now = this.clock();
    // Single-flight FIRST (Codex round-3): a caller must never proceed on a half-updated set while a
    // derivation is actively running — await it, then use its fresh result. Checked BEFORE the
    // throttle so a throttled caller still waits out an in-flight refresh rather than racing ahead.
    if (this.refreshInFlight) {
      await this.refreshInFlight;
      return;
    }
    // Throttle by ATTEMPT time (success or failure) so failures/floods can't hammer getLogs.
    if (
      !force &&
      this.lastRoleAttemptAt !== null &&
      now - this.lastRoleAttemptAt < this.roleRefreshMs
    ) {
      return;
    }
    this.lastRoleAttemptAt = now;
    this.refreshInFlight = this.doRefreshDerivedOperators(now, pinnedToBlock);
    try {
      await this.refreshInFlight;
    } finally {
      this.refreshInFlight = null;
    }
  }

  /** The actual derivation (guarded by refreshDerivedOperators' throttle + single-flight). */
  private async doRefreshDerivedOperators(now: number, pinnedToBlock?: number): Promise<void> {
    try {
      // Derive membership up to the SAME FINALIZED block violations are evaluated at (Codex Medium-1):
      // an unfinalized head RoleExited/Registered must not add/drop an operator relative to the
      // evidence, and a reorg must not flip the set after use. Reuse the tick's pinned block when
      // given (also saves an RPC); otherwise resolve our own finalized block.
      const toBlock =
        pinnedToBlock ??
        (await this.blockchainService.getViolationBlock(this.finalityConfirmations)).number;
      const members = await this.blockchainService.getRegisteredOperators(
        this.registryAddress,
        this.roleIds,
        this.roleFromBlock,
        toBlock,
        this.roleLogChunk,
        this.roleUseGetter
      );
      const canonical: string[] = [];
      for (const m of members) {
        try {
          canonical.push(ethers.getAddress(m));
        } catch {
          this.logger.warn(`Audit: dropping invalid on-chain operator "${m}" (not an address)`);
        }
      }
      this.derivedOperators = canonical;
      this.lastRoleRefreshAt = now;
      this.roleDeriveSucceeded = true;
      this.logger.log(
        `Audit: derived ${canonical.length} operator(s) from ${this.roleIds.length} on-chain role(s) ` +
          `@finalized block ${toBlock}`
      );
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      // KEEP the previous derivedOperators — a transient getLogs failure must NOT empty the watchlist.
      // lastRoleRefreshAt is left unchanged (freshness decays → derived-only slashing withheld once
      // stale), but lastRoleAttemptAt WAS updated so failures don't spin getLogs.
      this.logger.warn(
        `Audit: on-chain role derivation failed (${msg}) — keeping previous derived set ` +
          `(${this.derivedOperators.length} operator(s))`
      );
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
   * Rule ② offline detection (inc-1) for ONE operator, pinned to the same finalized block as the
   * credit sweep. Bridges the on-chain slash target (operator) to off-chain liveness:
   *   operator → BLSAggregator.getBLSPublicKey → nodeId=keccak256(EIP-2537 key) → gossip getLastSeen.
   * OFFLINE ⇔ this node last heard the nodeId's heartbeat MORE than offlineThresholdMs before the
   * finalized block's ON-CHAIN timestamp (a globally-consistent deadline — every DVT node computes the
   * SAME deadline from the SAME block, so the content-address is deterministic). The proof carries NO
   * per-node data (no lastSeen), only (operator, block, threshold), so all nodes reproduce the same
   * proofHash. inc-1 files a proposal + archives the proof; the armed BLS co-sign is inc-2.
   *
   * Fail-SAFE at every uncertainty: offline disabled, no gossip/aggregator, operator holds no active
   * slot, NEVER-seen node (no lastSeen → can't prove offline-since-T), or an unreadable block → SKIP
   * (never fabricate an offline violation). A healthy (online) read CLEARS any coarse slashed marker.
   */
  private async auditOfflineForOperator(
    operator: string,
    pinnedBlock: { number: number; hash: string },
    preResolvedNodeId?: string
  ): Promise<void> {
    if (!this.offlineEnabled || !this.gossip || !this.blsAggregatorAddress) return;

    // Reuse the nodeId the tick already resolved (for the gossip relevant-set push) to avoid a second
    // on-chain read; fall back to resolving here for a direct caller (tests).
    const nodeId =
      preResolvedNodeId ??
      (await this.blockchainService.getOperatorNodeId(this.blsAggregatorAddress, operator));
    if (!nodeId) return; // operator holds no ACTIVE BLS slot → nothing to bind/slash

    const lastSeen = this.gossip.getLastSeen(nodeId);
    if (lastSeen === null) return; // never observed → cannot prove "offline since T" (fail-safe)

    // Deadline anchored to the finalized block's ON-CHAIN timestamp (seconds → ms), NOT wall-clock,
    // so every node computes the same threshold. A read failure fails safe (skip this operator).
    let blockTsSec: number;
    try {
      blockTsSec = await this.blockchainService.getBlockTimestamp(pinnedBlock.number);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      this.logger.warn(
        `Audit: offline block-timestamp read failed for block ${pinnedBlock.number} (${msg})`
      );
      return;
    }
    // CLOCK-SANITY gate (Codex High-2) — lastSeen is stamped with THIS node's wall clock (Date.now at
    // heartbeat), but the deadline is chain time. A local clock running BEHIND the (already-past,
    // finalized) evidence block is broken and would age every heartbeat too far into the past → FALSE
    // offline. If our clock is earlier than a block that has already finalized, refuse to trust local
    // timestamps this tick (fail-safe skip). (A clock running AHEAD only SUPPRESSES offline — safe.)
    // NB: because the block is FINALIZED (~finality lag behind head), the EFFECTIVE offline window is
    // (finality lag + offlineThresholdMs) — deliberately conservative, which also absorbs sub-lag skew.
    if (this.clock() < blockTsSec * 1000) {
      this.logger.warn(
        `Audit: offline SKIP for ${operator} — local clock (${this.clock()}) is behind the finalized ` +
          `evidence block time (${blockTsSec * 1000}); refusing to trust local liveness timestamps`
      );
      return;
    }
    const deadlineMs = blockTsSec * 1000 - OFFLINE_THRESHOLD_MS;

    if (lastSeen >= deadlineMs) {
      // ONLINE (or within the threshold) — the operator is live; clear any prior offline marker so a
      // future genuine offline can slash again, and stop.
      await this.clearCoarseSlashed(operator, RULE_OFFLINE);
      return;
    }

    // OFFLINE violation. DETERMINISTIC identity — no lastSeen (would diverge across observers).
    const identity: ProofIdentity = {
      proofSchemaVersion: PROOF_SCHEMA_VERSION,
      chainId: this.chainId,
      operator,
      rule: RULE_OFFLINE,
      violationBlock: pinnedBlock.number,
      slashLevel: SLASH_LEVEL_OFFLINE,
      registry: this.normalizeAddress(this.registryAddress),
      dvtValidator: this.normalizeAddress(this.dvtValidatorAddress),
      offlineThresholdMs: OFFLINE_THRESHOLD_MS,
      blsAggregator: this.normalizeAddress(this.blsAggregatorAddress),
    };
    const offlineForMs = blockTsSec * 1000 - lastSeen;
    const reason =
      `${RULE_OFFLINE}: nodeId ${nodeId} last heartbeat ${offlineForMs}ms before finalized block ` +
      `${pinnedBlock.number} (> threshold ${OFFLINE_THRESHOLD_MS}ms)`;
    this.logger.warn(reason);
    // observedAt / lastSeen are HUMAN-only forensics in `sources` (excluded from the content-address).
    const sources: EvidenceSource[] = [
      {
        type: "view",
        name: "gossip.getLastSeen(nodeId)",
        value: `${lastSeen} (nodeId ${nodeId})`,
        block: pinnedBlock.number,
      },
      {
        type: "view",
        name: "block.timestamp",
        value: `${blockTsSec}s`,
        block: pinnedBlock.number,
      },
    ];
    await this.handleViolation({
      operator,
      slashLevel: SLASH_LEVEL_OFFLINE,
      reason,
      rule: RULE_OFFLINE,
      violationBlock: pinnedBlock.number,
      violationBlockHash: pinnedBlock.hash,
      sources,
      observedAt: this.clock(),
      identity,
      observed: `offline ${offlineForMs}ms`,
      threshold: `${OFFLINE_THRESHOLD_MS}ms`,
    });
  }

  /**
   * Rule ③ over-issue (CC-28) for ONE community xPNTs token, pinned to the finalized block. Reads the
   * token's OBJECTIVE on-chain isOverIssued() flag (issued value > governance effectiveCap). On true,
   * the SLASH SUBJECT is the token's communityOwner (the community that minted beyond its cap). The
   * evidence is a deterministic on-chain bool → every DVT node agrees → SAFELY quorum-slashable
   * (unlike gossip-offline). Fail-SAFE: over-issue disabled, an isOverIssued/communityOwner read
   * error, or a null owner → SKIP (never fabricate). A within-cap read CLEARS any coarse marker.
   */
  private async auditOverIssueForToken(
    token: string,
    pinnedBlock: { number: number; hash: string }
  ): Promise<void> {
    if (!this.overIssueEnabled) return;

    let over: boolean;
    try {
      over = await this.blockchainService.getIsOverIssued(token, pinnedBlock.number);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      this.logger.warn(`Audit: over-issue isOverIssued read failed for token ${token} — ${msg}`);
      return;
    }

    // The communityOwner is the slash subject — read it at the SAME block so the subject is pinned.
    const owner = await this.blockchainService.getCommunityOwner(token, pinnedBlock.number);
    if (!owner) return; // can't identify the subject → skip (fail-safe)

    if (!over) {
      await this.clearCoarseSlashed(owner, RULE_OVER_ISSUE);
      return;
    }

    // OVER-ISSUE violation. DETERMINISTIC identity — on-chain bool, no per-node data.
    const identity: ProofIdentity = {
      proofSchemaVersion: PROOF_SCHEMA_VERSION,
      chainId: this.chainId,
      operator: owner,
      rule: RULE_OVER_ISSUE,
      violationBlock: pinnedBlock.number,
      slashLevel: SLASH_LEVEL_OVER_ISSUE,
      registry: this.normalizeAddress(this.registryAddress),
      dvtValidator: this.normalizeAddress(this.dvtValidatorAddress),
      overIssueToken: this.normalizeAddress(token),
    };
    const reason = `${RULE_OVER_ISSUE}: community ${owner} over-issued xPNTs token ${token} (isOverIssued=true @block ${pinnedBlock.number})`;
    this.logger.warn(reason);
    const sources: EvidenceSource[] = [
      {
        type: "view",
        name: "xPNTs.isOverIssued()",
        value: "true",
        block: pinnedBlock.number,
      },
      {
        type: "view",
        name: "xPNTs.communityOwner()",
        value: owner,
        block: pinnedBlock.number,
      },
    ];
    await this.handleViolation({
      operator: owner,
      slashLevel: SLASH_LEVEL_OVER_ISSUE,
      reason,
      rule: RULE_OVER_ISSUE,
      violationBlock: pinnedBlock.number,
      violationBlockHash: pinnedBlock.hash,
      sources,
      observedAt: this.clock(),
      identity,
      observed: `over-issued (token ${token})`,
      threshold: "isOverIssued=false",
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
      // A1#6 (Codex High-1) — authorize against the EFFECTIVE set (static ∪ on-chain-derived), not
      // just the static list, or a derived-only operator could be audited by the requester yet never
      // co-signed by peers → never reaches quorum. Refresh (throttled) first so the responder's
      // derived set is current.
      await this.refreshDerivedOperators();
      if (!this.effectiveWatchlist().includes(operator)) return NO;

      const blockTag = req.epoch;
      if (!Number.isInteger(blockTag) || blockTag < 0) return NO;

      // A1#6 (Codex round-4, Low) — INDEPENDENTLY require the requester-supplied epoch to be FINALIZED
      // by THIS responder's own view. Every rule input + hasRole membership is pinned to req.epoch, so
      // a malicious requester who supplies an UNFINALIZED (reorg-able) block where the victim is
      // transiently over-limit / a member must not be able to harvest a co-signature. Reject any epoch
      // newer than our finalized head; a responder briefly behind simply refuses and the requester
      // retries (fail-closed). A read failure here is also fail-closed (caught by the outer try → NO).
      const finalizedHead = await this.blockchainService.getViolationBlock(
        this.finalityConfirmations
      );
      if (blockTag > finalizedHead.number) {
        this.logger.warn(
          `co-sign refused: epoch ${blockTag} is not finalized by this node (finalized head ` +
            `${finalizedHead.number}) — refusing to co-sign on reorg-able state`
        );
        return NO;
      }

      // A1#6 (Codex round-3) — a derived-only operator's membership is CONFIRMED at req.epoch (the
      // SAME block the evidence is verified at) via hasRole, not just the cached set's wall-clock
      // freshness — a peer must not co-sign a slash of an operator who had exited by the epoch block.
      if (!(await this.confirmSlashableAtBlock(operator, blockTag))) {
        this.logger.warn(
          `co-sign refused: ${operator} not a confirmed audited-role member at epoch ${blockTag}`
        );
        return NO;
      }

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

      // Re-derive the content-address from the SAME on-chain identity (wall-clock-free), so it
      // equals the requester's proofHash for the identical violation. Every slash-critical input —
      // availableCredit, slashLevel, and the source contract/token addresses — is committed at the
      // FINALIZED block, so evidenceHash is a full content address of exactly what would be slashed.
      // No block-HEADER read is needed (finding-2): reorg-safety comes from the finality-pinned
      // `epoch`, so a non-archive node that cannot read an old header still reproduces this proofHash.
      const identity: ProofIdentity = {
        proofSchemaVersion: PROOF_SCHEMA_VERSION,
        chainId: this.chainId,
        operator,
        rule: RULE_CREDIT_OVER_LIMIT,
        creditLimit: creditLimit.toString(),
        availableCredit: availableCredit.toString(),
        debt: (debt as bigint).toString(),
        violationBlock: blockTag,
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
    // credit-over-limit rule inputs — present on the credit path (used to build its identity inline).
    creditLimit?: bigint;
    availableCredit?: bigint;
    debt?: bigint;
    violationBlock: number;
    violationBlockHash: string;
    sources: EvidenceSource[];
    observedAt: number;
    // A pre-built content-address identity (rule ② offline). When provided it is used VERBATIM; when
    // absent the credit-over-limit identity is built inline from creditLimit/availableCredit/debt so
    // the credit path's proofHash is unchanged.
    identity?: ProofIdentity;
    // Human-readable evidence strings for the archived SlashProof (rule-generic). When absent the
    // credit path's debt/creditLimit are used, so its archived evidence is unchanged.
    observed?: string;
    threshold?: string;
  }): Promise<AuditDetection | null> {
    // DETERMINISTIC slash epoch = the violationBlock (an on-chain fact). Two DVT nodes observing
    // the SAME violation derive the SAME epoch, so their queue/execute co-sign preimages match and
    // the gossip BLS aggregate verifies. A wall-clock epoch (Math.floor(observedAt/1000)) would
    // diverge across nodes → divergent messageHashes → the aggregate would never verify on-chain.
    // observedAt stays a HUMAN-only field (already excluded from the content-address identity).
    const epoch = v.violationBlock;
    const proposer = this.blockchainService.getWalletAddress() ?? ethers.ZeroAddress;

    // Content-address IDENTITY = ON-CHAIN facts only (no wall-clock). Two DVT nodes seeing
    // the same violation at the same block derive the same proofHash + proposalId. The offline rule
    // passes a pre-built identity; the credit rule builds its (unchanged) identity inline.
    const identity: ProofIdentity = v.identity ?? {
      proofSchemaVersion: PROOF_SCHEMA_VERSION,
      chainId: this.chainId,
      operator: v.operator,
      rule: v.rule,
      creditLimit: v.creditLimit!.toString(),
      availableCredit: v.availableCredit!.toString(),
      debt: v.debt!.toString(),
      violationBlock: v.violationBlock,
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
    // Exact same violation@block already handled (this process, or on disk from a prior run) — with
    // TWO bypasses so an incomplete slash is not stranded:
    //   (a) `coSignRetryKeys` (in-memory): a prior attempt's ARMED co-sign aborted transiently.
    //   (b) archived INCOMPLETE slash (durable, Codex-Critical crash-restart fix): the archived proof
    //       has `queueTx` set but no `executeTx` — the operator was queued (pending, withdraw-locked)
    //       but never slashed. In-memory `coSignRetryKeys` is LOST on a crash, so without this the
    //       durable `archive.has` short-circuit would permanently skip the block → stuck pending. We
    //       carry the archived proof so its `proposalId` can be REUSED on the resume (no orphan).
    // The archived proof (if any) for THIS violation — read once (armed only) so we can (a) detect an
    // INCOMPLETE slash to resume and (b) REUSE its durably-persisted proposalId on the resume so no
    // path files a fresh orphan proposal. `incomplete` = queued (queueTx set) but not executed.
    const archived = this.executeSlash ? await this.archive.get(proofHash) : null;
    const resumeArchived = archived && archived.queueTx && !archived.executeTx ? archived : null;
    // ARMED + the archived proof did NOT record a completed execute (executeTx unset — includes a
    // crash BEFORE queueTx was even persisted) → do NOT short-circuit on `archive.has`: fall through
    // to `assessSlashState`, which reads the AUTHORITATIVE on-chain pending state (durable; survives
    // this tick's archive overwrite and any crash-before-persist window). Only a COMPLETED archived
    // slash (executeTx set), or the file-only path, takes the fast dedup skip. (Codex-Critical: the
    // archived queueTx alone is NOT a safe skip signal — the on-chain flag is.)
    // …unless we ALREADY know (in-memory, this process) the coarse operator+rule was slashed — then
    // the fast skip is safe (no resume needed) and avoids re-processing/re-archiving every tick when a
    // slash landed on-chain but its executeTx was never persisted locally (Codex Low: churn).
    const armedUnfinished =
      this.executeSlash &&
      !this.slashedCoarseKeys.has(coarseKey) &&
      (!archived || !archived.executeTx);
    if (!this.coSignRetryKeys.has(stableKey) && !armedUnfinished) {
      if (this.proposedStableKeys.has(stableKey) || (await this.archive.has(proofHash))) {
        this.logger.debug(
          `Audit: ${v.operator} ${v.rule}@${v.violationBlock} already proposed (proof ${proofHash}) — skip`
        );
        return null;
      }
    }
    if (resumeArchived) {
      this.logger.warn(
        `Audit: ${v.operator} ${v.rule}@${v.violationBlock} archived INCOMPLETE slash ` +
          `(queueTx ${resumeArchived.queueTx}, no executeTx) — will RESUME if on-chain pending`
      );
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
        observed: v.observed ?? v.debt?.toString() ?? "",
        threshold: v.threshold ?? v.creditLimit?.toString() ?? "",
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

    // Carry forward any durable on-chain PROGRESS from a prior incomplete attempt (queue/proposal
    // landed but execute did not) so this fresh archive.put does NOT overwrite the durable incomplete
    // marker with nulls — otherwise a crash right after this put would strand the resume (Codex-
    // Critical overwrite window). Never clobber a real archived value with undefined/null.
    if (archived) {
      proof.queueTx = archived.queueTx ?? proof.queueTx;
      proof.queueMessageHash = archived.queueMessageHash ?? proof.queueMessageHash;
      proof.proposalTx = archived.proposalTx ?? proof.proposalTx;
      proof.proposalId = archived.proposalId ?? proof.proposalId;
    }

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

    // Assess on-chain slash state: drives the over-slash guard ("executed"/"blocked" → skip), the
    // RESUME path ("pending"), and — critically — LEARNING that a PEER completed the slash. The
    // cooldown throttles the ATTEMPT, but it must NOT throttle learning: a node with an IN-FLIGHT slash
    // (pendingProposalIds / coSignRetryKeys) keeps scanning during its backoff so a peer's
    // SlashExecuted/OperatorSlashed is recorded (recordCoarseSlashed) WHILE it is still inside the
    // head-window — otherwise, if AUDIT_SLASH_LOOKBACK_BLOCKS is shorter than the cooldown's block
    // horizon, the event scrolls out of the window and the post-cooldown scan reads "clear" → a DOUBLE
    // slash of the same sustained violation (Codex). Only assess for armed nodes; file-only never
    // queues. `assessSlashState`'s own step-1/2 in-memory/journal checks keep repeat calls cheap.
    const inFlight = this.pendingProposalIds.has(coarseKey) || this.coSignRetryKeys.has(stableKey);
    const slashState: "executed" | "pending" | "clear" | "blocked" =
      this.executeSlash && (!withinCooldown || inFlight)
        ? await this.assessSlashState(coarseKey, v.operator, v.slashLevel, v.violationBlock)
        : "clear";

    if (withinCooldown) {
      this.logger.debug(
        `Audit: ${v.operator} ${v.rule} within cooldown (${this.clock() - (last as number)}ms < ` +
          `${this.cooldownMs}ms) — attempt suppressed, archiving evidence only`
      );
      proposalIdNote = "id-unresolved: proposal attempt suppressed by cooldown";
    } else if (slashState === "executed" || slashState === "blocked") {
      // ARMED path OVER-SLASH GUARD (finding-4/5): a slash already EXECUTED for this operator+rule
      // ("executed"), or the chain state is unreadable ("blocked" = fail-closed) → do NOT queue/
      // execute again, even after cooldownMs with an advancing block. Evidence is still archived.
      // NB: a "pending" (incomplete) slash is NOT handled here — it flows to the RESUME path below.
      this.logger.warn(
        `Audit: ${v.operator} ${v.rule} ${
          slashState === "executed" ? "already slashed" : "slash-state indeterminate"
        } — over-slash guard, on-chain slash SKIPPED`
      );
      this.emitAuditEvent("OVER_SLASH_SKIP", {
        operator: v.operator,
        rule: v.rule,
        reason: slashState,
      });
      proposalIdNote =
        slashState === "executed"
          ? "id-unresolved: operator already slashed for this rule (over-slash guard)"
          : "id-unresolved: slash-state indeterminate (over-slash guard fail-closed)";
    } else {
      // slashState === "clear" (normal full queue→create→execute) OR "pending" (RESUME: an on-chain
      // queue pre-flag is already set — this node queued on a prior tick then failed pre-execute, or a
      // peer queued it — so skip the replay-guarded re-queue and go straight to createProposal +
      // execute to COMPLETE the slash).
      const resume = slashState === "pending";
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
      // On the resume path, REUSE the proposalId this node already filed for this evidence (durably
      // recorded in the archived proof) instead of creating a fresh one — bounds resume to ZERO new
      // proposals for a same-node retry (Codex High-2: orphan re-explosion). A peer resuming with no
      // local proposal (null) files one, throttled by the cooldown that a post-queue failure keeps.
      // Reuse the in-flight proposalId: prefer the SAME-proof archived one, else the COARSE-key map
      // (which survives a violationBlock advance → proofHash change, so a later-block resume does not
      // file a fresh orphan proposal every cooldown window).
      const carriedProposalId =
        resumeArchived?.proposalId ?? this.pendingProposalIds.get(coarseKey) ?? null;
      const resumeProposalId = resume && carriedProposalId ? BigInt(carriedProposalId) : null;
      const res = await this.coordinateQuorumCoSign(
        {
          operator: v.operator,
          slashLevel: v.slashLevel,
          reason: v.reason,
          epoch,
          evidenceHash: proofHash,
          rule: v.rule,
        },
        proof,
        resume,
        resumeProposalId
      );
      proposalTx = res.proposalTx;
      onchainProposalId = res.proposalId;
      queueTx = res.queueTx;
      executeTx = res.executeTx;
      // Track the in-flight proposal by COARSE key so a later-block resume (proofHash changed as the
      // finalized violationBlock advanced) reuses this id instead of filing a fresh orphan. Set when a
      // proposal exists but the slash did NOT execute this tick; clear once it really executes. Dry-run
      // (executeTx = sentinel) touches neither — the drill is repeatable and writes no durable state.
      if (onchainProposalId !== null && executeTx === null) {
        this.pendingProposalIds.set(coarseKey, onchainProposalId.toString());
      } else if (executeTx !== null && executeTx !== DRY_RUN_TX_SENTINEL) {
        this.pendingProposalIds.delete(coarseKey);
      }
      if (res.queueMessageHash) proof.queueMessageHash = res.queueMessageHash;
      if (res.coSignAborted) {
        // An ARMED attempt did not fully execute → mark the block for co-sign RETRY (bypasses the
        // archived-evidence dedup in-process). Whether to also CLEAR the cooldown depends on how far
        // it got:
        //   • queue NEVER landed (queueTx null && not resuming) → pure transient (no gas spent, e.g.
        //     gossip mesh not up yet) → CLEAR cooldown so the next tick retries IMMEDIATELY.
        //   • queue DID land (queueTx set) or we were RESUMING → a post-queue failure. KEEP the
        //     cooldown so the execute retry is THROTTLED to once per cooldownMs — otherwise the resume
        //     path re-attempts every tick × every node (Codex High-2 orphan/gas explosion).
        this.coSignRetryKeys.add(stableKey);
        const queuePreflagLanded = res.queueTx !== null || resume;
        if (!queuePreflagLanded) {
          this.lastProposalAt.delete(coarseKey);
        }
        this.logger.warn(
          `Audit: ${v.operator} ${v.rule} co-sign aborted (${
            queuePreflagLanded
              ? "post-queue, cooldown kept — throttled resume"
              : "transient, cooldown cleared"
          }) — will retry next tick`
        );
        this.emitAuditEvent("COSIGN_ABORTED", {
          operator: v.operator,
          rule: v.rule,
          phase: queuePreflagLanded ? "post-queue" : "transient",
          queueTx: res.queueTx,
        });
      } else {
        // Co-sign completed (queued / executed / dry-run) → stop retrying this block.
        this.coSignRetryKeys.delete(stableKey);
      }
      if (executeTx === DRY_RUN_TX_SENTINEL) {
        // DRY RUN: the quorum co-sign + staticCall preflight passed against the REAL contracts, but
        // NOTHING was slashed (no broadcast). Record the real co-sign material + the sentinel tx so
        // the archive shows the drill, but DO NOT write the durable over-slash marker — a durable
        // marker would wrongly suppress a LATER real (or repeat dry) run for the same operator+rule.
        // The drill must be repeatable.
        this.logger.warn(
          `Audit: ${v.operator} ${v.rule} DRY RUN — staticCall passed, slash NOT broadcast; ` +
            `durable over-slash marker intentionally NOT written (repeatable drill)`
        );
        this.emitAuditEvent("DRY_RUN_PASSED", {
          operator: v.operator,
          rule: v.rule,
          proposalId: onchainProposalId?.toString(),
        });
        proof.signerMask = res.signerMask;
        proof.sigG2 = res.sigG2;
      } else if (executeTx !== null) {
        // A slash actually executed → arm the DURABLE over-slash guard (in-memory + archive journal,
        // finding-2) so a restart does not re-slash, and record the real co-sign material.
        await this.recordCoarseSlashed(coarseKey);
        proof.signerMask = res.signerMask;
        proof.sigG2 = res.sigG2;
        this.emitAuditEvent("SLASH_EXECUTED", {
          operator: v.operator,
          rule: v.rule,
          slashLevel: v.slashLevel,
          proposalId: onchainProposalId?.toString(),
          queueTx,
          executeTx,
        });
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
    // Only OVERWRITE proposalId when THIS tick resolved a real on-chain id (a fresh createProposal or
    // a reused resume id). When it did NOT (a cooldown-SUPPRESSED tick never called the orchestrator,
    // so onchainProposalId is null), KEEP the value already on `proof` — carried forward from the
    // archived incomplete attempt — so a durable proposalId survives for reuse and a later crash does
    // not lose it (Codex: null-clobber reopened orphan reuse). Never clobber a real id with null.
    if (onchainProposalId !== null) {
      proof.proposalId = proposalId;
    }
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
    this.metrics.detections++;
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
  private async assessSlashState(
    coarseKey: string,
    operator: string,
    slashLevel: number,
    violationBlock: number
  ): Promise<"executed" | "pending" | "clear" | "blocked"> {
    // (1) In-memory executed marker.
    if (this.slashedCoarseKeys.has(coarseKey)) return "executed";

    // (2) DURABLE executed journal — survives a restart within the same process/disk.
    try {
      if (await this.archive.hasSlashed(coarseKey)) {
        this.markCoarseSlashed(coarseKey); // cache in-memory (do not re-write the marker)
        return "executed";
      }
    } catch {
      // best-effort: journal read error → fall through to the on-chain scan.
    }

    // (3) ON-CHAIN slash-EXECUTED events — the authoritative cross-restart DOUBLE-slash guard. A
    // `null` from any target means that scan was INDETERMINATE (provider error), tracked so (5) can
    // fail closed.
    let scanIndeterminate = false;
    try {
      // Scan the most-recent `slashLookbackBlocks` at the chain HEAD (where slash events are emitted),
      // NOT anchored at the ~60-blocks-behind finalized violationBlock — the range then equals the
      // lookback (size it to the RPC's getLogs cap so the scan stays determinate).
      const scanTargets = [this.blsAggregatorAddress, this.superPaymasterAddress].filter(Boolean);
      for (const target of scanTargets) {
        const hit = await this.blockchainService.getRecentSlashExecuted(
          target,
          operator,
          slashLevel,
          this.slashLookbackBlocks
        );
        if (hit === true) {
          await this.recordCoarseSlashed(coarseKey); // persist durable + memory
          return "executed";
        }
        if (hit === null) scanIndeterminate = true; // provider error on this target — unconfirmable
      }
    } catch {
      // getRecentSlashExecuted threw (unexpected) → treat the whole scan as indeterminate.
      scanIndeterminate = true;
    }

    // (4) ON-CHAIN pending flag, reconstructed from SP events (SlashQueued/SlashCancelled/
    // OperatorSlashed — no getter; SP is EIP-170-capped). CRITICAL: a `pending` operator is NOT
    // "already slashed" — it is an INCOMPLETE slash (queued on-chain but not yet executed, because
    // the queuing node crashed/RPC-failed before executing, or a peer queued it). It must be RESUMED
    // (skip the replay-guarded re-queue, complete createProposal + execute), never SKIPPED — skipping
    // it was the stuck-pending liveness bug: the operator's withdraw stays locked forever yet the
    // slash never lands.
    let pendingIndeterminate = false;
    try {
      const pending = await this.blockchainService.isSlashPending(
        this.superPaymasterAddress,
        operator,
        this.slashLookbackBlocks
      );
      if (pending === true) return "pending";
      if (pending === null) pendingIndeterminate = true; // scan unavailable → unknown
    } catch {
      pendingIndeterminate = true; // RPC error → unknown
    }

    // (5) CONSERVATIVE fail-closed backstop. Reaching here means the operator is NOT already-executed
    // by any positive signal (1-3) and NOT pending (4). Fail CLOSED whenever the EXECUTED-scan was
    // indeterminate: a `pending === false` does NOT prove "never slashed" — a *completed* slash also
    // clears `_pendingSlash`, so if we cannot read the executed events we cannot rule out a prior
    // slash and must not fire an irreversible one. (Codex-Critical: the earlier `scanIndeterminate &&
    // pendingIndeterminate` was too weak — a determinate pending=false wrongly unblocked.) A
    // pendingIndeterminate alone (executed-scan determinate "not executed") is safe to slash. Only a
    // fully determinate "not executed / not pending" returns "clear".
    if (scanIndeterminate) {
      this.logger.warn(
        `Audit: ${operator} slash-state INDETERMINATE (executed-event scan unavailable; ` +
          `pending=${pendingIndeterminate ? "unknown" : "false"} cannot prove un-slashed) — ` +
          `fails CLOSED, on-chain slash SKIPPED`
      );
      return "blocked";
    }
    return "clear";
  }

  /**
   * The slash-consensus orchestration — the SINGLE createProposalWithEvidence call site for BOTH
   * the file-only and the armed (SP #329 two-step) paths. Runs in this exact order:
   *
   *   1. QUEUE    — (ARMED, and NOT `resume`) co-sign the 5-field queue preimage → queueSlashWithProof.
   *                 SKIPPED on the `resume` path (the operator is already pending on-chain — re-queuing
   *                 would hit the BLSAggregator replay guard and revert).
   *   2. PROPOSAL — createProposalWithEvidence(evidenceHash=proofHash) → the REAL proposal id, binding
   *                 the on-chain slash to the archived evidence. Runs when NOT armed (file-only: the
   *                 proposal IS the deliverable) OR the on-chain queue pre-flag is set — queued this
   *                 tick (queueTx !== null) OR `resume`. Gated so a transiently-aborted queue does NOT
   *                 spawn an orphan proposal Step 3 can't execute.
   *   3. EXECUTE  — (ARMED only) co-sign the 8-field execute preimage (bound to that real id +
   *                 evidenceHash) → executeWithProof (slash-only ⇒ repUsers/newScores empty). STRICTLY
   *                 contingent on the TWO-STEP SAFETY (finding-1): runs ONLY when the queue pre-flag is
   *                 set (queueTx !== null OR `resume`) AND the proposal id resolved. If neither, the
   *                 slash aborts to file+archive only — never execute without a confirmed queue.
   *
   * An ARMED attempt that did not reach a real execute (executeTx null) sets `coSignAborted` so the
   * caller retries next tick and RESUMES (Codex-Critical: a queued-but-unexecuted operator would
   * otherwise stay pending/withdraw-locked forever). When executeSlash is OFF (default) only step 2
   * runs — the file-only path: proposal filed + evidence bound, nothing queued or slashed. Each step
   * is wrapped: a co-sign or tx failure is logged and swallowed so the caller still archives the
   * evidence (evidence never lost) and the poll loop never crashes.
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
      /** Rule id — the offline rule (inc-1) is FILE-ONLY: no armed queue/execute yet (inc-2). */
      rule?: string;
    },
    proof?: SlashProof,
    /**
     * RESUME an incomplete on-chain slash: the operator is ALREADY pending-slash (the queue pre-flag
     * is set — this node queued on a prior tick then failed pre-execute, or a peer queued it). When
     * true, Step 1 (queue) is SKIPPED (a re-queue hits the BLSAggregator replay guard and reverts);
     * the flow goes straight to createProposal + execute to complete the slash. Defaults to false.
     */
    resume = false,
    /**
     * On the resume path, a proposalId this node ALREADY filed for this evidence (from the archived
     * proof). When provided, Step 2 REUSES it instead of creating a fresh proposal — so a same-node
     * resume adds ZERO new on-chain proposals (no orphan re-explosion). Null ⇒ Step 2 files one.
     */
    resumeProposalId: bigint | null = null
  ): Promise<{
    proposalTx: string | null;
    proposalId: bigint | null;
    queueTx: string | null;
    executeTx: string | null;
    queueMessageHash: string | null;
    signerMask: string;
    sigG2: string;
    /**
     * True when the ARMED queue co-sign could NOT complete for a TRANSIENT reason (no gossip peers
     * yet / quorum not reached / staticCall preflight reverted) — nothing was slashed and no gas was
     * spent. The caller then clears the per-block dedup + cooldown so the NEXT tick re-attempts,
     * instead of losing this violation-block's co-sign forever (robustness gap: a node that detects
     * before its gossip mesh is up must not permanently skip the block).
     */
    coSignAborted: boolean;
  }> {
    const { operator, slashLevel, reason, epoch, evidenceHash } = args;
    // FILE-ONLY rules (inc-1): file a proposal + archive the proof, but never queue/execute an on-chain
    // slash yet. Offline's armed co-sign is deferred (its evidence is gossip-local; see #202). Over-
    // issue's evidence IS objective (on-chain isOverIssued) so it is armable in principle, but its slash
    // SUBJECT is a communityOwner (not a BLS-slotted DVT operator) — arming waits until the SP contract
    // community-slash path is confirmed. The credit rule is unaffected (stays armed).
    const fileOnlyRule = args.rule === RULE_OFFLINE || args.rule === RULE_OVER_ISSUE;
    // A1#6 (Codex High-2 + round-3) — a derived-ONLY operator is armed for the irreversible on-chain
    // slash only when its membership is CONFIRMED at the evidence block (epoch) via hasRole — not just
    // the cached set's wall-clock freshness. Stale/never-confirmed/exited-by-epoch membership degrades
    // to file-only (proposal + archive, no queue/execute). Static-listed operators are always armed.
    const armed =
      this.executeSlash && !fileOnlyRule && (await this.confirmSlashableAtBlock(operator, epoch));
    if (this.executeSlash && !armed && !fileOnlyRule) {
      this.logger.warn(
        `Audit: ${operator} armed slash WITHHELD — derived-only operator not confirmed as an ` +
          `audited-role member at evidence block ${epoch}; filing proposal only`
      );
    }
    let coSignAborted = false;
    // DRY-RUN drill (only meaningful when armed): the co-sign below STILL happens and the queue/execute
    // staticCall preflight STILL runs against the REAL contracts, but the broadcast is skipped and the
    // step returns DRY_RUN_TX_SENTINEL. queueTx/executeTx then carry the sentinel (recorded as-is).
    const dryRun = this.dryRun;
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

    // ── Step 1: QUEUE (ARMED only, quorum co-signed; SKIPPED when resuming) ────────
    // On the RESUME path the operator's queue pre-flag is already set on-chain (a prior tick's / a
    // peer's queueSlashWithProof landed); re-queuing would replay the same 5-field messageHash and
    // revert on the BLSAggregator `usedSlashQueueHashes` guard. Skip straight to createProposal +
    // execute to COMPLETE the slash.
    if (armed && resume) {
      this.logger.warn(
        `Audit: ${operator} slash queue SKIPPED — operator already pending-slash on-chain ` +
          `(resuming to createProposal + execute)`
      );
    } else if (armed) {
      try {
        queueMessageHash = buildQueueMessageHash(operator, slashLevel, epoch, this.chainId);
        const cosign = await this.coSigner.coSign({
          proofSchemaVersion: PROOF_SCHEMA_VERSION,
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
          encoded,
          dryRun
        );
        this.logger.warn(
          `Audit: ${operator} slash ${dryRun ? "QUEUE DRY RUN (staticCall passed, NOT broadcast)" : "QUEUED"} (tx ${queueTx})`
        );
        // Durable BEFORE execute: the confirmed queueTx is persisted now (finding-4).
        if (proof) {
          proof.queueTx = queueTx;
          proof.queueMessageHash = queueMessageHash;
          await persistStep();
        }
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        // TRANSIENT: the armed queue co-sign didn't complete (no peers / quorum not met / staticCall
        // reverted). Nothing slashed, no gas spent. Signal the caller to RETRY next tick rather than
        // marking this violation-block permanently handled.
        coSignAborted = true;
        this.logger.error(
          `Audit: ${operator} slash queue step failed — ${msg} (evidence archived; slash not queued; will retry)`
        );
      }
    }

    // ── Step 2: file the proposal (binds evidenceHash=proofHash) ───────────────────
    // File-only (NOT armed): the proposal IS the deliverable — always create it.
    // ARMED: create the proposal ONLY when the on-chain queue pre-flag is set — i.e. we queued it
    // THIS tick (queueTx !== null; a dry-run's DRY_RUN_TX_SENTINEL counts) OR we are RESUMING an
    // already-pending slash (`resume`). Creating it when the queue co-sign aborted transiently (no
    // peers / under-threshold / a PEER already queued so our queueSlashWithProof reverts) would spawn
    // an ORPHAN proposal that Step 3 then SKIPS — and with N nodes each retrying every tick, one
    // orphan per node per tick. Gating on the queue pre-flag makes only the node(s) that hold it file
    // a proposal they can actually execute.
    if (resumeProposalId !== null) {
      // RESUME with a proposal this node already filed — reuse it, file NOTHING new (no orphan).
      proposalId = resumeProposalId;
      this.logger.warn(
        `Audit: ${operator} createProposal REUSED existing proposal id ${resumeProposalId} ` +
          `(resume) — no new on-chain proposal filed`
      );
    } else if (!armed || queueTx !== null || resume) {
      try {
        const res = await this.blockchainService.createProposalWithEvidence(
          this.dvtValidatorAddress,
          operator,
          slashLevel,
          reason,
          evidenceHash,
          dryRun
        );
        proposalTx = res.txHash;
        proposalId = res.proposalId;
        // ARMED only: persist the REAL proposalId durably NOW (before the execute step), so a crash
        // between createProposal and executeWithProof lets a restarted process REUSE this id on the
        // resume (no orphan) instead of filing a fresh proposal. File-only has no execute to resume,
        // and the final archive records the id anyway. Skip the sentinel/no-op dry-run id.
        if (proof && armed && proposalId !== null && proposalTx !== DRY_RUN_TX_SENTINEL) {
          proof.proposalId = proposalId.toString();
          await persistStep();
        }
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        this.logger.error(`Audit: ${operator} createProposal failed — ${msg}`);
      }
    } else {
      this.logger.warn(
        `Audit: ${operator} createProposal SKIPPED — armed queue step did not confirm ` +
          `(queueTx null); not filing an orphan proposal, will retry next tick`
      );
    }

    // ── Step 3: EXECUTE (ARMED only) — TWO-STEP SAFETY: queue pre-flag set + real id required ──
    // The pre-flag is set when we queued this tick (queueTx !== null) OR we are RESUMING an operator
    // already pending on-chain (`resume`). Either way `require(_pendingSlash)` in executeSlashWithBLS
    // is satisfied; without it the execute would revert.
    if (armed) {
      if (queueTx === null && !resume) {
        // finding-1: never execute a slash whose queue pre-flag did not confirm. Abort to
        // file+archive only — the evidence + proposal remain, but no irreversible slash fires.
        this.logger.error(
          `Audit: ${operator} slash execute SKIPPED — queue step did not confirm (queueTx null, ` +
            `not resuming); two-step safety requires the on-chain queue pre-flag before executeWithProof`
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
            proofSchemaVersion: PROOF_SCHEMA_VERSION,
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
            encoded,
            dryRun
          );
          // Record the EXECUTE co-sign material so the archived proof references the real slash.
          signerMask = ethers.toBeHex(cosign.signerMask);
          sigG2 = cosign.sigG2;
          this.logger.warn(
            dryRun
              ? `Audit: ${operator} DRY RUN: staticCall passed — would slash ${operator} ` +
                  `(proposal ${proposalId}), NOT broadcasting`
              : `Audit: ${operator} slash EXECUTED (proposal ${proposalId}, tx ${executeTx})`
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

    // RESUME-RETRY signal (Codex-Critical fix): an ARMED attempt that did NOT reach a real execute
    // (executeTx null — createProposal or the execute co-sign failed, or the queue confirmed but a
    // later step threw) leaves the operator PENDING-slash on-chain yet not slashed. Signal the caller
    // to retry next tick (bypassing the archived-evidence dedup + clearing cooldown) so `assessSlashState`
    // sees the "pending" state and RESUMES to completion — instead of marking the block handled and
    // stranding the operator withdraw-locked forever. Dry-run's sentinel executeTx is non-null, so a
    // clean rehearsal does not trip this. The existing queue-catch also sets coSignAborted for the
    // never-queued transient case; this widens it to every incomplete armed outcome.
    if (armed && !dryRun && executeTx === null) {
      coSignAborted = true;
    }

    return {
      proposalTx,
      proposalId,
      queueTx,
      executeTx,
      queueMessageHash,
      signerMask,
      sigG2,
      coSignAborted,
    };
  }

  /** Read-only status for GET /audit/status. No secrets. */
  async getStatus(): Promise<{
    enabled: boolean;
    intervalMs: number;
    watchlist: string[];
    roleDerive: boolean;
    derivedOperatorCount: number;
    derivedSetFresh: boolean;
    lastRoleRefreshAt: number | null;
    lastTickAt: number | null;
    recentDetections: AuditDetection[];
    archivedProofCount: number;
    metrics: {
      detections: number;
      slashesExecuted: number;
      dryRunPassed: number;
      coSignAborts: number;
      overSlashSkips: number;
      errors: number;
    };
  }> {
    let archivedProofCount: number;
    try {
      archivedProofCount = await this.archive.count();
    } catch {
      archivedProofCount = -1;
    }
    return {
      enabled: this.enabled,
      intervalMs: this.intervalMs,
      watchlist: this.effectiveWatchlist(),
      roleDerive: this.roleDerive,
      derivedOperatorCount: this.derivedOperators.length,
      derivedSetFresh: this.derivedSetIsFresh(),
      lastRoleRefreshAt: this.lastRoleRefreshAt,
      lastTickAt: this.lastTickAt,
      recentDetections: this.recentDetections,
      archivedProofCount,
      // Cumulative monitoring counters (since process start) — poll these OR alert on the
      // `[AUDIT-EVENT] kind=…` log lines. slashesExecuted/dryRunPassed = successes; coSignAborts/
      // overSlashSkips/errors = things to watch.
      metrics: { ...this.metrics },
    };
  }
}
