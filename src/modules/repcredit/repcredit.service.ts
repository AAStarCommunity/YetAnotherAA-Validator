import { Injectable, Logger } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { BlsService } from "../bls/bls.service.js";
import { BlockchainService } from "../blockchain/blockchain.service.js";
import { NodeService } from "../node/node.service.js";
import {
  aggregateRepCreditResponses,
  aggregateRepCreditSlashResponses,
  encodeRepCreditPublicKey,
  RepCreditAggregate,
  RepCreditCoSignResponse,
  RepCreditProposal,
  RepCreditSlashProposal,
  validateRepCreditProposal,
  validateRepCreditSlashProposal,
} from "./repcredit-consensus.js";
import { MAX_VALIDATORS } from "../audit/slash-consensus.js";
import {
  CHAINS_WITH_PRODUCTION_STAKE,
  checkRepCreditAggregatorPolicy,
  RepCreditAggregatorPolicyResult,
} from "./repcredit-isolation.js";
import { scrubProviderError } from "../../config/redact.js";
import { repCreditError } from "./repcredit-errors.js";

@Injectable()
export class RepCreditService {
  private readonly logger = new Logger(RepCreditService.name);

  constructor(
    private readonly config: ConfigService,
    private readonly blockchain: BlockchainService,
    private readonly nodeService: NodeService,
    private readonly blsService: BlsService
  ) {}

  async sign(proposal: RepCreditProposal): Promise<RepCreditCoSignResponse> {
    this.requireArmed();
    const localChainId = await this.localChainId();
    let messageHash: string;
    try {
      messageHash = validateRepCreditProposal(proposal, localChainId);
    } catch (error) {
      throw repCreditError("REPCREDIT_PROPOSAL_INVALID", messageOf(error));
    }

    return this.signValidatedHash(messageHash, localChainId);
  }

  async signSlash(proposal: RepCreditSlashProposal): Promise<RepCreditCoSignResponse> {
    this.requireArmed();
    const localChainId = await this.localChainId();
    let messageHash: string;
    try {
      messageHash = validateRepCreditSlashProposal(proposal, localChainId);
    } catch (error) {
      throw repCreditError("REPCREDIT_PROPOSAL_INVALID", messageOf(error));
    }
    return this.signValidatedHash(messageHash, localChainId);
  }

  private async signValidatedHash(
    messageHash: string,
    localChainId: number
  ): Promise<RepCreditCoSignResponse> {
    const slot = this.configuredSlot();
    const aggregator = this.aggregatorAddress();
    const node = this.nodeService.getNodeForSigning();

    let localKey: string;
    try {
      localKey = encodeRepCreditPublicKey(node.publicKey);
    } catch {
      throw repCreditError("REPCREDIT_LOCAL_KEY_MALFORMED", "local BLS public key is malformed");
    }

    // Cheap binding first (2 reads): a misconfigured slot short-circuits before the wider
    // audit-aggregator scan below. Neither check produces a signature on its own.
    const onChainKey = await this.blockchain.getBlsPublicKeyAtSlot(aggregator, slot);
    if (!onChainKey) {
      throw repCreditError(
        "REPCREDIT_SLOT_NOT_ACTIVE",
        `configured validator slot ${slot} is not active`
      );
    }
    if (localKey !== onChainKey.toLowerCase()) {
      throw repCreditError(
        "REPCREDIT_SLOT_KEY_MISMATCH",
        `local BLS key is not registered at validator slot ${slot}`
      );
    }

    await this.assertKeyIsolatedFromProductionAggregators(localKey, localChainId);

    const signature = await this.blsService.signRepCreditHash(messageHash, node);
    if (!signature.signatureCompact || !signature.publicKey) {
      throw repCreditError(
        "REPCREDIT_SIGNER_OUTPUT_INVALID",
        "BLS signer did not return compact signature material"
      );
    }
    return {
      slot,
      signerNodeId: node.nodeId,
      signerPublicKey: `0x${signature.publicKey.replace(/^0x/, "")}`,
      signatureCompact: `0x${signature.signatureCompact.replace(/^0x/, "")}`,
      messageHash,
    };
  }

  async aggregate(
    proposal: RepCreditProposal,
    responses: RepCreditCoSignResponse[],
    threshold: number
  ): Promise<RepCreditAggregate> {
    this.requireArmed();
    const localChainId = await this.localChainId();
    const aggregator = this.aggregatorAddress();
    await this.requireOnChainThreshold(aggregator, threshold);
    try {
      return await aggregateRepCreditResponses(proposal, localChainId, responses, threshold, slot =>
        this.blockchain.getBlsPublicKeyAtSlot(aggregator, slot)
      );
    } catch (error) {
      throw repCreditError("REPCREDIT_AGGREGATION_INVALID", messageOf(error));
    }
  }

  async aggregateSlash(
    proposal: RepCreditSlashProposal,
    responses: RepCreditCoSignResponse[],
    threshold: number
  ): Promise<RepCreditAggregate> {
    this.requireArmed();
    const localChainId = await this.localChainId();
    const aggregator = this.aggregatorAddress();
    await this.requireOnChainSlashThreshold(aggregator, proposal?.slashLevel, threshold);
    try {
      return await aggregateRepCreditSlashResponses(
        proposal,
        localChainId,
        responses,
        threshold,
        slot => this.blockchain.getBlsPublicKeyAtSlot(aggregator, slot)
      );
    } catch (error) {
      throw repCreditError("REPCREDIT_AGGREGATION_INVALID", messageOf(error));
    }
  }

  /**
   * The chain id every hash is bound to. Wrapped so an unreachable/401/rate-limited RPC
   * surfaces as an explicit refusal instead of escaping as an unhandled error: the previous
   * behaviour was still fail-closed (no signature is produced) but it returned a bare 500 and
   * let Nest's own handler log the raw ethers error — whose message, stack and
   * `info.requestUrl` all carry the RPC URL, i.e. the provider API key. Reproduced in a real
   * process during the round-3 smoke test.
   */
  private async localChainId(): Promise<number> {
    try {
      return await this.blockchain.getChainId();
    } catch (error) {
      this.logger.error(`RepCredit: chain id read failed: ${scrubProviderError(error)}`);
      throw repCreditError(
        "REPCREDIT_RPC_UNAVAILABLE",
        "cannot read the chain id from the configured RPC — refusing to sign or aggregate"
      );
    }
  }

  /**
   * First gate on every endpoint: armed, and pointed at an aggregator that is NOT the
   * production slash aggregator. Both are pure config checks, so they reject before any
   * caller-supplied field is parsed and before any RPC read is spent.
   */
  private requireArmed(): void {
    if (this.config.get<boolean>("repCreditExperimentSigning") !== true) {
      throw repCreditError(
        "REPCREDIT_EXPERIMENT_DISABLED",
        "RepCredit experiment signing is disabled"
      );
    }
    this.aggregatorPolicy();
  }

  /**
   * Config-layer isolation (CC-49 BLOCKER-1 / HIGH-A / MEDIUM-C). Pure — no RPC — so it
   * rejects before any caller-supplied field is parsed. Requires an isolated experiment
   * aggregator AND an explicitly configured audit aggregator; see repcredit-isolation.ts for
   * why an address comparison alone is not isolation.
   */
  private aggregatorPolicy(): RepCreditAggregatorPolicyResult {
    const verdict = checkRepCreditAggregatorPolicy({
      repCreditAggregatorAddress: this.config.get<string>("repCreditBlsAggregatorAddress"),
      auditAggregatorAddress: this.config.get<string>("auditBlsAggregatorAddress"),
      auditAggregatorFromEnv: this.config.get<boolean>("auditBlsAggregatorAddressFromEnv") === true,
      forbiddenAggregators: this.config.get<string[]>("repCreditForbiddenAggregators") ?? [],
      noProductionAggregator: this.config.get<boolean>("repCreditNoProductionAggregator") === true,
    });
    if (!verdict.ok) {
      throw repCreditError("REPCREDIT_AGGREGATOR_POLICY_VIOLATION", verdict.reason ?? "");
    }
    return verdict;
  }

  /**
   * Chain-layer isolation (CC-49 HIGH-A, extended round 3): refuse to sign with a key that is
   * ALSO active on ANY aggregator that guards real stake — the audit aggregator plus every
   * entry of `REPCREDIT_FORBIDDEN_AGGREGATORS`.
   *
   * The signed preimage carries no aggregator address and no domain tag, so a co-signature
   * produced "for" the experiment aggregator is byte-valid against a production one whenever
   * the same key sits in the same slot on both. Address separation cannot prevent that — only
   * refusing to reuse a production-registered key can. Runs on every signature rather than
   * once at boot, deliberately: a slot can be registered while the node is armed, and a cached
   * "clean" verdict would be exactly the stale answer that matters.
   *
   * Every failure mode is fail-closed:
   *   - a listed aggregator has no code, or does not answer the BLSAggregator ABI → refuse
   *     (this is also the wrong-chain guard: a Sepolia address on another chain has no code);
   *   - any slot read fails → refuse (the STRICT reader throws instead of returning `null`,
   *     so a transient RPC error can never be mistaken for "the key is absent");
   *   - the key is found active anywhere in [1, maxSlots] on any of them → refuse.
   *
   * The empty deny-list is reachable ONLY via the explicit REPCREDIT_NO_PRODUCTION_AGGREGATOR
   * acknowledgement, and is additionally refused on any chain id known to carry real
   * deployments — a devnet escape must not become a Sepolia escape.
   *
   * Reads are issued concurrently per aggregator, but ANY rejection refuses the signature:
   * parallelism changes the latency, never the verdict.
   */
  private async assertKeyIsolatedFromProductionAggregators(
    localKey: string,
    localChainId: number
  ): Promise<void> {
    const forbidden = this.aggregatorPolicy().forbidden;

    if (forbidden.length === 0) {
      // Acknowledged devnet. Refuse the acknowledgement itself on any chain that carries real
      // deployments, so the escape cannot be used where the scan actually matters.
      if (CHAINS_WITH_PRODUCTION_STAKE.has(localChainId)) {
        throw repCreditError(
          "REPCREDIT_AGGREGATOR_POLICY_VIOLATION",
          `REPCREDIT_NO_PRODUCTION_AGGREGATOR is not accepted on chain ${localChainId}, which ` +
            "hosts production deployments — set AUDIT_BLS_AGGREGATOR_ADDRESS (and any " +
            "REPCREDIT_FORBIDDEN_AGGREGATORS) so the signing key can be checked against them"
        );
      }
      this.logger.warn(
        `RepCredit: signing on chain ${localChainId} with an EMPTY production-aggregator ` +
          "deny-list (REPCREDIT_NO_PRODUCTION_AGGREGATOR=true). No key-reuse check is " +
          "possible; the experiment key must be ephemeral and this chain must hold no stake."
      );
      return;
    }

    for (const aggregator of forbidden) {
      await this.assertKeyAbsentFrom(aggregator, localKey);
    }
  }

  /** One aggregator: reachable, speaks the ABI, and does not hold `localKey` in any slot. */
  private async assertKeyAbsentFrom(aggregator: string, localKey: string): Promise<void> {
    // NOTE: the underlying error text is LOGGED (scrubbed), never returned. ethers wraps
    // provider failures with request detail that carries the RPC URL, and the RPC URL carries
    // the provider API key — `scrubProviderError` is what keeps that out of both the log line
    // and the response. The caller gets the fact of the refusal, nothing more.
    let code: string;
    try {
      code = await this.blockchain.getCode(aggregator);
    } catch (error) {
      this.logger.error(
        `RepCredit: getCode on the production aggregator ${aggregator} failed: ` +
          scrubProviderError(error)
      );
      throw repCreditError(
        "REPCREDIT_ISOLATION_INDETERMINATE",
        `cannot read the production aggregator at ${aggregator} — refusing to sign without a ` +
          "verifiable aggregator to isolate against"
      );
    }
    if (!code || code === "0x") {
      throw repCreditError(
        "REPCREDIT_ISOLATION_INDETERMINATE",
        `no contract deployed at production aggregator ${aggregator} on this chain — ` +
          "refusing to sign without a verifiable aggregator to isolate against"
      );
    }
    try {
      await this.blockchain.probeBlsAggregator(aggregator);
    } catch (error) {
      this.logger.error(
        `RepCredit: the production aggregator ${aggregator} failed the BLSAggregator interface ` +
          `probe: ${scrubProviderError(error)}`
      );
      throw repCreditError(
        "REPCREDIT_ISOLATION_INDETERMINATE",
        `production aggregator ${aggregator} does not answer the BLSAggregator interface on ` +
          "this chain"
      );
    }

    // FLOORED at the contract's MAX_VALIDATORS, never just AUDIT_MAX_SLOTS: this is a
    // security scan, and an operator lowering AUDIT_MAX_SLOTS must not be able to shrink it
    // into missing the slot their key actually sits in. A LARGER configured value is honoured.
    const configured = this.config.get<number>("auditMaxSlots") ?? MAX_VALIDATORS;
    const maxSlots = Math.max(MAX_VALIDATORS, Number.isInteger(configured) ? configured : 0);
    const slots = Array.from({ length: maxSlots }, (_, i) => i + 1);
    // allSettled, not all: a rejection must not cancel the remaining reads before their
    // results are inspected, and EVERY outcome is examined below. Any rejection refuses.
    const reads = await Promise.allSettled(
      slots.map(slot => this.blockchain.getBlsPublicKeyAtSlotStrict(aggregator, slot))
    );
    for (let i = 0; i < reads.length; i++) {
      const slot = slots[i];
      const read = reads[i];
      if (read.status === "rejected") {
        this.logger.error(
          `RepCredit: aggregator slot ${slot} read failed on ${aggregator}: ` +
            scrubProviderError(read.reason)
        );
        throw repCreditError(
          "REPCREDIT_ISOLATION_INDETERMINATE",
          `could not determine whether the local BLS key is active at aggregator ${aggregator} ` +
            `slot ${slot} — refusing to sign on an indeterminate isolation check`
        );
      }
      const key = read.value;
      if (key && key.toLowerCase() === localKey) {
        this.logger.error(
          `RepCredit refused to sign: the local BLS key is active at slot ${slot} on the ` +
            `production aggregator ${aggregator}. Experiment keys must be ephemeral and ` +
            "registered on the experiment aggregator only (CC-49 HIGH-A)."
        );
        throw repCreditError(
          "REPCREDIT_KEY_NOT_ISOLATED",
          `local BLS key is also active at slot ${slot} on production aggregator ${aggregator} ` +
            "— an experiment co-signature made with it would be a byte-valid production slash " +
            "proof; use an ephemeral experiment key"
        );
      }
    }
  }

  /**
   * Reputation path only. `defaultThreshold` is what BLSAggregator.verifyAndExecute
   * enforces for the reputation branch (contract default 7).
   */
  private async requireOnChainThreshold(aggregator: string, threshold: number): Promise<void> {
    const onChainThreshold = await this.blockchain.getBlsDefaultThreshold(aggregator);
    if (threshold < onChainThreshold) {
      throw repCreditError(
        "REPCREDIT_THRESHOLD_BELOW_ONCHAIN",
        `threshold ${threshold} is below on-chain defaultThreshold ${onChainThreshold}`
      );
    }
  }

  /**
   * Slash path (CC-49 MEDIUM-1). The contract's slash-only branch enforces
   * `slashThresholds[slashLevel]` (bootstrap WARNING 2 / MINOR 3 / MAJOR 3), NOT the flat
   * `defaultThreshold` used by the reputation branch. Reading the wrong getter made this
   * service reject legal quorums when defaultThreshold was higher, and pass under-quorum
   * aggregates through to an on-chain revert when it was lower. Mirrors the severity-keyed
   * source already used by the production audit path (`auditSlashThresholds`).
   */
  private async requireOnChainSlashThreshold(
    aggregator: string,
    slashLevel: unknown,
    threshold: number
  ): Promise<void> {
    // Validate before spending an RPC read on caller-supplied input. This bounds the
    // level only so the on-chain lookup key is well-formed — the contract's mapping is
    // keyed 0..2. The tighter policy (MINOR/MAJOR only) stays in the single authoritative
    // place, normalizedSlashProposalValues, which runs inside the aggregate call below.
    if (!Number.isInteger(slashLevel) || (slashLevel as number) < 0 || (slashLevel as number) > 2) {
      throw repCreditError(
        "REPCREDIT_SLASH_LEVEL_INVALID",
        "slashLevel must be an integer in [0, 2]"
      );
    }
    const level = slashLevel as number;
    const onChainThreshold = await this.blockchain.getBlsSlashThreshold(aggregator, level);
    if (threshold < onChainThreshold) {
      throw repCreditError(
        "REPCREDIT_THRESHOLD_BELOW_ONCHAIN",
        `threshold ${threshold} is below on-chain slashThresholds[${level}] ${onChainThreshold}`
      );
    }
  }

  private configuredSlot(): number {
    const slot = this.config.get<number>("repCreditValidatorSlot") ?? 0;
    if (!Number.isInteger(slot) || slot < 1 || slot > MAX_VALIDATORS) {
      throw repCreditError(
        "REPCREDIT_VALIDATOR_SLOT_INVALID",
        `REPCREDIT_VALIDATOR_SLOT must be in [1, ${MAX_VALIDATORS}]`
      );
    }
    return slot;
  }

  private aggregatorAddress(): string {
    // Re-assert here so the isolation invariant holds for any future caller that
    // resolves the aggregator without going through requireArmed(). The policy check also
    // owns the "address is required" case.
    this.aggregatorPolicy();
    return this.config.get<string>("repCreditBlsAggregatorAddress") as string;
  }
}

/**
 * Render a thrown value's own text for an error body. The result still passes through
 * `structuredError`'s scrub, so a provider error that reaches here cannot carry a credential
 * out — but nothing on these paths should be a provider error in the first place: RPC failures
 * are caught at their own call sites and reported as `REPCREDIT_RPC_UNAVAILABLE`.
 */
function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
