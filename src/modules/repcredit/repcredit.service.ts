import { BadRequestException, ForbiddenException, Injectable, Logger } from "@nestjs/common";
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
import { checkRepCreditAggregatorPolicy } from "./repcredit-isolation.js";

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
    const localChainId = await this.blockchain.getChainId();
    let messageHash: string;
    try {
      messageHash = validateRepCreditProposal(proposal, localChainId);
    } catch (error) {
      throw new BadRequestException(error instanceof Error ? error.message : String(error));
    }

    return this.signValidatedHash(messageHash);
  }

  async signSlash(proposal: RepCreditSlashProposal): Promise<RepCreditCoSignResponse> {
    this.requireArmed();
    const localChainId = await this.blockchain.getChainId();
    let messageHash: string;
    try {
      messageHash = validateRepCreditSlashProposal(proposal, localChainId);
    } catch (error) {
      throw new BadRequestException(error instanceof Error ? error.message : String(error));
    }
    return this.signValidatedHash(messageHash);
  }

  private async signValidatedHash(messageHash: string): Promise<RepCreditCoSignResponse> {
    const slot = this.configuredSlot();
    const aggregator = this.aggregatorAddress();
    const node = this.nodeService.getNodeForSigning();

    let localKey: string;
    try {
      localKey = encodeRepCreditPublicKey(node.publicKey);
    } catch {
      throw new ForbiddenException("local BLS public key is malformed");
    }

    // Cheap binding first (2 reads): a misconfigured slot short-circuits before the wider
    // audit-aggregator scan below. Neither check produces a signature on its own.
    const onChainKey = await this.blockchain.getBlsPublicKeyAtSlot(aggregator, slot);
    if (!onChainKey) {
      throw new ForbiddenException(`configured validator slot ${slot} is not active`);
    }
    if (localKey !== onChainKey.toLowerCase()) {
      throw new ForbiddenException(`local BLS key is not registered at validator slot ${slot}`);
    }

    await this.assertKeyIsolatedFromAuditAggregator(localKey);

    const signature = await this.blsService.signRepCreditHash(messageHash, node);
    if (!signature.signatureCompact || !signature.publicKey) {
      throw new ForbiddenException("BLS signer did not return compact signature material");
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
    const localChainId = await this.blockchain.getChainId();
    const aggregator = this.aggregatorAddress();
    await this.requireOnChainThreshold(aggregator, threshold);
    try {
      return await aggregateRepCreditResponses(proposal, localChainId, responses, threshold, slot =>
        this.blockchain.getBlsPublicKeyAtSlot(aggregator, slot)
      );
    } catch (error) {
      throw new BadRequestException(error instanceof Error ? error.message : String(error));
    }
  }

  async aggregateSlash(
    proposal: RepCreditSlashProposal,
    responses: RepCreditCoSignResponse[],
    threshold: number
  ): Promise<RepCreditAggregate> {
    this.requireArmed();
    const localChainId = await this.blockchain.getChainId();
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
      throw new BadRequestException(error instanceof Error ? error.message : String(error));
    }
  }

  /**
   * First gate on every endpoint: armed, and pointed at an aggregator that is NOT the
   * production slash aggregator. Both are pure config checks, so they reject before any
   * caller-supplied field is parsed and before any RPC read is spent.
   */
  private requireArmed(): void {
    if (this.config.get<boolean>("repCreditExperimentSigning") !== true) {
      throw new ForbiddenException("RepCredit experiment signing is disabled");
    }
    this.assertAggregatorIsolation();
  }

  /**
   * Config-layer isolation (CC-49 BLOCKER-1 / HIGH-A / MEDIUM-C). Pure — no RPC — so it
   * rejects before any caller-supplied field is parsed. Requires an isolated experiment
   * aggregator AND an explicitly configured audit aggregator; see repcredit-isolation.ts for
   * why an address comparison alone is not isolation.
   */
  private assertAggregatorIsolation(): void {
    const verdict = checkRepCreditAggregatorPolicy({
      repCreditAggregatorAddress: this.config.get<string>("repCreditBlsAggregatorAddress"),
      auditAggregatorAddress: this.config.get<string>("auditBlsAggregatorAddress"),
      auditAggregatorFromEnv: this.config.get<boolean>("auditBlsAggregatorAddressFromEnv") === true,
    });
    if (!verdict.ok) {
      throw new ForbiddenException(verdict.reason);
    }
  }

  /**
   * Chain-layer isolation (CC-49 HIGH-A): refuse to sign with a key that is ALSO active on the
   * production audit aggregator.
   *
   * The signed preimage carries no aggregator address and no domain tag, so a co-signature
   * produced "for" the experiment aggregator is byte-valid against the production one whenever
   * the same key sits in the same slot on both. Address separation cannot prevent that — only
   * refusing to reuse a production-registered key can. Runs on every signature rather than
   * once at boot, deliberately: a slot can be registered while the node is armed, and a cached
   * "clean" verdict would be exactly the stale answer that matters.
   *
   * Every failure mode is fail-closed:
   *   - audit aggregator has no code, or does not answer the BLSAggregator ABI → refuse
   *     (this is also the wrong-chain guard: a Sepolia address on another chain has no code);
   *   - any slot read fails → refuse (the STRICT reader throws instead of returning `null`,
   *     so a transient RPC error can never be mistaken for "the key is absent");
   *   - the key is found active anywhere in [1, maxSlots] → refuse.
   *
   * Cost: up to 2 × maxSlots (default 13) `eth_call`s per signature, on an endpoint that is
   * already HMAC-authenticated and loopback-bound.
   */
  private async assertKeyIsolatedFromAuditAggregator(localKey: string): Promise<void> {
    const auditAggregator = this.config.get<string>("auditBlsAggregatorAddress");
    if (!auditAggregator) {
      // Unreachable via requireArmed(), which rejects an unset audit aggregator. Kept so the
      // invariant holds for any future caller reaching this method directly.
      throw new ForbiddenException("AUDIT_BLS_AGGREGATOR_ADDRESS is required when armed");
    }

    // NOTE: the underlying error text is LOGGED, never returned. ethers wraps provider
    // failures with request detail that can carry the RPC URL, and the RPC URL carries the
    // provider API key (the redaction finding closed in round 1). The caller gets the fact
    // of the refusal, nothing more.
    let code: string;
    try {
      code = await this.blockchain.getCode(auditAggregator);
    } catch (error) {
      this.logger.error(
        `RepCredit: getCode on the audit aggregator ${auditAggregator} failed: ${errorText(error)}`
      );
      throw new ForbiddenException(
        `cannot read the audit aggregator at ${auditAggregator} — refusing to sign without a ` +
          "verifiable production aggregator to isolate against"
      );
    }
    if (!code || code === "0x") {
      throw new ForbiddenException(
        `no contract deployed at AUDIT_BLS_AGGREGATOR_ADDRESS ${auditAggregator} on this chain — ` +
          "refusing to sign without a verifiable production aggregator to isolate against"
      );
    }
    try {
      await this.blockchain.probeBlsAggregator(auditAggregator);
    } catch (error) {
      this.logger.error(
        `RepCredit: the audit aggregator ${auditAggregator} failed the BLSAggregator interface ` +
          `probe: ${errorText(error)}`
      );
      throw new ForbiddenException(
        `AUDIT_BLS_AGGREGATOR_ADDRESS ${auditAggregator} does not answer the BLSAggregator ` +
          "interface on this chain"
      );
    }

    // FLOORED at the contract's MAX_VALIDATORS, never just AUDIT_MAX_SLOTS: this is a
    // security scan, and an operator lowering AUDIT_MAX_SLOTS must not be able to shrink it
    // into missing the slot their key actually sits in. A LARGER configured value is honoured.
    const configured = this.config.get<number>("auditMaxSlots") ?? MAX_VALIDATORS;
    const maxSlots = Math.max(MAX_VALIDATORS, Number.isInteger(configured) ? configured : 0);
    for (let slot = 1; slot <= maxSlots; slot++) {
      let key: string | null;
      try {
        key = await this.blockchain.getBlsPublicKeyAtSlotStrict(auditAggregator, slot);
      } catch (error) {
        this.logger.error(
          `RepCredit: audit-aggregator slot ${slot} read failed on ${auditAggregator}: ` +
            errorText(error)
        );
        throw new ForbiddenException(
          `could not determine whether the local BLS key is active at audit aggregator slot ` +
            `${slot} — refusing to sign on an indeterminate isolation check`
        );
      }
      if (key && key.toLowerCase() === localKey) {
        this.logger.error(
          `RepCredit refused to sign: the local BLS key is active at slot ${slot} on the ` +
            `production audit aggregator ${auditAggregator}. Experiment keys must be ephemeral ` +
            "and registered on the experiment aggregator only (CC-49 HIGH-A)."
        );
        throw new ForbiddenException(
          `local BLS key is also active at slot ${slot} on the production audit aggregator — ` +
            "an experiment co-signature made with it would be a byte-valid production slash " +
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
      throw new BadRequestException(
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
      throw new BadRequestException("slashLevel must be an integer in [0, 2]");
    }
    const level = slashLevel as number;
    const onChainThreshold = await this.blockchain.getBlsSlashThreshold(aggregator, level);
    if (threshold < onChainThreshold) {
      throw new BadRequestException(
        `threshold ${threshold} is below on-chain slashThresholds[${level}] ${onChainThreshold}`
      );
    }
  }

  private configuredSlot(): number {
    const slot = this.config.get<number>("repCreditValidatorSlot") ?? 0;
    if (!Number.isInteger(slot) || slot < 1 || slot > MAX_VALIDATORS) {
      throw new ForbiddenException(`REPCREDIT_VALIDATOR_SLOT must be in [1, ${MAX_VALIDATORS}]`);
    }
    return slot;
  }

  private aggregatorAddress(): string {
    // Re-assert here so the isolation invariant holds for any future caller that
    // resolves the aggregator without going through requireArmed(). The policy check also
    // owns the "address is required" case.
    this.assertAggregatorIsolation();
    return this.config.get<string>("repCreditBlsAggregatorAddress") as string;
  }
}

function errorText(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
