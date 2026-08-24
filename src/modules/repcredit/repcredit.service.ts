import { BadRequestException, ForbiddenException, Injectable } from "@nestjs/common";
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

@Injectable()
export class RepCreditService {
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
    const onChainKey = await this.blockchain.getBlsPublicKeyAtSlot(aggregator, slot);
    if (!onChainKey) {
      throw new ForbiddenException(`configured validator slot ${slot} is not active`);
    }
    try {
      if (encodeRepCreditPublicKey(node.publicKey) !== onChainKey.toLowerCase()) {
        throw new ForbiddenException(`local BLS key is not registered at validator slot ${slot}`);
      }
    } catch (error) {
      if (error instanceof ForbiddenException) throw error;
      throw new ForbiddenException("local BLS public key is malformed");
    }

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
   * Refuse to share a BLSAggregator instance with the production audit/slash path
   * (CC-49 BLOCKER-1).
   *
   * A quorum produced here is byte-identical to a real slash proof, but it is NOT backed by
   * independent per-node re-verification of the violation. If the experiment ran against the
   * same BLSAggregator the audit path uses, an experiment co-signature would be directly
   * executable against production stake. The experiment must target its own isolated
   * aggregator deployment; production slashing goes through GossipQuorumCoSigner.
   */
  private assertAggregatorIsolation(): void {
    const address = this.config.get<string>("repCreditBlsAggregatorAddress");
    const auditAggregator = this.config.get<string>("auditBlsAggregatorAddress");
    if (address && auditAggregator && auditAggregator.toLowerCase() === address.toLowerCase()) {
      throw new ForbiddenException(
        "REPCREDIT_BLS_AGGREGATOR_ADDRESS must not equal AUDIT_BLS_AGGREGATOR_ADDRESS — " +
          "the experiment signer may not target the production slash aggregator"
      );
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
    if (!Number.isInteger(slot) || slot < 1 || slot > 13) {
      throw new ForbiddenException("REPCREDIT_VALIDATOR_SLOT must be in [1, 13]");
    }
    return slot;
  }

  private aggregatorAddress(): string {
    const address = this.config.get<string>("repCreditBlsAggregatorAddress");
    if (!address) {
      throw new ForbiddenException("REPCREDIT_BLS_AGGREGATOR_ADDRESS is required");
    }
    // Re-assert here so the isolation invariant holds for any future caller that
    // resolves the aggregator without going through requireArmed().
    this.assertAggregatorIsolation();
    return address;
  }
}
