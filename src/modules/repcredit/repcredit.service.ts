import { BadRequestException, ForbiddenException, Injectable } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { BlsService } from "../bls/bls.service.js";
import { BlockchainService } from "../blockchain/blockchain.service.js";
import { NodeService } from "../node/node.service.js";
import {
  aggregateRepCreditResponses,
  encodeRepCreditPublicKey,
  RepCreditAggregate,
  RepCreditCoSignResponse,
  RepCreditProposal,
  validateRepCreditProposal,
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
    const onChainThreshold = await this.blockchain.getBlsDefaultThreshold(aggregator);
    if (threshold < onChainThreshold) {
      throw new BadRequestException(
        `threshold ${threshold} is below on-chain defaultThreshold ${onChainThreshold}`
      );
    }
    try {
      return await aggregateRepCreditResponses(proposal, localChainId, responses, threshold, slot =>
        this.blockchain.getBlsPublicKeyAtSlot(aggregator, slot)
      );
    } catch (error) {
      throw new BadRequestException(error instanceof Error ? error.message : String(error));
    }
  }

  private requireArmed(): void {
    if (this.config.get<boolean>("repCreditExperimentSigning") !== true) {
      throw new ForbiddenException("RepCredit experiment signing is disabled");
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
    return address;
  }
}
