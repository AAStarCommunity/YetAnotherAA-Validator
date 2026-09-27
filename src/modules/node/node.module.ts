import { Module, forwardRef } from "@nestjs/common";
import { NodeService } from "./node.service.js";
import { NodeController } from "./node.controller.js";
import { IdentityController } from "./identity.controller.js";
import { NodeKeyConsistencyService } from "./node-key-consistency.service.js";
import { BlsModule } from "../bls/bls.module.js";
import { BlockchainModule } from "../blockchain/blockchain.module.js";

@Module({
  // NodeKeyConsistencyService gets signer selection through BlsService.resolveSigningPublicKey
  // (round-3 High-2) rather than depending on SignerService directly — BlsModule already
  // wires SignerService into BlsService, so no separate SignerModule import is needed here.
  imports: [forwardRef(() => BlsModule), BlockchainModule],
  providers: [NodeService, NodeKeyConsistencyService],
  controllers: [NodeController, IdentityController],
  exports: [NodeService, NodeKeyConsistencyService],
})
export class NodeModule {}
