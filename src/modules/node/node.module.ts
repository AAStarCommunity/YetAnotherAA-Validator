import { Module, forwardRef } from "@nestjs/common";
import { NodeService } from "./node.service.js";
import { NodeController } from "./node.controller.js";
import { IdentityController } from "./identity.controller.js";
import { NodeKeyConsistencyService } from "./node-key-consistency.service.js";
import { BlsModule } from "../bls/bls.module.js";
import { BlockchainModule } from "../blockchain/blockchain.module.js";

@Module({
  imports: [forwardRef(() => BlsModule), BlockchainModule],
  providers: [NodeService, NodeKeyConsistencyService],
  controllers: [NodeController, IdentityController],
  exports: [NodeService, NodeKeyConsistencyService],
})
export class NodeModule {}
