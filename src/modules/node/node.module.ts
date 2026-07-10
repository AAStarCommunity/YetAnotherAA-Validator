import { Module, forwardRef } from "@nestjs/common";
import { NodeService } from "./node.service.js";
import { NodeController } from "./node.controller.js";
import { IdentityController } from "./identity.controller.js";
import { BlsModule } from "../bls/bls.module.js";
import { BlockchainModule } from "../blockchain/blockchain.module.js";

@Module({
  imports: [forwardRef(() => BlsModule), BlockchainModule],
  providers: [NodeService],
  controllers: [NodeController, IdentityController],
  exports: [NodeService],
})
export class NodeModule {}
