import { Module } from "@nestjs/common";
import { BlsModule } from "../bls/bls.module.js";
import { BlockchainModule } from "../blockchain/blockchain.module.js";
import { NodeModule } from "../node/node.module.js";
import { RepCreditController } from "./repcredit.controller.js";
import { RepCreditService } from "./repcredit.service.js";

@Module({
  imports: [BlsModule, BlockchainModule, NodeModule],
  controllers: [RepCreditController],
  providers: [RepCreditService],
  exports: [RepCreditService],
})
export class RepCreditModule {}
