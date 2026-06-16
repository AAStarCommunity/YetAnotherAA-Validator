import { Module } from "@nestjs/common";
import { PolicyService } from "./policy.service.js";
import { BlockchainModule } from "../blockchain/blockchain.module.js";

@Module({
  imports: [BlockchainModule],
  providers: [PolicyService],
  exports: [PolicyService],
})
export class PolicyModule {}
