import { Module } from "@nestjs/common";
import { BlsService } from "./bls.service.js";
import { BlockchainModule } from "../blockchain/blockchain.module.js";

@Module({
  imports: [BlockchainModule],
  providers: [BlsService],
  exports: [BlsService],
})
export class BlsModule {}
