import { Module } from "@nestjs/common";
import { BlsService } from "./bls.service.js";
import { BlockchainModule } from "../blockchain/blockchain.module.js";
import { SignerModule } from "../signer/signer.module.js";

@Module({
  imports: [BlockchainModule, SignerModule],
  providers: [BlsService],
  exports: [BlsService],
})
export class BlsModule {}
