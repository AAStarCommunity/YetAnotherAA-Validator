import { Module, forwardRef } from "@nestjs/common";
import { NodeService } from "./node.service.js";
import { NodeController } from "./node.controller.js";
import { IdentityController } from "./identity.controller.js";
import { NodeKeyConsistencyService } from "./node-key-consistency.service.js";
import { BlsModule } from "../bls/bls.module.js";
import { BlockchainModule } from "../blockchain/blockchain.module.js";
import { SignerModule } from "../signer/signer.module.js";

@Module({
  // SignerModule is imported directly (not just transitively via BlsModule, which does not
  // export SignerService) so NodeKeyConsistencyService can derive keys through the REAL
  // signing path (round-2 Medium-5) rather than re-implementing hex validation.
  imports: [forwardRef(() => BlsModule), BlockchainModule, SignerModule],
  providers: [NodeService, NodeKeyConsistencyService],
  controllers: [NodeController, IdentityController],
  exports: [NodeService, NodeKeyConsistencyService],
})
export class NodeModule {}
