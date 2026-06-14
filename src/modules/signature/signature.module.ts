import { Module } from "@nestjs/common";
import { SignatureService } from "./signature.service.js";
import { SignatureController } from "./signature.controller.js";
import { BlsModule } from "../bls/bls.module.js";
import { NodeModule } from "../node/node.module.js";
import { PolicyModule } from "../policy/policy.module.js";

@Module({
  imports: [BlsModule, NodeModule, PolicyModule],
  providers: [SignatureService],
  controllers: [SignatureController],
  exports: [SignatureService],
})
export class SignatureModule {}
