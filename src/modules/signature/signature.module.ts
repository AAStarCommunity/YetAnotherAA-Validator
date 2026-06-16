import { Module } from "@nestjs/common";
import { SignatureService } from "./signature.service.js";
import { SignatureController } from "./signature.controller.js";
import { BlsModule } from "../bls/bls.module.js";
import { NodeModule } from "../node/node.module.js";
import { PolicyModule } from "../policy/policy.module.js";
import { NotificationModule } from "../notification/notification.module.js";
import { ThrottleGuard } from "../../common/throttle.guard.js";

@Module({
  imports: [BlsModule, NodeModule, PolicyModule, NotificationModule],
  providers: [SignatureService, ThrottleGuard],
  controllers: [SignatureController],
  exports: [SignatureService],
})
export class SignatureModule {}
