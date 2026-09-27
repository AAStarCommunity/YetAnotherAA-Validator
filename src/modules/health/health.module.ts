import { Module } from "@nestjs/common";
import { HealthController } from "./health.controller.js";
import { NodeModule } from "../node/node.module.js";

/**
 * Always-on liveness endpoint (`GET /health`). The CapabilityRegistry it reads
 * is a @Global singleton, so no import is needed for it here. NodeModule is
 * imported (CC-36) so /health can additively surface the node key-consistency
 * self-check result via NodeKeyConsistencyService.
 */
@Module({
  imports: [NodeModule],
  controllers: [HealthController],
})
export class HealthModule {}
