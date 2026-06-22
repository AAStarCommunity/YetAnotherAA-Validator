import { Module } from "@nestjs/common";
import { HealthController } from "./health.controller.js";

/**
 * Always-on liveness endpoint (`GET /health`). The CapabilityRegistry it reads
 * is a @Global singleton, so no import is needed here.
 */
@Module({
  controllers: [HealthController],
})
export class HealthModule {}
