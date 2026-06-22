import { Module } from "@nestjs/common";
import { RelayService } from "./relay.service.js";
import { RelayController } from "./relay.controller.js";

/**
 * Optional gasless purchase relay (#98). Opt-in via RELAY_ENABLED. The
 * CapabilityRegistry it self-registers into is a @Global singleton, so no
 * explicit import is needed here. Always loaded; the endpoint returns 503 until
 * RELAY_ENABLED + a valid RELAY_OPERATOR_PK make the operator wallet live.
 */
@Module({
  providers: [RelayService],
  controllers: [RelayController],
  exports: [RelayService],
})
export class RelayModule {}
