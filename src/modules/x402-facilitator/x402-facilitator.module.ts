import { Module } from "@nestjs/common";
import { X402FacilitatorService } from "./x402-facilitator.service.js";
import { X402FacilitatorController } from "./x402-facilitator.controller.js";
import { X402AuthGuard } from "./x402-auth.guard.js";

/**
 * Optional x402 payment facilitator (#130). Opt-in via X402_FACILITATOR_ENABLED.
 * The CapabilityRegistry it self-registers into is a @Global singleton, so no
 * explicit import is needed here. Always loaded; the endpoints return 503 until
 * X402_FACILITATOR_ENABLED + a valid X402_OPERATOR_PK make the operator wallet live
 * (mirrors the relay module). The auth guard is a provider so it can inject ConfigService.
 */
@Module({
  providers: [X402FacilitatorService, X402AuthGuard],
  controllers: [X402FacilitatorController],
  exports: [X402FacilitatorService],
})
export class X402FacilitatorModule {}
