import { Global, Module } from "@nestjs/common";
import { CapabilityRegistry } from "./capability-registry.service.js";

@Global()
@Module({
  providers: [CapabilityRegistry],
  exports: [CapabilityRegistry],
})
export class CapabilityModule {}
