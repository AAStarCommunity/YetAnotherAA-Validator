import { Global, Module } from "@nestjs/common";
import { OpsAlertService } from "./ops-alert.service.js";

/**
 * Global so any module (keeper, relay, …) can inject OpsAlertService without an
 * explicit import — mirrors CapabilityModule. Alerts are opt-in (OPS_ALERT_ENABLED)
 * and no-op until AASTAR_MONITOR_URL is set, so this is always safe to load.
 */
@Global()
@Module({
  providers: [OpsAlertService],
  exports: [OpsAlertService],
})
export class OpsAlertModule {}
