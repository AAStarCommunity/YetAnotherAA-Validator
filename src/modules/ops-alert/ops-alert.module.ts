import { Global, Module } from "@nestjs/common";
import { OpsAlertService } from "./ops-alert.service.js";
import { StatusReporterService } from "./status-reporter.service.js";
import { BlockchainModule } from "../blockchain/blockchain.module.js";

/**
 * Global so any module (keeper, relay, …) can inject OpsAlertService without an
 * explicit import — mirrors CapabilityModule. Alerts are opt-in (OPS_ALERT_ENABLED)
 * and no-op until a transport is configured, so this is always safe to load.
 * BlockchainModule is imported so the status heartbeat can probe RPC reachability.
 */
@Global()
@Module({
  imports: [BlockchainModule],
  providers: [OpsAlertService, StatusReporterService],
  exports: [OpsAlertService],
})
export class OpsAlertModule {}
