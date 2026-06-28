import { Module } from "@nestjs/common";
import { BlsModule } from "./modules/bls/bls.module.js";
import { NodeModule } from "./modules/node/node.module.js";
import { SignatureModule } from "./modules/signature/signature.module.js";
import { BlockchainModule } from "./modules/blockchain/blockchain.module.js";
import { GossipModule } from "./modules/gossip/gossip.module.js";
import { DashboardModule } from "./modules/dashboard/dashboard.module.js";
import { AppConfigModule } from "./config/config.module.js";
import { CapabilityModule } from "./modules/capability/capability.module.js";
import { KeeperModule } from "./modules/keeper/keeper.module.js";
import { RelayModule } from "./modules/relay/relay.module.js";
import { X402FacilitatorModule } from "./modules/x402-facilitator/x402-facilitator.module.js";
import { HealthModule } from "./modules/health/health.module.js";

@Module({
  imports: [
    AppConfigModule, // must be first — validates env vars on startup
    CapabilityModule, // global singleton registry; must load before optional modules
    BlsModule,
    NodeModule,
    SignatureModule,
    BlockchainModule,
    GossipModule,
    DashboardModule,
    KeeperModule,
    RelayModule,
    X402FacilitatorModule,
    HealthModule,
  ],
})
export class AppModule {}
