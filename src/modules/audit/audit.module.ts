import { Module } from "@nestjs/common";
import { ConfigModule, ConfigService } from "@nestjs/config";
import { AuditService } from "./audit.service.js";
import { AuditController } from "./audit.controller.js";
import { BlockchainModule } from "../blockchain/blockchain.module.js";
import { GossipModule } from "../gossip/gossip.module.js";
import { BlsModule } from "../bls/bls.module.js";
import { NodeModule } from "../node/node.module.js";
import { GossipService } from "../gossip/gossip.service.js";
import { BlsService } from "../bls/bls.service.js";
import { NodeService } from "../node/node.service.js";
import { BlockchainService } from "../blockchain/blockchain.service.js";
import { IQuorumCoSigner, PendingSlotCoSigner, QUORUM_COSIGNER } from "./slash-consensus.js";
import { GossipQuorumCoSigner } from "./gossip-quorum-cosigner.js";
import { LivenessKeeperService } from "./liveness-keeper.service.js";
import { GuardianSlashWatcherService } from "./guardian-slash-watcher.service.js";

/**
 * DVT Phase 2 (目标2) — autonomous operator audit module. Reuses the shared BlockchainService
 * (single provider/wallet) for all chain reads/writes.
 *
 * The quorum co-signer is FACTORY-provided (inc-2 live): an ARMED node (AUDIT_EXECUTE_SLASH=true)
 * gets the real gossip-based BLS aggregator (GossipQuorumCoSigner, wired to GossipService); a
 * disarmed node gets the fail-closed PendingSlotCoSigner default. The co-signer self-checks
 * slot/peer availability at coSign time and throws (audit degrades to file+archive) if unavailable.
 * DI is one-way: AuditModule imports GossipModule/BlsModule/NodeModule — not the reverse.
 */
@Module({
  imports: [BlockchainModule, GossipModule, BlsModule, NodeModule, ConfigModule],
  controllers: [AuditController],
  providers: [
    AuditService,
    // inc-2 C1 — liveness attest keeper (opt-in AUDIT_ATTEST_ENABLED). Self-disables at bootstrap
    // when unconfigured; OpsAlertService is @Global so it injects without an explicit import.
    LivenessKeeperService,
    // CC-89 stage-2 — guardian-slash watcher (opt-in AUDIT_GUARDIAN_WATCH_ENABLED). Self-disables at
    // bootstrap when unconfigured. Owns its own read-only provider; OpsAlertService is @Global.
    GuardianSlashWatcherService,
    {
      provide: QUORUM_COSIGNER,
      useFactory: (
        config: ConfigService,
        gossip: GossipService,
        bls: BlsService,
        node: NodeService,
        blockchain: BlockchainService
      ): IQuorumCoSigner => {
        if (config.get<boolean>("auditExecuteSlash") === true) {
          return new GossipQuorumCoSigner(gossip, bls, node, blockchain, config);
        }
        return new PendingSlotCoSigner();
      },
      inject: [ConfigService, GossipService, BlsService, NodeService, BlockchainService],
    },
  ],
  exports: [AuditService],
})
export class AuditModule {}
