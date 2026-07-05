import { Module } from "@nestjs/common";
import { AuditService } from "./audit.service.js";
import { AuditController } from "./audit.controller.js";
import { BlockchainModule } from "../blockchain/blockchain.module.js";

/**
 * DVT Phase 2 (目标2) — autonomous operator audit module (increment 1). Reuses the shared
 * BlockchainService (single provider/wallet) for all chain reads/writes.
 */
@Module({
  imports: [BlockchainModule],
  controllers: [AuditController],
  providers: [AuditService],
  exports: [AuditService],
})
export class AuditModule {}
