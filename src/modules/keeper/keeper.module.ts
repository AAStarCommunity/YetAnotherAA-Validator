import { Module } from "@nestjs/common";
import { KeeperService } from "./keeper.service.js";
import { BlockchainModule } from "../blockchain/blockchain.module.js";
import { NotificationModule } from "../notification/notification.module.js";

@Module({
  imports: [BlockchainModule, NotificationModule],
  providers: [KeeperService],
  exports: [KeeperService],
})
export class KeeperModule {}
