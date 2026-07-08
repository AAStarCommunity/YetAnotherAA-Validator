import { Module } from "@nestjs/common";
import { ConfigModule } from "@nestjs/config";
import { GossipService } from "./gossip.service.js";
import { GossipController } from "./gossip.controller.js";
import { NodeModule } from "../node/node.module.js";
import { BlsModule } from "../bls/bls.module.js";

@Module({
  imports: [ConfigModule, NodeModule, BlsModule],
  providers: [GossipService],
  controllers: [GossipController],
  exports: [GossipService],
})
export class GossipModule {}
