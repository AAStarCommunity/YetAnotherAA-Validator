import { Global, Module } from "@nestjs/common";
import { NodeAdminGuard, NodeAdminPolicy } from "./node-admin.guard.js";

/**
 * Application-level home of the node-admin gate (CC-49 round-6 MEDIUM-2).
 *
 * `@UseGuards(NodeAdminGuard)` makes Nest instantiate the guard once per MODULE that declares
 * a controller using it — node, dashboard and gossip — so any state the guard held was
 * partitioned three ways: the "global" anonymous brute-force ledger was really three ledgers
 * of N each, the per-source ledger likewise, and the boot banner printed three times. The
 * state now lives in `NodeAdminPolicy`, provided ONCE here and exported globally, so the three
 * per-module guard shells all spend the same budgets.
 *
 * It is `@Global` because the routes it protects sit in unrelated feature modules and none of
 * them should have to import an admission concern to be protected by it.
 */
@Global()
@Module({
  providers: [NodeAdminPolicy, NodeAdminGuard],
  exports: [NodeAdminPolicy, NodeAdminGuard],
})
export class NodeAdminModule {}
