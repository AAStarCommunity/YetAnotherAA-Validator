import { createRequire } from "module";
import { Controller, Get, Optional } from "@nestjs/common";
import { ApiOperation, ApiTags } from "@nestjs/swagger";
import { CapabilityRegistry } from "../capability/capability-registry.service.js";
import {
  NodeKeyConsistencyService,
  KeyConsistencyResult,
} from "../node/node-key-consistency.service.js";

const require = createRequire(import.meta.url);
const { version: APP_VERSION } = require("../../../package.json") as { version: string };

/**
 * Root + liveness endpoints. Plain `GET /health` is the conventional probe
 * (Docker/Cloudflare/uptime monitors hit it), and `GET /` is the bare-domain
 * landing — both previously 404'd. They always return 200 while the process is
 * up and list which optional capabilities are enabled (relay, keeper, policy, …)
 * from the global CapabilityRegistry.
 */
@ApiTags("health")
@Controller()
export class HealthController {
  constructor(
    @Optional() private readonly capabilities?: CapabilityRegistry,
    // CC-36: optional so /health keeps working even if NodeModule ever isn't wired in
    // some deployment variant. Additive-only field — see `health()` below.
    @Optional() private readonly keyConsistency?: NodeKeyConsistencyService
  ) {}

  @Get()
  @ApiOperation({
    summary: "Service index — identity + version + enabled capabilities + endpoint map",
  })
  root(): {
    service: string;
    status: string;
    version: string;
    capabilities: Array<{ name: string; enabled: boolean }>;
    endpoints: Record<string, string>;
  } {
    return {
      service: "aastar-dvt-node",
      status: "ok",
      version: APP_VERSION,
      capabilities: this.capList(),
      endpoints: {
        health: "GET /health",
        node: "GET /node/info",
        sign: "POST /signature/sign",
        aggregate: "POST /signature/aggregate",
        verify: "POST /signature/verify",
        relay: "POST /v3/relay",
        relayHealth: "GET /relay/health",
        admin: "GET /admin",
        docs: "GET /api",
      },
    };
  }

  @Get("health")
  @ApiOperation({ summary: "Liveness check + enabled capabilities" })
  health(): {
    status: string;
    version: string;
    capabilities: Array<{ name: string; enabled: boolean }>;
    keyConsistency?: KeyConsistencyResult;
  } {
    // Additive-only (CC-36): status/version/capabilities are unchanged and MUST stay
    // that way — external probes depend on them. `keyConsistency` is omitted entirely
    // (not even `null`) until a self-check has actually run, so existing consumers
    // that don't know the field see no shape change.
    const result = this.keyConsistency?.getLastResult() ?? undefined;
    return {
      status: "ok",
      version: APP_VERSION,
      capabilities: this.capList(),
      ...(result ? { keyConsistency: result } : {}),
    };
  }

  private capList(): Array<{ name: string; enabled: boolean }> {
    return (this.capabilities?.list() ?? []).map(c => ({ name: c.name, enabled: c.enabled }));
  }
}
