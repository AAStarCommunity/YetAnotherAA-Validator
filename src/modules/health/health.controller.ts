import { createRequire } from "module";
import { Controller, Get, Optional } from "@nestjs/common";
import { ApiOperation, ApiTags } from "@nestjs/swagger";
import { CapabilityRegistry } from "../capability/capability-registry.service.js";

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
  constructor(@Optional() private readonly capabilities?: CapabilityRegistry) {}

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
  } {
    return { status: "ok", version: APP_VERSION, capabilities: this.capList() };
  }

  private capList(): Array<{ name: string; enabled: boolean }> {
    return (this.capabilities?.list() ?? []).map(c => ({ name: c.name, enabled: c.enabled }));
  }
}
