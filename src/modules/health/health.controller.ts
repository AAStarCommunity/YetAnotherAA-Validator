import { Controller, Get, Optional } from "@nestjs/common";
import { ApiOperation, ApiTags } from "@nestjs/swagger";
import { CapabilityRegistry } from "../capability/capability-registry.service.js";

/**
 * Top-level liveness endpoint. Plain `GET /health` is the conventional probe
 * (Docker/Cloudflare/uptime monitors hit it); the node previously only exposed
 * `/node/info` and `/relay/health`, so a bare `/health` 404'd. This always
 * returns 200 while the process is up and lists which optional capabilities are
 * enabled (relay, keeper, policy, …) from the global CapabilityRegistry.
 */
@ApiTags("health")
@Controller("health")
export class HealthController {
  constructor(@Optional() private readonly capabilities?: CapabilityRegistry) {}

  @Get()
  @ApiOperation({ summary: "Liveness check + enabled capabilities" })
  health(): { status: string; capabilities: Array<{ name: string; enabled: boolean }> } {
    const caps = (this.capabilities?.list() ?? []).map(c => ({ name: c.name, enabled: c.enabled }));
    return { status: "ok", capabilities: caps };
  }
}
