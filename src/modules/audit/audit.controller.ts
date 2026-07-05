import { Controller, Get } from "@nestjs/common";
import { ApiOperation, ApiTags } from "@nestjs/swagger";
import { AuditService, AuditDetection } from "./audit.service.js";

/**
 * Read-only status surface for the DVT audit module (Phase 2 / 目标2). Exposes whether
 * auditing is enabled, its cadence, the watched operators, and the most recent detections
 * so operators can confirm the auditor is live and see what it has flagged. No secrets and
 * no write actions — filing/executing slashes happens only from the autonomous poll.
 */
@ApiTags("audit")
@Controller("audit")
export class AuditController {
  constructor(private readonly auditService: AuditService) {}

  @Get("status")
  @ApiOperation({
    summary: "DVT audit status — enabled flag, cadence, watchlist, recent detections",
  })
  async status(): Promise<{
    enabled: boolean;
    intervalMs: number;
    watchlist: string[];
    lastTickAt: number | null;
    recentDetections: AuditDetection[];
    archivedProofCount: number;
  }> {
    return this.auditService.getStatus();
  }
}
