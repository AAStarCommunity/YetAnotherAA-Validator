import { Body, Controller, Get, HttpException, Post } from "@nestjs/common";
import { ApiOperation, ApiTags } from "@nestjs/swagger";
import { RelayService } from "./relay.service.js";
import { RelayV3Dto } from "./dto/relay.dto.js";
import type { RelayErrorCode } from "./relay.constants.js";

/**
 * Gasless purchase relay endpoints (#98). Wire-compatible with the legacy
 * Cloudflare Worker so the SDK only repoints `relayerUrl` at a DVT node.
 *
 *   GET  /relay/health  — readiness + operator address
 *   POST /v3/relay      — submit a gasless GToken / aPNTs purchase
 */
@ApiTags("relay")
@Controller()
export class RelayController {
  constructor(private readonly relayService: RelayService) {}

  @Get("relay/health")
  @ApiOperation({ summary: "Relay readiness check" })
  health(): { status: string; operator: string | null; chainId?: number } {
    return {
      status: this.relayService.isEnabled() ? "ok" : "disabled",
      operator: this.relayService.operatorAddress(),
    };
  }

  @Post("v3/relay")
  @ApiOperation({ summary: "Gasless GToken/aPNTs purchase via BuyHelper (EIP-3009 + BuyIntent)" })
  async relayV3(
    @Body() body: RelayV3Dto
  ): Promise<{ txHash: string; matchedRule: string; status: string }> {
    const result = await this.relayService.relay(body);
    if (!result.ok) {
      throw new HttpException(
        { error: result.reason, code: result.code },
        this.httpStatus(result.code)
      );
    }
    return { txHash: result.txHash, matchedRule: result.matchedRule, status: "submitted" };
  }

  private httpStatus(code: RelayErrorCode): number {
    switch (code) {
      case "INVALID_SHAPE":
      case "EXPIRED":
      case "SIGNATURE_INVALID":
        return 400;
      case "NOT_WHITELISTED":
        return 403;
      case "RATE_LIMITED":
        return 429;
      case "INFRA_NOT_READY":
        return 503;
      case "SUBMIT_FAILED":
        return 502;
      default:
        return 500;
    }
  }
}
