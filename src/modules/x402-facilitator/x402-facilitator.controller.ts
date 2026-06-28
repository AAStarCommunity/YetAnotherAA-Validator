import { Body, Controller, Get, HttpException, HttpStatus, Post, UseGuards } from "@nestjs/common";
import { ApiOperation, ApiTags } from "@nestjs/swagger";
import { X402FacilitatorService } from "./x402-facilitator.service.js";
import { FacilitatorRequestDto } from "./dto/facilitator.dto.js";
import { X402AuthGuard } from "./x402-auth.guard.js";

/**
 * x402 v2 facilitator endpoints (#130), wire-compatible with the SDK's
 * `FacilitatorClient` (`aastar-sdk/packages/x402/src/facilitator.ts`) so a client
 * only repoints its facilitator `url` at `https://<dvt-node>/x402`:
 *
 *   POST /x402/verify     — off-chain signature/expiry/replay check (~100ms)
 *   POST /x402/settle     — submit the on-chain X402Facilitator settlement (~2s)
 *   GET  /x402/supported  — discovery: settleable kinds, assets, fee, contract
 *
 * Response-status contract (matched to the SDK client, which throws on non-2xx and
 * reads the JSON body only on 2xx):
 *  - verify/settle return HTTP 200 with the discriminated body for ALL application
 *    outcomes (isValid:false / success:false carry the reason) so the SDK reads the
 *    result instead of throwing.
 *  - HTTP 503 only when the module is disabled/misconfigured on this node.
 *  - The optional stateless HMAC auth guard may pre-empt /settle with 401/403 (X402AuthGuard).
 */
@ApiTags("x402-facilitator")
@Controller("x402")
export class X402FacilitatorController {
  constructor(private readonly service: X402FacilitatorService) {}

  @Post("verify")
  @ApiOperation({ summary: "x402 verify — off-chain payment signature/expiry/replay check" })
  async verify(
    @Body() body: FacilitatorRequestDto
  ): Promise<{ isValid: boolean; invalidReason?: string; payer?: string }> {
    this.assertEnabled();
    const result = await this.service.verify(body);
    return result.ok
      ? { isValid: true, payer: result.payer }
      : { isValid: false, invalidReason: result.reason };
  }

  @Post("settle")
  @UseGuards(X402AuthGuard)
  @ApiOperation({ summary: "x402 settle — submit the on-chain X402Facilitator settlement" })
  async settle(@Body() body: FacilitatorRequestDto): Promise<{
    success: boolean;
    transaction?: string;
    network?: string;
    payer?: string;
    errorReason?: string;
  }> {
    this.assertEnabled();
    const result = await this.service.settle(body);
    return result.ok
      ? {
          success: true,
          transaction: result.txHash,
          network: this.service.networkId(),
          payer: result.payer,
        }
      : { success: false, errorReason: result.reason };
  }

  @Get("supported")
  @ApiOperation({ summary: "x402 supported — settleable kinds, assets, fee, contract (discovery)" })
  supported(): {
    kinds: Array<{ x402Version: number; scheme: string; network: string; extra: unknown }>;
    extensions: string[];
  } {
    // Always 200 — discovery is safe even when disabled (advertises this node's config).
    return this.service.supported();
  }

  /** 503 when the operator wallet isn't live — a clear misconfiguration signal to clients. */
  private assertEnabled(): void {
    if (!this.service.isEnabled()) {
      throw new HttpException(
        { success: false, errorReason: "x402 facilitator not enabled on this node" },
        HttpStatus.SERVICE_UNAVAILABLE
      );
    }
  }
}
