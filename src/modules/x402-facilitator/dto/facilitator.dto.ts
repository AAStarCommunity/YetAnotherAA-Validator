import { IsObject, IsOptional, IsInt } from "class-validator";
import { ApiProperty } from "@nestjs/swagger";

/**
 * POST /x402/verify and /x402/settle request body — the x402 v2 facilitator
 * envelope the SDK's `FacilitatorClient` sends (`{ x402Version, paymentPayload,
 * paymentRequirements }`). See `aastar-sdk/packages/x402/src/facilitator.ts`.
 *
 * Following the project convention (see sign.dto.ts / relay.dto.ts): the nested
 * objects are NOT field-validated by the DTO — only their top-level presence/type.
 * All real validation (scheme guard, signature recovery, nonce replay, expiry)
 * happens inside X402FacilitatorService, which owns rejection and maps to the
 * correct response. This keeps the global ValidationPipe (whitelist:true,
 * forbidNonWhitelisted:true) from silently stripping nested fields we forward
 * verbatim to ethers / the contract.
 *
 * `paymentPayload.payload.authorization` carries the EIP-3009 fields
 * `{ from, to, value, validAfter, validBefore, nonce }` + `payload.signature`.
 * `paymentRequirements` carries `{ scheme, network, asset, amount, payTo,
 * maxTimeoutSeconds, extra }`, where `extra` additionally carries the
 * SuperPaymaster settlement fields (`settlement`, `maxFee`, `salt`, token
 * `name`/`version`) — schema documented in docs/x402-facilitator.md.
 */
export class FacilitatorRequestDto {
  @ApiProperty({ description: "x402 protocol version (must be 2).", example: 2 })
  @IsOptional()
  @IsInt()
  x402Version?: number;

  @ApiProperty({
    description:
      "x402 v2 PaymentPayload: { x402Version, accepted, payload: { signature, " +
      "authorization: { from, to, value, validAfter, validBefore, nonce } } }.",
  })
  @IsObject()
  paymentPayload: Record<string, unknown>;

  @ApiProperty({
    description:
      "x402 v2 PaymentRequirements: { scheme, network, asset, amount, payTo, " +
      "maxTimeoutSeconds, extra }. `extra` additionally carries SuperPaymaster " +
      "settlement fields { settlement?: 'direct'|'eip-3009', maxFee?, salt?, name?, version? }.",
  })
  @IsObject()
  paymentRequirements: Record<string, unknown>;
}
