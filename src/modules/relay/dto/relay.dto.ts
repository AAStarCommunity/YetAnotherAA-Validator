import { IsObject, IsString } from "class-validator";
import { ApiProperty } from "@nestjs/swagger";

/**
 * POST /v3/relay request body — a gasless GToken / aPNTs purchase.
 *
 * Wire-compatible with the legacy Cloudflare Worker `/v3/relay` so the SDK
 * (`@aastar/tokens` TokenSaleClient.buyGasless) only has to repoint `relayerUrl`
 * at a DVT node. Payload: { intent, buyIntentSig, transferAuth }.
 *
 * Following the project convention (see sign.dto.ts): the nested objects are NOT
 * field-validated by the DTO — only their top-level presence/type. All real
 * validation (whitelist, caps, deadline, signature recovery) happens inside
 * RelayService, which owns rejection and maps to the right HTTP status. This
 * keeps the ValidationPipe from silently stripping nested fields.
 */
export class RelayV3Dto {
  @ApiProperty({
    description:
      "BuyIntent fields: { buyer, paymentToken, paymentAmount, targetToken, " +
      "recipient, minOut, deadline, nonce }. Amounts are decimal strings; nonce is 0x bytes32.",
  })
  @IsObject()
  intent: {
    buyer: string;
    paymentToken: string;
    paymentAmount: string;
    targetToken: string;
    recipient: string;
    minOut: string;
    deadline: number;
    nonce: string;
  };

  @ApiProperty({
    description: "65-byte ECDSA signature (0x r||s||v) over the BuyIntent EIP-712 digest.",
    example: "0x" + "ab".repeat(65),
  })
  @IsString()
  buyIntentSig: string;

  @ApiProperty({
    description:
      "Extras for USDC.transferWithAuthorization (EIP-3009): { validAfter, v, r, s }. " +
      "The remaining transfer params are derived from `intent`.",
  })
  @IsObject()
  transferAuth: {
    validAfter: number;
    v: number;
    r: string;
    s: string;
  };
}
