import { Controller, Post, Get, Param, Body, ValidationPipe, Logger, UseGuards } from "@nestjs/common";
import { ThrottleGuard } from "../../common/throttle.guard.js";
import { ApiTags, ApiOperation, ApiResponse, ApiBody } from "@nestjs/swagger";
import { SignatureService } from "./signature.service.js";
import { SignMessageDto } from "../../dto/sign.dto.js";
import { AggregateSignatureDto } from "../../dto/aggregate.dto.js";
import { IsString, IsArray } from "class-validator";
import { ApiProperty } from "@nestjs/swagger";

export class VerifySignatureDto {
  @ApiProperty({
    description: "The aggregated BLS signature to verify",
    example: "0x1234567890abcdef...",
  })
  @IsString()
  signature: string;

  @ApiProperty({
    description: "Array of public keys used in the aggregated signature",
    type: [String],
    example: ["0x8052464ad7afdeaa...", "0x8338213c412750cf..."],
  })
  @IsArray()
  @IsString({ each: true })
  publicKeys: string[];

  @ApiProperty({
    description: "The original message that was signed",
    example: "Hello, BLS signatures!",
  })
  @IsString()
  message: string;
}

@ApiTags("signature")
@Controller("signature")
@UseGuards(ThrottleGuard)
export class SignatureController {
  private readonly logger = new Logger(SignatureController.name);

  constructor(private readonly signatureService: SignatureService) {}

  @ApiOperation({ summary: "Sign a message with current node" })
  @ApiResponse({
    status: 200,
    description: "Message signed successfully",
    schema: {
      type: "object",
      properties: {
        nodeId: {
          type: "string",
          description: "ID of the node that signed the message",
        },
        signature: {
          type: "string",
          description: "BLS signature in hex format",
        },
        publicKey: {
          type: "string",
          description: "Public key of the signing node",
        },
        message: {
          type: "string",
          description: "Original message that was signed",
        },
      },
    },
  })
  @ApiResponse({ status: 400, description: "Request body is not a JSON object (userOp missing)" })
  @ApiResponse({
    status: 403,
    description:
      "Owner authorization required — uniform fail-closed. Returned for malformed userOp " +
      "fields (bad sender / missing fields), getUserOpHash revert, owner read failure, " +
      "P256/passkey-only account (owner==0x0), and missing/malformed/mismatched ownerAuth",
  })
  @ApiBody({ type: SignMessageDto })
  @Post("sign")
  async signMessage(@Body(ValidationPipe) signDto: SignMessageDto) {
    this.logger.log(`=== BLS Sign Request ===`);
    this.logger.log(`userOp.sender: ${signDto.userOp?.sender}`);

    try {
      // Fix 2 Stage 1: bls.service derives the authoritative userOpHash from the full
      // UserOperation and rejects with 403 unless ownerAuth is a valid signature by
      // userOp.sender's on-chain owner over THAT derived hash.
      const result = await this.signatureService.signMessage(
        {
          sender: signDto.userOp.sender,
          nonce: signDto.userOp.nonce,
          initCode: signDto.userOp.initCode,
          callData: signDto.userOp.callData,
          accountGasLimits: signDto.userOp.accountGasLimits,
          preVerificationGas: signDto.userOp.preVerificationGas,
          gasFees: signDto.userOp.gasFees,
          paymasterAndData: signDto.userOp.paymasterAndData,
          // signature does not affect v0.7 getUserOpHash; default to 0x.
          signature: signDto.userOp.signature ?? "0x",
        },
        signDto.ownerAuth
      );

      if ("status" in result) {
        this.logger.log(`⏳ Pending out-of-band confirmation: ${result.userOpHash}`);
        return result;
      }

      this.logger.log(`✅ Sign Success:`);
      this.logger.log(`  Node ID: ${result.nodeId}`);
      this.logger.log(
        `  Signature: ${result.signature?.substring(0, 20)}...${result.signature?.substring(-10)}`
      );
      this.logger.log(
        `  Public Key: ${result.publicKey?.substring(0, 20)}...${result.publicKey?.substring(-10)}`
      );

      return result;
    } catch (error: any) {
      this.logger.error(`❌ Sign Failed: ${error.message}`);
      throw error;
    }
  }

  @ApiOperation({ summary: "Poll out-of-band confirmation status (#124, for SDK/UI)" })
  @ApiResponse({
    status: 200,
    description:
      "{ userOpHash, status: pending|approved|expired|not_found, expiresAt }. " +
      "approved → re-submit POST /signature/sign to release the signature; " +
      "not_found → never created or already consumed by a successful sign; " +
      "expired → TTL elapsed (re-submitting sign re-arms a new confirmation).",
  })
  @Get("confirmation/:userOpHash")
  getConfirmationStatus(@Param("userOpHash") userOpHash: string) {
    const s = this.signatureService.getConfirmationStatus(userOpHash);
    return { userOpHash, ...s };
  }

  @ApiOperation({ summary: "Approve a high-value op pending out-of-band confirmation" })
  @ApiResponse({ status: 200, description: "Confirmation result { confirmed: boolean }" })
  @Post("confirm")
  confirm(@Body() body: { userOpHash?: string; token?: string }) {
    const ok =
      typeof body?.userOpHash === "string" &&
      typeof body?.token === "string" &&
      this.signatureService.confirm(body.userOpHash, body.token);
    this.logger.log(`Confirm ${body?.userOpHash}: ${ok ? "accepted" : "rejected"}`);
    return { confirmed: ok };
  }

  @ApiOperation({ summary: "Aggregate multiple BLS signatures" })
  @ApiResponse({
    status: 200,
    description: "Signatures aggregated successfully",
    schema: {
      type: "object",
      properties: {
        signature: { type: "string", description: "Aggregated BLS signature" },
      },
    },
  })
  @ApiResponse({ status: 400, description: "Invalid input data" })
  @ApiBody({ type: AggregateSignatureDto })
  @Post("aggregate")
  async aggregateSignatures(@Body(ValidationPipe) aggregateDto: AggregateSignatureDto) {
    this.logger.log(`=== BLS Signature Aggregation Request ===`);
    this.logger.log(`Number of signatures to aggregate: ${aggregateDto.signatures?.length || 0}`);

    // Log each signature (truncated for readability)
    aggregateDto.signatures?.forEach((sig, index) => {
      this.logger.log(
        `  Signature ${index + 1}: ${sig?.substring(0, 20)}...${sig?.substring(-10)}`
      );
    });

    try {
      const startTime = Date.now();
      const result = await this.signatureService.aggregateExternalSignatures(
        aggregateDto.signatures
      );
      const duration = Date.now() - startTime;

      this.logger.log(`✅ Aggregation Success (${duration}ms):`);
      this.logger.log(
        `  Aggregated Signature: ${result.signature?.substring(0, 20)}...${result.signature?.substring(-10)}`
      );
      this.logger.log(`  Input signatures: ${aggregateDto.signatures?.length}`);
      this.logger.log(`  Processing time: ${duration}ms`);

      return result;
    } catch (error: any) {
      this.logger.error(`❌ Aggregation Failed: ${error.message}`);
      this.logger.error(`  Error details:`, error);
      this.logger.error(`  Input signatures count: ${aggregateDto.signatures?.length || 0}`);

      // Log problematic signatures if any
      if (aggregateDto.signatures) {
        aggregateDto.signatures.forEach((sig, index) => {
          if (!sig || typeof sig !== "string") {
            this.logger.error(`  Invalid signature at index ${index}: ${typeof sig} - ${sig}`);
          }
        });
      }

      throw error;
    }
  }

  @ApiOperation({ summary: "Verify an aggregated BLS signature" })
  @ApiResponse({
    status: 200,
    description: "Signature verification result",
    schema: {
      type: "object",
      properties: {
        valid: {
          type: "boolean",
          description: "Whether the signature is valid",
        },
        message: { type: "string", description: "Verification message" },
      },
    },
  })
  @ApiResponse({ status: 400, description: "Invalid input data" })
  @ApiBody({ type: VerifySignatureDto })
  @Post("verify")
  async verifySignature(@Body(ValidationPipe) verifyDto: VerifySignatureDto) {
    this.logger.log(`=== BLS Signature Verification Request ===`);
    this.logger.log(`Message: ${verifyDto.message}`);
    this.logger.log(
      `Signature: ${verifyDto.signature?.substring(0, 20)}...${verifyDto.signature?.substring(-10)}`
    );
    this.logger.log(`Public Keys count: ${verifyDto.publicKeys?.length || 0}`);

    // Log each public key (truncated)
    verifyDto.publicKeys?.forEach((pubKey, index) => {
      this.logger.log(
        `  PubKey ${index + 1}: ${pubKey?.substring(0, 20)}...${pubKey?.substring(-10)}`
      );
    });

    try {
      const startTime = Date.now();
      const result = await this.signatureService.verifyAggregatedSignature(
        verifyDto.signature,
        verifyDto.publicKeys,
        verifyDto.message
      );
      const duration = Date.now() - startTime;

      this.logger.log(`${result.valid ? "✅" : "❌"} Verification Result (${duration}ms):`);
      this.logger.log(`  Valid: ${result.valid}`);
      this.logger.log(`  Message: ${result.message}`);
      this.logger.log(`  Processing time: ${duration}ms`);

      return result;
    } catch (error: any) {
      this.logger.error(`❌ Verification Failed: ${error.message}`);
      this.logger.error(`  Error details:`, error);
      throw error;
    }
  }
}
