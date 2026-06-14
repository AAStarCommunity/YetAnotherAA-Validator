import { IsOptional, IsObject } from "class-validator";
import { ApiProperty, ApiPropertyOptional } from "@nestjs/swagger";

/**
 * ERC-4337 v0.7 PackedUserOperation.
 *
 * Carries the FULL UserOperation so the node can derive the authoritative
 * userOpHash itself (via EntryPoint.getUserOpHash) rather than trusting a
 * caller-supplied hash. This binds the signed hash to `sender`, the EntryPoint,
 * and chainId — closing the cross-account oracle hole (an attacker can no longer
 * pair their own account's owner signature with a victim's userOpHash).
 *
 * NOTE: the individual fields are intentionally NOT shape-validated by the DTO.
 * A malformed userOp must surface as 403 from the authorization gate (which
 * validates `sender` and lets `EntryPoint.getUserOpHash` reject the rest),
 * keeping the entire /signature/sign endpoint uniformly fail-closed with 403
 * rather than mixing 400 (validation) and 403 (authorization). This is purely
 * about the shape of a *signing request* — there is no signing-leak path either
 * way, since signing only happens after the gate passes.
 */
export class PackedUserOperationDto {
  @ApiProperty({
    description: "Account that the UserOperation is for (becomes the authorized account)",
    example: "0x08923CE682336DF2f238C034B4add5Bf73d4028A",
  })
  sender: string;

  @ApiProperty({ description: "Nonce (uint256, decimal or 0x-hex)", example: "0" })
  nonce: string;

  @ApiProperty({
    description: "Account init code (0x for already-deployed accounts)",
    example: "0x",
  })
  initCode: string;

  @ApiProperty({ description: "Call data", example: "0x" })
  callData: string;

  @ApiProperty({
    description: "Packed verificationGasLimit + callGasLimit (bytes32)",
    example: "0x" + "00".repeat(32),
  })
  accountGasLimits: string;

  @ApiProperty({ description: "preVerificationGas (uint256)", example: "0" })
  preVerificationGas: string;

  @ApiProperty({
    description: "Packed maxPriorityFeePerGas + maxFeePerGas (bytes32)",
    example: "0x" + "00".repeat(32),
  })
  gasFees: string;

  @ApiProperty({ description: "Paymaster and data (0x if none)", example: "0x" })
  paymasterAndData: string;

  @ApiPropertyOptional({
    description:
      "UserOperation signature field. Not used for authorization (ownerAuth is) and " +
      "does not affect getUserOpHash in v0.7. Defaults to 0x.",
    example: "0x",
  })
  signature?: string;
}

/**
 * Request to have this DVT node co-sign a UserOperation.
 *
 * Fix 2 Stage 1 (owner-authorization gate): the node co-signs ONLY when the
 * request carries a valid account-owner signature (`ownerAuth`) over the
 * userOpHash DERIVED from the full `userOp` (never a caller-supplied hash).
 * This closes the open-oracle hole — a network-reachable attacker without the
 * owner key, and an attacker who owns a *different* account, can no longer
 * obtain a DVT co-sign for someone else's userOpHash. It does NOT defend
 * against owner-key compromise — that is Stage 2 (issue #40).
 *
 * Uniform fail-closed contract: EVERY rejected request returns 403 from the
 * authorization gate, never a 400 from the ValidationPipe. The DTO therefore
 * does only the minimum shape check (`userOp` is an object); all field-level
 * and signature validation happens inside the gate → 403.
 */
export class SignMessageDto {
  @ApiProperty({
    description: "The full ERC-4337 v0.7 PackedUserOperation to co-sign",
    type: PackedUserOperationDto,
  })
  @IsObject()
  userOp: PackedUserOperationDto;

  @ApiProperty({
    description:
      "Account-owner ECDSA signature (EIP-191) over the EntryPoint-derived userOpHash. " +
      "Reuse the same owner signature that signs the UserOperation. 65-byte hex, 0x-prefixed. " +
      "Malformed/missing values are rejected with 403 by the authorization gate, not 400.",
    example: "0x" + "ab".repeat(65),
    required: false,
  })
  @IsOptional()
  ownerAuth?: string;
}
