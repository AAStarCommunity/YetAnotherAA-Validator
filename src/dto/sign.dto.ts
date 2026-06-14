import { IsString, IsNotEmpty, Matches, IsEthereumAddress } from "class-validator";
import { ApiProperty } from "@nestjs/swagger";

/**
 * Request to have this DVT node co-sign a userOpHash.
 *
 * Fix 2 Stage 1 (owner-authorization gate): the node will ONLY co-sign when the
 * request carries a valid account-owner signature (`ownerAuth`) over `userOpHash`.
 * This closes the open-oracle hole (a network-reachable attacker without the owner
 * key can no longer obtain a DVT co-sign). It does NOT defend against owner-key
 * compromise — that is Stage 2, tracked in YetAnotherAA-Validator issue #40.
 *
 * The value actually BLS-signed by the node remains `hashToCurve(userOpHash)`;
 * `account` and `ownerAuth` are used solely for the authorization check.
 */
export class SignMessageDto {
  @ApiProperty({
    description: "The ERC-4337 userOpHash to be BLS co-signed (32-byte hex, 0x-prefixed)",
    example: "0x8bb1b199f427dfc49e5fe40f2f3278cb1a48587824b78263051c8c4d81d77a81",
  })
  @IsString()
  @IsNotEmpty()
  @Matches(/^0x[0-9a-fA-F]{64}$/, {
    message: "userOpHash must be a 0x-prefixed 32-byte hex string",
  })
  userOpHash: string;

  @ApiProperty({
    description: "The AirAccount address whose owner authorizes this co-sign request",
    example: "0x08923CE682336DF2f238C034B4add5Bf73d4028A",
  })
  @IsString()
  @IsNotEmpty()
  @IsEthereumAddress({ message: "account must be a valid Ethereum address" })
  account: string;

  @ApiProperty({
    description:
      "Account-owner ECDSA signature (EIP-191) over userOpHash. Reuse the same owner " +
      "signature that signs the UserOperation. 65-byte hex, 0x-prefixed.",
    example: "0x" + "ab".repeat(65),
  })
  @IsString()
  @IsNotEmpty()
  @Matches(/^0x[0-9a-fA-F]+$/, {
    message: "ownerAuth must be a 0x-prefixed hex string",
  })
  ownerAuth: string;
}
