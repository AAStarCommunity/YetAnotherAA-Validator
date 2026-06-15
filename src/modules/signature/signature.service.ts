import { Injectable, BadRequestException } from "@nestjs/common";
import { ethers } from "ethers";
import { BlsService } from "../bls/bls.service.js";
import { NodeService } from "../node/node.service.js";
import { SignatureResult, AggregateSignatureResult } from "../../interfaces/signature.interface.js";
import { sigs, bls, BLS_DST } from "../../utils/bls.util.js";
import { PackedUserOp } from "../blockchain/blockchain.service.js";

@Injectable()
export class SignatureService {
  constructor(
    private readonly blsService: BlsService,
    private readonly nodeService: NodeService
  ) {}

  async signMessage(userOp: PackedUserOp, ownerAuth: string | undefined): Promise<SignatureResult> {
    const node = this.nodeService.getNodeForSigning();
    // bls.service enforces the Fix 2 Stage 1 owner-authorization gate: it derives the
    // authoritative userOpHash from userOp and requires a valid owner signature over it.
    return await this.blsService.signMessage(userOp, ownerAuth, node);
  }

  async aggregateExternalSignatures(signatureStrings: string[]): Promise<AggregateSignatureResult> {
    if (signatureStrings.length < 1) {
      throw new BadRequestException("At least 1 signature is required for aggregation");
    }

    const signatures = [];

    for (const sigHex of signatureStrings) {
      // Handle both EIP-2537 format (256 bytes) and compact format (96 bytes)
      let signature;
      const cleanHex = sigHex.startsWith("0x") ? sigHex.substring(2) : sigHex;

      // Check if it's EIP-2537 format (512 hex chars = 256 bytes)
      if (cleanHex.length === 512) {
        // Parse EIP-2537 format back to BLS signature
        signature = this.parseEIP2537ToSignature(sigHex);
      } else {
        // Assume it's compact format
        signature = this.hexToBlsSignature(sigHex);
      }
      signatures.push(signature);
    }

    // Aggregate signatures only
    const aggregatedSignature = await this.blsService.aggregateSignaturesOnly(signatures);

    return {
      signature: this.blsService.encodeToEIP2537(aggregatedSignature), // Return EIP-2537 format
      signatureCompact: aggregatedSignature.toHex(), // Also include compact format
    };
  }

  private parseEIP2537ToSignature(eipHex: string): any {
    // This is a placeholder - we need to implement proper EIP-2537 parsing
    // For now, throw an error indicating EIP format aggregation is not yet supported
    throw new BadRequestException(
      "EIP-2537 format aggregation not yet implemented. Please use compact format."
    );
  }

  async verifyAggregatedSignature(
    signatureHex: string,
    publicKeyHexes: string[],
    message: string
  ): Promise<{ valid: boolean; message?: string }> {
    try {
      // Convert hex signature to BLS signature
      const signature = this.hexToBlsSignature(
        signatureHex.startsWith("0x") ? signatureHex.substring(2) : signatureHex
      );

      // Convert hex public keys to BLS public keys
      const publicKeys = [];
      for (const pubKeyHex of publicKeyHexes) {
        const cleanHex = pubKeyHex.startsWith("0x") ? pubKeyHex.substring(2) : pubKeyHex;
        const pubKey = bls.G1.Point.fromHex(cleanHex);
        publicKeys.push(pubKey);
      }

      // Aggregate public keys
      const aggregatedPubKey = publicKeys.reduce((acc, pubKey) => acc.add(pubKey));

      // Verify the aggregated signature
      const messageBytes = ethers.getBytes(message);
      const messagePoint = await bls.G2.hashToCurve(messageBytes, {
        DST: BLS_DST,
      });
      const valid = await sigs.verify(signature, messagePoint, aggregatedPubKey);

      return {
        valid,
        message: valid ? "Signature is valid" : "Signature verification failed",
      };
    } catch (error) {
      console.error("BLS verification error:", error);
      return {
        valid: false,
        message: `Verification error: ${error instanceof Error ? error.message : String(error)}`,
      };
    }
  }

  private hexToBlsSignature(hex: string): any {
    const cleanHex = hex.startsWith("0x") ? hex.substring(2) : hex;
    return sigs.Signature.fromHex(cleanHex);
  }

  private hexToBytes(hex: string): Uint8Array {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
      bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return bytes;
  }
}
