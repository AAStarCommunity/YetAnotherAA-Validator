import { Injectable, BadRequestException, ForbiddenException, Logger } from "@nestjs/common";
import { ethers } from "ethers";
import { BlsService } from "../bls/bls.service.js";
import { NodeService } from "../node/node.service.js";
import { PolicyService } from "../policy/policy.service.js";
import { NotificationService } from "../notification/notification.service.js";
import { SignatureResult, AggregateSignatureResult } from "../../interfaces/signature.interface.js";
import { sigs, bls, BLS_DST } from "../../utils/bls.util.js";
import { PackedUserOp } from "../blockchain/blockchain.service.js";

@Injectable()
export class SignatureService {
  private readonly logger = new Logger(SignatureService.name);

  constructor(
    private readonly blsService: BlsService,
    private readonly nodeService: NodeService,
    private readonly policyService: PolicyService,
    private readonly notificationService: NotificationService
  ) {}

  async signMessage(userOp: PackedUserOp, ownerAuth: string | undefined): Promise<SignatureResult> {
    const node = this.nodeService.getNodeForSigning();

    // Fix 2 Stage 1 owner-auth gate FIRST: derive the authoritative userOpHash and
    // require a valid owner signature over it. Running this BEFORE the policy gate
    // (Codex F1) keeps /signature/sign uniformly fail-closed and ensures an
    // unauthenticated caller can never reach the policy gate — so there is no policy
    // oracle and no pre-auth on-chain registry RPC (DoS) surface.
    const userOpHash = await this.blsService.authorizeAndDeriveHash(userOp, ownerAuth);

    // Fix 2 Stage 2 INDEPENDENT policy gate, only reachable AFTER owner-auth passes
    // (so only the account owner can probe it). Refuses out-of-policy ops even with a
    // valid — possibly compromised — owner signature; this independence is the DVT
    // tier's value. Fail-closed: rejection is a 403, never a 200-without-signature.
    const decision = await this.policyService.evaluate(userOp);
    if (!decision.allowed) {
      this.logger.warn(`DVT policy rejected sign for ${userOp.sender}: ${decision.reason}`);
      throw new ForbiddenException("operation rejected by node policy");
    }

    // Sign the SAME already-authorized derived hash (no re-auth, no TOCTOU).
    const result = await this.blsService.signDerivedHash(userOpHash, node);

    // Fire-and-forget large-spend notification (#52). Must never block or fail signing.
    this.notificationService.notifyLargeSpend(userOp, userOpHash);

    return result;
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
