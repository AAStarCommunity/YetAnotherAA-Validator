import { Injectable, ForbiddenException, Logger } from "@nestjs/common";
import { ethers } from "ethers";
import { bls, sigs, BLS_DST, encodeG2Point } from "../../utils/bls.util.js";
import { SignatureResult } from "../../interfaces/signature.interface.js";
import { NodeKeyPair } from "../../interfaces/node.interface.js";
import { BlockchainService } from "../blockchain/blockchain.service.js";

@Injectable()
export class BlsService {
  private readonly logger = new Logger(BlsService.name);

  constructor(private readonly blockchainService: BlockchainService) {}

  /**
   * Fix 2 Stage 1 — owner-authorization gate.
   *
   * Before this node co-signs `userOpHash`, verify the caller holds a valid
   * account-owner ECDSA signature over that exact hash. This must match how the
   * v0.18 account verifies an owner signature, so any signature the account accepts
   * also passes here.
   *
   * Contract convention (AAStarAirAccountBase.sol `_validateECDSA`, line 665):
   *   bytes32 hash = userOpHash.toEthSignedMessageHash();   // EIP-191 prefix
   *   address recovered = ecrecover(hash, v, r, s);
   *   return recovered == owner ? 0 : 1;                    // `address public owner`
   * EIP-191 = `\x19Ethereum Signed Message:\n32` || userOpHash, exactly what ethers'
   * `verifyMessage(getBytes(userOpHash), sig)` reproduces.
   *
   * Stage 1 handles the ECDSA-owner case only. A P256/passkey-only account has no
   * recoverable ECDSA owner, so this gate FAILS CLOSED for it (see #40 for Stage 2
   * P256-owner support) — it must never silently sign.
   *
   * @throws ForbiddenException when authorization is missing/malformed/mismatched.
   */
  private async assertOwnerAuthorized(
    userOpHash: string,
    account: string,
    ownerAuth: string
  ): Promise<void> {
    let owner: string;
    try {
      owner = await this.blockchainService.getAccountOwner(account);
    } catch {
      // Cannot establish authority → fail closed.
      throw new ForbiddenException("owner authorization required");
    }

    // An ECDSA owner recovers to a non-zero EOA. The zero address indicates a
    // P256/passkey-only account with no ECDSA owner — Stage 1 cannot authorize it.
    // TODO(#40): add P256-owner authorization for passkey-only accounts (Stage 2).
    if (owner === ethers.ZeroAddress) {
      throw new ForbiddenException(
        "owner authorization required: account has no ECDSA owner (P256/passkey-only is not supported in Stage 1, see #40)"
      );
    }

    let recovered: string;
    try {
      // Match the contract's EIP-191 convention exactly: prefix over the raw
      // 32-byte userOpHash, then ecrecover.
      recovered = ethers.verifyMessage(ethers.getBytes(userOpHash), ownerAuth);
    } catch {
      throw new ForbiddenException("owner authorization required");
    }

    if (ethers.getAddress(recovered) !== owner) {
      this.logger.warn(
        `Owner-auth rejected for account ${account}: recovered ${recovered}, expected owner ${owner}`
      );
      throw new ForbiddenException("owner authorization required");
    }
  }

  async signMessage(
    userOpHash: string,
    account: string,
    ownerAuth: string,
    node: NodeKeyPair
  ): Promise<SignatureResult> {
    // Authorization gate (Fix 2 Stage 1): reject unless a valid owner signature
    // over userOpHash accompanies the request. Closes the open-oracle hole.
    await this.assertOwnerAuthorized(userOpHash, account, ownerAuth);

    // The value actually signed remains hashToCurve(userOpHash).
    const messageBytes = ethers.getBytes(userOpHash);
    const messagePoint = await bls.G2.hashToCurve(messageBytes, {
      DST: BLS_DST,
    });

    const privateKeyBytes = this.hexToBytes(node.privateKey.substring(2));
    const publicKey = sigs.getPublicKey(privateKeyBytes);
    const signature = await sigs.sign(messagePoint as any, privateKeyBytes);

    // Return both compact and EIP-2537 formats
    return {
      nodeId: node.nodeId,
      signature: this.encodeToEIP2537(signature), // Use EIP-2537 format as default
      signatureCompact: signature.toHex(), // Keep compact format for backward compatibility
      publicKey: publicKey.toHex(),
      message: userOpHash,
    };
  }

  async aggregateSignatures(signatures: any[], publicKeys: any[]): Promise<any> {
    const aggregatedSignature = sigs.aggregateSignatures(signatures);
    const aggregatedPubKey = sigs.aggregatePublicKeys(publicKeys);
    return { aggregatedSignature, aggregatedPubKey };
  }

  async aggregateSignaturesOnly(signatures: any[]): Promise<any> {
    return sigs.aggregateSignatures(signatures);
  }

  async verifySignature(signature: any, messagePoint: any, publicKey: any): Promise<boolean> {
    return await sigs.verify(signature, messagePoint, publicKey);
  }

  async hashMessageToCurve(message: string): Promise<any> {
    const messageBytes = ethers.getBytes(message);
    return await bls.G2.hashToCurve(messageBytes, { DST: BLS_DST });
  }

  encodeToEIP2537(point: any): string {
    // Directly encode the point without conversion
    const encoded = encodeG2Point(point);
    return "0x" + Buffer.from(encoded).toString("hex");
  }

  encodePublicKeyToEIP2537(publicKey: any): string {
    const encoded = this.encodeG1Point(publicKey);
    return "0x" + Buffer.from(encoded).toString("hex");
  }

  private encodeG1Point(point: any): Uint8Array {
    const result = new Uint8Array(128);
    const affine = point.toAffine();

    const xBytes = this.hexToBytes(affine.x.toString(16).padStart(96, "0"));
    const yBytes = this.hexToBytes(affine.y.toString(16).padStart(96, "0"));

    result.set(xBytes, 16); // Skip 16 zero bytes at start
    result.set(yBytes, 80); // Skip 16 zero bytes at start
    return result;
  }

  async getPublicKeyFromPrivateKey(privateKey: string): Promise<string> {
    const privateKeyBytes = this.hexToBytes(privateKey.substring(2));
    const publicKey = sigs.getPublicKey(privateKeyBytes);
    return "0x" + publicKey.toHex();
  }

  private hexToBytes(hex: string): Uint8Array {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
      bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return bytes;
  }
}
