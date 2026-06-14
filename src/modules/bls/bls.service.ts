import { Injectable, ForbiddenException, Logger } from "@nestjs/common";
import { ethers } from "ethers";
import { bls, sigs, BLS_DST, encodeG2Point } from "../../utils/bls.util.js";
import { SignatureResult } from "../../interfaces/signature.interface.js";
import { NodeKeyPair } from "../../interfaces/node.interface.js";
import { BlockchainService, PackedUserOp } from "../blockchain/blockchain.service.js";

@Injectable()
export class BlsService {
  private readonly logger = new Logger(BlsService.name);

  constructor(private readonly blockchainService: BlockchainService) {}

  /**
   * Fix 2 Stage 1 — owner-authorization gate.
   *
   * The node co-signs ONLY when the request carries a valid account-owner ECDSA
   * signature over the AUTHORITATIVE userOpHash, which is DERIVED from the full
   * UserOperation (never trusted from the caller). The flow:
   *
   *   account     = userOp.sender                                 (derived, not claimed)
   *   userOpHash  = EntryPoint.getUserOpHash(userOp)              (binds hash↔sender/chain)
   *   owner       = account.owner()
   *   require verifyMessage(getBytes(userOpHash), ownerAuth) == owner
   *   then BLS-sign hashToCurve(userOpHash)  — the SAME derived hash (no TOCTOU)
   *
   * Deriving the hash on-chain is what closes the cross-account oracle hole: an
   * attacker who owns account A cannot get the node to sign account B's userOpHash,
   * because the hash is computed from `userOp.sender` (= B) and getUserOpHash binds
   * it to B, chainId, and the EntryPoint. The owner check then requires B's owner.
   *
   * Owner-signature convention matches AAStarAirAccountBase.sol `_validateECDSA`:
   *   bytes32 hash = userOpHash.toEthSignedMessageHash();  // EIP-191 prefix
   *   ecrecover(hash, v, r, s) == owner                    // `address public owner`
   * which `ethers.verifyMessage(getBytes(userOpHash), sig)` reproduces exactly.
   *
   * Stage 1 handles the ECDSA-owner case only. A P256/passkey-only account
   * (owner() == 0x0) FAILS CLOSED (see #40 for Stage 2 P256-owner support).
   *
   * Fails closed (403) on ANY failure: malformed userOp, getUserOpHash revert,
   * owner read failure, owner == 0x0, malformed/missing ownerAuth, or recovered
   * signer != owner. Never signs on failure.
   *
   * @returns the derived userOpHash to BLS-sign.
   * @throws ForbiddenException on any authorization failure.
   */
  private async authorizeAndDeriveHash(
    userOp: PackedUserOp,
    ownerAuth: string | undefined
  ): Promise<string> {
    // account is the UserOperation sender — derived, never caller-claimed.
    const account = userOp.sender;

    // Derive the authoritative userOpHash on-chain. This binds the hash to the
    // sender, chainId, and EntryPoint — a caller cannot substitute another hash.
    let userOpHash: string;
    try {
      userOpHash = await this.blockchainService.getUserOpHash(userOp);
    } catch {
      throw new ForbiddenException("owner authorization required");
    }

    let owner: string;
    try {
      owner = await this.blockchainService.getAccountOwner(account);
    } catch {
      throw new ForbiddenException("owner authorization required");
    }

    // Zero owner → P256/passkey-only account, no ECDSA owner to authorize against.
    // TODO(#40): add P256-owner authorization for passkey-only accounts (Stage 2).
    if (owner === ethers.ZeroAddress) {
      throw new ForbiddenException(
        "owner authorization required: account has no ECDSA owner (P256/passkey-only is not supported in Stage 1, see #40)"
      );
    }

    let recovered: string;
    try {
      if (typeof ownerAuth !== "string" || ownerAuth.length === 0) {
        throw new Error("missing ownerAuth");
      }
      // EIP-191 over the raw 32-byte derived userOpHash, matching the contract.
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

    return userOpHash;
  }

  async signMessage(
    userOp: PackedUserOp,
    ownerAuth: string | undefined,
    node: NodeKeyPair
  ): Promise<SignatureResult> {
    // Authorization gate (Fix 2 Stage 1): derive the authoritative userOpHash from
    // the full UserOperation and require a valid owner signature over it. Returns
    // the SAME derived hash that gets signed below — no caller-supplied hash, no TOCTOU.
    const userOpHash = await this.authorizeAndDeriveHash(userOp, ownerAuth);

    // BLS-sign hashToCurve(userOpHash) using the exact derived hash.
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
