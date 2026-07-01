import { Injectable, ForbiddenException, Logger } from "@nestjs/common";
import { ethers } from "ethers";
import { bls, sigs, BLS_DST, encodeG2Point } from "../../utils/bls.util.js";
import { SignatureResult } from "../../interfaces/signature.interface.js";
import { NodeKeyPair } from "../../interfaces/node.interface.js";
import { BlockchainService, PackedUserOp } from "../blockchain/blockchain.service.js";
import { SignerService } from "../signer/signer.service.js";

@Injectable()
export class BlsService {
  private readonly logger = new Logger(BlsService.name);

  constructor(
    private readonly blockchainService: BlockchainService,
    private readonly signerService: SignerService
  ) {}

  /**
   * Fix 2 Stage 1 & 2 — owner-authorization gate (ERC-1271 style view).
   *
   * The node co-signs ONLY when the account validates the ownerAuth over the
   * AUTHORITATIVE userOpHash (which is DERIVED from the full UserOperation, never
   * trusted from the caller). The flow:
   *
   *   account     = userOp.sender                                 (derived, not claimed)
   *   userOpHash  = EntryPoint.getUserOpHash(userOp)              (binds hash↔sender/chain)
   *   isValid     = account.isValidOwnerAuth(userOpHash, ownerAuth) [eth_call view]
   *   require isValid returns magic value 0x1626ba7e
   *   then BLS-sign hashToCurve(userOpHash)  — the SAME derived hash (no TOCTOU)
   *
   * Deriving the hash on-chain is what closes the cross-account oracle hole: an
   * attacker who owns account A cannot get the node to sign account B's userOpHash,
   * because the hash is computed from `userOp.sender` (= B) and getUserOpHash binds
   * it to B, chainId, and the EntryPoint.
   *
   * By eth_calling the account's `isValidOwnerAuth` view, DVT delegates all signature
   * verification logic to the contract (ECDSA owner, P256 device-passkey, or future
   * auth schemes). DVT NEVER implements P256/WebAuthn locally, ensuring zero drift
   * from the on-chain validation. The account is the single source of truth.
   *
   * Fails closed (403) on ANY failure: malformed userOp, getUserOpHash revert,
   * isValidOwnerAuth revert/timeout, eth_call failure, or magic value mismatch.
   * Never signs on failure.
   *
   * @returns the derived userOpHash to BLS-sign.
   * @throws ForbiddenException on any authorization failure.
   */
  async authorizeAndDeriveHash(
    userOp: PackedUserOp,
    ownerAuth: string | undefined
  ): Promise<string> {
    // Fail-closed shape check (→ 403, never 400): a malformed signing request is
    // rejected by the same authorization gate as a bad signature, keeping the
    // endpoint uniformly fail-closed. `sender` must be a valid address (it becomes
    // the authorized account); the remaining fields must be present so
    // EntryPoint.getUserOpHash can ABI-encode them (any encoding failure also → 403).
    let account: string;
    try {
      if (!userOp || typeof userOp.sender !== "string") {
        throw new Error("malformed userOp");
      }
      account = ethers.getAddress(userOp.sender); // throws on non-address → 403
      const requiredFields: (keyof PackedUserOp)[] = [
        "nonce",
        "initCode",
        "callData",
        "accountGasLimits",
        "preVerificationGas",
        "gasFees",
        "paymasterAndData",
      ];
      for (const f of requiredFields) {
        if (userOp[f] === undefined || userOp[f] === null) {
          throw new Error(`malformed userOp: missing ${String(f)}`);
        }
      }
    } catch {
      throw new ForbiddenException("owner authorization required");
    }

    // Derive the authoritative userOpHash on-chain. This binds the hash to the
    // sender, chainId, and EntryPoint — a caller cannot substitute another hash.
    let userOpHash: string;
    try {
      userOpHash = await this.blockchainService.getUserOpHash(userOp);
    } catch {
      throw new ForbiddenException("owner authorization required");
    }

    // Validate ownerAuth via ERC-1271 style account view (eth_call isValidOwnerAuth).
    // The account handles all signature verification logic (ECDSA, P256 passkey, etc.)
    // and returns magic value 0x1626ba7e if valid. DVT never implements crypto locally.
    let isValid: boolean;
    try {
      if (typeof ownerAuth !== "string" || ownerAuth.length === 0) {
        throw new Error("missing ownerAuth");
      }
      isValid = await this.blockchainService.isValidOwnerAuth(account, userOpHash, ownerAuth);
    } catch {
      throw new ForbiddenException("owner authorization required");
    }

    if (!isValid) {
      this.logger.warn(`Owner-auth rejected for account ${account}: eth_call isValidOwnerAuth returned false`);
      throw new ForbiddenException("owner authorization required");
    }

    return userOpHash;
  }

  async signMessage(
    userOp: PackedUserOp,
    ownerAuth: string | undefined,
    node: NodeKeyPair
  ): Promise<SignatureResult> {
    // Convenience: owner-auth gate then sign. Callers that must run ANOTHER gate
    // between auth and signing (e.g. the node policy gate) should instead call
    // authorizeAndDeriveHash() then signDerivedHash() directly, so nothing runs
    // before owner-auth (no pre-auth oracle / RPC — see signature.service).
    const userOpHash = await this.authorizeAndDeriveHash(userOp, ownerAuth);
    return this.signDerivedHash(userOpHash, node);
  }

  /**
   * BLS-sign an ALREADY-AUTHORIZED derived userOpHash. Only ever call this with a
   * hash returned by authorizeAndDeriveHash (i.e. after the owner-auth gate passed).
   */
  async signDerivedHash(userOpHash: string, node: NodeKeyPair): Promise<SignatureResult> {
    // BLS-sign hashToCurve(userOpHash) using the exact derived hash.
    const messageBytes = ethers.getBytes(userOpHash);
    const messagePoint = await bls.G2.hashToCurve(messageBytes, {
      DST: BLS_DST,
    });

    // Key custody behind the pluggable BlsSigner port (default = local key). The signing
    // algorithm/wire is unchanged (conformance-bound); only WHERE the key lives is abstracted.
    const signer = this.signerService.forNode(node);
    const publicKey = await signer.getPublicKey();
    const signature = await signer.sign(messagePoint as any);

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
