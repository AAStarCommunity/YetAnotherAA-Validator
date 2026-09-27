import { Injectable, ForbiddenException, Logger, Optional } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
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
    private readonly signerService: SignerService,
    // @Optional() so existing 2-arg constructions (unit tests) keep working; when the
    // DI container provides it, hybrid Rust-signer config is read from here.
    @Optional() private readonly configService?: ConfigService
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
   *   require isValid returns magic value 0xa0cf00cf  (AAStarAirAccount isValidOwnerAuth, NOT ERC-1271)
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
      this.logger.warn(
        `Owner-auth rejected for account ${account}: eth_call isValidOwnerAuth returned false`
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
   *
   * Hybrid mode: when RUST_SIGNER_URL is set, signing is delegated to a local Rust
   * signer over loopback HTTP (byte-identical output — verified by the golden-vector
   * test in signer/src/bls.rs — and faster on ARM). When UNSET, signs in-process with
   * @noble/curves and never touches the network (no probe, zero overhead). On any Rust
   * error it falls back to Node signing, unless RUST_SIGNER_REQUIRED=true (fail-closed).
   */
  async signDerivedHash(userOpHash: string, node: NodeKeyPair): Promise<SignatureResult> {
    const rust = this.getRustSignerConfig();
    if (rust) {
      try {
        return await this.signViaRust(rust, userOpHash, node);
      } catch (error: any) {
        if (rust.required) {
          // Production wants Rust — surface the failure instead of silently degrading.
          this.logger.error(`Rust signer required but failed: ${error?.message ?? error}`);
          throw error;
        }
        this.logger.warn(
          `Rust signer unavailable (${error?.message ?? error}), falling back to Node.js signing`
        );
      }
    }
    return this.signViaNode(userOpHash, node);
  }

  /**
   * The ONE place both `signDerivedHash()` and any other consumer that needs to know
   * "which signer is currently authoritative for this node" (the node key-consistency
   * self-check, round-3 High-2) read the hybrid-signer config — so they can never
   * independently re-read the same env vars and silently drift apart on the decision.
   * Returns null when no remote signer is configured at all (plain local signing).
   */
  private getRustSignerConfig(): { url: string; required: boolean; token?: string } | null {
    const url = this.configService?.get<string>("rustSignerUrl");
    if (!url) {
      return null;
    }
    return {
      url,
      required: this.configService?.get<boolean>("rustSignerRequired") === true,
      token: this.configService?.get<string>("rustSignerToken"),
    };
  }

  /**
   * Round-3 High-2, round-4 correction: which public key is CURRENTLY authoritative for
   * this node's signing, resolved via the EXACT same signer selection `signDerivedHash()`
   * uses (`getRustSignerConfig()`). The node key-consistency self-check uses this instead of
   * unconditionally comparing the local `privateKey` field — a node can be configured for
   * remote (Rust/TEE-KMS) signing while STILL carrying a (possibly stale) local `privateKey`
   * in node_state.json, so comparing the local key would be comparing the wrong thing
   * entirely: it could report `ok` while every real (remote) signature actually fails, or
   * report a mismatch while every real signature is actually fine.
   *
   * When a remote signer is configured, this method makes NO request to it and returns
   * `{ source: "remote" }` with nothing to compare — round-4 review (Codex + coordinator):
   * an earlier version probed the remote signer's `/sign` endpoint with a fixed, harmless
   * message to read its public key off the response. That was REJECTED, because it breaks
   * the repo's core invariant that a node signs ONLY after the owner-authorization gate
   * (`authorizeAndDeriveHash`) passes (see CLAUDE.md, and the fail-closed gate above) — a
   * background health-check tick is not an authorized request, so it must never itself
   * cause the signer to produce a signature, no matter how "harmless" the message is:
   *   1. It breaks the audit invariant that every signature a TEE/KMS signer ever produces
   *      corresponds to an authorized request — a probe every cadence tick is an
   *      unauthorized signature with no owner-auth record behind it (~96/node/day at the
   *      15-minute recheck cadence).
   *   2. A KMS-TEE signer's operational policy is opaque to this repo — it may meter,
   *      rate-limit, run anomaly detection, or require operator/device presence per
   *      signature. A background probe competes with real traffic for that budget and could
   *      itself trip a rate limit or an alert, or in the worst case delay a real signature.
   *   3. It signs in the SAME BLS domain (`BLS_DST`, the same `_RO_POP_` suffix) as
   *      production traffic — not a separate, clearly-scoped test domain.
   *
   * The honest consequence: the remote signer's OWN key is NOT verified by this check right
   * now (the self-check reports `skipped_remote_signer` for that dimension — a deliberate,
   * documented limitation, never silently guessed as ok or mismatch in either direction). Two
   * follow-ups would close this WITHOUT ever causing an extra signature (neither is
   * implemented here):
   *   A. Passive observation: every REAL, already-authorized `/sign` response already
   *      includes `public_key` (see `signViaRust`) — record it from actual signing traffic
   *      (keyed by node/time) and compare THAT against the on-chain registration instead of
   *      asking for a dedicated read here. Zero extra signatures; only requires the node to
   *      have signed at least once recently.
   *   B. Ask repo:kms to add a read-only "get public key" endpoint to the remote signer,
   *      distinct from `/sign`, so a health check can query identity without invoking
   *      signing at all.
   *
   * Round-7 correction (Codex + coordinator): the round-4/5 version returned `{ source:
   * "remote" }` for ANY remote configuration, required or optional. That was itself a gap in
   * OPTIONAL mode (`rust.required === false`): `signDerivedHash()` SILENTLY FALLS BACK to the
   * local key (`signViaNode`) whenever the remote call fails — so in optional mode the local
   * `privateKey` is a REAL signing key that gets used, not a stale leftover. Skipping it
   * entirely left exactly the silent-failure gap this whole check exists to close (a stale
   * local fallback key, never verified, signing against the wrong on-chain registration).
   * Required mode has NO fallback path at all, so the local key stays signing-irrelevant
   * there and is still never touched.
   *
   * So now: required mode (or optional-but-no-local-key) -> `{ source: "remote" }`
   * (unverifiable, no fallback exists to check). Optional mode WITH a local `privateKey` ->
   * `{ source: "local_fallback", publicKey }`, derived by the exact same PURE computation as
   * the `"local"` branch (no network call, no signature — `resolveSigningPublicKey` still
   * never causes the checker to sign or contact any signer). The caller (the node
   * key-consistency self-check) MUST tag any result built from `"local_fallback"` with an
   * explicit scope (`scope: "local_fallback_only"`) — an `ok` here proves only that the
   * FALLBACK key is internally consistent, never that the remote signer's primary key is.
   */
  async resolveSigningPublicKey(node: NodeKeyPair): Promise<
    | { source: "local"; publicKey: any }
    | { source: "local_fallback"; publicKey: any }
    | { source: "remote" }
    | { source: "no_signer" }
  > {
    const rust = this.getRustSignerConfig();
    if (!rust) {
      if (!node.privateKey) {
        return { source: "no_signer" };
      }
      const signer = this.signerService.forNode(node);
      const publicKey = await signer.getPublicKey();
      return { source: "local", publicKey };
    }
    if (!rust.required && node.privateKey) {
      // Optional remote + a local key exists: signDerivedHash() WILL fall back to signing
      // with this exact key if the remote call fails, so verifying it (pure derivation, zero
      // signatures) closes a real gap rather than opening one — see the docstring above.
      const signer = this.signerService.forNode(node);
      const publicKey = await signer.getPublicKey();
      return { source: "local_fallback", publicKey };
    }
    return { source: "remote" };
  }

  /** Delegate signing to the local Rust signer. Throws on any transport/HTTP error. */
  private async signViaRust(
    rust: { url: string; token?: string },
    userOpHash: string,
    node: NodeKeyPair
  ): Promise<SignatureResult> {
    const url = `${rust.url.replace(/\/+$/, "")}/sign`;
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    // KMS-TEE mode: attach the shared secret when configured so a KMS signer with
    // KMS_BLS_SIGNER_TOKEN set accepts this request (and rejects other local processes).
    if (rust.token) {
      headers["X-Signer-Token"] = rust.token;
    }
    const response = await fetch(url, {
      method: "POST",
      headers,
      body: JSON.stringify({ user_op_hash: userOpHash, node_id: node.nodeId }),
    });
    if (!response.ok) {
      throw new Error(`Rust signer HTTP ${response.status}`);
    }
    const data = (await response.json()) as {
      signature: string;
      signature_compact: string;
      public_key: string;
    };
    this.logger.debug(`Signed via Rust signer: ${node.nodeId}`);
    // Byte-for-byte identical to the @noble/curves path (golden-vector verified).
    return {
      nodeId: node.nodeId,
      signature: data.signature, // EIP-2537 (0x-prefixed)
      signatureCompact: data.signature_compact, // compressed G2, 96 bytes
      publicKey: data.public_key, // compressed G1, 48 bytes
      message: userOpHash,
    };
  }

  /** In-process @noble/curves signing (the default / fallback path). */
  private async signViaNode(userOpHash: string, node: NodeKeyPair): Promise<SignatureResult> {
    const messageBytes = ethers.getBytes(userOpHash);
    const messagePoint = await bls.G2.hashToCurve(messageBytes, { DST: BLS_DST });

    const signer = this.signerService.forNode(node);
    const publicKey = await signer.getPublicKey();
    const signature = await signer.sign(messagePoint as any);

    return {
      nodeId: node.nodeId,
      signature: this.encodeToEIP2537(signature),
      signatureCompact: signature.toHex(),
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
