import { Injectable, Logger } from "@nestjs/common";
import { ethers } from "ethers";
import { bls, sigs, encodeG1Point } from "../../utils/bls.util.js";
import { BlockchainService } from "../blockchain/blockchain.service.js";
import { NodeState } from "../../interfaces/node.interface.js";

export type KeyConsistencyStatus =
  | "ok"
  | "mismatch_local"
  | "mismatch_onchain"
  | "not_registered"
  | "unknown"
  | "skipped_no_private_key";

export interface KeyConsistencyResult {
  status: KeyConsistencyStatus;
  checkedAt: string;
  /**
   * Informational only (per CC-36): whether `nodeId === keccak256(EIP-2537 publicKey)`.
   * The contract's `registerWithProof` path derives nodeId this way, but the older
   * `registerPublicKey(nodeId, publicKey)` bootstrap path lets the caller choose ANY
   * nodeId. A bootstrap-registered node legitimately has `derivedMatches === false`
   * and MUST still be reported `ok` when its keys actually agree — this field must
   * never be folded into `status`.
   */
  derivedMatches: boolean | null;
  nodeId: string;
}

function normalizeHex(hex: string | undefined | null): string {
  return "0x" + (hex ?? "").replace(/^0x/i, "").toLowerCase();
}

/**
 * CC-36 — node key-consistency self-check.
 *
 * Closes a silent failure mode: a DVT node's identity lives in node_state.json
 * (nodeId + publicKey + usually a privateKey). If the key actually used to sign
 * no longer matches what's registered on-chain for that nodeId, registration and
 * startup succeed, the node looks healthy, but every signature it produces will
 * fail verification against the on-chain registration forever — the node is
 * online and silently non-participating.
 *
 * Three-way comparison:
 *   1. local:    privateKey  -> derive pubkey -> compare to node_state.publicKey
 *   2. on-chain: node_state.publicKey (EIP-2537-encoded) -> compare to
 *                registeredKeys(nodeId) (only meaningful when isRegistered(nodeId))
 *   3. derivedMatches (informational only): nodeId == keccak256(EIP-2537 publicKey)
 *
 * Fail-loud, not fail-stop: `check()` never throws. Every failure mode (malformed
 * key material, RPC error, timeout) collapses into a `status` value so a broken
 * node stays observable instead of taking the process down with it — a node that
 * already can't produce valid signatures gains nothing from also losing its
 * health/metrics endpoint.
 */
@Injectable()
export class NodeKeyConsistencyService {
  private readonly logger = new Logger(NodeKeyConsistencyService.name);
  private lastResult: KeyConsistencyResult | null = null;

  constructor(private readonly blockchainService: BlockchainService) {}

  /** The most recent check() result, or null if none has run yet. Read by /health. */
  getLastResult(): KeyConsistencyResult | null {
    return this.lastResult;
  }

  async check(nodeState: NodeState, contractAddress: string): Promise<KeyConsistencyResult> {
    const checkedAt = new Date().toISOString();
    const derivedMatches = this.computeDerivedMatches(nodeState);

    const local = this.checkLocal(nodeState);
    const onchain = await this.checkOnchain(nodeState, contractAddress);
    const status = this.combine(local, onchain);

    const result: KeyConsistencyResult = {
      status,
      checkedAt,
      derivedMatches,
      nodeId: nodeState.nodeId,
    };

    if (status === "mismatch_local" || status === "mismatch_onchain") {
      const localPrefix = this.prefix(nodeState.publicKey);
      this.logger.error(
        `KEY CONSISTENCY FAILURE [${status}] for node ${nodeState.nodeId}: ` +
          (status === "mismatch_local"
            ? `the private key in node_state.json does NOT derive node_state.publicKey ` +
              `(local publicKey=${localPrefix}...). `
            : `node_state.publicKey (${localPrefix}...) does NOT match the on-chain ` +
              `registeredKeys() entry for this nodeId. `) +
          `This node will keep signing, but its signatures can NEVER verify against the ` +
          `on-chain registration — it is online and healthy while being silently ` +
          `non-participating. Fix: re-register the correct public key on-chain for this ` +
          `nodeId, or restore the matching privateKey/publicKey pair in node_state.json.`
      );
    }

    this.lastResult = result;
    return result;
  }

  private prefix(hex: string | undefined): string {
    const h = (hex ?? "").replace(/^0x/i, "");
    return "0x" + h.slice(0, 10);
  }

  /** privateKey -> derived pubkey vs. node_state.publicKey. Key-less nodes are a legitimate skip. */
  private checkLocal(nodeState: NodeState): "ok" | "mismatch" | "skipped" {
    if (!nodeState.privateKey) {
      return "skipped";
    }
    try {
      const privHex = nodeState.privateKey.replace(/^0x/i, "");
      const privBytes = new Uint8Array(privHex.length / 2);
      for (let i = 0; i < privHex.length; i += 2) {
        privBytes[i / 2] = parseInt(privHex.substr(i, 2), 16);
      }
      const derivedPub = sigs.getPublicKey(privBytes);
      const derivedHex = normalizeHex(derivedPub.toHex());
      const stateHex = normalizeHex(nodeState.publicKey);
      return derivedHex === stateHex ? "ok" : "mismatch";
    } catch (error: any) {
      // Malformed key material — cannot prove correctness, so treat as a mismatch rather
      // than silently skipping (a corrupt privateKey is itself worth surfacing).
      this.logger.warn(
        `local key-consistency check could not compute a public key from privateKey: ${error?.message ?? error}`
      );
      return "mismatch";
    }
  }

  /** node_state.publicKey (EIP-2537-encoded) vs. registeredKeys(nodeId), gated by isRegistered. */
  private async checkOnchain(
    nodeState: NodeState,
    contractAddress: string
  ): Promise<"ok" | "mismatch" | "not_registered" | "unknown"> {
    try {
      const isRegistered = await this.blockchainService.checkNodeRegistration(
        contractAddress,
        nodeState.nodeId
      );
      if (!isRegistered) {
        return "not_registered";
      }

      const localEip2537 = this.toEip2537Hex(nodeState.publicKey);
      if (localEip2537 === null) {
        // Registered on-chain, but the local publicKey isn't even a parsable curve
        // point — we cannot determine agreement either way. Never guess: unknown.
        this.logger.warn(
          `key-consistency check: node_state.publicKey for ${nodeState.nodeId} is not a valid ` +
            "G1 point; cannot compare against the on-chain registration"
        );
        return "unknown";
      }

      const onchainKey = await this.blockchainService.getNodePublicKey(
        contractAddress,
        nodeState.nodeId
      );
      return normalizeHex(onchainKey) === normalizeHex(localEip2537) ? "ok" : "mismatch";
    } catch (error: any) {
      // RPC failure/timeout/revert. NEVER read this as a mismatch (would falsely accuse a
      // healthy node) and NEVER read it as ok (would hide a real mismatch) — indeterminate.
      this.logger.warn(
        `on-chain key-consistency read failed for node ${nodeState.nodeId}: ${error?.message ?? error}`
      );
      return "unknown";
    }
  }

  /** Informational: does nodeId == keccak256(EIP-2537 publicKey)? Never feeds into `status`. */
  private computeDerivedMatches(nodeState: NodeState): boolean | null {
    if (!nodeState.nodeId) {
      return null;
    }
    const eip2537 = this.toEip2537Hex(nodeState.publicKey);
    if (eip2537 === null) {
      return null;
    }
    const derivedNodeId = ethers.keccak256(eip2537);
    return normalizeHex(derivedNodeId) === normalizeHex(nodeState.nodeId);
  }

  /** Decompress a 48-byte compressed G1 hex pubkey and re-encode it as 128-byte EIP-2537. */
  private toEip2537Hex(compressedPublicKeyHex: string | undefined): string | null {
    if (!compressedPublicKeyHex) {
      return null;
    }
    try {
      const point = bls.G1.Point.fromHex(compressedPublicKeyHex.replace(/^0x/i, ""));
      const encoded = encodeG1Point(point);
      return "0x" + Buffer.from(encoded).toString("hex");
    } catch {
      return null;
    }
  }

  /**
   * Priority (highest severity first): a proven local mismatch is the most certain
   * signal (the key on disk is definitely broken), then a proven on-chain mismatch
   * (the exact silent failure this check exists to catch), then the informational
   * not_registered / unknown on-chain outcomes, then — only once nothing else is
   * wrong — `skipped_no_private_key` if the local dimension could not be checked at
   * all (a key-less node is legitimate, but we were only able to verify half the
   * picture, so we don't claim full `ok`).
   */
  private combine(
    local: "ok" | "mismatch" | "skipped",
    onchain: "ok" | "mismatch" | "not_registered" | "unknown"
  ): KeyConsistencyStatus {
    if (local === "mismatch") return "mismatch_local";
    if (onchain === "mismatch") return "mismatch_onchain";
    if (onchain === "not_registered") return "not_registered";
    if (onchain === "unknown") return "unknown";
    if (local === "skipped") return "skipped_no_private_key";
    return "ok";
  }
}
