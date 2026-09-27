import { Injectable, Logger, OnModuleDestroy } from "@nestjs/common";
import { ethers } from "ethers";
import { bls, sigs } from "../../utils/bls.util.js";
import { BlockchainService } from "../blockchain/blockchain.service.js";
import { BlsService } from "../bls/bls.service.js";
import { NodeState } from "../../interfaces/node.interface.js";

export type KeyConsistencyStatus =
  | "ok"
  | "mismatch_local"
  | "mismatch_onchain"
  | "not_registered"
  | "unknown"
  | "skipped_no_private_key";

export interface KeyConsistencyResult {
  /**
   * Most recent CONCLUSIVE status (i.e. one this instance actually determined, never a
   * transient RPC failure "laundered" into `unknown` over a known conclusion — see `check()`).
   */
  status: KeyConsistencyStatus;
  /** When `status` (and `derivedMatches`) was last actually determined — NOT bumped by a failed retry. */
  checkedAt: string;
  /** When the most recent check ATTEMPT ran, successful or not — proves the retry loop is alive. */
  lastAttemptAt: string;
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

/** The outcome of a single, stateless comparison — before it's merged into the held `lastResult`. */
interface FreshCheck {
  status: KeyConsistencyStatus;
  derivedMatches: boolean | null;
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
 * Three-way comparison (one attempt, see `computeFresh`):
 *   1. local:    privateKey  -> derive pubkey -> compare to node_state.publicKey
 *   2. on-chain: node_state.publicKey (EIP-2537-encoded via the SAME encoder the
 *                registration path writes with — BlsService.encodePublicKeyToEIP2537,
 *                never a local re-implementation, so this check can never silently
 *                drift from what registerOnChain() actually wrote) -> compare to
 *                registeredKeys(nodeId) (only meaningful when isRegistered(nodeId))
 *   3. derivedMatches (informational only): nodeId == keccak256(EIP-2537 publicKey)
 *
 * Fail-loud, not fail-stop: a single attempt never throws. Every failure mode
 * (malformed key material, RPC error, timeout) collapses into a `status` value so a
 * broken node stays observable instead of taking the process down with it.
 *
 * Runs as a self-scheduling loop (`start()`), not a one-shot: an `unknown` result
 * (RPC error) retries with bounded backoff (30s/60s/120s/240s, then folding into the
 * regular cadence) rather than freezing forever on a boot-time hiccup, and a
 * CONCLUSIVE result is periodically rechecked (every RECHECK_INTERVAL_MS) so a node
 * that gets kicked off the on-chain registry post-boot (the validator's permissionless
 * `syncNode(nodeId)` deactivating an under-staked/role-losing operator) surfaces as
 * `not_registered` in /health instead of showing its startup `ok` forever. A recheck
 * that itself fails RPC never downgrades a known conclusion to `unknown` — see `check()`.
 */
@Injectable()
export class NodeKeyConsistencyService implements OnModuleDestroy {
  /** Backoff schedule while stuck on `unknown` (RPC down). After this it folds into RECHECK_INTERVAL_MS. */
  private static readonly UNKNOWN_BACKOFF_MS = [30_000, 60_000, 120_000, 240_000];
  /** Cadence once (and while) a conclusive result holds — also the post-backoff fallback cadence. */
  private static readonly RECHECK_INTERVAL_MS = 15 * 60_000;

  private readonly logger = new Logger(NodeKeyConsistencyService.name);
  private lastResult: KeyConsistencyResult | null = null;
  /** Consecutive `unknown` FRESH attempts (independent of `lastResult.status`, which may be a preserved older conclusion). */
  private consecutiveUnknown = 0;
  private timer: ReturnType<typeof setTimeout> | null = null;
  private stopped = true;

  constructor(
    private readonly blockchainService: BlockchainService,
    private readonly blsService: BlsService
  ) {}

  /** The most recently held result (a preserved conclusion survives a failed retry). Read by /health. */
  getLastResult(): KeyConsistencyResult | null {
    return this.lastResult;
  }

  /**
   * Start the self-check loop: an immediate check, then bounded-backoff retries while
   * `unknown`, then periodic rechecks once conclusive. Idempotent — calling again restarts
   * the loop from scratch (stopping any existing timer first) rather than stacking loops.
   */
  start(nodeState: NodeState, contractAddress: string): void {
    this.stop();
    this.stopped = false;
    void this.loop(nodeState, contractAddress);
  }

  /** Stop the loop and clear its timer. Safe to call repeatedly, or before `start()`. */
  stop(): void {
    this.stopped = true;
    if (this.timer !== null) {
      clearTimeout(this.timer);
      this.timer = null;
    }
  }

  /** Nest lifecycle hook — guarantees the timer never survives module/app shutdown. */
  onModuleDestroy(): void {
    this.stop();
  }

  private async loop(nodeState: NodeState, contractAddress: string): Promise<void> {
    await this.check(nodeState, contractAddress);
    if (this.stopped) {
      // stop() raced with this in-flight attempt — don't schedule a next one.
      return;
    }
    const delay = this.nextDelayMs();
    this.timer = setTimeout(() => {
      void this.loop(nodeState, contractAddress);
    }, delay);
    // Never keep the process alive just for this self-check (mirrors the rest of the
    // codebase's fire-and-forget timers; this one just says so explicitly).
    this.timer.unref?.();
  }

  private nextDelayMs(): number {
    const backoff = NodeKeyConsistencyService.UNKNOWN_BACKOFF_MS;
    if (this.consecutiveUnknown > 0 && this.consecutiveUnknown <= backoff.length) {
      return backoff[this.consecutiveUnknown - 1];
    }
    return NodeKeyConsistencyService.RECHECK_INTERVAL_MS;
  }

  /**
   * Run one attempt and merge it into the held result.
   *
   * The merge rule is the load-bearing part: a fresh `unknown` (this attempt's RPC failed)
   * NEVER overwrites a previously-held CONCLUSIVE result — it only bumps `lastAttemptAt`.
   * Reading a network blip as "we no longer know" would silently launder away a real
   * mismatch_onchain the moment the RPC hiccups, which defeats the whole point of this
   * check. `checkedAt` only advances when a conclusion was actually (re-)established.
   */
  async check(nodeState: NodeState, contractAddress: string): Promise<KeyConsistencyResult> {
    const now = new Date().toISOString();
    const fresh = await this.computeFresh(nodeState, contractAddress);

    if (fresh.status === "mismatch_local" || fresh.status === "mismatch_onchain") {
      this.logMismatch(fresh.status, nodeState);
    }

    if (fresh.status === "unknown") {
      this.consecutiveUnknown++;
      if (this.lastResult && this.lastResult.status !== "unknown") {
        this.lastResult = { ...this.lastResult, lastAttemptAt: now };
      } else {
        // No prior conclusion to preserve (first-ever attempt, or every attempt so far has
        // been unknown) — "unknown" IS the current conclusion in that case.
        this.lastResult = {
          status: "unknown",
          checkedAt: now,
          lastAttemptAt: now,
          derivedMatches: fresh.derivedMatches,
          nodeId: nodeState.nodeId,
        };
      }
    } else {
      this.consecutiveUnknown = 0;
      this.lastResult = {
        status: fresh.status,
        checkedAt: now,
        lastAttemptAt: now,
        derivedMatches: fresh.derivedMatches,
        nodeId: nodeState.nodeId,
      };
    }

    return this.lastResult;
  }

  private logMismatch(status: "mismatch_local" | "mismatch_onchain", nodeState: NodeState): void {
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

  private async computeFresh(
    nodeState: NodeState,
    contractAddress: string
  ): Promise<FreshCheck> {
    const derivedMatches = this.computeDerivedMatches(nodeState);
    const local = this.checkLocal(nodeState);
    const onchain = await this.checkOnchain(nodeState, contractAddress);
    const status = this.combine(local, onchain);
    return { status, derivedMatches };
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

  /**
   * Decompress a 48-byte compressed G1 hex pubkey and re-encode it as 128-byte EIP-2537 —
   * via `BlsService.encodePublicKeyToEIP2537`, the SAME encoder `registerOnChain()` writes
   * on-chain with (and gossip/dashboard/quorum-cosigner all read on-chain data with). This is
   * deliberately NOT a local re-implementation: a future change to the encoder would
   * otherwise silently diverge between what got written on-chain and what this check
   * compares against, causing exactly the kind of undetected drift this check exists to catch.
   */
  private toEip2537Hex(compressedPublicKeyHex: string | undefined): string | null {
    if (!compressedPublicKeyHex) {
      return null;
    }
    try {
      const point = bls.G1.Point.fromHex(compressedPublicKeyHex.replace(/^0x/i, ""));
      return this.blsService.encodePublicKeyToEIP2537(point);
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
