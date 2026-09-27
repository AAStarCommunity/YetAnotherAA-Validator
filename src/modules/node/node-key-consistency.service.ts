import { Injectable, Logger, OnModuleDestroy } from "@nestjs/common";
import { ethers } from "ethers";
import { bls } from "../../utils/bls.util.js";
import { BlockchainService } from "../blockchain/blockchain.service.js";
import { BlsService } from "../bls/bls.service.js";
import { NodeState } from "../../interfaces/node.interface.js";

export type KeyConsistencyStatus =
  | "ok"
  | "mismatch_local"
  | "mismatch_onchain"
  | "not_registered"
  | "unknown"
  | "skipped_no_private_key"
  | "skipped_remote_signer";

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
  /**
   * Round-3 Medium: set when the CHECKER ITSELF threw unexpectedly on the most recent
   * attempt (a bug — NOT an RPC blip, which already collapses to `unknown` inside `check()`
   * and never reaches here). `status`/`checkedAt`/`derivedMatches` are the last CONCLUSIVE
   * result from BEFORE the checker broke — preserved, never downgraded — but this field
   * means that conclusion has NOT been re-verified since `checkerErrorAt`; treat it as
   * stale. Cleared the next time an attempt completes without the checker itself throwing
   * (regardless of what status that attempt computes — even a fresh `unknown` clears it,
   * because it proves the checker is running again).
   */
  checkerError?: string;
  checkerErrorAt?: string;
}

/** The outcome of a single, stateless comparison — before it's merged into the held `lastResult`. */
interface FreshCheck {
  status: KeyConsistencyStatus;
  derivedMatches: boolean | null;
}

/** Type-safe against whatever a raw, unvalidated node_state.json actually contains on disk
 *  (round-2 High-3): a non-string field must normalize to "", never throw. */
function normalizeHex(hex: unknown): string {
  const s = typeof hex === "string" ? hex : "";
  return "0x" + s.replace(/^0x/i, "").toLowerCase();
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
 *   1. local:    resolve the CURRENTLY AUTHORITATIVE signing public key via
 *                `BlsService.resolveSigningPublicKey` — the exact same signer selection
 *                `signDerivedHash()` uses (local @noble/curves vs. remote Rust/TEE-KMS,
 *                round-3 High-2) — and compare it to node_state.publicKey (accepting
 *                EITHER wire format actually seen in production — see `parsePublicKeyPoint`,
 *                which also rejects a malformed or point-at-infinity value, round-3 High-1).
 *                When a REMOTE signer is configured, this comparison is deliberately NOT
 *                performed at all (round-4 correction): resolving the remote key would
 *                require asking the signer to sign a probe message, which would make this
 *                background health check itself produce an unauthorized signature — see
 *                `BlsService.resolveSigningPublicKey`'s docstring for why that is
 *                unacceptable. The honest, documented consequence is `skipped_remote_signer`:
 *                a remote-signing node is simply NOT verified by this dimension right now.
 *   2. on-chain: node_state.publicKey normalized to EIP-2537 via the SAME encoder the
 *                registration path writes with — BlsService.encodePublicKeyToEIP2537,
 *                never a local re-implementation, so this check can never silently
 *                drift from what registerOnChain() actually wrote -> compare to
 *                registeredKeys(nodeId) (only meaningful when isRegistered(nodeId))
 *   3. derivedMatches (informational only): nodeId == keccak256(EIP-2537 publicKey)
 *
 * Fail-loud, not fail-stop: a single attempt is designed to never throw — every failure mode
 * (malformed key material, RPC error, timeout) collapses into a `status` value. `loop()`
 * additionally holds a structural boundary in case a future bug throws anyway (round-2
 * High-3) — but unlike an RPC blip, an internal throw is FAIL-LOUD, not silent: it stamps
 * `checkerError`/`checkerErrorAt` onto the (preserved) result rather than quietly retrying
 * forever with no visible trace (round-3 Medium).
 *
 * Runs as a self-scheduling loop (`start()`), not a one-shot: an `unknown` result
 * (RPC error) retries with bounded backoff (30s/60s/120s/240s, then folding into the
 * regular cadence) rather than freezing forever on a boot-time hiccup, and a
 * CONCLUSIVE result is periodically rechecked (every RECHECK_INTERVAL_MS) so a node
 * that gets kicked off the on-chain registry post-boot (the validator's permissionless
 * `syncNode(nodeId)` deactivating an under-staked/role-losing operator) surfaces as
 * `not_registered` in /health instead of showing its startup `ok` forever. A recheck
 * that itself fails RPC never downgrades a known conclusion to `unknown` — see `check()`.
 *
 * `start()` is bound to one node identity at a time and is generation-tokened (round-2
 * Medium-4): restarting it (e.g. NodeService.reloadNodeState() after a dashboard
 * create/import/delete) invalidates any in-flight attempt from the previous identity, so its
 * result — however it eventually resolves — is discarded rather than clobbering the new
 * identity's published result or stacking a second timer.
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
  /** Bumped by every start()/stop(). A loop() iteration captures its generation at start() time
   *  and checks it after each attempt — a mismatch means a newer start()/stop() superseded it. */
  private generation = 0;

  constructor(
    private readonly blockchainService: BlockchainService,
    private readonly blsService: BlsService
  ) {}

  /** The most recently held result (a preserved conclusion survives a failed retry). Read by /health. */
  getLastResult(): KeyConsistencyResult | null {
    return this.lastResult;
  }

  /**
   * Start the self-check loop for `nodeState`: an immediate check, then bounded-backoff
   * retries while `unknown`, then periodic rechecks once conclusive. Idempotent — calling
   * again (e.g. against a NEW node identity after a dashboard create/import) restarts the
   * loop from scratch: stops any existing timer, bumps the generation token (invalidating an
   * in-flight attempt from the previous call), and clears the held result immediately so a
   * previous identity's finding is never shown even for a moment under the new loop.
   */
  start(nodeState: NodeState, contractAddress: string): void {
    this.stop();
    this.lastResult = null;
    this.consecutiveUnknown = 0;
    this.generation++;
    const myGeneration = this.generation;
    this.stopped = false;
    void this.loop(nodeState, contractAddress, myGeneration).catch(() => {});
  }

  /** Stop the loop and clear its timer. Safe to call repeatedly, or before `start()`. Does NOT
   *  clear the held result — callers that also want that (e.g. node deletion) call `clearResult()`. */
  stop(): void {
    this.stopped = true;
    this.generation++; // invalidate any in-flight loop() from the previous start()
    if (this.timer !== null) {
      clearTimeout(this.timer);
      this.timer = null;
    }
  }

  /**
   * Forget the held result entirely (round-2 High-2): called when the node identity is
   * deleted and none replaces it, so /health's `keyConsistency` goes back to being omitted
   * rather than confidently showing a stale identity's "ok" (or any other stale status) for
   * a node that no longer exists. Does not touch the timer/loop — pair with `stop()`.
   */
  clearResult(): void {
    this.lastResult = null;
    this.consecutiveUnknown = 0;
  }

  /** Nest lifecycle hook — guarantees the timer never survives module/app shutdown. */
  onModuleDestroy(): void {
    this.stop();
  }

  private async loop(
    nodeState: NodeState,
    contractAddress: string,
    myGeneration: number
  ): Promise<void> {
    try {
      await this.check(nodeState, contractAddress, myGeneration);
    } catch (error: unknown) {
      // Structural boundary (round-2 High-3), FAIL-LOUD not silent (round-3 Medium): see
      // recordCheckerError. This is deliberately the INNER catch (around check() only) so
      // scheduling below still runs even when check() itself threw — an internal bug must
      // not also kill the retry loop's future ticks. The OUTER `.catch(() => {})` at both
      // call sites of loop() is a separate, last-resort "never crash" net with no logic of
      // its own — the two layers have different jobs and must stay separate.
      this.recordCheckerError(nodeState, error);
    }
    if (this.stopped || myGeneration !== this.generation) {
      // Either stopped, or superseded by a newer start()/stop() while this attempt was in
      // flight — don't reschedule. This is also what keeps exactly one timer alive at a time.
      return;
    }
    const delay = this.nextDelayMs();
    this.timer = setTimeout(() => {
      // Same structural boundary on the recurring path.
      void this.loop(nodeState, contractAddress, myGeneration).catch(() => {});
    }, delay);
    // Never keep the process alive just for this self-check (mirrors the rest of the
    // codebase's fire-and-forget timers; this one just says so explicitly).
    this.timer.unref?.();
  }

  /**
   * Round-3 Medium: `check()` is designed to never throw (every failure mode it knows about
   * collapses into a status), but if it does anyway — a bug, NOT an RPC blip — this must be
   * FAIL-LOUD, never silent. A deterministic internal bug looking identical to "everything's
   * fine, still ok" forever is worse than no result at all — it is a confident lie. The prior
   * CONCLUSIVE result is preserved (same non-downgrade principle as an RPC failure: an
   * internal bug is not grounds to erase a real mismatch_onchain either), but the result is
   * stamped `checkerError`/`checkerErrorAt` so /health visibly flags that conclusion as
   * stale-since, and `lastAttemptAt` still advances (proving the loop itself is alive).
   */
  private recordCheckerError(nodeState: NodeState, error: unknown): void {
    const now = new Date().toISOString();
    const message = error instanceof Error ? error.message : String(error);
    const base: KeyConsistencyResult =
      this.lastResult ??
      ({
        status: "unknown",
        checkedAt: now,
        lastAttemptAt: now,
        derivedMatches: null,
        nodeId: this.safeNodeId(nodeState),
      } as KeyConsistencyResult);
    this.lastResult = {
      ...base,
      lastAttemptAt: now,
      checkerError: message,
      checkerErrorAt: now,
    };
    try {
      this.logger.error(
        `Key-consistency self-check threw unexpectedly (this should never happen — check() is ` +
          `designed to fail loud via a status value, not throw): ${message}. Preserving the ` +
          `last conclusive result (${this.lastResult.status} from ${this.lastResult.checkedAt}) ` +
          `— it has NOT been re-verified since; treat it as stale until the next successful attempt.`
      );
    } catch {
      // Logging itself must never be allowed to turn a checker bug into a crash — this is
      // exactly the concern that made the OUTER loop()-call-site catches necessary too.
    }
  }

  /** Best-effort nodeId read for the synthetic fallback result above — must not itself throw
   *  (e.g. if nodeId is a throwing getter on a pathological nodeState). */
  private safeNodeId(nodeState: NodeState): string {
    try {
      return typeof nodeState?.nodeId === "string" ? nodeState.nodeId : "";
    } catch {
      return "";
    }
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
   * NEVER overwrites a previously-held CONCLUSIVE result — it only bumps `lastAttemptAt` (and
   * clears any stale `checkerError` — reaching this line at all proves the checker itself
   * did NOT throw this time, regardless of what status it computed). Reading a network blip
   * as "we no longer know" would silently launder away a real mismatch_onchain the moment the
   * RPC hiccups, which defeats the whole point of this check. `checkedAt` only advances when
   * a conclusion was actually (re-)established.
   *
   * `generationToken` is set ONLY by `loop()` (a direct/manual call — as every existing unit
   * test makes — omits it and always publishes). When set and stale (round-2 Medium-4: a
   * newer start()/stop() ran while this attempt was in flight), the result is discarded
   * entirely: not merged into `lastResult`, not logged as a fresh finding. `loop()` itself
   * separately checks the generation afterward to decide whether to reschedule.
   */
  async check(
    nodeState: NodeState,
    contractAddress: string,
    generationToken?: number
  ): Promise<KeyConsistencyResult> {
    const now = new Date().toISOString();
    const fresh = await this.computeFresh(nodeState, contractAddress);

    if (generationToken !== undefined && generationToken !== this.generation) {
      return (
        this.lastResult ?? {
          status: fresh.status,
          checkedAt: now,
          lastAttemptAt: now,
          derivedMatches: fresh.derivedMatches,
          nodeId: nodeState.nodeId,
        }
      );
    }

    if (fresh.status === "mismatch_local" || fresh.status === "mismatch_onchain") {
      this.logMismatch(fresh.status, nodeState);
    }

    if (fresh.status === "unknown") {
      this.consecutiveUnknown++;
      if (this.lastResult && this.lastResult.status !== "unknown") {
        this.lastResult = {
          ...this.lastResult,
          lastAttemptAt: now,
          checkerError: undefined,
          checkerErrorAt: undefined,
        };
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
          ? `the current signing key does NOT match node_state.publicKey ` +
            `(local publicKey=${localPrefix}...). `
          : `node_state.publicKey (${localPrefix}...) does NOT match the on-chain ` +
            `registeredKeys() entry for this nodeId. `) +
        `This node will keep signing, but its signatures can NEVER verify against the ` +
        `on-chain registration — it is online and healthy while being silently ` +
        `non-participating. Fix: re-register the correct public key on-chain for this ` +
        `nodeId, or restore the matching signer/publicKey pair in node_state.json.`
    );
  }

  private async computeFresh(nodeState: NodeState, contractAddress: string): Promise<FreshCheck> {
    const derivedMatches = this.computeDerivedMatches(nodeState);
    const local = await this.checkLocal(nodeState);
    const onchain = await this.checkOnchain(nodeState, contractAddress);
    const status = this.combine(local, onchain);
    return { status, derivedMatches };
  }

  /** Type-safe against a raw, unvalidated node_state.json field (round-2 High-3). */
  private prefix(hex: unknown): string {
    const s = typeof hex === "string" ? hex : "";
    return "0x" + s.replace(/^0x/i, "").slice(0, 10);
  }

  /**
   * The CURRENTLY AUTHORITATIVE signing public key vs. node_state.publicKey. Delegates
   * signer selection entirely to `BlsService.resolveSigningPublicKey` (round-3 High-2): a
   * node may be configured for remote (Rust/TEE-KMS) signing while STILL carrying a
   * (possibly stale) local `privateKey` in node_state.json, so this must NEVER just compare
   * the local private key unconditionally — that would compare the wrong thing whenever a
   * remote signer is in play, producing either a false "ok" (local matches, but every real
   * signature is remote and different) or a false mismatch (local is stale, but every real
   * signature is remote and fine).
   *
   * `"no_signer"` (neither a local key nor a remote signer configured) maps to the
   * legitimate `skipped_no_private_key` outcome. `"remote"` (a remote signer IS configured)
   * ALSO maps to `skipped_remote_signer` (round-4 correction) — NEVER a fallback to
   * comparing the local key (which is exactly the bug this exists to prevent) and NEVER a
   * probe of the remote signer either (`resolveSigningPublicKey` deliberately makes no
   * request to it — see its docstring: doing so would make this background check itself
   * produce an unauthorized signature). This is a deliberate, honest limitation: a
   * remote-signing node's local dimension is simply not verified right now.
   */
  private async checkLocal(
    nodeState: NodeState
  ): Promise<"ok" | "mismatch" | "skipped_no_private_key" | "skipped_remote_signer"> {
    try {
      const resolved = await this.blsService.resolveSigningPublicKey(nodeState);
      if (resolved.source === "no_signer") {
        return "skipped_no_private_key";
      }
      if (resolved.source === "remote") {
        return "skipped_remote_signer";
      }

      // resolved.source === "local"
      const derivedHex = normalizeHex(resolved.publicKey.toHex());

      const statePoint = this.parsePublicKeyPoint(nodeState.publicKey);
      if (statePoint === null) {
        // node_state.publicKey isn't a valid point in EITHER accepted wire format.
        return "mismatch";
      }
      return derivedHex === normalizeHex(statePoint.toHex()) ? "ok" : "mismatch";
    } catch (error: any) {
      // Signer resolution itself failed unexpectedly (e.g. the local signer rejected a
      // malformed private key) — cannot prove correctness, so treat as a mismatch rather
      // than silently skipping.
      this.logger.warn(
        `local key-consistency check could not resolve/compare a signing public key: ${error?.message ?? error}`
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
        // Registered on-chain, but the local publicKey isn't a parsable curve point in
        // EITHER accepted wire format — we cannot determine agreement either way. Never
        // guess: unknown.
        this.logger.warn(
          `key-consistency check: node_state.publicKey for ${nodeState.nodeId} is not a valid ` +
            "G1 point in either accepted wire format; cannot compare against the on-chain registration"
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
   * Parse node_state.publicKey into a validated G1 curve point, accepting BOTH wire formats
   * actually seen on real nodes (round-2 review, High-1): 48-byte COMPRESSED (what a signing
   * node normally carries — verified against a live node's `/node/info`) and 128-byte
   * EIP-2537 UNCOMPRESSED (what dashboard.service.ts's create-node path stores —
   * `encodePublicKeyToEIP2537`'s own output — and `import-node.dto.ts` accepts as-is for
   * `publicKey`). Assuming only the compressed form would misreport every dashboard-created
   * node as `mismatch_local` — a false accusation against a legitimately-created node, the
   * same class of bug as trusting `derivedMatches` as a judgment.
   *
   * The 128-byte branch reconstructs the point via @noble/curves' OWN `Point.fromAffine` (a
   * public primitive of the SAME class `.fromHex()` returns) from the raw X/Y coordinates,
   * after first validating the 16-byte zero-padding on EACH coordinate (round-3 High-1.1: a
   * non-zero-padded value is not a well-formed EIP-2537 encoding — the encoder never
   * produces one — so it must be rejected as malformed, not silently normalized as if it
   * were legitimate).
   *
   * BOTH branches then explicitly reject the point-at-infinity (round-3 High-1.2, the more
   * serious gap): `.assertValidity()` alone does NOT reject it — @noble/curves deliberately
   * allows the group identity as "on-curve" — but an infinity "public key" is never a real
   * one: `e(_, infinity) = 1` trivially, so a pairing-based signature check against it would
   * pass with NO private key at all. This is exactly the rogue-key bypass
   * `AAStarValidator.registerWithProof`'s `require(!_isInfinity(publicKey))` guards against
   * on-chain (contracts/src/AAStarValidator.sol) — this check must refuse it with the same
   * finality, not launder it through as a valid-looking "ok" comparison.
   */
  private parsePublicKeyPoint(publicKeyHex: unknown): any | null {
    if (typeof publicKeyHex !== "string" || publicKeyHex.length === 0) {
      return null;
    }
    const hex = publicKeyHex.replace(/^0x/i, "").toLowerCase();
    try {
      if (hex.length === 96) {
        // 48-byte compressed G1.
        const point = bls.G1.Point.fromHex(hex);
        point.assertValidity();
        if (point.is0()) {
          return null; // point-at-infinity — see class doc above.
        }
        return point;
      }
      if (hex.length === 256) {
        // 128-byte EIP-2537: 16 zero-pad + 48-byte X + 16 zero-pad + 48-byte Y — the exact
        // inverse layout of BlsService's private encodeG1Point (byte offsets 16 and 80; in
        // hex-char offsets that's X at [32,128) and Y at [160,256), padding at [0,32) and
        // [128,160)).
        const pad1 = hex.slice(0, 32);
        const pad2 = hex.slice(128, 160);
        if (pad1 !== "0".repeat(32) || pad2 !== "0".repeat(32)) {
          return null; // non-zero padding: not a well-formed EIP-2537 encoding.
        }
        const x = BigInt("0x" + hex.slice(32, 128));
        const y = BigInt("0x" + hex.slice(160, 256));
        const point = bls.G1.Point.fromAffine({ x, y });
        point.assertValidity();
        if (point.is0()) {
          return null; // point-at-infinity — see class doc above.
        }
        return point;
      }
      return null; // neither accepted wire format
    } catch {
      return null;
    }
  }

  /**
   * Normalize node_state.publicKey (either accepted wire format) to 128-byte EIP-2537 — via
   * `BlsService.encodePublicKeyToEIP2537`, the SAME encoder `registerOnChain()` writes
   * on-chain with (and gossip/dashboard/quorum-cosigner all read on-chain data with). This is
   * deliberately NOT a local re-implementation: a future change to the encoder would
   * otherwise silently diverge between what got written on-chain and what this check
   * compares against, causing exactly the kind of undetected drift this check exists to catch.
   */
  private toEip2537Hex(publicKeyHex: unknown): string | null {
    const point = this.parsePublicKeyPoint(publicKeyHex);
    if (point === null) {
      return null;
    }
    try {
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
   * wrong — the two "couldn't fully verify the local dimension" outcomes
   * (`skipped_no_private_key` / `skipped_remote_signer`; a legitimate configuration, but we
   * only verified half the picture, so we don't claim full `ok`).
   */
  private combine(
    local: "ok" | "mismatch" | "skipped_no_private_key" | "skipped_remote_signer",
    onchain: "ok" | "mismatch" | "not_registered" | "unknown"
  ): KeyConsistencyStatus {
    if (local === "mismatch") return "mismatch_local";
    if (onchain === "mismatch") return "mismatch_onchain";
    if (onchain === "not_registered") return "not_registered";
    if (onchain === "unknown") return "unknown";
    if (local === "skipped_no_private_key") return "skipped_no_private_key";
    if (local === "skipped_remote_signer") return "skipped_remote_signer";
    return "ok";
  }
}
