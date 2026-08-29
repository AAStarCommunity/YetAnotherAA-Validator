import { Logger } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { ethers } from "ethers";
import { v4 as uuidv4 } from "uuid";
import { GossipService } from "../gossip/gossip.service.js";
import type { CoSignRequestPayload, CoSignResponsePayload } from "../gossip/gossip.interfaces.js";
import { BlsService } from "../bls/bls.service.js";
import { NodeService } from "../node/node.service.js";
import { BlockchainService } from "../blockchain/blockchain.service.js";
import { bls, sigs } from "../../utils/bls.util.js";
import { PROOF_SCHEMA_VERSION } from "./proof-archive.js";
import {
  CoSignRequest,
  CoSignVerifier,
  IQuorumCoSigner,
  MAX_VALIDATORS,
  SlashLevel,
  buildSignerMask,
  recomputeMessageHash,
} from "./slash-consensus.js";
import type { BlsConsensusDomain } from "./bls-consensus-domain.js";

/**
 * DVT Phase 2 (目标2, inc-2 live) — the REAL gossip-based BLS quorum co-signer.
 *
 * This is the most safety-critical code in the system: its aggregate proof drives a real,
 * irreversible on-chain GToken slash. It is DEFENSIVE and FAIL-CLOSED at every step — any
 * uncertainty (unarmed node, un-watchlisted operator, hash mismatch, unconfirmable violation,
 * unresolved slot, invalid signature, on-chain binding mismatch, or under-threshold count)
 * results in a refusal (responder) or a throw (requester → the audit degrades to file+archive).
 *
 * Two roles, one gate:
 *   • RESPONDER (`verifyAndSign`): every armed node re-derives the messageHash from the structured
 *     request AND independently re-confirms the violation from its OWN on-chain read at the epoch
 *     block, then signs ONLY on full agreement. Registered on GossipService at bootstrap so an
 *     armed node responds even if it never itself requests.
 *   • REQUESTER (`coSign`): the auditing node self-contributes (must independently agree), gathers
 *     peer signatures over gossip, cryptographically verifies + on-chain-binds EVERY response, and
 *     aggregates ONLY when a strict per-severity threshold of unique on-chain slots is met — never
 *     submitting an under-threshold proof that would revert.
 */
export class GossipQuorumCoSigner implements IQuorumCoSigner {
  private readonly logger = new Logger(GossipQuorumCoSigner.name);

  private readonly blsAggregatorAddress: string;
  /** SP Registry + chainId — the other two BLS-consensus domain-separator fields (node-local). */
  private readonly registryAddress: string;
  private readonly chainId: bigint;
  private readonly maxSlots: number;
  private readonly timeoutMs: number;
  private readonly slashThresholds: { WARNING: number; MINOR: number; MAJOR: number };
  private readonly executeSlash: boolean;

  /**
   * Independent violation re-confirmation + operator AUTHORIZATION, wired by AuditService via
   * `arm()`. AuditService.verifyViolationForCoSign is the SINGLE authority on which operators may be
   * co-signed: it checks the EFFECTIVE watchlist (static AUDIT_WATCHLIST ∪ the FRESH on-chain-derived
   * role set) and re-confirms the violation at the epoch block. The responder does NOT keep its own
   * static watchlist — a duplicate static-only check here would pre-reject derived-only operators
   * before this verifier ever runs, so they could never reach quorum (Codex A1#6 High-1).
   */
  private verifier: CoSignVerifier | null = null;

  /**
   * Memoized own on-chain slot. resolveOwnSlot is now an O(1) getBLSPublicKey(operatorEoa) read
   * (finding-3) — the on-chain BLSAggregator returns this validator's slot DIRECTLY, so there is no
   * 1..maxSlots scan. The slot is FIXED on-chain at registerBLSPublicKey, so a POSITIVE result is
   * cached permanently. A null (node not yet registered, or no wallet) is NOT cached — it re-resolves
   * next time so a later registration is picked up. `refreshOwnSlot()` forces re-resolution.
   */
  private ownSlot: number | null = null;
  private ownSlotResolved = false;

  /** Memoized positive result of the on-chain domain attestation (see ensureDomainAttested). */
  private domainAttested = false;

  constructor(
    private readonly gossip: GossipService,
    private readonly blsService: BlsService,
    private readonly nodeService: NodeService,
    private readonly blockchain: BlockchainService,
    config: ConfigService
  ) {
    this.blsAggregatorAddress = config.get<string>("auditBlsAggregatorAddress") ?? "";
    this.registryAddress = config.get<string>("auditRegistryAddress") ?? "";
    this.chainId = BigInt(config.get<number>("auditChainId") ?? 11155111);
    const maxSlots = config.get<number>("auditMaxSlots") ?? MAX_VALIDATORS;
    this.maxSlots =
      Number.isInteger(maxSlots) && maxSlots > 0 && maxSlots <= MAX_VALIDATORS
        ? maxSlots
        : MAX_VALIDATORS;
    this.timeoutMs = config.get<number>("auditCoSignTimeoutMs") ?? 15_000;
    this.slashThresholds = config.get<{ WARNING: number; MINOR: number; MAJOR: number }>(
      "auditSlashThresholds"
    ) ?? { WARNING: 2, MINOR: 3, MAJOR: 3 };
    this.executeSlash = config.get<boolean>("auditExecuteSlash") === true;
  }

  /**
   * Wire the independent violation verifier and register the responder handler on GossipService.
   * Called by AuditService at bootstrap so every armed node responds. Idempotent-safe.
   */
  arm(verifier: CoSignVerifier): void {
    this.verifier = verifier;
    this.gossip.registerCoSignHandler(payload => this.verifyAndSign(payload));
    this.logger.log("Gossip quorum co-sign responder registered (armed)");
    // Attest the domain on-chain eagerly so a misconfiguration surfaces at arm time, not only on the
    // first co-sign. Non-blocking (arm stays sync); the HARD gate is `ensureDomainAttested()` awaited
    // in verifyAndSign/coSign, so a slow/failed attestation here never lets an unattested sign through.
    void this.ensureDomainAttested();
  }

  /**
   * This node's OWN BLS-consensus domain. Used for EVERY messageHash recompute (both roles), so a
   * signature is only ever produced for the aggregator/Registry/chain this node is configured for —
   * the domain is NEVER taken from the (untrusted) request.
   */
  private blsDomain(): BlsConsensusDomain {
    return {
      chainId: this.chainId,
      aggregator: this.blsAggregatorAddress,
      registry: this.registryAddress,
    };
  }

  /**
   * Fail-closed domain attestation gate. Before this node signs ANYTHING it must prove — on-chain —
   * that its local (chainId, aggregator, Registry) is the exact domain the live aggregator
   * reconstructs (`domainSeparator()` + non-zero matching `REGISTRY()`). A success is memoized (the
   * aggregator's domain is immutable); a failure is NOT cached, so a transient RPC error re-checks
   * next call rather than permanently wedging a correctly-configured node. Returns false on any
   * failure → the caller refuses to co-sign.
   */
  private async ensureDomainAttested(): Promise<boolean> {
    if (this.domainAttested) return true;
    try {
      await this.blockchain.attestBlsDomain(
        this.blsAggregatorAddress,
        this.chainId,
        this.registryAddress
      );
      this.domainAttested = true;
      return true;
    } catch (e: any) {
      this.logger.warn(
        `co-sign domain attestation FAILED — refusing to co-sign over an unverified domain: ` +
          `${e?.message ?? String(e)}`
      );
      return false;
    }
  }

  // ── RESPONDER ───────────────────────────────────────────────────────────────────

  /**
   * The peer gate. Returns a signed CoSignResponsePayload ONLY when every check passes; ANY
   * failure or uncertainty returns `null` (silent, fail-closed refusal). Order:
   *   1. local node armed (AUDIT_EXECUTE_SLASH)               — else refuse.
   *   2. operator address parses (authorization deferred to 4) — else refuse.
   *   3. recompute messageHash locally, assert == request     — NEVER trust the requester's hash.
   *   4. verifier: authorize (effective watchlist + freshness) AND confirm violation at `epoch`
   *      block — proofHash === evidenceHash (execute). The verifier owns operator authorization.
   *   5. resolve own on-chain validator slot                  — else refuse.
   *   6. BLS-sign the LOCALLY-recomputed hash.
   */
  async verifyAndSign(req: CoSignRequestPayload): Promise<CoSignResponsePayload | null> {
    try {
      // 1. must be armed.
      if (!this.executeSlash) return null;
      if (!this.verifier) return null;
      // 1a. domain attested on-chain — never sign over an unverified aggregator/Registry/chain.
      if (!(await this.ensureDomainAttested())) return null;

      // 1b. proof-schema version must match (finding-1). A mixed-version fleet computes DIFFERENT
      // proofHashes, so co-signing would silently fail to reach quorum with no clear reason. Refuse
      // EXPLICITLY with a WARNING (fail-closed, safe) so the operator can diagnose + align versions.
      if (req.proofSchemaVersion !== PROOF_SCHEMA_VERSION) {
        this.logger.warn(
          `verifyAndSign refused: proof schema version mismatch: req=${req.proofSchemaVersion} ` +
            `local=${PROOF_SCHEMA_VERSION} — all DVT nodes must run the same inc-2-live version; ` +
            `refusing to co-sign`
        );
        return null;
      }

      // 2. operator address must parse. AUTHORIZATION (is this operator watched + slashable?) is NOT
      // done here — it is delegated to the verifier at step 4, the single authority that checks the
      // EFFECTIVE (static ∪ fresh-derived) watchlist. A static-only check here would pre-reject
      // derived-only operators before the verifier runs (Codex A1#6 High-1).
      try {
        ethers.getAddress(req.operator);
      } catch {
        return null;
      }

      // 3. recompute the messageHash from first principles; NEVER trust req.messageHash.
      let localHash: string;
      try {
        localHash = recomputeMessageHash(req, this.blsDomain());
      } catch {
        return null;
      }
      if (localHash.toLowerCase() !== String(req.messageHash).toLowerCase()) return null;

      // 4. independent violation confirmation (re-read on-chain at the epoch block).
      const { confirmed, proofHash } = await this.verifier(req);
      if (!confirmed || proofHash === null) return null;
      // The linchpin "innocent-operator" / "bogus-evidence" defense (MEDIUM 2): bind evidenceHash
      // for BOTH the queue AND the execute step. The request MUST carry an evidenceHash equal to the
      // proofHash we independently re-derived. For execute this stops a substituted operator (the
      // on-chain preimage already includes evidenceHash). For queue — whose 5-field on-chain preimage
      // does NOT include evidenceHash — this still means a queue quorum only FORMS when every signer
      // agrees on the same evidence, so a malicious requester cannot get a real queue quorum while
      // attaching a bogus evidenceHash and submitting a spurious queue tx (gas / pending-state churn).
      if (
        typeof req.evidenceHash !== "string" ||
        proofHash.toLowerCase() !== req.evidenceHash.toLowerCase()
      ) {
        return null;
      }

      // 5. resolve own on-chain validator slot (O(1) by our own operator EOA, finding-3).
      const node = this.nodeService.getNodeForSigning();
      const slot = await this.resolveOwnSlot();
      if (slot === null) return null;

      // 6. sign the locally-recomputed hash.
      const sig = await this.blsService.signDerivedHash(localHash, node);
      if (typeof sig.signatureCompact !== "string" || typeof sig.publicKey !== "string") {
        return null; // fail-closed: cannot produce a valid response without both
      }
      return {
        requestId: req.requestId,
        slot,
        signerNodeId: node.nodeId,
        signerPublicKey: sig.publicKey,
        signatureCompact: sig.signatureCompact,
        messageHash: localHash,
      };
    } catch (error) {
      this.logger.warn(
        `verifyAndSign refused (unexpected error): ${error instanceof Error ? error.message : String(error)}`
      );
      return null;
    }
  }

  // ── REQUESTER ─────────────────────────────────────────────────────────────────

  /**
   * Gather a threshold quorum of peer signatures over the request's messageHash, validate every
   * one cryptographically + on-chain-bind it to a registered slot, and aggregate into the SP wire
   * proof (signerMask + EIP-2537 sigG2). THROWS on any precondition failure or when fewer than the
   * per-severity threshold of valid unique-slot signatures are collected — so the audit degrades
   * to file+archive and NEVER submits an under-threshold proof that would revert / double-slash.
   */
  async coSign(req: CoSignRequest): Promise<{ signerMask: bigint; sigG2: string }> {
    // Fail-closed preconditions.
    if (!this.executeSlash) {
      throw new Error("gossip co-sign: node is not armed (AUDIT_EXECUTE_SLASH!=true)");
    }
    if (!this.verifier) {
      throw new Error("gossip co-sign: responder/verifier not wired");
    }
    if (!(await this.ensureDomainAttested())) {
      throw new Error(
        "gossip co-sign: BLS-consensus domain not attested on-chain — refusing (fail-closed)"
      );
    }
    const node = this.nodeService.getNodeForSigning();
    const ownSlot = await this.resolveOwnSlot();
    if (ownSlot === null) {
      throw new Error("gossip co-sign: local node has no on-chain validator slot — refusing");
    }
    if (this.gossip.getPeers().length === 0) {
      throw new Error("gossip co-sign: no gossip peers available to reach quorum");
    }

    const threshold = this.thresholdFor(req.slashLevel);

    // Self-contribution: the requester must independently agree via the SAME responder gate.
    const own = await this.verifyAndSign({
      ...req,
      requestId: uuidv4(),
      requesterNodeId: node.nodeId,
    });
    if (own === null) {
      throw new Error(
        "gossip co-sign: local node could not independently confirm the violation — refusing"
      );
    }

    // Request peer signatures over gossip. The requester needs `threshold - 1` MORE (its own
    // contribution counts), so ask peers for that many; 0 resolves immediately.
    const requestId = uuidv4();
    const payload: CoSignRequestPayload = { ...req, requestId, requesterNodeId: node.nodeId };
    const peerThreshold = Math.max(0, threshold - 1);
    // finding-2: one per-coSign-call cache (slot → on-chain uncompressed key) SHARED between the
    // collector's validate callback and the post-collection defense-in-depth loop, so repeated
    // same-slot validations within a single coSign hit getBlsPublicKeyAtSlot at most once per slot.
    const keyCache = new Map<number, string | null>();
    // MEDIUM 1: hand the collector the SAME per-response validation (crypto + on-chain slot binding)
    // and a slot-based dedup key, so ONLY validated, unique-slot peer responses count toward the
    // collector's early-resolve — a peer cannot flood bogus responses to crowd out honest signers.
    // coSign still re-validates + re-dedups the returned set below (idempotent defense-in-depth).
    const peerResponses = await this.gossip.requestCoSignatures(payload, {
      threshold: peerThreshold,
      timeoutMs: this.timeoutMs,
      validate: resp => this.validateResponse(req, resp, keyCache),
      dedupKey: resp => resp.slot,
    });

    // Validate EVERY response (own + peers) before counting its bit. Dedup by slot.
    const bySlot = new Map<number, { pubkey: string; sigCompact: string }>();
    for (const resp of [own, ...peerResponses]) {
      if (!(await this.validateResponse(req, resp, keyCache))) continue;
      if (!bySlot.has(resp.slot)) {
        bySlot.set(resp.slot, { pubkey: resp.signerPublicKey, sigCompact: resp.signatureCompact });
      }
    }

    // STRICT threshold enforcement: below → THROW (no aggregation, no on-chain call).
    if (bySlot.size < threshold) {
      throw new Error(
        `gossip co-sign: only ${bySlot.size} valid unique-slot signature(s), need ${threshold} ` +
          `for slashLevel ${req.slashLevel} — refusing (never submit under-threshold proof)`
      );
    }

    // Aggregate: parse compact G2 sigs → aggregate → EIP-2537 sigG2; signerMask over the slots.
    const slots = [...bySlot.keys()].sort((a, b) => a - b);
    const signatures = slots.map(s => sigs.Signature.fromHex(strip0x(bySlot.get(s)!.sigCompact)));
    const aggregate = await this.blsService.aggregateSignaturesOnly(signatures);
    const sigG2 = this.blsService.encodeToEIP2537(aggregate);
    const signerMask = buildSignerMask(slots);
    this.logger.warn(
      `Gossip quorum co-sign OK: ${slots.length} signers (slots ${slots.join(",")}), ` +
        `signerMask=${signerMask} for ${req.step} slash of ${req.operator}`
    );
    return { signerMask, sigG2 };
  }

  // ── Internal helpers ────────────────────────────────────────────────────────────

  /**
   * Cryptographically verify a co-sign response AND bind it to the on-chain validator set. All of:
   *   - slot in range,
   *   - response messageHash === the locally recomputed hash,
   *   - signatureCompact verifies against signerPublicKey over hashToCurve(messageHash),
   *   - signerPublicKey === the on-chain key registered at that slot (uncompressed EIP-2537).
   * A NON-NULL getBlsPublicKeyAtSlot ALREADY implies the slot resolves to a non-zero, ACTIVE
   * validator (it reads validatorAtSlot internally, returns null on the zero address, and checks
   * isActive), so the previously-separate getValidatorAtSlot call was redundant and is dropped
   * (finding-2). Any failure / error → false (the signature is dropped, never counted).
   *
   * `keyCache` (slot → on-chain key) is an optional PER-coSign-call memo so repeated same-slot
   * validations within one coSign don't re-hit RPC. `null` is cached too (a null-keyed slot stays
   * rejected for the whole call).
   */
  private async validateResponse(
    req: CoSignRequest,
    resp: CoSignResponsePayload,
    keyCache?: Map<number, string | null>
  ): Promise<boolean> {
    try {
      if (!resp || typeof resp.slot !== "number") return false;
      if (!Number.isInteger(resp.slot) || resp.slot < 1 || resp.slot > this.maxSlots) return false;
      if (typeof resp.signerPublicKey !== "string" || typeof resp.signatureCompact !== "string") {
        return false;
      }

      // The response MUST commit to the exact hash we recompute — never the requester's copy.
      const expected = recomputeMessageHash(req, this.blsDomain());
      if (String(resp.messageHash).toLowerCase() !== expected.toLowerCase()) return false;

      // Cryptographic verification of the compact G2 signature over hashToCurve(messageHash).
      const signature = sigs.Signature.fromHex(strip0x(resp.signatureCompact));
      const publicKey = bls.G1.Point.fromHex(strip0x(resp.signerPublicKey));
      const msgPoint = await this.blsService.hashMessageToCurve(expected);
      const valid = await this.blsService.verifySignature(signature, msgPoint, publicKey);
      if (!valid) return false;

      // On-chain binding: the returned key MUST be the one registered at the claimed slot. A
      // non-null getBlsPublicKeyAtSlot already guarantees the slot resolves to a non-zero, ACTIVE
      // validator (it reads validatorAtSlot + isActive internally), so no separate getValidatorAtSlot
      // is needed. Memoize per coSign call so two responses for the same slot read RPC only once.
      let onchainKey: string | null;
      if (keyCache && keyCache.has(resp.slot)) {
        onchainKey = keyCache.get(resp.slot) ?? null;
      } else {
        onchainKey = await this.blockchain.getBlsPublicKeyAtSlot(
          this.blsAggregatorAddress,
          resp.slot
        );
        if (keyCache) keyCache.set(resp.slot, onchainKey);
      }
      if (!onchainKey) return false;
      const respUncompressed = this.uncompressedFromCompressed(resp.signerPublicKey);
      if (onchainKey.toLowerCase() !== respUncompressed.toLowerCase()) return false;

      return true;
    } catch {
      return false;
    }
  }

  /**
   * Resolve THIS node's own slot with a SINGLE on-chain read (finding-3): getRegisteredSlot reads
   * BLSAggregator.getBLSPublicKey(ownOperatorEoa), which returns this validator's slot directly — no
   * 1..maxSlots scan. The operator EOA is the node's on-chain wallet (the same EOA that registered
   * the BLS key and submits the slash txs). `null` when there is no wallet or the operator holds no
   * active slot. The requester still independently binds our returned slot to its on-chain key
   * (validateResponse), so a slot whose registered key differs from our signing key is rejected there
   * — safety does not rely on this lookup matching the key.
   */
  private async resolveOwnSlot(): Promise<number | null> {
    // Serve a previously-resolved POSITIVE slot from cache: the on-chain slot is fixed at
    // registration, so once found it never changes for this operator.
    if (this.ownSlotResolved) return this.ownSlot;
    const operatorEoa = this.blockchain.getWalletAddress();
    if (!operatorEoa) return null; // no wallet → cannot resolve own slot (do NOT cache)
    const slot = await this.blockchain.getRegisteredSlot(this.blsAggregatorAddress, operatorEoa);
    if (slot === null) {
      // Not yet registered at an active slot: do NOT cache the null — re-resolve next time so a
      // later registration is picked up.
      return null;
    }
    this.ownSlot = slot;
    this.ownSlotResolved = true;
    return slot;
  }

  /** Force re-resolution of the memoized own slot on the next resolveOwnSlot call. */
  refreshOwnSlot(): void {
    this.ownSlot = null;
    this.ownSlotResolved = false;
  }

  /** Compressed 48-byte G1 (0x-hex) → uncompressed EIP-2537 128-byte (0x-hex). */
  private uncompressedFromCompressed(compressed: string): string {
    const point = bls.G1.Point.fromHex(strip0x(compressed));
    return this.blsService.encodePublicKeyToEIP2537(point);
  }

  /** Per-severity quorum threshold (WARNING 2, MINOR/MAJOR 3 at N=3), from config with defaults. */
  private thresholdFor(slashLevel: number): number {
    const map = this.slashThresholds;
    let value: number | undefined;
    if (slashLevel === SlashLevel.WARNING) value = map.WARNING;
    else if (slashLevel === SlashLevel.MINOR) value = map.MINOR;
    else if (slashLevel === SlashLevel.MAJOR) value = map.MAJOR;
    if (typeof value === "number" && Number.isInteger(value) && value > 0) return value;
    // Defensive default when the table is malformed / the level is unknown.
    return slashLevel === SlashLevel.WARNING ? 2 : 3;
  }
}

/** Strip an optional 0x prefix. */
function strip0x(hex: string): string {
  return hex.startsWith("0x") ? hex.slice(2) : hex;
}
