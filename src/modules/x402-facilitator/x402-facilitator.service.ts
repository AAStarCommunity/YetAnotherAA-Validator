import { Injectable, Logger, Optional, OnApplicationBootstrap } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { ethers } from "ethers";
import { CapabilityRegistry } from "../capability/capability-registry.service.js";
import { bumpedFees } from "../../utils/gas.util.js";
import { FacilitatorRequestDto } from "./dto/facilitator.dto.js";
import {
  SEPOLIA_DEFAULTS,
  X402_FACILITATOR_ABI,
  ERC1271_ABI,
  ERC1271_MAGIC_VALUE,
  X402_AUTH_TYPES,
  RECEIVE_WITH_AUTH_TYPES,
  getX402FacilitatorDomain,
  getEip3009TokenDomain,
  computeX402NonceKey,
  computeEip3009Nonce,
  rejectUnsupportedScheme,
  toNetworkId,
  type SettlementScheme,
  type VerifyResult,
  type SettleResult,
} from "./x402-facilitator.constants.js";

/**
 * Fully-normalized settlement parameters, derived from the SDK's x402 v2 envelope
 * by {@link X402FacilitatorService.normalize}. Both verify and settle operate on
 * THIS shape so they can never interpret the same request differently.
 */
export interface NormalizedPayment {
  scheme: SettlementScheme;
  from: string;
  to: string; // FINAL recipient (paymentRequirements.payTo)
  asset: string;
  amount: bigint;
  maxFee: bigint;
  validAfter: bigint;
  validBefore: bigint;
  nonce: string; // raw authorization nonce (direct path nonce, eip-3009 salt fallback)
  salt: string; // eip-3009 preimage; on-chain nonce = keccak256(to, maxFee, salt)
  signature: string;
  tokenName: string; // EIP-3009 domain name (e.g. "USDC")
  tokenVersion: string; // EIP-3009 domain version (e.g. "2")
}

/**
 * x402 payment facilitator (#130) — optional, opt-in DVT node module.
 *
 * Operates the x402 *facilitator service* the way `relay` (#98) operates the
 * gasless purchase relay: an HTTP service that holds a DEDICATED operator key and
 * submits an on-chain settlement on the payer's behalf. The role was previously
 * homeless — the SDK (`@aastar/x402`) is client-only and the in-repo
 * SuperPaymaster node is `@deprecated`; this module gives it a home on the DVT
 * node so the SDK just repoints its facilitator URL.
 *
 * It is ORTHOGONAL to the BLS signing core: no PackedUserOperation, no
 * AAStarValidator, no BLS aggregation — so it never touches the security-critical
 * 403 owner-auth gate. The payer authorizes via their own EIP-712 signature
 * (X402PaymentAuthorization for xPNTs `direct`, or EIP-3009 ReceiveWithAuthorization
 * for USDC `eip-3009`); the node submits with its operator EOA.
 *
 * Opt-in (X402_FACILITATOR_ENABLED, default off → behavior unchanged). Requires a
 * DEDICATED X402_OPERATOR_PK — a funded EOA that (1) holds ROLE_PAYMASTER_SUPER in
 * the Registry and (2) is in `approvedFacilitators` on each supported xPNTs token.
 * It intentionally does NOT fall back to ETH_PRIVATE_KEY (validator owner) or
 * RELAY_OPERATOR_PK — the public-facing settlement key stays isolated.
 *
 * Off-chain verify is a fast-fail gate (signature, expiry, nonce replay) that
 * mirrors what the contract enforces; the X402Facilitator contract re-verifies
 * everything on-chain and is authoritative.
 */
@Injectable()
export class X402FacilitatorService implements OnApplicationBootstrap {
  private readonly logger = new Logger(X402FacilitatorService.name);

  private readonly enabledByConfig: boolean;
  private readonly operatorPk: string;
  private readonly rpcUrl: string;
  private readonly chainId: number;
  private readonly facilitatorContract: string;
  /** Lower-cased xPNTs assets this operator is provisioned for (settled `direct`). */
  private readonly supportedAssets: string[];
  private readonly feeBPS: number;
  private readonly now: () => number;

  /** Live once bootstrap validates the operator key + RPC; null = disabled. */
  private wallet: ethers.Wallet | null = null;
  private contract: ethers.Contract | null = null;
  private provider: ethers.JsonRpcProvider | null = null;

  /** Serializes on-chain submissions so concurrent requests can't reuse a nonce. */
  private submitChain: Promise<unknown> = Promise.resolve();

  constructor(
    private readonly config: ConfigService,
    @Optional() capabilityRegistry?: CapabilityRegistry,
    /** Test seam: controls `Date.now()` for expiry windows. */
    @Optional() now?: () => number
  ) {
    this.enabledByConfig = config.get<boolean>("x402FacilitatorEnabled") === true;
    this.operatorPk = config.get<string>("x402OperatorPk") ?? "";
    this.rpcUrl = config.get<string>("x402RpcUrl") ?? config.get<string>("ethRpcUrl") ?? "";
    this.chainId = config.get<number>("x402ChainId") ?? SEPOLIA_DEFAULTS.chainId;
    this.facilitatorContract =
      config.get<string>("x402FacilitatorContract") ?? SEPOLIA_DEFAULTS.facilitatorContract;
    this.supportedAssets = (config.get<string[]>("x402SupportedAssets") ?? []).map(a =>
      a.toLowerCase()
    );
    this.feeBPS = config.get<number>("x402FeeBPS") ?? 200;
    this.now = now ?? (() => Date.now());

    capabilityRegistry?.register({
      name: "x402-facilitator",
      class: "infra-app",
      description: `x402 payment facilitator (${this.supportedAssets.length} asset(s), feeBPS=${this.feeBPS})`,
      enabled: this.enabledByConfig,
    });
  }

  onApplicationBootstrap(): void {
    if (!this.enabledByConfig) return;
    if (!/^0x[0-9a-fA-F]{64}$/.test(this.operatorPk)) {
      this.logger.warn(
        "x402: X402_FACILITATOR_ENABLED=true but X402_OPERATOR_PK missing/invalid " +
          "(must be 32-byte 0x hex, DEDICATED — not the validator owner or relay key) — disabled"
      );
      return;
    }
    if (!this.rpcUrl) {
      this.logger.warn(
        "x402: X402_FACILITATOR_ENABLED=true but no RPC URL (X402_RPC_URL/ETH_RPC_URL) — disabled"
      );
      return;
    }
    if (!ethers.isAddress(this.facilitatorContract)) {
      this.logger.warn("x402: X402_FACILITATOR_CONTRACT is not a valid address — disabled");
      return;
    }
    this.provider = new ethers.JsonRpcProvider(this.rpcUrl, this.chainId);
    this.wallet = new ethers.Wallet(this.operatorPk, this.provider);
    this.contract = new ethers.Contract(
      this.facilitatorContract,
      X402_FACILITATOR_ABI,
      this.wallet
    );
    this.logger.log(
      `x402 facilitator ENABLED — operator=${this.wallet.address} chainId=${this.chainId} ` +
        `contract=${this.facilitatorContract} feeBPS=${this.feeBPS} ` +
        `assets(direct)=[${this.supportedAssets.join(", ")}]`
    );
  }

  /** True once the operator wallet + contract are live. */
  isEnabled(): boolean {
    return this.wallet !== null && this.contract !== null;
  }

  /** Operator address for discovery/health, or null when disabled. */
  operatorAddress(): string | null {
    return this.wallet?.address ?? null;
  }

  /** CAIP-2 network id this node settles on (e.g. "eip155:11155111"). */
  networkId(): string {
    return toNetworkId(this.chainId);
  }

  /**
   * GET /x402/supported — advertise settleable kinds for client/gossip discovery.
   * Carries the SuperPaymaster-specific bits (supported assets, fee, contract,
   * settlement schemes) in `extra`, the schema this module owns (docs/x402-facilitator.md).
   */
  supported(): {
    kinds: Array<{ x402Version: number; scheme: string; network: string; extra: unknown }>;
    extensions: string[];
  } {
    return {
      kinds: [
        {
          x402Version: 2,
          scheme: "exact",
          network: toNetworkId(this.chainId),
          extra: {
            settlementSchemes: ["direct", "eip-3009"],
            assets: this.supportedAssets,
            feeBPS: this.feeBPS,
            facilitatorContract: this.facilitatorContract,
            operator: this.operatorAddress(),
          },
        },
      ],
      extensions: [],
    };
  }

  /**
   * Resolve the on-chain settlement scheme. An explicit `extra.settlement` wins
   * (and is run through the shared guard by the caller); otherwise an asset in the
   * operator's provisioned xPNTs set settles `direct`, everything else `eip-3009`.
   */
  resolveScheme(asset: string, extraSettlement?: unknown): string {
    if (typeof extraSettlement === "string" && extraSettlement.length > 0) return extraSettlement;
    return this.supportedAssets.includes(asset.toLowerCase()) ? "direct" : "eip-3009";
  }

  /**
   * Parse the SDK x402 v2 envelope into a {@link NormalizedPayment}. Pure (no
   * network). Returns a `{ reason }` on any structural problem so verify/settle
   * fail identically. Both endpoints MUST funnel through this — it is the single
   * source of the values handed to ethers + the contract.
   */
  normalize(
    dto: FacilitatorRequestDto
  ): { ok: true; payment: NormalizedPayment } | { ok: false; reason: string } {
    const pp = dto?.paymentPayload as Record<string, unknown> | undefined;
    const pr = dto?.paymentRequirements as Record<string, unknown> | undefined;
    if (!pp || !pr) return { ok: false, reason: "missing paymentPayload or paymentRequirements" };

    // Reject non-v2 envelopes explicitly: a different protocol version whose field
    // shape happens to overlap must not be silently processed as v2. Both the top
    // level and the embedded paymentPayload carry x402Version per the SDK contract.
    for (const [v, where] of [
      [dto.x402Version, "request"],
      [pp.x402Version, "paymentPayload"],
    ] as const) {
      if (v !== undefined && v !== 2) {
        return {
          ok: false,
          reason: `unsupported x402Version in ${where}: ${String(v)} (expected 2)`,
        };
      }
    }

    const inner = pp.payload as Record<string, unknown> | undefined;
    const auth = inner?.authorization as Record<string, unknown> | undefined;
    if (!inner || !auth)
      return { ok: false, reason: "missing paymentPayload.payload.authorization" };

    const extra = (pr.extra as Record<string, unknown> | undefined) ?? {};

    // x402 v2 pricing scheme: the SDK only produces "exact". Reject "upto"/unknown.
    const pricingScheme = pr.scheme;
    if (pricingScheme !== undefined && pricingScheme !== "exact") {
      return {
        ok: false,
        reason: `unsupported x402 scheme: ${String(pricingScheme)} (expected "exact")`,
      };
    }

    // Network must match this node's chain (when supplied).
    if (pr.network !== undefined && pr.network !== toNetworkId(this.chainId)) {
      return { ok: false, reason: `network ${String(pr.network)} != ${toNetworkId(this.chainId)}` };
    }

    const from = auth.from;
    const to = pr.payTo ?? auth.to; // final recipient
    const asset = pr.asset;
    const amountStr = (pr.amount ?? auth.value) as unknown;
    const signature = inner.signature;
    const nonce = auth.nonce;
    const validAfterStr = (auth.validAfter ?? "0") as unknown;
    const validBeforeStr = auth.validBefore;

    for (const [v, name] of [
      [from, "from"],
      [to, "to"],
      [asset, "asset"],
    ] as const) {
      if (typeof v !== "string" || !ethers.isAddress(v)) {
        return { ok: false, reason: `invalid ${name}: not an address` };
      }
    }
    if (typeof nonce !== "string" || !/^0x[0-9a-fA-F]{64}$/.test(nonce)) {
      return { ok: false, reason: "invalid nonce: must be 0x + 64 hex chars" };
    }
    if (typeof signature !== "string" || !ethers.isHexString(signature) || signature.length < 4) {
      return { ok: false, reason: "invalid signature: must be a hex string" };
    }
    if (typeof amountStr !== "string" || !/^\d+$/.test(amountStr)) {
      return { ok: false, reason: "invalid amount: must be a non-negative integer string" };
    }
    if (typeof validBeforeStr !== "string" || !/^\d+$/.test(validBeforeStr)) {
      return { ok: false, reason: "invalid validBefore: must be a non-negative integer string" };
    }
    if (typeof validAfterStr !== "string" || !/^\d+$/.test(validAfterStr)) {
      return { ok: false, reason: "invalid validAfter: must be a non-negative integer string" };
    }

    const amount = BigInt(amountStr);
    const maxFeeRaw = extra.maxFee;
    let maxFee: bigint;
    try {
      maxFee = maxFeeRaw === undefined ? amount : BigInt(maxFeeRaw as string | number);
    } catch {
      return { ok: false, reason: "invalid extra.maxFee" };
    }

    // salt is OPTIONAL and falls back to the authorization nonce when ABSENT. But a
    // PRESENT-yet-malformed salt is a client encoding bug, not a fallback case:
    // reject it loudly rather than silently settling against a different nonce than
    // the client believes it signed.
    const saltRaw = extra.salt;
    let salt: string;
    if (saltRaw === undefined) {
      salt = nonce;
    } else if (typeof saltRaw === "string" && /^0x[0-9a-fA-F]{64}$/.test(saltRaw)) {
      salt = saltRaw;
    } else {
      return { ok: false, reason: "invalid extra.salt: must be 0x + 64 hex chars" };
    }

    const scheme = this.resolveScheme(asset as string, extra.settlement);
    const schemeReason = rejectUnsupportedScheme(scheme);
    if (schemeReason) return { ok: false, reason: schemeReason };

    return {
      ok: true,
      payment: {
        scheme: scheme as SettlementScheme,
        from: ethers.getAddress(from as string),
        to: ethers.getAddress(to as string),
        asset: ethers.getAddress(asset as string),
        amount,
        maxFee,
        validAfter: BigInt(validAfterStr),
        validBefore: BigInt(validBeforeStr),
        nonce,
        salt,
        signature,
        tokenName: typeof extra.name === "string" ? (extra.name as string) : "USDC",
        tokenVersion: typeof extra.version === "string" ? (extra.version as string) : "2",
      },
    };
  }

  /** On-chain effective nonce, identical to how the contract derives it per scheme. */
  effectiveNonce(p: NormalizedPayment): string {
    return p.scheme === "direct" ? p.nonce : computeEip3009Nonce(p.to, p.maxFee, p.salt);
  }

  /**
   * Off-chain signature + expiry check (no replay read). Pure w.r.t. the chain
   * except for the optional ERC-1271 fallback (smart-account / passkey signatures),
   * which needs a provider — EOA recovery alone is provider-free and unit-tested.
   */
  async verifySignatureOffChain(p: NormalizedPayment): Promise<VerifyResult> {
    const nowSec = BigInt(Math.floor(this.now() / 1000));
    if (p.amount === 0n) return { ok: false, reason: "Zero amount" };

    if (p.scheme === "direct") {
      if (nowSec > p.validBefore)
        return { ok: false, reason: "Authorization expired (validBefore)" };
      const domain = getX402FacilitatorDomain(this.chainId, this.facilitatorContract);
      const value = {
        from: p.from,
        to: p.to,
        asset: p.asset,
        amount: p.amount,
        maxFee: p.maxFee,
        validBefore: p.validBefore,
        nonce: p.nonce,
      };
      return this.recoverOrErc1271(domain, X402_AUTH_TYPES, value, p.signature, p.from);
    }

    // eip-3009: token-domain ReceiveWithAuthorization, recipient = the facilitator
    // contract (it pulls funds in, then forwards to the final `to`).
    if (p.validAfter > 0n && nowSec < p.validAfter) {
      return { ok: false, reason: "Payment not yet valid (validAfter)" };
    }
    if (nowSec >= p.validBefore) return { ok: false, reason: "Payment expired (validBefore)" };
    const domain = getEip3009TokenDomain(p.tokenName, p.tokenVersion, this.chainId, p.asset);
    const value = {
      from: p.from,
      to: this.facilitatorContract,
      value: p.amount,
      validAfter: p.validAfter,
      validBefore: p.validBefore,
      nonce: this.effectiveNonce(p),
    };
    return this.recoverOrErc1271(domain, RECEIVE_WITH_AUTH_TYPES, value, p.signature, p.from);
  }

  /**
   * Recover an EIP-712 signature to the expected EOA; on mismatch, fall back to an
   * on-chain ERC-1271 `isValidSignature` check (AirAccount passkey / smart accounts),
   * matching the contract's SignatureCheckerLib which accepts both.
   */
  private async recoverOrErc1271(
    domain: ethers.TypedDataDomain,
    types: Record<string, ReadonlyArray<ethers.TypedDataField>>,
    value: Record<string, unknown>,
    signature: string,
    expected: string
  ): Promise<VerifyResult> {
    try {
      const recovered = ethers.verifyTypedData(
        domain,
        types as Record<string, Array<ethers.TypedDataField>>,
        value,
        signature
      );
      if (recovered.toLowerCase() === expected.toLowerCase()) return { ok: true, payer: expected };
    } catch {
      // fall through to ERC-1271
    }

    if (this.provider) {
      try {
        const digest = ethers.TypedDataEncoder.hash(
          domain,
          types as Record<string, Array<ethers.TypedDataField>>,
          value
        );
        const account = new ethers.Contract(expected, ERC1271_ABI, this.provider);
        const magic: string = await account.isValidSignature(digest, signature);
        if (magic === ERC1271_MAGIC_VALUE) return { ok: true, payer: expected };
      } catch {
        // not a smart account / no code / reverted → invalid
      }
    }
    return {
      ok: false,
      reason: "Invalid signature (EOA recovery failed; not a valid ERC-1271 signer)",
    };
  }

  /**
   * POST /x402/verify — full off-chain verification: structural normalize → scheme
   * guard → signature/expiry → on-chain nonce-replay read. Never throws; returns a
   * discriminated result the controller maps to the SDK VerifyResponse.
   */
  async verify(dto: FacilitatorRequestDto): Promise<VerifyResult> {
    if (!this.isEnabled())
      return { ok: false, reason: "x402 facilitator not enabled on this node" };

    const norm = this.normalize(dto);
    if (!norm.ok) return { ok: false, reason: norm.reason };
    const p = norm.payment;

    // Nonce replay: the contract records the (asset, from, nonce) triple key; the
    // raw-nonce slot is only the legacy pre-v5.4 path. Mirror BOTH lookups against
    // the EFFECTIVE nonce so we reject exactly when the contract would revert.
    const eff = this.effectiveNonce(p);
    try {
      const key = computeX402NonceKey(p.asset, p.from, eff);
      const [keyUsed, legacyUsed] = await Promise.all([
        this.contract!.x402SettlementNonces(key) as Promise<boolean>,
        this.contract!.x402SettlementNonces(eff) as Promise<boolean>,
      ]);
      if (keyUsed || legacyUsed) return { ok: false, reason: "Nonce already used" };
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      return { ok: false, reason: `nonce replay check failed: ${msg}` };
    }

    return this.verifySignatureOffChain(p);
  }

  /**
   * Build the ordered contract call for a normalized payment. Pure — the SOLE
   * source of the on-chain args, so a unit test can lock arg order against the
   * X402Facilitator ABI without an RPC harness. A transposed arg reverts on-chain.
   */
  buildSettleCall(p: NormalizedPayment): { method: string; args: unknown[] } {
    if (p.scheme === "direct") {
      // settleX402PaymentDirect(from, to, asset, amount, maxFee, validBefore, nonce, signature)
      return {
        method: "settleX402PaymentDirect",
        args: [p.from, p.to, p.asset, p.amount, p.maxFee, p.validBefore, p.nonce, p.signature],
      };
    }
    // settleX402Payment(from, to, asset, amount, maxFee, validAfter, validBefore, salt, signature)
    return {
      method: "settleX402Payment",
      args: [
        p.from,
        p.to,
        p.asset,
        p.amount,
        p.maxFee,
        p.validAfter,
        p.validBefore,
        p.salt,
        p.signature,
      ],
    };
  }

  /**
   * POST /x402/settle — submit the on-chain settlement. Re-normalizes (never trusts
   * a prior verify) and serializes submissions so concurrent requests on the single
   * operator EOA can't collide on a nonce. Never throws; returns a discriminated result.
   */
  async settle(dto: FacilitatorRequestDto): Promise<SettleResult> {
    if (!this.isEnabled())
      return { ok: false, reason: "x402 facilitator not enabled on this node" };

    const norm = this.normalize(dto);
    if (!norm.ok) return { ok: false, reason: norm.reason };
    const p = norm.payment;

    const run = this.submitChain.then(
      () => this.sendSettle(p),
      () => this.sendSettle(p)
    );
    this.submitChain = run.catch(() => {});
    return run;
  }

  private async sendSettle(p: NormalizedPayment): Promise<SettleResult> {
    try {
      const { method, args } = this.buildSettleCall(p);
      const fees = await bumpedFees(this.wallet!.provider!);
      const tx: ethers.TransactionResponse = await this.contract!.getFunction(method)(
        ...args,
        fees
      );
      this.logger.log(`x402 settle (${p.scheme}) submitted ${p.amount} ${p.asset} → ${tx.hash}`);
      const receipt = await tx.wait(1);
      if (!receipt || receipt.status !== 1) {
        return { ok: false, reason: `settlement reverted (tx ${tx.hash})` };
      }
      return { ok: true, txHash: tx.hash, payer: p.from };
    } catch (e: unknown) {
      const msg =
        (e as { shortMessage?: string })?.shortMessage ??
        (e instanceof Error ? e.message : String(e));
      this.logger.error(`x402 settle failed: ${msg}`);
      return { ok: false, reason: msg };
    }
  }
}
