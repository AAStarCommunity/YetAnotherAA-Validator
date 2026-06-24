import { Injectable, Logger, Optional, OnApplicationBootstrap } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { ethers } from "ethers";
import { CapabilityRegistry } from "../capability/capability-registry.service.js";
import { bumpedFees } from "../../utils/gas.util.js";
import { RelayV3Dto } from "./dto/relay.dto.js";
import {
  BUY_INTENT_DOMAIN_NAME,
  BUY_INTENT_DOMAIN_VERSION,
  BUY_INTENT_TYPES,
  DEFAULT_MAX_PAYMENT_USDC_6DEC,
  EXECUTE_BUY_FRAGMENT,
  SEPOLIA_DEFAULTS,
  type RelayErrorCode,
  type RelayResult,
} from "./relay.constants.js";

/**
 * Gasless purchase relay (#98) — optional, opt-in module.
 *
 * Ports the v3 path of the standalone `mycelium/launch → services/relayer`
 * Cloudflare Worker into the DVT node so the launch token sale (GToken / aPNTs)
 * no longer depends on a single centralized Worker. dvt1/2/3 can each run it for
 * redundancy + anti-censorship — every node is an independent relayer; the SDK
 * picks one and fails over. This is "redundancy decentralization"; the aPoints-
 * metered economic layer (permissionless, paid relay) is a deferred Phase 2.
 *
 * It is ORTHOGONAL to the BLS signing core: the buyer signs with their own EOA
 * (EIP-3009 + EIP-712 BuyIntent), the node submits with its operator EOA. No
 * PackedUserOperation, no AAStarValidator, no BLS aggregation is involved — so
 * this never touches the security-critical 403 owner-auth gate.
 *
 * Opt-in (RELAY_ENABLED, default off). Requires a DEDICATED RELAY_OPERATOR_PK —
 * a funded hot wallet that pays gas. It intentionally does NOT fall back to the
 * validator-owner ETH_PRIVATE_KEY: the relay operator is a public-facing
 * gas-paying key and must be isolated from the registration/owner key.
 *
 * Off-chain checks here (whitelist, caps, deadline, signature recovery) are a
 * fast-fail gate to save gas; BuyHelper re-verifies everything on-chain and is
 * authoritative.
 */
@Injectable()
export class RelayService implements OnApplicationBootstrap {
  private readonly logger = new Logger(RelayService.name);

  private readonly enabledByConfig: boolean;
  private readonly operatorPk: string;
  private readonly rpcUrl: string;
  private readonly chainId: number;
  private readonly buyHelper: string;
  private readonly usdc: string;
  private readonly gtoken: string;
  private readonly apnts: string;
  private readonly maxPaymentAmount: bigint;
  private readonly maxPerAddressPerHour: number;
  private readonly maxGlobalPerHour: number;
  private readonly now: () => number;

  /** Live once bootstrap validates the operator key; null = relay disabled. */
  private wallet: ethers.Wallet | null = null;

  /** In-memory rate-limit counters, replacing the Worker's Cloudflare KV. */
  private readonly addrCounts = new Map<string, number>();
  private readonly globalCounts = new Map<number, number>();

  /** Serializes on-chain submissions so concurrent requests can't reuse a nonce. */
  private submitChain: Promise<unknown> = Promise.resolve();

  constructor(
    private readonly config: ConfigService,
    @Optional() capabilityRegistry?: CapabilityRegistry,
    /** Test seam: controls `Date.now()` for deadline/rate-limit windows. */
    @Optional() now?: () => number
  ) {
    this.enabledByConfig = config.get<boolean>("relayEnabled") === true;
    this.operatorPk = config.get<string>("relayOperatorPk") ?? "";
    this.rpcUrl = config.get<string>("relayRpcUrl") ?? config.get<string>("ethRpcUrl") ?? "";
    this.chainId = config.get<number>("relayChainId") ?? SEPOLIA_DEFAULTS.chainId;
    this.buyHelper = config.get<string>("relayBuyHelper") ?? SEPOLIA_DEFAULTS.buyHelper;
    this.usdc = config.get<string>("relayUsdc") ?? SEPOLIA_DEFAULTS.usdc;
    this.gtoken = config.get<string>("relayGtoken") ?? SEPOLIA_DEFAULTS.gtoken;
    this.apnts = config.get<string>("relayApnts") ?? SEPOLIA_DEFAULTS.apnts;
    this.maxPaymentAmount = BigInt(
      config.get<string>("relayMaxPaymentAmount") ?? DEFAULT_MAX_PAYMENT_USDC_6DEC
    );
    this.maxPerAddressPerHour = config.get<number>("relayRateLimitPerAddressPerHour") ?? 5;
    this.maxGlobalPerHour = config.get<number>("relayRateLimitGlobalPerHour") ?? 100;
    this.now = now ?? (() => Date.now());

    capabilityRegistry?.register({
      name: "relay",
      class: "infra-app",
      description: "Gasless GToken/aPNTs purchase relay for the launch sale (#98)",
      enabled: this.enabledByConfig,
    });
  }

  onApplicationBootstrap(): void {
    if (!this.enabledByConfig) return;
    if (!/^0x[0-9a-fA-F]{64}$/.test(this.operatorPk)) {
      this.logger.warn(
        "Relay: RELAY_ENABLED=true but RELAY_OPERATOR_PK missing/invalid " +
          "(must be 32-byte 0x hex, dedicated — NOT the validator owner key) — disabled"
      );
      return;
    }
    if (!this.rpcUrl) {
      this.logger.warn(
        "Relay: RELAY_ENABLED=true but no RPC URL (RELAY_RPC_URL/ETH_RPC_URL) — disabled"
      );
      return;
    }
    const provider = new ethers.JsonRpcProvider(this.rpcUrl, this.chainId);
    this.wallet = new ethers.Wallet(this.operatorPk, provider);
    this.logger.log(
      `Gasless relay ENABLED — operator=${this.wallet.address} chainId=${this.chainId} ` +
        `buyHelper=${this.buyHelper} caps: ${this.maxPerAddressPerHour}/addr/h ` +
        `${this.maxGlobalPerHour}/global/h perTx≤${this.maxPaymentAmount}`
    );
  }

  /** True once the operator wallet is live (RELAY_ENABLED + valid key + RPC). */
  isEnabled(): boolean {
    return this.wallet !== null;
  }

  /** Operator address for /relay/health, or null when disabled. */
  operatorAddress(): string | null {
    return this.wallet?.address ?? null;
  }

  /**
   * Full relay attempt: rate limit → validate/build → submit. Never throws;
   * returns a discriminated RelayResult that the controller maps to HTTP status.
   */
  async relay(body: RelayV3Dto): Promise<RelayResult> {
    if (!this.wallet) {
      return { ok: false, code: "INFRA_NOT_READY", reason: "relay not enabled on this node" };
    }

    const buyer = body?.intent?.buyer;
    if (!buyer || typeof buyer !== "string" || !/^0x[0-9a-fA-F]{40}$/.test(buyer)) {
      return { ok: false, code: "INVALID_SHAPE", reason: "intent.buyer must be a valid address" };
    }

    const rl = this.checkRateLimit(buyer);
    if (!rl.allowed) {
      return { ok: false, code: "RATE_LIMITED", reason: rl.reason };
    }

    const built = this.validateAndBuild(body);
    if (!built.ok) return built;

    return this.submit(built.callData, built.matchedRule);
  }

  /**
   * Pure validation + calldata encoding (no network). Verifies whitelist, caps,
   * deadline and the BuyIntent signature, then ABI-encodes executeBuy. Exposed
   * for unit testing.
   */
  validateAndBuild(
    body: RelayV3Dto
  ):
    | { ok: true; callData: string; matchedRule: string }
    | { ok: false; code: RelayErrorCode; reason: string } {
    if (!body?.intent || !body?.buyIntentSig || !body?.transferAuth) {
      return { ok: false, code: "INVALID_SHAPE", reason: "missing required fields" };
    }
    const i = body.intent;
    if (!i.buyer || !i.paymentToken || !i.targetToken || !i.recipient || !i.nonce) {
      return { ok: false, code: "INVALID_SHAPE", reason: "missing intent field" };
    }

    // Whitelist: USDC payment only; GToken or aPNTs target only.
    if (i.paymentToken.toLowerCase() !== this.usdc.toLowerCase()) {
      return {
        ok: false,
        code: "NOT_WHITELISTED",
        reason: `paymentToken ${i.paymentToken} not whitelisted`,
      };
    }
    const isGToken = i.targetToken.toLowerCase() === this.gtoken.toLowerCase();
    const isAPNTs = i.targetToken.toLowerCase() === this.apnts.toLowerCase();
    if (!isGToken && !isAPNTs) {
      return {
        ok: false,
        code: "NOT_WHITELISTED",
        reason: `targetToken ${i.targetToken} not whitelisted`,
      };
    }

    // Deadline (cheap, before signature work).
    const nowSec = Math.floor(this.now() / 1000);
    if (i.deadline < nowSec) {
      return { ok: false, code: "EXPIRED", reason: `deadline ${i.deadline} < now ${nowSec}` };
    }

    // Amount caps.
    let paymentAmount: bigint;
    let minOut: bigint;
    try {
      paymentAmount = BigInt(i.paymentAmount);
      minOut = BigInt(i.minOut);
    } catch {
      return { ok: false, code: "INVALID_SHAPE", reason: "paymentAmount/minOut not integer" };
    }
    if (paymentAmount === 0n) {
      return { ok: false, code: "INVALID_SHAPE", reason: "paymentAmount must be > 0" };
    }
    if (paymentAmount > this.maxPaymentAmount) {
      return {
        ok: false,
        code: "NOT_WHITELISTED",
        reason: `paymentAmount ${paymentAmount} exceeds per-tx cap ${this.maxPaymentAmount}`,
      };
    }

    // Off-chain verify BuyIntent (BuyHelper re-checks on-chain).
    let recovered: string;
    try {
      recovered = ethers.verifyTypedData(
        {
          name: BUY_INTENT_DOMAIN_NAME,
          version: BUY_INTENT_DOMAIN_VERSION,
          chainId: this.chainId,
          verifyingContract: this.buyHelper,
        },
        BUY_INTENT_TYPES as unknown as Record<string, ethers.TypedDataField[]>,
        {
          buyer: i.buyer,
          paymentToken: i.paymentToken,
          paymentAmount,
          targetToken: i.targetToken,
          recipient: i.recipient,
          minOut,
          deadline: BigInt(i.deadline),
          nonce: i.nonce,
        },
        body.buyIntentSig
      );
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      return { ok: false, code: "SIGNATURE_INVALID", reason: `BuyIntent verify threw: ${msg}` };
    }
    if (recovered.toLowerCase() !== i.buyer.toLowerCase()) {
      return {
        ok: false,
        code: "SIGNATURE_INVALID",
        reason: `BuyIntent signer ${recovered} ≠ buyer ${i.buyer}`,
      };
    }

    // Encode executeBuy calldata.
    let callData: string;
    try {
      const iface = new ethers.Interface([EXECUTE_BUY_FRAGMENT]);
      callData = iface.encodeFunctionData("executeBuy", [
        [
          i.buyer,
          i.paymentToken,
          paymentAmount,
          i.targetToken,
          i.recipient,
          minOut,
          BigInt(i.deadline),
          i.nonce,
        ],
        body.buyIntentSig,
        [
          BigInt(body.transferAuth.validAfter),
          body.transferAuth.v,
          body.transferAuth.r,
          body.transferAuth.s,
        ],
      ]);
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      return { ok: false, code: "INVALID_SHAPE", reason: `encode failed: ${msg}` };
    }

    return {
      ok: true,
      callData,
      matchedRule: isGToken ? "TOKEN_BUY → GToken" : "TOKEN_BUY → aPNTs",
    };
  }

  /** Submit the executeBuy tx, serialized so concurrent calls get distinct nonces. */
  private submit(callData: string, matchedRule: string): Promise<RelayResult> {
    const run = this.submitChain.then(
      () => this.sendTx(callData, matchedRule),
      () => this.sendTx(callData, matchedRule)
    );
    // Keep the chain alive regardless of this submission's outcome.
    this.submitChain = run.catch(() => {});
    return run;
  }

  private async sendTx(callData: string, matchedRule: string): Promise<RelayResult> {
    try {
      // Bump fees (estimate +15%, priority floor) so the tx mines promptly — a
      // BuyIntent carries a deadline, and an underpriced tx that mines late
      // reverts on-chain with Expired (still burning the operator's gas).
      const fees = await bumpedFees(this.wallet!.provider!);
      const tx = await this.wallet!.sendTransaction({
        to: this.buyHelper,
        data: callData,
        value: 0n,
        ...fees,
      });
      this.logger.log(`Relay submitted ${matchedRule} → ${tx.hash}`);
      return { ok: true, txHash: tx.hash, matchedRule };
    } catch (e: unknown) {
      const msg =
        (e as { shortMessage?: string })?.shortMessage ??
        (e instanceof Error ? e.message : String(e));
      this.logger.error(`Relay submit failed: ${msg}`);
      return { ok: false, code: "SUBMIT_FAILED", reason: msg };
    }
  }

  /**
   * 1-hour fixed-window rate limit, per-address and global. Mirrors the Worker's
   * KV limiter with in-memory counters; old windows are pruned on each check.
   */
  private checkRateLimit(buyer: string): { allowed: boolean; reason: string } {
    const epoch = Math.floor(this.now() / 3_600_000);
    this.pruneWindows(epoch);

    const addrKey = `${buyer.toLowerCase()}:${epoch}`;
    const addrCount = this.addrCounts.get(addrKey) ?? 0;
    const globalCount = this.globalCounts.get(epoch) ?? 0;

    if (addrCount >= this.maxPerAddressPerHour) {
      return {
        allowed: false,
        reason: `Address rate limit: ${this.maxPerAddressPerHour}/hour exceeded`,
      };
    }
    if (globalCount >= this.maxGlobalPerHour) {
      return {
        allowed: false,
        reason: `Global rate limit: ${this.maxGlobalPerHour}/hour exceeded`,
      };
    }

    this.addrCounts.set(addrKey, addrCount + 1);
    this.globalCounts.set(epoch, globalCount + 1);
    return { allowed: true, reason: "" };
  }

  /** Drop counters from windows older than the current one to bound memory. */
  private pruneWindows(currentEpoch: number): void {
    for (const epoch of this.globalCounts.keys()) {
      if (epoch < currentEpoch) this.globalCounts.delete(epoch);
    }
    for (const key of this.addrCounts.keys()) {
      const epoch = Number(key.slice(key.lastIndexOf(":") + 1));
      if (epoch < currentEpoch) this.addrCounts.delete(key);
    }
  }
}
