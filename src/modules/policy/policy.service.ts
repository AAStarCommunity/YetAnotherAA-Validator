import { Injectable, Logger } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { ethers } from "ethers";
import { PackedUserOp, BlockchainService } from "../blockchain/blockchain.service.js";

/**
 * Fix 2 Stage 2 — DVT node INDEPENDENT policy gate (owner-compromise protection).
 *
 * Stage 1 proved the request carries the account owner's signature. That defends
 * against an attacker WITHOUT the owner key, but NOT against a *compromised* owner
 * key — once stolen, the attacker can produce a valid ownerAuth.
 *
 * Stage 2's value comes purely from INDEPENDENCE (see AirAccount #70): this node
 * applies its OWN decision, using rules that the account owner and the CA cannot
 * change, BEFORE it co-signs. A node that blind-signs provides zero security.
 *
 * Two layers, ANDed (either rejects → no co-sign):
 *   - Layer 1 (per-account, on-chain): IPolicyRegistry.checkPolicy — the account
 *     owner's own limits, governance-gated so a compromised owner cannot instantly
 *     loosen them. SAME source slashing references (node-source == slash-source).
 *   - Layer 2 (node operator, local): perTxMax + recipient allowlist — the operator's
 *     floor that no on-chain state can override. The hard independence guarantee.
 *
 * v1 layer-1 scope: native-value flows map to (asset = ETH sentinel, amount = value);
 * token/contract calls pass (asset = target, amount = value) + selector, so the
 * registry's per-contract ContractScope applies. ERC20 in-calldata amount extraction
 * is a follow-up. Pending SP final Q4 (ETH sentinel value) / Q5 (governance) — both
 * are configurable constants and do not change the checkPolicy read signature.
 */
export interface PolicyDecision {
  allowed: boolean;
  /** Human-readable reason; surfaced in logs only, never leaks signing material. */
  reason?: string;
}

interface DecodedCall {
  to: string;
  value: bigint;
  /** 4-byte selector of the inner call (0x00000000 if none / plain transfer). */
  selector: string;
}

// IPolicyRegistry.PolicyDecision enum.
const REJECT = 2;

// Account call surface (contracts/src/AAStarAccountBase.sol).
const EXECUTE_SELECTOR = ethers.id("execute(address,uint256,bytes)").slice(0, 10);
const EXECUTE_BATCH_SELECTOR = ethers.id("executeBatch(address[],uint256[],bytes[])").slice(0, 10);
const NULL_SELECTOR = "0x00000000";

const ABI = new ethers.AbiCoder();

@Injectable()
export class PolicyService {
  private readonly logger = new Logger(PolicyService.name);

  private readonly enabled: boolean;
  private readonly perTxMaxWei: bigint | null;
  /** Lowercased recipient allowlist; empty set = allow any recipient. */
  private readonly recipientAllowlist: Set<string>;
  /** Layer-1: on-chain IPolicyRegistry address; empty = layer-1 disabled. */
  private readonly registryAddress: string;
  /** Asset key used for native ETH in checkPolicy (Q4 — pending SP final). */
  private readonly ethSentinel: string;

  constructor(
    private readonly configService: ConfigService,
    private readonly blockchainService: BlockchainService
  ) {
    this.enabled = this.configService.get<boolean>("policyEnabled") === true;
    const max = this.configService.get<string>("policyPerTxMaxWei");
    this.perTxMaxWei = max ? BigInt(max) : null;
    const allow = this.configService.get<string[]>("policyRecipientAllowlist") ?? [];
    this.recipientAllowlist = new Set(allow.map(a => a.toLowerCase()));
    this.registryAddress = this.configService.get<string>("policyRegistryAddress") ?? "";
    this.ethSentinel =
      this.configService.get<string>("policyEthSentinel") ??
      "0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE";

    if (this.enabled) {
      this.logger.log(
        `DVT policy gate ENABLED — perTxMaxWei=${this.perTxMaxWei ?? "unset"}, ` +
          `allowlist=${this.recipientAllowlist.size} entries, ` +
          `registry=${this.registryAddress || "unset (layer-1 off)"}`
      );
    } else {
      this.logger.log("DVT policy gate DISABLED (POLICY_ENABLED!=true) — Stage 1 behavior only");
    }
  }

  /**
   * Decide whether this node may co-sign `userOp`. Fail-closed: when the gate is
   * enabled and the operation cannot be decoded into concrete calls — or the
   * on-chain registry read reverts — the node REFUSES.
   *
   * When disabled, always allows (preserves Stage 1 behavior exactly).
   */
  async evaluate(userOp: PackedUserOp): Promise<PolicyDecision> {
    if (!this.enabled) {
      return { allowed: true };
    }

    let calls: DecodedCall[];
    try {
      calls = this.decodeCalls(userOp.callData);
    } catch (e: any) {
      return { allowed: false, reason: `undecodable callData (fail-closed): ${e?.message ?? e}` };
    }

    if (calls.length === 0) {
      return { allowed: false, reason: "no decodable calls in callData (fail-closed)" };
    }

    // Layer 2 — node-operator floor (local, owner/CA cannot override).
    for (const [i, call] of calls.entries()) {
      if (this.perTxMaxWei !== null && call.value > this.perTxMaxWei) {
        return {
          allowed: false,
          reason: `call[${i}] value ${call.value} exceeds perTxMaxWei ${this.perTxMaxWei}`,
        };
      }
      if (this.recipientAllowlist.size > 0 && !this.recipientAllowlist.has(call.to.toLowerCase())) {
        return { allowed: false, reason: `call[${i}] recipient ${call.to} not in allowlist` };
      }
    }

    // Layer 1 — per-account on-chain registry (if configured). Fail-closed on revert.
    if (this.registryAddress) {
      for (const [i, call] of calls.entries()) {
        const isNative = call.value > 0n;
        const asset = isNative ? this.ethSentinel : call.to;
        let decision: number;
        try {
          ({ decision } = await this.blockchainService.checkPolicy(
            this.registryAddress,
            userOp.sender,
            call.to,
            asset,
            call.value,
            call.selector
          ));
        } catch (e: any) {
          return {
            allowed: false,
            reason: `call[${i}] registry checkPolicy reverted (fail-closed): ${e?.message ?? e}`,
          };
        }
        // ALLOW / REQUIRE_DVT are both within policy → node may co-sign. REJECT → refuse.
        if (decision === REJECT) {
          return { allowed: false, reason: `call[${i}] registry decision = REJECT` };
        }
      }
    }

    return { allowed: true };
  }

  /**
   * Decode the account's callData into concrete (to, value, selector) calls.
   * Supports the standard ERC-4337 v0.7/v0.8 account surface; anything else
   * throws → fail-closed.
   */
  private decodeCalls(callData: string): DecodedCall[] {
    if (typeof callData !== "string" || !callData.startsWith("0x") || callData.length < 10) {
      throw new Error("callData is not a 0x selector-prefixed string");
    }

    const selector = callData.slice(0, 10);
    const args = "0x" + callData.slice(10);

    if (selector === EXECUTE_SELECTOR) {
      const [dest, value, func] = ABI.decode(["address", "uint256", "bytes"], args);
      return [
        {
          to: dest as string,
          value: value as bigint,
          selector: this.innerSelector(func as string),
        },
      ];
    }

    if (selector === EXECUTE_BATCH_SELECTOR) {
      const [dests, values, funcs] = ABI.decode(["address[]", "uint256[]", "bytes[]"], args);
      const destArr = dests as string[];
      const valueArr = values as bigint[];
      const funcArr = funcs as string[];
      if (destArr.length !== valueArr.length || destArr.length !== funcArr.length) {
        throw new Error("executeBatch dest/value/func length mismatch");
      }
      return destArr.map((to, i) => ({
        to,
        value: valueArr[i],
        selector: this.innerSelector(funcArr[i]),
      }));
    }

    throw new Error(`unsupported callData selector ${selector}`);
  }

  /** 4-byte selector of an inner call payload, or NULL_SELECTOR for a bare transfer. */
  private innerSelector(func: string): string {
    if (typeof func !== "string" || !func.startsWith("0x") || func.length < 10) {
      return NULL_SELECTOR;
    }
    return func.slice(0, 10);
  }
}
