import { Injectable, Logger } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { ethers } from "ethers";
import { PackedUserOp } from "../blockchain/blockchain.service.js";

/**
 * Fix 2 Stage 2 — DVT node INDEPENDENT policy gate (owner-compromise protection).
 *
 * Stage 1 proved the request carries the account owner's signature. That defends
 * against an attacker WITHOUT the owner key, but NOT against a *compromised* owner
 * key — once stolen, the attacker can produce a valid ownerAuth.
 *
 * Stage 2's value comes purely from INDEPENDENCE (see AirAccount #70): this node
 * applies its OWN decision, using rules that the account owner and the CA cannot
 * change, BEFORE it co-signs. The node decodes the operation and refuses to
 * co-sign anything outside policy. A node that blind-signs provides zero security,
 * so this gate is the whole point of the DVT tier as a true second factor.
 *
 * This gate is INDEPENDENT of the on-chain BLS binding format (airaccount-contract
 * #45/#110): it decides *whether* to sign, not *what* the signed messagePoint is.
 * It can therefore ship before the cross-repo signature-format negotiation settles.
 *
 * v1 scope: per-tx value limit + recipient allowlist, fail-closed on anything it
 * cannot decode. Daily/velocity limits and out-of-band confirmation are follow-ups
 * (they need cross-request persistence; see #40).
 */
export interface PolicyDecision {
  allowed: boolean;
  /** Human-readable reason; surfaced in logs only, never leaks signing material. */
  reason?: string;
}

interface DecodedCall {
  to: string;
  value: bigint;
}

// Account call surface (contracts/src/AAStarAccountBase.sol).
const EXECUTE_SELECTOR = ethers.id("execute(address,uint256,bytes)").slice(0, 10);
const EXECUTE_BATCH_SELECTOR = ethers.id("executeBatch(address[],uint256[],bytes[])").slice(0, 10);

const ABI = new ethers.AbiCoder();

@Injectable()
export class PolicyService {
  private readonly logger = new Logger(PolicyService.name);

  private readonly enabled: boolean;
  private readonly perTxMaxWei: bigint | null;
  /** Lowercased recipient allowlist; empty set = allow any recipient. */
  private readonly recipientAllowlist: Set<string>;

  constructor(private readonly configService: ConfigService) {
    this.enabled = this.configService.get<boolean>("policyEnabled") === true;
    const max = this.configService.get<string>("policyPerTxMaxWei");
    this.perTxMaxWei = max ? BigInt(max) : null;
    const allow = this.configService.get<string[]>("policyRecipientAllowlist") ?? [];
    this.recipientAllowlist = new Set(allow.map(a => a.toLowerCase()));

    if (this.enabled) {
      this.logger.log(
        `DVT policy gate ENABLED — perTxMaxWei=${this.perTxMaxWei ?? "unset"}, ` +
          `allowlist=${this.recipientAllowlist.size} entries`
      );
    } else {
      this.logger.log("DVT policy gate DISABLED (POLICY_ENABLED!=true) — Stage 1 behavior only");
    }
  }

  /**
   * Decide whether this node may co-sign `userOp`. Fail-closed: when the gate is
   * enabled and the operation cannot be decoded into concrete (to, value) calls,
   * the node REFUSES — an undecodable op cannot be proven within policy.
   *
   * When disabled, always allows (preserves Stage 1 behavior exactly).
   */
  evaluate(userOp: PackedUserOp): PolicyDecision {
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

    return { allowed: true };
  }

  /**
   * Decode the account's callData into concrete (to, value) calls. Supports the
   * standard ERC-4337 v0.7/v0.8 account surface; anything else throws → fail-closed.
   */
  private decodeCalls(callData: string): DecodedCall[] {
    if (typeof callData !== "string" || !callData.startsWith("0x") || callData.length < 10) {
      throw new Error("callData is not a 0x selector-prefixed string");
    }

    const selector = callData.slice(0, 10);
    const args = "0x" + callData.slice(10);

    if (selector === EXECUTE_SELECTOR) {
      const [dest, value] = ABI.decode(["address", "uint256", "bytes"], args);
      return [{ to: dest as string, value: value as bigint }];
    }

    if (selector === EXECUTE_BATCH_SELECTOR) {
      const [dests, values] = ABI.decode(["address[]", "uint256[]", "bytes[]"], args);
      const destArr = dests as string[];
      const valueArr = values as bigint[];
      if (destArr.length !== valueArr.length) {
        throw new Error("executeBatch dest/value length mismatch");
      }
      return destArr.map((to, i) => ({ to, value: valueArr[i] }));
    }

    throw new Error(`unsupported callData selector ${selector}`);
  }
}
