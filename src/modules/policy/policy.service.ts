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
 * layer-1 amount semantics: native-value flows map to (asset = ETH sentinel,
 * amount = value); ERC-20 transfer/transferFrom map to (asset = token, amount =
 * the in-calldata amount, target = recipient) so per-asset token limits apply;
 * other contract calls pass (asset = target, amount = 0) for ContractScope only.
 * Pending SP final Q4 (ETH sentinel value) / Q5 (governance) — both are
 * configurable constants and do not change the checkPolicy read signature.
 */
export interface PolicyDecision {
  allowed: boolean;
  /** Human-readable reason; surfaced in logs only, never leaks signing material. */
  reason?: string;
}

interface DecodedCall {
  to: string;
  value: bigint;
  /** Inner call payload (the ERC-20/contract call the account makes). */
  func: string;
  /** 4-byte selector of the inner call (0x00000000 if none / plain transfer). */
  selector: string;
}

/**
 * The policy-relevant view of a call. `contract` and `recipient` are kept SEPARATE
 * on purpose: a selector match alone must never let a call masquerade as a token
 * transfer and skip the contract check (the F3-augment fix). For a real ERC-20
 * transfer these differ (contract = token, recipient = payee); for native/generic
 * calls they coincide (both = execute's dest).
 */
interface PolicyCall {
  /** The contract actually being called (execute's dest) — the ContractScope key. */
  contract: string;
  /** Value recipient: decoded payee/spender for token ops, else the contract. */
  recipient: string;
  asset: string;
  amount: bigint;
  selector: string;
}

// IPolicyRegistry.PolicyDecision enum. Co-sign ONLY on these known-good values;
// REJECT (2) and any unknown/future variant (e.g. a v2 REQUIRE_EXTRA) fail closed.
const ALLOW = 0;
const REQUIRE_DVT = 1;

// Account call surface (contracts/src/AAStarAccountBase.sol).
const EXECUTE_SELECTOR = ethers.id("execute(address,uint256,bytes)").slice(0, 10);
const EXECUTE_BATCH_SELECTOR = ethers.id("executeBatch(address[],uint256[],bytes[])").slice(0, 10);
const NULL_SELECTOR = "0x00000000";

// ERC-20 value-moving calls — the moved amount lives in the inner calldata, not
// in execute()'s native `value`. Extracting it is what lets per-asset amount
// limits apply to token transfers (the common case), not just native ETH.
const ERC20_TRANSFER = ethers.id("transfer(address,uint256)").slice(0, 10);
const ERC20_TRANSFER_FROM = ethers.id("transferFrom(address,address,uint256)").slice(0, 10);
// approve() authorizes future spend — gate the approved amount too, else an
// infinite approval is invisible to the amount checks (Codex F7).
const ERC20_APPROVE = ethers.id("approve(address,uint256)").slice(0, 10);

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
      // Fail fast on a no-op gate: POLICY_ENABLED=true with zero rules would silently
      // allow everything, giving operators a false sense of enforcement.
      if (
        !this.registryAddress &&
        this.perTxMaxWei === null &&
        this.recipientAllowlist.size === 0
      ) {
        throw new Error(
          "POLICY_ENABLED=true but no policy configured — set POLICY_REGISTRY_ADDRESS, " +
            "POLICY_PER_TX_MAX_WEI, and/or POLICY_RECIPIENT_ALLOWLIST. Refusing to start a no-op gate."
        );
      }
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

    // Normalize each call ONCE to its policy-relevant (target, asset, amount, selector).
    // Throws on a malformed token payload → fail-closed. Reused by both layers so the
    // operator floor sees the REAL recipient/amount, not just the immediate `to`.
    let pcs: PolicyCall[];
    try {
      pcs = calls.map(c => this.normalizeForPolicy(c));
    } catch (e: any) {
      return { allowed: false, reason: `undecodable transfer (fail-closed): ${e?.message ?? e}` };
    }

    // Layer 2 — node-operator floor (local, owner/CA cannot override).
    for (const [i, call] of calls.entries()) {
      // perTxMaxWei is a NATIVE-wei cap → only the native value of the call.
      if (this.perTxMaxWei !== null && call.value > this.perTxMaxWei) {
        return {
          allowed: false,
          reason: `call[${i}] value ${call.value} exceeds perTxMaxWei ${this.perTxMaxWei}`,
        };
      }
      // Allowlist must cover EVERY address the call touches — both the contract being
      // called AND the decoded recipient (augment, not replace). Checking only the
      // decoded recipient would let execute(maliciousContract, 0, transferSelector‖
      // allowlistedAddr‖x) masquerade as a token transfer and skip the contract check.
      if (this.recipientAllowlist.size > 0) {
        for (const addr of [pcs[i].contract, pcs[i].recipient]) {
          if (!this.recipientAllowlist.has(addr.toLowerCase())) {
            return { allowed: false, reason: `call[${i}] address ${addr} not in allowlist` };
          }
        }
      }
    }

    // Layer 1 — per-account on-chain registry (if configured). Fail-closed on revert.
    // Checks run concurrently (Codex F6 — no sequential per-call RPC latency).
    if (this.registryAddress) {
      let results: { decision: number; remainingDaily: bigint }[];
      try {
        results = await Promise.all(
          pcs.map(pc =>
            // ContractScope key = the contract actually called (call.to), NOT the
            // decoded recipient — so a selector-collision call can't be checked as a
            // benign token transfer while the real target goes unexamined.
            this.blockchainService.checkPolicy(
              this.registryAddress,
              userOp.sender,
              pc.contract,
              pc.asset,
              pc.amount,
              pc.selector
            )
          )
        );
      } catch (e: any) {
        return {
          allowed: false,
          reason: `registry checkPolicy reverted (fail-closed): ${e?.message ?? e}`,
        };
      }
      // Fail-closed: co-sign ONLY on a known-good decision. REJECT and any unknown/
      // future variant refuse (Codex F4 — was fail-open on anything != REJECT).
      for (const [i, { decision }] of results.entries()) {
        if (decision !== ALLOW && decision !== REQUIRE_DVT) {
          return {
            allowed: false,
            reason: `call[${i}] registry decision = ${decision} (not ALLOW/REQUIRE_DVT)`,
          };
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
          func: func as string,
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
        func: funcArr[i],
        selector: this.innerSelector(funcArr[i]),
      }));
    }

    throw new Error(`unsupported callData selector ${selector}`);
  }

  /**
   * Reduce a decoded call to what the policy actually cares about: which asset
   * moves, how much, and to whom. Native ETH's amount is execute()'s `value`;
   * an ERC-20 transfer's amount lives in the inner calldata (value == 0), so it
   * must be decoded — otherwise per-asset token limits see amount 0 and never fire
   * (the gap a compromised owner draining stablecoins would slip through).
   * Throws on a malformed token payload → caller fails closed.
   */
  private normalizeForPolicy(call: DecodedCall): PolicyCall {
    // Token value-moving calls are checked BEFORE the native-value shortcut (Codex F2)
    // so a token transfer's real (asset, amount, recipient) is always captured — even
    // if a stray native value is also attached.
    //
    // ERC-20 transfer(to, amount): asset = the token (call.to), amount from calldata.
    if (call.selector === ERC20_TRANSFER) {
      const [to, amount] = ABI.decode(["address", "uint256"], "0x" + call.func.slice(10));
      return {
        contract: call.to,
        recipient: to as string,
        asset: call.to,
        amount: amount as bigint,
        selector: call.selector,
      };
    }
    // ERC-20 transferFrom(from, to, amount): value pulled to `to`; asset = the token.
    if (call.selector === ERC20_TRANSFER_FROM) {
      const [, to, amount] = ABI.decode(
        ["address", "address", "uint256"],
        "0x" + call.func.slice(10)
      );
      return {
        contract: call.to,
        recipient: to as string,
        asset: call.to,
        amount: amount as bigint,
        selector: call.selector,
      };
    }
    // ERC-20 approve(spender, amount): an allowance is authorized FUTURE spend — gate
    // the approved amount so a large/infinite approval is not invisible (Codex F7).
    if (call.selector === ERC20_APPROVE) {
      const [spender, amount] = ABI.decode(["address", "uint256"], "0x" + call.func.slice(10));
      return {
        contract: call.to,
        recipient: spender as string,
        asset: call.to,
        amount: amount as bigint,
        selector: call.selector,
      };
    }
    // Native ETH movement: the value leaving the account is execute()'s `value`.
    if (call.value > 0n) {
      return {
        contract: call.to,
        recipient: call.to,
        asset: this.ethSentinel,
        amount: call.value,
        selector: call.selector,
      };
    }
    // Generic contract call: no native value, no recognized token transfer.
    // amount 0 → only the registry's per-contract ContractScope (allow/velocity) applies.
    return {
      contract: call.to,
      recipient: call.to,
      asset: call.to,
      amount: 0n,
      selector: call.selector,
    };
  }

  /** 4-byte selector of an inner call payload, or NULL_SELECTOR for a bare transfer. */
  private innerSelector(func: string): string {
    if (typeof func !== "string" || !func.startsWith("0x") || func.length < 10) {
      return NULL_SELECTOR;
    }
    return func.slice(0, 10);
  }
}
