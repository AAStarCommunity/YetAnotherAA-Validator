import { Injectable, Logger } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { ethers } from "ethers";
import { randomBytes } from "crypto";
import { PackedUserOp } from "../blockchain/blockchain.service.js";
import { NotificationService } from "../notification/notification.service.js";

/** Result of the confirmation gate for a co-sign request. */
export type GateResult = "not_required" | "confirmed" | "pending" | "undeliverable";

interface Pending {
  token: string;
  confirmed: boolean;
  expiry: number;
}

const EXECUTE_SELECTOR = ethers.id("execute(address,uint256,bytes)").slice(0, 10);
const ABI = new ethers.AbiCoder();

/**
 * Out-of-band CONFIRMATION (scheme A — #50 ⑤ / #52 increment 2).
 *
 * For a high-value op the node does NOT co-sign until the real account user approves via
 * an independent channel (Telegram/email/Nostr) that an attacker — even one holding the
 * owner key — does not control. This is what lets the DVT tier survive owner-key
 * compromise: the stolen key alone can authorize Stage-1, but cannot produce the
 * out-of-band approval.
 *
 * Flow: gate() on a high-value op creates a pending entry, sends a one-time `token`
 * ONLY over the user's independent channel, and returns "pending" (node withholds the
 * signature). The user approves by hitting POST /signature/confirm with that token
 * (e.g. a link in the Telegram message) — the client/attacker never sees it. A later
 * sign request for the same userOpHash then gates to "confirmed" and signs.
 *
 * Fail-closed: if a high-value op needs confirmation but no contact/channel can deliver
 * the token ("undeliverable"), the node REFUSES — it must never sign a high-value op it
 * cannot get the user to approve. Tokens are single-use and expire.
 *
 * Opt-in via CONFIRM_ENABLED.
 */
@Injectable()
export class ConfirmationService {
  private readonly logger = new Logger(ConfirmationService.name);
  private readonly enabled: boolean;
  private readonly thresholdWei: bigint;
  private readonly ttlMs: number;
  private readonly pending = new Map<string, Pending>();

  constructor(
    configService: ConfigService,
    private readonly notificationService: NotificationService
  ) {
    this.enabled = configService.get<boolean>("confirmEnabled") === true;
    this.thresholdWei = BigInt(configService.get<string>("confirmThresholdWei") ?? "0");
    this.ttlMs = configService.get<number>("confirmTtlMs") ?? 600_000; // 10 min default
    if (this.enabled) {
      this.logger.log(
        `Out-of-band confirmation ENABLED — threshold=${this.thresholdWei} wei, ttl=${this.ttlMs}ms`
      );
    }
  }

  /**
   * Decide whether this op may be signed now. For a high-value op it creates/sends a
   * pending confirmation and returns "pending" (withhold signature) until the user
   * confirms out-of-band; "confirmed" releases it (single-use); "undeliverable" means
   * fail-closed (no channel to reach the user).
   */
  async gate(userOp: PackedUserOp, userOpHash: string): Promise<GateResult> {
    if (!this.enabled) return "not_required";
    if (this.nativeValue(userOp) < this.thresholdWei) return "not_required";

    const now = Date.now();
    let p = this.pending.get(userOpHash);
    if (p && p.expiry <= now) {
      this.pending.delete(userOpHash);
      p = undefined;
    }
    if (p?.confirmed) {
      this.pending.delete(userOpHash); // single-use
      return "confirmed";
    }
    if (p) return "pending"; // already awaiting confirmation

    // New high-value op → require out-of-band approval.
    if (!this.notificationService.hasContact(userOp.sender)) return "undeliverable";
    const token = "0x" + randomBytes(16).toString("hex");
    this.pending.set(userOpHash, { token, confirmed: false, expiry: now + this.ttlMs });
    const msg =
      `🔐 DVT confirmation required for ${userOp.sender}.\n` +
      `Op ${userOpHash}\nApprove only if you initiated it. Confirm token: ${token}`;
    const delivered = await this.notificationService.sendToAccount(userOp.sender, msg);
    if (!delivered) {
      this.pending.delete(userOpHash);
      return "undeliverable";
    }
    return "pending";
  }

  /** Approve a pending op by its userOpHash + the out-of-band token. Single-use. */
  confirm(userOpHash: string, token: string): boolean {
    const p = this.pending.get(userOpHash);
    if (!p || p.expiry <= Date.now() || p.token !== token) return false;
    p.confirmed = true;
    return true;
  }

  private nativeValue(userOp: PackedUserOp): bigint {
    try {
      const cd = userOp.callData;
      if (typeof cd !== "string" || cd.slice(0, 10) !== EXECUTE_SELECTOR) return 0n;
      const [, value] = ABI.decode(["address", "uint256", "bytes"], "0x" + cd.slice(10));
      return value as bigint;
    } catch {
      return 0n;
    }
  }
}
