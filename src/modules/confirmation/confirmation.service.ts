import { Injectable, Logger, Optional } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { ethers } from "ethers";
import { randomBytes } from "crypto";
import axios from "axios";
import { PackedUserOp } from "../blockchain/blockchain.service.js";
import { NotificationService } from "../notification/notification.service.js";
import { CapabilityRegistry } from "../capability/capability-registry.service.js";

/** Out-of-band approval factor injected for testing the KMS RP verification. */
export type KmsVerifyFn = (
  account: string,
  userOpHash: string,
  passkey: unknown
) => Promise<boolean>;

/** Result of the confirmation gate for a co-sign request. */
export type GateResult = "not_required" | "confirmed" | "pending" | "undeliverable";

/** Read-only poll status of a pending confirmation (for SDK/UI; see getStatus). */
export type ConfirmationStatus = "pending" | "approved" | "expired" | "not_found";

interface Pending {
  token: string;
  confirmed: boolean;
  expiry: number;
  /** Account (userOp.sender) — passed to KMS for passkey RP verification (path-2). */
  account: string;
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
  private readonly kmsBaseUrl: string;
  private readonly kmsApiKey: string;
  /** KMS RP verification (test seam — defaults to the real HTTP call). */
  private readonly kmsVerify: KmsVerifyFn;
  private readonly pending = new Map<string, Pending>();

  constructor(
    configService: ConfigService,
    private readonly notificationService: NotificationService,
    @Optional() capabilityRegistry?: CapabilityRegistry,
    /** Test seam: inject a fake KMS verifier. Production uses the real HTTP call. */
    @Optional() kmsVerify?: KmsVerifyFn
  ) {
    this.enabled = configService.get<boolean>("confirmEnabled") === true;
    this.thresholdWei = BigInt(configService.get<string>("confirmThresholdWei") ?? "0");
    this.ttlMs = configService.get<number>("confirmTtlMs") ?? 600_000; // 10 min default
    this.kmsBaseUrl = (configService.get<string>("kmsBaseUrl") ?? "").replace(/\/$/, "");
    this.kmsApiKey = configService.get<string>("kmsApiKey") ?? "";
    this.kmsVerify = kmsVerify ?? ((a, u, p) => this.realKmsVerify(a, u, p));
    capabilityRegistry?.register({
      name: "confirm",
      class: "infra-app",
      description: "Out-of-band confirmation gate for high-value ops (#50 ⑤)",
      enabled: this.enabled,
    });
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
    this.pending.set(userOpHash, {
      token,
      confirmed: false,
      expiry: now + this.ttlMs,
      account: userOp.sender ?? "",
    });
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

  /**
   * Read-only status of a pending confirmation — does NOT consume it (for SDK/UI
   * polling, #124). The single-use consumption happens in gate() when the sign is
   * re-submitted after approval.
   *   not_found = never created, or already consumed by a successful sign
   *   pending   = awaiting out-of-band approval
   *   approved  = approved; re-submit the sign to release the signature
   *   expired   = TTL elapsed without approval (the implicit "rejected"; explicit
   *               reject isn't modeled — letting it expire is how a user declines)
   */
  getStatus(userOpHash: string): { status: ConfirmationStatus; expiresAt: number | null } {
    const p = this.pending.get(userOpHash);
    if (!p) return { status: "not_found", expiresAt: null };
    if (p.expiry <= Date.now()) return { status: "expired", expiresAt: p.expiry };
    return { status: p.confirmed ? "approved" : "pending", expiresAt: p.expiry };
  }

  /** Approve a pending op by its userOpHash + the out-of-band token. Single-use. */
  confirm(userOpHash: string, token: string): boolean {
    const p = this.pending.get(userOpHash);
    if (!p || p.expiry <= Date.now() || p.token !== token) return false;
    p.confirmed = true;
    return true;
  }

  /**
   * Approve a pending op via a passkey (WebAuthn) assertion — path-2 (#124, #193).
   * The passkey is a factor INDEPENDENT of the owner key, so this approval survives
   * owner-key compromise (a stolen secp256k1 owner key alone cannot produce it).
   *
   * Two checks, both must pass (fail-closed):
   *   1. local binding: clientDataJSON.type == "webauthn.get" AND challenge == base64url(userOpHash)
   *      — the assertion is bound to THIS op (the node enforces this itself).
   *   2. KMS RP verify: the WebAuthn assertion is cryptographically valid for the
   *      account's registered passkey (the RP lives in KMS, not the node).
   * `passkey` is the raw `navigator.credentials.get()` AuthenticationResponseJSON.
   */
  async confirmWithPasskey(userOpHash: string, passkey: unknown): Promise<boolean> {
    const p = this.pending.get(userOpHash);
    if (!p || p.expiry <= Date.now()) return false;

    if (!this.assertionBindsTo(passkey, userOpHash)) {
      this.logger.warn(
        `Passkey confirm ${userOpHash}: clientData challenge ≠ userOpHash — rejected`
      );
      return false;
    }
    // Lowercase the account before the KMS call — defense-in-depth so a checksummed
    // (EIP-55) userOp.sender always matches KMS's address key. KMS normalizes to
    // lowercase internally (AirAccount v0.27.2), but we don't depend on that here.
    const account = (p.account || "").toLowerCase();
    const verified = await this.kmsVerify(account, userOpHash, passkey).catch(e => {
      this.logger.error(`Passkey confirm ${userOpHash}: KMS verify threw — ${String(e)}`);
      return false; // fail-closed
    });
    if (!verified) return false;

    p.confirmed = true;
    return true;
  }

  /** clientDataJSON.type == "webauthn.get" AND its challenge == base64url(userOpHash). */
  private assertionBindsTo(passkey: unknown, userOpHash: string): boolean {
    try {
      const cdjB64 = (passkey as { response?: { clientDataJSON?: unknown } })?.response
        ?.clientDataJSON;
      if (typeof cdjB64 !== "string") return false;
      const cdj = JSON.parse(Buffer.from(cdjB64, "base64url").toString("utf8"));
      if (cdj?.type !== "webauthn.get") return false;
      const expected = Buffer.from(userOpHash.replace(/^0x/, ""), "hex").toString("base64url");
      return cdj?.challenge === expected;
    } catch {
      return false;
    }
  }

  /** Real KMS RP verification — POST /verify-confirm-assertion (per-node x-api-key). Fail-closed. */
  private async realKmsVerify(
    account: string,
    userOpHash: string,
    passkey: unknown
  ): Promise<boolean> {
    if (!this.kmsBaseUrl) {
      this.logger.error("Passkey confirm: KMS_BASE_URL not set — fail-closed");
      return false;
    }
    const res = await axios.post(
      `${this.kmsBaseUrl}/verify-confirm-assertion`,
      { account, userOpHash, passkey },
      { headers: { "x-api-key": this.kmsApiKey }, timeout: 8000 }
    );
    return res.data?.verified === true;
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
