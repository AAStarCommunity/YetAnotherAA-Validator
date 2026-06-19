import { Injectable, Logger, Optional } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { ethers } from "ethers";
import { existsSync, readFileSync } from "fs";
import { PackedUserOp } from "../blockchain/blockchain.service.js";
import { CapabilityRegistry } from "../capability/capability-registry.service.js";

/** Per-account contact targets (loaded from a git-ignored file, never committed). */
export interface Contact {
  telegramChatId?: string;
  email?: string;
  nostrPubkey?: string;
}

/** A delivery channel. Telegram ships first; email + Nostr are follow-ups (#52). */
export interface NotificationChannel {
  readonly name: string;
  send(contact: Contact, message: string): Promise<void>;
}

class TelegramChannel implements NotificationChannel {
  readonly name = "telegram";
  constructor(private readonly token: string) {}
  async send(contact: Contact, message: string): Promise<void> {
    if (!contact.telegramChatId) return;
    const r = await fetch(`https://api.telegram.org/bot${this.token}/sendMessage`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ chat_id: contact.telegramChatId, text: message }),
    });
    if (!r.ok) throw new Error(`telegram HTTP ${r.status}`);
  }
}

const EXECUTE_SELECTOR = ethers.id("execute(address,uint256,bytes)").slice(0, 10);
const ABI = new ethers.AbiCoder();

/**
 * Multi-channel user notification (#52). Increment 1: one-way "large spend" alert —
 * after the node co-signs a high-value op, tell the real user via channels an attacker
 * (even one holding the owner key) does not control, so anomalies are caught quickly.
 *
 * Hard rule: notification is **fire-and-forget and never throws / never blocks** — a
 * delivery failure must not affect signing. (Out-of-band CONFIRMATION — which DOES gate
 * signing, #50 ⑤ scheme A — is a separate follow-up that reuses these channels.)
 *
 * Opt-in via NOTIFY_ENABLED. Contacts load from NOTIFY_CONTACTS_FILE (git-ignored).
 */
@Injectable()
export class NotificationService {
  private readonly logger = new Logger(NotificationService.name);
  private readonly enabled: boolean;
  private readonly thresholdWei: bigint;
  private readonly channels: NotificationChannel[] = [];
  private readonly contacts = new Map<string, Contact>();

  constructor(
    configService: ConfigService,
    /** Test seam: inject channels/contacts; production builds them from config. */
    @Optional() channels?: NotificationChannel[],
    @Optional() contacts?: Map<string, Contact>,
    @Optional() capabilityRegistry?: CapabilityRegistry
  ) {
    this.enabled = configService.get<boolean>("notifyEnabled") === true;
    this.thresholdWei = BigInt(configService.get<string>("notifyThresholdWei") ?? "0");
    capabilityRegistry?.register({
      name: "notify",
      class: "infra-app",
      description: "Large-spend Telegram notification, fire-and-forget (#52)",
      enabled: this.enabled,
    });

    if (channels) {
      this.channels = channels;
    } else {
      const tgToken = configService.get<string>("telegramBotToken");
      if (tgToken) this.channels.push(new TelegramChannel(tgToken));
    }

    if (contacts) {
      this.contacts = contacts;
    } else {
      const file = configService.get<string>("notifyContactsFile");
      if (file && existsSync(file)) {
        try {
          const raw = JSON.parse(readFileSync(file, "utf8")) as Record<string, Contact>;
          for (const [acct, c] of Object.entries(raw)) this.contacts.set(acct.toLowerCase(), c);
        } catch (e: any) {
          this.logger.error(`failed to load notify contacts from ${file}: ${e?.message ?? e}`);
        }
      }
    }

    if (this.enabled) {
      this.logger.log(
        `Notifications ENABLED — channels=[${this.channels.map(c => c.name).join(",") || "none"}], ` +
          `contacts=${this.contacts.size}, threshold=${this.thresholdWei} wei`
      );
    }
  }

  /**
   * Fire a one-way large-spend notification. Returns immediately; deliveries run in the
   * background and any failure is swallowed (never affects the signing path).
   */
  notifyLargeSpend(userOp: PackedUserOp, userOpHash: string): void {
    try {
      const plan = this.plan(userOp, userOpHash);
      if (!plan) return;
      for (const ch of this.channels) {
        ch.send(plan.contact, plan.message).catch(e =>
          this.logger.warn(`notify ${ch.name} failed (ignored): ${e?.message ?? e}`)
        );
      }
    } catch (e: any) {
      this.logger.warn(`notifyLargeSpend error (ignored): ${e?.message ?? e}`);
    }
  }

  /** Whether an account has any registered out-of-band contact (used by confirmation). */
  hasContact(account: string): boolean {
    return this.contacts.has((account || "").toLowerCase());
  }

  /**
   * Send an arbitrary message to an account's contacts over EVERY channel. Used by the
   * out-of-band CONFIRMATION flow (which must know delivery succeeded). Returns true if
   * at least one channel delivered. Awaited (unlike the fire-and-forget notify path).
   */
  async sendToAccount(account: string, message: string): Promise<boolean> {
    const contact = this.contacts.get((account || "").toLowerCase());
    if (!contact || this.channels.length === 0) return false;
    const results = await Promise.allSettled(this.channels.map(ch => ch.send(contact, message)));
    return results.some(r => r.status === "fulfilled");
  }

  /**
   * Decide whether/what to notify. Returns null when disabled, below threshold, or no
   * contact. Pure (no I/O) — the testable core of notifyLargeSpend.
   */
  plan(userOp: PackedUserOp, userOpHash: string): { contact: Contact; message: string } | null {
    if (!this.enabled) return null;
    const amount = this.nativeValue(userOp);
    if (amount < this.thresholdWei) return null;
    const contact = this.contacts.get((userOp.sender || "").toLowerCase());
    if (!contact) return null;
    const message =
      `⚠️ DVT: account ${userOp.sender} just co-signed a large operation — ` +
      `${ethers.formatEther(amount)} ETH (userOpHash ${userOpHash}). ` +
      `If this wasn't you, freeze the account immediately.`;
    return { contact, message };
  }

  /** Native ETH value of an execute() call; 0 for non-execute / undecodable. */
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
