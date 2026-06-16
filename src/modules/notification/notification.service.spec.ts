import { ethers } from "ethers";
import { NotificationService, Contact, NotificationChannel } from "./notification.service.js";
import type { PackedUserOp } from "../blockchain/blockchain.service.js";

const coder = new ethers.AbiCoder();
const ACCOUNT = "0x" + "ab".repeat(20);
const RECIPIENT = "0x" + "11".repeat(20);

function executeUserOp(valueWei: bigint): PackedUserOp {
  const sel = ethers.id("execute(address,uint256,bytes)").slice(0, 10);
  const callData =
    sel + coder.encode(["address", "uint256", "bytes"], [RECIPIENT, valueWei, "0x"]).slice(2);
  return {
    sender: ACCOUNT,
    nonce: "0",
    initCode: "0x",
    callData,
    accountGasLimits: "0x" + "00".repeat(32),
    preVerificationGas: "0",
    gasFees: "0x" + "00".repeat(32),
    paymasterAndData: "0x",
    signature: "0x",
  };
}

function make(
  config: Record<string, unknown>,
  channels?: NotificationChannel[],
  contacts?: Map<string, Contact>
): NotificationService {
  return new NotificationService({ get: (k: string) => config[k] } as any, channels, contacts);
}

const contactsOf = (c: Contact) => new Map([[ACCOUNT.toLowerCase(), c]]);

describe("NotificationService — large-spend notification (#52)", () => {
  it("no plan when disabled (default off)", () => {
    const svc = make({ notifyEnabled: false }, [], contactsOf({ telegramChatId: "1" }));
    expect(svc.plan(executeUserOp(10n ** 18n), "0xhash")).toBeNull();
  });

  it("no plan below threshold", () => {
    const svc = make(
      { notifyEnabled: true, notifyThresholdWei: "1000000000000000000" },
      [],
      contactsOf({ telegramChatId: "1" })
    );
    expect(svc.plan(executeUserOp(5n), "0xhash")).toBeNull();
  });

  it("plans a notification at/above threshold with a registered contact", () => {
    const svc = make(
      { notifyEnabled: true, notifyThresholdWei: "100" },
      [],
      contactsOf({ telegramChatId: "42" })
    );
    const plan = svc.plan(executeUserOp(101n), "0xhash");
    expect(plan).not.toBeNull();
    expect(plan!.contact.telegramChatId).toBe("42");
    expect(plan!.message).toMatch(/large operation/);
  });

  it("no plan when the account has no registered contact", () => {
    const svc = make({ notifyEnabled: true, notifyThresholdWei: "0" }, [], new Map());
    expect(svc.plan(executeUserOp(10n ** 18n), "0xhash")).toBeNull();
  });

  it("notifyLargeSpend dispatches to every channel and NEVER throws on channel failure", async () => {
    const calls: string[] = [];
    const okChannel: NotificationChannel = {
      name: "ok",
      send: async () => {
        calls.push("ok");
      },
    };
    const failChannel: NotificationChannel = {
      name: "fail",
      send: async () => {
        throw new Error("down");
      },
    };
    const svc = make(
      { notifyEnabled: true, notifyThresholdWei: "0" },
      [okChannel, failChannel],
      contactsOf({ telegramChatId: "1" })
    );
    expect(() => svc.notifyLargeSpend(executeUserOp(10n ** 18n), "0xhash")).not.toThrow();
    await new Promise(r => setTimeout(r, 5)); // let fire-and-forget settle
    expect(calls).toContain("ok"); // ok channel fired; fail channel's rejection swallowed
  });
});
