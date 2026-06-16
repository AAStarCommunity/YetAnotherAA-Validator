import { ethers } from "ethers";
import { ConfirmationService } from "./confirmation.service.js";
import type { PackedUserOp } from "../blockchain/blockchain.service.js";

const coder = new ethers.AbiCoder();
const ACCOUNT = "0x" + "ab".repeat(20);

function executeUserOp(valueWei: bigint): PackedUserOp {
  const sel = ethers.id("execute(address,uint256,bytes)").slice(0, 10);
  const callData =
    sel +
    coder
      .encode(["address", "uint256", "bytes"], ["0x" + "11".repeat(20), valueWei, "0x"])
      .slice(2);
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

/** NotificationService stub: hasContact toggle + sendToAccount capturing the token msg. */
function notif(hasContact: boolean, deliver = true) {
  const sent: string[] = [];
  return {
    sent,
    hasContact: () => hasContact,
    sendToAccount: async (_a: string, msg: string) => {
      sent.push(msg);
      return deliver;
    },
  } as any;
}

function make(config: Record<string, unknown>, n: any): ConfirmationService {
  return new ConfirmationService({ get: (k: string) => config[k] } as any, n);
}

const HASH = "0x" + "cd".repeat(32);

describe("ConfirmationService — out-of-band confirmation (scheme A, #50 ⑤)", () => {
  it("not_required when disabled", async () => {
    const svc = make({ confirmEnabled: false }, notif(true));
    expect(await svc.gate(executeUserOp(10n ** 18n), HASH)).toBe("not_required");
  });

  it("not_required below threshold", async () => {
    const svc = make(
      { confirmEnabled: true, confirmThresholdWei: "1000000000000000000" },
      notif(true)
    );
    expect(await svc.gate(executeUserOp(5n), HASH)).toBe("not_required");
  });

  it("undeliverable (fail-closed) when high-value but no contact", async () => {
    const svc = make({ confirmEnabled: true, confirmThresholdWei: "100" }, notif(false));
    expect(await svc.gate(executeUserOp(101n), HASH)).toBe("undeliverable");
  });

  it("undeliverable when contact exists but delivery fails", async () => {
    const svc = make({ confirmEnabled: true, confirmThresholdWei: "100" }, notif(true, false));
    expect(await svc.gate(executeUserOp(101n), HASH)).toBe("undeliverable");
  });

  it("pending on first high-value request and sends a token out-of-band", async () => {
    const n = notif(true);
    const svc = make({ confirmEnabled: true, confirmThresholdWei: "100" }, n);
    expect(await svc.gate(executeUserOp(101n), HASH)).toBe("pending");
    expect(n.sent.length).toBe(1);
    expect(n.sent[0]).toMatch(/Confirm token: 0x[0-9a-f]+/);
  });

  it("confirmed after the user approves with the correct token (single-use)", async () => {
    const n = notif(true);
    const svc = make({ confirmEnabled: true, confirmThresholdWei: "100" }, n);
    await svc.gate(executeUserOp(101n), HASH);
    const token = n.sent[0].match(/Confirm token: (0x[0-9a-f]+)/)![1];
    expect(svc.confirm(HASH, token)).toBe(true);
    expect(await svc.gate(executeUserOp(101n), HASH)).toBe("confirmed");
    // single-use: a fresh gate after consumption is pending again
    expect(await svc.gate(executeUserOp(101n), HASH)).toBe("pending");
  });

  it("rejects a wrong token", async () => {
    const n = notif(true);
    const svc = make({ confirmEnabled: true, confirmThresholdWei: "100" }, n);
    await svc.gate(executeUserOp(101n), HASH);
    expect(svc.confirm(HASH, "0xwrong")).toBe(false);
    expect(await svc.gate(executeUserOp(101n), HASH)).toBe("pending");
  });

  it("expires a pending confirmation (ttl=0)", async () => {
    const n = notif(true);
    const svc = make({ confirmEnabled: true, confirmThresholdWei: "100", confirmTtlMs: 0 }, n);
    await svc.gate(executeUserOp(101n), HASH);
    const token = n.sent[0].match(/Confirm token: (0x[0-9a-f]+)/)![1];
    expect(svc.confirm(HASH, token)).toBe(false); // already expired
  });
});
