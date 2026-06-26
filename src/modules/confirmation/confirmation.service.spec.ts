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

/** Build a service with an injected KMS verifier (path-2 test seam). */
function makeKms(config: Record<string, unknown>, n: any, kmsVerify: any): ConfirmationService {
  return new ConfirmationService({ get: (k: string) => config[k] } as any, n, undefined, kmsVerify);
}

const HASH = "0x" + "cd".repeat(32);

/** base64url of a hex string's bytes. */
function challengeOf(hash: string): string {
  return Buffer.from(hash.replace(/^0x/, ""), "hex").toString("base64url");
}
/** A raw AuthenticationResponseJSON whose clientDataJSON binds `challengeB64`. */
function passkeyWithChallenge(challengeB64: string): unknown {
  const clientDataJSON = Buffer.from(
    JSON.stringify({ type: "webauthn.get", challenge: challengeB64, origin: "https://kms.aastar.io" })
  ).toString("base64url");
  return {
    id: "cred",
    rawId: "cred",
    type: "public-key",
    response: { authenticatorData: "AAAA", clientDataJSON, signature: "BBBB" },
  };
}

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

  it("getStatus: not_found before any gate, pending after, approved after confirm (read-only)", async () => {
    const n = notif(true);
    const svc = make({ confirmEnabled: true, confirmThresholdWei: "100" }, n);
    expect(svc.getStatus(HASH)).toEqual({ status: "not_found", expiresAt: null });

    await svc.gate(executeUserOp(101n), HASH);
    const pend = svc.getStatus(HASH);
    expect(pend.status).toBe("pending");
    expect(typeof pend.expiresAt).toBe("number");

    const token = n.sent[0].match(/Confirm token: (0x[0-9a-f]+)/)![1];
    svc.confirm(HASH, token);
    expect(svc.getStatus(HASH).status).toBe("approved");
    // read-only: polling didn't consume it — the gate still releases it
    expect(await svc.gate(executeUserOp(101n), HASH)).toBe("confirmed");
  });

  it("confirmWithPasskey: valid binding + KMS verified → confirmed, account passed, gate releases", async () => {
    const calls: Array<{ a: string; u: string }> = [];
    const svc = makeKms(
      { confirmEnabled: true, confirmThresholdWei: "100" },
      notif(true),
      async (a: string, u: string) => {
        calls.push({ a, u });
        return true;
      }
    );
    await svc.gate(executeUserOp(101n), HASH);
    expect(await svc.confirmWithPasskey(HASH, passkeyWithChallenge(challengeOf(HASH)))).toBe(true);
    expect(calls[0]).toEqual({ a: ACCOUNT, u: HASH }); // account (userOp.sender) forwarded to KMS
    expect(await svc.gate(executeUserOp(101n), HASH)).toBe("confirmed");
  });

  it("confirmWithPasskey: challenge ≠ userOpHash → rejected, KMS NOT called", async () => {
    let called = false;
    const svc = makeKms({ confirmEnabled: true, confirmThresholdWei: "100" }, notif(true), async () => {
      called = true;
      return true;
    });
    await svc.gate(executeUserOp(101n), HASH);
    // assertion bound to a different hash → local binding check fails first
    expect(
      await svc.confirmWithPasskey(HASH, passkeyWithChallenge(challengeOf("0x" + "00".repeat(32))))
    ).toBe(false);
    expect(called).toBe(false);
  });

  it("confirmWithPasskey: binding ok but KMS verified:false → rejected (fail-closed)", async () => {
    const svc = makeKms(
      { confirmEnabled: true, confirmThresholdWei: "100" },
      notif(true),
      async () => false
    );
    await svc.gate(executeUserOp(101n), HASH);
    expect(await svc.confirmWithPasskey(HASH, passkeyWithChallenge(challengeOf(HASH)))).toBe(false);
  });

  it("confirmWithPasskey: KMS throws → rejected (fail-closed)", async () => {
    const svc = makeKms({ confirmEnabled: true, confirmThresholdWei: "100" }, notif(true), async () => {
      throw new Error("kms down");
    });
    await svc.gate(executeUserOp(101n), HASH);
    expect(await svc.confirmWithPasskey(HASH, passkeyWithChallenge(challengeOf(HASH)))).toBe(false);
  });

  it("confirmWithPasskey: no pending entry → false", async () => {
    const svc = makeKms({ confirmEnabled: true, confirmThresholdWei: "100" }, notif(true), async () => true);
    expect(await svc.confirmWithPasskey(HASH, passkeyWithChallenge(challengeOf(HASH)))).toBe(false);
  });

  it("getStatus: expired once TTL elapsed (ttl=0)", async () => {
    const n = notif(true);
    const svc = make({ confirmEnabled: true, confirmThresholdWei: "100", confirmTtlMs: 0 }, n);
    await svc.gate(executeUserOp(101n), HASH);
    expect(svc.getStatus(HASH).status).toBe("expired");
  });

  it("expires a pending confirmation (ttl=0)", async () => {
    const n = notif(true);
    const svc = make({ confirmEnabled: true, confirmThresholdWei: "100", confirmTtlMs: 0 }, n);
    await svc.gate(executeUserOp(101n), HASH);
    const token = n.sent[0].match(/Confirm token: (0x[0-9a-f]+)/)![1];
    expect(svc.confirm(HASH, token)).toBe(false); // already expired
  });
});
