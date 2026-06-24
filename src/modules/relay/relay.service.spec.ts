import { ethers } from "ethers";
import { RelayService } from "./relay.service.js";
import { BUY_INTENT_TYPES } from "./relay.constants.js";

const CHAIN_ID = 11155111;
const BUY_HELPER = ethers.getAddress("0x" + "ab".repeat(20));
const USDC = ethers.getAddress("0x" + "11".repeat(20));
const GTOKEN = ethers.getAddress("0x" + "22".repeat(20));
const APNTS = ethers.getAddress("0x" + "33".repeat(20));
const RECIPIENT = ethers.getAddress("0x" + "44".repeat(20));
const NONCE = "0x" + "55".repeat(32);

// Fixed buyer so signatures are deterministic.
const buyer = new ethers.Wallet("0x" + "11".repeat(32));
const stranger = new ethers.Wallet("0x" + "22".repeat(32));

// Clock fixed at t = 1e12 ms → nowSec = 1e9 s. Deadlines below use 2e9 s (future).
const NOW_MS = 1_000_000_000_000;
const FUTURE_DEADLINE = 2_000_000_000;

const BASE_CONFIG: Record<string, unknown> = {
  relayEnabled: true,
  relayChainId: CHAIN_ID,
  relayBuyHelper: BUY_HELPER,
  relayUsdc: USDC,
  relayGtoken: GTOKEN,
  relayApnts: APNTS,
  relayMaxPaymentAmount: "864000000",
  relayRateLimitPerAddressPerHour: 2,
  relayRateLimitGlobalPerHour: 3,
};

function makeConfig(overrides: Record<string, unknown> = {}) {
  const cfg = { ...BASE_CONFIG, ...overrides };
  return { get: (k: string) => cfg[k] } as any;
}

function makeRegistry() {
  const registered: Array<{ name: string; enabled: boolean }> = [];
  return { registered, register: (cap: any) => registered.push(cap) } as any;
}

const DOMAIN = {
  name: "MyceliumBuyHelper",
  version: "1",
  chainId: CHAIN_ID,
  verifyingContract: BUY_HELPER,
};

async function signedBody(
  signer: ethers.Wallet = buyer,
  intentOverrides: Record<string, unknown> = {}
): Promise<any> {
  const intent = {
    buyer: buyer.address,
    paymentToken: USDC,
    paymentAmount: "1000000",
    targetToken: GTOKEN,
    recipient: RECIPIENT,
    minOut: "0",
    deadline: FUTURE_DEADLINE,
    nonce: NONCE,
    ...intentOverrides,
  };
  const message = {
    buyer: intent.buyer,
    paymentToken: intent.paymentToken,
    paymentAmount: BigInt(intent.paymentAmount as string),
    targetToken: intent.targetToken,
    recipient: intent.recipient,
    minOut: BigInt(intent.minOut as string),
    deadline: BigInt(intent.deadline as number),
    nonce: intent.nonce,
  };
  const buyIntentSig = await signer.signTypedData(DOMAIN, BUY_INTENT_TYPES as any, message);
  return {
    intent,
    buyIntentSig,
    transferAuth: { validAfter: 0, v: 27, r: "0x" + "00".repeat(32), s: "0x" + "00".repeat(32) },
  };
}

function makeService(overrides: Record<string, unknown> = {}) {
  return new RelayService(makeConfig(overrides), makeRegistry(), () => NOW_MS);
}

/** EXECUTE_BUY_FRAGMENT selector for executeBuy(...). */
const EXECUTE_BUY_SELECTOR = new ethers.Interface([
  "function executeBuy((address,address,uint256,address,address,uint256,uint256,bytes32),bytes,(uint256,uint8,bytes32,bytes32))",
]).getFunction("executeBuy")!.selector;

describe("RelayService", () => {
  it("registers capability reflecting RELAY_ENABLED", () => {
    const reg = makeRegistry();
    new RelayService(makeConfig({ relayEnabled: false }), reg, () => NOW_MS);
    expect(reg.registered).toEqual([expect.objectContaining({ name: "relay", enabled: false })]);
  });

  it("is disabled (no wallet) until bootstrap validates a key", () => {
    const svc = makeService();
    expect(svc.isEnabled()).toBe(false);
    expect(svc.operatorAddress()).toBeNull();
  });

  it("relay() returns INFRA_NOT_READY when the operator wallet is not live", async () => {
    const svc = makeService();
    const res = await svc.relay(await signedBody());
    expect(res).toEqual({ ok: false, code: "INFRA_NOT_READY", reason: expect.any(String) });
  });

  describe("validateAndBuild", () => {
    it("accepts a valid GToken purchase and encodes executeBuy", async () => {
      const svc = makeService();
      const res = svc.validateAndBuild(await signedBody());
      expect(res.ok).toBe(true);
      if (res.ok) {
        expect(res.matchedRule).toBe("TOKEN_BUY → GToken");
        expect(res.callData.startsWith(EXECUTE_BUY_SELECTOR)).toBe(true);
      }
    });

    it("accepts an aPNTs purchase", async () => {
      const svc = makeService();
      const res = svc.validateAndBuild(await signedBody(buyer, { targetToken: APNTS }));
      expect(res.ok).toBe(true);
      if (res.ok) expect(res.matchedRule).toBe("TOKEN_BUY → aPNTs");
    });

    it("rejects a non-whitelisted payment token", async () => {
      const svc = makeService();
      const body = await signedBody(buyer, {
        paymentToken: ethers.getAddress("0x" + "99".repeat(20)),
      });
      expect(svc.validateAndBuild(body)).toMatchObject({ ok: false, code: "NOT_WHITELISTED" });
    });

    it("rejects a non-whitelisted target token", async () => {
      const svc = makeService();
      const body = await signedBody(buyer, {
        targetToken: ethers.getAddress("0x" + "99".repeat(20)),
      });
      expect(svc.validateAndBuild(body)).toMatchObject({ ok: false, code: "NOT_WHITELISTED" });
    });

    it("rejects an expired deadline", async () => {
      const svc = makeService();
      const body = await signedBody(buyer, { deadline: 100 });
      expect(svc.validateAndBuild(body)).toMatchObject({ ok: false, code: "EXPIRED" });
    });

    it("rejects a zero payment amount", async () => {
      const svc = makeService();
      const body = await signedBody(buyer, { paymentAmount: "0" });
      expect(svc.validateAndBuild(body)).toMatchObject({ ok: false, code: "INVALID_SHAPE" });
    });

    it("rejects a payment over the per-tx cap", async () => {
      const svc = makeService();
      const body = await signedBody(buyer, { paymentAmount: "864000001" });
      expect(svc.validateAndBuild(body)).toMatchObject({ ok: false, code: "NOT_WHITELISTED" });
    });

    it("rejects a signature from a different signer", async () => {
      const svc = makeService();
      // stranger signs but intent.buyer stays buyer.address → recovered ≠ buyer.
      const body = await signedBody(stranger);
      expect(svc.validateAndBuild(body)).toMatchObject({ ok: false, code: "SIGNATURE_INVALID" });
    });
  });

  describe("rate limiting", () => {
    it("enforces the per-address hourly cap", async () => {
      const svc = makeService();
      // Inject a stub wallet (with a provider for the fee-bump) so relay()
      // proceeds past INFRA_NOT_READY.
      (svc as any).wallet = {
        address: buyer.address,
        provider: {
          getFeeData: async () => ({
            maxFeePerGas: 3_000_000_000n,
            maxPriorityFeePerGas: 2_000_000_000n,
          }),
        },
        sendTransaction: async () => ({ hash: "0xdead" }),
      };

      const r1 = await svc.relay(await signedBody());
      const r2 = await svc.relay(await signedBody());
      const r3 = await svc.relay(await signedBody());
      expect(r1.ok).toBe(true);
      expect(r2.ok).toBe(true);
      expect(r3).toMatchObject({ ok: false, code: "RATE_LIMITED" });
    });
  });
});
