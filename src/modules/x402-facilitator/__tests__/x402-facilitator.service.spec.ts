import { ethers } from "ethers";
import { X402FacilitatorService } from "../x402-facilitator.service.js";
import {
  X402_AUTH_TYPES,
  RECEIVE_WITH_AUTH_TYPES,
  getX402FacilitatorDomain,
  getEip3009TokenDomain,
  computeEip3009Nonce,
  rejectUnsupportedScheme,
} from "../x402-facilitator.constants.js";

const CHAIN_ID = 11155111;
const FACILITATOR = ethers.getAddress("0x" + "fe".repeat(20));
const APNTS = ethers.getAddress("0x" + "a1".repeat(20)); // a supported xPNTs (direct)
const USDC = ethers.getAddress("0x" + "11".repeat(20)); // not supported → eip-3009
const PAY_TO = ethers.getAddress("0x" + "44".repeat(20));
const NONCE = "0x" + "55".repeat(32);

// TEST-ONLY deterministic keys (all-0x11 / all-0x22). They never hold funds —
// they exist only to produce reproducible signatures in these unit tests.
const payer = new ethers.Wallet("0x" + "11".repeat(32));
const stranger = new ethers.Wallet("0x" + "22".repeat(32));

const NOW_MS = 1_000_000_000_000; // nowSec = 1e9
const NOW_SEC = 1_000_000_000;
const FUTURE = NOW_SEC + 3600;

const BASE_CONFIG: Record<string, unknown> = {
  x402FacilitatorEnabled: false, // pure-method tests don't need a live wallet
  x402ChainId: CHAIN_ID,
  x402FacilitatorContract: FACILITATOR,
  x402SupportedAssets: [APNTS.toLowerCase()],
  x402FeeBPS: 200,
};

function makeConfig(overrides: Record<string, unknown> = {}) {
  const cfg = { ...BASE_CONFIG, ...overrides };
  return { get: (k: string) => cfg[k] } as any;
}

function makeRegistry() {
  const registered: Array<{ name: string; enabled: boolean }> = [];
  return { registered, register: (cap: any) => registered.push(cap) } as any;
}

function makeService(configOverrides: Record<string, unknown> = {}) {
  return new X402FacilitatorService(makeConfig(configOverrides), makeRegistry(), () => NOW_MS);
}

/** Build the SDK x402 v2 envelope for a direct (xPNTs) payment, signed by `signer`. */
async function directEnvelope(
  signer: ethers.Wallet = payer,
  overrides: { amount?: bigint; maxFee?: bigint; nonce?: string; validBefore?: number } = {}
) {
  const amount = overrides.amount ?? 1_000_000n;
  const maxFee = overrides.maxFee ?? amount;
  const nonce = overrides.nonce ?? NONCE;
  const validBefore = overrides.validBefore ?? FUTURE;
  const domain = getX402FacilitatorDomain(CHAIN_ID, FACILITATOR);
  const message = {
    from: payer.address,
    to: PAY_TO,
    asset: APNTS,
    amount,
    maxFee,
    validBefore: BigInt(validBefore),
    nonce,
  };
  const signature = await signer.signTypedData(domain, X402_AUTH_TYPES as any, message);
  return {
    x402Version: 2,
    paymentPayload: {
      x402Version: 2,
      payload: {
        signature,
        authorization: {
          from: payer.address,
          to: PAY_TO,
          value: amount.toString(),
          validAfter: "0",
          validBefore: validBefore.toString(),
          nonce,
        },
      },
    },
    paymentRequirements: {
      scheme: "exact",
      network: `eip155:${CHAIN_ID}`,
      asset: APNTS,
      amount: amount.toString(),
      payTo: PAY_TO,
      maxTimeoutSeconds: 3600,
      extra: { settlement: "direct", maxFee: maxFee.toString() },
    },
  };
}

/** Build the SDK envelope for an EIP-3009 (USDC) payment, signed over the derived nonce. */
async function eip3009Envelope(
  signer: ethers.Wallet = payer,
  overrides: {
    amount?: bigint;
    maxFee?: bigint;
    salt?: string;
    validBefore?: number;
    validAfter?: number;
  } = {}
) {
  const amount = overrides.amount ?? 2_000_000n;
  const maxFee = overrides.maxFee ?? amount;
  const salt = overrides.salt ?? NONCE;
  const validBefore = overrides.validBefore ?? FUTURE;
  const validAfter = overrides.validAfter ?? 0;
  const effectiveNonce = computeEip3009Nonce(PAY_TO, maxFee, salt);
  const domain = getEip3009TokenDomain("USDC", "2", CHAIN_ID, USDC);
  const message = {
    from: payer.address,
    to: FACILITATOR, // EIP-3009 recipient is the facilitator contract
    value: amount,
    validAfter: BigInt(validAfter),
    validBefore: BigInt(validBefore),
    nonce: effectiveNonce,
  };
  const signature = await signer.signTypedData(domain, RECEIVE_WITH_AUTH_TYPES as any, message);
  return {
    x402Version: 2,
    paymentPayload: {
      x402Version: 2,
      payload: {
        signature,
        authorization: {
          from: payer.address,
          to: PAY_TO,
          value: amount.toString(),
          validAfter: validAfter.toString(),
          validBefore: validBefore.toString(),
          nonce: salt,
        },
      },
    },
    paymentRequirements: {
      scheme: "exact",
      network: `eip155:${CHAIN_ID}`,
      asset: USDC,
      amount: amount.toString(),
      payTo: PAY_TO,
      maxTimeoutSeconds: 3600,
      extra: {
        settlement: "eip-3009",
        maxFee: maxFee.toString(),
        salt,
        name: "USDC",
        version: "2",
      },
    },
  };
}

describe("X402FacilitatorService", () => {
  describe("capability registration", () => {
    it("registers x402-facilitator reflecting the enabled flag", () => {
      const reg = makeRegistry();
      new X402FacilitatorService(makeConfig({ x402FacilitatorEnabled: true }), reg, () => NOW_MS);
      expect(reg.registered).toHaveLength(1);
      expect(reg.registered[0]).toMatchObject({ name: "x402-facilitator", enabled: true });
    });
  });

  describe("resolveScheme", () => {
    const svc = makeService();
    it("settles a provisioned xPNTs asset via direct", () => {
      expect(svc.resolveScheme(APNTS)).toBe("direct");
      expect(svc.resolveScheme(APNTS.toLowerCase())).toBe("direct");
    });
    it("settles an unknown asset via eip-3009", () => {
      expect(svc.resolveScheme(USDC)).toBe("eip-3009");
    });
    it("honors an explicit extra.settlement override", () => {
      expect(svc.resolveScheme(USDC, "direct")).toBe("direct");
    });
  });

  describe("rejectUnsupportedScheme (shared guard)", () => {
    it("accepts direct + eip-3009, rejects permit2/unknown", () => {
      expect(rejectUnsupportedScheme("direct")).toBeNull();
      expect(rejectUnsupportedScheme("eip-3009")).toBeNull();
      expect(rejectUnsupportedScheme("permit2")).toMatch(/Unsupported/);
      expect(rejectUnsupportedScheme("bogus")).toMatch(/Unsupported/);
    });
  });

  describe("normalize", () => {
    const svc = makeService();

    it("normalizes a direct envelope", async () => {
      const dto = await directEnvelope();
      const r = svc.normalize(dto as any);
      expect(r.ok).toBe(true);
      if (!r.ok) return;
      expect(r.payment).toMatchObject({
        scheme: "direct",
        from: payer.address,
        to: PAY_TO,
        asset: APNTS,
        amount: 1_000_000n,
        maxFee: 1_000_000n,
        nonce: NONCE,
      });
    });

    it("auto-detects eip-3009 when extra.settlement is absent (asset not provisioned)", async () => {
      const dto = await eip3009Envelope();
      delete (dto.paymentRequirements.extra as any).settlement;
      const r = svc.normalize(dto as any);
      expect(r.ok).toBe(true);
      if (!r.ok) return;
      expect(r.payment.scheme).toBe("eip-3009");
    });

    it("rejects a permit2 settlement via the shared guard", async () => {
      const dto = await directEnvelope();
      (dto.paymentRequirements.extra as any).settlement = "permit2";
      const r = svc.normalize(dto as any);
      expect(r.ok).toBe(false);
      if (r.ok) return;
      expect(r.reason).toMatch(/Unsupported settlement scheme/);
    });

    it("rejects a network mismatch", async () => {
      const dto = await directEnvelope();
      dto.paymentRequirements.network = "eip155:1";
      const r = svc.normalize(dto as any);
      expect(r.ok).toBe(false);
    });

    it("rejects a non-exact x402 pricing scheme", async () => {
      const dto = await directEnvelope();
      dto.paymentRequirements.scheme = "upto";
      const r = svc.normalize(dto as any);
      expect(r.ok).toBe(false);
    });

    it("rejects a malformed nonce / address / amount", async () => {
      const bad1 = await directEnvelope();
      (bad1.paymentPayload.payload.authorization as any).nonce = "0xdeadbeef";
      expect(svc.normalize(bad1 as any).ok).toBe(false);

      const bad2 = await directEnvelope();
      bad2.paymentRequirements.asset = "not-an-address";
      expect(svc.normalize(bad2 as any).ok).toBe(false);

      const bad3 = await directEnvelope();
      bad3.paymentRequirements.amount = "12.5";
      expect(svc.normalize(bad3 as any).ok).toBe(false);
    });

    it("rejects a missing paymentPayload", () => {
      expect(svc.normalize({ paymentRequirements: {} } as any).ok).toBe(false);
    });

    it("rejects a non-v2 x402Version (top level or embedded)", async () => {
      const bad1 = await directEnvelope();
      bad1.x402Version = 1;
      expect(svc.normalize(bad1 as any).ok).toBe(false);

      const bad2 = await directEnvelope();
      (bad2.paymentPayload as any).x402Version = 3;
      expect(svc.normalize(bad2 as any).ok).toBe(false);
    });

    it("rejects a present-but-malformed extra.salt instead of silently falling back", async () => {
      const dto = await eip3009Envelope();
      (dto.paymentRequirements.extra as any).salt = "0xnothex";
      const r = svc.normalize(dto as any);
      expect(r.ok).toBe(false);
      if (r.ok) return;
      expect(r.reason).toMatch(/salt/);
    });
  });

  describe("effectiveNonce", () => {
    const svc = makeService();
    it("uses the raw nonce for direct", async () => {
      const r = svc.normalize((await directEnvelope()) as any);
      if (!r.ok) throw new Error("normalize failed");
      expect(svc.effectiveNonce(r.payment)).toBe(NONCE);
    });
    it("derives keccak256(to, maxFee, salt) for eip-3009", async () => {
      const r = svc.normalize((await eip3009Envelope()) as any);
      if (!r.ok) throw new Error("normalize failed");
      expect(svc.effectiveNonce(r.payment)).toBe(computeEip3009Nonce(PAY_TO, 2_000_000n, NONCE));
    });
  });

  describe("buildSettleCall (on-chain arg order)", () => {
    const svc = makeService();

    it("direct → settleX402PaymentDirect(from,to,asset,amount,maxFee,validBefore,nonce,sig)", async () => {
      const r = svc.normalize((await directEnvelope()) as any);
      if (!r.ok) throw new Error("normalize failed");
      const call = svc.buildSettleCall(r.payment);
      expect(call.method).toBe("settleX402PaymentDirect");
      expect(call.args).toEqual([
        payer.address,
        PAY_TO,
        APNTS,
        1_000_000n,
        1_000_000n,
        BigInt(FUTURE),
        NONCE,
        r.payment.signature,
      ]);
    });

    it("eip-3009 → settleX402Payment(from,to,asset,amount,maxFee,validAfter,validBefore,salt,sig)", async () => {
      const r = svc.normalize((await eip3009Envelope()) as any);
      if (!r.ok) throw new Error("normalize failed");
      const call = svc.buildSettleCall(r.payment);
      expect(call.method).toBe("settleX402Payment");
      expect(call.args).toEqual([
        payer.address,
        PAY_TO,
        USDC,
        2_000_000n,
        2_000_000n,
        0n,
        BigInt(FUTURE),
        NONCE, // salt
        r.payment.signature,
      ]);
    });
  });

  describe("verifySignatureOffChain (EOA recovery)", () => {
    const svc = makeService();

    it("accepts a valid direct X402PaymentAuthorization signature", async () => {
      const r = svc.normalize((await directEnvelope()) as any);
      if (!r.ok) throw new Error("normalize failed");
      const v = await svc.verifySignatureOffChain(r.payment);
      expect(v).toEqual({ ok: true, payer: payer.address });
    });

    it("rejects a direct signature from the wrong signer", async () => {
      const r = svc.normalize((await directEnvelope(stranger)) as any);
      if (!r.ok) throw new Error("normalize failed");
      const v = await svc.verifySignatureOffChain(r.payment);
      expect(v.ok).toBe(false);
    });

    it("rejects a direct payment whose amount was tampered after signing", async () => {
      const dto = await directEnvelope();
      // Bump amount in BOTH the requirements and authorization so it normalizes,
      // but the signature was over the original amount → recovery mismatches.
      dto.paymentRequirements.amount = "999999999";
      (dto.paymentPayload.payload.authorization as any).value = "999999999";
      const r = svc.normalize(dto as any);
      if (!r.ok) throw new Error("normalize failed");
      const v = await svc.verifySignatureOffChain(r.payment);
      expect(v.ok).toBe(false);
    });

    it("rejects an expired direct authorization", async () => {
      const r = svc.normalize((await directEnvelope(payer, { validBefore: NOW_SEC - 1 })) as any);
      if (!r.ok) throw new Error("normalize failed");
      const v = await svc.verifySignatureOffChain(r.payment);
      expect(v.ok).toBe(false);
      if (v.ok) return;
      expect(v.reason).toMatch(/expired/i);
    });

    it("accepts a valid eip-3009 ReceiveWithAuthorization signature", async () => {
      const r = svc.normalize((await eip3009Envelope()) as any);
      if (!r.ok) throw new Error("normalize failed");
      const v = await svc.verifySignatureOffChain(r.payment);
      expect(v).toEqual({ ok: true, payer: payer.address });
    });

    it("rejects an expired eip-3009 payment", async () => {
      const r = svc.normalize((await eip3009Envelope(payer, { validBefore: NOW_SEC - 1 })) as any);
      if (!r.ok) throw new Error("normalize failed");
      const v = await svc.verifySignatureOffChain(r.payment);
      expect(v.ok).toBe(false);
    });
  });

  describe("disabled node", () => {
    it("verify/settle short-circuit when not enabled", async () => {
      const svc = makeService();
      expect(svc.isEnabled()).toBe(false);
      const dto = await directEnvelope();
      expect((await svc.verify(dto as any)).ok).toBe(false);
      expect((await svc.settle(dto as any)).ok).toBe(false);
    });
  });
});
