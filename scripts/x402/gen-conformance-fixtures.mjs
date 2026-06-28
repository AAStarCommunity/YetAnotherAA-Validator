/* eslint-env node */
/* global process */
// Generate deterministic x402 conformance fixtures (golden wire vectors).
//
// These are the cross-repo contract artifact for issue #130 / aastar-sdk#39: the
// EXACT wire `/x402/{verify,settle}` request bodies a conformant SDK
// `X402Client.createPayment` + `settleViaFacilitator` must emit, plus the values
// the DVT facilitator derives from them. The DVT consumes this file in
// `x402-conformance.spec.ts`; the SDK can load the same JSON to assert its own
// `createPayment` produces byte-identical envelopes (signatures included).
//
// Deterministic: fixed payer key + fixed params, NO Date.now()/random. Regenerate
// with:  node scripts/x402/gen-conformance-fixtures.mjs > conformance/x402/fixtures.json

import { ethers } from "ethers";
import { createHmac } from "crypto";

const CHAIN_ID = 11155111;
const FACILITATOR = ethers.getAddress("0x" + "fe".repeat(20));
const APNTS = ethers.getAddress("0x" + "a1".repeat(20)); // supported xPNTs → direct
const USDC = ethers.getAddress("0x" + "11".repeat(20)); // not supported → eip-3009
const PAY_TO = ethers.getAddress("0x" + "44".repeat(20));
const NONCE = "0x" + "55".repeat(32);
const VALID_BEFORE = 2_000_000_000; // fixed future (s); tests pin now below this
const VALID_AFTER_EIP3009 = 1_000_000_000;

const payer = new ethers.Wallet("0x" + "11".repeat(32));

const X402_AUTH_TYPES = {
  X402PaymentAuthorization: [
    { name: "from", type: "address" },
    { name: "to", type: "address" },
    { name: "asset", type: "address" },
    { name: "amount", type: "uint256" },
    { name: "maxFee", type: "uint256" },
    { name: "validBefore", type: "uint256" },
    { name: "nonce", type: "bytes32" },
  ],
};
const RECEIVE_WITH_AUTH_TYPES = {
  ReceiveWithAuthorization: [
    { name: "from", type: "address" },
    { name: "to", type: "address" },
    { name: "value", type: "uint256" },
    { name: "validAfter", type: "uint256" },
    { name: "validBefore", type: "uint256" },
    { name: "nonce", type: "bytes32" },
  ],
};

function deriveEip3009Nonce(payTo, maxFee, salt) {
  return ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["address", "uint256", "bytes32"],
      [payTo, maxFee, salt]
    )
  );
}

async function directVector() {
  const amount = 1_000_000n;
  const maxFee = amount;
  const signature = await payer.signTypedData(
    { name: "X402Facilitator", version: "1", chainId: CHAIN_ID, verifyingContract: FACILITATOR },
    X402_AUTH_TYPES,
    {
      from: payer.address,
      to: PAY_TO,
      asset: APNTS,
      amount,
      maxFee,
      validBefore: BigInt(VALID_BEFORE),
      nonce: NONCE,
    }
  );
  const accepted = {
    scheme: "exact",
    network: `eip155:${CHAIN_ID}`,
    asset: APNTS,
    amount: amount.toString(),
    payTo: PAY_TO,
    maxTimeoutSeconds: 3600,
    extra: { name: "aPNTs", version: "1", settlement: "direct", maxFee: maxFee.toString() },
  };
  const body = {
    x402Version: 2,
    paymentPayload: {
      x402Version: 2,
      accepted,
      payload: {
        signature,
        authorization: {
          from: payer.address,
          to: PAY_TO,
          value: amount.toString(),
          validAfter: "0",
          validBefore: VALID_BEFORE.toString(),
          nonce: NONCE,
        },
      },
    },
    paymentRequirements: accepted, // SDK #218 mergeRequirements default = payload.accepted
  };
  return {
    name: "direct-xpnts",
    description: "xPNTs direct settlement — payer signs X402PaymentAuthorization",
    body,
    expect: {
      scheme: "direct",
      payer: payer.address,
      effectiveNonce: NONCE,
      settle: {
        method: "settleX402PaymentDirect",
        args: [
          payer.address,
          PAY_TO,
          APNTS,
          amount.toString(),
          maxFee.toString(),
          VALID_BEFORE.toString(),
          NONCE,
          signature,
        ],
      },
    },
  };
}

async function eip3009Vector() {
  const amount = 2_000_000n;
  const maxFee = amount;
  const salt = NONCE;
  const derivedNonce = deriveEip3009Nonce(PAY_TO, maxFee, salt);
  const signature = await payer.signTypedData(
    { name: "USDC", version: "2", chainId: CHAIN_ID, verifyingContract: USDC },
    RECEIVE_WITH_AUTH_TYPES,
    {
      from: payer.address,
      to: FACILITATOR,
      value: amount,
      validAfter: BigInt(VALID_AFTER_EIP3009),
      validBefore: BigInt(VALID_BEFORE),
      nonce: derivedNonce,
    }
  );
  const accepted = {
    scheme: "exact",
    network: `eip155:${CHAIN_ID}`,
    asset: USDC,
    amount: amount.toString(),
    payTo: PAY_TO,
    maxTimeoutSeconds: 3600,
    extra: { name: "USDC", version: "2", settlement: "eip-3009", maxFee: maxFee.toString(), salt },
  };
  const body = {
    x402Version: 2,
    paymentPayload: {
      x402Version: 2,
      accepted,
      payload: {
        signature,
        authorization: {
          from: payer.address,
          to: FACILITATOR,
          value: amount.toString(),
          validAfter: VALID_AFTER_EIP3009.toString(),
          validBefore: VALID_BEFORE.toString(),
          nonce: derivedNonce,
        },
      },
    },
    paymentRequirements: accepted,
  };
  return {
    name: "eip3009-usdc",
    description:
      "USDC EIP-3009 settlement — payer signs ReceiveWithAuthorization over the recipient-bound derived nonce",
    body,
    expect: {
      scheme: "eip-3009",
      payer: payer.address,
      effectiveNonce: derivedNonce,
      settle: {
        method: "settleX402Payment",
        args: [
          payer.address,
          PAY_TO,
          USDC,
          amount.toString(),
          maxFee.toString(),
          VALID_AFTER_EIP3009.toString(),
          VALID_BEFORE.toString(),
          salt,
          signature,
        ],
      },
    },
  };
}

function authHeaderVector() {
  // Reference vector for the optional X402AuthGuard / SDK createAuthHeaders scheme:
  // X-X402-Auth = HMAC-SHA256(secret, `${ts}.${rawBody}`).
  const secret = "conformance-secret";
  const timestampMs = 1_500_000_000_000;
  const rawBody = '{"hello":"x402"}';
  const auth = createHmac("sha256", secret).update(`${timestampMs}.${rawBody}`).digest("hex");
  return {
    secret,
    rawBody,
    headers: { "X-X402-Timestamp": String(timestampMs), "X-X402-Auth": auth },
  };
}

const fixtures = {
  note: "Golden x402 wire conformance vectors (#130 / aastar-sdk#39). Regenerate via scripts/x402/gen-conformance-fixtures.mjs.",
  config: {
    chainId: CHAIN_ID,
    facilitatorContract: FACILITATOR,
    supportedAssets: [APNTS.toLowerCase()],
    nowSecForVerify: 1_500_000_000,
  },
  vectors: [await directVector(), await eip3009Vector()],
  authHeader: authHeaderVector(),
};

process.stdout.write(JSON.stringify(fixtures, null, 2) + "\n");
