/**
 * Wire constants for the gasless purchase relay (#98).
 *
 * Ported from the standalone Cloudflare Worker `mycelium/launch → services/relayer`
 * (v3 path only: EIP-3009 + EIP-712 BuyIntent → BuyHelper.executeBuy). The v1
 * (EIP-7702) and v2 paths are deprecated and intentionally NOT ported.
 *
 * Sepolia defaults are the Path-A canonical-bound sale stack (2026-06-21). All
 * are overridable via env so a community operator can point the relay at a
 * different sale deployment without a code change.
 */

/** EIP-712 typed-data field layout for BuyIntent — mirrors BuyHelper.sol. */
export const BUY_INTENT_TYPES = {
  BuyIntent: [
    { name: "buyer", type: "address" },
    { name: "paymentToken", type: "address" },
    { name: "paymentAmount", type: "uint256" },
    { name: "targetToken", type: "address" },
    { name: "recipient", type: "address" },
    { name: "minOut", type: "uint256" },
    { name: "deadline", type: "uint256" },
    { name: "nonce", type: "bytes32" },
  ],
} as const;

/** EIP-712 domain name/version for BuyHelper (chainId + verifyingContract are dynamic). */
export const BUY_INTENT_DOMAIN_NAME = "MyceliumBuyHelper";
export const BUY_INTENT_DOMAIN_VERSION = "1";

/**
 * Human-readable ABI for BuyHelper.executeBuy. ethers v6 parses the named tuple
 * components; args are passed positionally (see relay.service buildCallData).
 */
export const EXECUTE_BUY_FRAGMENT =
  "function executeBuy(" +
  "(address buyer,address paymentToken,uint256 paymentAmount,address targetToken," +
  "address recipient,uint256 minOut,uint256 deadline,bytes32 nonce) intent," +
  " bytes buyIntentSig," +
  " (uint256 validAfter,uint8 v,bytes32 r,bytes32 s) transferAuth)";

/** Sepolia Path-A canonical-bound stack; buyHelper = onlyRelayer redeploy 2026-06-23
 *  (MushroomDAO/launch#21 — whitelists the 3 DVT operators). Override via env in prod. */
export const SEPOLIA_DEFAULTS = {
  usdc: "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238",
  gtoken: "0x20a051502a7AE6e40cfFd6EBe59057538E698984",
  apnts: "0x9e66B457E0ABb1F139FD8A596d00f784eBA2873b",
  buyHelper: "0xF78f898413ef069C870A554f47B66eC6D9c5B429",
  chainId: 11155111,
} as const;

/** $864 in 6-decimal USDC — matches on-chain SaleContractV2.perPersonCapUSD. */
export const DEFAULT_MAX_PAYMENT_USDC_6DEC = "864000000";

/** Discriminated result of a relay attempt. */
export type RelayResult =
  | { ok: true; txHash: string; matchedRule: string }
  | { ok: false; code: RelayErrorCode; reason: string };

export type RelayErrorCode =
  | "INVALID_SHAPE"
  | "EXPIRED"
  | "SIGNATURE_INVALID"
  | "NOT_WHITELISTED"
  | "RATE_LIMITED"
  | "SUBMIT_FAILED"
  | "INFRA_NOT_READY";
