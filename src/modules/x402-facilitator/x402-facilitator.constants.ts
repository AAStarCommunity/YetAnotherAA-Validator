/**
 * Wire + on-chain constants for the optional x402 payment-facilitator module (#130).
 *
 * The DVT node runs the x402 facilitator the same way it runs `relay` (#98): an
 * opt-in HTTP service that holds a DEDICATED operator key and submits an on-chain
 * settlement on the payer's behalf. The HTTP envelope is the SDK's x402 v2
 * `FacilitatorClient` contract (`aastar-sdk/packages/x402/src/facilitator.ts`);
 * the SuperPaymaster-specific settlement fields (settlement scheme, maxFee, salt)
 * ride in `paymentRequirements.extra`, whose schema this module owns (see
 * docs/x402-facilitator.md).
 *
 * The verify/settle LOGIC is ported from the battle-tested reference service
 * `SuperPaymaster/packages/x402-facilitator-node` (4/4 E2E on Sepolia v5.4.1-rc.1),
 * rewritten from viem to ethers v6 to match this repo. The ABIs below are taken
 * from the AUTHORITATIVE contract source
 * `SuperPaymaster/contracts/src/paymasters/superpaymaster/v3/X402Facilitator.sol`
 * (NOT the stale `@aastar/core` ABI, which still carries the pre-v5.4 8-arg
 * `settleX402Payment` and an unsigned direct path — see aastar-sdk#39).
 */

import { ethers } from "ethers";

/**
 * Settlement schemes this facilitator can actually settle on-chain.
 *
 * This is the SuperPaymaster *settlement* axis (which contract call), distinct
 * from the x402 v2 *pricing* scheme (`exact`/`upto`) the SDK puts in
 * `paymentRequirements.scheme`. "permit2" was removed in the v5.4 god-split and
 * is rejected, exactly as the reference node does.
 */
export const SUPPORTED_SETTLEMENT_SCHEMES = ["direct", "eip-3009"] as const;
export type SettlementScheme = (typeof SUPPORTED_SETTLEMENT_SCHEMES)[number];

export function isSupportedSettlementScheme(scheme: string): scheme is SettlementScheme {
  return (SUPPORTED_SETTLEMENT_SCHEMES as readonly string[]).includes(scheme);
}

/**
 * The single shared scheme guard called by BOTH verify and settle so the two
 * paths can never diverge — the exact invariant Codex stop-review enforced on the
 * reference node (`lib/scheme.ts`): if verify accepts a scheme settle must too,
 * and vice-versa. Returns a human-readable rejection reason, or null when settleable.
 */
export function rejectUnsupportedScheme(scheme: string): string | null {
  if (isSupportedSettlementScheme(scheme)) return null;
  return `Unsupported settlement scheme: ${scheme}. Supported: ${SUPPORTED_SETTLEMENT_SCHEMES.join(", ")}`;
}

/**
 * Authoritative X402Facilitator ABI (human-readable, ethers v6). Mirrors the
 * deployed `X402Facilitator-1.0.0` (Sepolia 0xfe1DB01e…) function signatures:
 *
 *   settleX402Payment(from,to,asset,amount,maxFee,validAfter,validBefore,salt,sig)
 *     — EIP-3009 receiveWithAuthorization path; on-chain nonce = keccak256(to,maxFee,salt)
 *   settleX402PaymentDirect(from,to,asset,amount,maxFee,validBefore,nonce,sig)
 *     — xPNTs path; requires payer X402PaymentAuthorization signature (EOA or ERC-1271)
 *
 * Arg order is part of the contract signature: a transposed argument reverts (or
 * mis-settles). It is locked here and asserted in the settle-args unit test.
 */
export const X402_FACILITATOR_ABI = [
  "function settleX402Payment(address from,address to,address asset,uint256 amount,uint256 maxFee,uint256 validAfter,uint256 validBefore,bytes32 salt,bytes signature) returns (bytes32 settlementId)",
  "function settleX402PaymentDirect(address from,address to,address asset,uint256 amount,uint256 maxFee,uint256 validBefore,bytes32 nonce,bytes signature) returns (bytes32 settlementId)",
  "function x402SettlementNonces(bytes32) view returns (bool)",
  "function x402NonceKey(address asset,address from,bytes32 nonce) pure returns (bytes32)",
  "function facilitatorFeeBPS() view returns (uint256)",
  "function version() pure returns (string)",
] as const;

/** Minimal ERC-1271 ABI for the optional on-chain smart-account signature fallback in verify. */
export const ERC1271_ABI = [
  "function isValidSignature(bytes32 hash,bytes signature) view returns (bytes4)",
] as const;

/** EIP-1271 magic value returned by `isValidSignature` for a valid signature. */
export const ERC1271_MAGIC_VALUE = "0x1626ba7e";

/**
 * EIP-712 domain for the X402Facilitator contract (direct/xPNTs path).
 *
 * v5.4 god-split: the payer's `X402PaymentAuthorization` is recovered by
 * `X402Facilitator._x402DomainSeparator`, which uses name="X402Facilitator",
 * version="1", verifyingContract = the facilitator contract address. A wrong name
 * or verifyingContract makes every recovery yield the wrong signer → settle reverts.
 */
export function getX402FacilitatorDomain(
  chainId: number,
  facilitatorAddress: string
): ethers.TypedDataDomain {
  return { name: "X402Facilitator", version: "1", chainId, verifyingContract: facilitatorAddress };
}

/**
 * Matches X402Facilitator.X402_AUTH_TYPEHASH:
 * "X402PaymentAuthorization(address from,address to,address asset,uint256 amount,uint256 maxFee,uint256 validBefore,bytes32 nonce)"
 */
export const X402_AUTH_TYPES = {
  X402PaymentAuthorization: [
    { name: "from", type: "address" },
    { name: "to", type: "address" },
    { name: "asset", type: "address" },
    { name: "amount", type: "uint256" },
    { name: "maxFee", type: "uint256" },
    { name: "validBefore", type: "uint256" },
    { name: "nonce", type: "bytes32" },
  ],
} as const;

/**
 * EIP-3009 ReceiveWithAuthorization typed data (EIP-3009 path).
 *
 * The contract calls `receiveWithAuthorization` (NOT transfer-): the token forces
 * msg.sender == to (= the facilitator), closing the front-run nonce-burn grief
 * vector. The two EIP-3009 variants sign IDENTICAL fields under DIFFERENT typehash
 * strings, so the payer's signature only recovers `from` against this Receive
 * typehash; verifying against TransferWithAuthorization would reject every valid sig.
 */
export const RECEIVE_WITH_AUTH_TYPES = {
  ReceiveWithAuthorization: [
    { name: "from", type: "address" },
    { name: "to", type: "address" },
    { name: "value", type: "uint256" },
    { name: "validAfter", type: "uint256" },
    { name: "validBefore", type: "uint256" },
    { name: "nonce", type: "bytes32" },
  ],
} as const;

/** EIP-712 domain for an EIP-3009 token (e.g. USDC: name "USDC", version "2"). */
export function getEip3009TokenDomain(
  tokenName: string,
  tokenVersion: string,
  chainId: number,
  tokenAddress: string
): ethers.TypedDataDomain {
  return { name: tokenName, version: tokenVersion, chainId, verifyingContract: tokenAddress };
}

/**
 * Mirror X402Facilitator.x402NonceKey(asset, from, nonce):
 *   keccak256(abi.encode(address asset, address from, bytes32 nonce))
 *
 * The contract records spent settlement nonces at THIS triple key in
 * `x402SettlementNonces`, NOT at the raw nonce slot (the raw slot is only checked
 * for legacy pre-v5.4 entries). A replay check on the raw nonce always misses real
 * replays. Must stay byte-identical to Solidity `abi.encode(address,address,bytes32)`.
 */
export function computeX402NonceKey(asset: string, from: string, nonce: string): string {
  return ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["address", "address", "bytes32"],
      [asset, from, nonce]
    )
  );
}

/**
 * Mirror X402Facilitator.settleX402Payment's on-chain EIP-3009 nonce derivation:
 *   nonce = keccak256(abi.encode(address to, uint256 maxFee, bytes32 salt))
 *
 * C-03/M-1: the EIP-3009 path binds the FINAL recipient `to` AND the payer-approved
 * fee cap `maxFee` into the token-level nonce. The contract derives it from the
 * preimage `salt` and submits it to receiveWithAuthorization, so the payer's
 * EIP-3009 signature and the replay slot are BOTH keyed on this derived value, not
 * on the raw `salt`. verify MUST therefore check the signature + replay slot against
 * this derived nonce, exactly as the contract derives it.
 */
export function computeEip3009Nonce(to: string, maxFee: bigint, salt: string): string {
  return ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(["address", "uint256", "bytes32"], [to, maxFee, salt])
  );
}

/**
 * AAStar Sepolia defaults (v5.4.1-rc.1, per issue #130). All overridable via env so
 * a community operator can point the module at a different deployment without code
 * changes. The two default supported assets are xPNTs variants settled via the
 * `direct` scheme (the xPNTs factory auto-approves the facilitator at deploy).
 */
export const SEPOLIA_DEFAULTS = {
  chainId: 11155111,
  facilitatorContract: "0xfe1DB01e1d6622e722B92ed5993af61325DB92aF",
  apnts: "0x696A73701b104c6cCBbAadDD2216788ea08EaB89", // AAStar community
  pnts: "0xE6579A90dc498a710008de12119812D0FB7aA224", // Mycelium community
} as const;

/** CAIP-2 network id from a chain id (e.g. 11155111 → "eip155:11155111"). */
export function toNetworkId(chainId: number): string {
  return `eip155:${chainId}`;
}

/** Discriminated result of an off-chain verify. */
export type VerifyResult = { ok: true; payer: string } | { ok: false; reason: string };

/** Discriminated result of an on-chain settle attempt. */
export type SettleResult =
  | { ok: true; txHash: string; payer: string }
  | { ok: false; reason: string };
