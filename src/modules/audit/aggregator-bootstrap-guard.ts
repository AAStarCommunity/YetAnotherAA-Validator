/**
 * Shared fail-closed policy for the SP BLS aggregator address, used by BOTH audit consumers
 * (the offline-audit rule in `audit.service.ts` and the CC-89 guardian-slash watcher). Centralizing
 * it here prevents the two bootstraps from drifting (Codex CC-89 round-2: the watcher originally had
 * no chain guard at all while the offline rule did).
 *
 * The built-in `auditBlsAggregatorAddress` default in `configuration.ts` is a Sepolia PRODUCTION
 * address. Two silent-inheritance footguns it must never enable:
 *   1. wrong chain — the RPC actually points at a chain other than AUDIT_CHAIN_ID; the default (or
 *      any Sepolia address) is then garbage.
 *   2. off-Sepolia default — even when the RPC matches AUDIT_CHAIN_ID, if that chain is NOT Sepolia
 *      and the operator never explicitly set AUDIT_BLS_AGGREGATOR_ADDRESS, they are unknowingly
 *      polling a Sepolia address on a non-Sepolia chain. `getCode != 0x` cannot catch this (a
 *      wrong-but-deployed address passes it); requiring an explicit env value does.
 */
export const SEPOLIA_CHAIN_ID = 11155111;

export interface AggregatorChainPolicyInput {
  /** AUDIT_CHAIN_ID (the chain the audit is configured for). */
  expectedChainId: number;
  /** The RPC provider's actual chainId (from getNetwork). */
  providerChainId: number;
  /** Whether AUDIT_BLS_AGGREGATOR_ADDRESS was set explicitly in the env (NOT the resolved value —
   *  the resolved value always carries the built-in default, which masks the unset case). */
  aggregatorFromEnv: boolean;
  /** Whether this consumer actually uses the aggregator (offline-audit rule / guardian watcher). The
   *  chain-mismatch guard applies regardless (all default addresses are Sepolia); the
   *  off-Sepolia-explicit guard only when the aggregator is genuinely consumed. */
  aggregatorRequired: boolean;
}

/** Pure fail-closed policy check. Returns `{ ok: false, reason }` when the audit/watcher must
 *  refuse to start rather than trust a possibly-wrong-chain aggregator address. */
export function checkAggregatorChainPolicy(input: AggregatorChainPolicyInput): {
  ok: boolean;
  reason?: string;
} {
  const { expectedChainId, providerChainId, aggregatorFromEnv, aggregatorRequired } = input;
  if (providerChainId !== expectedChainId) {
    return {
      ok: false,
      reason:
        `RPC chainId ${providerChainId} != AUDIT_CHAIN_ID ${expectedChainId} — refusing to ` +
        `poll network-specific default addresses on the wrong chain`,
    };
  }
  if (aggregatorRequired && expectedChainId !== SEPOLIA_CHAIN_ID && !aggregatorFromEnv) {
    return {
      ok: false,
      reason:
        `AUDIT_CHAIN_ID ${expectedChainId} is not Sepolia but AUDIT_BLS_AGGREGATOR_ADDRESS was not ` +
        `set explicitly — the built-in default is a Sepolia-only address; set it explicitly`,
    };
  }
  return { ok: true };
}
