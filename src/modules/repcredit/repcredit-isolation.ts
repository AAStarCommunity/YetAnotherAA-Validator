/**
 * Fail-closed isolation policy between the RepCredit EXPERIMENT signer and every aggregator
 * that guards real stake (CC-49 HIGH-A / MEDIUM-C / round-3 MEDIUM).
 *
 * WHAT THIS IS AND IS NOT. This is a TRANSITIONAL OPERATOR GUARD, not cryptographic
 * isolation. The slash preimage this path signs (`buildRepCreditSlashMessageHash`) is
 * byte-identical to the production one and contains only `block.chainid` — no aggregator
 * address, no domain-separation tag. A signature is therefore portable across every
 * aggregator on the same chain: if a key is active at the same slot on both the experiment
 * and a production aggregator, an experiment quorum is a byte-valid production slash proof.
 * Nothing in this file can change that. What it can do is stop a node from PRODUCING such a
 * signature in the first place, and stop the two most likely operator mistakes:
 *
 *   - pointing the experiment at the production aggregator (address check), and
 *   - signing with a key that is registered on an aggregator guarding real stake (the
 *     on-chain active-slot scan in `RepCreditService`).
 *
 * Both are configuration-driven, and configuration can be wrong: an operator who names a
 * DECOY contract as the "production" aggregator passes every check here while their key sits
 * on the real one. That residual is not closeable in this repo — the real fix is a fixed
 * domain tag + `address(this)` in the on-chain preimage, owned by repo:sp. Until that schema
 * lands, treat this file as reducing accident, not as a security boundary against a
 * determined or careless operator.
 *
 * The DENY-LIST (`REPCREDIT_FORBIDDEN_AGGREGATORS`) exists because a single
 * `AUDIT_BLS_AGGREGATOR_ADDRESS` only ever described ONE aggregator, while a chain can host
 * several that hold stake. Entries are UNIONed with the audit aggregator, each is scanned,
 * and ANY failure — unreadable, wrong ABI, key found — refuses the signature.
 *
 * THE CHAIN-SWITCH GUARD (MEDIUM-C). `auditBlsAggregatorAddress` carries a built-in Sepolia
 * default, so on any other chain an unset env would silently compare against a foreign-chain
 * address. Arming therefore requires the value to be set EXPLICITLY. The one escape is
 * `REPCREDIT_NO_PRODUCTION_AGGREGATOR=true` for a throwaway devnet that genuinely hosts no
 * production aggregator; it is refused on every chain id known to carry real deployments
 * (see `CHAINS_WITH_PRODUCTION_STAKE`), so it cannot be used to skip the scan on Sepolia.
 */

/**
 * Chain ids where a live SuperPaymaster/BLSAggregator deployment exists or is expected, and
 * where "there is no production aggregator here" is therefore never a true statement.
 * Sepolia is INCLUDED: the live SP instance the audit path guards runs there.
 */
export const CHAINS_WITH_PRODUCTION_STAKE = new Set<number>([
  1, // Ethereum mainnet
  10, // OP mainnet
  137, // Polygon
  8453, // Base
  42161, // Arbitrum One
  11155111, // Sepolia — the live SP/BLSAggregator testnet deployment
]);

export interface RepCreditAggregatorPolicyInput {
  /** REPCREDIT_BLS_AGGREGATOR_ADDRESS (resolved). */
  repCreditAggregatorAddress?: string;
  /** AUDIT_BLS_AGGREGATOR_ADDRESS (resolved — always carries the Sepolia default). */
  auditAggregatorAddress?: string;
  /** Whether AUDIT_BLS_AGGREGATOR_ADDRESS was set EXPLICITLY, not inherited from the default. */
  auditAggregatorFromEnv: boolean;
  /** REPCREDIT_FORBIDDEN_AGGREGATORS — extra aggregators the signing key must not sit on. */
  forbiddenAggregators?: string[];
  /** REPCREDIT_NO_PRODUCTION_AGGREGATOR — devnet acknowledgement (see file header). */
  noProductionAggregator?: boolean;
}

export interface RepCreditAggregatorPolicyResult {
  ok: boolean;
  reason?: string;
  /**
   * Aggregators the local signing key must NOT be active on. Empty ONLY in the acknowledged
   * no-production-aggregator case, which `RepCreditService` additionally gates on chain id.
   */
  forbidden: string[];
}

/** Pure config-layer check. No RPC — safe to run before any caller-supplied field is parsed. */
export function checkRepCreditAggregatorPolicy(
  input: RepCreditAggregatorPolicyInput
): RepCreditAggregatorPolicyResult {
  const {
    repCreditAggregatorAddress,
    auditAggregatorAddress,
    auditAggregatorFromEnv,
    forbiddenAggregators = [],
    noProductionAggregator = false,
  } = input;

  const deny: string[] = [];
  const fail = (reason: string): RepCreditAggregatorPolicyResult => ({
    ok: false,
    reason,
    forbidden: [],
  });

  if (!repCreditAggregatorAddress) {
    return fail("REPCREDIT_BLS_AGGREGATOR_ADDRESS is required when armed");
  }
  const experiment = repCreditAggregatorAddress.toLowerCase();

  if (auditAggregatorFromEnv && auditAggregatorAddress) {
    deny.push(auditAggregatorAddress);
  } else if (!noProductionAggregator) {
    return fail(
      "AUDIT_BLS_AGGREGATOR_ADDRESS must be set EXPLICITLY to arm the RepCredit experiment — " +
        "the built-in default is a Sepolia address and inheriting it would compare the " +
        "experiment aggregator against an address that is meaningless on this chain. On a " +
        "throwaway devnet that hosts no production aggregator at all, set " +
        "REPCREDIT_NO_PRODUCTION_AGGREGATOR=true instead (refused on chains with real " +
        "deployments)"
    );
  }
  deny.push(...forbiddenAggregators);

  // De-duplicate case-insensitively, keeping the operator's original casing for messages.
  const seen = new Set<string>();
  const forbidden: string[] = [];
  for (const entry of deny) {
    const address = entry?.trim();
    if (!address) continue;
    if (!/^0[xX][0-9a-fA-F]{40}$/.test(address)) {
      return fail(`"${address}" is not a valid aggregator address (REPCREDIT deny-list)`);
    }
    const key = address.toLowerCase();
    if (key === experiment) {
      return fail(
        `REPCREDIT_BLS_AGGREGATOR_ADDRESS must not equal ${address} — the experiment signer ` +
          "may not target an aggregator that guards production stake"
      );
    }
    if (seen.has(key)) continue;
    seen.add(key);
    forbidden.push(address);
  }

  return { ok: true, forbidden };
}
