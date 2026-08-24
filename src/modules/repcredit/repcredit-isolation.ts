/**
 * Fail-closed isolation policy between the RepCredit EXPERIMENT signer and the production
 * audit/slash aggregator (CC-49 HIGH-A / MEDIUM-C).
 *
 * WHY ADDRESS COMPARISON IS NOT ENOUGH. The slash preimage this path signs
 * (`buildRepCreditSlashMessageHash`) is byte-identical to the production one and contains
 * only `block.chainid` — no aggregator address, no domain-separation tag. A signature is
 * therefore portable across every aggregator on the same chain: if a key is active at the
 * same slot on both the experiment and the production aggregator, an experiment quorum is a
 * byte-valid production slash proof. Refusing `experiment == audit` only controls where THIS
 * node reads slot registrations from; it cannot control where the signature is spent.
 *
 * So isolation is enforced on the KEY, not just the address:
 *   - config layer (pure, here): arming requires an EXPLICIT `AUDIT_BLS_AGGREGATOR_ADDRESS`
 *     and a distinct `REPCREDIT_BLS_AGGREGATOR_ADDRESS`.
 *   - chain layer (`RepCreditService`): the audit aggregator must have code and answer the
 *     BLSAggregator ABI, and the local signing key must not be active in ANY slot on it.
 *
 * The explicit-env requirement is also the chain-switch guard (MEDIUM-C). `auditBlsAggregator
 * Address` carries a built-in Sepolia default, so on any other chain an unset env would make
 * the comparison — and the slot scan — run against a foreign-chain address that means nothing
 * there. Requiring the explicit value makes the wrong-chain case impossible to inherit
 * silently, and the on-chain code/ABI probe rejects a Sepolia address pointed at a chain
 * where nothing is deployed.
 *
 * A fixed domain tag + `address(this)` in the on-chain preimage is the real fix and is owned
 * by repo:sp; until that schema lands, these two layers are what keeps an experiment
 * signature away from production stake.
 */
export interface RepCreditAggregatorPolicyInput {
  /** REPCREDIT_BLS_AGGREGATOR_ADDRESS (resolved). */
  repCreditAggregatorAddress?: string;
  /** AUDIT_BLS_AGGREGATOR_ADDRESS (resolved — always carries the Sepolia default). */
  auditAggregatorAddress?: string;
  /** Whether AUDIT_BLS_AGGREGATOR_ADDRESS was set EXPLICITLY, not inherited from the default. */
  auditAggregatorFromEnv: boolean;
}

export interface RepCreditAggregatorPolicyResult {
  ok: boolean;
  reason?: string;
}

/** Pure config-layer check. No RPC — safe to run before any caller-supplied field is parsed. */
export function checkRepCreditAggregatorPolicy(
  input: RepCreditAggregatorPolicyInput
): RepCreditAggregatorPolicyResult {
  const { repCreditAggregatorAddress, auditAggregatorAddress, auditAggregatorFromEnv } = input;

  if (!repCreditAggregatorAddress) {
    return { ok: false, reason: "REPCREDIT_BLS_AGGREGATOR_ADDRESS is required when armed" };
  }
  if (!auditAggregatorFromEnv || !auditAggregatorAddress) {
    return {
      ok: false,
      reason:
        "AUDIT_BLS_AGGREGATOR_ADDRESS must be set EXPLICITLY to arm the RepCredit experiment — " +
        "the built-in default is a Sepolia address and inheriting it would compare the " +
        "experiment aggregator against an address that is meaningless on this chain",
    };
  }
  if (auditAggregatorAddress.toLowerCase() === repCreditAggregatorAddress.toLowerCase()) {
    return {
      ok: false,
      reason:
        "REPCREDIT_BLS_AGGREGATOR_ADDRESS must not equal AUDIT_BLS_AGGREGATOR_ADDRESS — " +
        "the experiment signer may not target the production slash aggregator",
    };
  }
  return { ok: true };
}
