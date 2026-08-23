# RepCredit Structured Co-signing

The RepCredit evidence endpoint is local-experiment functionality and is
disabled by default. It does not alter `/signature/sign` or accept arbitrary
digests. Each node reconstructs the Registry hash from the full proposal and its
RPC chain ID, then checks that its compact BLS key matches the active key
registered at its configured on-chain slot.

Required opt-in configuration:

```bash
REPCREDIT_EXPERIMENT_SIGNING=true
REPCREDIT_BLS_AGGREGATOR_ADDRESS=0x...
REPCREDIT_VALIDATOR_SLOT=1
```

Generate local-only deterministic node states in a temporary or gitignored
directory:

```bash
node scripts/e2e/gen-repcredit-nodes.mjs .e2e/repcredit 3
```

Run each process from its own `nodeN/` directory so it reads that directory's
`node_state.json`. POST the same structured proposal to `POST /repcredit/sign`
on all three nodes, then POST their responses with `threshold: 3` to
`POST /repcredit/aggregate`. The aggregate response includes the decimal
`signerMask`, EIP-2537 `sigG2`, and ABI-encoded production `proof`.

Never use these deterministic keys or this opt-in endpoint on a production
network.
