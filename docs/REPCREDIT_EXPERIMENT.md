# RepCredit Structured Co-signing — EXPERIMENT ONLY

> **Status: experiment signer. NOT a production validator.** This path is
> disabled by default and must never be armed on a node that also serves the
> production audit/slash quorum. Production slashing is `GossipQuorumCoSigner`
> (`src/modules/audit/gossip-quorum-cosigner.ts`).

## What this path does and does not prove

A node here recomputes the Registry / `BLSAggregator` hash preimage from the
**caller-supplied** proposal fields plus its own RPC `chainId`, checks that its
compact BLS key matches the active key registered at its configured on-chain
slot, and signs the locally recomputed hash. It never accepts a caller's
`messageHash` and never signs an arbitrary digest.

What a quorum on this path establishes:

- **Yes** — N independent processes, holding N distinct registered keys, agree
  on the _encoding_ of one structured proposal, and each verified the hash
  itself.
- **No** — it does **not** establish that any node independently verified the
  underlying _fact_ (the contribution, or the violation being slashed). Every
  signer is endorsing the same unverified input.

Papers and release notes must describe this as a **multi-process experiment
signer reaching agreement on structured input/encoding**, not as independent
validation of contribution facts. An independent policy/verifier interface for a
production RepCredit path is future work (CC-49 HIGH-1).

Contrast with the production audit path, which is what independent verification
actually looks like:

| Production (`GossipQuorumCoSigner`)                                                      | RepCredit experiment                                    |
| ---------------------------------------------------------------------------------------- | ------------------------------------------------------- |
| Armed by `AUDIT_EXECUTE_SLASH`                                                           | Armed by `REPCREDIT_EXPERIMENT_SIGNING`                 |
| Operator must be in the effective watchlist (static ∪ on-chain roles)                    | Any well-formed address                                 |
| Each node re-reads chain state at the `epoch` block and re-confirms the violation itself | No fact re-verification                                 |
| `evidenceHash` must equal the node's locally recomputed `proofHash`                      | Any 32 bytes                                            |
| Severity-keyed `auditSlashThresholds`                                                    | Severity-keyed `slashThresholds[level]` (read on-chain) |
| Peer-authenticated gossip transport                                                      | HTTP + mandatory HMAC, loopback by default              |

## Why the endpoints are gated the way they are

`/repcredit/slash/sign` produces a signature over a preimage that is
byte-identical to `BLSAggregator.verifyAndExecute`'s slash-only hash, signed
with the node's **production** BLS key at its registered slot. A quorum of those
signatures is a valid, irreversible slash proof. The node listens on `0.0.0.0`,
so an unauthenticated endpoint here would be a public slash-proof oracle (CC-49
BLOCKER-1).

`RepCreditExperimentGuard` therefore admits a request only when **all** of the
following hold, in this order:

1. `REPCREDIT_EXPERIMENT_SIGNING=true` — otherwise `403`.
2. `REPCREDIT_EXPERIMENT_AUTH_SECRET` is set — armed without a secret returns
   `503` for every request. There is no "auth off" mode.
3. Body is within `REPCREDIT_MAX_BODY_BYTES` (default 64 KiB) — otherwise `413`.
4. The caller is on loopback, unless `REPCREDIT_ALLOW_REMOTE=true` — otherwise
   `403`.
5. `X-RepCredit-Timestamp` is within the TTL and `X-RepCredit-Auth` matches
   `HMAC-SHA256(secret, "<timestamp>.<raw body>")` in constant time — otherwise
   `401`/`403`.
6. That exact auth token has not been used before within the TTL window (replay
   defence) — otherwise `403`.

Separately, `RepCreditService` refuses to arm at all when
`REPCREDIT_BLS_AGGREGATOR_ADDRESS == AUDIT_BLS_AGGREGATOR_ADDRESS`: the
experiment must run against its **own isolated aggregator deployment**, so an
experiment co-signature can never be executed against production stake.

> The loopback check is defence in depth, not the authenticator. A node behind a
> local tunnel (`cloudflared → 127.0.0.1:3001`) sees every public request as
> loopback. The HMAC secret is the real barrier, which is why it is mandatory.

## Configuration

```bash
# Arm (all four are required together)
REPCREDIT_EXPERIMENT_SIGNING=true
REPCREDIT_EXPERIMENT_AUTH_SECRET=<32+ bytes of CSPRNG output, per node>
REPCREDIT_BLS_AGGREGATOR_ADDRESS=0x...   # isolated experiment instance ONLY
REPCREDIT_VALIDATOR_SLOT=1

# Optional
REPCREDIT_EXPERIMENT_AUTH_TTL_MS=120000  # default 120s
REPCREDIT_MAX_BODY_BYTES=65536           # default 64 KiB
REPCREDIT_ALLOW_REMOTE=false             # default: loopback callers only
RATE_LIMIT_ENABLED=true                  # recommended; ThrottleGuard is a no-op without it
```

Generate the auth secret with a CSPRNG, one per node, and inject it from outside
the machine's disk (systemd `LoadCredential`, an orchestrator secret, or typed):

```bash
openssl rand -hex 32
```

## Deployment runbook

1. **Deploy an isolated `BLSAggregator`** for the experiment. Do not reuse the
   instance referenced by `AUDIT_BLS_AGGREGATOR_ADDRESS`; the service refuses to
   start signing if the two addresses match.
2. **Generate ephemeral node keys** into a gitignored or temporary directory.
   Keys come from the OS CSPRNG, are written `0600`, and the generator refuses
   to overwrite existing key material:
   ```bash
   node scripts/e2e/gen-repcredit-nodes.mjs .e2e/repcredit 3
   ```
3. **Register those public keys** at slots 1..N on the _experiment_ aggregator
   only.
4. **Set a distinct auth secret per node** and start each process from its own
   `nodeN/` directory so it reads that directory's `node_state.json`.
5. **Keep nodes on loopback.** Leave `REPCREDIT_ALLOW_REMOTE` unset; drive the
   run from an orchestrator co-located with each node (SSH tunnel / local
   script). If the run genuinely requires a remote caller, set
   `REPCREDIT_ALLOW_REMOTE=true` knowingly — the HMAC then becomes the only
   barrier — and enable `RATE_LIMIT_ENABLED=true`.
6. **Call each node** with signed headers. Reference computation:
   `RepCreditExperimentGuard.computeHeaders(secret, Date.now(), rawBody)`. Sign
   the **exact bytes** you send; re-serialising the JSON will not match.
7. **Aggregate.** POST the responses to `/repcredit/aggregate` (reputation) or
   `/repcredit/slash/aggregate` (slash). The slash path validates `threshold`
   against the on-chain `slashThresholds[slashLevel]` — the severity-specific
   getter the contract's slash branch actually enforces, not `defaultThreshold`
   (CC-49 MEDIUM-1). The response carries the decimal `signerMask`, EIP-2537
   `sigG2`, and the ABI-encoded production `proof`.
8. **Disarm when the run ends.** Unset `REPCREDIT_EXPERIMENT_SIGNING` and rotate
   the auth secret. Nodes keep no record of what they signed, so an armed window
   is an unbounded co-signature-harvesting window.

## Key hygiene

Experiment keys are **ephemeral and random**. Earlier revisions of the generator
derived the private key from the node index (the literal scalars `1`, `2`, `3`);
any evidence produced with those keys is reproducible by anyone and is
cryptographically worthless. If such a key was ever registered on a live
aggregator, revoke that slot, rotate the key, and re-run the experiment before
citing the result (CC-49 HIGH-2).

Never point this endpoint at a production aggregator, and never arm it on a node
carrying stake you are not willing to see slashed.
