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
with the node's local BLS key at its configured slot on the **experiment**
aggregator. A quorum of those signatures is a valid, irreversible slash proof.
The node listens on `0.0.0.0`, so an unauthenticated endpoint here would be a
public slash-proof oracle (CC-49 BLOCKER-1).

**The key used here must be ephemeral and experiment-only.** The service
enforces that (see
[Aggregator and key isolation](#aggregator-and-key-isolation)); the runbook
below is how you produce such a key. Nothing in this path may be signed with a
key that carries production stake.

`RepCreditExperimentGuard` therefore admits a request only when **all** of the
following hold, in this order:

1. `REPCREDIT_EXPERIMENT_SIGNING=true` — otherwise `403`.
2. `REPCREDIT_EXPERIMENT_AUTH_SECRET` is set — armed without a secret returns
   `503` for every request. There is no "auth off" mode.
3. Body is within `REPCREDIT_MAX_BODY_BYTES` (default 64 KiB) — otherwise `413`.
4. The caller is on loopback, unless `REPCREDIT_ALLOW_REMOTE=true` — otherwise
   `403`.
5. `X-RepCredit-Scheme: v2` is present, `X-RepCredit-Timestamp` is within the
   window, the raw request bytes are available, and `X-RepCredit-Auth` matches
   the v2 preimage in constant time — otherwise `401`/`403`. The preimage is

   ```
   "v2" \n METHOD \n REQUEST-TARGET \n TIMESTAMP-MS \n RAW-BODY
   ```

   so a token authorises exactly one method on exactly one endpoint. If the raw
   bytes are unavailable the request is **rejected**; the node never
   authenticates against a re-serialised body.

6. That exact auth token has not been used before within the TTL window (replay
   defence) — otherwise `403`. The replay cache is bounded
   (`REPCREDIT_REPLAY_CACHE_MAX`); when full it returns `503` rather than
   evicting, because evicting would silently re-open the window it closes.

> The loopback check is defence in depth, not the authenticator. A node behind a
> local tunnel (`cloudflared → 127.0.0.1:3001`) sees every public request as
> loopback. The HMAC secret is the real barrier, which is why it is mandatory.

## Aggregator and key isolation

**A signature produced here is not bound to the aggregator it was produced
for.** The slash preimage contains `block.chainid` and the proposal fields — no
aggregator address, no domain-separation tag. On a given chain, a quorum
collected against the experiment aggregator is a byte-valid slash proof against
_any_ aggregator where the same keys occupy the same slots. Address separation
alone therefore does **not** make an experiment co-signature unusable against
production stake; earlier revisions of this document claimed it did, and that
claim was wrong (CC-49 HIGH-A).

**What follows is a transitional operator guard, not cryptographic isolation.**
It stops a node from _producing_ a portable signature, and it catches the two
likely operator mistakes (pointing the experiment at a production aggregator;
signing with a production-registered key). It cannot stop a signature that has
already been produced from being spent elsewhere, and it is
configuration-driven: an operator who names a **decoy** contract as the
"production" aggregator passes every check here while their key sits on the real
one. Treat it as reducing accident, not as a boundary against a careless or
hostile operator. The boundary is repo:sp's domain tag (below).

Isolation is enforced on the **key**, in two layers, both fail-closed:

| Layer                             | Enforced when                 | Effect                                                                                                                                                                                                    |
| --------------------------------- | ----------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Config (`repcredit-isolation.ts`) | every request, before any RPC | `REPCREDIT_BLS_AGGREGATOR_ADDRESS` set, `AUDIT_BLS_AGGREGATOR_ADDRESS` set **explicitly**, every `REPCREDIT_FORBIDDEN_AGGREGATORS` entry well-formed, and none of them equal to the experiment aggregator |
| Chain (`RepCreditService`)        | every signature               | **each** deny-listed aggregator has code and answers the BLSAggregator ABI, and the local signing key is active in **no** slot on **any** of them                                                         |

Consequences worth stating plainly:

- Arming requires an explicit `AUDIT_BLS_AGGREGATOR_ADDRESS`. The built-in
  default is a Sepolia address; inheriting it on another chain would compare
  against — and scan — an address that means nothing there (CC-49 MEDIUM-C).
  Changing chains without setting it fails closed.
- One address describes one aggregator, but a chain can host several that hold
  stake. Name the rest in `REPCREDIT_FORBIDDEN_AGGREGATORS` (comma-separated).
  Every entry is scanned; **any** failure refuses the signature. A malformed
  entry is an error, never a skipped one.
- If a deny-listed aggregator has no code on the connected chain, or does not
  answer `validatorAtSlot` / `getBLSPublicKey`, the node refuses to sign. It
  will not proceed on an unverifiable isolation claim.
- If any single slot read fails, the node refuses to sign. A transient RPC error
  is never read as "the key is absent" — that is what the STRICT reader exists
  for, and every malformed/short/undecodable response throws rather than
  returning "absent".
- If the local key is active at any slot on any listed aggregator, the node
  refuses to sign and logs the slot.
- Underlying provider errors are **logged, scrubbed, and never returned**: an
  ethers error message embeds the request URL, and the RPC URL carries the
  provider API key. The caller learns only that the node refused.
- **Devnet escape.** A throwaway chain hosting no production aggregator at all
  (local anvil) has nothing to isolate against. Set
  `REPCREDIT_NO_PRODUCTION_AGGREGATOR=true` **instead of**
  `AUDIT_BLS_AGGREGATOR_ADDRESS` — the node then arms with an empty deny-list
  and logs a loud warning. It is **refused on any chain id that carries real
  deployments** (1, 10, 137, 8453, 42161, 11155111), so it cannot be used to
  skip the scan on Sepolia. `REPCREDIT_FORBIDDEN_AGGREGATORS` still applies
  under the acknowledgement.

The scan runs on every signature rather than once at boot: a slot can be
registered while the node is armed, and a cached "clean" verdict is exactly the
stale answer that would matter. It covers at least `MAX_VALIDATORS` (13) slots
per listed aggregator — lowering `AUDIT_MAX_SLOTS` cannot shrink a security scan
into missing the slot a key actually occupies, though raising it is honoured.
Slot reads are issued concurrently, but every outcome is inspected and any
rejection refuses the signature: parallelism changes the latency, never the
verdict. Cost is up to 2 × 13 × (number of listed aggregators) `eth_call`s per
signature, on an endpoint that is already HMAC-authenticated and loopback-bound.

**Still missing, and owned elsewhere.** The real fix is domain separation in the
on-chain preimage — a fixed domain tag plus `address(this)` — so an experiment
signature is not a well-formed production proof in the first place. That schema
is owned by repo:sp; the two layers above are what stands in until it lands, and
they must be re-derived byte-for-byte against the new preimage when it does.

## Configuration

```bash
# Arm (all five are required together)
REPCREDIT_EXPERIMENT_SIGNING=true
REPCREDIT_EXPERIMENT_AUTH_SECRET=<32+ bytes of CSPRNG output, per node>
REPCREDIT_BLS_AGGREGATOR_ADDRESS=0x...   # isolated experiment instance ONLY
REPCREDIT_VALIDATOR_SLOT=1
AUDIT_BLS_AGGREGATOR_ADDRESS=0x...       # the PRODUCTION aggregator to isolate against.
                                         # Must be set explicitly, on every chain — the
                                         # built-in default is Sepolia-only and arming
                                         # without this fails closed (CC-49 MEDIUM-C).
                                         # On a devnet with no production aggregator at
                                         # all, use REPCREDIT_NO_PRODUCTION_AGGREGATOR
                                         # instead (see below).

# Optional
REPCREDIT_FORBIDDEN_AGGREGATORS=0x...,0x...    # extra aggregators the key must not sit on
REPCREDIT_NO_PRODUCTION_AGGREGATOR=false       # devnet-only; refused on chains with real
                                               # deployments (1/10/137/8453/42161/11155111)
REPCREDIT_EXPERIMENT_AUTH_TTL_MS=120000        # default 120s (backwards tolerance)
REPCREDIT_AUTH_MAX_FUTURE_SKEW_MS=5000         # default 5s (forwards tolerance; keep small)
REPCREDIT_REPLAY_CACHE_MAX=10000               # default 10k single-use auth tokens
REPCREDIT_MAX_BODY_BYTES=65536                 # default 64 KiB
REPCREDIT_ALLOW_REMOTE=false                   # default: loopback callers only
AUDIT_MAX_SLOTS=13                             # slots scanned per aggregator; floored at 13
RATE_LIMIT_ENABLED=true                        # recommended; ThrottleGuard is a no-op without it
```

Every numeric knob above is parsed **strictly**: a non-integer or out-of-range
value aborts start-up rather than silently falling back to a default. `parseInt`
yields `NaN` for a typo, and every comparison against `NaN` is false — a
mistyped TTL would have disabled the staleness check outright, and a mistyped
`REPCREDIT_MAX_BODY_BYTES` would have removed the body cap (CC-49 round 3).

The auth window is deliberately **asymmetric**: a token may be up to
`REPCREDIT_EXPERIMENT_AUTH_TTL_MS` old, but no more than
`REPCREDIT_AUTH_MAX_FUTURE_SKEW_MS` in the future. A symmetric window let a
client whose clock ran fast mint tokens that outlived their own replay record
(CC-49 MEDIUM-B). Orchestrators must keep their clock in sync; a machine more
than 5s ahead will have every request rejected with `401`.

Generate the auth secret with a CSPRNG, one per node, and inject it from outside
the machine's disk (systemd `LoadCredential`, an orchestrator secret, or typed):

```bash
openssl rand -hex 32
```

## Deployment runbook

1. **Deploy an isolated `BLSAggregator`** for the experiment, and set
   `AUDIT_BLS_AGGREGATOR_ADDRESS` explicitly to the production instance on the
   same chain — plus `REPCREDIT_FORBIDDEN_AGGREGATORS` for any other aggregator
   on that chain that holds stake. The service refuses to sign if an address
   matches the experiment aggregator, if the audit address is not set
   explicitly, or if any listed address has no code / wrong ABI on the connected
   chain. On a throwaway devnet with no production aggregator, set
   `REPCREDIT_NO_PRODUCTION_AGGREGATOR=true` instead — it is refused on Sepolia
   and every mainnet.
2. **Generate ephemeral node keys** into a gitignored or temporary directory.
   These keys exist for this run only and must never be registered on the
   production aggregator — the service refuses to sign with a key that is active
   there. Keys come from the OS CSPRNG, are written `0600`, and the generator
   refuses to overwrite existing key material:
   ```bash
   node scripts/e2e/gen-repcredit-nodes.mjs .e2e/repcredit 3
   ```
3. **Register those public keys** at slots 1..N on the _experiment_ aggregator
   only. Registering an experiment key on the production aggregator (or reusing
   a production-registered key here) is refused at signing time, per slot.
4. **Set a distinct auth secret per node** and start each process from its own
   `nodeN/` directory so it reads that directory's `node_state.json`.
5. **Keep nodes on loopback.** Leave `REPCREDIT_ALLOW_REMOTE` unset; drive the
   run from an orchestrator co-located with each node (SSH tunnel / local
   script). If the run genuinely requires a remote caller, set
   `REPCREDIT_ALLOW_REMOTE=true` knowingly — the HMAC then becomes the only
   barrier — and enable `RATE_LIMIT_ENABLED=true`.
6. **Call each node** with signed headers. Reference computation:

   ```ts
   RepCreditExperimentGuard.computeHeaders(secret, {
     method: "POST",
     requestTarget: "/repcredit/slash/sign", // exactly as sent, query string included
     timestampMs: Date.now(),
     rawBody,
   });
   ```

   It returns all three headers (`X-RepCredit-Scheme`, `-Timestamp`, `-Auth`).
   Sign the **exact bytes** you send; re-serialising the JSON will not match.
   Stamp a fresh timestamp per request — each token is single-use, and a token
   more than `REPCREDIT_AUTH_MAX_FUTURE_SKEW_MS` ahead of the node's clock is
   rejected.

7. **Aggregate.** POST the responses to `/repcredit/aggregate` (reputation) or
   `/repcredit/slash/aggregate` (slash). The slash path validates `threshold`
   against the on-chain `slashThresholds[slashLevel]` — the severity-specific
   getter the contract's slash branch actually enforces, not `defaultThreshold`
   (CC-49 MEDIUM-1). The response carries the decimal `signerMask`, EIP-2537
   `sigG2`, and the ABI-encoded production `proof`.
8. **Disarm when the run ends.** Unset `REPCREDIT_EXPERIMENT_SIGNING` and rotate
   the auth secret. Nodes keep no record of what they signed, so an armed window
   is an unbounded co-signature-harvesting window.

## Auth scheme migration (v1 → v2) — for orchestrator authors

The HMAC preimage changed in CC-49 round 3. There is **no v1 fallback**:
accepting both would leave the unbound preimage reachable and defeat the change.

|                  | v1 (commit `840bfdc`)                          | v2 (current)                                                              |
| ---------------- | ---------------------------------------------- | ------------------------------------------------------------------------- |
| Preimage         | `"<ts>.<raw body>"`                            | `"v2" \n METHOD \n REQUEST-TARGET \n TIMESTAMP-MS \n RAW-BODY`            |
| Headers          | `X-RepCredit-Timestamp`, `X-RepCredit-Auth`    | the same two **plus** `X-RepCredit-Scheme: v2`                            |
| Helper           | `computeHeaders(secret, timestampMs, rawBody)` | `computeHeaders(secret, { method, requestTarget, timestampMs, rawBody })` |
| Missing raw body | HMAC over a re-serialised body (warned)        | rejected `401`                                                            |

What a client must change:

- Send `X-RepCredit-Scheme: v2`. Omitting it, or sending `v1`, is `401`.
- Include the uppercased HTTP method and the request target — the path exactly
  as it appears in the request line, query string included — in the preimage. A
  token minted for `/repcredit/sign` is rejected on `/repcredit/slash/sign`.
- Everything else is unchanged: per-node secret, fresh timestamp per request,
  single-use tokens, sign the bytes you actually send.

`buildRepCreditAuthPreimage` and `REPCREDIT_AUTH_SCHEME` are exported from
`src/modules/repcredit/repcredit-experiment.guard.ts` for clients that pin the
contract in a test.

## Key hygiene

Experiment keys are **ephemeral and random**. Earlier revisions of the generator
derived the private key from the node index (the literal scalars `1`, `2`, `3`);
any evidence produced with those keys is reproducible by anyone and is
cryptographically worthless. If such a key was ever registered on a live
aggregator, revoke that slot, rotate the key, and re-run the experiment before
citing the result (CC-49 HIGH-2).

Never point this endpoint at a production aggregator, never register an
experiment key on one, and never arm this path on a node whose BLS key carries
stake. The first two are enforced in code and fail closed; the third is
procedural, because a node cannot tell what its key is worth.
