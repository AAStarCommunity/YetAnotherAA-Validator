# Pre-release test checklist (DVT signer + slash consensus)

Mandatory before any release, and before flipping `AUDIT_EXECUTE_SLASH=true` on
a live node. Two layers: **(A) automated gates** run on every PR/release, and
**(B) the slash-consensus live drill** — a staged, real-network dress rehearsal
that the unit tests provably cannot cover.

Most of §B's items are here because the **first live drill surfaced 5
real-environment failures that 360 green unit tests never caught** (see the
regression table). Treat every one as a must-pass gate before arming slashing
against real operators.

---

## A. Automated gates (every PR + release)

```bash
npm run type-check      # tsc --noEmit — clean
npm run build           # nest build — clean
npm run lint:check      # 0 errors
npm run format:check    # prettier clean (root README + imx93 README have bitten us — CI checks the whole repo)
NODE_OPTIONS=--experimental-vm-modules npx jest   # full suite green (currently 360/360, 24 suites)
npm run config:check    # deploy/sdk-dvt-config.testnet.json in sync with the live nodes' /node/info
```

The slash path (`audit/`, `gossip-quorum-cosigner`, `slash-consensus`, the
`blockchain.service` queue/execute + `getRecentSlashExecuted`) drives real money
— its unit tests carry the invariants below; do not merge with any of them red:

- `signerMask` bit convention = slot `s` → bit `s-1` (pinned vs
  `BLSAggregator.sol`; `[1,2,3]`=7n)
- responder gate fail-closed (not-armed / not-watchlisted / hash-mismatch /
  proofHash≠evidenceHash / no-slot)
- requester per-response BLS verify + on-chain slot→key binding + strict
  under-threshold → throw
- staticCall preflight before queue/execute (a would-revert throws, no gas)
- `AUDIT_DRY_RUN` never broadcasts (queue/execute **and createProposal**) +
  never writes a durable slashed marker
- `PROOF_SCHEMA_VERSION` bound into proofHash + mismatch → explicit refusal
- owner-auth cross-repo invariant
  `selector(isValidOwnerAuth(bytes32,bytes)) === 0xa0cf00cf`

---

## B. Slash-consensus live drill (before arming `AUDIT_EXECUTE_SLASH` in prod)

Deploy all N nodes ATOMICALLY (same `PROOF_SCHEMA_VERSION` — a mixed-version
fleet silently loses quorum), then walk the stages. Use `AUDIT_DRY_RUN=true` for
the dress rehearsal — it proves the whole path against the REAL contracts
(co-sign + staticCall accepted by `verifyAndExecute`) with ZERO real slash —
before ever setting `AUDIT_DRY_RUN=false`.

### Stage 0 — deploy + mesh

- [ ] All N nodes on the same build/`PROOF_SCHEMA_VERSION`; `/health` green.
- [ ] Gossip mesh actually connected (`/gossip/peers` == N, heartbeats flowing).
      **Co-located drill nodes must gossip over localhost**
      (`DRILL_LOCAL_GOSSIP=1`) — the cloudflare tunnel returns 502 on the
      `wss://…/ws` upgrade (real-env #2).

### Stage 1 — detection (disarmed, `AUDIT_EXECUTE_SLASH=false`)

- [ ] Create a real over-limit condition for a watchlisted operator (debt >
      creditLimit, availableCredit == 0). Detection is **finality-gated** — the
      audit reads the finalized block, so the violation only shows AFTER the
      debt-recording block finalizes (~13 min on Sepolia). This is correct
      reorg-safe behaviour, not a bug.
- [ ] All N nodes independently detect it AND compute the **identical
      `proofHash`** (the co-sign gate requires byte-identical evidence — verify
      via `/audit/status`).

### Stage 2 — dry-run co-sign (`AUDIT_EXECUTE_SLASH=true` + `AUDIT_DRY_RUN=true`)

- [ ] Each node's operator EOA (`ETH_PRIVATE_KEY`) is a registered validator at
      its slot.
- [ ] The quorum co-sign completes over gossip and the staticCall preflight is
      ACCEPTED by the real `verifyAndExecute` → logs
      `DRY RUN … staticCall passed, NOT broadcasting`.
- [ ] No real tx broadcast: no queue/execute tx, **no orphaned createProposal**
      (F1), operator stake UNCHANGED on-chain.

### Stage 3 — first real slash (`AUDIT_DRY_RUN=false`) — only after Stage 2 is clean

- [ ] `queueSlashWithProof` → `createProposal(evidenceHash=proofHash)` →
      `executeWithProof` land; verify the `SlashExecuted` event + the operator's
      GToken stake reduced by the penalty.
- [ ] Restore the drill's scene (repay/reset any synthetic over-limit
      condition).

---

## RPC requirements (the drill's biggest lesson)

The over-slash guard's `getRecentSlashExecuted` and the audit reads both hit the
RPC every tick. The node's RPC MUST provide:

- **`eth_getLogs` range ≥ `AUDIT_SLASH_LOOKBACK_BLOCKS`.** Alchemy's FREE tier
  caps `eth_getLogs` at **10 blocks** → the scan errored → the over-slash guard
  failed CLOSED → every slash was blocked (real-env #4). The scan now anchors a
  bounded window at the chain HEAD, so size `AUDIT_SLASH_LOOKBACK_BLOCKS` to the
  RPC's cap (e.g. 9 for Alchemy free). A wider range than the cap →
  indeterminate → fail-closed (safe, but nothing slashes).
- **Reliable `eth_call`.** Some public RPCs (e.g. `sepolia.drpc.org`) allow big
  `getLogs` ranges but return `500` on `eth_call` reads → the audit tick fails
  (real-env #4b). Use a provider that does BOTH.
- **Archive access.** Each node independently re-reads the historical
  violation-block state to confirm
  - rebuild `proofHash` — a non-archive node can't confirm an old violation (by
    design; run archive RPC or slash promptly within the pruning window).

---

## Double-slash residuals — ✅ CONTRACT-CLOSED by SuperPaymaster 5.4.2

Both residuals below (surfaced by an 8-round adversarial review) are now
**authoritatively closed on-chain** by SuperPaymaster **5.4.2** (deployed
Sepolia 2026-07-08, UUPS in-place — address unchanged): the BLS slash path now
enforces a **1h cooldown gate inside `SP.queueSlash`** (`_blsSlashCd`, decoupled
from the owner-path `_slashCd`). Within the window, a `BLS_AGGREGATOR`
`queueSlash` reverts `SlashCooldown()`, so a racing second slash of the same
operator **cannot even queue** — the DVT `queueSlashWithProof` staticCall
preflight catches it and degrades to file+archive (no gas, no parked pending).
The gate is at `queueSlash` (not `executeSlashWithBLS`) precisely so a stale
`_pendingSlash` is never parked.

The DVT over-slash guard (`getRecentSlashExecuted` incl. `OperatorSlashed`,
`isSlashPending` — now the O(1) typed getter with the event reconstruction as a
pre-5.4.2 fallback, + the during-cooldown "learning" scan) is retained as
gas-saving defence-in-depth; the contract is the authority.

1. **Fresh-node / long-offline window** — a fresh node could read "clear" for a
   sustained violation whose peer slash aged out of
   `AUDIT_SLASH_LOOKBACK_BLOCKS` → ✅ now the contract reverts its `queueSlash`
   within the 1h cooldown. Still size `AUDIT_SLASH_LOOKBACK_BLOCKS` sensibly to
   avoid needless preflight churn.

2. **Different-epoch concurrent slash** → ✅ closed: two nodes at different
   `epoch`s could both queue, but the 1h `_blsSlashCd` gate in `SP.queueSlash`
   reverts the second regardless of epoch.

⚠️ **Cold-start floor:** the 5.4.2 upgrade atomically primed a 1h blanket BLS
cooldown (`primeBlsSlashCooldown`), so for ~1h AFTER the upgrade EVERY BLS
`queueSlash` (even a never-slashed operator) reverts `SlashCooldown`. **Schedule
the first real slash E2E ≥ 1h after the upgrade** (≥ ~2026-07-08 09:24 UTC), or
the queue reverts. The owner path is unaffected.

---

## Regression table — the 5 real-env failures the drill caught (unit tests could not)

| #   | Failure                                                                                                                                                   | Fix                                                                                                     | Now covered by                                                 |
| --- | --------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------- |
| 1   | Node that detects a violation before its gossip mesh is up permanently skips that block's co-sign (dedup marks it handled even though the co-sign failed) | `coSignRetryKeys` — a transient no-peers abort retries next tick, bypassing the archived-evidence dedup | audit.service.spec "transient abort → re-attempted every tick" |
| 2   | Cloudflare tunnel returns 502 on the gossip `wss://…/ws` upgrade → co-located nodes never mesh                                                            | `DRILL_LOCAL_GOSSIP=1` (localhost gossip for co-located nodes)                                          | §B Stage 0                                                     |
| 3   | `AUDIT_SLASH_LOOKBACK_BLOCKS` wider than the RPC's `getLogs` cap → over-slash scan indeterminate → fail-closed blocks all slashing                        | scan a bounded window at the HEAD (range == lookback); size to the RPC cap                              | getRecentSlashExecuted head-window test + this doc             |
| 4   | `AUDIT_DRY_RUN` did NOT gate `createProposalWithEvidence` → dry-run broadcast a REAL governance proposal (orphaned on-chain)                              | dry-run staticCalls createProposal for the would-be id, no broadcast                                    | blockchain.service.spec "createProposal dryRun"                |
| 5   | RPC that does one of {big getLogs, reliable eth_call} but not both → tick fails                                                                           | RPC requirements above; use a provider that does both                                                   | §RPC requirements                                              |
