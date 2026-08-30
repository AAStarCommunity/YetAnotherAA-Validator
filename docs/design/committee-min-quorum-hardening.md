# Committee minimum-quorum hardening — design & redeploy analysis

**Status:** design (pre-issue), **Codex round-1 applied** · **Repo:**
YetAnotherAA-Validator (DVT) · **Target:** `AAStarCommitteeValidator` (deployed
`0x1A8Db639…`, Sepolia) **Origin:** CC-97 (tier-2/3 quorum enforcement) → CC-98
(per-proposal committee model). Raised again 2026-08-19 during the DSR paper
re-pin review.

---

## 0. Accountability note (why this exists)

A `minCommittee = 3` floor is a **core security invariant**. It was
**implemented** in the first attempt (global-N model, PR #235: floor 3,
owner-can't-lower) and **verified by DSR**. When that model was scrapped and the
per-proposal `AAStarCommitteeValidator` was **rewritten from scratch (#237)**,
the floor was **not carried over**. Deployed result: `requiredQuorum = ⌈2m/3⌉`
but **no minimum N** → `N=1 → quorum 1` (single node passes), `N=2 → 2`.

"It got dropped in the rewrite" is the mechanism, not an excuse. "Does the
rewritten validator still enforce every previously-agreed security invariant?"
must be a **mandatory review checklist item** on any security-sensitive rewrite.
It wasn't. That is a review failure.

**Codex round-1 correction to this note:** the framing "I only missed the floor"
was itself wrong. This document's first draft _also_ (a) missed that "currently
staked" is not enforced at validation, (b) misclassified eligible-set accounting
as liveness-only, (c) stated a `⌈2N/3⌉`-of-committee invariant the contract does
not implement (quorum is over the _nominal_ target `m`, not the realized set),
and (d) overclaimed a live-set halt in P6. The real first task is the
**invariant specification** (§0.5), not Solidity.

---

## 0.5 Invariant specification — THREE decisions (LOCKED 2026-08-19)

**Owner-adjudicated: D1a + D2b + D3a.** Consequences: D1a = paper-wording only
(no code); D3a = P6 live-halt withdrawn; **D2b = the one pillar that needs real
engineering — see §2.5 for its cheap-vs-expensive fork and two blocking
dependencies.** Options preserved below for the record.

**D1 — Quorum semantics.** The contract requires `⌈2m/3⌉` signatures where
`m = expectedCommittee(n)` is the _nominal_ DSR committee target, and the
_realized_ oversampled committee is ~`1.25m` (can exceed `2/3`-of-realized).
Options:

- **D1a (recommended, = current impl):** quorum = `⌈2m/3⌉` over the nominal DSR
  target `m`; safety rests on the analytical two-tail bound (forgery ≤1e-6 @
  β≤10%), **not** on "2/3 of the realized committee." Paper must state it this
  way (no "2/3 of the committee" phrasing).
- **D1b:** require `⌈2/3⌉` of the _realized_ selected committee. Changes the
  security math and the DSR curve. Larger change.

**D2 — Meaning of "staked/eligible" at validation.** Today validation checks
only `isRegistered && !isBootstrap` (`AAStarCommitteeValidator.sol:508`); actual
stake is checked at **registration** or when someone calls `syncNode()`.
Options:

- **D2a (weaker, = current impl):** "registered-as-staked, not yet evicted by
  `syncNode`." Cheap. A node that unstakes keeps signing until synced. Must be
  **disclosed** as the real economic-security model (not "currently staked").
- **D2b (stronger, real intent):** "currently staked." Requires an on-chain
  synchronization architecture — Registry callback / unbonding hook / mandatory
  `syncNode` before an epoch counts a node — so stake loss reaches this
  validator. This is the **hardest** part of the whole change (cross-contract
  state).

**D3 — Does the ≥3 floor apply to the frozen snapshot only, or also the live
eligible set mid-epoch?**

- **D3a (recommended, standard BFT):** floor applies to the **frozen epoch
  committee**. 2-of-frozen-3 remains valid even if a node deactivates mid-epoch
  — that is exactly the `f=1` fault tolerance, not a hole. P6's "live halt"
  claim is **withdrawn**. Safety against churn comes from D2 (stake) + short
  epochs, not from a live-set recount per op.
- **D3b:** additionally gate each op on a **current** eligible count ≥ 3. Needs
  live eligible accounting in `validate()` (interacts with D2b). Stricter, more
  gas, more surface.

> Working recommendation: **D1a + D2b + D3a.** D1a/D3a match the deployed
> BFT/DSR design and only need honest paper wording. D2b is the one that costs
> real engineering and is the true economic-security fix — it is what "no stake
> ⇒ no cost to misbehave" demands. Confirm before code.

---

## 2.5 D2b architecture — "currently staked" without breaking ERC-4337 validation

Primitive that exists: `_isStaked(op)` is a synchronous view =
`registry.hasRole(ROLE_DVT, op) && getEffectiveStake(op, ROLE_DVT) >= minStake`
(`AAStarValidator.sol:934`). `syncNode(nodeId)` (`:924`) permissionlessly evicts
a node whose `_isStaked` is now false — **pull-based**. Committee `validate()`
today checks only `isRegistered && !isBootstrap`
(`AAStarCommitteeValidator.sol:508`), never `_isStaked` → the "not-yet-evicted"
gap.

**Constraint that shapes everything:** `validate()` runs in the ERC-4337
**validation phase**. It deliberately reads only the validator's OWN storage
(frozen seed/root/count/isRegistered) to stay within ERC-7562 storage-access
rules. A per-signer external Registry read inside `validate()` (Option A below)
very likely makes ops un-bundleable. **Verify this before choosing.**

Options:

- **A — per-signer `_isStaked` in `validate()`:** authoritative, no new
  architecture (reuse the view), but (i) k extra Registry staticcalls of gas and
  (ii) **probably violates ERC-7562** validation-phase storage rules. Likely
  non-viable.
- **B — snapshot-time stake-clean + unbonding ≥ epoch (recommended):** keep
  `validate()` reading only own frozen state (ERC-7562-clean). Ensure the frozen
  set is stake-clean at freeze (either `snapshotEpoch` verifies `_isStaked` per
  node in that permissionless **keeper** tx — O(N) staticcalls are fine OUTSIDE
  validation phase — or unstaked nodes are `syncNode`-evicted before freeze).
  Rely on SuperPaymaster **unbonding delay ≥ epochLength** so a node staked at
  freeze[e-1] stays slashable through epoch e. Then "staked at snapshot" ⟹
  "economically bonded through the epoch" = the D2b guarantee, with zero
  Registry reads in validation phase.
- **C — `lastVerified[nodeId]` freshness gate:** bounded staleness; more state,
  weaker than B.

**Two blocking dependencies before coding D2b:**

1. **(cross-repo, SuperPaymaster)** Does ROLE_DVT stake have an
   **unbonding/withdrawal delay ≥ epochLength**, and does `getEffectiveStake`
   stay bonded-until-unbonding (vs dropping to 0 on withdrawal-initiation)? This
   decides whether B is sound. → open a CC question to `repo:sp`.
2. **(ERC-4337)** Confirm a per-op external Registry read in `validate()`
   violates ERC-7562 (kills Option A). If it somehow does not, A becomes a
   viable authoritative fallback.

Working plan: pursue **B**. It needs `snapshotEpoch` to become stake-aware
(verify `_isStaked` at freeze) + a documented `epochLength ≤ unbondingDelay`
invariant.

---

## 1. The invariant (precise, pending D1–D3)

> When committee mode is active, any accepted tier-2/3 aggregate carries
> `≥ ⌈2m/3⌉` signatures from **cryptographically distinct public keys**, where
> `m = expectedCommittee(n)` is the nominal DSR committee target over the
> **frozen** look-ahead pool `n = epochSetCount[e-1]`; that frozen pool was
> formed from nodes that were **eligible** (registered ∧, under `requireStake`,
> backed by ≥ `minStake` at snapshot time per D2) and had size
> `n ≥ minCommittee (= 3)`. Safety of `⌈2m/3⌉` over the oversampled realized
> committee rests on the analytical two-tail bound, not on "2/3 of the realized
> set."

Note the deliberate separation of **pool `n`** / **nominal target `m`** /
**realized selected committee** — conflating them is the §0.5-D1 error.

---

## 2. Pillars (revised after Codex round-1)

### P1 — MIN_COMMITTEE floor over the frozen pool (core safety)

- `minCommittee` (default 3), `setMinCommittee(v)` onlyOwner `require(v>=3)`
  raise-only, **bumps `configVersion`**.
- `validate()`: `if (committedCount < minCommittee) return 1;` (`committedCount`
  already loaded, ≈0 gas).
- `requiredQuorum()`: `committedCount < minCommittee → return type(uint256).max`
  (fail-closed sentinel path).
- **Depends on P3 for correctness**: the floor is only meaningful if
  `committedCount` counts _eligible_ nodes (see P3).

### P2 — activation semantics + legacy fallback (Codex High #5)

- Do **not** `require(setCount>=min)` in `snapshotEpoch()` (reintroduces the
  round-2-High pinning DoS). Min lives on the read side (P1). Activation-floor
  semantics then come for free **without** bricking future epochs.
- **RESOLVED (CC-116) — enforced at the ACCOUNT layer, option (i).**
  `epochLength == 0` still falls back to `_validateWholeSet`, which has no floor
  and no quorum. That is unchanged and deliberate: giving the fallback its own
  quorum is exactly the non-scaling global-⌈2N/3⌉ model CC-97 rejected
  (registration is unbounded, so the quorum eventually exceeds `MAX_NODE_COUNT`
  and fails the whole network closed).

  The floor for that window lives on the account side instead, and is now a
  merged on-chain guarantee rather than a runbook promise (`airaccount-contract`
  #208, merged `72d2311`, v0.32.0). `_blsAlgMode()` distinguishes **three**
  states where the old code collapsed two:

  | `committeeActive()` | validator state                                      | account behaviour                             |
  | ------------------- | ---------------------------------------------------- | --------------------------------------------- |
  | `true`              | armed (`epochLength != 0`)                           | accountId injection + `requiredQuorum` mirror |
  | `false`             | mounted but NOT armed                                | **tier-2/3 fails closed**                     |
  | reverts             | a true legacy validator (`0x539B`, no such function) | whole-set passthrough, long-term coexistence  |

  Gated at all three BLS entry points, and in `_validateTripleSignature` the
  gate sits **before** the aggregator deferral so a validator exposing a
  non-zero `aggregator()` cannot route around it. pr-daemon verified each gate
  with two-directional mutation (delete a gate → its test reddens; move the
  triple gate after the deferral without deleting it → only the ordering test
  reddens), and **enumerated the `_blsAlgMode()` / `_verifyAgg` call sites** to
  establish there is no fourth BLS path. Codex independently confirmed three
  adjacent properties — the owner-direct and executor paths force ECDSA, the
  fallback exposes no execution entry point, and `executeUserOp` refills the
  session context before the delegatecall. It is the two together that close "no
  fourth path"; neither does it alone.

  **The DVT-side precondition this relies on, verified here:**
  `committeeActive()` returns `epochLength != 0`
  (`AAStarCommitteeValidator.sol`), so an unarmed committee validator returns
  `false` rather than reverting; and the base `AAStarValidator` does not declare
  the function at all, so a true legacy validator reverts. The three account
  states therefore map onto three genuinely distinct validator states.

  Consequence for the cutover: during enroll → flip, tier-2/3 on this validator
  is **unavailable**, not unprotected. That unavailability is the intended
  fail-closed posture, not a downside — an earlier round of this discussion had
  it backwards and treated it as a cost to be mitigated by operational
  discipline.

### P3 — eligible-set accounting: SAFETY-critical, not liveness-only (Codex High #3)

- **Bug:** `activeCount`/`epochSetCount` count **all registered incl. retired
  bootstrap**; eligibility filtered only at signer-verify (`:508`). Two effects,
  now correctly classified:
  - **Safety:** once `committedCount` feeds the P1 `N≥3` gate, an inaccurate
    count (e.g. 1 real staked + 2 stale bootstrap = "3") **defeats the
    minimum-population predicate**. This is a safety role, correcting the first
    draft's "never a safety hole."
  - **Liveness:** inflated quorum denominator / wasted sortition slots.
- Fix: the committee SMT/count == the **eligible** set; eligibility transitions
  (stake add/remove per D2, bootstrap retire, `requireStake` toggle) are set
  mutations. Under `requireStake=OFF` (current) this is latent.
- **Coupled to D2b**: "eligible = currently staked" requires the same
  Registry-sync architecture. P3 is the **hard** pillar, not "modest."

### P4 — distinct keys across ALL key-state transitions (Codex Medium #6/#7)

- Staked path already byte-unique: `nodeId=keccak(pubkey)`
  (`AAStarValidator.sol:874`), no key update (`:981`), deactivate clears
  (`:941`). **Caveat:** this proves _encoding_ uniqueness, not distinct
  operators/beneficial owners.
- Bootstrap gap: `registerPublicKey`/`batchRegisterPublicKeys` bind no
  nodeId↔pubkey → owner can dup a pubkey.
- Fix (reverse lock `pubkeyHash → nodeId`) must cover **every** transition
  atomically: register, **batch incl. intra-batch dups**, **`updatePublicKey`
  (`:993`)**, deactivate, revoke. Hash the **canonical** G1 encoding.

### P5 — configVersion / reconciliation on EVERY eligibility or safety-math param (Codex Medium #8)

> **What P5 does NOT do (Codex round-2 High).** Bumping `configVersion`
> invalidates snapshots pinned under the OLD policy; it does **not** make the
> NEXT snapshot stake-clean. Nodes stay `isRegistered` until `syncNode` evicts
> them, so after e.g. raising `minStake` above the incumbents' balances, two
> fresh snapshots under the new version still record the same `N`, and those
> economically-ineligible nodes can still satisfy the floor and the quorum.
> Closing that is exactly **P3 + P8** (eligible-set accounting + "currently
> staked"), which are blocked on the SuperPaymaster unbonding facts (CC-112).
> **The floor (P1) is therefore a floor on the FROZEN REGISTERED pool, not yet
> on a stake-verified pool** — do not read P5 as closing eligibility.

- Already bumps: `setEpochLength`, `setOversample`. Add: `setMinCommittee`.
- **Missing bumps/reconciliation:** `setRequireStake` (`:965`), **`setRegistry`
  (`:960`)**, **`setMinStake` (`:970`)** — all change which frozen nodes still
  qualify. Each needs configVersion bump or a defined re-snapshot/reconciliation
  path.

### P6 — churn behaviour (CORRECTED; claim withdrawn)

- **Withdrawn:** first draft claimed "eligible set < min ⇒ tier-2/3 halts."
  Under D3a (frozen committee) it does **not**, and should not — 2-of-frozen-3
  after one node leaves is intended `f=1` tolerance. If D3b is chosen instead,
  this becomes a real live-count gate in `validate()`.
- Retained: `committeeHealthy()` view is **not just polish** (Codex Low #9) —
  external systems need to distinguish "frozen quorum says 2" from "only 1 live
  eligible signer remains." Expose: snapshot usability, frozen eligible count,
  current synced eligible count, minCommittee, nominal `m`, required signatures,
  configVersion.

### P7 — account-side mirror (airaccount-contract; cross-repo)

- Propagate `minCommittee` to the account's independent quorum recompute —
  **only** valid if it uses byte-identical definitions (same `m`, same eligible
  count) and cannot diverge. Separate PR via CC, sequenced with cutover.

### P8 — currently-staked enforcement (NEW pillar; Codex Critical #2) — only if D2b

- If D2 = D2b: validation (or the epoch snapshot that admits a node) must
  reflect **current** stake, via Registry callback / unbonding hook / mandatory
  `syncNode` freshness. Without it, "staked committee" is really "was-staked,
  not-yet-evicted." This is the substance of the economic-security fix and the
  gate on batching.

### P9 — adversarial test matrix (expanded per Codex)

- N=1/2 rejected (validate + `requiredQuorum` sentinel); N=3 passes; identical
  crypto, **only N varies**.
- `setMinCommittee` floor; raising min invalidates old snapshot via
  configVersion.
- **Frozen N=3, deactivate one, remaining two validate** (asserts the D3a/D3b
  decision).
- **3 registered staked, 2 lose stake without `syncNode`, aggregate attempted**
  (asserts D2a/D2b); and after only 1 synced.
- `setRegistry` / raise `minStake` / toggle `requireStake` around a pinned
  snapshot.
- `epochLength==0` with 3 registered + 1 signer (asserts P2 fallback decision).
- Dup key via `updatePublicKey`; dup keys within one batch; same G1 point in two
  encodings.
- Separate assertions for pool `n`, nominal `m`, realized selected count,
  oversampled target (asserts D1a wording).

---

## 2.9 D2 as built (CC-112 answered; P3 + P8 implemented)

SuperPaymaster answered the two blocking questions (CC-112 `49ffcae0`), and DSR
confirmed both follow-ups with source evidence (`b726b6a0`). Option **B** is
implemented:

**Eligibility is decided in the permissionless keeper's `snapshotEpoch`, never
in `validate()`** — so the validation phase still reads only this contract's own
storage and stays inside ERC-7562. The predicate is:

1. `hasRole(ROLE_DVT, op)` and `getEffectiveStake(op, ROLE_DVT) >= minStake`
   (i.e. the existing `_isStaked`, so eligibility cannot drift from `syncNode`);
2. `blsAggregator.guardianExitRequests(op).readyAt == 0`;
3. bootstrap nodes: `!requireStake` — the exact mirror of `syncNode`'s
   predicate.

`snapshotEpoch(bytes32[] activeNodeIds)` now takes the complete active set and
**proves** completeness rather than trusting it: strictly increasing (no
duplicates) + every entry currently holds a slot + exactly `activeCount` entries
⟹ the list is precisely the active set. Any omission would need a duplicate or a
non-member to pad it, and both are rejected.

### Why `readyAt == 0` is stricter than SP suggested

SP proposed `readyAt == 0 || readyAt > snapshotTime + epochLength`. We take only
the first disjunct. `readyAt` is **seconds**; `epochLength` is **blocks**.
Writing SP's condition on-chain would weld a block-time assumption into a
**non-upgradeable** validator, and a block-time change would loosen it
_silently_ instead of failing closed. The stricter rule needs no conversion, is
a subset of SP's, and matches SP's own look-ahead accounting, which already
excludes any guardian with `readyAt != 0`. Cost: a guardian that filed and then
cancelled an exit rejoins at the next snapshot — SP already imposes a 1-day
cancel cooldown, so this adds nothing material.

### The bond is enforced on the CLOCK, not on a block count

An earlier draft bounded `epochLength` so that
`2 * epochLength * 1s <= GUARDIAN_EXIT_DELAY`, calling 1s/block "the
conservative direction". **That reasoning was backwards.** Bounding how long
`2L` blocks take needs an _upper_ bound on block time; a lower bound proves
nothing. At a real ~12s/block the accepted `L = 86400` spans ~24 days, during
which a guardian can complete `exitRole` and withdraw while the old root is
still serving committees — precisely the invariant this pillar claims.

Replaced with a wall-clock deadline: each snapshot records
`epochSetValidUntil[e] = block.timestamp + GUARDIAN_EXIT_DELAY`, and
`_epochUsable` fails closed past it (strictly — SP admits an exit at
`block.timestamp == readyAt`). The guarantee then holds at any block time and
survives a chain halt.

**But deleting the broken bound deleted a correct one with it.** Safety no
longer depends on block time; **liveness still does**. `validate` requires both
`_epochUsable(e)` and `_epochUsable(e-1)`, so `setRoot[e-1]` must remain
unexpired throughout `e`. If one epoch's wall-clock length approaches the bond
window, the look-ahead set is already expired every time it is needed and
committee mode fails closed **permanently** — from a governance call that looks
legitimate, on a contract that cannot be upgraded. An intermediate revision of
this branch even had a test _blessing_ `L = 200000` (~27.8 days per epoch at
12s).

`setEpochLength` therefore carries the same inequality with the direction fixed:
`2 * epochLength * MAX_BLOCK_SECONDS < GUARDIAN_EXIT_DELAY`, with
`MAX_BLOCK_SECONDS = 24` (sustained missed slots at Ethereum's 12s cadence),
capping `L` at 3599 — about 12 hours per epoch at 12s. Here **over**-estimating
block time is the conservative direction: it shortens the accepted epoch. Being
wrong costs liveness, which fails closed and is visible — never the silent
relaxation the previous bound would have produced.

### A ROLE_DVT exit notice needs its own permissionless eviction

`snapshotEpoch` refuses a set containing a node with `readyAt != 0`, but
`syncNode` only knows about role/stake/bootstrap — and SP deliberately keeps
**both** role and stake intact for the whole 2-day notice. So `syncNode` reverts
`Node still active` while `snapshotEpoch` reverts `ineligible node`, and no
permissionless action breaks the tie: **one ordinary exit would halt committee
mode for two days.**

`syncExitNotice(nodeId)` closes that. Its predicate is deliberately narrow — an
in-flight exit notice, nothing else — rather than `!_isEligibleForSnapshot`,
which would let anyone empty the whole set whenever `blsAggregator` is unset.

### The aggregator is bound to the Registry, not configured by hand

SP exposes `Registry.setBLSAggregator` and `queueBLSAggregator`/
`applyBLSAggregator`, and CC-115 B3 is explicitly a _successor_ deployment, so
the address **will** change within this validator's lifetime.

`setBlsAggregator` therefore requires the address to equal
`Registry.blsAggregator()`, and `snapshotEpoch` re-checks that equality whenever
the set contains a staked node. An ABI-surface probe alone is not identity: any
contract with a fallback returning 64 zero bytes passes it. Without the Registry
check, a rotation would leave the validator reading the OLD ledger, which
reports "no notice" for one filed on the new aggregator — a silent fail-open.

A change **bumps `configVersion`**, failing every already-pinned snapshot
closed. Rotation therefore causes a deliberate, documented outage of at least
the current epoch; the migration order is in `docs/DVT_OPERATIONS.md`.

### Same-block mutations are included, not rejected

The block-start latch is gone. It existed so a permissionless `syncNode` could
not be atomically composed with the freeze to depress `epochSetCount`; that
defence is obsolete, because eviction can only remove a node the Registry itself
judges stale, so depressing the count is now the _correct_ outcome.

An intermediate revision reverted on **any** same-block mutation instead. That
was both unnecessary and harmful: the real pin window is
`min(256, epochLength - 1)` blocks — only 63 at `L = 64`, not 256 — so an
attacker holding that many staked operators could register one per block and
deny every keeper for the whole window (stake is locked, not spent). A list
captured before a same-block mutation is rejected on its own terms by the
completeness check, not by a block-number guard.

### Boundary 2 (in-epoch slash): an EXPLICIT NON-CLAIM

- **Claimed.** Every frozen signer held bonded, slashable stake at freeze time
  and cannot have withdrawn it while the snapshot is still usable (the bond
  window is enforced on the clock, above). "Misbehaviour has a cost" holds.
- **NOT claimed.** That every signer stays `>= minStake` for the whole epoch. A
  mid-epoch `slashByDVT` breaks it without any exit flow.
- **Liveness semantics (CORRECTED).** An earlier draft claimed a slashed node
  "stays in the frozen set and keeps signing". **That is false.** Slashing makes
  it `syncNode`-able immediately, and `_deactivate` clears `isRegistered`, which
  `_verifyCommitteeSigners` reads live — so it stops being able to sign at once.
  What survives is the frozen **denominator**: `epochSetCount` is immutable once
  pinned. That makes an in-epoch slash a **liveness** cost — the quorum still
  asks for ⌈2m/3⌉ of the frozen population while the signable population has
  shrunk — rather than a safety one. The next snapshot excludes it.

Pinned at the `validate` level by
`test_a_node_removed_mid_epoch_cannot_sign_while_the_frozen_denominator_stays`
(AAStarCommitteeValidator.t.sol), and at the snapshot level by
`test_in_epoch_slash_evicts_the_node_but_never_rewrites_the_frozen_set`.

---

## 3. Redeploy analysis — batch or not

`AAStarCommitteeValidator` is **non-upgradeable**: any `.sol` change ⇒ new
address + router re-mount + re-enroll + testnet cutover + paper re-pin. That
ceremony is identical for every pillar, so **batch P1+P3+P4+P5 (+P8 if D2b) into
ONE new validator version, ONE deploy** rather than paying the ceremony 3×.

**Codex caveat (accepted):** the batching is economically right, but P3/P8 are
**not modest** — under D2b they add cross-contract stake synchronization, the
hardest part. So batching is correct **but gated on the §0.5 decisions**: define
D1/D2/D3 first, because they determine whether P3/P8/P6 are in-scope at all.

| Pillar                     | Redeploy?             | Notes                                                |
| -------------------------- | --------------------- | ---------------------------------------------------- |
| P1 floor                   | yes                   | trivial code, depends on P3 for meaning              |
| P3 eligible-count          | yes                   | hard under D2b (Registry sync)                       |
| P4 key-uniqueness          | yes                   | base registration path; all transitions              |
| P5 configVersion/reconcile | yes                   | folded into P1/P3                                    |
| P8 currently-staked        | yes (if D2b)          | the real economic fix                                |
| P6 health view             | yes if on-chain       | off-chain monitoring from existing events needs none |
| P7 account mirror          | separate (airaccount) | coordinated with cutover, not a validator redeploy   |
| P9 tests                   | no                    | verification                                         |

**Sequencing:** resolve D1/D2/D3 → one PR (separated commits per pillar) →
pr-daemon + Codex review → new deploy (default state + fallback decided) →
router re-mount + re-enroll → testnet cutover ("N=1 reject / ⌈2m/3⌉ pass /
unstaked-unsynced reject / dup-key reject") → owner enable → airaccount P7
mirror → DSR re-pin.

**Owner-flagged:** current chain `requireStake = OFF` (bootstrap, deploy
default, 3 bootstrap nodes). Stated intent: production must be staked. The
OFF→ON flip is the economic-security switch and interacts with D2b.

---

## 3.5 Codex round-2 (pre-PR review of the P1+P4+P5 branch)

Verdict: reject-as-complete, 2 High + 2 Low. Neither High is a defect introduced
by this change; both are unclosed parts of the overall objective, now recorded
rather than implied-closed:

- **High — P5 permits a stale "new-policy" snapshot.** See the note in P5 above.
  Deferred to P3/P8, blocked on CC-112. Action taken: framing corrected
  everywhere (commit, PR, this doc); no claim that eligibility is closed.
- **High — `epochLength == 0` keeps the original single-signer path.** RESOLVED
  by CC-116 at the account layer (see P2 above): `airaccount-contract` #208
  (merged `72d2311`, v0.32.0) fails tier-2/3 closed whenever the mounted
  validator reports `committeeActive() == false`. The whole-set fallback in this
  contract is unchanged, because giving it a quorum is the non-scaling model
  CC-97 rejected.

Codex confirmed solid: no bypass of the floor with committee mode active;
correct bind/unbind ordering on every key transition (revoke, `syncNode`,
update, re-register) with atomic rollback on failure and no stranded keys;
config bumps cannot permanently brick committee mode (worst case ~2 epochs of
fail-closed outage until re-pinned); storage layout safe for this fresh-deploy,
non-proxied model.

---

## 4. Honest status

First draft over-scoped "彻底" as "audit everything" **and** still under-covered
the real fault set (Codex found the staked-at-validation hole, the
nominal-vs-realized quorum overclaim, the P3 safety role, the fallback window,
and extra config/transition paths). Corrected: the fault set is **not closed**
until D1/D2/D3 are decided. P1 alone is not the whole security fix once D2/D3
are on the table.
