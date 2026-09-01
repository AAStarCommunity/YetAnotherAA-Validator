# DVT Audit / Slash Model

> Authoritative model for how the DVT node enforces rules. Corrected after a
> design review (2026-07-09) that removed the credit① and over-issue③
> stake-slash rules. See PR #205.
>
> This doc covers the quorum auditing **operators**. For the inverse — slashing
> the **guardians** (co-signers) themselves when ≥m collude to pass a false
> slash — see
> [`design/guardian-collusion-slash.md`](design/guardian-collusion-slash.md)
> (CC-89, Protocol B).

## 1. Two enforcement mechanisms

|        | **Proactive sign-gate**                                                          | **Reactive audit**            |
| ------ | -------------------------------------------------------------------------------- | ----------------------------- |
| When   | BEFORE signing a UserOperation                                                   | AFTER the fact, on a schedule |
| Where  | `signature.service.ts` → `PolicyService.evaluate` → PolicyRegistry `checkPolicy` | `audit.service.ts` tick loop  |
| Effect | REFUSE to sign (`ForbiddenException`) — the op never happens                     | detect a violation → penalty  |

The two are independent. Credit/spending limits are a **sign-gate** concern
(refuse), not an audit concern.

## 2. Three penalty types — never conflate them

| Penalty        | What                                                       | Evidence bar                                            | Decision                                                                  |
| -------------- | ---------------------------------------------------------- | ------------------------------------------------------- | ------------------------------------------------------------------------- |
| **SLASH**      | burn the operator's **stake** (irreversible)               | OBJECTIVE + ATTRIBUTABLE + globally-verifiable on-chain | BLS-quorum consensus                                                      |
| **JAIL**       | stop **fee** + exclude from the active set (self-heals)    | objective on-chain liveness                             | deterministic, no quorum vote — **but see the ⚠️ below: not wired today** |
| **REPUTATION** | a public **credibility score** (no penalty, informational) | on-chain economic facts                                 | on-chain view (auto)                                                      |

> Lesson (#202): a DVT node is only **slashed** for
> objective+attributable+globally-verifiable evidence. Subjective /
> absence-based signals (e.g. gossip heartbeat absence) must NOT slash — they
> JAIL at most. `fee` today is a reserved semantic (the infra fee/profit-sharing
> layer isn't live yet); the intended teeth of jail are **exclusion from the
> active set / quorum denominator**.
>
> ⚠️ **Jail has NO teeth today — it is not implemented anywhere.** Committee
> eligibility checks stake, role and guardian-exit state and **never reads
> `isOffline`** (`AAStarCommitteeValidator.sol:460-469`); `LivenessRegistry`
> advertises "zero SuperPaymaster-core coupling" (`:13`). There is no auto-jail
> in either repo — only a deployed signal with no consumer.
>
> ⚠️ **Do not over-read that lesson.** It disqualifies **gossip absence** as
> evidence, not **liveness** as an offence. CC-29's on-chain `isOffline(op)`
> (`block.number - lastLive > window`, with never-attested ⇒ `true`) is a far
> better signal than a heartbeat. So stake loss and JAIL are **not
> alternatives** for liveness — they are **two independent layers on one time
> axis**: jail removes the node from service while it is offline, and the burn
> accrues over that same interval. Neither carries out the other; jail alone
> takes no stake, and a burn alone would leave an unreachable node sitting in
> the quorum.
>
> **Terminology:** that burn is a **leak**, not a slash — it is _intended_ to be
> settled by computation rather than by a quorum vote, so none of the
> voted-slash machinery applies. "Intended": no settlement mechanism exists yet.
> [`design/offline-penalty-escalation.md`](./design/offline-penalty-escalation.md)
> is authoritative on this rule; §3.2 below is a summary that defers to it.
>
> ⚠️ And do not over-read _this_ correction either: `isOffline` proves only that
> the operator's key sent a transaction recently. It explicitly does **not**
> prove the DVT stack is online (`LivenessRegistry.sol:21,28`), so an operator
> that attests while refusing to co-sign is invisible to it.

## 3. The four rules — final handling

| #   | Rule              | Handling                                                      | Why                                                                                                                                                                                                                                |
| --- | ----------------- | ------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ①   | credit-over-limit | **sign-gate REFUSE** (not slash)                              | an individual over their limit is refused at sign time; slashing an _operator's_ stake for a member's credit is wrong                                                                                                              |
| ②   | offline           | **tiered LEAK + jail** — DESIGN SKETCH, see §3.2              | liveness is the archetypal punishable behaviour (Jason, 2026-09-01); jail and the burn are parallel layers, not one executing the other. CC-29 IS deployed — what is missing is the settlement state a leak needs, plus the N gate |
| ③   | over-issue        | **on-chain credibility score** (not slash, not DVT-disclosed) | `credibilityScore()`/`isOverIssued()` are auto-computed on-chain views; consumers read them directly                                                                                                                               |
| ④   | proof-forgery     | **not done**                                                  | co-sign re-verification + on-chain aggregate rejection already block forged slashes; residual spam → reputation                                                                                                                    |

### ② offline — tiered leak + jail (DESIGN SKETCH, not built, not yet specifiable)

**Corrected 2026-09-01.** This document previously said liveness is "jail
(fee-stop), **not** stake-slash". That is wrong as a statement of intent. Jason,
asked directly:

> 存活时间就是最典型的可罚行为。如果存活时间低于多少小时,就要 slash
> —— 这是网络稳定的保障。slash 的方式是先 put in
> jail,恢复了就上线。**但可以设定不同的时限、slash 不同的额度**,这一定要有,否则都掉线了,网络就宕机了,还提供什么整体service。

So the intended shape is:

| element    | intent                                                                                                                                                                         |
| ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| offence    | **continuous** downtime past the liveness window, counted in escalation periods, the escalation level decaying during uptime (design doc §4) — NOT a lifetime cumulative total |
| evidence   | CC-29 `LivenessRegistry` — but see §5 of the design doc: the registry's **current state is not sufficient** to settle money                                                    |
| penalty    | **a LEAK — a stake burn tiered by outage duration**, intended to settle by computation rather than by a BLS-quorum vote (no settlement mechanism exists yet)                   |
| jail layer | runs in parallel over the same interval — fee stopped + excluded from the active set. Does NOT carry out the burn, and the burn does not carry out it (both unbuilt)           |
| recovery   | self-healing — attest liveness again and the node re-enters the set                                                                                                            |

> **This rule does NOT travel the §5 playbook.** It files no proposal, gathers
> no co-signatures and produces no slash message. Everything below about pinned
> blocks, proofHashes and quorum re-verification applies to _voted_ rules and
> **not** to this one.

Five things are missing before this can be specified, let alone armed:

1. **The evidence source IS deployed — this document previously said it was not,
   and that was wrong.** `LivenessRegistry-1.0.0` is live on Sepolia at
   `0x02d841F7905aFb4424DBA71680D27C0F75d36BE7` with `livenessWindow() = 300`.
   The error came from reading a config default
   (`AUDIT_LIVENESS_REGISTRY_ADDRESS` defaults to `""`,
   `src/config/configuration.ts:350`) as evidence about the chain. **An unset
   client config is not an absent contract.**

   What is actually missing is smaller and fixable: the address is not in any
   node's env, and **no operator has ever attested** (`lastLive == 0` fleet-wide
   ⇒ `isOffline == true` for everyone). DVT already holds the locked read ABI
   (`blockchain.service.ts:653-657`) and the attest keeper
   (`liveness-keeper.service.ts`); pointing them at that address is a config
   change, not a build — **but that only enables the nodes to ATTEST.** It
   builds no jail, no exclusion and no penalty; those consumers do not exist
   (see the ⚠️ in §2).

   **Unit is BLOCKS**, confirmed at source, not inferred:
   `_lastLive[msg.sender] = block.number` and
   `isOffline ⇔ block.number - last > _livenessWindow`
   (`LivenessRegistry.sol:101,123`). DVT's existing assumption (blocks) is
   correct. 300 blocks ≈ 60 min on Sepolia.

   Until an operator attests, the only liveness signal DVT actually has is the
   gossip heartbeat — which §2 correctly forbids as slash evidence.

2. **The tier table does not exist.** "不同的时限、不同的额度" needs concrete
   (duration → burn) rows with **explicitly defined units**, and they must be
   **on-chain governance values with versioned activation blocks, or snapshotted
   into the outage episode**. On-chain alone is NOT sufficient: `livenessWindow`
   and any tier value are mutable with immediate effect (the registry stores
   only the _current_ window in a single slot, `LivenessRegistry.sol:67`, read
   back by `livenessWindow()` at `:136`; the governance note at `:33` states
   that a change re-partitions the live set immediately), so if governance moves
   a parameter between the outage and its settlement, **the caller's timing
   selects which parameter set applies** — the very caller-dependence the leak
   exists to avoid. The requirement is not "on-chain", it is **"reconstructible
   for the epoch being charged"**. And not because a quorum has to agree on a
   message (there is no quorum here), but because a permissionless settlement
   whose result depends on who calls it is not a settlement. Today DVT's only
   offline threshold is the hard-coded, version-bound
   `OFFLINE_THRESHOLD_MS = 600_000` (`audit.service.ts:66`) — a gossip
   wall-clock number that deliberately enters the proofHash of the _voted_
   pipeline. It is **not** a candidate tier source.
3. **The asset is decided — GToken (Jason, 2026-09-02) — and that is what makes
   the margin load-bearing.** The two deployed burn paths hit different assets:
   DVT-originated operator slashing burns SP-held **aPNTs** (capped at 30%,
   `SuperPaymaster.sol:986`), while committee eligibility reads the **GToken**
   role lock (`Registry.getEffectiveStake` → `getLockedStake`). Burning GToken
   is the choice that actually reaches eligibility — and therefore the choice
   that walks straight into the zero margin measured in
   [`SLASH_ROLLOUT_GATE.md` §1](./SLASH_ROLLOUT_GATE.md), which is why Plan A
   (§7 there) is a precondition rather than a companion.
4. **Half the tier table LOOKS like it exists as dead config — but its units are
   undefined.** `IRegistry.RoleConfig.slashBase / slashInc / slashMax` carry
   live ROLE_DVT values on-chain (`2 / 1 / 10`) and are read by **no** code in
   SP's `contracts/src/`. The interface calls them slash _amount_ / _increment_
   / _maximum_ — **not** percentages — so reading `2` as "2%" is archaeology,
   not a citation. Reuse the fields if the units are defined explicitly (basis
   points), bounds-validated and migrated deliberately; but do not leave a
   configured-looking escalation policy that nothing honours.
5. **The settlement state the leak needs does not exist.** `lastLive` is a
   single overwritten slot, so an operator can erase weeks of downtime with one
   attestation before settlement; there is no idempotency checkpoint, no episode
   start, and no stored registration stake. This is the blocking item — see
   [`design/offline-penalty-escalation.md` §5](./design/offline-penalty-escalation.md).

Until those are settled, "offline cannot slash today" remains a true statement
about **capability**. It is not a statement about **design intent**, and this
document should never again be read as saying liveness is not worth punishing.

### ③ economic credibility — an on-chain view (CC-28, SP-side)

Computed live on every read from current state — no DVT compute, no stored
score:

```
issuedValueUSD  = totalSupply × aPNTsPriceUSD / exchangeRate         (ceil)
backingValueUSD = staked aPNTs (canonical SP) × aPNTsPriceUSD         (only if operator configured + linked)
effectiveCapUSD = industryScaleUSD[category] × capRatioBps/10000  +  backingValueUSD
credibilityScore = min(100, backingValueUSD / issuedValueUSD × 100)   // backing coverage %
isOverIssued     = issuedValueUSD > effectiveCapUSD  (or issuanceCap breach; renounced-factory ⇒ flag)
```

- Backing = **stake + (future) committed redemption services** (MyShop via a
  pluggable `IBackingSource`, deferred; today: SP-staked aPNTs only).
- Baseline is per-industry, factory-governed (default ~$10k; e.g. foreign-trade
  higher), adjusted via the community multisig — a community can't self-pick a
  high baseline (category is `onlyOwner` factory governance).
- **Consumers are INTENDED to read it directly** on-chain: SuperPaymaster
  (sponsorship decisions), wallets/dapps (token trust), users, AgentStore. DVT
  does nothing. ⚠️ As of 2026-09-02 **there are no actual consumers yet** — grep
  finds no call to `credibilityScore()` or `isOverIssued()` anywhere in SP's
  `contracts/src/` outside the token itself. That is good news for the open
  question of where the serviceability cutoff lives (CC-118 discussion):
  unifying it on-chain now costs no migration, because nothing has hard-coded a
  threshold yet.

> **When may it be turned on?** See
> [`SLASH_ROLLOUT_GATE.md`](./SLASH_ROLLOUT_GATE.md) — at N=3 one slash halts
> the whole stack, so the gate is a NODE-COUNT question, not a code-readiness
> question.

## 4. The slash pipeline is DORMANT (kept for the future)

There is **no active rule feeding the stake-slash pipeline** — at the 3-node
bootstrap, nodes are guaranteed online, so no slash is needed yet. The machinery
is retained, unarmed:

- Kept: `handleViolation` → `createProposal` → queue → execute,
  `GossipQuorumCoSigner` / `PendingSlotCoSigner` / `QUORUM_COSIGNER` factory,
  proof archive (`PROOF_SCHEMA_VERSION` unchanged).
- ① was the **only armed rule** (its `verifyViolationForCoSign` was
  credit-specific); removing it leaves the co-sign responder unarmed/dormant.

## 5. How to add a new DVT audit rule (playbook)

The audit pipeline is **rule-agnostic**. A rule plugs into this fixed flow:

```
enumerate targets → pin ONE finalized block → RULE predicate (deterministic)
  → content-address the proof (keccak of on-chain-only identity)
  → archive proof → file proposal (createProposal)
  → [if armed] BLS-quorum co-sign (each peer re-verifies from first principles)
  → queue → execute → slash stake
```

### Step 0 — decide the penalty (§2)

- Objective + attributable + globally-verifiable economic fraud → **SLASH**
  (this playbook).
- Liveness / availability → **a tiered LEAK, with JAIL as a parallel layer over
  the same interval** (§3.2). **Not this playbook.** A leak would settle by
  computation with no proposal, no co-signing and no quorum, so none of the
  steps below apply to it. It is a design sketch, not a decision that liveness
  goes unpunished — see
  [`design/offline-penalty-escalation.md`](./design/offline-penalty-escalation.md).
- Informational → **REPUTATION** (on-chain view; DVT doesn't act).

Only build a slash rule for the first case.

### Step 1 — the on-chain cooperation matrix (do this FIRST)

| The rule's evidence is…                                              | DVT work                                   | On-chain (SP) work                                     |
| -------------------------------------------------------------------- | ------------------------------------------ | ------------------------------------------------------ |
| a **pure on-chain view** (e.g. `isOverIssued`, a debt/limit compare) | predicate reads the view at a pinned block | **none** — machinery already deployed                  |
| **derived from existing on-chain state** but not a single view       | predicate composes reads deterministically | none, unless a helper view is cleaner                  |
| **new on-chain state that doesn't exist yet**                        | predicate reads the new view               | **SP must add the state + a `blockTag`-readable view** |

The execution machinery (`DVTValidator.createProposal` →
`BLSAggregator.verifyAndExecute` → `slashThresholds`) is **already deployed** —
waking a slash never needs new execution contracts, only (sometimes) a new
**evidence source**.

### Step 2 — DVT code changes (in this repo)

1. `blockchain.service.ts`: add a **read helper** for the rule's on-chain
   inputs, `blockTag`-capable (so every co-signer reproduces the same value at
   the epoch block). Model it on `getIsOverIssued`.
2. `audit.service.ts`: add a **predicate** method (`auditXxxForTarget`) — pin to
   the finalized block, read inputs, decide, and on a violation call the shared
   `handleViolation({ …, identity, … })`. Add its call in `tick()`. Add a
   `RULE_XXX` string + `SLASH_LEVEL_XXX` (`SlashLevel` enum).
3. `proof-archive.ts`: add the rule's **identity fields** to `ProofIdentity`
   (optional; `stableStringify` drops undefined). Do **NOT** change
   `PROOF_SCHEMA_VERSION` unless you break an existing rule's hash.
4. **Arm the responder** — add a `verifyViolationForCoSign`-style verifier that
   re-reads the SAME inputs pinned at `req.epoch` and re-derives the proofHash,
   and wire it via `armable.arm(...)` in `onApplicationBootstrap`. This is what
   makes the slash a **quorum** (peers independently confirm) — the
   innocent-operator defense. Without it the rule is file-only (proposal, never
   executes).
5. `configuration.ts`: add any `AUDIT_*` addresses/params + a fail-closed
   required-check.
6. Tests: predicate true/false branches, determinism (same proofHash across
   nodes at the epoch), dedup (one proposal per violation), evidence-never-lost
   (archive before propose), and the armed co-sign path.

### Step 3 — arming & rollout

- Keep it **file-only** first (`AUDIT_EXECUTE_SLASH` off) to observe proposals
  without slashing.
- Arm (`AUDIT_EXECUTE_SLASH=true`) only after the evidence is proven objective
  on the target chain.
- Every rejected/indeterminate read must **fail-safe** (no proposal), never
  fail-open.

### Worked example — offline-duration tiered penalty (SUPERSEDED, kept as an illustration of the playbook)

> ⚠️ **This worked example predates the 2026-09-02 design and no longer
> describes the intended rule.** It frames offline as a quorum-voted DVT slash;
> the **intended** shape is a permissionlessly-settled leak with no quorum at
> all — a sketch, not a built or fully specified mechanism
> ([`design/offline-penalty-escalation.md`](./design/offline-penalty-escalation.md)).
> It survives only as an illustration of how the generic **voted-rule** playbook
> is applied. **Do not read its analysis as applying to the leak** — its
> accumulated-downtime and tier reasoning was written for a quorum-voted message
> and understates what a permissionless settlement needs (design doc §5).

Goal: 1 day offline → 10% slash; 3 days → 30% + permanent-offline until stake
top-up.

- **On-chain (SP) work (required first):** `LivenessRegistry` today exposes only
  the _instantaneous_ `isOffline` / `lastLive`. This rule needs
  **accumulated-downtime** tracking + **penalty tiers** — new on-chain state + a
  `blockTag`-readable view (e.g. `offlineSinceBlock(op)` / `downtimeTier(op)`).
- **DVT work:** a read helper for the new view; a predicate that maps the tier →
  `SlashLevel` and a slash percentage; an armed verifier; config. The execution
  pipeline is unchanged.

Contrast: a rule like over-issue would have been **DVT-only** (its evidence
`isOverIssued()` is already an on-chain view) — but we chose to make over-issue
a **reputation** signal, not a slash (§3).
