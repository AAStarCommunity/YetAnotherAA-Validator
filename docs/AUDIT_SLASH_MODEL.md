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

| Penalty        | What                                                       | Evidence bar                                            | Decision                     |
| -------------- | ---------------------------------------------------------- | ------------------------------------------------------- | ---------------------------- |
| **SLASH**      | burn the operator's **stake** (irreversible)               | OBJECTIVE + ATTRIBUTABLE + globally-verifiable on-chain | BLS-quorum consensus         |
| **JAIL**       | stop **fee** + exclude from the active set (self-heals)    | objective on-chain liveness                             | deterministic auto-jail (SP) |
| **REPUTATION** | a public **credibility score** (no penalty, informational) | on-chain economic facts                                 | on-chain view (auto)         |

> Lesson (#202): a DVT node is only **slashed** for
> objective+attributable+globally-verifiable evidence. Subjective /
> absence-based signals (e.g. gossip heartbeat absence) must NOT slash — they
> JAIL at most. `fee` today is a reserved semantic (the infra fee/profit-sharing
> layer isn't live yet); the concrete teeth of jail right now is **exclusion
> from the active set / quorum denominator**.

## 3. The four rules — final handling

| #   | Rule              | Handling                                                      | Why                                                                                                                   |
| --- | ----------------- | ------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| ①   | credit-over-limit | **sign-gate REFUSE** (not slash)                              | an individual over their limit is refused at sign time; slashing an _operator's_ stake for a member's credit is wrong |
| ②   | offline           | **auto-jail** (SP `LivenessRegistry`) + gossip soft signal    | liveness is an objective on-chain fact (`block.number > lastLive + window`); jail (fee-stop), not stake-slash         |
| ③   | over-issue        | **on-chain credibility score** (not slash, not DVT-disclosed) | `credibilityScore()`/`isOverIssued()` are auto-computed on-chain views; consumers read them directly                  |
| ④   | proof-forgery     | **not done**                                                  | co-sign re-verification + on-chain aggregate rejection already block forged slashes; residual spam → reputation       |

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
- **Consumers read it directly** on-chain: SuperPaymaster (sponsorship
  decisions), wallets/dapps (token trust), users, AgentStore. DVT does nothing.

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
- Liveness / availability → **JAIL** (SP LivenessRegistry, not this pipeline).
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

### Worked example — offline-duration tiered slash (a FUTURE rule)

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
