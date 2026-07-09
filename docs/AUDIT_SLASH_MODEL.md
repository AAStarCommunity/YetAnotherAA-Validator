# DVT Audit / Slash Model

> Authoritative model for how the DVT node enforces rules. Corrected after a design review
> (2026-07-09) that removed the credit① and over-issue③ stake-slash rules. See PR #205.

## 1. Two enforcement mechanisms

| | **Proactive sign-gate** | **Reactive audit** |
|---|---|---|
| When | BEFORE signing a UserOperation | AFTER the fact, on a schedule |
| Where | `signature.service.ts` → `PolicyService.evaluate` → PolicyRegistry `checkPolicy` | `audit.service.ts` tick loop |
| Effect | REFUSE to sign (`ForbiddenException`) — the op never happens | detect a violation → penalty |

The two are independent. Credit/spending limits are a **sign-gate** concern (refuse), not an audit concern.

## 2. Three penalty types — never conflate them

| Penalty | What | Evidence bar | Decision |
|---|---|---|---|
| **SLASH** | burn the operator's **stake** (irreversible) | OBJECTIVE + ATTRIBUTABLE + globally-verifiable on-chain | BLS-quorum consensus |
| **JAIL** | stop **fee** + exclude from the active set (self-heals) | objective on-chain liveness | deterministic auto-jail (SP) |
| **REPUTATION** | a public **credibility score** (no penalty, informational) | on-chain economic facts | on-chain view (auto) |

> Lesson (#202): a DVT node is only **slashed** for objective+attributable+globally-verifiable evidence.
> Subjective / absence-based signals (e.g. gossip heartbeat absence) must NOT slash — they JAIL at most.
> `fee` today is a reserved semantic (the infra fee/profit-sharing layer isn't live yet); the concrete
> teeth of jail right now is **exclusion from the active set / quorum denominator**.

## 3. The four rules — final handling

| # | Rule | Handling | Why |
|---|---|---|---|
| ① | credit-over-limit | **sign-gate REFUSE** (not slash) | an individual over their limit is refused at sign time; slashing an *operator's* stake for a member's credit is wrong |
| ② | offline | **auto-jail** (SP `LivenessRegistry`) + gossip soft signal | liveness is an objective on-chain fact (`block.number > lastLive + window`); jail (fee-stop), not stake-slash |
| ③ | over-issue | **on-chain credibility score** (not slash, not DVT-disclosed) | `credibilityScore()`/`isOverIssued()` are auto-computed on-chain views; consumers read them directly |
| ④ | proof-forgery | **not done** | co-sign re-verification + on-chain aggregate rejection already block forged slashes; residual spam → reputation |

### ③ economic credibility — an on-chain view (CC-28, SP-side)

Computed live on every read from current state — no DVT compute, no stored score:

```
issuedValueUSD  = totalSupply × aPNTsPriceUSD / exchangeRate         (ceil)
backingValueUSD = staked aPNTs (canonical SP) × aPNTsPriceUSD         (only if operator configured + linked)
effectiveCapUSD = industryScaleUSD[category] × capRatioBps/10000  +  backingValueUSD
credibilityScore = min(100, backingValueUSD / issuedValueUSD × 100)   // backing coverage %
isOverIssued     = issuedValueUSD > effectiveCapUSD  (or issuanceCap breach; renounced-factory ⇒ flag)
```

- Backing = **stake + (future) committed redemption services** (MyShop via a pluggable `IBackingSource`, deferred; today: SP-staked aPNTs only).
- Baseline is per-industry, factory-governed (default ~$10k; e.g. foreign-trade higher), adjusted via the community multisig — a community can't self-pick a high baseline (category is `onlyOwner` factory governance).
- **Consumers read it directly** on-chain: SuperPaymaster (sponsorship decisions), wallets/dapps (token trust), users, AgentStore. DVT does nothing.

## 4. The slash pipeline is DORMANT (kept for the future)

There is **no active rule feeding the stake-slash pipeline** — at the 3-node bootstrap, nodes are guaranteed online, so no slash is needed yet. The machinery is retained, unarmed:

- Kept: `handleViolation` → `createProposal` → queue → execute, `GossipQuorumCoSigner` / `PendingSlotCoSigner` / `QUORUM_COSIGNER` factory, proof archive (`PROOF_SCHEMA_VERSION` unchanged).
- ① was the **only armed rule** (its `verifyViolationForCoSign` was credit-specific); removing it leaves the co-sign responder unarmed/dormant.

### Waking a future slash

1. Re-code a DVT **rule predicate** (detect the violation at a pinned finalized block, deterministic).
2. **Arm** a co-sign verifier (re-confirm the violation from first principles) so peers cross-verify.
3. **File** a proposal → BLS-quorum co-sign → queue/execute → slash stake.

The on-chain execution machinery (`DVTValidator` / `BLSAggregator` / `slashThresholds`) is already deployed.
- A rule whose evidence is a **pure on-chain view** (like `isOverIssued`) → **DVT-only** re-code.
- A rule needing **new on-chain state** → also needs SP contract work. Example: **offline-duration tiered
  slash** (1d → 10%, 3d → 30% + permanent-offline-until-stake-topup) needs accumulated-downtime tracking
  + penalty tiers, which `LivenessRegistry` does **not** have today (only instantaneous `isOffline`).
