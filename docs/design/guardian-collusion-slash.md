# Guardian-Collusion Slashing (CC-89, Protocol B)

> Stage-0 design doc. Companion to [`../AUDIT_SLASH_MODEL.md`](../AUDIT_SLASH_MODEL.md),
> which covers the DVT node auditing **operators**. This doc covers the inverse:
> slashing the **guardians** (the DVT co-signers themselves) when they collude.
> Origin: CC-89 evaluation request from the RepCredit paper (DSR-Research-Flow).

## 1. Why this exists — the threat the operator-audit model doesn't cover

`AUDIT_SLASH_MODEL.md` is about a DVT quorum watching **operators** and slashing
their **aPNTs**. It says nothing about the quorum itself being dishonest.

The BLS slash path (`BLSAggregator.verifyAndExecute`) verifies that `m` real
guardians co-signed a message and binds the slash to an `evidenceHash`, but the
contract **never re-verifies the evidence content on-chain** — it commits to the
hash and trusts the quorum. Therefore:

> **≥m colluding guardians can pass a valid slash of an innocent operator.** The
> aggregate signature is real, so nothing on-chain rejects it. The only possible
> deterrent is economic: make the colluders lose their own stake.

This is the threat the RepCredit paper's anti-collusion inequality models:

```
k · C_max  <  m · ρ · S_op · p_G
                └──────┬──────┘
      right side = a guardian's loss when its collusion is caught and slashed
```

- `m` = signatures needed to pass the attack. **For a slash this is
  `slashThresholds[level]` (bootstrap WARNING=2 / MINOR=3 / MAJOR=3), NOT
  `defaultThreshold=7`** (`defaultThreshold` is the reputation-consensus path
  only). Using 7 overstates collusion resistance ~2–3×.
- `S_op` = a guardian's ROLE_DVT GToken lock.
- `ρ` = probability the collusion is detected **and** leads to a slash — the term
  with no code correspondent until the detection layer (stage 2) exists.

### Asset distinction — not "party" distinction

The slashed operator (`operators[operator].aPNTsBalance`, requires
ROLE_PAYMASTER_SUPER config) and the co-signing guardian (ROLE_DVT lock) are
**different assets, not guaranteed-different parties**: the BLS slash path does
**not** enforce ROLE_PAYMASTER_SUPER at slash time, and one address can hold both
roles. What is guaranteed distinct is the asset — **aPNTs balance ≠ ROLE_DVT
GToken lock**, even at a shared address. The gap is that the paper's `ρ · S_op`
(a ROLE_DVT-stake loss) has no execution path targeting that asset.

## 2. The auto-eject property (the free half of the mechanism)

Every BLS verify reconstructs the aggregate key on-chain and checks **each
signer** for live role + stake — `BLSAggregator._reconstructPkAgg`:

```solidity
if (!REGISTRY.hasRole(roleDvt, v)) revert SlotValidatorRoleRevoked(slot, v);
(uint128 amount,,,, ) = staking.roleLocks(v, roleDvt);
if (uint256(amount) < minStake) revert SlotValidatorStakeBelowMinimum(...);   // strict <
```

> **Consequence:** a guardian whose ROLE_DVT lock drops **below** `minStake` is
> automatically ejected from all future signing — any proof that includes its
> slot reverts. No separate "kick" logic is needed. The penalty shape for
> collusion is therefore *slash the full lock → 0 < minStake → auto-eject*, which
> both burns `S_op` and removes eligibility in one step.

Note the boundary (SP review): the check is strict `<`. To **guarantee** ejection
the slash must take the **full** lock (leaving 0), not `minStake` — leaving
exactly `minStake` still passes the check. `executeGuardianSlash` slashes the
full lock for this reason.

## 3. Trigger authority — how the circular dependency is broken

The obvious problem: `queueSlashWithConsensus` / `verifyAndExecute` require
`msg.sender == DVT_VALIDATOR || owner()`, and the colluders **are** that quorum —
they will never slash themselves. A same-quorum trigger cannot work.

SP's `executeGuardianSlash` (BLSAggregator 4.2.0, **PR #370**) resolves this at
the contract layer:

| Property | How | Why it matters |
| --- | --- | --- |
| **Permissionless call, verifier-gated** | no caller-identity check; gated by `IFraudProofVerifier.verify(...)` | fraud *validity*, not caller identity, authorizes the slash → bypasses the colluding quorum |
| **Address-based** (not slot) | slashes `roleLocks(guardian, ROLE_DVT)` by address | `validatorAtSlot` is reassignable (`revokeBLSPublicKey`); a slot captured at fraud time could resolve to an innocent validator later. Also blocks the revoke-key-to-escape trick |
| **Full slash, no 30% cap** | slashes the entire lock | proven collusion must lose eligibility; the operator-path 30% cap protects *honest* operators from one bad epoch — a different threat model |
| **fail-closed** | `fraudProofVerifier == address(0)` → revert | dormant until governance wires a verifier; safe to ship |

So the trigger is **solved**. The remaining unbuilt half is purely the
**detection**: what does `verify()` actually check.

## 4. Stage-2 blueprint — `IFraudProofVerifier` (owned by this repo)

```solidity
interface IFraudProofVerifier {
    function verify(uint256 fraudProofId, address[] calldata guiltyGuardians, bytes calldata fraudProof)
        external view returns (bool);
}
```

SP trusts only an owner-set verifier and never judges fraud itself. This repo
builds the verifier + the off-chain cross-monitoring that feeds it.

### The `view` constraint bounds ρ

`verify` is `view` → the fraud proof must reduce to **on-chain-checkable facts**.
That bounds which collusion is objectively provable:

| Slash's underlying evidence | Trustless `view` fraud proof? | ρ status |
| --- | --- | --- |
| over-issue (`isOverIssued()` bool) | ✅ can prove "at block N `isOverIssued` was false → slash fraudulent" | can become a system property |
| liveness / gossip heartbeat (today's active rule ②) | ❌ `evidenceHash` is opaque on-chain; `view` can't adjudicate | needs **CC-29 LivenessRegistry** to put liveness on-chain first |
| purely off-chain evidence | ❌ | stays a governance assumption |

> **ρ is only a system property for on-chain-objective violation classes.** For
> off-chain-evidence slashes it remains a detection/governance assumption. This
> is the same lesson as `AUDIT_SLASH_MODEL.md §2` (only objective on-chain
> evidence may slash) applied to the accusers instead of the accused.

### Design notes for the verifier

- **`fraudProofId` must be verifier-bound to the fraud content** (e.g. a
  deterministic derivation of the disputed proposalId), not a caller-arbitrary
  value, so a valid proof cannot be "consumed" under an unrelated id.
  (`consumedFraudProofs` in SP is a replay guard, not a binding.)
- Guilty parties are bound to the **signer address at fraud time**, not the slot
  (slot reuse — see §3).
- Double-slash is already prevented by SP's 0-lock skip: a re-submitted proof
  finds `amount == 0` and no-ops.

## 4b. Stage-2 fraud-proof spec (draft — CC-89 stage-2 kickoff)

A fraud proof disputes **one executed slash** and asks the verifier to confirm
two independent things. The second one is the hard, newly-surfaced blocker.

**What is disputed:** an executed slash proposal
`(proposalId, operator, slashLevel, epoch, evidenceHash)` — the tuple
`verifyAndExecute` signed over. `BLSAggregator.executedProposals[proposalId]`
proves it actually ran (view-readable).

**The verifier must confirm BOTH:**

| # | Claim | Difficulty |
| --- | --- | --- |
| (i) | the cited violation was **false at `epoch`** (the slash was unjustified) | **tractable** for on-chain-objective classes: recompute the evidence from state pinned at the `epoch` block (e.g. `isOverIssued()` was false) |
| (ii) | a specific set of **guardian addresses co-signed** this exact proposal | **blocked** — see below |

### The attribution gap (ii) — the real stage-2 blocker

`BLSAggregator` persists **only `executedProposals[proposalId]` (a bool)**. It
does **not** store the signer set, the `signerMask`, or the signature; the
`SlashExecuted` / `SlashConsensusReached` events carry some of it but **a `view`
verifier cannot read logs**. And `signerMask → validatorAtSlot` is **not**
back-resolvable: slots are reassignable (`revokeBLSPublicKey`), so today's
mapping ≠ the fraud-time mapping. **Result: after the fact, on-chain state cannot
tell you which addresses co-signed a past slash.** You can prove the slash was
wrong (i) but not who to punish (ii).

Two ways to close (ii):

| Option | Mechanism | Cost / risk |
| --- | --- | --- |
| **A — SP persists attribution** | `verifyAndExecute` stores, per `proposalId`, the resolved **signer address set** (addresses, not slots). Verifier reads it. | needs an **SP change** (storage + a getter); robust. |
| **B — proof carries re-verifiable sig** | fraud proof carries `{message, claimedSigners[], sigG2}`; verifier reconstructs the claimed signers' aggregate pubkey from their **current** BLS keys and re-checks the pairing → proves they signed. | no SP storage change, but **breaks if a colluder rotates/revokes its BLS key post-attack** (key no longer on-chain to reconstruct). Needs a key snapshot or accepts the gap. |

> **Decision needed with SP.** Option A is the clean, robust path but makes
> stage 2 a **joint SP+dvt** change, not dvt-only. Option B keeps it dvt-side but
> has a post-attack key-revocation hole. This must be settled before any verifier
> code — it changes who builds what.

### fraudProofId binding

`fraudProofId` must be a **deterministic derivation of the disputed
`proposalId`** (e.g. `keccak256("GUARDIAN_FRAUD", proposalId)`), computed by the
verifier — never a caller-free value — so a valid proof can't be consumed under
an unrelated id and the same fraud can't be double-filed. SP's
`consumedFraudProofs[fraudProofId]` is then a correct replay guard.

### Prerequisites (why stage-2 implementation can't start yet)

1. **An armed, on-chain-objective slash rule** to defend. Today none exists:
   over-issue is a *view* (not a slash), liveness is *auto-jail* (not a
   stake-slash), the slash pipeline is dormant (`AUDIT_SLASH_MODEL.md §4`). No
   armed slash ⇒ nothing to fraud-prove.
2. **Attribution (ii)** resolved — Option A (SP) or B (dvt), above.
3. **Liveness class only:** CC-29 `LivenessRegistry` deployed (liveness must be
   an on-chain fact before a `view` proof can dispute an offline-slash).

The **spec is dependency-free and complete enough to build against**; the
**implementation** waits on 1 + 2 (+ 3 for liveness).

## 5. Ownership & sequencing

| Stage | Owner | Status |
| --- | --- | --- |
| 1 — `executeGuardianSlash` thin entry | SP | ✅ landed dormant (PR #370, BLSAggregator 4.2.0) |
| 0 — this doc (auto-eject + threat model + trigger authority) | dvt | ✅ this file |
| 2 — `IFraudProofVerifier` + off-chain detection (produces ρ) | dvt (+ SP for attribution, §4b) | ⏳ spec drafted (§4b); impl blocked on: an armed slash rule + attribution decision (A/B) + (liveness) CC-29 |

**When to activate:** N large + operators independent (not co-located) + an
on-chain-verifiable independent adjudication path. At the current 3-node,
co-located, single-owner bootstrap, guardian-slash is dormant by design — the
anti-collusion property is provided by **trusted owner**, and the paper's
inequality is a **decentralized-phase target**, not a current deployed property.

## References

- CC-89 (coordination task) — evaluation thread and division of labour.
- `SuperPaymaster` PR #370 — `executeGuardianSlash` + `IFraudProofVerifier`.
- [`../AUDIT_SLASH_MODEL.md`](../AUDIT_SLASH_MODEL.md) — the operator-audit side.
- CC-29 — LivenessRegistry (prerequisite for the liveness fraud-proof class).
