# When to turn slashing on — the N gate

> **Status: slashing is OFF, and that is a deliberate decision, not an
> oversight.**
>
> This document records the OBJECTIVE state as of 2026-09-01 and the node-count
> thresholds that govern when it may be turned on. For _how_ each rule works and
> why it was classified the way it was, see
> [`AUDIT_SLASH_MODEL.md`](./AUDIT_SLASH_MODEL.md). This file answers a
> different question: **at what network size does slashing stop being
> self-destructive?**

## 1. Why the gate exists: at N=3 one slash stops the whole network

Verified on-chain 2026-09-01 (`AAStarCommitteeValidator`
`0x7ac7E9d471742FA4397Beef0B5b11fbD22D196a9`):

```
minStake        30e18        every operator's effectiveStake   30e18   ← margin 0
minCommittee    3            activeCount                       3       ← margin 0
requiredQuorum  2
```

The eligibility predicate is `getEffectiveStake(op, ROLE_DVT) >= minStake`.
Because stake equals the threshold exactly, **a slash of one wei disqualifies a
node at the next snapshot**, and then:

```
epochSetCount 2  <  minCommittee 3
  ⇒ requiredQuorum() returns the unsatisfiable sentinel
  ⇒ the account-side gate (CC-116) can never be satisfied
  ⇒ ALL tier-2/3 traffic fails closed, for every account on the stack
```

So at N=3, **punishing one bad node punishes every user.** The security
mechanism working as designed is indistinguishable, from the outside, from a
total outage.

This is a property of N=3, not of the mechanism — see the table below.

## 2. The deployed curve, and the three thresholds it creates

`expectedCommittee(n)` as deployed (source, not design intent):

```solidity
if (n <= 8) return n;                 // bootstrap: whole set
uint256 m = (n + 4) / 5;              // ceil(n/5)
if (m < 30) m = 30;                   // floor — see below
if (m > 86) m = 86;                   // cap
if (m > n) m = n;                     // never sample more than the pool
```

`requiredQuorum = ceil(2*m/3)`, and `requiredQuorum()` returns the sentinel
whenever `epochSetCount < minCommittee`.

| N (eligible) | committee m | quorum | after one slash | stack        | slashes tolerated |
| -----------: | ----------: | -----: | --------------: | :----------- | ----------------: |
|        **3** |           3 |      2 |               2 | ❌ **halts** |             **0** |
|            4 |           4 |      3 |               3 | ✅           |                 1 |
|            8 |           8 |      6 |               7 | ✅           |                 5 |
|           20 |          20 |     14 |              19 | ✅           |                17 |
|       **30** |          30 |     20 |              29 | ✅           |                27 |
|       **31** |          30 |     20 |              30 | ✅           |                28 |
|           60 |          30 |     20 |              59 | ✅           |                57 |
|          150 |          30 |     20 |             149 | ✅           |               147 |
|         430+ |          86 |     58 |             429 | ✅           |               N−3 |

Three distinct thresholds, often confused:

1. **N ≥ 4 — mechanical survival.** One slash no longer halts the stack. This is
   the bare minimum and it is _fragile_: at N=4 a second slash halts it again.
2. **N ≥ 31 — sampling actually begins.** Below this the committee IS the whole
   set (`m > n ⇒ m = n`), so sortition buys nothing: an attacker knows exactly
   who is on the committee, because everyone is. **31 is the first N where the
   committee is a strict subset of the pool.**
3. **N ≥ 30 — the ε≤1e-6 forgery bound becomes meaningful.** The bound is a
   property of _m_, not of N: `P(Poisson(β·1.25·m) ≥ ceil(2m/3)) ≤ 1e-6` for β ≤
   10% holds at m = 30 with ~4.4e-9 headroom. At m = 3 (quorum 2) it does not
   hold in any useful sense — two colluding nodes forge.

   The floor of 30 is deliberate: B1's earlier single-tail floor-17 curve left a
   **6.3% honest-liveness failure rate**, found in review, which is why the
   deployed curve is double-tailed with floor 30 and oversample 1.25.

> ⚠️ A committee of **10** — sometimes suggested informally as "pick 10 out of
> 100" — does **not** meet the ε≤1e-6 bound and is not what the deployed curve
> does. At N=100 the committee is **30**.

## 3. The decision (Jason, 2026-09-01)

**Slashing stays OFF until the network is large enough that removing a node does
not remove the network.** Early security is **trusted operators**, not
economics: the three nodes are known and are not expected to misbehave.

This is recorded as an accepted risk, including for mainnet — see the
release-notes framing in CC-115 / CC-46. It is _accepted_, not _unnoticed_.

**Recommended gate: N ≥ 30.** Rationale: it is the first point where the
deployed security argument (the ε bound) actually holds AND the committee stops
being the whole set. N ≥ 4 is survivable but not defensible; anything between 4
and 30 buys tolerance without buying the security property the design is built
on.

Node growth is a function of community and governance, not of engineering — it
cannot be bought. The levers that _are_ held today (raising stake above
`minStake`, reducing slash amounts) **mitigate but do not solve**: they help
against a partial slash and do nothing against a full slash or a voluntary exit.

## 4. What is actually off today, and how

Slashing is not merely "not used" — it is gated in code, which is stronger than
a policy promise:

| gate                        | location                                                                          | default                                                        |
| --------------------------- | --------------------------------------------------------------------------------- | -------------------------------------------------------------- |
| `AUDIT_ENABLED`             | `src/config/configuration.ts`                                                     | **false**                                                      |
| second arm (`executeSlash`) | `src/modules/audit/audit.service.ts`                                              | **false** — "nothing is auto-slashed until explicitly enabled" |
| `AUDIT_DRY_RUN`             | same                                                                              | drill mode, no broadcast                                       |
| rule ① credit-over-limit    | retired by design review (PR #205)                                                | not a slash rule                                               |
| rule ③ over-issue           | retired by design review (PR #205)                                                | on-chain credibility view                                      |
| rule ② offline              | present, but needs an objective on-chain liveness signal SP has not built (CC-29) | cannot slash today                                             |
| rule ④ proof-forgery        | closed as non-slashing                                                            | prevented, not punished                                        |

**Two of the four rules were retired, one is blocked on an upstream signal that
does not exist, and the fourth was deliberately closed. The origination path for
a slash is therefore empty today even if both flags were flipped.**

### What this does NOT gate

The gates above cover **DVT originating a slash**. They do **not** cover:

- **Guardian slashing** (`executeGuardianSlash`, armed 2026-09-04 via the
  fraud-proof verifier). That punishes _guardians who slashed unjustly_ — the
  appeal layer, not the enforcement layer. SP's three guardians have the same
  zero margin and a MINOR threshold of 3 with exactly 3 registered, so slashing
  any one of them takes SP's slash consensus below its own threshold.
- **Anything SP does on its own** with `slashByDVT` / `executeSlashWithBLS`.

So "slashing is off" is precise only for the DVT-originated path. Say it that
way.

## 5. Re-read this before turning it on

1. `activeCount` and every operator's `effectiveStake` — the margin must be > 0
   on **both** axes, not just the count.
2. Whether committee operators and guardians are still disjoint address sets.
   They are today (verified: 6 addresses, zero overlap), and that disjointness
   is what stops `executeGuardianSlash` from taking down the committee. Merging
   the roles couples the two failure modes.
3. Whether `minCommittee` still matches the intended floor for the new N.
