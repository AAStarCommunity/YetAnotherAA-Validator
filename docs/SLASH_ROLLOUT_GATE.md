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
2. **N ≥ 39 — sampling actually begins.** Membership is NOT decided by `m`; it
   is decided by the **oversampled target** in `_thresholdOf` (`:625-626`):

   ```solidity
   uint256 target = (oversampleNum * m + oversampleDen - 1) / oversampleDen; // ceil(1.25*m)
   if (target >= n) return type(uint256).max;   // whole set - the draw is SKIPPED
   ```

   With floor `m = 30` and oversample 1.25, `target = ceil(37.5) = 38`, so
   `target >= n` holds for **every n <= 38**: the per-signer draw is skipped and
   every active node is admitted. **The committee is literally the whole set up
   to N = 38; n = 39 is the first N that samples.** The contract says so itself
   at `:606` — _"on N >= N0 (>= ~39, where sampling begins)"_.

   > Footnote, because it is a true statement about a different quantity and it
   > is exactly what an earlier version of this section wrongly used: **31** is
   > the first N where `expectedCommittee(n) < n`. That is a property of the
   > parameter `m`, not of membership — at N = 31 the committee is still the
   > whole set. Reading `m < n` as "sampling has begun" is the error; the
   > oversampled target is the gate.

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

**Recommended gate: N ≥ 39.** It is the first point where **both** halves of the
deployed security argument hold at once:

|         N | ε≤1e-6 bound (needs m = 30) | sortition unpredictability (needs a strict subset) |
| --------: | :-------------------------- | :------------------------------------------------- |
|      4–29 | ❌ m < 30                   | ❌ whole set                                       |
| **30–38** | ✅ m = 30                   | ❌ **still the whole set** (`target 38 >= n`)      |
|   **39+** | ✅                          | ✅                                                 |

**N = 30 buys only the first half**, and it is worth being precise about what
that half is: with a whole-set committee, safety does not come from an attacker
being unable to predict who is drawn — everyone is drawn. It comes from the
classical requirement that they corrupt ⌈2m/3⌉ = 20 of the 30. That is a real
property, but it is **BFT, not sortition**, and the ε argument the design rests
on is about sortition.

N ≥ 4 is survivable but not defensible. Anything from 4 to 38 buys tolerance
(the `N−3` column) without buying the unpredictability the ε argument needs.

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
| second arm (`executeSlash`) | `src/config/configuration.ts:247-251`                                             | **false** — "nothing is auto-slashed until explicitly enabled" |
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
  zero margin, and MINOR's **slash** threshold is 3 with exactly 3 registered,
  so slashing any one of them takes SP's slash consensus below its own
  threshold.

  > Do not generalise that to "all thresholds are 3". Verified on-chain
  > 2026-09-01 on **both** aggregators: `slashThresholds[0,1,2] = 2,3,3` but
  > `defaultThreshold = 7`, with only **3** validators registered (slots 1-3; 4+
  > are zero). `defaultThreshold` governs the non-slash paths, so **the
  > reputation-batch and generic-proposal paths cannot execute at all today** —
  > `_checkSignatures` reverts `InvalidSignatureCount(3, 7)` before any
  > signature is examined. Pre-existing configuration, not a result of the
  > aggregator rotation. It does not affect DVT (the committee validator does
  > its own BLS verification via the EIP-2537 precompiles and never routes
  > through SP's threshold), and it does not change the slash-path conclusion
  > above.

- **A guardian's duties are broader than "sign slash proposals"** — which is
  what makes the note above load-bearing rather than trivia. `BLSAggregator` has
  three BLS-threshold entry points (`queueSlashWithConsensus`,
  `verifyAndExecute` — whose reputation branch uses `defaultThreshold` — and
  `executeProposal`), and all three reconstruct the signer set from the **same**
  `validatorAtSlot` registry. So the correct statement is _not_ "guardians have
  no routine duty"; it is **"the routine duties are currently unexecutable
  because `defaultThreshold` (7) exceeds the registered count (3)"**.
  `setDefaultThreshold` is one owner transaction away from making them live, at
  which point guardian keys must be online. The two statements license very
  different architecture decisions.
- **Anything SP does on its own** with `slashByDVT` / `executeSlashWithBLS`.

So "slashing is off" is precise only for the DVT-originated path. Say it that
way.

## 5. Re-read this before turning it on

Each item names **how to read it**, not what it read last time. Values drift;
the call does not.

1. **Both margins must be > 0** — the count axis and the stake axis, not just
   the count.

   ```
   validator.activeNodeIdsSorted()                     -> bytes32[] nodeIds
   validator.nodeOperator(nodeId)                      -> operator address
   registry.getEffectiveStake(operator, ROLE_DVT)      -> must be STRICTLY > minStake()
   validator.activeNodeIdsSorted().length              -> must be STRICTLY > minCommittee()
   ROLE_DVT = keccak256("DVT")
   ```

2. **Committee operators and guardians must still be disjoint address sets.**
   That disjointness is what stops `executeGuardianSlash` from taking down the
   committee; merging the roles couples the two failure modes.

   ```
   committee: activeNodeIdsSorted() -> nodeOperator(id)      (the calls above)
   guardians: blsAggregator.validatorAtSlot(1), (2), (3), AND (4)
   ```

   **Read slot 4 as well.** Reading only 1–3 confirms the three you expected and
   cannot tell you a fourth was added; reading 4 turns "there are three
   guardians" from an assumption into a measurement. (It is zero today.)

3. **`minCommittee` must still match the intended floor for the new N.** It is
   not automatic — `setMinCommittee` floors it at 3 and nothing raises it as the
   pool grows.
