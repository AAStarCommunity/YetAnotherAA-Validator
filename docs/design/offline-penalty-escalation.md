# Offline penalty escalation — jail and stake loss on one time axis

> **Status: DESIGN ONLY. Nothing here is built, and nothing should be built
> until the preconditions in §7 are met.** Recorded 2026-09-02 on Jason's
> instruction ("咱现在不要着急做,先把这个记录下来"). This is ecosystem mechanism
> design; it is deliberately **out of scope for the paper**.
>
> Companions: [`AUDIT_SLASH_MODEL.md` §3.2](../AUDIT_SLASH_MODEL.md) (why rule ②
> is a slash rule at all) and
> [`SLASH_ROLLOUT_GATE.md`](../SLASH_ROLLOUT_GATE.md) (the N gate, the stake
> margin, and the asset question).

## 1. What Jason asked for

> 借鉴信标链的罚没过程。如果你离线可能超过多久,我就开始 slash 你。但离线超过一段时间,我就把你放进 jail,不让你参与线上的投票,直到你重新上线。……如果我放进jail 之后你持续没有上线,比如说一年没上线,我肯定不能一直等你。比如说超过一个月没上线,那就开始 slash。我是希望一个逐步升级的过程。所以 jail 和 slash 它并存。

Two requirements, and the second is the one that constrains the design:

1. **Escalation, not a cliff.** Longer outage ⇒ heavier consequence.
2. **jail and slash COEXIST.** Jail is not the terminal state; a node parked in
   jail forever must eventually stop being the network's problem.

## 2. What the Beacon Chain actually does — and the one correction it forces

The analogy is the right one, but it corrects a word we have been using loosely.
Ethereum does **not slash for being offline.** It has three distinct mechanisms:

| Ethereum mechanism     | trigger               | who decides                                   |
| ---------------------- | --------------------- | --------------------------------------------- |
| **inactivity penalty** | missed attestations   | **nobody — the state transition computes it** |
| **inactivity leak**    | chain not finalising  | same, quadratic in outage length              |
| **slashing**           | provable equivocation | a whistleblower submits proof                 |
| **ejection**           | balance < 16 ETH      | automatic consequence of the above            |

Slashing is reserved for **provable malicious action**; absence is punished by a
**leak** — a continuous, deterministic drain. That distinction is not cosmetic
for us, because it decides how much machinery this rule needs:

> **A leak needs no quorum.** It is a pure function of on-chain state
> (`lastLive`, `livenessWindow`, `block.number`), so any caller can trigger the
> settlement and every observer computes the same number. **No BLS consensus, no
> guardian vote, no fraud proof, no `proposalSignersCommitment`, and therefore
> no guardian-collusion exposure at all** (contrast
> [`guardian-collusion-slash.md`](./guardian-collusion-slash.md), which exists
> only because _voted_ slashes can be unjust).

This also resolves a live cross-repo conflict. SP's contract states its scope
explicitly (`LivenessRegistry.sol:31`):

> Offline itself carries NO slash — it only shrinks the live-set.

Modelled as a **leak** rather than a **slash**, our design and SP's stated
semantics stop contradicting each other: the quorum-voted slash pipeline still
never fires on absence, and stake still drains. **Use the word "leak" (or
"inactivity penalty") for this rule and reserve "slash" for the voted,
fraud-provable path.** See §8 for what still needs SP's agreement.

## 3. The state machine

Four states on one axis. Jail and stake loss are **layers**, not alternatives —
which is exactly Jason's "并存".

| state       | entered when                        | effect                                                                                       | exit                                  |
| ----------- | ----------------------------------- | -------------------------------------------------------------------------------------------- | ------------------------------------- |
| **LIVE**    | `isOffline(op) == false`            | normal participation                                                                         | —                                     |
| **GRACE**   | silent, but within `livenessWindow` | **nothing** — absorbs RPC/gas/reorg jitter                                                   | attest ⇒ LIVE                         |
| **JAIL**    | `isOffline(op) == true`             | excluded from the active set + quorum denominator; fee stopped; **the leak starts accruing** | attest ⇒ LIVE (leak stops, burn kept) |
| **EJECTED** | `effectiveStake < minStake`         | forced exit; ROLE_DVT registration must be redone                                            | top up stake and re-register          |

Jail is entered **immediately** at the window boundary and is **free at first**
— the leak accrues from the same instant but the first period's rate is small.
So a node that is down for twenty minutes and returns loses its slot for twenty
minutes and effectively nothing else, while a node that is down for weeks drains
toward ejection without anyone having to vote on it.

**EJECTED is the answer to "一年没上线我不能一直等你".** No special "one month"
rule is needed: the escalating leak reaches the floor on its own schedule, and
the schedule is a tunable parameter (§4). This is precisely how Ethereum avoids
maintaining a list of abandoned validators.

## 4. The escalation curve, and how "one month" is set

Let `S_reg` be the operator's stake at registration and `S_floor = minStake`.
Under **Plan A** (Jason, 2026-09-02) `S_reg = 50`, `S_floor = 30`, so the **leak
budget is 20 GToken = 40% of `S_reg`**.

Per escalation period `P` of continuous downtime, burn `rate(k)` of **`S_reg`**
(the registered stake, NOT the current balance):

```
rate(k) = min(base + inc × (k − 1), max)      k = 1, 2, 3, …
```

Reusing the values SP already carries on-chain for ROLE_DVT (`base = 2%`,
`inc = 1%`, `max = 10%` — see §6):

| period k | rate | burn (GToken) | cumulative |    remaining stake |
| -------: | ---: | ------------: | ---------: | -----------------: |
|        1 |   2% |           1.0 |        1.0 |               49.0 |
|        2 |   3% |           1.5 |        2.5 |               47.5 |
|        3 |   4% |           2.0 |        4.5 |               45.5 |
|        4 |   5% |           2.5 |        7.0 |               43.0 |
|        5 |   6% |           3.0 |       10.0 |               40.0 |
|        6 |   7% |           3.5 |       13.5 |               36.5 |
|        7 |   8% |           4.0 |       17.5 |               32.5 |
|    **8** |   9% |           4.5 |   **22.0** | **28.0 → EJECTED** |

**Eight periods to ejection.** That single number is the whole tuning surface:

| choose `P` | time to ejection                                |
| ---------- | ----------------------------------------------- |
| 1 day      | ~8 days                                         |
| **4 days** | **~1 month** ✓ matches Jason's stated intuition |
| 1 week     | ~2 months                                       |

**Recommendation: `P = 4 days`.** It puts ejection at roughly a month of
continuous, unattended downtime while making the first few days cheap enough
that an ordinary incident is not punitive.

### Three properties this curve must have

1. **Percentages are of `S_reg`, not of current stake.** A percentage of the
   _current_ balance is asymptotic — it approaches the floor but never crosses
   it, and the node is never ejected. This is the single easiest way to get the
   design wrong.
2. **Recovery stops the leak; it does not refund it.** Coming back online halts
   accrual, and the burned stake stays burned. Without this ratchet, flapping is
   free.
3. **The escalation level decays with uptime, it does not reset.** A hard reset
   lets a node flap at period boundaries forever and never leave `k = 1`.
   Suggested: `k` decays one step per uptime period. This is the deliberate
   analogue of Ethereum's inactivity-score bleed-off.

## 5. Why this needs Plan A to exist at all

With the margin measured on 2026-09-01 — `effectiveStake == minStake == 30e18`,
**margin zero** — every row of the table above collapses into one: the first
burn of any size drops the node below the floor and ejects it. **The curve is
not merely less effective without the margin; it is arithmetically
indistinguishable from a cliff.**

So the ordering is fixed: **Plan A (top every operator up to 50) is a
precondition of this design, not a companion to it.**

Plan A's own gap, recorded so it is not forgotten: registration and eligibility
share one threshold (`AAStarValidator._isStaked` checks `>= minStake` for both),
so "everyone stakes 50" is an **onboarding convention, not an enforced
mechanism**. It holds only while registration stays owner-gated
(`requireStake = false`). Making it a mechanism means separate entry and
ejection thresholds in the contract — the Beacon Chain shape (32 to activate, 16
to eject) — and the validator is **not upgradeable**, so that lands with the
next redeploy, not before.

## 6. Half the parameters already exist on-chain, unread

`IRegistry.RoleConfig` declares
`slashThreshold / slashBase / slashInc / slashMax`, and ROLE_DVT carries live
values `10 / 2 / 1 / 10` (read on-chain by superpaymaster-b6; the original
2025-12-20 comments gloss them
as 惩罚触发阈值 / 基础惩罚金额 / 惩罚递增量 / 最大惩罚上限) — literally the
`base 2%, +1%, cap 10%` curve above. **Zero code in SP's `contracts/src/` reads
any of them.** Reuse them rather than inventing a parallel table; a
configured-looking policy that nothing honours is worse than an absent one.

> ⚠️ **Always write these fully qualified.** `RoleConfig.slashThreshold`
> (uint32, per role, `= 10`, **error count**, dead) and
> `BLSAggregator.slashThresholds[level]` (uint8, per severity, `= 2/3/3`,
> **signature count**, live) are different quantities in different units with
> near-identical names. Two sessions have already talked past each other on
> this.

## 7. Preconditions — none of which are met today

| #   | precondition                                               | state                                                                                                                                                                                                                                                                        |
| --- | ---------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | `LivenessRegistry.owner` moved to a timelock/multisig      | ❌ owner is an EOA (`0xb5600060…`). The contract's own header says the owner **MUST** be a timelock, because changing `livenessWindow` re-partitions the live-set **immediately and in both directions**. Once the window decides who loses stake, this stops being optional |
| 2   | registry address in every node's env + a first attestation | ❌ `AUDIT_LIVENESS_REGISTRY_ADDRESS` unset; `lastLive == 0` fleet-wide, so every operator currently reads `isOffline == true`                                                                                                                                                |
| 3   | Plan A margin in place (§5)                                | ❌ every operator holds exactly `minStake`                                                                                                                                                                                                                                   |
| 4   | the attest cadence derived from the on-chain window        | ❌ `MAX_INTERVAL_MS = 6h` is a static constant against a 300-block (~60 min) window — a healthy node can be configured into permanent jail with no warning                                                                                                                   |
| 5   | the N gate                                                 | ❌ see [`SLASH_ROLLOUT_GATE.md`](../SLASH_ROLLOUT_GATE.md). **The margin buys time, not safety**: the count axis still has `minCommittee == activeCount == 3`, so an ejection at N=3 halts the stack regardless of how gently it was reached                                 |

## 8. Open questions for SP

1. **Does SP accept a stake-draining leak keyed off `LivenessRegistry`?** The
   contract's stated scope is jail-only (§2). Modelling it as a leak rather than
   a voted slash narrows the conflict but does not erase it.
2. **Where does the leak execute?** A leak wants a permissionless `settle(op)`
   that anyone can poke, computing the deduction from `lastLive`. Today the only
   path into GToken is `GTokenStaking.slashByDVT`, which is
   `authorizedSlashers`-gated and takes a caller-supplied amount — the wrong
   shape for a deterministic leak.
3. **Guardian slashing is untouched by any of this.** `BLSAggregator:2003` reads
   the full remaining lock and passes it as the penalty, so the contract cannot
   express a partial guardian slash: staking 50 and staking 30 both end at zero.
   Plan A does **not** help guardians; capping that path is a separate contract
   change.
