# Offline penalty escalation — jail and stake loss on one time axis

> **Status: DESIGN SKETCH. Nothing here is built, and it is NOT yet
> implementable as written** — §5 lists on-chain state that does not exist and
> without which the mechanism is either evadable or over-chargeable. Recorded
> 2026-09-02 on Jason's instruction ("咱现在不要着急做,先把这个记录下来").
> Ecosystem mechanism design; deliberately **out of scope for the paper**.
>
> **This file is authoritative on terminology and on the offline penalty's
> shape.** Where [`AUDIT_SLASH_MODEL.md`](../AUDIT_SLASH_MODEL.md) and
> [`SLASH_ROLLOUT_GATE.md`](../SLASH_ROLLOUT_GATE.md) describe the same rule,
> they defer to this document.
>
> Revised after an adversarial review (Codex, 2026-09-02) that found the first
> draft "not safe to merge as guidance": it asserted a settlement mechanism that
> the available on-chain state cannot support, and justified a design choice
> with a mathematical claim that is false. Both are corrected below and the
> errors are kept visible rather than silently patched.

> **Cross-repo citations.** Files named `LivenessRegistry.sol`, `Registry.sol`,
> `GTokenStaking.sol`, `IRegistry.sol`, `BLSAggregator.sol`,
> `SuperPaymaster.sol` and `xPNTsToken.sol` live in **`@repo:sp`**
> (`SuperPaymaster`, `contracts/src/…`), not in this repository — a `find .`
> here returns an empty set for them. Files named `AAStarValidator.sol`,
> `AAStarCommitteeValidator.sol`, `audit.service.ts`,
> `liveness-keeper.service.ts` and `configuration.ts` are local.

## 1. What Jason asked for

> 借鉴信标链的罚没过程。如果你离线可能超过多久,我就开始 slash 你。但离线超过一段时间,我就把你放进 jail,不让你参与线上的投票,直到你重新上线。……如果我放进jail 之后你持续没有上线,比如说一年没上线,我肯定不能一直等你。比如说超过一个月没上线,那就开始 slash。我是希望一个逐步升级的过程。所以 jail 和 slash 它并存。

Two requirements, the second being the binding one:

1. **Escalation, not a cliff.** Longer outage ⇒ heavier consequence.
2. **jail and stake loss COEXIST.** Jail is not terminal; a node parked in jail
   forever must eventually stop being the network's problem.

## 2. The Beacon Chain analogy — what it gives, and where it breaks

Ethereum does **not slash for being offline.** Three distinct mechanisms:

| Ethereum mechanism     | trigger                         | who decides                                   |
| ---------------------- | ------------------------------- | --------------------------------------------- |
| **inactivity penalty** | missed attestations             | **nobody — the state transition computes it** |
| **inactivity leak**    | **the chain fails to finalise** | same; cumulative loss ~quadratic in time      |
| **slashing**           | contradictory _signed_ messages | a whistleblower submits proof                 |
| **ejection**           | effective balance **≤ 16 ETH**  | automatic consequence of the above            |

Slashing punishes **provable signed misbehaviour** — the protocol proves the
behaviour, not intent. Absence is handled by a **leak**: a continuous,
deterministic drain nobody votes on.

**What the analogy buys us.** A leak is settled by **EVM execution rather than
by an application-level quorum vote** — that execution is of course still
consensus-finalised like any transaction; what disappears is the BLS quorum, the
guardian vote and the fraud proof. **Guardian collusion is therefore absent from
this path** — and guardian collusion is the entire reason
[`guardian-collusion-slash.md`](./guardian-collusion-slash.md) exists.

### Where the analogy breaks — three disanalogies that matter

1. **Ethereum's leak is globally conditioned on loss of finality.** It fires
   when _the chain_ is failing, not when _one validator_ misses a duty. Ordinary
   missed attestations cost the (much smaller) inactivity penalty. A design that
   drains stake for individual missed self-attestations **while the chain is
   perfectly healthy** is a strictly harsher instrument than the one being
   borrowed from, and should not claim Ethereum's safety record.
2. **Our liveness signal is much weaker than an attestation.**
   `LivenessRegistry` says so itself (`LivenessRegistry.sol:21,28`): it proves
   only that _the operator's key sent a transaction recently_. It explicitly
   does **not** prove the DVT stack is online, and an operator that attests
   faithfully while refusing to co-sign is invisible to it. So the signal is
   evadable in the direction that matters: **a malicious operator can look live
   while serving nothing.**
3. **The failure modes are asymmetric in the wrong direction.** A full chain
   halt does **not** accrue any leak, because `block.number` stops — real
   downtime becomes invisible. The opposite case is the dangerous one: the chain
   advances normally while operators cannot get transactions included (RPC
   outage, gas exhaustion, censorship, a provider incident), and **every honest
   operator sharing that dependency leaks simultaneously.** The blast radius is
   whoever sits behind the common failure — for a fleet on one provider, or a
   single self-hosted deployment, that is everyone; for a genuinely diversified
   fleet, a subset. Correlated infrastructure is the quantity to measure, not
   operator count.

### Therefore: trust is RELOCATED, not eliminated

The first draft of this document claimed a deterministic leak removes
guardian-collusion exposure "and therefore" is safe. Only the first half holds.
What the design does is move trust from guardians to:

- **the `LivenessRegistry` owner** — one `setLivenessWindow` call re-partitions
  the live set immediately and in both directions (`LivenessRegistry.sol:33`);
- **block proposers and transaction ordering** — see the settlement race in §5;
- **every operator's continuous RPC access and gas balance.**

Any of those can now cost an honest operator stake. That is a _different_ risk
profile from guardian collusion, and arguably a better one, but it is not the
absence of risk.

### Terminology

**Call this rule a `leak` (or `inactivity penalty`). Reserve `slash` for the
voted, fraud-provable path.** This is not cosmetic: it keeps the fraud-proof
machinery — which exists to adjudicate _unjust votes_ — out of a path that has
no votes.

> ⚠️ **The rename does NOT resolve the conflict with SP.**
> `LivenessRegistry.sol:7,28,31` says offline "carries NO slash — it only
> shrinks the live-set" — i.e. **no stake punishment of any kind**, whatever it
> is called. A leak still burns stake, so it still contradicts that stated
> scope. Renaming only stops us from _additionally_ dragging the voted-slash
> machinery in. The substantive disagreement is real and unresolved: it is open
> question 1 in §9, and SP has to agree before any of this is built.

## 3. The state machine

Four states on one axis. Jail and stake loss are **layers**, not alternatives —
Jason's "并存".

| state       | entered when                        | effect                                                                           | exit                                  |
| ----------- | ----------------------------------- | -------------------------------------------------------------------------------- | ------------------------------------- |
| **LIVE**    | `isOffline(op) == false`            | normal participation                                                             | —                                     |
| **GRACE**   | silent, but within `livenessWindow` | **nothing** — absorbs RPC/gas/reorg jitter                                       | attest ⇒ LIVE                         |
| **JAIL**    | `isOffline(op) == true`             | excluded from the active set + quorum denominator; fee stopped; **leak accrues** | attest ⇒ LIVE (leak stops, burn kept) |
| **EJECTED** | `effectiveStake < minStake`         | forced exit; ROLE_DVT registration must be redone                                | top up stake and re-register          |

**Boundary, precisely.** `isOffline` is `block.number - lastLive > window`
(strict, `LivenessRegistry.sol:123`), and `lastLive == 0` returns `true`. So
JAIL begins one block _after_ equality, not at it. With `window = 300` blocks
(~60 min on Sepolia), a **20-minute** outage never leaves GRACE and costs
nothing; a **90-minute** outage enters JAIL for ~30 minutes and — depending on
how partial periods are handled (§5) — may cost nothing either.

**EJECTED is the answer to "一年没上线我不能一直等你".** No special "one month"
rule is needed: the escalating leak reaches the floor on its own schedule, tuned
by one parameter (§4). This is how Ethereum avoids maintaining a list of
abandoned validators.

> ⚠️ **JAIL's exclusion effect is NOT wired today.** `LivenessRegistry`
> advertises "zero SuperPaymaster-core coupling" (`:13`), and committee
> eligibility checks stake, role and guardian-exit state — **never `isOffline`**
> (`AAStarCommitteeValidator.sol:460-469`). DVT holds read helpers, but the only
> production consumer of the window is keeper logging; the offline audit is
> still gossip-based (`audit.service.ts`). **Signal deployed ≠ enforcement
> integrated**, and the consumer that would exclude a jailed operator is itself
> unbuilt work, not configuration.

## 4. The escalation curve, and how "one month" is set

Let `S_reg` be the operator's stake at registration and `S_floor = minStake`.
Under **Plan A** (Jason, 2026-09-02) `S_reg = 50`, `S_floor = 30` ⇒ **leak
budget 20 GToken**.

Per escalation period `P` of continuous downtime, burn `rate(k)` of **`S_reg`**:

```
rate(k) = min(base + inc × (k − 1), max)      k = 1, 2, 3, …
```

With `base = 2%`, `inc = 1%`, `max = 10%` (see §7 for where these numbers come
from and why they are **not** yet a citation):

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

**Eight periods to ejection** (independently recomputed and confirmed in
review). That number is the whole tuning surface:

| choose `P` | time to ejection                                |
| ---------- | ----------------------------------------------- |
| 1 day      | ~8 days                                         |
| **4 days** | **~1 month** ✓ matches Jason's stated intuition |
| 1 week     | ~2 months                                       |

**Recommendation: `P = 4 days`** — ejection at roughly a month of continuous
unattended downtime, with the first periods cheap enough that an ordinary
incident is not punitive. (Add ~1 liveness window of initial silence before the
leak starts.)

### Three properties this curve must have

1. **Percentages are of `S_reg`, not of the current balance.** _Corrected:_ the
   first draft justified this by claiming a percentage of the current balance
   "approaches the floor but never crosses it". **That is false.** A percentage
   of the current balance decays toward **zero**, not toward 30, and crosses the
   floor in finite time — applying these same rates to the running balance gives
   `49, 47.5, 45.6, 43.3, 40.7, 37.9, 34.9, 31.7, 28.6`, ejecting in period
   **9** rather than never. The real reasons to prefer `S_reg` are that it makes
   the schedule **predictable and auditable in advance** and keeps the burn from
   shrinking exactly when escalation is supposed to bite. Only a percentage of
   the _margin above the floor_ would be genuinely asymptotic.
2. **Recovery stops the leak; it does not refund it.** Otherwise flapping is
   free.
3. **The escalation level decays with uptime, it does not reset.** A hard reset
   lets a node flap at period boundaries and never leave `k = 1`. Suggested: `k`
   decays one step per uptime period — the analogue of Ethereum's
   inactivity-score bleed-off.

> ⚠️ **`S_reg` is not stored anywhere.** Registration records node identity and
> the operator binding; it checks `_isStaked` at that moment and keeps no stake
> snapshot (`AAStarValidator.sol:884-890`). The curve's own base quantity is
> therefore not currently readable, and the design does not yet define whether a
> top-up raises `S_reg`, whether re-registration resets it, or which value a
> second outage uses. See §5.

## 5. What this mechanism actually needs on-chain — and does not have

**This section is the reason the document is a sketch and not a spec.** The
first draft claimed the leak is "a pure function of `lastLive`,
`livenessWindow`, `block.number`". Those three inputs are enough to answer _"is
this operator offline right now?"_ They are **not** enough to settle money.
Concretely, with today's `LivenessRegistry` (`_lastLive` is a single mapping
slot declared at `:71` and overwritten on every attestation at `:101`, keeping
no history):

| gap                                                               | consequence if built anyway                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| ----------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **No record that an outage happened** — only `lastLive`           | An operator that has been down for weeks can **attest one block before settlement and erase the entire history**. The penalty is trivially evadable                                                                                                                                                                                                                                                                                                                                          |
| **No settlement checkpoint** (`lastSettledPeriod` / accrued debt) | Any number of permissionless callers can settle the **same** outage repeatedly. Over-charging is as easy as calling twice                                                                                                                                                                                                                                                                                                                                                                    |
| **Outcome depends on transaction ordering**                       | If settlement is possible, a searcher can front-run an honest operator's recovery attestation to force a burn; if the operator wins the race, the burn vanishes. **A monetary outcome decided by mempool ordering is not "objective"**                                                                                                                                                                                                                                                       |
| **No durable episode start**                                      | Weaker than the rows above, but not derivable in general. For an operator that previously attested and has stayed offline the start is `lastLive + window + 1` — but that form reintroduces the addition overflow the source deliberately avoids by subtracting (`LivenessRegistry.sol:114,120`), it is unavailable for a **never-attested** operator (`lastLive == 0`, a distinct state with no episode start at all), and it evaporates the moment an attestation moves `lastLive` (row 1) |
| **No escalation-score state**                                     | The decay rule in §4.3 is unimplementable after any recovery                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| **`S_reg` not stored** (§4)                                       | The burn base does not exist on-chain                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| **No suitable burn primitive**                                    | `GTokenStaking.slashByDVT` is `authorizedSlashers`-gated and takes a **caller-supplied amount** (`:498,:504`) — the opposite shape of a permissionless, self-computing leak                                                                                                                                                                                                                                                                                                                  |
| **Nobody is paid to call `settle`**                               | Accrual can be a pure function of time and be _realised_ later — but nothing is realised until someone pays gas, so with no incentive the penalty exists on paper and never moves stake. **Accrual ≠ realisation**; the design needs both                                                                                                                                                                                                                                                    |

**Mutable parameters break settlement too — this is a state requirement, not a
governance nicety.** `livenessWindow` (and any tier value) can be changed with
immediate effect, and the registry stores only the _current_ window (the window
lives in a single slot, `LivenessRegistry.sol:68`, read back by
`livenessWindow()` at `:136`; the governance note at `:33` spells out that a
change re-partitions the live set immediately. SP's `Registry.configureRole`
overwrites a whole role config the same way — `roleConfigs[roleId] = config` at
`Registry.sol:462`, retaining no history). If a parameter moves between the
outage and its settlement, **the caller's timing decides which parameter set is
applied** — the exact caller-dependence a computed settlement is supposed to
eliminate. Storing the tiers "on-chain" is therefore not sufficient; they must
be **versioned with activation blocks, or snapshotted into the episode when it
opens**, so the charge is reconstructible for the epoch being charged.

**Minimum additional state before this is specifiable:**
`offlineSinceBlock(op)`, `lastSettledPeriod(op)` or a cumulative penalty debt, a
stored `S_reg` with defined top-up/re-registration semantics, an escalation
score with decay, and an explicit decision on **how `attestLiveness` preserves
outstanding debt before it overwrites `lastLive`** — it must _crystallise_ the
accrued amount into a debt slot, **not necessarily settle it inline**: burning
inside the attestation path couples liveness to a token transfer and invites a
revert/DoS vector where a node cannot re-attest at all. Something must happen
there, or the evasion in row 1 stands).

**Invariants to pin down at the same time:** idempotency of `settle`, behaviour
under reorgs, whether partial periods accrue pro rata or only on completion,
rounding direction, and a correlated-outage circuit breaker so a shared-provider
incident cannot drain a whole cohort at once (§2, disanalogy 3).

⚠️ **That circuit breaker is named here and nowhere designed.** It has no
threshold, no activator, no defined scope (does it freeze accrual, or only
realisation?), and no anti-gaming analysis — an attacker who can trip it can
also suppress honest penalties. Treat it as an open sub-problem of comparable
weight to the settlement state itself, not as a mitigation that can be assumed.

## 6. Why this needs Plan A to exist at all

With the margin measured on 2026-09-01 — `effectiveStake == minStake == 30e18`,
**margin zero** — the first non-zero burn (2% of 30 = 0.6, leaving 29.4) already
fails `>= minStake`. **The eligibility outcome is a cliff regardless of how
gentle the curve is.** (The monetary loss still tracks the curve; it is the
_eligibility_ consequence that collapses.)

So the ordering is fixed: **Plan A — top every operator up to 50 — is a
precondition of this design, not a companion to it.**

Plan A's own gap: `_isStaked` (`AAStarValidator.sol:950`) backs **both**
registration (`:887`) and continued eligibility (`:940`,
`AAStarCommitteeValidator.sol:464`), and the predicate is `>= minStake`. Nothing
stops a new operator joining at exactly `minStake` with zero margin. With
`requireStake = false` registration is owner-only and checks no stake at all
(`:844-845` — `require(!requireStake)` then `require(msg.sender == owner)`). So
"everyone stakes 50" is an **onboarding convention**, enforceable only while
registration stays owner-gated. Making it a mechanism needs **separate entry and
ejection thresholds** in the contract — the Beacon Chain shape — and the
validator is **not upgradeable**, so that lands with the next redeploy.

## 7. The `2 / 1 / 10` numbers are NOT yet a parameter table

`IRegistry.RoleConfig` declares
`slashThreshold / slashBase / slashInc / slashMax` (`IRegistry.sol:48-51`) and
ROLE_DVT carries on-chain values `10 / 2 / 1 / 10`. **Zero code in SP's
`contracts/src/` reads any of them** — verified by grep over the whole tree.

**Do not treat these as the percentages used in §4.** The interface documents
them as slash **amount**, **increment** and **maximum** (`IRegistry.sol:32-35`);
the original 2025-12-20 comments gloss `slashBase` as 基础惩罚金额 — an
_amount_, not a rate. Because nothing reads them, **their units have no
executable definition at all**, and reading `2` as "2%" is archaeology, not a
citation. The §4 curve is a _proposal that happens to be shaped like these
numbers_, and the resemblance is the argument for reusing the fields — not
evidence about what they mean.

If reused: define the units explicitly (basis points), validate bounds on-chain,
version the interface, and migrate the values deliberately.

> ⚠️ **Name collision — always write these fully qualified.**
> `RoleConfig.slashThreshold` (uint32, per role, `= 10`, glossed in a 2025-12-20
> comment as 惩罚触发阈值 / error count but **read by no code, so its units are
> as undefined as the rest of the group**, dead) vs
> `BLSAggregator.slashThresholds[level]` (uint8, per severity, `= 2/3/3`,
> **signature count**, live). Two sessions have already talked past each other
> on this.

## 8. Preconditions — none met today

| #   | precondition                                                          | state                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| --- | --------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | the settlement state of §5 designed and built                         | ❌ **not started; this is the blocking item**                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| 2   | `LivenessRegistry.owner` moved to a timelock/multisig                 | ❌ owner is an EOA (`0xb5600060…`). The contract's own header says the owner **MUST** be a timelock, because `setLivenessWindow` re-partitions the live set immediately and in both directions. Once the window decides who loses stake, this stops being optional                                                                                                                                                                                                                                                                                                     |
| 3   | JAIL enforcement wired (a consumer that excludes an offline operator) | ❌ nothing reads `isOffline` for eligibility (§3)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| 4   | registry address in node env + a first attestation                    | ❌ `AUDIT_LIVENESS_REGISTRY_ADDRESS` unset; `lastLive == 0` fleet-wide, so every operator currently reads `isOffline == true`. This one **is** just configuration — but it only enables _attesting_                                                                                                                                                                                                                                                                                                                                                                    |
| 5   | Plan A margin in place (§6)                                           | ❌ every operator holds exactly `minStake`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| 6   | attest cadence cross-checked against the on-chain window              | ✅ **built** — the keeper runs a watchdog that reads `lastLive` and the head and attests as soon as `head - lastLive` has spent `window/3`, so the configured interval is nominal only. Two residual gaps are known and recorded rather than claimed fixed: the watchdog's own POLL PERIOD is still tuned from a measured block-time average (not a bound), so a block-rate burst can open a blind spot of up to the 60s ceiling; and reads are pinned by block NUMBER, which a reorg can re-point. Eliminating both needs block-head subscription — a separate change |
| 7   | the N gate                                                            | ❌ see [`SLASH_ROLLOUT_GATE.md`](../SLASH_ROLLOUT_GATE.md). **The margin buys time, not safety**: the count axis is still `minCommittee == activeCount == 3`, so an ejection at N=3 halts the stack however gently it was reached                                                                                                                                                                                                                                                                                                                                      |

## 9. Open questions for SP

1. **Does SP accept a stake-draining leak keyed off `LivenessRegistry`?** Its
   stated scope is jail-only. Modelling this as a leak narrows the conflict but
   does not erase it.
2. **Where does settlement live, and who pays for it?** §5's state has to live
   somewhere, and a permissionless `settle(op)` needs an incentive.
3. **Can the signal be strengthened to prove service, not just key activity?**
   Disanalogy 2 in §2 is the design's weakest joint: attesting is cheap and
   proves almost nothing about co-signing.
4. **Guardian slashing is untouched by all of this.** `BLSAggregator:2003` reads
   the full remaining lock and passes it as the penalty, so the contract cannot
   express a partial guardian slash: staking 50 and staking 30 both end at zero.
   **Plan A does not help guardians**; capping that path is a separate change.
