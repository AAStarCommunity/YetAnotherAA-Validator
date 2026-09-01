# The fraud-proof verifier threshold curve — ρ as a computable quantity

> **Status: DESIGN NOTE, answering an open question, not a build order.**
> Nothing here is implemented and the contract does not support it today.
>
> Discharges an SP request made on CC-89 (2026-08-26) that was never answered:
> items (1) selector and (2) the conformance fixture were delivered under CC-115
> B1, but **(3) "an M(N) threshold curve for a multi-verifier aggregate" was
> lost when CC-89 was sealed and its remaining work moved to CC-115.** Found by
> an audit on 2026-09-02. It carries a paper consequence, quoted from the
> original ask:
>
> > ρ 的上界不是治理意愿,而是 verifier 判定正确的概率;单 verifier 阶段它是一个假设,门限阶段它是一条可计算的曲线。

## 1. Where ρ actually sits today

`BLSAggregator.fraudProofVerifier` is **one address**
(`contracts/src/modules/monitoring/BLSAggregator.sol:328`), set by governance.
`executeGuardianSlash` burns a guardian's stake on that single contract
returning `true`.

So today ρ — the probability that a guardian slash is unjust _given_ the fraud
proof was accepted — is bounded by the probability that **one** verifier is
wrong, and nothing in the system measures or constrains that. **It is an
assumption, and the honest way to write it in the paper is as an assumption.**
Governance can replace the verifier, which sets its value, but replacing a
component is not the same as bounding its error.

## 2. The curve, once there is more than one verifier

Let a slash require **M of N** independent verifiers to return `true`, each
verifier having a per-verifier false-accept rate `q` (says "fraud proven" when
it was not) and false-reject rate `r` (says "not proven" when it was).

```
P(unjust slash executes)  = P(Binom(N, q)   ≥ M)      ← false accept
P(real collusion escapes) = P(Binom(N, 1−r) <  M)      ← false reject
```

Both are Binomial tails — the same shape as the committee forgery bound in
[`SLASH_ROLLOUT_GATE.md` §2](../SLASH_ROLLOUT_GATE.md), and computable rather
than asserted. At `q = r = 1%`:

| M-of-N     | unjust slash (ρ) | collusion escapes |
| ---------- | ---------------: | ----------------: |
| **1-of-1** |     **1.00e-02** |      **1.00e-02** |
| 2-of-3     |         2.98e-04 |          2.98e-04 |
| 3-of-3     |     **1.00e-06** |      **2.97e-02** |
| 3-of-5     |         9.85e-06 |          9.85e-06 |
| 4-of-5     |         4.96e-08 |          9.80e-04 |
| 5-of-5     |         1.00e-10 |          4.90e-02 |
| 4-of-7     |         3.42e-07 |          3.42e-07 |
| 5-of-7     |         2.07e-09 |          3.40e-05 |

**Read the two columns together, never one alone.** Raising M drives ρ down and
drives escapes up, monotonically. Unanimity is the trap: `5-of-5` buys ρ = 1e-10
and lets **one in twenty** real collusions walk, which is worse than the single
verifier it replaced. The diagonal — simple majority, `2-of-3` / `3-of-5` /
`4-of-7` — is where the two errors are equal, and is the only family where
adding verifiers improves _both_.

**This is the sentence the paper can now make:** with N independent verifiers at
a majority threshold, ρ ≤ `P(Binom(N, q) ≥ ⌈(N+1)/2⌉)` — a function of N and the
per-verifier error rate, not of governance intent.

## 3. The assumption the whole curve rests on, and why it is the weak part

**Independence.** Every number above assumes verifier failures are uncorrelated.
They will not be:

- verifiers implementing the same spec share the spec's bugs;
- verifiers built from a common template share the template's bugs;
- all of them read the same on-chain state through the same RPC-visible chain,
  so a reorg or a mis-set parameter hits every one of them identically;
- the CC-115 verifier already carries a **known** common-mode defect — it reads
  the disputed token's _current_ `isOverIssued()` rather than the state at the
  disputed epoch (`OverIssueFraudProofVerifier.sol:55`, self-labelled NOT
  PRODUCTION-SAFE). N copies of that verifier are wrong together, every time.

With perfectly correlated failures the curve collapses to the `1-of-1` row **for
any N** — the table becomes a picture of a guarantee that is not there. So:

> **N verifiers built by one team from one spec are one verifier.** The curve is
> only worth the independence behind it, and independence has to be argued
> (different authors, different derivations of the evidence, ideally different
> data paths), not assumed from a count.

That argument is exactly what does not exist yet, which is why this is a design
note and not a proposal to raise N.

## 4. What the contract would need

`fraudProofVerifier` is a single `address` and `queueGuardianSlash` consults it
once. An M-of-N version needs a verifier **set** with add/remove governance, an
accept threshold, and per-case tallying of which verifiers answered — plus a
rule for a verifier that reverts or never answers (silence must not count as
either vote). None of that exists. **Sequencing note from the original ask,
which still holds: this does not block arming the single-verifier path.**

## 5. Honest status

- **ρ today is an assumption** (single verifier), and the paper should say so.
- **ρ under M-of-N is computable**, and §2 gives the function and the numbers.
- **The gap between those two statements is independence**, not arithmetic.
