# Guardian-Collusion Slashing (CC-89, Protocol B)

> **Historical Stage-0 design.** For CC-115 route B, the current contract seam
> is `verify(bytes32,uint256,address[],bytes)`, the accused set must equal the
> committed signer set, and SP 4.11 queues a verifier-approved case before
> executing it. Use `cc89-e2e-runbook.md` for the current integration path;
> three-parameter, subset, owner/quorum and direct-execute passages below are
> retained only to explain the evolution of the threat model.

> Stage-0 design doc. Companion to
> [`../AUDIT_SLASH_MODEL.md`](../AUDIT_SLASH_MODEL.md), which covers the DVT
> node auditing **operators**. This doc covers the inverse: slashing the
> **guardians** (the DVT co-signers themselves) when they collude. Origin: CC-89
> evaluation request from the RepCredit paper (DSR-Research-Flow).

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
  `defaultThreshold`** (which is **2** on the deployed 4.11.0 — it read 7 on
  4.1.0/4.3.0 and was lowered without N changing, so do not treat it as a
  function of committee size; `defaultThreshold` is the reputation-consensus
  path only). Using 7 overstates collusion resistance ~2–3×.
- `S_op` = a guardian's ROLE_DVT GToken lock.
- `ρ` = probability the collusion is detected **and** leads to a slash — the
  term with no code correspondent until the detection layer (stage 2) exists.

### Asset distinction — not "party" distinction

The slashed operator (`operators[operator].aPNTsBalance`, requires
ROLE_PAYMASTER_SUPER config) and the co-signing guardian (ROLE_DVT lock) are
**different assets, not guaranteed-different parties**: the BLS slash path does
**not** enforce ROLE_PAYMASTER_SUPER at slash time, and one address can hold
both roles. What is guaranteed distinct is the asset — **aPNTs balance ≠
ROLE_DVT GToken lock**, even at a shared address. The gap is that the paper's
`ρ · S_op` (a ROLE_DVT-stake loss) has no execution path targeting that asset.

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
> collusion is therefore _slash the full lock → 0 < minStake → auto-eject_,
> which both burns `S_op` and removes eligibility in one step.

Note the boundary (SP review): the check is strict `<`. To **guarantee**
ejection the slash must take the **full** lock (leaving 0), not `minStake` —
leaving exactly `minStake` still passes the check. `executeGuardianSlash`
slashes the full lock for this reason.

## 3. Trigger authority — how the circular dependency is broken

The obvious problem: `queueSlashWithConsensus` / `verifyAndExecute` require
`msg.sender == DVT_VALIDATOR || owner()`, and the colluders **are** that quorum
— they will never slash themselves. A same-quorum trigger cannot work.

SP's `executeGuardianSlash` (BLSAggregator 4.2.0, **PR #370 — merged, but
dormant** until a verifier is wired) resolves this at the contract layer:

| Property                                | How                                                                  | Why it matters                                                                                                                                                                   |
| --------------------------------------- | -------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Permissionless call, verifier-gated** | no caller-identity check; gated by `IFraudProofVerifier.verify(...)` | fraud _validity_, not caller identity, authorizes the slash → bypasses the colluding quorum                                                                                      |
| **Address-based** (not slot)            | slashes `roleLocks(guardian, ROLE_DVT)` by address                   | `validatorAtSlot` is reassignable (`revokeBLSPublicKey`); a slot captured at fraud time could resolve to an innocent validator later. Also blocks the revoke-key-to-escape trick |
| **Full slash, no 30% cap**              | slashes the entire lock                                              | proven collusion must lose eligibility; the operator-path 30% cap protects _honest_ operators from one bad epoch — a different threat model                                      |
| **fail-closed**                         | `fraudProofVerifier == address(0)` → revert                          | dormant until governance wires a verifier; safe to ship                                                                                                                          |

So the trigger is **solved**. At Stage 0 the remaining unbuilt half was purely
the **detection**: what does `verify()` actually check. That half is now built
and merged (§5, stage 2); the limitations that remain are listed there, not
here.

## 4. Stage-2 blueprint — `IFraudProofVerifier` (owned by this repo)

```solidity
// AS SHIPPED — contracts/src/interfaces/IFraudProofVerifier.sol
interface IFraudProofVerifier {
    function verify(
        bytes32 domainDigest,
        uint256 fraudProofId,
        address[] calldata guiltyGuardians,
        bytes calldata fraudProof
    ) external view returns (bool);
}
```

> The first `domainDigest` parameter was added after this blueprint was written
> (CC-115 B1, PR #240) to bind a proof to its domain. The sketch here showed the
> three-parameter form, whose selector belongs to no deployed function —
> integrate against the four-parameter signature above, selector
> **`0x61077735`** (`docs/evidence/cc115-b3-arming-sepolia.md`).

SP trusts only an owner-set verifier and never judges fraud itself. This repo
builds the verifier + the off-chain cross-monitoring that feeds it.

### The `view` constraint bounds ρ

`verify` is `view` → the fraud proof must reduce to **on-chain-checkable
facts**. That bounds which collusion is objectively provable:

| Slash's underlying evidence                         | Trustless `view` fraud proof?                                                                                                                                            | ρ status                                                                                        |
| --------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------- |
| over-issue (`isOverIssued()` bool)                  | ⚠️ **only within a challenge window** — a `view` verifier reads _current_ state, not the `epoch`-block state the slash was pinned to (see "historical-state gap" in §4b) | system property **only** while the disputed block's state is on-chain-provable (bounded window) |
| liveness / gossip heartbeat (today's active rule ②) | ❌ `evidenceHash` is opaque on-chain; `view` can't adjudicate                                                                                                            | needs **CC-29 LivenessRegistry** to put liveness on-chain first                                 |
| purely off-chain evidence                           | ❌                                                                                                                                                                       | stays a governance assumption                                                                   |

> **ρ is only a system property for on-chain-objective violation classes, and
> even then only within a bounded challenge window** (§4b historical-state gap).
> For off-chain-evidence slashes it remains a detection/governance assumption.
> This is the same lesson as `AUDIT_SLASH_MODEL.md §2` (only objective on-chain
> evidence may slash) applied to the accusers instead of the accused.

### Design notes for the verifier

- **`fraudProofId` must be verifier-bound to the fraud content** (e.g. a
  deterministic derivation of the disputed proposalId), not a caller-arbitrary
  value, so a valid proof cannot be "consumed" under an unrelated id. (SP's
  `guardianSlashed[fraudProofId][guardian]` is a replay guard, not a content
  binding.)
- Guilty parties are bound to the **signer address at fraud time**, not the slot
  (slot reuse — see §3).
- Replay/double-slash guard is **per-`(fraudProofId, guardian)`**
  (`guardianSlashed`), not per-id: a re-submitted proof re-slashing an
  already-slashed guardian no-ops, and an already-exited (0-lock) co-signer is
  **not** consumed — so listing an exited guardian can never burn the proof for
  the still-staked colluders (the exited-guardian griefing fix, PR #370).

## 4b. Stage-2 fraud-proof spec (draft — CC-89 stage-2 kickoff)

A fraud proof disputes **one executed slash** and asks the verifier to confirm
two independent things. The second one is the hard, newly-surfaced blocker.

**What is disputed:** an executed slash proposal
`(proposalId, operator, slashLevel, epoch, evidenceHash)` — the tuple
`verifyAndExecute` signed over. `BLSAggregator.executedProposals[proposalId]`
proves it actually ran (view-readable).

**The verifier must confirm BOTH:**

| #    | Claim                                                                    | Difficulty                                                                                                                                                                                        |
| ---- | ------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| (i)  | the cited violation was **false at `epoch`** (the slash was unjustified) | **not as easy as it looks** — a `view` verifier reads _current_ state, not the `epoch` block. `isOverIssued()` now ≠ at `epoch`. Needs a historical-state mechanism (see "historical-state gap"). |
| (ii) | a specific set of **guardian addresses co-signed** this exact proposal   | resolved by A' (SP commitment) — see "attribution gap"                                                                                                                                            |

### The attribution gap (ii) — the real stage-2 blocker

`BLSAggregator` persists **only `executedProposals[proposalId]` (a bool)**. It
does **not** store the signer set, the `signerMask`, or the signature; the
`SlashExecuted` / `SlashConsensusReached` events carry some of it but **a `view`
verifier cannot read logs**. And `signerMask → validatorAtSlot` is **not**
back-resolvable: slots are reassignable (`revokeBLSPublicKey`), so today's
mapping ≠ the fraud-time mapping. **Result: after the fact, on-chain state
cannot tell you which addresses co-signed a past slash.** You can prove the
slash was wrong (i) but not who to punish (ii).

**Resolved: A' (commitment compromise)** — decided with SP on CC-89
(Codex-reviewed). Three options were weighed:

| Option                                                                                                              | Mechanism | Verdict                                                                                                                 |
| ------------------------------------------------------------------------------------------------------------------- | --------- | ----------------------------------------------------------------------------------------------------------------------- |
| A — SP stores the full **signer address set** per proposal                                                          | robust    | rejected: N-address `SSTORE` per slash, heavy                                                                           |
| B — proof carries `{message, claimedSigners[], sigG2}`, verifier re-checks the pairing against **current** BLS keys | dvt-only  | rejected: **breaks if a colluder revokes/rotates its BLS key post-attack** (a normal guardian right + a natural escape) |
| **A' — SP stores a 1-word fraud-time commitment**                                                                   | chosen    | ~1/N the gas of A; the commitment is a fraud-time snapshot, so post-attack key revoke can't break it                    |

**A' mechanics.** In `verifyAndExecute`, after `_checkSignatures` succeeds and
before any `revokeBLSPublicKey`, SP persists one word per proposal (reusing the
`_reconstructPkAgg` slot loop — no second traversal), on **all** success paths
(incl. reputation/combined):

```solidity
// SP 4.11 domain-separated layout (BLSAggregator.sol:255/1299). The domain separator binds
// chainId+aggregator+Registry, so the pre-image carries NO raw chainid/aggregator and uses a
// versioned bytes32 path tag (superseding the pre-4.11 string-tag + raw-chainid encoding).
bytes32 constant DOMAIN_NAME            = keccak256("SuperPaymaster.BLSConsensus.v1");
bytes32 constant TAG_SIGNERS_COMMITMENT = keccak256("SuperPaymaster.BLS.SignersCommitment.v1");
bytes32 domainSeparator = keccak256(abi.encode(DOMAIN_NAME, block.chainid, address(this), address(REGISTRY)));

mapping(uint256 proposalId => bytes32) proposalSignersCommitment;
commitment = keccak256(abi.encode(
  domainSeparator, TAG_SIGNERS_COMMITMENT,
  proposalId, expectedMessageHash, signerMask, sortedSigners));  // uint160 strict-asc, no dup/zero, ≤ MAX_VALIDATORS
```

The `verify(fraudProofId, guiltyGuardians, fraudProof)` verifier then:

1. decodes the disputed `proposalId` + `claimedSigners` from `fraudProof`;
2. reads `proposalSignersCommitment[proposalId]`, checks
   `keccak(same-structure) == commitment`;
3. **enforces `guiltyGuardians ⊆ claimedSigners`** — the commitment only proves
   the _set_, not that the accused are in it; without this subset check a valid
   commitment could slash **innocent** addresses (the actual slash targets the
   externally-supplied `guiltyGuardians`). This check is mandatory,
   verifier-side;
4. recomputes the disputed evidence (subject to the historical-state gap below).

**Data availability (dvt).** The commitment is irreversible — it cannot
reproduce the address set. So the detection layer's watcher **must record
`claimedSigners` at fraud-observation time**, and watchers must be **redundant /
multi-point**: if every watcher misses the fraud-time signer set, attribution is
permanently lost.

### The historical-state gap (i) — over-issue is not free either

Claim (i) — "the cited violation was false at `epoch`" — is **not** trivially a
`view` read. `IFraudProofVerifier.verify` is called on-chain from
`executeGuardianSlash`, where an ordinary Solidity `view` reads **current**
state. `isOverIssued()` _now_ is not `isOverIssued()` at `epoch`. If the token's
state changes between the false slash and the fraud-proof submission, a naive
`isOverIssued()` read either fails to slash or adjudicates against the wrong
block. Closing it needs one of:

- a **bounded challenge window** using `BLOCKHASH` (only the last ~256 blocks
  are reachable on-chain) + an EIP-1186 storage proof against the `epoch`
  block's state root → trustless but time-bounded;
- extending A''s commitment to also anchor the **objective evidence value** at
  fraud time (only helps if that value is itself objective, not the guardians'
  claim);
- a trusted historical-state checkpoint/oracle → weakens ρ to a governance
  assumption.

**Consequence for the paper:** over-issue ρ is a system property **only within a
bounded challenge window**, not indefinitely. This must be stated. (It also
means the challenge-period design SP deferred for the stake-exit escape is
needed for evidence-recompute too, not just for exit.)

### fraudProofId binding

`fraudProofId` must be a **deterministic derivation of the disputed
`proposalId`** (e.g. `keccak256("GUARDIAN_FRAUD", proposalId)`), computed by the
verifier — never a caller-free value — so a valid proof can't be consumed under
an unrelated id and the same fraud can't be double-filed. SP's
per-`(proof, guardian)` `guardianSlashed` map is then a correct replay guard.

### Over-issue evidence & slash convention (the filer MUST match)

To bind the disputed `token` into the commitment (closing the token-swap forgery
a naive verifier allows — CC-89 Codex review), the verifier does **not** trust a
caller-supplied message hash. It reconstructs SP's slash-only
`expectedMessageHash` from the slash fields, where the over-issue `evidenceHash`
has a **fixed preimage**:

```
// SP 4.11 domain-separated layout (BLSAggregator.sol:255/977/1299). domainSeparator binds
// chainId+aggregator+Registry; the slash message uses TAG_EXECUTE_SLASH and has NO empty rep arrays
// and NO raw chainid; the commitment uses TAG_SIGNERS_COMMITMENT (bytes32), not a string tag.
domainSeparator = keccak256(abi.encode(keccak256("SuperPaymaster.BLSConsensus.v1"),
                                       chainid, aggregator, registry))
evidenceHash    = keccak256(abi.encode("DVT_OVERISSUE_EVIDENCE_V1", token, operator, epoch))
messageHash     = keccak256(abi.encode(domainSeparator, keccak256("SuperPaymaster.BLS.ExecuteSlash.v1"),
                                       proposalId, operator, slashLevel, epoch, evidenceHash))
commitment      = keccak256(abi.encode(domainSeparator, keccak256("SuperPaymaster.BLS.SignersCommitment.v1"),
                                       proposalId, messageHash, signerMask, claimedSigners))
```

**Whoever files an over-issue slash (the E2E filer / the future audit rule)
MUST**:

1. set
   `evidenceHash = keccak256(abi.encode("DVT_OVERISSUE_EVIDENCE_V1", token, operator, epoch))`;
2. file it as a **pure** slash — `repUsers` **and** `newScores` both empty. SP's
   slash-only branch fires on `repUsers.length == 0` alone, but the verifier
   only recognises the canonical empty/empty form; a non-empty `newScores`
   yields a different `messageHash` and the proof will (fail-closed) not verify.

Any deviation just means that slash cannot be fraud-proven (no wrongful slash) —
but it is a **cross-repo alignment point**, not something the verifier can
self-enforce.

### Prerequisites (HISTORICAL — written before stage 2 was built)

> These were the blockers as of Stage 0. Stage 2 has since been built, merged
> and armed on Sepolia (§5). Items 1-2 below describe **production-safety** gaps
> that remain open; they are no longer implementation blockers. Item 3 is built
> (the watcher, #224).

1. **An armed, on-chain-objective slash rule** to defend. Today none exists:
   over-issue is a _view_ (not a slash), liveness is _auto-jail_ (not a
   stake-slash), the slash pipeline is dormant (`AUDIT_SLASH_MODEL.md §4`). No
   armed slash ⇒ nothing to fraud-prove.
2. **A historical-state / challenge-window mechanism** for claim (i) — a `view`
   verifier can't read `epoch`-block state (above). Bounds when a fraud proof
   can be filed.
3. **The claimedSigners watcher** (dvt, redundant) — needed to reproduce the set
   the A' commitment only anchors.
4. **Liveness class only:** CC-29 `LivenessRegistry` deployed (liveness must be
   an on-chain fact before a `view` proof can dispute an offline-slash).
5. Attribution direction (A') is **decided**; SP changing `verifyAndExecute` (a
   load-bearing consensus path) still requires spec alignment before code.

The spec was complete enough to build against, and the implementation has since
been built and merged (§5). What items 1-2 (+ 4 for liveness) now gate is
**production activation**, not writing the code. Orthogonal: the **stake-exit
escape** (a guardian withdrawing its ROLE_DVT lock to 0 before the proof →
`executeGuardianSlash` skips) is a challenger-mechanism concern (challenge
period / withdrawal freeze), tracked separately.

## 5. Ownership & sequencing

| Stage                                                        | Owner                                       | Status                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| ------------------------------------------------------------ | ------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1 — `executeGuardianSlash` thin entry                        | SP                                          | ✅ **merged** (PR #370) and, on **Sepolia only**, no longer inert: BLSAggregator-4.11.0 `0xEaeC2F51…` has `fraudProofVerifier() == 0xa1346F16…` since 2026-09-04T05:37:12Z (`docs/evidence/cc115-b3-arming-sepolia.md`). This evidence covers that aggregator only — it is not a deployment inventory, so any other deployment must be read independently; one with `fraudProofVerifier == 0` is dormant/fail-closed. Address-based, per-`(proof,guardian)` idempotent. |
| 0 — this doc (auto-eject + threat model + trigger authority) | dvt                                         | PR #221                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| 2 — `IFraudProofVerifier` + off-chain detection (produces ρ) | dvt (+ SP `proposalSignersCommitment`, §4b) | ✅ **built + merged**: verifier (#223), watcher (#224), assembler (#225), DVT-side E2E dry-run + runbook (#226), Sepolia deploy script (#227), and the verifier now armed on Sepolia. Still open: the SP **joint** E2E against the real verifier rather than `MockVerifier` (#222), the historical-state/challenge-window mechanism, and (liveness only) CC-29.                                                                                                         |

**When to activate:**

> ⚠️ **Sepolia is technically ARMED. Do not read anything below as "inert".** On
> `0xEaeC2F51…` the fraud-proof verifier has been live since
> 2026-09-04T05:37:12Z, so a proof that verifies moves 100% of an accused
> guardian's ROLE_DVT lock **on that deployment**. What follows is
> **production-activation policy**, not contract state.

Production activation needs N large + operators independent (not co-located) +
an on-chain-verifiable independent adjudication path. At the current 3-node,
co-located, single-owner bootstrap, guardian-slash is **not
production-activated** — the anti-collusion property is provided by **trusted
owner**, and the paper's inequality is a **decentralized-phase target**, not a
current deployed property.

The word "dormant" is used elsewhere in this document to mean
`fraudProofVerifier == 0`, i.e. genuinely inert. It is deliberately NOT used
here, because on Sepolia that is no longer the case. That deployment is armed
solely so the joint E2E runs against a real verifier; it is equally not
activation — the operators behind those three guardians are still the same
party, so an armed slash path supplies no anti-collusion property the deployment
did not already lack. Arming a testnet and activating production are different
decisions, and only the first has been made.

## References

- CC-89 (coordination task) — evaluation thread and division of labour.
- `SuperPaymaster` PR #370 — `executeGuardianSlash` + `IFraudProofVerifier`.
- [`../AUDIT_SLASH_MODEL.md`](../AUDIT_SLASH_MODEL.md) — the operator-audit
  side.
- CC-29 — LivenessRegistry (prerequisite for the liveness fraud-proof class).
