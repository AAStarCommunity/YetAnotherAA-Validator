# CC-115 B3 — verifier arming evidence (Sepolia)

**COMPLETE as of 2026-09-04T05:37:12Z.** All seven arming records are now FINAL:
the four-day delay matured at 05:36:24Z and the permissionless
`applyFraudProofVerifier()` landed 48 seconds later. The verifier is ARMED on
Sepolia.

This document was assembled ahead of maturity so the freeze would be a one-line
update rather than an assembly job; records 6 and 7 below are that update.

Contract state and binding values here were read back from chain independently.
Transaction metadata — receipt `status`, gas, caller, calldata, event fields —
comes from the transaction and its receipt, and is labelled as such in record 6
rather than folded in with the reads.

## The chain being armed

|                                                              |                                                    |
| ------------------------------------------------------------ | -------------------------------------------------- |
| Registry (proxy, unchanged across the 5.4.2 → 5.8.0 upgrade) | `0xf5Bf37ca83AfdAab73691bA7eCcDfA69b8708E71`       |
| BLSAggregator (new, non-upgradeable)                         | `0xEaeC2F512eA50708211fa95533e4dBb60e3d2E5D`       |
| `version()` on that aggregator                               | `BLSAggregator-4.11.0`                             |
| `VERIFIER_ROTATION_DELAY`                                    | `345600` (4 days, == `GUARDIAN_SLASH_CASE_WINDOW`) |
| aggregator `owner()`                                         | `0xb5600060e6de5E11D3636731964218E53caadf0E`       |

The aggregator address was pinned out of band before deploying against it, which
the deploy script requires and refuses to proceed without: `version()` is a
string any contract can return, so it is not an identity proof. Three
independent sources agreed — `Registry.blsAggregator()` read directly, SP's own
handoff post, and pr-daemon's independent read.

## Arming records

| #   | Record                    | Value                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| --- | ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | **Dormant at deploy**     | `fraudProofVerifier() == 0x0` and `pendingFraudProofVerifierReadyAt() == 0` immediately before the proposal — confirmed by read, not assumed from a fresh deployment                                                                                                                                                                                                                                                                                          |
| 2   | **Verifier deployed**     | `0xa1346F1668cBf8D031Cc5D72eDA45F5788CA1cd3`                                                                                                                                                                                                                                                                                                                                                                                                                  |
|     | deploy tx                 | `0x74da9b2fa49667c79fee7aaecd7e1d9f530d23797471401a1843130a1d53e3e6`                                                                                                                                                                                                                                                                                                                                                                                          |
|     | Etherscan                 | Verified — `src/verifiers/OverIssueFraudProofVerifier.sol`, solc `v0.8.33+commit.64118f21`                                                                                                                                                                                                                                                                                                                                                                    |
|     | binding readback          | `AGGREGATOR() = 0xEaeC2F51…`, `REGISTRY() = 0xf5Bf37ca…`                                                                                                                                                                                                                                                                                                                                                                                                      |
|     | ABI                       | `verify(bytes32 domainDigest, uint256 fraudProofId, address[] guiltyGuardians, bytes fraudProof)` → selector **`0x61077735`** — read off the deployed runtime bytecode, which contains `61077735` and does not contain `65f24022`                                                                                                                                                                                                                             |
|     | ABI, corrected            | This row read `verify(bytes32,bytes32,address[],bytes)` / `0x65f24022` until 2026-09-04. `fraudProofId` is a `uint256`, not a `bytes32` (`contracts/src/interfaces/IFraudProofVerifier.sol`), so that selector belongs to no function this contract has. Left visible rather than silently rewritten: @repo:sdk is instructed to pin the selector from this manifest, and a reader who saw the old value needs to know it changed                             |
| 3   | **Proposal receipt**      | `0x2df606e5a8964ca69b13c125971c3ae34118fc0ae84e93638f69c7c4734749b2` (block 11603716)                                                                                                                                                                                                                                                                                                                                                                         |
| 4   | **readyAt**               | `1788500184` = **2026-09-04T05:36:24Z**                                                                                                                                                                                                                                                                                                                                                                                                                       |
| 5   | **Delay actually served** | `readyAt` 1788500184 (2026-09-04T05:36:24Z) → applied in the block timestamped 1788500232 (2026-09-04T05:37:12Z). Served in full, 48 s over. The two timestamps alone establish that the full delay elapsed. (The pre-maturity refusal in the negative-control table below was recorded earlier without a block-tagged locator, so unlike the rows above it is not reproducible from this document; the timestamps, not that row, are what carry this record) |
| 6   | **Apply receipt**         | `0x9add3d631cb7d0a853dbe4f8718eca629f31d48560fb86cba4a3c2c2bc2dd782` — block 11631496, `status = 1`, gasUsed 46168                                                                                                                                                                                                                                                                                                                                            |
|     | caller                    | `0xb5600060e6de5E11D3636731964218E53caadf0E`. This is also the aggregator `owner()`, which is **incidental, not required**: `applyFraudProofVerifier()` is permissionless and takes no arguments, so the owner key here bought no authority it had not already spent at propose time                                                                                                                                                                          |
|     | calldata                  | `0x585d5bc0` — the bare `applyFraudProofVerifier()` selector, no arguments. There is nothing in this transaction to choose: it can only finalise the address proposed four days earlier                                                                                                                                                                                                                                                                       |
|     | event                     | `FraudProofVerifierUpdated(address,address)` (`0x0927c220b05679c8ddca1cd3f736241175bd4f477e2770c15fee70b62fc93321`), old `0x0` → new `0xa1346F16…`                                                                                                                                                                                                                                                                                                            |
| 7   | **Final active address**  | `fraudProofVerifier() == 0xa1346F1668cBf8D031Cc5D72eDA45F5788CA1cd3`, `pendingFraudProofVerifier() == 0x0`, `pendingFraudProofVerifierReadyAt() == 0` — read at block 11632589, not taken from the receipt                                                                                                                                                                                                                                                    |
|     | binding re-read post-arm  | `AGGREGATOR() = 0xEaeC2F51…`, `REGISTRY() = 0xf5Bf37ca…` — unchanged from the deploy-time reading; the armed contract is the one that was proposed                                                                                                                                                                                                                                                                                                            |
|     | bytecode re-read post-arm | runtime code (2981 bytes) still contains `61077735` and still does not contain `65f24022` — the selector correction in record 2 holds against the ARMED contract, not only the deployed one                                                                                                                                                                                                                                                                   |

## Negative controls

A gate that is never observed to refuse is not evidence that it exists.

| probe                                                       | result                                                                                                                                                       |
| ----------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `applyFraudProofVerifier()` before `readyAt`                | reverts `VerifierRotationNotReady`                                                                                                                           |
| `proposeFraudProofVerifier(...)` from a non-owner           | reverts                                                                                                                                                      |
| deploy script against the OLD 4.3.0 aggregator              | refused at the version gate                                                                                                                                  |
| deploy script with no canonical aggregator pinned           | refused before broadcasting                                                                                                                                  |
| `applyFraudProofVerifier()` AFTER the rotation was consumed | reverts `NoPendingVerifierRotation()` (`0x17e6c91f`, selector matched against the raw revert data, not guessed from a message) — the apply is not replayable |

## Two properties of this mechanism worth stating, because they are asymmetric

**Arming is slow on purpose.** SP removed the direct `setFraudProofVerifier`
setter entirely. The only path is propose → full delay → permissionless apply,
and the four days ARE the security property (CC-48 MEDIUM-1): a public window in
which anyone can see which verifier is about to become authoritative. Shortening
it does not speed up the rollout, it removes the defence.

**Disarming is immediate.** `emergencyDisarmFraudProofVerifier` is owner-only
and takes effect at once, clearing both the active verifier and any in-flight
rotation. The contract's own reasoning: a compromised verifier can open a case
and have it executed for 100% of an accused guardian's lock **within a single
block**, so a four-day remedy would not be a remedy. Arm slowly, disarm
instantly — the asymmetry is deliberate and should not be read as an
inconsistency.

**The pending proposal does not expire.** `applyFraudProofVerifier` checks only
`readyAt != 0` and `block.timestamp >= readyAt`. Missing the exact moment costs
nothing; the rotation stays available until applied or disarmed.

## What this does and does not unblock

The CC-89 acceptance item "Verifier arming evidence" is **complete**. What that
means precisely, since "armed" is easy to over-read:

- `executeGuardianSlash` on this Sepolia aggregator is **no longer inert**. It
  previously reverted on `fraudProofVerifier == address(0)`; it now routes to
  `0xa1346F16…`. A proof that verifies can slash a guardian's ROLE_DVT lock.
- It does **not** mean the joint E2E is done. The remaining `#222` boxes — a
  crafted over-issue slash, then preflight/queue/frozen-exit/execute/auto-eject
  against the real verifier rather than `MockVerifier` — are still open, and
  they are the SP joint run.
- The **zero-margin** configuration recorded in `SLASH_ROLLOUT_GATE.md` — SP has
  exactly three registered guardians and MINOR's slash threshold is 3 — already
  existed and is unchanged by this. Arming altered neither the guardian count,
  the thresholds, nor the likelihood of a fraudulent slash; what it changed is
  that the loss transition is now **executable** on this aggregator once a
  qualifying fraudulent slash has produced an A' commitment and a proof
  verifies. Read it that way rather than as "the risk just became real". No
  route-B slash has been recorded yet — that box is still open below.
- It does **not** touch mainnet. Nothing about this arming is deployed beyond
  Sepolia, and per `guardian-collusion-slash.md §5` guardian-slash is **not
  production-activated** at the current 3-node co-located bootstrap. Note the
  wording: that document reserves "dormant" for `fraudProofVerifier == 0`, which
  this aggregator no longer is. Not-activated is a policy statement; it does not
  make the Sepolia path inert.

`deploy/apply-verifier-rotation.mjs` and the hourly
`io.aastar.dvt-apply-rotation` job no longer broadcast: they read state, find
the active verifier equal to the address they are pinned to, print "already
applied" and exit 0. That is not nothing — the same code path fails loudly on a
disarm, on a different verifier being active, or on a later rotation proposing
an address it is not pinned to, so it is now a drift guard rather than an
applier. What a green run does **not** prove is that this job performed the
apply; it did not. Before any future rotation, repoint `APPLY_EXPECTED_VERIFIER`
/ `--expect-verifier`, or the job goes red on a correct chain state.

### Who actually applied it — because neither scheduled path did

Worth recording, since the whole point of those two jobs was that nobody should
have to remember the day.

|              |                                                                                                                                                                                                                                                                             |
| ------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Proven**   | The signer `0xb5600060…` is the address derived from this repo's own `.env.sepolia` deploy key. The calldata is the bare `applyFraudProofVerifier()` selector.                                                                                                              |
| **Proven**   | The hourly launchd job did **not** broadcast: its log shows the 05:11:01Z run still reading `pending`, and the 06:11:03Z run already reading `already applied`, with no broadcast in between.                                                                               |
| **Proven**   | The GitHub Actions workflow did **not** broadcast: its last run before the apply was 2026-09-03T11:41Z, and its cron is 06:41Z — after the fact.                                                                                                                            |
| **Inferred** | So it was a manual run of `deploy/apply-verifier-rotation.mjs --broadcast` from a DVT session at ~05:37Z, which reported it to CC-115 at 05:56:43Z with that script's readback output. Nothing here is "an external party": it is this repo's own tooling, invoked by hand. |

The consequence is not that anything went wrong — the rotation was applied
correctly, 48 s after it became legal, by the intended tool. The consequence is
that **the automation's broadcast path has still never been exercised.** Both
jobs ran, on schedule, and observed the event; neither performed it. A green run
of either proves the trigger fires, not that the action works. If that path
matters for the next rotation, it needs to be tested deliberately rather than
credited from this one.
