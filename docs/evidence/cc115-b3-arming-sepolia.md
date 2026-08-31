# CC-115 B3 — verifier arming evidence (Sepolia)

Assembled so the B3 manifest freeze is a one-line update when the delay matures,
not an assembly job. Five of the six arming records below are FINAL. The sixth
cannot exist yet by construction: the four-day delay is the security property,
not an obstacle to route around.

Every value here was read back from chain, not taken from a transaction receipt.

## The chain being armed

| | |
|---|---|
| Registry (proxy, unchanged across the 5.4.2 → 5.8.0 upgrade) | `0xf5Bf37ca83AfdAab73691bA7eCcDfA69b8708E71` |
| BLSAggregator (new, non-upgradeable) | `0xEaeC2F512eA50708211fa95533e4dBb60e3d2E5D` |
| `version()` on that aggregator | `BLSAggregator-4.11.0` |
| `VERIFIER_ROTATION_DELAY` | `345600` (4 days, == `GUARDIAN_SLASH_CASE_WINDOW`) |
| aggregator `owner()` | `0xb5600060e6de5E11D3636731964218E53caadf0E` |

The aggregator address was pinned out of band before deploying against it, which
the deploy script requires and refuses to proceed without: `version()` is a
string any contract can return, so it is not an identity proof. Three independent
sources agreed — `Registry.blsAggregator()` read directly, SP's own handoff post,
and pr-daemon's independent read.

## Arming records

| # | Record | Value |
|---|---|---|
| 1 | **Dormant at deploy** | `fraudProofVerifier() == 0x0` and `pendingFraudProofVerifierReadyAt() == 0` immediately before the proposal — confirmed by read, not assumed from a fresh deployment |
| 2 | **Verifier deployed** | `0xa1346F1668cBf8D031Cc5D72eDA45F5788CA1cd3` |
| | deploy tx | `0x74da9b2fa49667c79fee7aaecd7e1d9f530d23797471401a1843130a1d53e3e6` |
| | Etherscan | Verified — `src/verifiers/OverIssueFraudProofVerifier.sol`, solc `v0.8.33+commit.64118f21` |
| | binding readback | `AGGREGATOR() = 0xEaeC2F51…`, `REGISTRY() = 0xf5Bf37ca…` |
| | ABI | `verify(bytes32,bytes32,address[],bytes)` → selector `0x65f24022` (the four-parameter domain-bound form) |
| 3 | **Proposal receipt** | `0x2df606e5a8964ca69b13c125971c3ae34118fc0ae84e93638f69c7c4734749b2` (block 11603716) |
| 4 | **readyAt** | `1788500184` = **2026-09-04T05:36:24Z** |
| 5 | **Delay actually served** | see the negative control below; final confirmation is record 6 |
| 6 | **Apply receipt** | ⏳ NOT YET — earliest 2026-09-04T05:36:24Z |
| 7 | **Final active address** | ⏳ NOT YET — `fraudProofVerifier()` is still `0x0` |

## Negative controls

A gate that is never observed to refuse is not evidence that it exists.

| probe | result |
|---|---|
| `applyFraudProofVerifier()` before `readyAt` | reverts `VerifierRotationNotReady` |
| `proposeFraudProofVerifier(...)` from a non-owner | reverts |
| deploy script against the OLD 4.3.0 aggregator | refused at the version gate |
| deploy script with no canonical aggregator pinned | refused before broadcasting |

## Two properties of this mechanism worth stating, because they are asymmetric

**Arming is slow on purpose.** SP removed the direct `setFraudProofVerifier`
setter entirely. The only path is propose → full delay → permissionless apply,
and the four days ARE the security property (CC-48 MEDIUM-1): a public window in
which anyone can see which verifier is about to become authoritative. Shortening
it does not speed up the rollout, it removes the defence.

**Disarming is immediate.** `emergencyDisarmFraudProofVerifier` is owner-only and
takes effect at once, clearing both the active verifier and any in-flight
rotation. The contract's own reasoning: a compromised verifier can open a case
and have it executed for 100% of an accused guardian's lock **within a single
block**, so a four-day remedy would not be a remedy. Arm slowly, disarm instantly
— the asymmetry is deliberate and should not be read as an inconsistency.

**The pending proposal does not expire.** `applyFraudProofVerifier` checks only
`readyAt != 0` and `block.timestamp >= readyAt`. Missing the exact moment costs
nothing; the rotation stays available until applied or disarmed.

## What remains, and who can do it

`applyFraudProofVerifier()` is **permissionless** — any funded key, no arguments,
no owner involvement. Run `deploy/apply-verifier-rotation.mjs` on or after
2026-09-04T05:36:24Z; it refuses to act early and reads the result back rather
than trusting the receipt.

After that, records 6 and 7 are filled and the DVT half of the CC-89 acceptance
checklist item "Verifier arming evidence" is complete.
