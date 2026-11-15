# rc.8 deploy day: what DVT changes

Status: **plan**. The steps below run only after SP's rc.8 manifest PR lands and
the rc.8 contracts are deployed and read back. Until then nothing here is
executed (DSR, 2026-11-15).

## Why there is a DVT step at all

DSR ruled on 2026-11-15 that rc.8 adds a step A7.dvt. It deploys a **new**
DVTValidator (0.9.0 at the tag; SP main at `9cacd4ec` still reports
`DVTValidator-0.8.0`, and 0.9.0 arrives with SP's step 4, so always go by
`version()` in the tag's tree, never by SP main) together with a **new**
BLSAggregator-4.14.0. Without that step, the new aggregator would have been
wired to the old DVTValidator that is live on Sepolia today. `firstProposalId`
is computed from the chain when the step runs.

Both contracts get new addresses and start with empty state:

- The guardians' BLS keys must be registered again, on the new DVTValidator.
- Every DVT setting that names a DVTValidator or aggregator address, or a start
  block, must be switched to the read-back values.

## Order

1. SP runs A7.dvt and A7 and publishes the read-back: the deploy log or manifest
   output.
2. DVT re-registers the guardians on the new DVTValidator (see "Guardian
   re-registration" below).
3. The DVT nodes and the pause detector are switched to the read-back values
   (see "Settings to change" below).
4. Only then may any step that needs a BLS proof run. SP marks these steps in
   the step-13 manifest.

## Settings to change

Every value comes from the rc.8 read-back, never from this repo or from memory.
The "Today" column was read on 2026-11-15 and only shows what changes. Do not
reuse it.

| Where                               | Setting                                                           | Today                                                       | rc.8 value                                                                | Live nodes read it today?                |
| ----------------------------------- | ----------------------------------------------------------------- | ----------------------------------------------------------- | ------------------------------------------------------------------------- | ---------------------------------------- |
| node env (all 3 containers)         | `AUDIT_DVT_VALIDATOR_ADDRESS` **(required)**                      | unset; the code default is `0x568b1486…` (old DVTValidator) | new DVTValidator                                                          | no: audit is off (`AUDIT_ENABLED` unset) |
| node env (all 3 containers)         | `AUDIT_BLS_AGGREGATOR_ADDRESS` **(required)**                     | unset; the code default is `0xEaeC2F51…` (4.11.0)           | new BLSAggregator-4.14.0, also checked against `Registry.blsAggregator()` | no: audit and guardian watch are off     |
| node env (all 3 containers)         | `AUDIT_GUARDIAN_WATCH_FROM_BLOCK` **(required)**                  | unset (0)                                                   | block where the new aggregator was deployed                               | no: guardian watch is off                |
| node env                            | start proposal id                                                 | **no such setting**: the node keeps no proposal-id cursor   | none                                                                      | —                                        |
| node env                            | `VALIDATOR_CONTRACT_ADDRESS`                                      | `0x539B9681…` (AAStarValidator, the signing path)           | **unchanged**: this is not SP's DVTValidator                              | yes                                      |
| `src/config/configuration.ts`       | code defaults for the two addresses above                         | old DVTValidator / 4.11.0 aggregator                        | new addresses, in a code PR after the read-back                           | only if the env is unset                 |
| `deploy/reregister-guardians.mjs`   | target contract, `--expect-version`                               | `--aggregator`, BLSAggregator-4.11.0                        | new DVTValidator (owner path); see below                                  | —                                        |
| `deploy/pause-job/sp-pin.json`      | `spCommit` plus ABIs                                              | SP `23e9633d…`                                              | rc.8 tag commit, via `gen-sp-pin.mjs`                                     | the pause job is not loaded              |
| `~/.aoa-pause-detector/config.json` | `spProxy`, `registry`, implementations, code hashes, `startBlock` | not deployed yet                                            | rc.8 read-back (`deploy/pause-detector/README.md`, "Deploy")              | not deployed yet                         |

Notes:

- **The detector and the pause job have no DVTValidator or aggregator setting.**
  At run time they read `SuperPaymaster.BLS_AGGREGATOR()` and
  `Registry.blsAggregator()` from the chain (`deploy/pause-job/lib/core.mjs`).
  For them the new aggregator arrives through the pinned SP and Registry
  addresses.
- **The live nodes read neither address today.** All three containers run
  without `AUDIT_ENABLED` (read with `docker inspect` on 2026-11-15). Switching
  the node settings therefore does not change today's behaviour. It matters once
  a BLS-proof step needs the nodes' audit or co-sign path. Which steps those are
  comes from SP's step-13 list, and enabling audit is a separate decision.
- **The three node settings marked required must be set explicitly** (DSR
  2026-11-15), even though the live nodes do not read them today. A node left on
  the code defaults does not fail. It watches the superseded contracts and
  silently sees nothing. The comment at `configuration.ts` "FAIL-SILENT"
  explains why. After the switch, read `Registry.blsAggregator()` and compare it
  with `AUDIT_BLS_AGGREGATOR_ADDRESS` on every node.

## Guardian re-registration

The interface below was checked against SP main at
`9cacd4ecf228ca3eb9fb99470861c57de12608c4` (SP #630, BLSAggregator-4.14.0 and
DVTValidator-0.8.0), `DVTValidator.sol:209`. It is unchanged from SP's earlier
branch. SP's step 4 is still to come, so check it once more against the step-4
merge commit.

```
registerBLSPublicKey(address validator, BLS.G1Point key, uint8 slot, BLS.G2Point pop)
```

- **Path.** The owner path: the DVTValidator owner may register any validator.
  - The permissionless path needs three things:
    `aggregator.permissionlessBLSRegistration()`, `msg.sender == validator`, and
    an eligible validator.
  - It also picks the slot itself, and slot identity matters (mask bits,
    historical proofs). So the script stays owner-only, as it is today.
  - Before sending, it reads `permissionlessBLSRegistration()` and records it.
- **Addresses.** No address is hard-coded. The DVTValidator and aggregator
  addresses come from SP's deploy log or manifest output.
- **PoP.** Every registration, including owner forwarding, needs a PoP. At
  `9cacd4ec` the PoP format is the same as the one the script already computes:
  - `popDigest = keccak256(abi.encode(domainSeparator(), TAG_POP, validator, pk))`,
    with `TAG_POP = keccak256("SuperPaymaster.BLS.PoP.v1")`
    (`BLSAggregator.sol:290`);
  - `domainSeparator() = keccak256(abi.encode(keccak256("SuperPaymaster.BLSConsensus.v1"), chainid, aggregator, registry))`;
  - DST `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`, and `blsKeyOwner` is
    keyed by `keccak256(abi.encode(pk))`.

  The digest is bound to the **aggregator** address and the validator address,
  not to the DVTValidator. PoPs are still recomputed for the new aggregator; old
  ones are worthless. The script keeps checking its digest byte for byte against
  the contract's `popDigest()` (gates 4 and 7).

- **Call target.** On 4.14.0, `BLSAggregator.registerBLSPublicKey` accepts only
  `msg.sender == DVT_VALIDATOR`. The script's current direct call to the
  aggregator would revert, so it must call the DVTValidator.
- **Who sends.** At `9cacd4ec`, the DVTValidator's registration branch checks
  `msg.sender == DVTValidator.owner()`. A follow-up SP fix changes that check to
  `aggregator.owner() == msg.sender`, as `removeValidator` already does. On rc.8
  both owners should be the same address. **Before sending, the script reads
  `DVTValidator.owner()` and `aggregator.owner()` and stops if they differ**
  (DSR 2026-11-15). If DVT does not hold that key, the script's `--export-pop`
  writes the public PoP data for the owner to submit. It never signs a
  transaction.
- **Rehearsal.**
  1. Once SP's manifest PR is out, run the script's dry run (staticCall from the
     on-chain owner) against SP's Sepolia fork rehearsal.
  2. Send the result to DSR.
  3. Only after that, the real run.
- **Review gate.** This script sends transactions. So its PR keeps the strict
  merge gate: Codex on the exact head with no High, plus clestons approval.
  (DSR's relaxed gate covers only the read-only pause detector.)

## Code changes this needs (after SP's manifest PR, not before)

1. `deploy/reregister-guardians.mjs`:
   - target DVTValidator's owner path;
   - read `permissionlessBLSRegistration()`;
   - call the DVTValidator, not the aggregator;
   - stop if `DVTValidator.owner()` and `aggregator.owner()` differ;
   - re-derive the PoP domain;
   - new `--expect-version`.
2. `src/modules/audit`: evidence is filed through
   `BlockchainService.createProposalWithEvidence` (`blockchain.service.ts`).
   That is a TypeScript method, not a contract function. Underneath it calls the
   four-argument `createProposal(address,uint8,string,bytes32)`, which is
   unchanged at `9cacd4ec` (`DVTValidator.sol:275`). Check that the ABI fragment
   still matches the step-4 code. The node keeps no proposal-id cursor.
3. `configuration.ts`: the address defaults move to the read-back values, and
   the node's startup check fails when `AUDIT_DVT_VALIDATOR_ADDRESS` or
   `AUDIT_BLS_AGGREGATOR_ADDRESS` is empty or equals a superseded address (DSR
   2026-11-15). If it is a single assertion it ships in the re-registration PR;
   if it needs structural change, it goes back to DSR first.
4. The sp-parity pin (`ci/sp-parity-pin`) is set to SP's step-4 merge commit.

## Operations notes from SP #630 (BLSAggregator-4.14.0)

Read from SP main `9cacd4ec`. Re-check them against the step-4 merge commit.

- **A guardian cannot leave when the committee sits exactly at a quorum.**
  - Two calls refuse a departure that would break a configured quorum:
    `requestGuardianExit` (guardian-initiated) and
    `DVTValidator.removeValidator` (owner, forwarded through the DVTValidator).
  - They refuse when the number of counted guardians equals any configured
    threshold: `minThreshold`, `defaultThreshold`, or any
    `slashThresholds[level]` (`_isRequiredThreshold`, `BLSAggregator.sol:1780`).
    A guardian is counted when it has an active key, is not suspended, holds
    `ROLE_DVT` with at least the minimum stake, and its exit notice has not
    matured (`_requireCommitteeSurvivesExit`, `BLSAggregator.sol:1800`). At N=3
    with a threshold of 3, both calls revert.
  - The way out is for the aggregator owner to call
    `BLSAggregator.revokeAndSuspend(validator)` directly. It skips the quorum
    check, suspends the guardian and revokes its key. A direct owner call to
    `revokeBLSPublicKey` also skips the check, but it does not suspend, so the
    guardian could register again on the permissionless path. That path is open
    only while `permissionlessBLSRegistration()` is true. rc.8 expects it to be
    false. **If the flag is true, revoke does not mean removal**: use
    `revokeAndSuspend`.
  - Losing that guardian then leaves the committee below that quorum. Proofs
    that need the quorum stop working until a new guardian registers.
- **`proposalSignersCommitment` keys depend on the path** (`_commitSigners`):
  - execute-slash and reputation: the key is the `proposalId`;
  - queue-slash: the key is `uint256(expectedMessageHash)`;
  - generic `executeProposal`: the key is its replay key.

  The `SignersCommitted(key, signerMask)` event carries the key. Nothing in the
  node or audit reads this mapping today. The users are the over-issue fraud
  verifier and the fork drill in `reregister-guardians.mjs`, both on the
  execute-slash path.

- **The commitment now includes a block hash.** The 4.14.0 pre-image ends with
  `blockhash(block.number - 1)` (`BLSAggregator.sol:1386`).
  `contracts/src/verifiers/OverIssueFraudProofVerifier.sol` recomputes the
  commitment without it, so against 4.14.0 it never matches and every honest
  fraud proof is rejected.
  - The fork drill (`--export-fraud-drill`) writes the commitment straight into
    the fork using the old pre-image, so it would still pass and hide this.
  - Neither matters for rc.8: no fraud-proof verifier is set there (next item).
    Tracked in #441 as a prerequisite for enabling guardian slash.
  - The deploy script already blocks this: Gate A' in
    `contracts/script/DeployOverIssueVerifier.s.sol` refuses to deploy the
    current verifier against any BLSAggregator from 4.13.0 on, with no override.
  - Before any 5.5.0 verifier is deployed against a 4.14.0 or later aggregator,
    the verifier and the drill must take the parent block hash as an input.
- **Do not verify any stake-slash path on deploy day.** DSR stated on 2026-11-15
  that the rc.8 aggregator will not be authorised as a `GTokenStaking` slasher.
  That is deploy state, not code: SP's own comment (`BLSAggregator.sol:43`) says
  the aggregator is already authorised. Read
  `GTokenStaking.authorizedSlashers(aggregator)` from the chain on deploy day
  and record the value rather than relying on this line. With
  `fraudProofVerifier == 0`, the 5.5.0 guardian-slash path cannot be reached.
  Deploy day checks registration, proofs and the detector only.
