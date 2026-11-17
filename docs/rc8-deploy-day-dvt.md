# rc.8 deploy day: what DVT changes

Status: **plan**. Nothing here runs before SP's rc.8 manifest PR lands. On
deploy day the steps fall in two phases:

- **Before the new contracts exist** (between SP's pin and the manifest's first
  send): the guardian PoP export ("Guardian re-registration", steps 1–3).
- **After the contracts are deployed and read back:** everything else (A10
  read-back, settings switch, detector).

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
   - In the same change, add the DVTValidator and aggregator being replaced to
     the superseded lists in `src/config/audit-address-guard.ts` (#442; it must
     be merged first) (`SUPERSEDED_DVT_VALIDATORS`,
     `SUPERSEDED_BLS_AGGREGATORS`), so a node with audit on refuses to start on
     them (DSR 2026-11-17).
   - A node with audit and the guardian watch off does not check the addresses;
     its startup log says "audit addresses NOT checked".
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

### How rc.8 does it (SP and DSR, 2026-11-17)

The guardians are registered **before** the owner hand-off, by the deployer, as
SP manifest step **A10**. DVT does not send anything. DVT's job is to produce
the A10 input: three PoP calldata entries.

The new aggregator and DVTValidator do not exist yet when the PoPs are made.
Their addresses come from SP's frozen plan, which SP precomputes at the pin.

1. **SP pins.** The frozen plan JSON gives `addresses.BLSAggregator`,
   `addresses.DVTValidator` and `pin.{block, blockHash, oldAggregator}`. It also
   gives `pin.senders.deployer.{address, nonce}`.
2. **DVT exports**, from the plan, with no transaction:

   ```
   node deploy/reregister-guardians.mjs --plan <frozen plan.json> \
     --sp-aggregator-source <BLSAggregator.sol from the rc.8 tag tree> \
     --sp-commit <40-hex rc.8 tag commit> \
     --nodes node_dev_001.json,node_dev_002.json,node_dev_003.json \
     --export-pop <out.json> --env <Sepolia RPC env>
   ```

   The source file is `contracts/src/modules/monitoring/BLSAggregator.sol` at
   the tag, fetched with `gh api`. `DOMAIN_NAME` and `TAG_POP` are extracted
   from it, not copied into the script.

   Before signing, the script checks four things, read only:
   - both precomputed addresses have no code;
   - `pin.blockHash` is the hash of `pin.block` on this chain;
   - the deployer's nonce (latest and pending) still equals the pin nonce;
   - the Registry, read from `pin.oldAggregator.REGISTRY()`, has code.

   It computes `domainSeparator` and each `popDigest` locally, signs, checks
   each PoP with a pairing check, and writes the file. The output has two parts:
   - `pop`: three entries with exactly SP's six keys: `validator`, `slot`,
     `calldata`, `aggregator`, `pinBlockHash`, `domainSeparator`
     (`manifest_exec.py`, `pop_fields`);
   - `popContext`: `dvt`, `aggregator`, `registry`, `chainId`,
     `deployerAddress`, `deployerNonce`, `pinBlock`, `pinBlockHash`, `spCommit`,
     `spAggregatorSourceSha256`, and `popDigests` in `pop` order.

3. **DVT hands the file to SP.** SP freezes the manifest with it.
4. **SP pauses everything that shares the deployer EOA.** The freeze list is
   SP's step-13 list. On the DVT side these three must be off:
   - launchd `io.aastar.dvt-apply-rotation`;
   - launchd `io.aastar.dvt-committee-keeper`;
   - the GitHub workflow "Apply Verifier Rotation".

   Check with `launchctl list | grep io.aastar.dvt-` (neither job listed) and
   `gh workflow list --all` (shows `disabled_manually`). Once #443 is merged,
   neither job falls back to the deployer key: both take `KEEPER_PRIVATE_KEY`
   only and refuse to run without it. Until then they do fall back, so keeping
   them off is the only protection. That does not stop someone from putting the
   deployer key into `KEEPER_PRIVATE_KEY`; the guarantee is "no silent
   fallback", not "can never be the deployer". They stay off anyway.

5. **A10 sends** the three calldata entries to the new **DVTValidator**
   (`popContext.dvt`). On 4.14.0 the aggregator rejects any other caller, so
   SP's A10 routing patch is needed. Before sending, A10 asserts:
   - the deployed addresses equal the plan;
   - the on-chain `domainSeparator()` and `popDigest(validator, key)` equal the
     export;
   - the versions, the wiring between the two contracts, and owner == deployer.

   After each send it reads back `validatorAtSlot` and `getBLSPublicKey`.

6. **Before the hand-off, a full read-back:** 3 active keys, slots as planned,
   none suspended.
7. **Owners move to the SAFE** (2-of-3, per SP's rc.8 owner table).

**If the deployer sends any transaction that is not part of the frozen manifest,
between the pin and A10, every precomputed address is void.** The manifest's own
deployments advance the nonce as planned and do not void anything. The manifest
stops, SP pins again, and DVT exports again. The script refuses to export unless
the nonce still equals the pin nonce, so it must run before the manifest starts
sending. If the contracts land elsewhere, A10's address assertion stops the
send.

### Signing key

The script reads only `REREGISTER_OWNER_PRIVATE_KEY`, and only for a dry run or
`--broadcast` against deployed contracts. It never falls back to `PRIVATE_KEY`,
`OWNER_PRIVATE_KEY` or `DEPLOYER_PRIVATE_KEY`, which are the deployer EOA in the
Sepolia env files (DSR 2026-11-17). On rc.8 nothing needs it: `--plan` and
`--export-pop` read no key. After the hand-off the owner is the SAFE, so
`--broadcast` cannot pass the owner check with any EOA key.

### After the hand-off

Adding or removing a guardian goes through the SAFE. Run the script against the
deployed contracts with `--deployment` and `--export-pop`, then two SAFE signers
execute the exported calldata. Here `--expect-owner` is the SAFE. On deploy day
the owner is the deployer, but A10 checks the owner, not this script.

Before signing in the SAFE, the signers check:

- the target is the DVTValidator;
- the selector is `0xaded17c5`;
- the validator, slot and the four key words decoded from the calldata match the
  node's `publicKeyEip2537`.

`cast calldata-decode` with the signature above prints these fields.

### Interface

Checked against SP main `b5e7544e3970eab24dc9a3412366140207e36b28`
(BLSAggregator-4.14.0, DVTValidator-0.8.0). SP #633 moves main to 4.14.1 / 0.8.1
and step 4 moves the DVTValidator to 0.9.0. The script holds no version string:
`--expect-versions` takes them from the tag's tree. Check the interface again
against the step-4 merge commit.

```
DVTValidator.registerBLSPublicKey(address validator, BLS.G1Point key, uint8 slot, BLS.G2Point pop)
```

- **Owner path only.** The owner branch requires the caller to be both
  `DVTValidator.owner()` and `aggregator.owner()` (`DVTValidator.sol:209`, the
  check at `:227`). The permissionless path picks the slot itself, and slot
  identity matters (mask bits, historical proofs). The script reads and records
  `permissionlessBLSRegistration()`.
- **PoP.**
  - `popDigest = keccak256(abi.encode(domainSeparator(), TAG_POP, validator, pk))`;
  - `domainSeparator() = keccak256(abi.encode(DOMAIN_NAME, chainid, aggregator, registry))`;
  - DST `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`.

  The digest is bound to the aggregator and the validator address, not to the
  DVTValidator.

- **Call target.** `BLSAggregator.registerBLSPublicKey` accepts only
  `msg.sender == DVT_VALIDATOR`.

### Rehearsed on anvil (2026-11-17)

These ran against SP's `DeployAnvil` at `b5e7544e` with throwaway BLS keys. The
pre-deployment flow is `deploy/rehearse-reregister-plan.sh` (`good` and
`nonce-moved`); rerun it against the step-4 commit before this PR leaves draft:

- **Pre-deployment flow:**
  1. Generation 1 plays the old stack.
  2. A plan with precomputed addresses for a new pair is exported before the
     pair exists.
  3. The pair is deployed in the planned order and wired (A8).
  4. The A10-equivalent assertions pass: addresses, `domainSeparator()`, and all
     three `popDigest()`.
  5. The deployer sends the calldata to the DVTValidator: 3/3 status 1.
  6. The read-back is 3 active keys, slots match, none suspended.
- **Nonce moved:** one extra deployer transaction after the export. The
  re-export stops on the nonce check, the pair lands at other addresses, and the
  address assertion stops.
- **Post-deployment modes:** `--deployment` dry run and broadcast, and
  `--export-pop` with the owner on another address sending the calldata. Both
  read back correctly, and the negative cells each stop the run.

### Review gate

This script produces transactions. Its PR keeps the strict merge gate: Codex on
the exact head with no High, plus clestons approval.

## Code changes this needs

Written against SP main `b5e7544e3970eab24dc9a3412366140207e36b28`
(BLSAggregator-4.14.0, DVTValidator-0.8.0) and checked again against SP's step-4
merge commit before deploy day. Three separate PRs, each from master (DSR
2026-11-17); **none of these protections exists until its PR is merged**, so
deploy day checks each one on master:

- re-registration script and this document: this PR;
- keeper key fallback removed: #443;
- node startup address check: #442.

1. `deploy/reregister-guardians.mjs`:
   - addresses come only from SP's output: `--plan <frozen plan>` before
     deployment (the rc.8 A10 export), or `--deployment <deploy output JSON>`
     after; `--aggregator` is gone;
   - calls `DVTValidator.registerBLSPublicKey` on the owner path;
   - checks the pair is wired to each other and that `Registry.blsAggregator()`
     is this aggregator;
   - stops if `DVTValidator.owner()` and `aggregator.owner()` differ, or the
     signer is not that owner;
   - reads and records `permissionlessBLSRegistration()`;
   - re-derives the PoP domain for the new aggregator; `--expect-versions` and
     `--expect-owner` come from SP's tag tree and owner table, never from the
     script.
   - (#443, pending) `committee-keeper.mjs` and `apply-verifier-rotation.mjs`
     take `KEEPER_PRIVATE_KEY` only; their old fallback to `PRIVATE_KEY` (the
     deployer EOA) is removed (DSR 2026-11-17).
2. `src/modules/audit`: evidence is filed through
   `BlockchainService.createProposalWithEvidence` (`blockchain.service.ts`).
   That is a TypeScript method, not a contract function. Underneath it calls the
   four-argument `createProposal(address,uint8,string,bytes32)`. Its ABI
   fragment (`blockchain.service.ts:1854`) matches `abis/DVTValidator.json` at
   `b5e7544e`. Check it again against the step-4 code. The node keeps no
   proposal-id cursor.
3. (#442, pending) Node startup (`src/config/audit-address-guard.ts`): with
   `AUDIT_ENABLED` or `AUDIT_GUARDIAN_WATCH_ENABLED` on, the node refuses to
   start when `AUDIT_DVT_VALIDATOR_ADDRESS` or `AUDIT_BLS_AGGREGATOR_ADDRESS` is
   empty or on the superseded list. With both off it does not check and logs
   that it did not (DSR 2026-11-17). The code defaults in `configuration.ts`
   move to the read-back values in a PR after the read-back.
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
    matured (`_requireCommitteeSurvivesExit`, `BLSAggregator.sol:1800`). rc.8
    sets `minThreshold` 2, `defaultThreshold` 2 and `slashThresholds` (2, 3, 3)
    with N=3 (DSR 2026-11-17). Three counted guardians equal the slash threshold
    3, so both calls revert.
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
