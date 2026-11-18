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
   - With audit or the guardian watch on, the node also refuses an address with
     surrounding whitespace, the zero address, or a mixed-case address with a
     wrong EIP-55 checksum (#445, #446). Such a value used to start and then
     silently disable the watcher; it now stops startup, so check the values
     before restarting a node.
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

   `node_dev_00{1,2,3}.json` are the author's **test** guardian keys for
   dvt1/2/3, as the author recalls. They are for testnets only (author, via DSR,
   2026-11-18). OP mainnet guardians must use separately generated keys, kept
   outside this directory and every checkout of this repository. The author
   decides how those keys are generated and kept; that decision is still
   pending.

   The source file is `contracts/src/modules/monitoring/BLSAggregator.sol` at
   the tag, fetched with `gh api`. `DOMAIN_NAME` and `TAG_POP` are extracted
   from it, not copied into the script.

   Before signing, the script checks four things, read only:
   - both precomputed addresses have no code;
   - `pin.blockHash` is the hash of `pin.block` on this chain;
   - the deployer's nonce (latest and pending) still equals the pin nonce;
   - the Registry, read from `pin.oldAggregator.REGISTRY()`, has code.

   It computes `domainSeparator` and each `popDigest` locally, signs, checks
   each PoP with a pairing check, and writes the file. The pairing check only
   shows the signature matches the key derived from the same secret. What
   catches a wrong key is the secret↔public-key comparison in the node file, and
   then SP's A10 (clestons #444). The output has three parts:
   - `pop`: three entries with exactly SP's six keys: `validator`, `slot`,
     `calldata`, `aggregator`, `pinBlockHash`, `domainSeparator`
     (`manifest_exec.py`, `pop_fields`);
   - `popContext`: `dvt`, `aggregator`, `registry`, `chainId`,
     `deployerAddress`, `deployerNonce`, `pinBlock`, `pinBlockHash`, `spCommit`,
     `spAggregatorSourceSha256`, and `popDigests` in `pop` order;
   - `aggregatorSourceVersion`, a top-level field outside `popContext` (DSR
     2026-11-18). It holds the `version()` string the source returns, for
     example `BLSAggregator-4.14.2`. The contract does not exist yet, so this is
     read from `--sp-aggregator-source`. The source must contain exactly one
     such line, or the export stops. SP's adapter requires this field to equal
     the aggregator in its `RELEASE_VERSIONS`, and rejects an export without it.

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

### No signing key: `--broadcast` is disabled

The script sends no transaction and uses no EOA key (DSR 2026-11-18). Daybreak
on `63a484d0` found a High in the old `--broadcast` path. Its only check that
the RPC was the real chain was `chainId`, which a Sepolia fork shares. A live
key could therefore sign a valid Sepolia transaction for a fork, and that
transaction could later be replayed on Sepolia. rc.8 never used that path,
because the SAFE executes the calldata. So the path was removed rather than
given a network check.

- `--broadcast` anywhere on the command line exits 1 with "--broadcast is
  disabled in rc.8". This happens before any file is read and before any RPC
  request is sent. `npm run check:reregister` pins it in CI, and a control run
  shows that its file and RPC recorders do see a normal run.
- `REREGISTER_OWNER_PRIVATE_KEY` is no longer used.
- From the env file only `SEPOLIA_RPC_URL`, `ETH_RPC_URL` and `RPC_URL` are
  kept. Every other line, including the deployer keys the Sepolia env files
  hold, is dropped as the file is split. The file is still read whole, so those
  keys pass through memory, though none is kept, used or printed. To avoid even
  that, pass an env file that holds only the RPC URL.
- The script still reads the node files' BLS secret keys, to sign each PoP; they
  never leave the process.

Restoring `--broadcast` has a precondition, see "Follow-ups".

### After the hand-off

Adding or removing a guardian goes through the SAFE. Run the script against the
deployed contracts with `--deployment` and `--export-pop`, then two SAFE signers
execute the exported calldata. Here `--expect-owner` is the SAFE. On deploy day
the owner is the deployer, but A10 checks the owner, not this script.

Every gate of the registration path (the dry run and `--export-pop`) reads state
at one block. `--export-fraud-drill`, already stale against 4.14.0 (#441), is
not covered. The export records that block as
`basis: {block, blockHash, timestamp}`. It also records the reads the gates
relied on, as `reads`, with their digest `readsDigest`:

- both contracts' code hashes;
- the routing: `DVTValidator.BLS_AGGREGATOR()`, `aggregator.DVT_VALIDATOR()`,
  `REGISTRY()` and `Registry.blsAggregator()`;
- both owners and both versions;
- `permissionlessBLSRegistration`, the domain separator with `DOMAIN_NAME`,
  `TAG_POP` and `MAX_VALIDATORS`, the staking address and `minStake`;
- for each guardian: its slot holder, suspension, active flag, slot and key, the
  key's `blsKeyOwner`, `ROLE_DVT`, its lock and its exit notice.

The calldata carries no state commitment of its own. So, **immediately before
executing in the SAFE**, re-run the same command to a new file. Then:

- it must pass every gate again;
- its `readsDigest` must equal the first export's, and only `basis` may differ;
- its `registrations[].calldata` must be identical.

A difference means the state moved since the export: stop and find out why. The
rehearsal checks that a re-export on a later block reproduces the digest, and
that a guardian suspended after the export stops the re-run.

Before signing in the SAFE, the signers also check:

- **the export's chain is the real one.** Take `basis` from the **final
  re-export**, the one made just before executing. Read the block hash at
  `basis.block` from a block explorer or a second provider, not the RPC the
  script used, and check that it equals `basis.blockHash` (clestons #444,
  Medium). If they differ, or the hash cannot be read, stop. The script's own
  end-of-run hash check and the re-run use the same RPC, so a same-chain-ID fork
  would pass both. The calldata would be the same on a fork, but the state gates
  (for example, a guardian already active with another key) would have read the
  fork's state. This catches an ordinary fork; it does not authenticate every
  state answer of a malicious RPC;
- the target is the DVTValidator;
- the selector is `0xaded17c5`;
- the validator, slot and the four key words decoded from the calldata match the
  node's `publicKeyEip2537`.

`cast calldata-decode` with the signature above prints these fields.

The script also refuses two cases where the call itself would succeed (Daybreak
on `63a484d0`, M1 and M2):

- **A different key for an active guardian.** A guardian that is active in this
  slot with a different BLS key would have its key silently rotated. The script
  stops, and prints the first and last bytes of the on-chain key and of the
  file's key, enough to tell which one is stale. There is no key-rotation mode.
- **A guardian that cannot sign.** The guardian must:
  - hold `ROLE_DVT`;
  - have a `GTokenStaking.roleLocks` amount of at least `minStake`;
  - have no exit notice in effect.

  These are the checks SP's `_reconstructPkAgg` makes at every aggregation
  (`BLSAggregator.sol` at `f2b2cd9b`). Any read that fails stops the run. These
  checks apply to `--deployment`, not to `--plan`: on deploy day A10 registers
  the guardians on an aggregator that does not exist yet.

**A guardian that comes back after a completed exit** (SP BLSAggregator-4.14.2,
Daybreak M-01; DSR 2026-11-17). From 4.14.2, `consumeGuardianExit` also suspends
the guardian and revokes its BLS key. Re-staking to get `ROLE_DVT` back does not
restore it: its proposals revert `ValidatorSuspended` and its signatures do not
count (`UnknownValidatorSlot`). The two steps back each restore one half:

1. The owner (the SAFE) lifts the suspension on the aggregator. From then on the
   address can propose again (`createProposal`), even before its key is
   re-registered.
2. It signs again only after a re-registration with a valid PoP: `--export-pop`,
   then the SAFE signs as above. The PoP digest does not include an admission
   epoch, so the PoP from before the exit is still valid and can be reused; a
   new one is not required. The guardian must hold `ROLE_DVT` with at least
   `minStake` again; the script checks this and refuses the export otherwise.
3. `DVTValidator.addValidator` is needed only if the address was removed or
   pruned.

This follows SP's `docs/deployment/rc8-guardian-operations.md` at `f2b2cd9b`
("Re-admission after an exit"). SP says the re-registration script must perform
step 1 first. Here DVT sends nothing, so the SAFE lifts the suspension first,
and only then is the script run; until then it refuses the guardian (below).

The script refuses a suspended guardian before it exports anything
(`reregister-guardians.mjs`, the `suspended(validator)` check: "is suspended on
this aggregator — SP reverts ValidatorSuspended"). It never lifts a suspension
itself. Deploy day's A10 registers guardians on a new aggregator, none of which
has exited, so it is not affected.

### Interface

Checked against SP main `b5e7544e3970eab24dc9a3412366140207e36b28`
(BLSAggregator-4.14.0, DVTValidator-0.8.0). SP #633 moves main to 4.14.1 / 0.8.1
and step 4 (SuperPaymaster#635) moves the DVTValidator to 0.9.0. #635 merged as
`053117cc8ca31eb69ae1f62755a1d7790e71190f` (SP main), whose tree is identical to
the head rechecked here, `d55f76f8ac379718e47e7f5c1d8fa46467914d69` (GitHub's
compare: no file changed; the DVTValidator, BLSAggregator and foundry.toml blobs
match). At that commit (BLSAggregator-4.14.1, DVTValidator-0.9.0):
`BLSAggregator.sol` is byte-identical to `1845b124`, so `popDigest`,
`domainSeparator()` and the aggregator's registration gate are unchanged;
`registerBLSPublicKey` is unchanged (selector `0xaded17c5`). What 0.9.0 changes
is the DVTValidator constructor, now
`(registry, firstProposalId, bytes32[] categories, address[] checkers)`; rc.8
passes two empty lists (`categoryCount() == 0`). The script holds no version
string: `--expect-versions` takes them from the tag's tree. Check the interface
again against the tag commit at the rc.8 freeze.

**Rechecked at SP main `f2b2cd9b4a566d7cb73c8482e1327c674f8887a8`** (2026-11-18;
BLSAggregator-4.14.2, DVTValidator-0.9.0; holds SuperPaymaster #636–#639). Three
checks, all passing:

- **ABI.** Every SP function the script calls was matched against SP's committed
  ABIs at that commit (`abis/BLSAggregator.json`, `DVTValidator.json`,
  `Registry.json`, `SuperPaymaster.full.json`), by selector and output types;
  all match. The script's three other fragments (`AGGREGATOR()`,
  `deriveFraudProofId`, `slashMessageHash`) are this repository's fraud
  verifier, not SP. The five reads added for the Daybreak eligibility check were
  matched the same way. They are `Registry.GTOKEN_STAKING()`, `hasRole`,
  `getRoleConfig`, `GTokenStaking.roleLocks` and
  `BLSAggregator.guardianExitRequests`, checked against `abis/Registry.json`,
  `abis/GTokenStaking.json` and `abis/BLSAggregator.json` at `f2b2cd9b`; all
  match.
- **DVTValidator.** `DVTValidator.sol` has the same git blob as at `d55f76f8`,
  so the lines cited below still hold.
- **BLSAggregator.** It changed from 4.14.1. In 4.14.2, `popDigest` and
  `domainSeparator()` keep the formulas below, and `registerBLSPublicKey` still
  accepts only `msg.sender == DVT_VALIDATOR` (`BLSAggregator.sol:789`).

```
DVTValidator.registerBLSPublicKey(address validator, BLS.G1Point key, uint8 slot, BLS.G2Point pop)
```

- **Owner path only.** The owner branch requires the caller to be both
  `DVTValidator.owner()` and `aggregator.owner()` (`DVTValidator.sol:254` at
  `d55f76f8`, the check at `:272`). The permissionless path picks the slot
  itself, and slot identity matters (mask bits, historical proofs). The script
  reads and records `permissionlessBLSRegistration()`.
- **PoP.**
  - `popDigest = keccak256(abi.encode(domainSeparator(), TAG_POP, validator, pk))`;
  - `domainSeparator() = keccak256(abi.encode(DOMAIN_NAME, chainid, aggregator, registry))`;
  - DST `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`.

  The digest is bound to the aggregator and the validator address, not to the
  DVTValidator.

- **Call target.** `BLSAggregator.registerBLSPublicKey` accepts only
  `msg.sender == DVT_VALIDATOR`.

### Rehearsed on anvil (2026-11-17)

Usage note (clestons #444): a run writes SP's `deployments/config.anvil.json`
through `forge script`. With a git checkout as `SP_DIR`, the next run therefore
stops on the clean-checkout check ("SP_DIR has changes"). Restore that file
(`git -C "$SP_DIR" checkout -- deployments/config.anvil.json`) or use a fresh
`SP_DIR` before each run. A tarball `SP_DIR` is checked by blobs, not by
cleanliness, so this does not apply to it.

These ran against SP's `DeployAnvil` at `b5e7544e` with throwaway BLS keys. The
pre-deployment flow is `deploy/rehearse-reregister-plan.sh` (`good` and
`nonce-moved`, with a required `EXPECT_VERSIONS`). It passed again on SP
`1845b124` (BLSAggregator-4.14.1, DVTValidator-0.8.1): `good` exit 0,
`nonce-moved` exit 3, both generations reporting the expected versions. With the
0.9.0 constructor it passed on #635's head `d55f76f8` (BLSAggregator-4.14.1,
DVTValidator-0.9.0): `good` exit 0, `nonce-moved` exit 3 with both stops, and
again with `SP_COMMIT` = the merge commit `053117cc` (same tree): `good` exit 0,
`nonce-moved` exit 3, both stops firing. On SP main `f2b2cd9b`
(BLSAggregator-4.14.2, DVTValidator-0.9.0, 2026-11-18), built from its tarball
with its submodules at the commits it pins:

- `good` exited 0. Both generations reported the expected versions, the deployed
  addresses equalled the plan, and the read-back was OK for all 3 slots.
- `nonce-moved` exited 3. The re-export stopped on the nonce check, and the A10
  address assertion found the mismatch and stopped the send. The flow:

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
- **Post-deployment modes (2026-11-17, before `--broadcast` was disabled):**
  `--deployment` dry run and broadcast, and `--export-pop` with the owner on
  another address sending the calldata. Both read back correctly, and the
  negative cells each stop the run.
- **`--deployment --export-pop` after the Daybreak fixes** (SP `f2b2cd9b`,
  2026-11-18, in `good`, against the pair just registered):
  - with guardians that do not hold `ROLE_DVT`, the export stopped;
  - each throwaway guardian then got `ROLE_DVT` with `minStake` from its own
    address (GToken from the anvil deployer). The export then passed, and a
    re-export three blocks later reproduced `reads`, `readsDigest` and the
    calldata;
  - a node file with a new key for slot 1's active guardian stopped the export,
    and the message showed only each key's ends;
  - a guardian suspended after the export stopped the re-run.
- **`SP_COMMIT` is checked.** On a checkout, `HEAD` must equal `SP_COMMIT` and
  the tree must be clean. In either case, each source the two artifacts were
  compiled from (8 for BLSAggregator, 9 for DVTValidator) must meet two
  conditions:
  - it is on disk with the keccak256 the metadata records;
  - it has the git blob that is pinned for it. SP's own files are checked
    against `SP_COMMIT`'s tree (from GitHub for a tarball). The OpenZeppelin
    files vendored under `singleton-paymaster` are checked against
    OpenZeppelin's v5.0.2 tag. Any other path stops the run.

  `EXPECT_VERSIONS` must equal the `version()` strings in the sources. The
  compiler settings are printed, not compared. Two controls were run:
  `SP_COMMIT` = `b5e7544e` stopped on a blob, and `EXPECT_VERSIONS` = 4.14.1
  stopped on the sources' versions.

### Review gate

This script produces the calldata the SAFE executes. Its PR keeps the strict
merge gate: Codex on the exact head with no High, plus clestons approval.
Daybreak ran once, on `63a484d0`, and found 1 High, 4 Medium and 1 Low; the raw
report is `docs/evidence/daybreak-444-63a484d0.md`. DSR ruled that no second
Daybreak is needed, because the path with the High is removed and the other
changes tighten read-only checks. Codex reviews the delta instead.

### Follow-ups

- **Restoring `--broadcast`** (DSR 2026-11-18). Before this script signs
  anything again, it needs a check that the RPC is the real chain and not a
  same-chain-ID fork. Two checks are known not to work:
  - rejecting localhost or private addresses fails, because hosted forks have
    public addresses;
  - a fixed block hash fails, because a fork shares all history before its fork
    point.

  What works is comparing the latest finalized block's hash with a second,
  independent provider's at the same height, and requiring that block to be
  recent. It is a new mechanism and needs its own design and review.

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
