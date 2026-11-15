# rc.8 deploy day: what DVT changes

Status: **plan**. The steps below run only after SP's rc.8 manifest PR lands and
the rc.8 contracts are deployed and read back. Until then nothing here is
executed (DSR, 2026-11-15).

## Why there is a DVT step at all

DSR ruled on 2026-11-15 that rc.8 adds a step A7.dvt. It deploys a **new**
DVTValidator (0.9.0 at the tag) together with a **new** BLSAggregator-4.14.0.
Without that step, the new aggregator would have been wired to the old
DVTValidator that is live on Sepolia today. `firstProposalId` is computed from
the chain when the step runs.

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
| node env (all 3 containers)         | `AUDIT_DVT_VALIDATOR_ADDRESS`                                     | unset; the code default is `0x568b1486…` (old DVTValidator) | new DVTValidator                                                          | no: audit is off (`AUDIT_ENABLED` unset) |
| node env (all 3 containers)         | `AUDIT_BLS_AGGREGATOR_ADDRESS`                                    | unset; the code default is `0xEaeC2F51…` (4.11.0)           | new BLSAggregator-4.14.0, also checked against `Registry.blsAggregator()` | no: audit and guardian watch are off     |
| node env (all 3 containers)         | `AUDIT_GUARDIAN_WATCH_FROM_BLOCK`                                 | unset (0)                                                   | block where the new aggregator was deployed                               | no: guardian watch is off                |
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
- **Set the addresses explicitly anyway.** A node left on the code defaults does
  not fail. It watches the superseded contracts and silently sees nothing. The
  comment at `configuration.ts` "FAIL-SILENT" explains why. After the switch,
  read `Registry.blsAggregator()` and compare it with
  `AUDIT_BLS_AGGREGATOR_ADDRESS` on every node.

## Guardian re-registration

The interface below is taken from SP's unmerged branch `cc125/rc8-bls-dvt` at
`91758361d0b538e58572c94a27deb9a4a0465497`, `DVTValidator.sol:207`. It must be
checked again against SP's step-4 merge commit.

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
- **PoP.**
  - SP's natspec says every registration, including owner forwarding, needs an
    address-bound PoP.
  - The current script binds the PoP to the aggregator's `domainSeparator()`. It
    checks the digest byte for byte against the contract's `popDigest()` (gates
    4 and 7).
  - Whether the 4.14.0 digest is bound to the aggregator, the DVTValidator or
    the validator address must be checked against the merged code. Either way
    the PoPs are recomputed for the new addresses; old PoPs are worthless.
- **Who sends.** The DVTValidator owner. If DVT does not hold that key, the
  script's `--export-pop` writes the public PoP data for the owner to submit. It
  never signs a transaction.
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
   - re-derive the PoP domain;
   - new `--expect-version`.
2. `src/modules/audit`: file evidence with the four-argument
   `createProposal(address,uint8,string,bytes32)`, by selector. There is no
   function named `createProposalWithEvidence`.
3. `configuration.ts`: the address defaults move to the read-back values.
4. The sp-parity pin (`ci/sp-parity-pin`) is set to SP's step-4 merge commit.
