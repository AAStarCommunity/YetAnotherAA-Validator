# #441 acceptance: the parent-block-hash verifier on BLSAggregator-4.14.0

Status: **passed on a local anvil, latest on SP `f2b2cd9b`
(BLSAggregator-4.14.2), 2026-11-18.** DSR updated the 2026-11-15 ruling on
2026-11-18: the verifier may change, for the release after rc.8 (rc.8 does not
deploy a verifier). The work is split in two: part 1 is the verifier 3.0.0 and
its encoders, and part 2 is the drill, this acceptance and its evidence.

DSR asked for this run. It is the only prerequisite for enabling guardian slash
that nobody had run before. The question: does a commitment that the aggregator
wrote itself, through its real execute path, verify under
`OverIssueFraudProofVerifier-2.0.0`? And does the whole
`queueGuardianSlash → executeGuardianSlash` chain then complete?

## Rerun on SP main f2b2cd9b (BLSAggregator-4.14.2, DVTValidator-0.9.0), 2026-11-18

SP main `f2b2cd9b4a566d7cb73c8482e1327c674f8887a8` (holds SuperPaymaster
#636–#639), built from its tarball. **43/43 checks passed**
(`441-acceptance-report-f2b2cd9b.json`).

- Before any change, the branch's existing E3 also passed on this commit, 28/28.
  So on the evidence rule, 4.14.2 brings no new incompatibility relative to
  4.14.0. This run's commitment checks still hold: the queue path stores the
  commitment under `uint256(messageHash)`, the 4.14 pre-image with the parent
  block hash reproduces it, the 4.11 pre-image does not, and N0, N1 and N2 are
  refused.
- New in this run, step 4b. It runs
  `reregister-guardians.mjs --export-fraud-drill` against this stack, once the
  #441 verifier is active:
  - the export exits 0;
  - the valid `fraudProof` strictly decodes as 8 fields, and re-encodes to the
    same bytes, with a zero `parentBlockHash` placeholder;
  - `forkState.commitment` carries no value to write, only how to produce it;
  - N1–N4 are present, and N3 is also 8 fields;
  - filling the template as its note says changes field 8 and keeps the guardian
    array intact. Field 8 is ABI head word 7, bytes 224–255, not the last 32
    bytes, because the guardian array is encoded after it (Codex).

  With master's old drill in place of this one, three of these four checks fail
  and the acceptance fails.

- New in this run, N0b (Codex): the evidence checker is really consulted. With
  SP's `MockEvidenceCategory` set to reject, `executeWithProof` with the
  proposal's own matching evidence reverts `EvidenceRejected`, and the checker
  is set back to accept. Before this, an accept-all checker could not show it
  was called at all.
- The lock check now also requires a positive starting lock and a positive cut
  (Codex: `0 == 0` passed before).
- **Daybreak on `e8d2a9a8` (1 High, 3 Medium, 1 Low), fixed; this run is
  43/43:**
  - **High: the watcher could not decode the normal path.** It decoded only a
    top-level `verifyAndExecute`, but the slash runs through
    `DVTValidator.executeWithProof`, which calls the aggregator internally. The
    watcher now dispatches on `tx.to`. For the DVTValidator the aggregator names
    at that block, it decodes `executeWithProof` and reads `operator`,
    `slashLevel` and `evidenceHash` from `proposals(id)` at the execution block.
    Any other target is refused. This run records the real wrapper transaction
    and every read the watcher makes into
    `src/modules/audit/fixtures/441-wrapper-tx.f2b2cd9b.json`. A jest spec
    (`guardian-slash-watcher.replay.spec.ts`) replays it and requires a
    **verified** record. With the old decoding, 2 of its 3 cases fail.
  - **Medium: the drill's exported cases are executed.** `--drill-case` aims the
    drill at this run's executed slash. Step 5b then:
    - fills field 8 from the real execution;
    - requires the filled proof to equal the proof built from the execution,
      byte for byte;
    - runs the valid case (`verify` true, `queueGuardianSlash` accepted) and
      N1–N4: N1 and N3 revert `InvalidFraudProof`; N2 sets the token
      over-issued, reverts, and restores the storage; N4 makes `verify` return
      false.
  - **Medium: Gate A' floor 4.14.0.** 4.13.x has no parent block hash and is now
    refused.
  - **Medium: the compiled `CANONICAL_AGGREGATOR` wins.** An env value may only
    repeat it. Both rules have Foundry tests, and each fails under its mutant.
  - **Low:** the drill refuses the default `.env.sepolia`; it needs `--env` with
    an RPC-only file.
- The drill's template mode (the three real guardian addresses) is still checked
  for shape only (step 4b), because its proposal does not exist on anvil. Case
  mode (step 5b) is the executed check.

## Rerun on SP #635's head d55f76f8 (BLSAggregator-4.14.1, DVTValidator-0.9.0), 2026-11-17

SP step 4 (#635, unmerged head `d55f76f8ac379718e47e7f5c1d8fa46467914d69`) adds
`bytes evidence` to `queueSlashWithProof` / `executeWithProof`, and DVTValidator
recomputes the proposal's evidenceHash from it with the M0 §3.1 category rule.
This branch therefore moves to **`OverIssueFraudProofVerifier-3.0.0`**:

- `OVERISSUE_CATEGORY = keccak256("DVT.Evidence.OverIssue.v1")`;
- body `abi.encode(address disputedToken, address operator, uint256 epoch)`;
- `evidenceHash = keccak256(abi.encode(TAG_EVIDENCE, OVERISSUE_CATEGORY, keccak256(body)))`.

**This category string and body layout are a proposal, not finalized** (DSR
2026-11-17). They are settled with SP, together with SP's checker contract,
before the category is deployed. 2.0.0 (the old `DVT_OVERISSUE_EVIDENCE_V1`
pre-image) was never deployed. The goldens were recomputed with `cast`, whose
method reproduces all three 2.0.0 goldens.

The rehearsal now includes enablement step **E3**. DVTValidator-0.9.0 fixes its
categories at construction, so enabling one means deploying a new DVTValidator
with it and rotating:

1. deploy SP's `DVTValidator(registry, 1, [OverIssue.v1], [checker])`;
2. `newDVT.setBLSAggregator(aggregator)` (owner);
3. `aggregator.setDVTValidator(newDVT)` (owner);
4. `newDVT.addValidator(guardian)` for each guardian.

**28/28 checks passed**,
`EXPECT_VERSIONS=BLSAggregator-4.14.1,DVTValidator-0.9.0`. Raw report:
`docs/evidence/441-acceptance-report-d55f76f8.json`. Beyond the 18 checks below,
it shows:

- rc.8's state: DeployAnvil's DVTValidator has no category, and a slash-shaped
  `createProposal` reverts `UnknownEvidenceCategory`;
- after E3: the aggregator points at the new DVTValidator, the old one reverts
  `NotCurrentDVT`, `ValidatorAdded` is emitted once per guardian, and the BLS
  keys stay active in the same slots;
- the verifier and the E3 DVTValidator use the same category;
- **N0:** execute with evidence naming another token reverts
  `EvidenceHashMismatch`.

**The checker is SP's test-only `MockEvidenceCategory`, which accepts every
body.** An honest OverIssue checker would refuse this slash, because the token
is not over-issued, and the rehearsal needs a fraudulent slash. So this run
proves that the pipeline is connected (category → checker → evidenceHash →
aggregator commitment → fraud proof → guardian slash). It does **not** prove
that an over-issue verdict is right. With an on-chain checker, the
historical-state gap becomes wrongful slashing of honest guardians: see #447.

## Rerun on SP 1845b124 (BLSAggregator-4.14.1, DVTValidator-0.8.1), 2026-11-17

After SP #633 merged (`1845b12482e13a9937c7ec7f7f059ed9a3d33829`), the rehearsal
was rerun with `EXPECT_VERSIONS=BLSAggregator-4.14.1,DVTValidator-0.8.1`.
DeployAnvil no longer authorises the aggregator as a slasher; E1 is still done
explicitly in the rehearsal. **18/18 checks passed**, the same results as below.
Raw report: `docs/evidence/441-acceptance-report-1845b124.json`.

## How to rerun

```
cd contracts && forge build && cd ..
SP_DIR=<SP checkout, built> SP_COMMIT=<40-hex> EXPECT_VERSIONS=BLSAggregator-<x>,DVTValidator-<y> \
  deploy/rehearse-guardian-slash.sh [report.json]
```

`SP_DIR` must be fetched into its own directory with
`gh api repos/AAStarCommunity/SuperPaymaster/tarball/<sha>`, plus the
`contracts/lib` submodules. The script refuses any chain but 31337. The three
guardian BLS keys and addresses are generated fresh on every run, and no key is
written to the report.

## Inputs of this run

|            |                                                                                                 |
| ---------- | ----------------------------------------------------------------------------------------------- |
| SP commit  | `b5e7544e3970eab24dc9a3412366140207e36b28` (SP main; #631 merged, #633 not yet)                 |
| Aggregator | `BLSAggregator-4.14.0`, deployed by SP's `DeployAnvil`                                          |
| Verifier   | `OverIssueFraudProofVerifier-2.0.0` from this branch, bound to that aggregator and its Registry |
| Raw report | `docs/evidence/441-acceptance-report.json` (30 steps, 18 checks, with transaction hashes)       |

## What ran

1. **Guardians.** Three throwaway guardians:
   - each was funded, minted GToken, and called
     `Registry.registerRole(ROLE_DVT)` with the role's minimum stake;
   - the owner registered each BLS key on the DVTValidator owner path, with a
     real address-bound PoP;
   - the owner admitted each with `DVTValidator.addValidator`.
2. **Proposal.** Guardian 1 filed it on the DVTValidator:
   `createProposal(operator, MINOR, reason, evidenceHash)`.
   - The operator is the DeployAnvil deployer, a registered SuperPaymaster
     operator.
   - `evidenceHash` binds a `MockOverIssuableToken` that is **not** over-issued.
     So the slash is fraudulent, and a fraud proof against its signers should
     succeed.
3. **SP's two-step slash, as in production:**
   - `DVTValidator.queueSlashWithProof`, with all three guardians' BLS
     signatures over the QUEUE_SLASH message;
   - `DVTValidator.executeWithProof` → `BLSAggregator.verifyAndExecute`, with
     all three guardians' BLS signatures over the EXECUTE_SLASH message. This is
     the transaction in which the **aggregator itself** writes
     `proposalSignersCommitment[proposalId]`.
4. **Commitment.** It is recomputed off-chain from the transaction's parent
   block hash, and compared both ways (see the results).
5. **Enablement step E2**, which rc.8 will not have:
   `proposeFraudProofVerifier(v2)` (owner), then a warp of
   `VERIFIER_ROTATION_DELAY` (432000 s), then `applyFraudProofVerifier()`
   (permissionless).
6. **Negative cases** against `queueGuardianSlash`, then the real queue.
7. `executeGuardianSlash` **before** enablement step E1. Then **E1**,
   `GTokenStaking.setAuthorizedSlasher(aggregator, true)` (owner), which rc.8
   will not have either. Then `executeGuardianSlash` again.

## Results (all 18 checks passed)

| Check                                                                                                              | Result                   |
| ------------------------------------------------------------------------------------------------------------------ | ------------------------ |
| The aggregator is an anchored release (≥ 4.13.0)                                                                   | ✓ `BLSAggregator-4.14.0` |
| Verifier build marker (`VERIFIER_VERSION`, `COMMITMENT_BINDS_PARENT_BLOCKHASH`)                                    | ✓                        |
| The queue path stored its commitment under the key `uint256(messageHash)`                                          | ✓                        |
| The execute path stored a non-zero commitment under `proposalId`                                                   | ✓                        |
| **The 4.14 pre-image with the parent block hash reproduces the stored commitment**                                 | ✓                        |
| **The 4.11 pre-image without it does not.** This is the #441 bug, observed on a real commitment                    | ✓                        |
| `fraudProofVerifier()` is the v2 verifier after E2                                                                 | ✓                        |
| **N1:** a proof in the old 7-field shape (no parent block hash) → `queueGuardianSlash` reverts `InvalidFraudProof` | ✓                        |
| **N2:** a parent block hash off by one bit → `InvalidFraudProof`                                                   | ✓                        |
| `verify()` accepts the correct proof                                                                               | ✓                        |
| `queueGuardianSlash` with the correct proof, which emits `GuardianSlashQueued`                                     | ✓                        |
| DeployAnvil leaves the aggregator **not** authorised as slasher, as rc.8 will                                      | ✓                        |
| **Without E1:** `executeGuardianSlash` gives `GuardianSlashFailed` ×3, no slash, and the case stays pending        | ✓                        |
| **With E1:** `GuardianSlashed` ×3                                                                                  | ✓                        |
| Each guardian's ROLE_DVT lock fell by exactly `guardianSlashBps` (3000/10000)                                      | ✓                        |
| The case resolves (status 2)                                                                                       | ✓                        |

## What this shows, and what it does not

- **Shown:**
  - Against a commitment that BLSAggregator-4.14.0 wrote through its real
    DVT-driven execute path, the 2.0.0 verifier reproduces the commitment from
    the parent block hash.
  - The guardian-slash chain completes end to end.
  - The two negative cases are refused.
- **Shown:** the two 5.5.x enablement steps are both needed.
  - Without E2 there is no verifier to call.
  - Without E1 the slash reaches staking and fails there, with
    `GuardianSlashFailed` and the case left pending.

  Both belong on SP's 5.5.x enablement list, in one timelock batch.

- **Not shown:**
  - Any Sepolia behaviour: this was a local anvil.
  - The later SP releases: 4.14.1 after #633, and step 4.
  - The over-issue evidence is still read at proof time (`isOverIssued()` now),
    not at the disputed epoch. That is the historical-state gap in the
    verifier's NatSpec, which this run does not address. It remains a blocker
    for any deployment where `executeGuardianSlash` moves real stake.
- Rerun against SP's step-4 merge commit before this branch is used for
  anything.
