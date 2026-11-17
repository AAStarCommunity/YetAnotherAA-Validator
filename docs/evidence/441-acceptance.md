# #441 acceptance: the parent-block-hash verifier on BLSAggregator-4.14.0

Status: **passed on a local anvil, 2026-11-17.** This is on branch
`feat/441-verifier-parent-blockhash`. It is not a PR and is not to be merged
(DSR). It is not part of rc.8.

DSR asked for this run. It is the only prerequisite for enabling guardian slash
that nobody had run before. The question: does a commitment that the aggregator
wrote itself, through its real execute path, verify under
`OverIssueFraudProofVerifier-2.0.0`? And does the whole
`queueGuardianSlash → executeGuardianSlash` chain then complete?

## How to rerun

```
cd contracts && forge build && cd ..
SP_DIR=<SP checkout, built> SP_COMMIT=<40-hex> deploy/rehearse-guardian-slash.sh [report.json]
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
- Rerun against SP's step-4 merge commit, and against 4.14.1, before this branch
  is used for anything.
