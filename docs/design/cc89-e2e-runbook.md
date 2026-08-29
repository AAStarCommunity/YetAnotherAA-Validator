# CC-89 Stage-2 — over-issue guardian-slash E2E runbook

> The full over-issue guardian-collusion slash chain, end to end, and the joint
> testnet acceptance checklist. Scope: **testnet-E2E** (no mainnet activation).
> CC-115 route-B update (2026-08-29): this runbook targets the SP 4.11
> four-parameter verifier seam and the queue-then-execute slash lifecycle.
> Companion to `cc89-stage2-shipping-plan.md` (the shipping plan) and
> `guardian-collusion-slash.md` (stage-0 threat model + A' spec).

## The chain (who does what)

```
                         SuperPaymaster (SP)                         DVT (this repo)
 ┌──────────────────────────────────────────┐   ┌──────────────────────────────────────────┐
 │ A) craft a FRAUDULENT over-issue slash    │   │                                            │
 │    verifyAndExecute(pid, op, level, [],[],│   │                                            │
 │      epoch, evidenceHash, proof)          │   │                                            │
 │    → _checkSignatures (m guardians)       │   │                                            │
 │    → stores proposalSignersCommitment[pid]│   │                                            │
 │      = A' snapshot of the signer ADDRESSES│   │                                            │
 │    → emits SlashExecuted                  │──▶│ B) WATCHER (F1) observes SlashExecuted     │
 └──────────────────────────────────────────┘   │    → decode verifyAndExecute calldata       │
                                                 │    → validatorAtSlot @ EXECUTION block      │
                                                 │    → recompute A' commitment, SELF-CHECK    │
                                                 │      == on-chain → durably record            │
                                                 │      {claimedSigners, …} (VERIFIED)          │
                                                 │                     │                        │
                                                 │                     ▼                        │
                                                 │ C) ASSEMBLER (F2): record + disputedToken →  │
                                                 │    exact claimedSigners + proof + proofId     │
                                                 │    (caller cannot shrink the guilty set)      │
                                                 │                     │ preflightVerify (view) │
 ┌──────────────────────────────────────────┐   │                     ▼                        │
 │ D) queueGuardianSlash(...) verifies once, │◀──│    queueGuardianSlash (armed), then execute │
 │    freezes exits + verdict; then           │   └──────────────────────────────────────────┘
 │    executeGuardianSlash(...) slashes       │
 │    → verifier.verify(domain,id,set,proof)  │
 │      (5 checks, #223) == true             │
 │    → slashByDVT: guilty ROLE_DVT lock → 0 │
 │    → next verify → _reconstructPkAgg      │
 │      reverts (< minStake) → AUTO-EJECT    │
 └──────────────────────────────────────────┘
```

## Cross-repo evidence convention (MUST match on both sides)

The disputed slash MUST be filed as a **pure over-issue slash** so the DVT
verifier can reconstruct its message:

- `evidenceHash = keccak256(abi.encode("DVT_OVERISSUE_EVIDENCE_V1", token, operator, epoch))`
  (`overIssueEvidenceHash` in `guardian-fraud-proof.ts`;
  `OVERISSUE_EVIDENCE_TAG` in the verifier).
- **`repUsers` AND `newScores` both empty** — the slash-only branch (8-field
  messageHash committing `evidenceHash` + chainid). A non-empty rep array
  changes the messageHash → the verifier rejects.
- Signer set derivation: `validatorAtSlot[slot]` at the **verifyAndExecute
  execution block**, uint160 strictly ascending (SP `_computeSignersCommitment`
  `sorted`; DVT `resolveClaimedSigners`). Byte alignment is pinned by the golden
  vector in both suites (`OverIssueFraudProofVerifier.t.sol` ⇄
  `guardian-fraud-proof.spec.ts`).

## DVT-side E2E dry-run (this repo, CI-verified)

`guardian-slash-e2e.spec.ts` stitches the DVT half end to end against a mock
provider: craft a slash → `buildGuardianSignerRecord` (watcher core)
self-verifies against the on-chain A' commitment → `assembleOverIssueFraudProof`
(assembler) builds the fraudProof → assert the fraudProof's embedded data
**reproduces the same commitment** the verifier will recompute, and that
`fraudProofId`, `guiltyGuardians == claimedSigners`, and the decoded fields all
line up. Negative: a token-swap is refused in the E2E; corrupt, empty,
duplicate, zero-address, unsorted, or oversized claimed-signer records are
rejected before assembly. The caller cannot provide a subset. The byte-level
acceptance by the Solidity verifier is transitively proven by the golden vector
shared with `OverIssueFraudProofVerifier.t.sol`.

Run:
`NODE_OPTIONS=--experimental-vm-modules npx jest src/modules/audit/guardian-slash-e2e.spec.ts`

## Joint successor-Sepolia run (CC-115 B0/B3)

1. **SP**: deploy `BLSAggregator-4.11.0` to Sepolia with
   `fraudProofVerifier == address(0)` (dormant); wire it into Registry before
   arming, authorize it as the staking slasher, and register N guardians with
   ROLE_DVT locks at minStake. Deploy `OverIssueFraudProofVerifier` bound to
   this exact aggregator and Registry, then have the aggregator owner call
   `proposeFraudProofVerifier(verifier)`. Record the proposal receipt and
   `pendingFraudProofVerifierReadyAt`, wait the on-chain
   `VERIFIER_ROTATION_DELAY` (**4 days**), and call the permissionless
   `applyFraudProofVerifier()`. There is deliberately no direct setter or
   deployment-time bypass in SP 4.11.
2. **SP**: craft a fraudulent over-issue slash — call `verifyAndExecute` with
   the evidence convention above over a token that is **not** actually
   over-issued (`isOverIssued() == false`), holding that state constant through
   the run (current-state variant; historical-state is Phase-3).
3. **DVT**: run a node with `AUDIT_GUARDIAN_WATCH_ENABLED=true` +
   `AUDIT_BLS_AGGREGATOR_ADDRESS` set; the watcher captures the VERIFIED
   signer-set record.
4. **DVT**: `assembleOverIssueFraudProof(record, token)` derives the exact
   committed signer set →
   `preflightVerify(provider, verifier, aggregator, assembled)` obtains SP's
   canonical `fraudProofDigest` and calls the four-parameter verifier (expect
   true) → `queueGuardianSlash` → wait for the receipt → `executeGuardianSlash`
   with the identical set and proof.
5. **Assert**: the queue freezes each guilty guardian's exit; execution reduces
   every guilty guardian's ROLE_DVT lock to 0; a subsequent `verifyAndExecute`
   whose mask includes a slashed guardian reverts in `_reconstructPkAgg`
   (auto-eject). Mirrors SP's `GuardianSlashE2E.t.sol` (swap its `MockVerifier`
   for the real one).

## Acceptance checklist (joint — tracked in issue #222)

DVT side:

- [x] Watcher captures + self-verifies the signer set (F1, #224).
- [x] Assembler builds a verifier-accepted fraudProof; refuses doomed/harmful
      inputs (F2, #225).
- [x] DVT-side E2E dry-run green (`guardian-slash-e2e.spec.ts`).
- [x] Evidence convention documented (this runbook) + pinned by the shared
      golden vector.

SP/DVT joint gate:

- [ ] A'-commitment BLSAggregator + real verifier wired on Sepolia.
- [ ] Verifier arming evidence records dormant-at-deploy, proposal receipt,
      `readyAt`, the full four-day delay, apply receipt, and final active
      address.
- [ ] Fraudulent over-issue slash crafted (evidence convention; over-issue state
      held constant).
- [ ] Four-parameter preflight, queue, frozen-exit, execute, full-lock slash and
      auto-eject are verified against the real DVT verifier, not a mock.

Deferred (Phase-3, not E2E): historical-state proof (BLOCKHASH + storage proof,
bounded challenge window); wrapped-call (DVTValidator/relayer/multicall) trace
resolution in the watcher; production arming of an on-chain-objective slash
rule; liveness class (gated on CC-29).
