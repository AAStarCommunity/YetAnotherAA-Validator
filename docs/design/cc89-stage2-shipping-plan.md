# CC-89 Stage-2 Shipping Plan — over-issue guardian-collusion slash (DVT half)

> **Historical plan — superseded for route B.** CC-115 now owns the release
> gate. The current implementation uses the SP 4.11 four-parameter verifier,
> exact-set attribution, and queue-then-execute lifecycle documented in
> `cc89-e2e-runbook.md`. Subset and direct-execute statements below record the
> earlier design and must not be used as current integration instructions.

> **Scope**: testnet-E2E only (no mainnet activation). Ship every remaining DVT
> dev task agreed on CC-89, each as its own reviewed PR, then run the DVT-side
> E2E, then hand off to a joint testnet run with SuperPaymaster (SP). This doc
> is the machine-readable checklist the `/goal` command drives; it is also the
> human plan of record.
>
> Coordination hub: Seeder **CC-89** (project `Coordination`, `repo:dvt` /
> `repo:sp` labels). Upstream contract already merged on SP:
> `executeGuardianSlash` (PR #370), A' commitment `proposalSignersCommitment`
> (PR #371). SP E2E harness lives on SP branch `feat/guardian-slash-e2e-harness`
> (`contracts/test/modules/GuardianSlashE2E.t.sol`).

## 0. What is already DONE (do not rebuild)

| #   | Deliverable                                                                           | Where                                     | Status            |
| --- | ------------------------------------------------------------------------------------- | ----------------------------------------- | ----------------- |
| D0  | Stage-0 design doc (threat model, auto-eject, trigger authority)                      | `docs/design/guardian-collusion-slash.md` | ✅ PR #221 merged |
| D1  | `OverIssueFraudProofVerifier.sol` + `IFraudProofVerifier.sol` + 16 Foundry tests      | `contracts/`                              | ✅ PR #223 merged |
| D2  | Watcher CORE (`guardian-fraud-proof.ts`: derivation + encode + golden byte-alignment) | `src/modules/audit/`                      | ✅ PR #223 merged |

## 1. Feature decomposition — each ships as ONE PR

### F1 — Guardian-slash watcher SERVICE ✅ built, awaiting review→PR→merge

Branch: `feat/cc89-guardian-watcher` (already checked out, changes present,
UNCOMMITTED). Files: `guardian-signer-store.ts`,
`guardian-slash-watcher.core.ts`, `guardian-slash-watcher.service.ts` (+ 3
specs) + `guardian-fraud-proof.ts` extensions (`decodeVerifyAndExecuteCalldata`,
`rawSlashMessageHash`, `repSlashMessageHash`) + `audit.module.ts` /
`configuration.ts` wiring.

What it does: polls `BLSAggregator.SlashExecuted`, decodes the
`verifyAndExecute` calldata, resolves the co-signer address set via
`validatorAtSlot` pinned to the **execution block**, self-checks the recomputed
A' commitment against on-chain, and durably records
`proposalId → {claimedSigners, …}` (the irreversible-commitment
data-availability layer). In-process per node; opt-in
`AUDIT_GUARDIAN_WATCH_ENABLED` (default off); fail-closed; restart-safe cursor.

**Acceptance (F1):**

- [ ] `npm run type-check` + `npm run lint:check` + `npm run format:check`
      clean.
- [ ] `jest src/modules/audit` green (new specs + no regression).
- [ ] `npm run build` clean.
- [ ] Codex review: no unresolved Critical/High.
- [ ] Opt-in default-off + fail-closed disable paths present (aggregator no-code
      / bad addr / bad interval).
- [ ] Watcher NEVER persists a partial/guessed signer set (throws → skip +
      alert); a commitment self-check miss is RECORDED with
      `commitmentVerified:false` + loud alert (not silently dropped).
- [ ] pr-daemon/`clestons` APPROVE + required checks green (既有 non-required
      reds documented).
- [ ] Merged; `jest src/modules/audit` green on master.

### F2 — Fraud-proof ASSEMBLER ⬜ to build

New: `src/modules/audit/guardian-fraud-proof-assembler.ts` (+ spec). Optionally
a thin CLI `scripts/cc89-file-fraud-proof.mjs` for the E2E.

What it does: given a disputed `proposalId` (its watcher record) + the
`disputedToken` + the accused `guiltyGuardians`, it (a) validates
`guiltyGuardians ⊆ claimedSigners`, (b) builds the `fraudProof` bytes +
`fraudProofId` (reusing merged `encodeOverIssueFraudProof` /
`deriveFraudProofId`), (c) self-checks the record's commitment reproduces
on-chain AND that the disputed token's over-issue evidence recompute would pass,
and (d) exposes a submit path to
`BLSAggregator.executeGuardianSlash(fraudProofId, guiltyGuardians, fraudProof)`.
Refuses to assemble/submit if any self-check fails (never files a proof that
will revert/return false).

**Acceptance (F2):**

- [ ] Cross-check test: assembler output fed to `OverIssueFraudProofVerifier`
      (Foundry, or a TS↔golden vector) returns `true` for a genuine over-issue
      fraud and `false` for token-swap / non-subset / still-over-issued.
- [ ] `guiltyGuardians ⊆ claimedSigners` enforced before assembly; assembler
      throws otherwise.
- [ ] Submit path is dry-run-able (build + local staticCall preflight) and does
      NOT broadcast unless explicitly armed.
- [ ] type-check / lint / format / jest / build clean; Codex no Critical/High.
- [ ] pr-daemon APPROVE + checks green; merged; tests green on master.

### F3 — E2E acceptance checklist + DVT-side E2E driver ⬜ to build

Update issue **#222** with the joint acceptance checklist; add
`docs/design/cc89-e2e-runbook.md`

- a driver `scripts/cc89-e2e.mjs` (dry-run against a local/Sepolia BLSAggregator
  with A' commitment) that walks: over-issue slash (verifyAndExecute stores
  commitment) → watcher captures `claimedSigners` → assembler builds
  `fraudProof` → `executeGuardianSlash` → `OverIssueFraudProofVerifier.verify` →
  guardian ROLE_DVT lock → 0 → auto-eject.

**Acceptance (F3):**

- [ ] Runbook documents the full chain + the cross-repo evidence convention
      (`evidenceHash = keccak256("DVT_OVERISSUE_EVIDENCE_V1", token, operator, epoch)`,
      slash filed pure = empty repUsers AND newScores).
- [ ] Driver dry-runs the DVT half end-to-end against SP's
      `GuardianSlashE2E.t.sol` shape (real verifier swapped for `MockVerifier`),
      asserting the watcher's recompute == on-chain commitment.
- [ ] Issue #222 acceptance checklist posted; CC-89 updated; both repos' items
      enumerated.
- [ ] Documented handoff for the **tomorrow** joint testnet run with SP.

## 2. Per-feature loop protocol (what `/goal` runs for EACH feature)

```
for feature F in [F1, F2, F3]:
  1. SYNC:   git checkout master && git pull --ff-only
             if F already merged (grep git log for its PR / marker) → skip F.
  2. BRANCH: reuse F's feature branch if it exists with the built changes; else create it off master.
  3. BUILD:  implement F (F1 is already built). Keep ESM .js imports; match repo conventions.
  4. GATE:   npm run type-check && npm run lint:check && npm run format:check
             && NODE_OPTIONS=--experimental-vm-modules npx jest <F specs> && npm run build
             (+ cd contracts && forge test  if F touches contracts/)
             → any red: fix, re-run. Do NOT proceed on red.
  5. REVIEW: Codex Tier-1 (codex:codex-rescue) on the diff. Strict/adversarial: correctness,
             races, fail-closed, fund-safety. Fix every Critical/High; re-review; loop until clean
             (or a finding is EXPLICITLY deferred with rationale). Report rounds to the user.
  6. COMMIT: git add -A && commit  "feat(CC-89): <F summary> (Codex Tier-1 reviewed)"
             (money-adjacent → follow the security-fix message convention in history).
  7. PR:     git push -u origin <branch>; gh pr create --base master --reviewer clestons
             --title/--body (link CC-89 + issue #222 + acceptance box). The reviewer add triggers
             the background pr-daemon bot.
  8. WAIT:   poll  gh pr view <n> --json reviewDecision,statusCheckRollup,reviews  (via /loop 5m).
             - REQUEST_CHANGES  → fix findings (goutou PR-review / Codex), push new commit
                                  (NEVER force-push, NEVER amend pushed commits), re-request; loop.
             - APPROVED + required checks green → step 9.
             (既有 non-required reds — Security Audit / Code Quality / forge coverage viaIR —
              are the repo's pre-existing UNSTABLE state, not this PR's regression: document, don't block.)
  9. MERGE:  gh pr merge <n> --squash --delete-branch.
 10. VERIFY: git checkout master && git pull; run F's suite on master → must be green.
 11. REPORT: goutou → CC-89 comment "[repo:dvt] F<n> 交付 ✅ (PR #<n> merged)"; update this doc's
             status boxes + the guardian-collusion-slash-gap memory.
```

**Never** bypass branch protection / enforce_admins / self-approve (see memory
`never-bypass-branch-protection`). Cross-repo changes go via PR, never direct
edits (`pr-not-direct-edit-other-repos`).

## 3. After all features merged — E2E phase

1. Run the F3 driver (`scripts/cc89-e2e.mjs` dry-run) — DVT half end-to-end,
   assert watcher recompute == on-chain commitment and verifier returns true for
   the crafted fraud.
2. Confirm the issue #222 acceptance checklist DVT items are all ticked.
3. Post CC-89 "DVT stage-2 dev complete + E2E dry-run green; ready for joint
   testnet" with the handoff (SP action: deploy A'-BLSAggregator to Sepolia +
   run `GuardianSlashE2E` with the real verifier swapped in; DVT action: run
   watcher + assembler against it).

## 4. Tomorrow — joint testnet E2E with SP (not in this run)

SP deploys the A' `BLSAggregator` to Sepolia and rewires; crafts an over-issue
slash; DVT's watcher captures `claimedSigners`; DVT assembler files the fraud
proof; `executeGuardianSlash` slashes the colluding guardians' ROLE_DVT lock to
0 → auto-eject. This closes ρ's detection half (paper: "implemented +
testnet-verified"). Coordinate timing on CC-89.

## 5. Definition of done (whole `/goal` run)

- [ ] F1, F2, F3 each: Codex-clean, bot-approved, merged to master, suite green
      on master.
- [ ] DVT-side E2E dry-run green.
- [ ] Issue #222 acceptance checklist (DVT items) complete; CC-89 updated;
      memory updated.
- [ ] Handoff posted for the tomorrow joint run. (The joint run itself is out of
      scope here.)
