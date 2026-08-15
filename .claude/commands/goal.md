---
description:
  Ship all remaining CC-89 stage-2 DVT features to testnet-E2E — each feature
  its own Codex-reviewed, bot-approved, merged PR, then run E2E, then hand off
  to the SP joint run.
argument-hint:
  "[optional: F1|F2|F3 to run just one feature, else all remaining]"
---

# /goal — CC-89 stage-2 DVT shipping pipeline

You are the DVT (`YetAnotherAA-Validator`) repo agent. Execute the shipping plan
in `docs/design/cc89-stage2-shipping-plan.md` end-to-end. Respond in **中文**.
Be strict and adversarial in review (money-adjacent slash code).

## Prime directives (never violate)

1. **Review before every PR.** Codex Tier-1 (`codex:codex-rescue`) on the diff;
   fix all Critical/High; loop until clean or a finding is explicitly deferred
   with rationale. This is the "所有都要扣 review" rule — no PR opens without
   it.
2. **Wait for the background bot.** After opening a PR, add `clestons` as
   reviewer to trigger the pr-daemon bot; do NOT merge until it APPROVES **and**
   required checks are green.
3. **Never bypass branch protection** (no enforce_admins toggle, no self-merge
   to skip review).
4. **Never force-push / amend a pushed commit.** Fix findings with NEW commits.
5. **One feature = one PR.** Do not batch F1/F2/F3 into one PR.
6. **Resumable.** Re-running `/goal` must detect already-merged features (via
   `git log` on master
   - PR state) and skip them — safe to run across context windows.

## Steps

### 0. Orient

- `git fetch origin && git checkout master && git pull --ff-only`.
- Read `docs/design/cc89-stage2-shipping-plan.md`. Determine which of F1/F2/F3
  are still outstanding: a feature is DONE if its PR is merged to master (grep
  `git log --oneline` for its marker / check `gh pr list --state merged`). If
  `$ARGUMENTS` names a single feature, do only that.
- Print the plan: which features remain, in order F1 → F2 → F3.

### 1. For each remaining feature, run the loop in `§2` of the plan doc

Concretely, per feature F:

1. **Sync + branch.** `git checkout master && git pull`. If F's branch already
   exists with built changes (F1 = `feat/cc89-guardian-watcher`, already built &
   UNCOMMITTED), check it out. Else create `feat/cc89-<slug>` off master and
   implement F per its spec in the plan doc.
2. **Gate (all must pass before review):**
   ```
   npm run type-check && npm run lint:check && npm run format:check \
     && NODE_OPTIONS=--experimental-vm-modules npx jest <F's specs> && npm run build
   ```
   If F touches `contracts/`: also `cd contracts && forge test`. Fix reds; never
   proceed on red.
3. **Codex review loop** (prime directive 1). Send the full diff; ask for
   correctness / races / fail-closed / fund-safety. Fix → re-review → repeat.
   Tell the user how many rounds + the final Codex verdict.
4. **Commit** with the security-fix message convention:
   `feat(CC-89): <F summary> (Codex Tier-1 reviewed)`.
5. **PR:** `git push -u origin <branch>` then
   `gh pr create --base master --reviewer clestons --title "…" --body "…"`. Body
   must link CC-89 + issue #222 and paste F's acceptance checklist from the plan
   doc.
6. **Wait for the bot.** Arm a Monitor / `/loop 5m` on
   `gh pr view <n> --json reviewDecision,statusCheckRollup,reviews`:
   - `REQUEST_CHANGES` → fix (goutou PR-review branch or Codex), push a NEW
     commit, re-request review, keep looping.
   - `APPROVED` + required checks green → merge. (Pre-existing non-required reds
     — Security Audit / Code Quality / forge-coverage viaIR — are the repo's
     UNSTABLE baseline, NOT this PR's regression: verify they predate the diff,
     document, and do not block.)
7. **Merge:** `gh pr merge <n> --squash --delete-branch`.
8. **Verify on master:** `git checkout master && git pull`; re-run F's suite →
   must be green.
9. **Report:** via `/goutou` post `[repo:dvt] F<n> 交付 ✅ (PR #<n> merged)` to
   CC-89; tick F's boxes in the plan doc; update the
   `guardian-collusion-slash-gap` memory.

### 2. After ALL features merged — E2E phase (plan §3)

- Run the F3 driver dry-run (`scripts/cc89-e2e.mjs`) — DVT half end-to-end;
  assert the watcher's recompute == on-chain commitment and the verifier returns
  `true` for the crafted over-issue fraud and `false` for token-swap /
  non-subset / still-over-issued.
- Confirm issue #222 acceptance checklist (DVT items) all ticked.

### 3. Handoff (plan §4) — do NOT do the joint run now

- Post CC-89: "DVT stage-2 dev complete + E2E dry-run green; ready for joint
  testnet" with the SP action (deploy A'-BLSAggregator to Sepolia + swap real
  verifier into `GuardianSlashE2E`) and the DVT action (run watcher + assembler
  against it). The joint run is **tomorrow**, out of this scope.

### 4. Final report to the user

Summarize: features shipped (with PR #s + Codex rounds + bot verdict), suites
green, E2E dry-run result, issue #222 / CC-89 / memory updates, and the
tomorrow-joint-run handoff. Flag anything deferred.

## Acceptance / 验收 (Definition of Done)

See plan §5. In short: F1+F2+F3 each Codex-clean + bot-approved + merged +
suite-green on master; DVT E2E dry-run green; issue #222 + CC-89 + memory
updated; SP joint-run handoff posted.
