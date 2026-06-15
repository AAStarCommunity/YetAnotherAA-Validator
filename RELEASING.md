# Releasing — template / runbook

Reusable checklist for cutting a release of this repo. Also serves as the
per-repo template for the cross-repo **DVT program** release (see `#42`).

## Per-repo release steps

1. **Green main**: on `master`, `npm ci` → `npm run type-check` → `npm test` →
   `npm run build` all pass.
2. **Decide version** (SemVer): patch = fixes; minor = backward-compatible
   features; major = breaking API/behavior change. Note any behavior change in
   the notes.
3. **Branch** `chore/release-vX.Y.Z`; bump `package.json` version; update
   `CHANGELOG.md` (Added / Changed / Security / Config / Follow-ups).
4. **PR → review → merge** to `master` (do not tag an unmerged commit).
5. **Tag + GitHub release** on the merged commit:
   ```
   git tag -a vX.Y.Z -m "vX.Y.Z" && git push origin vX.Y.Z
   gh release create vX.Y.Z --title "vX.Y.Z — <theme>" --notes-file <notes>
   ```
6. **Verify**: `gh release view vX.Y.Z`; tag points at merged `master`.
7. Record in `#42` (the coordination hub) if part of the DVT program.

## DVT program (cross-repo) release gate — ALL must hold before tagging `DVT v1`

- [ ] Each repo cut its own release per the steps above.
- [ ] Three-way signing format matches the same golden vectors byte-for-byte
      (node `#42` / SDK `#63` / contract `#110` / SP reference `#283`, DST
      `_POP_`).
- [ ] `PolicyRegistry` is the single source for node layer-1 read, `#110`
      validation, and slash reference (sender-keyed, deployed address pinned).
- [ ] All program PRs merged (per repo).
- [ ] **One on-chain E2E**: a real combined signature (KMS/P256 main +
      ≥threshold DVT BLS aggregate) verified through
      `AAStarBLSAlgorithm.validate` on Sepolia, evidence in `#42`.
- [ ] Coordinator marks **DVT v1 RELEASED** in `#42` with the per-repo version
      table.
