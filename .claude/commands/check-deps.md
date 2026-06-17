---
description:
  Sync-check the aNode DVT node's pinned upstream/downstream dependencies
  (addresses + source-level interface drift) and report what to adapt
allowed-tools: Bash
---

Run the dependency-sync skill for this repo and report the result.

1. Execute `npm run check-deps` (= `node scripts/check-deps.mjs`). It checks
   every pinned dependency at **two levels**:
   - **address / deploy** — resolves each dep's canonical address from its
     committed `deployments/config.sepolia.json` on the default branch (this
     catches a doc-less `*-redeploy` tag that ships no GitHub release), scans
     all tags for `-redeploy` variants, and confirms the address has on-chain
     code.
   - **source / deep** — diffs the exact source file the node binds to
     (`PolicyRegistry.sol`, `AAStarBLSAlgorithm.sol`) between the integrated
     baseline ref and the current default-branch HEAD, asserts the called ABI
     signature is still present, and guards the KMS TA version (the ownerAuth
     signing scheme).

   Every `gh` lookup is retried with backoff. **Exit codes**: `0` aligned · `1`
   **real drift** (adapt before release) · `2` **transient** (a lookup failed
   after retries — network/proxy/rate-limit; NOT drift). A "SOURCE CHANGED"
   verdict is only emitted when both the baseline and current files fetched
   successfully and differ.

2. Report the per-dependency result (the tool's output table) back to the user.

3. On **exit 2 (transient)**: do NOT report drift — say lookups failed and
   re-run (once or twice). Only treat it as a problem if it stays transient.

4. On **exit 1 (REAL DRIFT)**, do NOT stop at the address — assess the real
   impact before concluding:
   - A source file diffed → fetch and read the diff; decide whether it touches
     the ABI / wire format / DST / data structure the node binds to, and state
     concretely what the node must do: pin-address update only, a code change,
     or node re-registration.
   - The KMS TA version moved → check whether the `ownerAuth` signing scheme
     changed.
   - Give a clear "要不要改 / 怎么改" conclusion. Do NOT cut a release until
     drift is resolved and re-verified (unit tests + real-node E2E
     `validate=0`).

5. When applying any fix: **never bypass review** — open a PR and hand off for
   an independent approval. Do not self-merge and do not relax branch protection
   (no disabling `enforce_admins`, no lowering required reviews).

Notes:

- Requires `SEPOLIA_RPC_URL` in `.env.sepolia` (for the on-chain `getCode`
  check) and an authenticated `gh` CLI (to read the upstream repos). With no RPC
  the on-chain line shows `rpc-unavailable`; the rest still runs.
- The pinned baseline lives in `scripts/check-deps.mjs` (the `DEPS` array).
  Update it there only after a re-pin has been reviewed and merged.
