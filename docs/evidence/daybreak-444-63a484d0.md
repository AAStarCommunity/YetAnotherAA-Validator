# Daybreak review of #444 at 63a484d0 (2026-11-18)

This was the one Daybreak run DSR asked for on #444's final head, after #458
merged. It found a High, so #444 stayed in draft until the fixes below.

- **Reviewer:** Codex Daybreak,
  `codex exec -s read-only -m gpt-daybreak-blue-latest --cyber-access-program daybreak_blue`,
  codex-cli 0.166.0.
- **Target:** `63a484d087de7ab720de9fdc90d1b274c6b6df95`, in a clean detached
  worktree.
- **Prompt:** `daybreak-444-63a484d0-prompt.txt`. It allowed reading only this
  worktree, with no network, chain, RPC, `.env`, keystore or key file.
- **Cost:** 67,895 tokens. There was no quota or rate-limit error.
- **Raw report, verbatim:** `daybreak-444-63a484d0-raw.md`. It found 1 High, 4
  Medium and 1 Low.

## What was done (DSR's ruling, 2026-11-18)

| Finding                                                                                                                      | Disposition                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| ---------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **High.** `--broadcast` checked the network only by `chainId`, which a Sepolia fork shares.                                  | **Path removed.** `--broadcast` exits 1 before any file or RPC is read. `REREGISTER_OWNER_PRIVATE_KEY` is no longer read, the script has no wallet, and the send and read-back code is gone. DSR rejected adding a network check instead: rejecting localhost misses hosted forks, and a fixed block hash is shared by every fork. Restoring `--broadcast` needs a two-provider finalized-block comparison, recorded in `docs/rc8-deploy-day-dvt.md` under "Follow-ups". |
| **Medium 1.** An active validator's slot was compared, but not its key, so a stale node file could rotate the key.           | Fixed. The script stops if the on-chain key differs from the file's. The message shows the first and last 8 bytes of each key.                                                                                                                                                                                                                                                                                                                                           |
| **Medium 2.** The doc required `ROLE_DVT` and `minStake`, but the tool did not check them.                                   | Fixed. `--deployment` checks `ROLE_DVT`, that `GTokenStaking.roleLocks` is at least `minStake`, and that no exit notice is in effect. These are the checks SP's `_reconstructPkAgg` makes. Every read fails closed.                                                                                                                                                                                                                                                      |
| **Medium 3.** The export carried no state commitment, and the SAFE checklist had no step to re-check state before executing. | Fixed. Every gate reads at one block. That block's hash is re-checked at the end. The export records `basis` (the block, hash and timestamp), `reads` and `readsDigest`. The SAFE checklist now says to re-run the export just before executing: only `basis` may differ.                                                                                                                                                                                                |
| **Medium 4.** The rehearsal's `SP_COMMIT` was only a label.                                                                  | Fixed. A checkout must be clean at `SP_COMMIT`. A tarball's two sources must match `SP_COMMIT`'s git blobs. The artifacts must carry the sources' keccak256, and `EXPECT_VERSIONS` must equal the sources' `version()` strings.                                                                                                                                                                                                                                          |
| **Low.** "Reads no key" was not literally true, because the whole env file was parsed.                                       | Fixed. Only the three RPC names are kept, and every other line is dropped as the file is split. The file is still read whole, so the doc now says "uses no EOA key" and suggests an RPC-only env file (Codex on the delta). The node files' BLS secrets are still read, to sign the PoPs.                                                                                                                                                                                |

There was no second Daybreak, by DSR's ruling: the path with the High is gone,
and the remaining changes tighten read-only checks. Codex (the regular model)
reviews the delta, and any High it reports goes to DSR. Verification is in the
PR description.
