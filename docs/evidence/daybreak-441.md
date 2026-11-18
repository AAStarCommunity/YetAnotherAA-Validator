# Daybreak reviews of #441 (2026-11-18)

Two runs of Codex Daybreak:

```
codex exec -s read-only -m gpt-daybreak-blue-latest --cyber-access-program daybreak_blue
```

codex-cli 0.166.0, each in a clean detached worktree. Each prompt allowed
reading only the worktree, with no network, chain, RPC, `.env`, keystore or key
file.

| Run | Head                                       | Tokens  | Result                                                    | Raw report                     |
| --- | ------------------------------------------ | ------- | --------------------------------------------------------- | ------------------------------ |
| 1   | `e8d2a9a8c68c485cbcbba8773122b9bc53309f7f` | 113,792 | 1 High, 3 Medium, 1 Low                                   | `daybreak-441-e8d2a9a8-raw.md` |
| 2   | `7aa2288ec556cf9bb85adbe9da8eb666fb8a8c47` | 143,683 | "Findings: none." All five run-1 findings verified fixed. | `daybreak-441-7aa2288e-raw.md` |

Neither run hit a quota or rate-limit error. Run 2's head is the tree of this PR
pair, apart from these evidence files.

## Run 1 findings and what was done

| Finding                                                                                                                                                                 | Fix                                                                                                                                                                                                                                                                                                                                                     | Where                                         |
| ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------- |
| **High.** The watcher decoded only a top-level `verifyAndExecute`. The normal path is `DVTValidator.executeWithProof`, so honest fraud proofs could never be assembled. | The watcher dispatches on `tx.to`. For the DVTValidator the aggregator names at the execution block, it decodes `executeWithProof` and reads `operator`, `slashLevel` and `evidenceHash` from `proposals(id)` at that block. Any other target is refused. A jest spec replays a real wrapper transaction recorded by E3 and requires a verified record. | Part 1 (watcher); part 2 (fixture and replay) |
| **Medium.** A nonzero `EXPECTED_AGGREGATOR` overrode the compiled `CANONICAL_AGGREGATOR`.                                                                               | The constant wins; the env value may only repeat it.                                                                                                                                                                                                                                                                                                    | Part 1                                        |
| **Medium.** Gate A' admitted 4.13.x, which has no parent block hash.                                                                                                    | The floor is now 4.14.0.                                                                                                                                                                                                                                                                                                                                | Part 1                                        |
| **Medium.** E3 checked only the drill export's shape.                                                                                                                   | `--drill-case` aims the drill at the executed slash, on chain 31337 only. E3 step 5b fills field 8 and requires byte equality with the execution's proof, then runs valid plus N1–N4.                                                                                                                                                                   | Part 2                                        |
| **Low.** The drill read the default `.env.sepolia`.                                                                                                                     | Drill mode requires `--env` on the command line; an inherited `DVT_ENV_FILE` does not count.                                                                                                                                                                                                                                                            | Part 2                                        |

Still known, and unchanged by these PRs: the verifier reads the token's current
`isOverIssued()`, not its state at the disputed epoch (#447). Guardian slash
with real stake stays off until that is resolved.
