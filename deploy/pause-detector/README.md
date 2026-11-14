# Pause detector (rc.8)

For rc.8, pausing an understaked operator is **detect, then act by hand** (DSR):
keeper α is parked, and the standalone D2 pause job (`deploy/pause-job`) is
retired. This detector watches, and a person pauses with the exact command it
sends.

It is D2's read path with every send path removed. It holds **no key**. There is
no keystore, no signer, and no signing or broadcast code. Three layers back
this, and they are not equally strong:

1. **The boundary: Node's permission model.** The plist runs the pinned node
   (`~/.local/keeper-node/node-v24.21.0`, not Homebrew's, whose directories
   admin can write) with `--permission`, reads of the repo and
   `~/.aoa-pause-detector` only, and writes of its state directory only.
   - So the process cannot start a child process (no `cast`), a worker, a native
     addon or WASI.
   - It cannot read any key on the host: not the price keeper's `key.env`, not a
     foundry keystore, not `~/.ssh`.
   - It holds no key, so it cannot sign.
   - `detector.mjs` checks `process.permission` first and refuses to start
     without the model or with anything more allowed.
   - Preflight checks that launchd LOADED exactly these arguments.
   - A CI cell runs node with the plist's flags and proves spawn, worker and an
     outside read all fail. The anvil e2e runs `detector.mjs` itself that way.
2. **Runtime allowlist.** Only seven read-only JSON-RPC methods are allowed. The
   check runs twice: in the client, and again in the transport, which is a plain
   `fetch` POST with no ethers provider. A write method is refused before any
   request is made.
3. **Static scan, a review aid.** `no-signing-scan.mjs` parses (acorn) the
   detector and every module it reaches by static import or re-export. CI fails
   on any of these:
   - a name, key or string that holds a key, signs, broadcasts or runs a
     program;
   - dynamic import, `require`, `eval`, `globalThis`, `.constructor`;
   - a computed member built from strings;
   - `process` or `console` used other than as a few named members;
   - ethers used other than as nine pure utilities;
   - any `fetch` other than to the Telegram Bot API or from the one JSON-RPC
     transport.

   Control cells show the scan catching each form Codex found in rounds 1–3.
   **It is not complete and cannot be.** JavaScript can build a name at run time
   (`const k = "constr" + "uctor"; f[k]`) in ways no static scan of this kind
   rules out. It catches direct and accidental code. Layers 1 and 2 hold against
   deliberate code.

**Durability under the model.** Node 24 disables `fsync` under the permission
model. State writes stay atomic (temp file + rename) but are not fsynced. A
crash can lose the last write, which costs a rescan and a repeated alert, never
a missed one.

## What one round does (hourly, launchd)

1. **Inventory.** It extends the operator list from the SP proxy's
   `OperatorConfigured` logs, over finalized ranges only. The cursor moves past
   a range only after that range's `getLogs` succeeded; a failed range is
   retried next round, never skipped.
   - Every log must carry an ABI address topic (12 zero bytes, then the address)
     and a `blockHash` equal to the canonical hash of its block. Anything else
     makes the round unknown.
   - Each round re-reads the last `rescanBlocks` behind the cursor. Once a day
     it re-reads everything from `startBlock`. So a lagging backend that
     answered `[]` cannot hide an operator for good.
   - A cursor ahead of the finalized block stops the round. State times after
     now (a clock that was ahead) are reset and reported.
2. **One block.** It pins B, the latest block, by hash. Every read below is at B
   (EIP-1898, `requireCanonical`).
3. **Identity at B.**
   - `SuperPaymaster.REGISTRY()` is the configured Registry.
   - The EIP-1967 implementation slot of **both** proxies holds the configured
     implementation.
   - The SP proxy, its implementation, the Registry proxy and its implementation
     all hash to their configured code hashes. SP and the Registry are both
     ERC-1967 proxies with the same proxy bytecode, so a proxy's code hash alone
     identifies nothing.
4. **Recent operators.** Operators configured after the cursor, up to B, are
   read this round too. They are not persisted until finalized.
   - **Ancestry.** It walks B's ancestry by hash (`eth_getBlockByHash`) down to
     the finalized block, and the walk must join the finalized block read by
     number. Every log above finalized must come from that chain, so a
     load-balanced endpoint answering from another fork is caught. More than
     2048 blocks above finalized is unknown.
   - **Every unfinalized block by hash.** Every block above finalized, and B
     itself, is asked for its logs by hash (EIP-234). Those operators count. If
     a block's by-hash answer differs from its number-range answer, the round is
     unknown. This runs every round, even when the cursor has reached B, so a
     lagging range backend that omits a log is caught.
   - A latest block below the finalized block or the cursor (a lagging backend),
     or a height that is not a safe integer, stops the round. Range construction
     is bounded.
5. **Each operator at B.**
   - It reads `operators(op).{isConfigured, isPaused}` and the three Registry
     reads of `SuperPaymasterStorage._hasEffectiveSuperStake`:
     `hasRole(ROLE_PAYMASTER_SUPER, op)`,
     `getRoleConfig(ROLE_PAYMASTER_SUPER).minStake` and
     `getEffectiveStake(op, ROLE_PAYMASTER_SUPER)`. The operator is understaked
     when it is configured and does not hold the role with
     `effective >= minStake`.
   - It cross-checks with an `eth_call` of `pauseUnderstakedOperator(op)` from
     the zero address. The function is permissionless; an eth_call broadcasts
     nothing. If the reads and SP's own check disagree, the result is
     **unknown**.
6. **Canonical check.** B is re-checked canonical after every read. If it left
   the chain, the whole round is unknown.

## Alerts (Telegram, the aastar-monitor bot)

| Result                                                                                                 | Alert                                                                                                                                          |
| ------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| configured, understaked, **not paused**, identity confirmed                                            | `PAUSE NEEDED: operator <op> … Run:` followed by `cast send <SP> "pauseUnderstakedOperator(address)" <op> --rpc-url <RPC> <your signer flags>` |
| a read failed, the cross-check disagrees, identity not confirmed, an inventory range failed, B reorged | `unknown: …`, naming the read                                                                                                                  |
| `OperatorConfigured` seen but not configured at B                                                      | a notice                                                                                                                                       |
| understaked and already paused, or meets the stake                                                     | nothing                                                                                                                                        |

- **"unknown" is never "clear".** `status.json.clear` is true only when the
  identity was confirmed at a canonical B, every read succeeded, and no operator
  is actionable or unknown.
- **When the identity is not confirmed, no PAUSE NEEDED is sent.** The identity
  alert is sent instead, because the detector may be reading the wrong contract.
- **Delivery.** Alerts go out in messages of whole lines, under Telegram's
  limit. A message counts as delivered only on HTTP 2xx with a JSON body
  `ok: true`. Only the alerts in delivered messages are marked sent; the rest
  are retried next round.
- **Repeats.** An alert repeats every `realertMinutes` while it holds.
- **Resolution.** A `resolved:` line is sent once a later round sees the
  condition gone. For an operator, that requires the operator to be read at a
  canonical B with the identity confirmed.
- **No all-clear messages.** The trigger evidence is `status.json`, which
  preflight checks.

## Files

- `detector.mjs`: config, lock, secrets, the read-only RPC client, delivery,
  `status.json`.
- `lib/detect.mjs`: the round. It does no I/O; the chain is injected.
- `check-pause-detector.mjs`: the CI cells (`npm run check:pause-detector`).
- `no-signing-scan.mjs`: the AST scan those cells run (test code, not loaded by
  the detector).
- `e2e-anvil.mjs`: end to end against SP's real contracts, deployed by SP's
  `DeployAnvil.s.sol` at `sp-pin.json`'s commit:
  - it raises minStake on chain;
  - it runs the alert's exact `cast send` command and confirms the operator is
    paused;
  - it checks that the next round is clear and resolves the alert.

  Run:
  `node deploy/pause-detector/e2e-anvil.mjs --sp <SP checkout at the pin, built>`.

- `config.example.json`, `io.aastar.dvt-pause-detector.plist` (`StartInterval`
  3600).

Shared with D2: `../pause-job/sp-pin.json` (ABI fragments and ROLE_* at one SP
commit, `gen-sp-pin.mjs`), `../pause-job/lib/secret-file.mjs` (the generic
secret-file reader, called with the detector's own name table) and
`../pause-job/lib/safe-error.mjs`.

## Deploy (on the Mini, after the rc.8 read-back)

1. Regenerate the pin at the rc.8 tag:
   `node deploy/pause-job/gen-sp-pin.mjs <tag commit>`, and review the diff.
2. Write `~/.aoa-pause-detector/config.json`. The addresses, implementations,
   code hashes and deploy block come from the tag read-back, never from this
   repo.
   - `rescanBlocks` (blocks re-read behind the cursor each round; 20000 in the
     example) bounds how long a lagging backend's `[]` can hide an operator
     before the daily full rescan.
   - `logChunk` must fit the providers' `getLogs` range limits. A range that is
     too wide makes every round `unknown` until it is fixed; it never makes a
     round clear.
3. Create the secrets as 0600 files in a 0700 directory, without argv or
   history:
   - `aoa-dvt-detector-rpc-primary` and `aoa-dvt-detector-rpc-fallback` (RPC
     URLs);
   - `aoa-dvt-alert-bot-token` (the aastar-monitor bot).

   There is no keystore and no password file. The detector cannot read the D2
   keystore-password name; a cell checks this.

4. Make the state dir 0700. The state is created on the first run and is bound
   to `{chainId, spProxy, startBlock}`. A new deployment needs a new `stateDir`.
5. Render and load the plist, then check
   `launchctl print gui/$(id -u)/io.aastar.dvt-pause-detector | grep "run interval"`
   shows 3600. The plist needs the pinned node at
   `~/.local/keeper-node/node-v24.21.0` (installed and verified on the Mini,
   11-14), and the repo and `~/.aoa-pause-detector` both under the home
   directory.
6. Run `node deploy/pause-job/preflight.mjs`. It checks:
   - **launchd-on**: the detector and the price keeper are loaded; the committee
     keeper, apply-rotation and the D2 pause job are not; no other loaded job
     runs a DVT sender;
   - **detector-args**: the loaded detector runs exactly the pinned node,
     `--permission`, the two reads and the one write;
   - **pause-detector**: `status.json` is at most two intervals old.

## Before rc.8

On Sepolia today (SP 5.4.2, 11-14) `pauseUnderstakedOperator` is **not
deployed**: its eth_call reverts with empty data. The detector therefore reports
every operator `unknown`, which is the fail-closed answer. A dry run with
meaningful answers needs the rc.8 code: the anvil end to end above, or SP's rc.8
fork.
