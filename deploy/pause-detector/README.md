# Pause detector (rc.8)

For rc.8, pausing an understaked operator is **detect, then act by hand** (DSR):
keeper α is parked, and the standalone D2 pause job (`deploy/pause-job`) is
retired. This detector watches, and a person pauses with the exact command it
sends.

It is D2's read path with every send path removed.

**The guarantee (DSR's wording):** no key held, no signing path by design,
spawn/worker disabled and key material unreadable. This guards against an
**accidental** signing path. It does **not** guard against a malicious
dependency. The trust boundary is the same uid as the price keeper: anything
running as that account, or a compromised dependency, is out of scope. Node's
own documentation says the permission model is not a security boundary against
malicious code, and nothing here claims it is.

Three layers carry it, and they are not equally strong:

1. **Node's permission model, run from a bundle.** The detector never runs from
   a repository checkout, which may hold `node_state.json`, `.env.sepolia` or
   `.keys/` (Codex R7). `bundle.mjs` builds `~/.aoa-pause-detector/app` from a
   clean checkout. The bundle holds only the detector's own modules (the scan's
   walk), `sp-pin.json`, and the ethers dependency closure, about 1.8k files,
   plus a `MANIFEST.json` with each file's sha256. The plist runs the pinned
   node (`~/.local/keeper-node/node-v24.21.0`, not Homebrew's, whose directories
   admin can write) with `--permission`, reads of `~/.aoa-pause-detector` only,
   and writes of its state directory only.
   - So the process cannot start a child process (no `cast`), a worker, a native
     addon or WASI.
   - It cannot read key material on the host: not the price keeper's `key.env`,
     not a foundry keystore, not `~/.ssh`, not any checkout.
   - It holds no key and has no signing code, so there is no signing path by
     design.
   - **ethers' `Wallet` is in the bundle** (DSR), because the bundle carries the
     ethers package whole. The detector never uses it; the scan pins ethers to
     nine pure utilities. And it has nothing to work with: no key is readable,
     and the RPC allowlist refuses every send and sign method.
   - **Environment.** The process runs only with an allowlist of variables: what
     macOS and launchd give an agent, plus `SSH_AUTH_SOCK`. That is an agent
     socket, and an agent never hands out key material. Anything else refuses
     the start, so a stale `KEEPER_PRIVATE_KEY` inherited from launchd never
     sits in the process (Codex R8).
   - **Startup guards.** `detector.mjs` is the entry and uses Node builtins only
     (`lib/guard.mjs`). It refuses to start unless all of these hold:
     - `process.permission` exists and grants nothing more;
     - node's own flags (`process.execArgv`) are exactly the plist's, the script
       is the bundle's entry, and the only arguments after it are
       `--config ~/.aoa-pause-detector/config.json` (clestons #434 F3);
     - no option-injecting variable is set (`NODE_OPTIONS`, `NODE_*`, `DYLD_*`,
       `BASH_ENV`). A `NODE_OPTIONS=--allow-fs-read=<key>` would widen the
       grants with the arguments unchanged (Codex R4);
     - nothing under `~/.aoa-pause-detector` is a symlink. The permission model
       follows a symlink inside a granted directory to a target outside it
       (Codex R5);
     - the bundle is exactly its manifest: no extra file, none missing, every
       sha256 equal.

     Only then does it import `run.mjs`. So `sp-pin.json`, which `detect.mjs`
     reads at import, is read only after it was verified (Codex R7). Config and
     state are read with `O_NOFOLLOW`, checked on the descriptor: a regular
     file, this uid, writable by nobody else. The secrets were already read that
     way.

   - **Preflight.** It runs outside the model, so it also covers the entry file
     itself. It checks three things:
     - launchd LOADED exactly the plist's arguments;
     - the loaded or inherited environment holds no injecting variable;
     - the bundle matches its manifest, with no symlink in the directory.
   - **Tests.** CI cells build a real bundle and launch it with the plist's
     flags. They prove that a spawn, a worker, an outside read and a read of the
     repository all fail, and that the detector refuses each of these:
     - a `NODE_OPTIONS` grant;
     - a symlinked `config.json` or `sp-pin.json`;
     - a file added to the bundle, changed in it or missing from it;
     - a launch from a checkout.

     The anvil e2e runs the bundle under the flags.

   - **Not covered.** Code inside the process can still use the network. A
     malicious module could POST a transaction someone else signed. That is the
     malicious-dependency case the guarantee excludes.
2. **Runtime allowlist.** Only seven read-only JSON-RPC methods are allowed. The
   check runs twice: in the client, and again in the transport, which is a plain
   `fetch` POST with no ethers provider. `eth_sendRawTransaction`,
   `eth_sendTransaction`, every `eth_sign*` and every `personal_*` method is
   refused before any request is made. A cell tries each one.
3. **Static scan, a review aid.** `no-signing-scan.mjs` parses (acorn) the
   detector and every module it reaches by static import or re-export. CI fails
   on any of these:
   - a name, key or string that holds a key, signs, broadcasts or runs a
     program;
   - dynamic import, `require`, `eval`, `globalThis`, `.constructor`;
   - an inline computed member built from strings (`x["send" + y]`). A variable
     index (`x[k]`) is allowed: the scan does no data-flow analysis, and a send
     method reached that way is still refused by the transport (layer 2)
     (Daybreak M10);
   - `process` or `console` used other than as a few named members;
   - ethers used other than as nine pure utilities;
   - any `fetch` other than to the Telegram Bot API or from the one JSON-RPC
     transport.

   Control cells show the scan catching each form Codex found in rounds 1–3.
   **It is not complete and cannot be.** JavaScript can build a name at run time
   (`const k = "constr" + "uctor"; f[k]`) in ways no static scan of this kind
   rules out. It catches direct and accidental code, which is the case the
   guarantee is about.

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
   - A cursor ahead of the finalized block means the chain is not the one the
     state was built on, so everything is read and verified again from
     `startBlock`. State times after now (a clock that was ahead) are reset and
     reported.
2. **One block.** It pins B, the latest block, by hash. Every read below is at B
   (EIP-1898, `requireCanonical`).
   - **A fresh head.** A head older than `maxHeadAgeSec` (1800 in the example;
     Sepolia's block time is 12 s) stops the round as `unknown` (clestons #434
     B1). A node frozen at a height is self-consistent, so every other check
     passes against it; only the head's age shows it.
   - **A head from the future** (Daybreak M8, DSR 2026-11-17). A head more than
     300 s ahead of the Mini's clock also stops the round as `unknown`, naming
     the clock. A real block is never far in the future, so either the Mini's
     clock is behind (and a frozen head would look fresher than it is by that
     much) or the provider is wrong.
   - The provider probe treats a stale head as a failed probe, so the fallback
     takes over from a frozen primary.
   - `status.json` records B's timestamp, and preflight FAILs a `clear` on an
     old or undated head.
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
   - **The cross-check watermark (`checked`).** Every block up to `checked` was
     asked for its logs both by hash (EIP-234) and by range, and the two answers
     agreed. Each round asks every block in (`checked`, B] both ways and
     compares them. A block above finalized uses the hash from B's ancestry
     walk; one at or below it uses the canonical hash by number. A block that no
     range scan of this round covered gets its own range query.
     - The watermark only advances over contiguous blocks that agreed, and never
       past finalized, since a block above it can still be replaced.
     - It starts below `startBlock`, so every block is compared once, even if
       the first rounds fail (Codex R11).
     - **One chain.** It only advances along a single chain. At or below
       finalized, each block's header is read by its hash, and its parent must
       be the previous checked block. Above finalized, the hashes come from B's
       own ancestry walk, which joins the finalized block. So the checked chain
       reaches B link by link, and a by-number answer from another fork breaks
       it (Codex R13). An advanced watermark without its hash re-verifies from
       `startBlock`.
     - It is bound to the canonical hash of its block. If that hash changes, or
       the watermark or cursor is above the finalized block, the chain under
       them changed. Nothing below them can be assumed, so everything is read
       and verified again from `startBlock`, and an alert says so (Codex R12).
       This is rare, and it costs one backlog.
     - A round's progress (cursor, watermark, rescan time) is committed only if
       the round ends with B still canonical. A throw at any point, or a
       rejected B, leaves them where they were. The inventory still keeps what
       it saw, since a superset is safe.
     - A failed read or a disagreement stops it where it is. On a disagreement
       the cursor also moves back before that block.
     - So the block is asked again next round, before and after finalization
       alike. The round stays unknown until the watermark is within reach of B.
     - This runs every round, even when the cursor has reached B, so a lagging
       or forked range backend that omits a log is caught (Codex R3, R8–R10).
     - At most 4096 blocks are checked per round. A larger backlog (after a long
       outage) is worked off over several rounds and reads unknown meanwhile.
   - **The inventory only grows.** Every operator seen by range or by hash is
     kept, whatever else failed that round. So an incomplete later answer cannot
     make one disappear. One that is not real costs a read and reads
     `not-configured`, never a false clear.
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

### Trust in the RPC providers (DSR scope ruling)

The detector **trusts its two RPC providers not to equivocate on finalized
blocks**. Its worst outcome is a missed or late alert, since it sends nothing.

- **What holds without that trust.** Every read failure and every inconsistency
  the detector can see yields `unknown`, never clear. Honest providers with
  ordinary lag, load balancing, reorgs or a frozen head cannot produce a false
  clear. That rests on the head-age check, the hash-bound chain-linked
  cross-check watermark above, and the commit-on-canonical rounds.
- **One provider per round.** Each round reads from one provider, the primary
  unless it fails its probe. Its range answers and its by-hash answers come from
  the same backend, so a log index that consistently lacks one block's logs (an
  honest indexer bug is enough) answers `[]` both ways, and the window and daily
  rescans ask it again (Daybreak H1).
- **The daily inventory cross-check** (Daybreak H1; **DSR ruling 2026-11-17**).
  Once a day the detector reads the operator inventory from `startBlock` again
  from the configured **fallback**, up to the lower of the inventory's cursor
  and the fallback's finalized block. It compares the two sets of operators
  (`crossCheckInventory`, `lib/detect.mjs`).
  - **Fixed roles** (clestons #448 B2). The inventory is never "checked" by the
    provider whose answers built it. Only the configured fallback compares, and
    only on a round that the configured primary ran (`crossCheckPlan`,
    `run.mjs`). A round that ran on the fallback records an incomplete attempt
    instead. Residual: blocks that the fallback itself added to the inventory,
    on rounds when the primary failed its probe, are compared against the
    fallback's own answers until the primary's next daily full rescan re-reads
    them.
  - An operator only the fallback has: the primary's index missed it. Every
    round is `unknown` and the alert names it, and it is checked every round
    from then on. The check is repeated every round while the two disagree. **It
    leaves the disagreement only** when it is in the inventory (then every round
    checks it), or when the same provider that found it, over at least the
    height at which it found it, no longer reports it (clestons #448 B1/B2: a
    lower comparison, or one by the inventory's builder, cannot clear it).
  - An inventory entry the other provider lacks is asked of the primary again,
    by operator: if the primary has no such log either, it is a harmless
    superset entry (a block that later left the chain) and not a disagreement;
    otherwise it is one too, named the same way. The inventory entries the
    fallback lacks are re-asked in one `getLogs` per chunk, with up to 50
    operators as an OR topic; more than 1000 such entries make the attempt
    incomplete (clestons #448 N1).
  - If the fallback cannot answer, the day is recorded as incomplete
    (`status.json` `report.crossCheck`). Three incomplete days in a row raise
    `the daily inventory cross-check … has not completed for N days`.
  - **An incomplete cross-check is tolerated for at most 3 days** (Daybreak
    narrow rerun High A, DSR 2026-11-17). Once the inventory's cursor is more
    than 3 × `CROSS_CHECK_MAX_LAG_BLOCKS` (21600) blocks past what the last
    completed cross-check covered, every round is `unknown`
    (`crosscheck-behind`). That happens at the same point that
    `crosscheck-incomplete` starts to alert.

  - **It must keep up** (Daybreak rerun High, DSR 2026-11-17). The highest block
    a completed cross-check covered is kept (`coveredTo`). An attempt whose
    height is below it, or more than 7200 blocks (a day at Sepolia's 12 s;
    `CROSS_CHECK_MAX_LAG_BLOCKS` in `lib/detect.mjs`, **chosen for Sepolia's
    block time: recompute it there, as one day / block time, before watching
    another chain**, e.g. 43200 on OP Mainnet) behind the primary's cursor, is
    incomplete: the other provider's finalized block stalled or went back. A
    standing disagreement is replaced or cleared only by a comparison that
    reaches its height, whatever that comparison finds (Daybreak narrow rerun
    High B).
  - **No round is clear before a first cross-check has completed** (DSR
    2026-11-17): a first deployment, or a state file that was lost or emptied
    (which also resets `coveredTo`), reads `unknown`
    (`no inventory cross-check … has completed yet`) until one completes. On a
    first deployment with the fallback down, that means `unknown` until it
    answers.

  - A state whose cross-check record is inconsistent (a completed record without
    `coveredTo`, a disagreement without its height, Daybreak narrow rerun
    Medium) is refused. The round stops and reports `unknown`; the state is
    never rebuilt silently.

  So an honest provider's index gap is found within a day, and a fallback that
  is down for under 3 days does not turn every round unknown once a first
  cross-check exists.

- **The known residuals.**
  - Both providers missing the **same** log the same way is not found.
  - **The guards' combinations are covered by unit cells only** (DSR
    2026-11-17). Each guard has its own cell and a mutant that fails it, and the
    lower-height and swapped-role probes from clestons #448 are cells. No
    further Daybreak round reviewed how the guards interact.
  - A provider that **deliberately** answers one finalized block two different
    ways, consistently, could still hide an operator. For example, it might
    serve another fork's block by number and by hash alike, with matching empty
    logs, along a whole linked stretch. That case is outside the threat model
    (DSR 2026-11-14) and is not mitigated.
- **A follow-up, not required for rc.8.** With both providers configured, read
  the decision inputs at B (role, minStake, effectiveStake, isPaused) from both
  and treat a disagreement as `unknown`.

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
  - `undeliveredSince` (for the dead-man) clears on a round in which **nothing
    failed** (clestons #448 N2, DSR 2026-11-17). An alert whose condition went
    away before it was ever delivered is no longer owed, so it does not hold the
    field.
  - The dead-man treats an unreadable, or future-dated, `undeliveredSince` as
    "delivered" (clestons #448 N4). The detector writes the field clamped to its
    own clock, so that needs a forged or corrupted heartbeat; disclosed, not
    mitigated.
- **Repeats.** An alert repeats every `realertMinutes` while it holds.
- **Resolution.** A `resolved:` line is sent once a later round sees the
  condition gone. For an operator, that requires the operator to be read at a
  canonical B with the identity confirmed.
- **No all-clear messages.** The trigger evidence is `status.json`, which
  preflight checks.
- **A stop is never silent** (clestons #434 F1). Every early stop writes a
  `status.json` with `clear: false` and the reason in `startup`, and preflight
  FAILs on it. That covers a guard refusal, a bad config or state directory, and
  a failed startup. The only exception is a second instance that loses the lock;
  the run holding the lock writes its own status. The same goes for a round
  whose alerts were not delivered.
- **Uncaught exceptions** and rejections, once the entry's guards have passed,
  are recorded as a stop too, then the process exits non-zero. Only the error's
  code or class is recorded, never its message, which may carry a URL.

## Dead-man (DSR: required before this is rc.8's pause path)

A detector that stops silently gives no signal at all. So a **separate** launchd
job watches it: `io.aastar.dvt-pause-detector-deadman`, every 15 minutes
(`deadman.mjs`).

**What it covers, and what it does not** (clestons #435 B1, #436). The dead-man
checks only what it uses itself: its own six files against `MANIFEST.json`
(`DEADMAN_GRAPH` in `lib/guard.mjs`), with every directory on their path a real
one, and the heartbeat read through a real `state/` directory. A failure in a
part only the detector uses therefore no longer stops the dead-man.

| The detector stops because                                                                                     | Dead-man alerts?   |
| -------------------------------------------------------------------------------------------------------------- | ------------------ |
| its plist is unloaded, or its launch arguments are wrong                                                       | yes                |
| it hangs, crashes, or a round throws on every run                                                              | yes                |
| an unrelated process holds its lock port                                                                       | yes                |
| its state directory or an RPC secret is unusable, including a symlink in `state/` or `state/` itself           | yes                |
| a file only the detector loads does not match `MANIFEST.json`, or a stray symlink outside the dead-man's files | yes                |
| a `config.json` field only the detector uses is invalid                                                        | yes                |
| the pinned node is missing or moved                                                                            | **no** (known gap) |
| `config.json` is missing, unreadable or not JSON, or its `telegram` field is invalid                           | **no** (known gap) |
| the alert bot token file is unusable (both jobs read the same file)                                            | **no** (known gap) |
| one of the dead-man's own six files does not match `MANIFEST.json` (the detector checks them too)              | **no** (known gap) |

**The detector watches the dead-man back** (#436). Every round reads
`deadman/status.json`. If it is missing, not the dead-man's schema, older than
three dead-man intervals (45 min), dated in the future, a stop, or reports
undelivered messages, the round raises the alert
`the dead-man check is not working`. The alert resolves on its own once the
dead-man runs cleanly again. So a dead-man that is down (plist unloaded,
directory missing, state unreadable, its own guards failing) is reported by the
detector, as long as the detector itself is running.

**Known gaps.** DSR accepted all four on 2026-11-15 and ruled that no further
mechanism be added for them. In each, both jobs stop and neither sends anything.
What covers each:

- **The pinned node** lives at a fixed path
  (`~/.local/keeper-node/node-v24.21.0`) that nothing upgrades automatically.
- **`config.json`** changes only at a deploy, and **preflight runs after every
  deploy**; it reports both jobs' stopped `status.json`.
- **The alert bot token file**: if it fails, neither job can deliver an alert.
  On deploy day the author checks by hand, once, that an alert actually arrives.
- **The dead-man's own files**: the bundle is never edited in place (an upgrade
  is a new directory swapped in), and preflight's `detector-bundle` checks it
  after every deploy.

One more case is not a stop but a false alarm: if the Mini's clock is set back,
the dead-man's `status.json` can read as dated in the future, and the detector
raises `the dead-man check is not working` for a round until the clock passes it
again. Both jobs run on the same machine and clock, so this needs a clock step,
and it errs towards alerting (clestons #438).

**Nothing runs preflight on a schedule yet**, so these four are visible only on
a manual preflight. A broken redeploy is the most likely way to hit one: **run
preflight after every deploy.**

- **Heartbeat.** Every **completed** round writes
  `state/heartbeat.json { at, gaps, block, clear }`. A completed round means no
  throw and B still canonical, whether or not it reads clear. A round that reads
  unknown still alerts on its own, so the heartbeat only answers "is the
  detector running rounds at all".
- **Undelivered alerts** (Daybreak M7, DSR 2026-11-17). The heartbeat also
  carries `undeliveredSince`: since when some due alert of the detector could
  not be delivered (it is retried every round, and the field clears on the first
  round that delivers everything). A completed round still writes the heartbeat,
  so without this a detector whose own messages fail would look alive. When
  `undeliveredSince` is more than 2 h old, the dead-man alerts
  `the pause detector runs, but its alerts have not been delivered since …`,
  repeating every 6 hours, and sends one notice when they are delivered again.
  Both jobs share the bot token, so this covers a failure of the detector's
  messages only, not of the token (the known gap above).
- **Check.** Of the heartbeat the dead-man reads only `schema`, `at`, `gaps` and
  `undeliveredSince`. With no completed round for more than **2 hours**, it
  alerts via aastar-monitor, repeating every 6 hours while that lasts. A missing
  heartbeat, an unreadable one or one dated in the future counts as silence. It
  sends one `rounds resumed` notice when the heartbeat is fresh again. An alert
  that was not delivered is retried at the next run.
- **No message lost silently.**
  - Undelivered messages are queued in the dead-man's state, written **before**
    each delivery attempt and emptied only once Telegram accepted them.
  - The queue goes out in messages of whole lines under Telegram's limit; each
    delivered message leaves the queue, the rest is retried (Codex dm-R6 P2). A
    message already queued is not queued again.
  - A long queue is compacted, never truncated: it keeps the first outage, a
    count of what was folded, and the latest messages.
  - An existing state that cannot be read stops the run, and the file is left as
    it is. That stop sends nothing; it is visible only on preflight (see the
    table above).
  - Its directory `~/.aoa-pause-detector/deadman` must be a real directory owned
    by the job's account, mode `700`, the same rule as the detector's state
    directory; otherwise the run stops (exit 78) (Codex dm-R7).
- **Outages carried until acknowledged.** A host crash (no fsync under the
  permission model) can still roll back the queue, and a later round can
  overwrite the heartbeat before the dead-man reads it. So the heartbeat itself
  carries `gaps`: the outages (no completed round for more than 2 h) the
  dead-man has not acknowledged yet, at most 20 of them.
  - A new gap is added when the previous completed round is more than 2 h old.
  - The detector drops a gap only once it appears in the dead-man's
    `reportedGaps`.
  - The dead-man reports each gap it has not reported yet, once, and adds it to
    `reportedGaps` only after the whole queue was delivered (Codex dm-R6 P1).

  - Past 20 unacknowledged gaps, the first and the latest 19 are kept and the
    ones in between are dropped unreported. That needs 20 separate outages with
    the dead-man not running or not delivering through all of them, a state
    preflight already fails on (`pause-detector-deadman`).

  So an outage is reported even if its queued alert was lost or the heartbeat
  has moved on twice. The worst case is a duplicate (Codex dm-R4, dm-R5).

- **Confinement.** It runs from the same bundle, under the same permission
  model, with the detector's startup guards except the whole-tree ones: it
  checks only its own files (see above). It reads `~/.aoa-pause-detector` and
  writes **only** `~/.aoa-pause-detector/deadman`, its own state and
  `status.json`. It reads no chain and holds no key.
- **Preflight** checks that it is loaded with exactly its plist's arguments
  (`deadman-args`). It also checks its own `status.json`
  (`pause-detector-deadman`): written within three of its intervals, not a stop,
  the detector reported alive, and nothing undelivered. A dead-man that is not
  running is as silent as the detector it watches.

## Files

- `detector.mjs`: the entry. It runs the startup guards, then imports `run.mjs`.
- `lib/guard.mjs`: the guards (Node builtins only): the permission model, the
  exact launch, no-follow reads, symlinks, bundle versus manifest.
- `run.mjs`: config, lock, secrets, the read-only RPC client, delivery,
  `status.json`.
- `lib/detect.mjs`: the round. It does no I/O; the chain is injected.
- `deadman.mjs`, `deadman-run.mjs`: the dead-man check's entry (its guards cover
  only its own files, `DEADMAN_GRAPH`) and its run.
- `lib/notify.mjs`: delivery shared by both jobs (Telegram batches, durable
  writes, the secret names); it imports no detector code.
- `bundle.mjs`: builds the bundle and its manifest. It is a deploy tool, never
  in the bundle.
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

0. **Deploy gate (DSR 2026-11-15).** Run Codex once over the whole
   `deploy/pause-detector` directory on the master commit being deployed. Deploy
   only if it reports no High. (The merge gate for this read-only directory is
   the clestons approval. If the directory ever gains a signing or sending
   capability, the stricter merge gate applies again.)
   - **Known issue, could not reproduce (DSR 2026-11-15, part of this gate).**
     On #439's head `fda1990f` one Node 20.20.2 run of `check:pause-detector`
     had one failed cell, which was not captured. It was then run 30 times in a
     row on Node 20.20.2 (`node deploy/pause-detector/check-pause-detector.mjs`,
     each run's full log kept): 30/30 passed, 109/109 each. Not chased further.
     If it recurs, keep the full log and name the cell before deploying.
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
   - `maxHeadAgeSec` (60..86400) is the oldest head a round accepts.
   - `startBlock` is the rc.8 SP deploy block, or earlier. The detector checks
     it once per state (Daybreak H2, DSR 2026-11-17): SuperPaymaster must have
     **no code at `startBlock − 1`**, so no earlier `OperatorConfigured` can
     exist. Until that read returns empty code, every round is `unknown`
     (`start-block`). A later `startBlock` would leave earlier operators unread
     for good; fix it with a new `stateDir`. The read needs historical
     `eth_getCode`, which both configured providers serve.
   - The state file is read with a 1 MiB limit. The inventory only grows, at
     about 60 bytes per operator, so that is roughly 17,000 operators (Daybreak
     L11); rc.8 has a handful.
   - The first rounds cross-check every block from there, at most 4096 per
     round, so a start far in the past reads `cross-check is behind` (unknown,
     fail-closed) for a while (clestons #434 F5).
3. Create the secrets as 0600 files in a 0700 directory, without argv or
   history:
   - `aoa-dvt-detector-rpc-primary` and `aoa-dvt-detector-rpc-fallback` (RPC
     URLs);
   - `aoa-dvt-alert-bot-token` (the aastar-monitor bot).

   There is no keystore and no password file. The detector cannot read the D2
   keystore-password name; a cell checks this.

4. Make the state dir 0700. The state is created on the first run and is bound
   to `{chainId, spProxy, startBlock}`. A new deployment needs a new `stateDir`.
5. Build the bundle from a clean checkout at the merged commit:
   `node deploy/pause-detector/bundle.mjs --out ~/.aoa-pause-detector/app`.
   - It refuses if the output directory exists, and if the detector's files
     differ from HEAD.
   - It records the commit in `MANIFEST.json`, and prints the source commit and
     the sha256 of `MANIFEST.json`. **Record both in the deploy log.** SP puts
     them in the step-13 manifest as the detector's identity (DSR). Preflight
     compares the running bundle against them (step 7; Daybreak H4).
   - A bundle built with `--allow-dirty` from files that differ from the commit
     is marked `dirty` in its manifest, and the detector and preflight refuse it
     (Daybreak H4); the dead-man then reports the detector's silence.
   - Every bundled package must be exactly the version `package-lock.json` lists
     at that path, with an integrity entry; otherwise the bundler stops
     (Daybreak H5b). **This checks metadata, not the installed bytes:** a file
     changed inside `node_modules/ethers` with its `package.json` left alone is
     not caught here. The bytes are checked by `npm ci`, which verifies each
     tarball against the lockfile's integrity at install time, so build from a
     fresh `npm ci` (Daybreak rerun Low, disclosed; DSR 2026-11-17).
   - The checkout is not needed after this, and the detector cannot read it.
   - To upgrade, build a new bundle into a new directory and swap it in.
   - It copies ethers from the checkout's `node_modules`. So install that with
     `npm ci`, which installs exactly the lockfile, not `npm install`.
     `--allow-dirty` is for tests only.
   - The bundle is tested on the pinned Node 24.21.0 (CI also runs the cells on
     Node 20). clestons reports that under Node 26's permission model the lock
     socket fails to open (#434 F6, not reproduced here), so do not run it on
     another major version without re-testing.
6. Render and load the plist, then check
   `launchctl print gui/$(id -u)/io.aastar.dvt-pause-detector | grep "run interval"`
   shows 3600. The plist needs the pinned node at
   `~/.local/keeper-node/node-v24.21.0` (installed and verified on the Mini,
   11-14).
   - Then the dead-man: `mkdir -m 700 ~/.aoa-pause-detector/deadman`, render and
     load `io.aastar.dvt-pause-detector-deadman.plist`, and check that its run
     interval is 900.
7. Run
   `node deploy/pause-job/preflight.mjs --detector-commit <commit> --detector-manifest-sha256 <sha256>`
   with the two values from step 5's deploy log. It checks:
   - **launchd-on**: the detector, its dead-man and the price keeper are loaded;
     the committee keeper, apply-rotation and the D2 pause job are not; no other
     loaded job runs a DVT sender;
   - **deadman-args** and **pause-detector-deadman**: see "Dead-man" above;
   - **detector-args**: the loaded detector runs exactly the pinned node,
     `--permission`, the one read, the one write and the bundle's entry, with no
     injecting variable;
   - **detector-bundle**: the bundle matches its manifest, with no symlink under
     `~/.aoa-pause-detector`; the manifest is not `dirty`; its `commit` and its
     sha256 are the recorded ones (missing values FAIL);
   - **pause-detector**: `status.json` is at most two intervals old, is not a
     startup failure, has no undelivered alerts, and a `clear` in it is on a
     head no older than two intervals.
8. **On deploy day the author checks by hand that an alert arrives** in the
   aastar-monitor chat (DSR 2026-11-15: this is what covers the shared token
   file). Any message from this deployment counts. If none came, unload the
   detector (`launchctl bootout gui/$(id -u)/io.aastar.dvt-pause-detector`).
   Within 2 h 15 min the dead-man must send `DEAD-MAN: … no successful round`.
   Then load the detector again and wait for `rounds resumed`.

## Before rc.8

On Sepolia today (SP 5.4.2, 11-14) `pauseUnderstakedOperator` is **not
deployed**: its eth_call reverts with empty data. The detector therefore reports
every operator `unknown`, which is the fail-closed answer. A dry run with
meaningful answers needs the rc.8 code: the anvil end to end above, or SP's rc.8
fork.
