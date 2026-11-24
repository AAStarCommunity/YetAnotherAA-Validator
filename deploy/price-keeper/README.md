# Price keeper on the Mac Mini

DVT runs the SuperPaymaster price keeper on the Mac Mini (`ssh mac-mini`). It
keeps `cachedPrice` fresh on a SuperPaymaster proxy, and on a PaymasterV4 when
the deployment has one. The keeper code is `scripts/keeper.ts` in `aastar-sdk`;
this directory holds the launchd wrapper around it.

The wrapper runs one or more **entries**. An entry is one keeper process for one
deployment on one chain, configured by `entries/<entry>.env` (non-secret
settings only).

| Entry        | Chain                 | SuperPaymaster                                    | PaymasterV4   | Signer           | State                    |
| ------------ | --------------------- | ------------------------------------------------- | ------------- | ---------------- | ------------------------ |
| `op-sepolia` | OP Sepolia (11155420) | `0x3c73dd3c…a31e7` (rc.8, `SuperPaymaster-5.5.3`) | none          | `0xc2dF42…AeB1e` | running since 2026-11-24 |
| (Sepolia)    | Sepolia (11155111)    | `0x09DF0d2e…4DE9`                                 | `0x2118…a4B6` | `0xc2dF42…AeB1e` | **retired 2026-11-24**   |
| `op-mainnet` | OP mainnet (10)       | not deployed yet                                  | —             | its own key      | planned                  |

## Layout on the Mini

| Item        | Path                                                                                                                       |
| ----------- | -------------------------------------------------------------------------------------------------------------------------- |
| Keeper code | the `aastar-sdk` worktree named by `KEEPER_SDK_DIR` (`~/Dev/aastar/aastar-sdk-price-keeper-next`, detached at `dab087cc`)  |
| Entry dir   | `~/.config/aastar-price-keeper-<entry>/` (mode 700): `entry.env`, `run.sh`, `stale-watch.sh`, `status.mjs`, `stale-watch/` |
| Secrets     | in the entry dir, mode 600: `rpc.env` (`RPC_URL`), `key.env` (`KEEPER_PRIVATE_KEY`), `telegram.env` (optional)             |
| Signer      | `address` in the entry dir: the key's public address on one line                                                           |
| Control     | `~/.config/aastar-price-keeper-bin/keeperctl.sh`, shared by all entries                                                    |
| Jobs        | `io.aastar.price-keeper-<entry>` (keeper, `KeepAlive`) and `io.aastar.price-keeper-<entry>-stale-watch` (every 600 s)      |
| Logs        | `~/Library/Logs/aastar-price-keeper-<entry>.log` and `…-<entry>-stale-watch.log`                                           |

## What `run.sh` checks before it starts the keeper

`run.sh` sources no file. It reads `entry.env`, `rpc.env`, `key.env` and
`telegram.env` as data, each for its own fields only, and starts the keeper with
`PATH`, `HOME` and the credential fields alone. It refuses to start (exit 78)
when:

- a file holds an unknown name, a field twice, a byte outside printable ASCII,
  or a value with a quote, `$`, backtick, backslash, space or shell
  metacharacter (a value may be wholly in double quotes);
- `KEEPER_ENTRY` does not name its directory, or is a reserved name (`bin`,
  `list`, `*-stale-watch`);
- the SuperPaymaster or PaymasterV4 address is malformed, there is no
  `KEEPER_HARD_MAX_FEE_GWEI` or `KEEPER_MIN_BALANCE_WEI`, or `KEEPER_SDK_DIR` is
  not `~/Dev/aastar/aastar-sdk<suffix>`;
- an argument other than `--once` or `--dry-run` is passed;
- the SDK dir holds a `.env.<network>`, which `keeper.ts` would read;
- the key is not `0x` and 64 hex digits, or does not sign as the `address` file;
- a mainnet entry's `key.env` is a link.

An empty `KEEPER_PAYMASTER` passes `--no-paymaster` explicitly. Leaving
`--paymaster` out instead would make `keeper.ts` fall back to the SDK's
canonical PaymasterV4 for the chain, which on OP Sepolia belongs to an abandoned
deployment (`0xf250416C…80ea`).

## Operate it

`keeperctl.sh` runs on the Mini; from any other machine with the `mac-mini` SSH
alias it re-runs itself there.

```bash
deploy/price-keeper/keeperctl.sh list
deploy/price-keeper/keeperctl.sh op-sepolia status    # see the exit codes below
deploy/price-keeper/keeperctl.sh op-sepolia pause     # before a collection window
deploy/price-keeper/keeperctl.sh op-sepolia resume
deploy/price-keeper/keeperctl.sh op-sepolia restart   # only while loaded
deploy/price-keeper/keeperctl.sh op-sepolia logs 100
deploy/price-keeper/keeperctl.sh op-sepolia dry-run   # one tick, sends nothing
```

- **pause** disables both jobs and confirms launchd lists both as disabled, then
  boots them out, then waits until no keeper process of the entry is left (by
  the job's process group and by the entry's keeper command line). It prints
  `PAUSED` (exit 0) only when all of that is confirmed; anything else is
  `NOT PAUSED` (exit 1). Disabled first, so neither `KeepAlive`, a reboot nor a
  stray `bootstrap` can start a new keeper. The stale-watch is paused too.
- **resume** checks both plists, enables and bootstraps both jobs, and prints
  `RESUMED` only when the keeper runs `scripts/keeper.ts` with its worker and is
  still the same process, not restarted, 10 s later. A setup `run.sh` refuses is
  `NOT RESUMED`.
- pause, resume and `install.sh` of an entry share a lock; a second one
  exits 75.
- An in-window price update aborts SP's collector: pause before the window,
  check for `PAUSED`, and check that the signer's nonce stops moving. After a
  resume the first update is immediate only if the cache is older than 3600 s.
- Only the time rule sends (cache age ≥ 3600 s and a newer Chainlink round),
  about 24 a day; a volatility move only alerts.

Judge health from the `status` exit code, not from `state = running`. A previous
keeper stayed running for weeks while every RPC call returned 403.

| Exit code | Meaning                                                                                                                                                          |
| --------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0         | Every cache the entry updates is fresh and the signer holds at least `KEEPER_MIN_BALANCE_WEI`                                                                    |
| 1         | A cache is stale or the balance is below that floor                                                                                                              |
| 2         | Undetermined: a setup `run.sh` would refuse, a key that does not sign as `address`, an RPC on another chain or with a head more than 300 s old, or a failed call |

## External stale check

`io.aastar.price-keeper-<entry>-stale-watch` runs `stale-watch.sh` every 600 s
and at load. It runs the entry's `status.mjs` and sends Telegram messages
through the same bot and chat as the keeper, from a separate process, so it
still alerts when the keeper is stuck. Every message is tagged
`[price-keeper <entry>]`, and `telegram.env` is read as data by `run.sh`'s rules
(a malformed line means no alert, and the log says why).

| `status` exit | What `stale-watch` sends                                                                      |
| ------------- | --------------------------------------------------------------------------------------------- |
| 0             | `RECOVERED`, once, if an alert was outstanding                                                |
| 1             | `ALERT` with the `STALE` / `LOW_GAS` lines, at most hourly, and at once when a new item fails |
| 2             | `UNDETERMINED` after 3 checks in a row, at most hourly                                        |

"A new item" means one that was not in the last delivered alert. While the set
of failing items only shrinks, the stored set keeps the old items, so an item
that flaps back waits for the hourly repeat (`REALERT_SECONDS`). This keeps a
value hovering at its threshold, such as the balance near its floor, from
alerting on every run. `stale-watch/last-run` holds the time and exit code of
the last check; `stale-watch.sh --test` sends one TEST message.

## Install or update an entry

On the Mini, from a checkout of this repository:

```bash
bash deploy/price-keeper/install.sh op-sepolia
# first install only: create rpc.env, key.env, address (and telegram.env) in the entry dir, mode 600
bash ~/.config/aastar-price-keeper-bin/keeperctl.sh op-sepolia dry-run
bash ~/.config/aastar-price-keeper-bin/keeperctl.sh op-sepolia resume
```

- A **first install** disables both jobs before their plists exist, so nothing
  starts, even at a reboot, until `resume`.
- An **update** of a loaded entry changes no launchd state; new scripts take
  effect at the next pause + resume. A change to `entries/<entry>.env` is
  refused (exit 3) while the entry is loaded: pause, install, resume.
- Everything is staged and published by rename; a failure puts the previous
  files back (exit 1), and a rollback that cannot complete exits 2 and names the
  files. Replaced files are also kept in `backup-<time>/`.
- It never creates, reads or prints a secret; it exits 2 while `rpc.env`,
  `key.env` or `address` is missing, and warns when a secret's mode is not 600.

The keeper worktree: `git -C ~/Dev/aastar/aastar-sdk worktree add --detach
<dir> <sdk-commit>`, then in it `pnpm install --frozen-lockfile
--config.strictDepBuilds=false` and `git checkout -- pnpm-lock.yaml`. Change an
entry's SDK commit or addresses by PR to `entries/<entry>.env`, then pause,
install, dry-run, resume.

## Adding the OP mainnet entry

Add `entries/op-mainnet.env` by PR once the deployment exists: the
SuperPaymaster address read back from the chain (`version()`, `REGISTRY()`),
`KEEPER_PAYMASTER` empty unless that deployment has a V4, a
`KEEPER_HARD_MAX_FEE_GWEI` sized for OP mainnet, and a `KEEPER_MIN_BALANCE_WEI`
covering several days of updates. Then:

- **Its own key**, generated on the Mini for this entry only, never `0xc2dF…`
  and never a link to another entry's `key.env` (`run.sh` and `status.mjs`
  refuse a linked key on a mainnet entry). The key is the author's decision; the
  signer must hold no other role.
- **A dedicated RPC** in its `rpc.env`, not a public gateway.
- Install, dry-run, and resume only after the author's go.

## Tests

macOS only (launchd, `plutil`, BSD `stat`); not in CI, which runs on Ubuntu.

```bash
bash deploy/price-keeper/test_run.sh           # run.sh, stub tsx and viem
bash deploy/price-keeper/test_stale_watch.sh   # stale-watch.sh and status.mjs, stub curl and viem
bash deploy/price-keeper/test_install.sh       # install.sh, stub launchctl
bash deploy/price-keeper/test_keeperctl.sh     # keeperctl.sh on real launchd, throwaway jobs
```

## Limits

- Telegram alerts go through `@AAstarMonitorBot`. The keeper's own alerts stop
  when the keeper dies; `stale-watch` covers that, but a dead Mini sends
  nothing.
- `run.sh` sets the Chainlink stale alert to 4200 s; the SDK default of 600 s
  alerted about every 12 minutes on Sepolia.
- Do not run a second keeper for the same entry anywhere else: two keepers spend
  gas on the same updates.

## The retired Sepolia keeper (2026-11-24)

By the author's decision only the OP Sepolia keeper is served. The Sepolia
keeper (`io.aastar.price-keeper`, `~/.config/aastar-price-keeper/`) was stopped
with bootout + disable on 2026-11-24, and the pause-job preflight forbids its
label. Its last updates were
`0x594b95fafff4f493a4009553372511ecfeb922709852f0d9f7a4e0cdea9b6215`
(SuperPaymaster `0x09DF0d2e…4DE9`, block 12201638, 09:07:36Z) and
`0x44ca857524653bb0a8dadd144afd3277643f3b821718c825a1f5c13c6f519826`
(PaymasterV4 `0x2118…a4B6`, block 12201639, 09:08:00Z). Its log file
`~/Library/Logs/aastar-price-keeper.log` had been deleted while the process
still held it open, so its last weeks of log are lost.

### Migration of the running `op-sepolia` entry (once)

The entry was staged by hand on 2026-11-24, before this layout existed: its own
`run.sh`, `status.mjs`, `stale-watch.sh` and `keeperctl-op-sepolia.sh`, with
`key.env` and `telegram.env` as links into the retired Sepolia directory.
Outside a collection window, with DSR told first:

```bash
bash ~/.config/aastar-price-keeper-op-sepolia/keeperctl-op-sepolia.sh pause   # the staged controller
bash deploy/price-keeper/install.sh op-sepolia                               # backs up the staged files
D=~/.config/aastar-price-keeper-op-sepolia; O=~/.config/aastar-price-keeper
for f in key.env telegram.env; do [ -L "$D/$f" ] && rm "$D/$f" && mv "$O/$f" "$D/$f"; done
rm "$D/keeperctl-op-sepolia.sh"
bash ~/.config/aastar-price-keeper-bin/keeperctl.sh op-sepolia dry-run
bash ~/.config/aastar-price-keeper-bin/keeperctl.sh op-sepolia resume
bash ~/.config/aastar-price-keeper-bin/keeperctl.sh op-sepolia status        # exit 0
```

Then move the retired Sepolia plists out of `~/Library/LaunchAgents` into
`~/.config/aastar-price-keeper/retired-<date>/`, and keep that directory.
