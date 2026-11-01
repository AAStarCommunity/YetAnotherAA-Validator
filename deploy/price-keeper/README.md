# Price keeper on the Mac Mini

DVT runs the SuperPaymaster price keeper on the Mac Mini (`ssh mac-mini`). It
keeps `cachedPrice` fresh on the SuperPaymaster proxy and on PaymasterV4
`0x2118…a4B6`, which are the two contracts the previous keeper served.

| Item        | Value                                                                                                         |
| ----------- | ------------------------------------------------------------------------------------------------------------- |
| Keeper code | `aastar-sdk` detached worktree at `~/Dev/aastar/aastar-sdk-price-keeper`                                      |
| Signer      | Dedicated EOA `0xc2dF42897a186e268ee4f1F4aB041DD6557AeB1e`; the key was generated on the Mini and stays there |
| Config      | `~/.config/aastar-price-keeper/` (`rpc.env`, `key.env` and `telegram.env`, mode 600)                          |
| Service     | LaunchAgent `io.aastar.price-keeper`, with `RunAtLoad` and `KeepAlive`                                        |
| Log         | `~/Library/Logs/aastar-price-keeper.log` on the Mini                                                          |

## First install on a Mac

Run these on the machine that will host the keeper. `aastar-sdk` must already be
cloned at `~/Dev/aastar/aastar-sdk`. The plist hardcodes `/Users/jason`, and
`keeperctl.sh` identifies the Mini by its `LocalHostName`, so change both on any
other machine.

```bash
git -C ~/Dev/aastar/aastar-sdk worktree add --detach ~/Dev/aastar/aastar-sdk-price-keeper <sdk-commit>
cd ~/Dev/aastar/aastar-sdk-price-keeper
pnpm install --frozen-lockfile --config.strictDepBuilds=false
git checkout -- pnpm-lock.yaml

mkdir -p ~/.config/aastar-price-keeper && chmod 700 ~/.config/aastar-price-keeper
cd <this repo>/deploy/price-keeper
cp run.sh keeperctl.sh status.mjs ~/.config/aastar-price-keeper/
cp io.aastar.price-keeper.plist ~/Library/LaunchAgents/
```

Create these files in `~/.config/aastar-price-keeper/`. Set mode 600 on the
three `.env` files.

| File           | Contents                                                                | Required                           |
| -------------- | ----------------------------------------------------------------------- | ---------------------------------- |
| `rpc.env`      | `RPC_URL=<Sepolia RPC URL>`                                             | Yes                                |
| `key.env`      | `KEEPER_PRIVATE_KEY=<new key generated on this machine>`                | Yes                                |
| `address`      | The public address of that key, on one line; `status` reads its balance | Yes                                |
| `telegram.env` | `TELEGRAM_BOT_TOKEN=<token>` and `TELEGRAM_CHAT_ID=<id>`                | No; without it there are no alerts |

Fund the address, then run `keeperctl.sh dry-run` and `keeperctl.sh start`.
Check that `keeperctl.sh status` exits 0.

## Operate it from any machine with the `mac-mini` SSH alias

```bash
deploy/price-keeper/keeperctl.sh status    # see the exit codes below
deploy/price-keeper/keeperctl.sh restart
deploy/price-keeper/keeperctl.sh logs 100
deploy/price-keeper/keeperctl.sh stop      # also disables it, so it stays off after a reboot
deploy/price-keeper/keeperctl.sh start
```

Judge health from the `status` exit code, not from `state = running`. The
previous keeper stayed running for weeks while every RPC call returned 403.

| Exit code | Meaning                                                                          |
| --------- | -------------------------------------------------------------------------------- |
| 0         | Both caches are fresh and the keeper has at least 0.01 ETH                       |
| 1         | A cache is stale or the balance is below 0.01 ETH                                |
| 2         | The check could not determine the state, for example because the RPC call failed |

Nothing runs `status` on a schedule yet, so someone has to run it by hand.

## Limits

- Telegram alerts go through `@AAstarMonitorBot`, configured in `telegram.env`
  (mode 600). They come from the keeper process, so a dead keeper or a dead Mini
  sends nothing; `status` is still the check for that.
- `status` warns below 0.01 ETH.
- `run-keeper.sh` in `aastar-sdk` bakes in SuperPaymaster 5.3.3, so `run.sh`
  passes the addresses explicitly.
- Do not re-enable `io.aastar.price-keeper` on the laptop: two keepers would
  spend gas on the same updates.

## After a new deployment

Move the worktree to the new SDK commit, run
`pnpm install --frozen-lockfile --config.strictDepBuilds=false`, restore
`pnpm-lock.yaml` if pnpm rewrote it, update the addresses in `run.sh`, run
`keeperctl.sh dry-run`, then `restart`.
