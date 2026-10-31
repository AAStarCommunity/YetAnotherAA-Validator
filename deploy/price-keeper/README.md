# Price keeper on the Mac Mini

DVT runs the SuperPaymaster price keeper on the Mac Mini (`ssh mac-mini`). It keeps `cachedPrice` fresh on the
SuperPaymaster proxy and on PaymasterV4 `0x2118…a4B6`, which are the two contracts the previous keeper served.

| Item | Value |
|---|---|
| Keeper code | `aastar-sdk` detached worktree at `~/Dev/aastar/aastar-sdk-price-keeper` |
| Signer | Dedicated EOA `0xc2dF42897a186e268ee4f1F4aB041DD6557AeB1e`; the key was generated on the Mini and stays there |
| Config | `~/.config/aastar-price-keeper/` (`rpc.env` and `key.env`, mode 600) |
| Service | LaunchAgent `io.aastar.price-keeper`, with `RunAtLoad` and `KeepAlive` |
| Log | `~/Library/Logs/aastar-price-keeper.log` on the Mini |

## Operate it from any machine with the `mac-mini` SSH alias

```bash
deploy/price-keeper/keeperctl.sh status    # exit 0 = caches fresh and gas sufficient
deploy/price-keeper/keeperctl.sh restart
deploy/price-keeper/keeperctl.sh logs 100
deploy/price-keeper/keeperctl.sh stop      # also disables it, so it stays off after a reboot
deploy/price-keeper/keeperctl.sh start
```

Judge health from the `status` exit code, not from `state = running`. The previous keeper stayed running for weeks
while every RPC call returned 403.

## Limits

- Telegram alerts are off because the old bot token returns `Unauthorized`. Nothing pushes an alert; someone has to
  run `status` or add a monitor.
- `status` warns below 0.01 ETH.
- `run-keeper.sh` in `aastar-sdk` bakes in SuperPaymaster 5.3.3, so `run.sh` passes the addresses explicitly.
- Do not re-enable `io.aastar.price-keeper` on the laptop: two keepers would spend gas on the same updates.

## After a new deployment

Move the worktree to the new SDK commit, run `pnpm install --frozen-lockfile --config.strictDepBuilds=false`, restore
`pnpm-lock.yaml` if pnpm rewrote it, update the addresses in `run.sh`, run `keeperctl.sh dry-run`, then `restart`.
