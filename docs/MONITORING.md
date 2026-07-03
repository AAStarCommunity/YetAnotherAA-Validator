# Operator monitoring → aastar-monitor (push)

The DVT pushes **operator** alerts (node/relay/keeper failures) to the
**aastar-monitor** Telegram bot. This is distinct from `NOTIFY_*`, which alerts
**end users** about large spends on their account.

Delivery is **fire-and-forget** — a monitoring outage never blocks signing or
relaying. Alerts are opt-in and a no-op until a transport is configured.

## Enable (transport A — native Telegram bot, recommended)

Send straight to the aastar-monitor bot's chat. Get the bot token from
BotFather; the chat id is your user id (DM the bot **/start** first, or use a
group's id).

```bash
OPS_ALERT_ENABLED=true
OPS_ALERT_BOT_TOKEN=<AAstarMonitorBot token>   # keep in a git-ignored .env only
OPS_ALERT_CHAT_ID=<your telegram id or group id>
OPS_ALERT_NODE=dvt1                            # label for which node alerted
OPS_STATUS_INTERVAL_MS=21600000                # optional heartbeat (0/unset = off; 6h here)
```

> The bot can only DM a user who has messaged it first — send `/start` to the
> bot once. **Never commit the token**; treat a leaked token as compromised
> (BotFather `/revoke` mints a new one).

Telegram messages look like:
`🔴 [dvt1] keeper updatePrice failed for 0x…: <reason>` (🟢 info · 🟠 warn · 🔴
critical).

## Enable (transport B — generic webhook)

If you front delivery with your own aggregator instead of the raw bot:

```bash
OPS_ALERT_ENABLED=true
AASTAR_MONITOR_URL=https://<aggregator>/ingest
AASTAR_MONITOR_TOKEN=<optional bearer token>
```

Webhook payload (the DVT treats a 2xx as accepted):

```
POST <AASTAR_MONITOR_URL>   (Authorization: Bearer <token> if set)
{ "node":"dvt1", "level":"critical", "message":"…", "timestamp":"ISO-8601" }
```

Telegram takes priority when both transports are configured.

## What currently pushes

| Source | Level    | When                                     |
| ------ | -------- | ---------------------------------------- |
| Keeper | critical | `updatePrice()` reverted / tx failed     |
| Relay  | critical | gasless submit failed                    |
| Status | info     | boot ("🟢 online"), then every heartbeat |

The heartbeat summary reports version, uptime, RPC reachability, and enabled
capabilities — a recurring "still alive + health check" the operator asked for.

## Planned (follow-ups, issue #100)

- Hot-wallet **balance watch** (relay/keeper EOAs below a threshold → `warn`)
- Node **health** self-report (startup, shutdown, repeated tick errors)
- De-dup / rate-limit identical alerts so a flapping failure doesn't spam the
  channel
