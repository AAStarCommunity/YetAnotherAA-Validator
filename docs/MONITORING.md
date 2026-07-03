# Operator monitoring → aastar-monitor (push)

The DVT pushes **operator** alerts (node/relay/keeper failures) to the
**aastar-monitor** Telegram bot. This is distinct from `NOTIFY_*`, which alerts
**end users** about large spends on their account.

Delivery is **fire-and-forget** — a monitoring outage never blocks signing or
relaying. Alerts are opt-in and a no-op until a destination URL is configured.

## Enable

```bash
OPS_ALERT_ENABLED=true
AASTAR_MONITOR_URL=https://<aastar-monitor>/ingest   # the bot's webhook
AASTAR_MONITOR_TOKEN=<optional bearer token>         # if the webhook requires auth
OPS_ALERT_NODE=dvt1                                  # label for which node alerted
```

## Wire contract (align the bot to this)

Each alert is a single `POST` to `AASTAR_MONITOR_URL`:

```
POST <AASTAR_MONITOR_URL>
Content-Type: application/json
Authorization: Bearer <AASTAR_MONITOR_TOKEN>   # only if a token is set

{
  "node": "dvt1",           // OPS_ALERT_NODE
  "level": "critical",      // "info" | "warn" | "critical"
  "message": "keeper updatePrice failed for 0x…: <reason>",
  "timestamp": "2026-07-03T15:00:00.000Z"   // ISO-8601
}
```

The bot should treat a 2xx as accepted; the DVT logs+swallows any non-2xx.

## What currently alerts

| Source | Level    | When                                 |
| ------ | -------- | ------------------------------------ |
| Keeper | critical | `updatePrice()` reverted / tx failed |
| Relay  | critical | gasless submit failed                |

## Planned (follow-ups, issue #100)

- Hot-wallet **balance watch** (relay/keeper EOAs below a threshold → `warn`)
- Node **health** self-report (startup, shutdown, repeated tick errors)
- De-dup / rate-limit identical alerts so a flapping failure doesn't spam the
  channel
