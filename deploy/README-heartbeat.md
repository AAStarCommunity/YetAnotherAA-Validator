# Local heartbeat — the trigger that actually fires

## Why this exists

GitHub Actions `schedule` **does not run in this repository.** Measured, not
assumed:

| cron                 | repo                | window     | expected ticks | scheduled runs |
| -------------------- | ------------------- | ---------- | -------------- | -------------- |
| `*/15 * * * *`       | dvt                 | 53 min     | 4              | **0**          |
| `7,22,37,52 * * * *` | dvt                 | 6 h 33 min | 26             | **0**          |
| `7,22,37,52 * * * *` | airaccount-contract | 83 min     | 5              | **0**          |

Everything else checked out, so this is not a configuration problem:

- the `on:` block parses to a valid schedule (checked by parsing, not by eye);
- the API reports `state=active`;
- the repo is neither archived nor disabled, and `pushed_at` shows pushes
  throughout the window, so it is not the 60-day inactivity auto-disable;
- `workflow_dispatch` on the same workflow is green.

The job **can** run. Nothing presses it.

Offsetting the cron minutes is **not** the fix. That claim originated here,
extrapolated from the 53-minute `*/15` observation and stated to
airaccount-contract as fact rather than as inference; it then propagated into
that repo's comments. Both repos have since measured offset crons at zero and
corrected the text. Recorded because the failure was in how an inference was
transmitted, not in the measurement.

The consequence worth naming: for as long as this went unnoticed, "monitoring is
switched to the v0.33.0 router" was an **empty claim**. The workflow existed,
the checker was correct and tested, and nothing ever ran it. A monitor's
capability and a monitor's trigger are separate things, and only one of them was
ever verified.

## What is installed

Two launchd agents, sources version-controlled in `deploy/launchd/`:

| label                            | interval | does                                                                                                 |
| -------------------------------- | -------- | ---------------------------------------------------------------------------------------------------- |
| `io.aastar.dvt-committee-health` | 900 s    | `committee-health.mjs` against the router; opens/updates a GitHub issue on any non-zero exit         |
| `io.aastar.dvt-apply-rotation`   | 3600 s   | `apply-verifier-rotation.mjs --broadcast`; a no-op that exits 0 until readyAt (2026-09-04T05:36:24Z) |

Both run `deploy/local-heartbeat.sh`, which is **independent of
`committee-keeper.mjs`**. A monitor that dies with the process it watches is
silent in exactly the case it exists for.

The Actions workflows stay installed as redundancy — they cost nothing and might
fire. They are not the guarantee.

### The failure modes are different, which is the point

`launchd` stops when the laptop is off, and that is **knowable**. The Actions
path's alerting also runs inside Actions, so if Actions has a problem, "nobody
pressed the button" and "the button was pressed but the alert could not be sent"
look identical from outside. Two monitors with the same failure mode are one
monitor.

## Install

```bash
# .run MUST exist first: launchd opens StandardOutPath/StandardErrorPath BEFORE the wrapper runs, so
# its own `mkdir -p` is too late and a clean checkout can fail to start at all.
install -d -m 700 deploy/.run

cp deploy/launchd/io.aastar.dvt-*.plist ~/Library/LaunchAgents/
for L in io.aastar.dvt-committee-health io.aastar.dvt-apply-rotation; do
  launchctl bootout    gui/$(id -u)/$L 2>/dev/null
  launchctl bootstrap  gui/$(id -u) ~/Library/LaunchAgents/$L.plist
done
```

## Verify — and do NOT use `plutil -lint` for this

`plutil -lint` answers "is this valid XML plist", which is not the question.
`io.aastar.dvt-testnet.plist` on this machine passes `-lint` while its
`StartInterval` sits **inside** `<EnvironmentVariables>`, where launchd never
sees it — so the 120-second self-heal its own comment promises has never once
happened. Ask **launchd** what it registered:

```bash
launchctl print gui/$(id -u)/io.aastar.dvt-committee-health | grep -E "run interval|runs|last exit"
#   run interval = 900 seconds     <- the line that matters. Its ABSENCE is the bug above.
```

Then confirm the interval actually fires, rather than only `RunAtLoad`:

```bash
deploy/local-heartbeat.sh check     # ok / STALE / NEVER RAN, per job
```

`check` reads a timestamp each run stamps **before** doing any work, so it
answers "did the trigger fire" without depending on the work having succeeded —
and without depending on trusting this file.

## Exercised, not just written

Both alert paths were run deliberately, because an alert path that has never
fired is not delivered:

- fault injection (`COMMITTEE_ROUTER=0x…dEaD`) → issue opened, both labels
  attached;
- the same fault again → **comment appended to the same issue**, no second issue
  (dedup works);
- generation probe, both cells → new validator `d2`, old `0x1A8Db639` `pre-d2`
  (the probe moves in both directions and is not always-true);
- `apply` before readyAt → exit 0, countdown printed, **no transaction**.

Three real bugs were found by running it, none of which reading it would have
surfaced: the alert captured `gh`'s stderr into the issue URL, the labels the
dedup queries by were never created, and the first `apply` run inherited a
pre-#261 script that treated the countdown as a failure. Two throwaway issues
(#262, #263) were filed and closed in the process.

## Dedup spans both monitors

`alert()` deduplicates on **labels only**, deliberately not on author. The
workflow files as `github-actions[bot]` and a local run files as the human, so
an author filter would make the two monitors unable to see each other's issue
and each would open its own.

## Recovery closes the issue — the other half of dedup

A healthy run **closes** the issues it opened, with a comment naming the
recovery time.

This is not a nicety. Deduplicating means the EXISTENCE of an open issue stops
meaning "something is wrong now" and starts meaning "something was wrong once".
A long-lived open issue trains people to ignore the label, which is not
different from not alerting — the same alert fatigue, arriving from the other
end. With auto-close, the set of open `committee-health` issues stays equal to
the set of things failing right now.

**It can only close issues carrying this monitor's marker**, a hidden HTML
comment in the body:

```
<!-- committee-health-alert-v1:<category> -->
```

So an issue a human filed under the same label is never touched. Verified with a
control cell: a human-filed issue carrying both labels and no marker survived a
recovery run that closed the monitor's own issue in the same pass.

The marker convention is shared with airaccount-contract's monitor, so both
repos' alerts are recognisable by one rule.
