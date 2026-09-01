# Local heartbeat — the trigger that actually fires

## Why this exists

GitHub Actions `schedule` fires here **sparsely**, not never. Measured across
four repos in the same org:

| cron         | repo                | outcome                                                                                     |
| ------------ | ------------------- | ------------------------------------------------------------------------------------------- |
| 15 min       | dvt                 | first run **7.4 h** after landing on master; then **3 runs / 20.9 h vs 83 expected = 3.6%** |
| 15 min       | airaccount-contract | fires, similarly sparse                                                                     |
| daily `0 6`  | aastar-sdk          | **76 runs over 75 days ≈ 100%**, consistently ~6 h late                                     |
| daily `37 6` | SuperPaymaster      | fires, 5–8 h late                                                                           |

**Daily schedules are delivered (hours late); sub-hourly ones are mostly
dropped; a newly added workflow does not fire for several hours.** None of the
documented causes apply — not archived or disabled, not a fork, file on the
default branch, `gh workflow list` and the API both reporting `state=active`.

**3.6% delivery cannot monitor a 12-minute outage.** That is the reason this
heartbeat exists.

> ### An earlier version of this file said `schedule` NEVER fires. That was wrong.
>
> It was measured over 6h33m — 26 expected ticks, 0 runs — and that window sat
> **entirely inside the registration delay**: first fire came at 11:10Z, **53
> minutes after the window closed**. airaccount-contract had proposed exactly
> that alternative and set a 4-hour disproof threshold; 4 hours was too short,
> and crossing it was treated as settling the question. aastar-sdk's
> counter-evidence — same org, same platform, 76/76 — is what forced the
> recheck.
>
> The claim that offsetting the cron minutes is a fix was also wrong, also mine,
> and was stated to a sibling repo as fact rather than inference; it reached
> that repo's committed comments.
>
> **A window in which nothing happened is not a rate of zero.** Size the window
> to the expected time-to-first-event — for a new scheduled workflow that is >12
> hours, not 4.

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
