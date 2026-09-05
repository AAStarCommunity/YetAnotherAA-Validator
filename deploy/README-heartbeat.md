# Local heartbeat — the trigger that actually fires

## Why this exists

GitHub Actions `schedule` fires here **sparsely**, not never. Measured across
four repos in the same org:

| cron         | repo                | outcome                                                                                                           |
| ------------ | ------------------- | ----------------------------------------------------------------------------------------------------------------- |
| 15 min       | dvt                 | **3 scheduled runs TOTAL** in 20.9 h vs **84** slots = **3.6%**; the first came **7.4 h** after landing on master |
| 15 min       | airaccount-contract | fires, similarly sparse                                                                                           |
| daily `0 6`  | aastar-sdk          | **76 runs / 76 distinct days = 100% delivery**; median **2.1 h** late (p25 1.1, p75 2.9, **max 11.7**)            |
| daily `37 6` | SuperPaymaster      | fires, 5–8 h late                                                                                                 |

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
> **And the corollary, which the first version of this very file got wrong:** a
> handful of observations is not a distribution. That version said aastar-sdk
> was "consistently ~6 h late". The median is **2.1 h**; only 13% of runs were
> even 4 h late, and the spread runs 0.25–11.7 h — a ~47× range. "~6" is exactly
> the mean of the three most recent runs (5.8 / 4.8 / 5.9): a window smaller
> than the phenomenon, reported with a confidence word ("consistently") the
> sample cannot carry — the same shape as the error this file exists to retract,
> committed two paragraphs below the retraction. Caught by pr-daemon, which
> measured all 76.
>
> **The variance is the finding, not the delay.** `schedule` cannot be a
> deadline — not because it is reliably late by six hours, but because it is
> late by anywhere from 15 minutes to 12 hours with no way to know which in
> advance.
>
> **A window in which nothing happened is not a rate of zero.** Size the window
> to the expected time-to-first-event — for a new scheduled workflow that is >12
> hours, not 4.

## What is installed

Four launchd agents, sources version-controlled in `deploy/launchd/`:

| label                            | trigger                | does                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| -------------------------------- | ---------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `io.aastar.dvt-committee-health` | every 900 s            | `committee-health.mjs` against the router; opens/updates a GitHub issue on any non-zero exit                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| `io.aastar.dvt-apply-rotation`   | every 3600 s           | `apply-verifier-rotation.mjs --broadcast`. **Its rotation is done** — applied externally at 2026-09-04T05:37:12Z, not by this job — so runs from here do not broadcast: they check the active verifier against the address the job is pinned to, print "already applied" and exit 0. Green means the observed state matched that pin (it fails loudly on a disarm, a different verifier, or an unpinned new rotation); it does **not** mean this job applied anything. Repoint the expected verifier before the next rotation |
| `io.aastar.dvt-tunnel-keepalive` | every 300 s            | `tunnel-keepalive.sh`: probes the **public** `dvt{1,2,3}.aastar.io/health` and restarts the cloudflared container when they stop serving, then re-probes to confirm it worked. Refuses to restart while any node is unhealthy (exit 3) — compose destroys the tunnel _before_ checking `service_healthy`, so restarting there would turn a partial outage into a total one. Worth knowing: **one** unhealthy node blocks cloudflared from starting at all, so in that window the other two nodes have no public entry either  |
| `io.aastar.dvt-committee-keeper` | `KeepAlive` (resident) | keeps `committee-keeper.mjs --watch` alive; restarts it if it dies                                                                                                                                                                                                                                                                                                                                                                                                                                                            |

The first two run `deploy/local-heartbeat.sh`, which is **independent of
`committee-keeper.mjs`**. A monitor that dies with the process it watches is
silent in exactly the case it exists for.

### Why the third one exists

For most of this file's life there were two agents, and the thing they watched
had no supervisor at all — it was started by hand with `nohup`.

On 2026-09-04 that cost eleven hours. The keeper process died around 23:05 the
previous night and was still not running the next morning: **52 consecutive
epochs unpinned, committee `validate()` fail-closed for 53 of them** (it needs
both `e` and `e-1`), on the morning of the CC-115 B3 evidence run.

Nothing was broken except the absence of that agent. The health monitor worked
perfectly — it fired every 15 minutes and appended to issue #305 forty-five
consecutive times. The host was awake; the three DVT containers reported
`Up 2 days (healthy)` throughout. The outage was **fully observed and fully
unattended**, which is its own failure mode and not one this directory had a
name for: complete monitoring pointed at a process nothing would restart.

It is also a different failure from the eight misses before it. Those were host
sleep (clamshell on AC, maintenance sleep on battery — `caffeinate` covers
neither), each self-healing on wake within k≤3 epochs. A dead process does not
wake up with the laptop.

`KeepAlive`, not `StartInterval`: this one supervises a **resident** process
rather than running a job and exiting — which changes how you verify it, below.

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
for L in io.aastar.dvt-committee-health io.aastar.dvt-apply-rotation io.aastar.dvt-committee-keeper; do
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

The keeper agent is the exception, and reading it the same way would be a false
alarm: it has **no** interval, so `run interval` is correctly absent. Read
`state` and `pid`:

```bash
launchctl print gui/$(id -u)/io.aastar.dvt-committee-keeper | grep -E "state|pid|last exit"
#   state = running
#   pid = NNNNN
```

Then verify the RESTART, not the running — the outage above was not caused by
launchd failing to keep something alive, it was caused by nothing being asked
to. So ask it, by killing the process and watching it come back:

```bash
PID=$(launchctl print gui/$(id -u)/io.aastar.dvt-committee-keeper | awk '/^\tpid = /{print $3}')
kill -9 "$PID"
sleep 35 && launchctl print gui/$(id -u)/io.aastar.dvt-committee-keeper | grep pid   # a DIFFERENT pid
```

Done on install: pid 51320 killed with `-9`, relaunched as 52488 after ~20 s.

And do not stop at "launchd says running" — that was never the failing question.
Ask the chain:

```bash
node scripts/check-pin-rate.mjs --blocks 600    # recent epochs, misses grouped into runs
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
- `apply` before readyAt → exit 0, countdown printed, **no transaction**;
- `apply` after the rotation was consumed → exit 0, "already applied", **no
  transaction** (observed from 2026-09-04T06:11Z onward).

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
