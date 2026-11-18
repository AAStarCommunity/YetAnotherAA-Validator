# Pause detector: follow-ups

The rule (DSR 2026-11-18). A review finding left after #455 goes in one of two
places:

- **The deploy gate:** fixed before the Mini deploy. This covers anything that
  can produce a **silent clear**, or that can make the detector **stop**: wedge,
  stop writing its heartbeat, or stop alerting.
- **This list:** done after the deploy. Everything else: wording, observability
  improvements, argument-parsing edge cases, and availability-only effects that
  already alert.

On deploy day DSR checks that **the gate section is empty**. Classification is
DVT's; doubtful cases go to DSR.

## In the deploy gate (must be empty on deploy day)

**Empty** since #457 merged as `2ba173d8`.

**Done:**

- #457: a `replayNext` or `classifiedTo` beyond the finalized block could mark a
  replay done, or skip forward classification, without reading anything, and
  rounds read clear. A `crossCheck.coveredTo` beyond it made every later
  comparison incomplete. The state is now re-verified, or its coverage starts
  over. Source: clestons #455 Low 2, reproduced by a cell.
- #455, merged as `fca14290`: a corrupt state time or mismatch name threw on
  every round and wedged the detector (clestons #454 Low; Codex on #455). #455
  also handled #454's two other Infos: `chooseProvider` reads the clock once,
  and the fallback replay's overdue text says it advances only on fallback
  rounds.
- This PR: the test flake
  `#438: CONTROL a round with a fresh dead-man status.json raises no dead-man alert`
  (ENOENT on `state/status.json`). Running that cell alone 200 times reproduced
  it once (run 152). The detector exited 75 with
  `another run holds the lock (127.0.0.1:50625)`: the cell's random lock port,
  40000–60000, was held by another socket inside macOS's ephemeral range. The
  product writes `status.json` atomically (temp file, then rename), and the cell
  reads it only after the process exited, so no partial write can be seen.
  Fixed: cells take a port in 10000–32767, below both macOS's and Linux's
  default ephemeral ranges (CI runs on Ubuntu, 32768–60999), that is bindable
  just then. A run that still loses the lock (exit 75, a race with another
  process between the check and the bind) is retried on a fresh port, at most
  twice, and only when the cell confirms another socket holds that port after
  the detector exited. A lock loss nobody else caused fails the cell as a
  detector defect (Codex). 200 runs pass. And per DSR, preflight's
  `detector-lockport` now checks the deployed `lockPort` is outside the
  ephemeral range.

## After the deploy

| Item                                                                                                                                                                                                                                                                     | Source               | Why not in the gate                                                                                                                                                                                                                                                                                            |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| A `crossCheck.mismatch.height` beyond the finalized block makes every later cross-check refuse ("below the standing disagreement"), so rounds are `unknown` for good until a new `stateDir`                                                                              | clestons #457 Low 1  | Loud: unknown, alerting, heartbeat running. And a height above _this round's_ finalized is legitimate when a provider's finalized goes back (B1's case), so bounding it would reopen B1. A cell showed that (`B1: the primary briefly reports a lower finalized block …`), so the bound was tried and reverted |
| An `operators[op]` block beyond the finalized block shows that operator as a standing "only the fallback has" disagreement                                                                                                                                               | clestons #457 Low 2  | Loud, and the operator is still checked every round. A block above finalized is legitimate too (recent operators are stored up to B)                                                                                                                                                                           |
| Under Node 26 the heartbeat and dead-man cells report `startup: uncaught ERR_ACCESS_DENIED` (5 cells)                                                                                                                                                                    | clestons #457 Info 4 | The known permission-model difference (README, clestons #434 F6). The deploy runs the pinned Node 24.21.0 and CI runs Node 20                                                                                                                                                                                  |
| `isTime` checks a state time's range, not its unit, so a value in seconds passes. It never throws; at worst a time is shown wrong, or `replay-overdue` warns early                                                                                                       | clestons #455 Info 1 | Display and a warning only. Every writer stores `Date.now()` ms, so only a hand-edited state holds one                                                                                                                                                                                                         |
| `resolved: replay-overdue:*` / `resolved: reclassify` can be sent in the reclassify round itself, before it finished                                                                                                                                                     | clestons #454 Info 2 | Display only. The round is still `unknown` (`events`), and clear is unaffected                                                                                                                                                                                                                                 |
| CI audit gate: recognise npm 10/11's real registry-failure output (`{message, error:{summary:"",detail:""}}`, plus `statusCode` etc. on a 5xx) as an outage, and feed the cells real captured npm output                                                                 | clestons #451 Medium | CI availability only. A real outage turns Security Audit red (fail-closed); no advisory passes                                                                                                                                                                                                                 |
| CI audit gate: accept an advisory url only on `github.com/advisories/`. Today only its last path segment is read, so another host with the excepted id still matches (Codex reproduced `https://example.invalid/advisories/GHSA-fc5q-39xc-vjpf` passing for `picomatch`) | clestons #451 Low    | Not the detector. The url comes from npm's own audit report, and a wrong host can only relabel an advisory as the one exception already allowed (that GHSA id, in package `picomatch`). That needs the registry itself to misreport; no other advisory or package passes                                       |
| CI audit gate: cap an exception's `expires` at about 45 days ahead                                                                                                                                                                                                       | clestons #451 Low    | A longer date still needs a reviewed diff to `scripts/ci/audit-exceptions.json`                                                                                                                                                                                                                                |
| CI audit gate: add cells for a high advisory with no GHSA id, and for a via chain naming a package the report lacks                                                                                                                                                      | clestons #451 Low    | Both paths already fail closed; this adds the cells only                                                                                                                                                                                                                                                       |
| preflight `detector-lockport` reads only macOS's `net.inet.ip.portrange.*`. On Linux that read fails and the item FAILS (it assumes no range); a Linux preflight would need `net.ipv4.ip_local_port_range`                                                               | clestons #459 Low 2  | Fails closed, and the deploy target is the Mac Mini                                                                                                                                                                                                                                                            |
| The cells' lock-loss retry proves only that _some_ socket holds the port, not that it is unrelated to the detector: a second live detector instance would also count as "someone else"                                                                                   | clestons #459 Low 4  | Test harness only. The detector's own socket is released when it exits, so its own leftover cannot trigger it                                                                                                                                                                                                  |
| Two concurrent cells can still pick the same free port between the probe and the bind                                                                                                                                                                                    | clestons #459 Low 5  | That window is what the bounded retry covers; test harness only                                                                                                                                                                                                                                                |
