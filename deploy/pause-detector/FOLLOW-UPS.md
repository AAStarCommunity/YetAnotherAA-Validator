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

| Item                                                                                                    | Source                           | Status          |
| ------------------------------------------------------------------------------------------------------- | -------------------------------- | --------------- |
| A corrupt state time (or mismatch name) throws on every round and wedges the detector with no heartbeat | clestons #454 Low; Codex on #455 | #455, in review |

## After the deploy

| Item                                                                                                                                                                                                                                                                     | Source               | Why not in the gate                                                                                                                                                                                                                                                      |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `resolved: replay-overdue:*` / `resolved: reclassify` can be sent in the reclassify round itself, before it finished                                                                                                                                                     | clestons #454 Info 2 | Display only. The round is still `unknown` (`events`), and clear is unaffected                                                                                                                                                                                           |
| CI audit gate: recognise npm 10/11's real registry-failure output (`{message, error:{summary:"",detail:""}}`, plus `statusCode` etc. on a 5xx) as an outage, and feed the cells real captured npm output                                                                 | clestons #451 Medium | CI availability only. A real outage turns Security Audit red (fail-closed); no advisory passes                                                                                                                                                                           |
| CI audit gate: accept an advisory url only on `github.com/advisories/`. Today only its last path segment is read, so another host with the excepted id still matches (Codex reproduced `https://example.invalid/advisories/GHSA-fc5q-39xc-vjpf` passing for `picomatch`) | clestons #451 Low    | Not the detector. The url comes from npm's own audit report, and a wrong host can only relabel an advisory as the one exception already allowed (that GHSA id, in package `picomatch`). That needs the registry itself to misreport; no other advisory or package passes |
| CI audit gate: cap an exception's `expires` at about 45 days ahead                                                                                                                                                                                                       | clestons #451 Low    | A longer date still needs a reviewed diff to `scripts/ci/audit-exceptions.json`                                                                                                                                                                                          |
| CI audit gate: add cells for a high advisory with no GHSA id, and for a via chain naming a package the report lacks                                                                                                                                                      | clestons #451 Low    | Both paths already fail closed; this adds the cells only                                                                                                                                                                                                                 |
