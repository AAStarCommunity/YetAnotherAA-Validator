#!/usr/bin/env bash
# CI's npm audit gate, one mode per call (DSR 2026-11-18):
#   prod  `npm audit --omit=dev`, STRICT: no exception applies. It proves, mechanically, that an
#         excepted advisory is not in a runtime dependency.
#   full  every dependency; the GHSA ids listed in scripts/ci/audit-exceptions.json are excepted
#         until their date, and an expired entry fails by itself.
# Fetching (below) and deciding (scripts/ci/audit-decide.mjs, cells in check-audit-decide.mjs) are
# separate. The fetch keeps the rule in .github/workflows/ci.yml: a registry outage passes, loudly;
# advisory DATA never fails open.
mode="${1:?usage: npm-audit.sh prod|full}"
case "$mode" in
  prod) args="--omit=dev" ;;
  full) args="" ;;
  *) echo "usage: npm-audit.sh prod|full" >&2; exit 2 ;;
esac
set -uo pipefail
here="$(dirname "$0")"
# an exception's date is checked BEFORE anything is fetched, so a registry outage cannot outlive it
if [ "$mode" = full ]; then
  node "$here/audit-decide.mjs" --mode expiry || exit 1
fi
for attempt in 1 2 3; do
  # THE PER-ATTEMPT TIMEOUT AND THE JOB TIMEOUT ARE ONE BUDGET, and the first version of
  # this step blew it: `npm ci` takes ~5.5 min of the job's 10, and 3 x 120s + 45s of
  # backoff needs 6.75 more. Attempt 3 was killed by `timeout-minutes` and the job went red
  # with "The operation was canceled" — the retry logic working exactly as written, and the
  # check still failing for an infrastructure reason, which is the thing this step exists to
  # stop. 45s is generous for an endpoint that is up; one that is down does not get better
  # at 120. Worst case is now 45+10+45+20+45 = 165s, and the job has room to spare.
  out=$(timeout 45 npm audit $args --audit-level=high --json 2>/dev/null)
  status=$?
  # Empty output is an outage ONLY with timeout's own exit status, 124: the endpoint hung (Codex
  # pre-PR r4). Empty output with any other status (npm missing 126/127, an abort 134, a kill 137,
  # a 0 or 1 that printed nothing) is a broken job, not evidence of an outage, and fails.
  if [ -z "$out" ] && [ "$status" -ne 124 ]; then
    echo "::error title=npm audit ($mode)::npm audit printed nothing and exited $status (not a timeout): a local failure, not a registry outage"
    exit 1
  fi
  # (History of the count check, which now lives in audit-decide.mjs and still holds:)
  # THE GUARD ASSERTS WHAT THE NEXT LINES CONSUME — the two numbers — not merely that their
  # parent object exists. `jq -e '.metadata.vulnerabilities'` is true for `{}`, and then
  # `null + null` is `null`, `[ "null" -gt 0 ]` errors to stderr and lands in the else
  # branch, and the step prints "no high or critical advisories": the exact sentence this
  # whole change exists to stop it from saying when it has not checked. Found by @clestons
  # constructing the input rather than reading the code.
  #
  # Deliberately NOT `// 0`, which was independently suggested: defaulting a missing count to
  # zero translates "I did not find out" into "there are none", which is the same defect
  # wearing a shorter diff.
  # WHAT COUNTS AS "NO DATA" (Codex pre-PR review, r2): only empty output after a timeout (124,
  # above), or npm's own error envelope -- an object with nothing but `error` (and `message`)
  # whose error.code is a registry or transport failure -- is retried and, after three attempts,
  # passed as an outage. ANY other output is data and goes to audit-decide.mjs, which fails what
  # it cannot read: a malformed report, a report carrying an `error` key, or a local failure such
  # as ENOLOCK is never an outage. Without jq nothing matches, so output is treated as data.
  # `-s`: the output must be exactly ONE JSON value (Codex pre-PR r3): jq judges each value of a
  # stream, so a report followed by an outage envelope would otherwise read as an outage.
  if [ -n "$out" ] && ! printf '%s' "$out" | jq -se 'length == 1 and (.[0] |
      type == "object" and ((keys - ["error", "message"]) == [])
      and (.error | type == "object") and (.error.code | type == "string")
      and (.error.code | test("^(ENOAUDIT|E429|E5[0-9][0-9]|ECONNRESET|ECONNREFUSED|ETIMEDOUT|ENOTFOUND|EAI_AGAIN|EPIPE|ERR_SOCKET_TIMEOUT)$")))
    ' >/dev/null 2>&1; then
    break
  fi
  out=""
  # The message and the sleep are behind the SAME condition. They were not: the echo sat
  # outside the guard, so the third attempt printed "retrying in 30s" and then neither
  # slept nor retried. Caught in this step's own first live run — a log line stating
  # something that did not happen, which is the exact class of defect this step exists to
  # remove from CI. There is no fourth attempt to wait for, and every real outage was
  # paying for that sleep anyway.
  if [ "$attempt" -lt 3 ]; then
    echo "npm audit attempt $attempt did not return advisory data; retrying in $((attempt * 10))s"
    sleep $((attempt * 10))
  else
    echo "npm audit attempt $attempt did not return advisory data; no attempts left"
  fi
done

if [ -z "$out" ]; then
  echo "::warning title=npm audit could not run::The registry did not return advisory data after 3 attempts. This step ($mode) PASSED WITHOUT CHECKING npm advisories — it is not a statement that there are none. Trivy, CodeQL and Dependency Review still ran."
  exit 0
fi

printf '%s' "$out" | node "$here/audit-decide.mjs" --mode "$mode"
