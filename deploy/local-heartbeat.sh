#!/bin/bash
# Local heartbeat for the committee stack -- the trigger that actually fires.
#
# WHY THIS EXISTS, measured -- and corrected after the first measurement was too short.
#
# GitHub Actions `schedule` DOES fire here -- sparsely. An earlier version of this text said it never
# does, measured over 6h33m with 26 expected ticks and 0 runs. That window sat ENTIRELY INSIDE a
# registration delay: the workflow landed on master at 03:44Z and first fired at 11:10Z, 53 minutes
# AFTER the window closed. Corrected measurements, four repos, same org:
#
#   15-min cron, dvt                  3 scheduled runs TOTAL in 20.9h vs 84 slots = 3.6%; the first of
#                                   those came 7.4h after the workflow landed on master
#   15-min cron, airaccount-contract  fires, similarly sparse
#   daily cron, aastar-sdk            76 runs / 76 distinct days = 100% delivery; median 2.1h late
#                                   (p25 1.1, p75 2.9, max 11.7 -- a ~47x spread, not a fixed offset)
#   daily cron, SuperPaymaster        fires, 5-8h late
#
# So: DAILY schedules are delivered (hours late); SUB-HOURLY ones are mostly dropped; and a newly
# added workflow does not fire for several hours. None of the documented causes applied -- not
# archived or disabled, not a fork, file on the default branch, `gh workflow list` and the API both
# reporting state=active.
#
# The local heartbeat is still the right primary trigger, but for the corrected reason: 3.6% delivery
# cannot monitor a 12-minute outage, NOT that nothing ever runs.
#
# The claim that offsetting the cron minutes is a fix was ALSO mine and also wrong; it was
# extrapolated from a 53-minute observation and stated to airaccount-contract as fact rather than
# inference, reaching that repo's committed comments before being checked.
#
# TWO PROPERTIES THIS FILE EXISTS TO HAVE, both learned the hard way today:
#
#   1. IT LEAVES EVIDENCE THAT IT RAN. Every invocation stamps $HEARTBEAT before doing anything
#      else. The entire failure above was invisible precisely because a trigger that never fires
#      and a monitor that always passes look identical from outside. `check` below reads that stamp
#      back, so the question "is the monitor alive" has an answer that does not depend on trusting
#      this comment.
#   2. IT IS INDEPENDENT OF THE KEEPER PROCESS. A monitor that dies with the thing it watches is
#      silent in exactly the case it exists for. Nothing here talks to committee-keeper.mjs; it
#      reads the chain.
#
# Install / verify: see deploy/README-heartbeat.md
#
# Usage:
#   local-heartbeat.sh health   run the committee health check; alert on non-zero
#   local-heartbeat.sh apply    apply the verifier rotation once its delay matures (no-op before)
#   local-heartbeat.sh check    report whether the heartbeats are recent (for a human, exits non-zero if stale)

set -uo pipefail   # NOT -e: a non-zero exit from the checker is the signal, not a crash.

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_DIR="$REPO_DIR/deploy/.run"
GH_REPO_SLUG="AAStarCommunity/YetAnotherAA-Validator"
umask 077          # the logs sit next to an env file full of keys; do not create them world-readable
mkdir -p "$RUN_DIR"

# launchd hands a process a minimal PATH that has neither node nor gh. Absolute-ish PATH, set here
# rather than only in the plist, so running this by hand and running it under launchd behave the same.
export PATH="/Users/jason/.nvm/versions/node/v22.22.2/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"

MODE="${1:-}"
HEARTBEAT="$RUN_DIR/heartbeat-${MODE}.txt"
LOG="$RUN_DIR/heartbeat-${MODE}.log"
ENV_FILE="${HEARTBEAT_ENV_FILE:-/Users/jason/Dev/aastar/SuperPaymaster/.env.sepolia}"
ROUTER="${COMMITTEE_ROUTER:-0xA97A752779ebfDA58612F6727Ec7C8366c39f897}"

stamp() { date -u +%Y-%m-%dT%H:%M:%SZ; }

# A HUNG CHILD IS THE WORST OUTCOME AVAILABLE HERE, worse than any wrong verdict: launchd will not
# start the next StartInterval while this one is still running, so a single stuck RPC read silently
# retires the monitor -- indefinitely, with no alert, which is precisely the "trigger stopped and
# nobody could tell" failure this whole file exists to answer. Neither node script has its own
# timeout and macOS has no coreutils `timeout` (verified in this repo: rc=127), so the watchdog is
# hand-rolled. Exit 124 matches coreutils' convention and is routed to its own alert category rather
# than folded into the checker's codes -- "it hung" and "it said the committee is down" call for
# different responses.
WATCHDOG_SECS="${HEARTBEAT_TIMEOUT:-300}"

# A SECOND, OUTER watchdog on the whole script, because run_bounded only covers the node children and
# they are not the only thing that can hang. `gh` makes network calls too -- resolve() alone can make
# several -- and a hung gh retires this monitor exactly as thoroughly as a hung RPC: launchd will not
# start the next interval while this process lives. Found by measuring, not by reading: with
# HEARTBEAT_TIMEOUT=3 a run still took 8 seconds, and the extra 5 were gh calls sitting outside the
# inner watchdog entirely.
#
# The outer bound is generous relative to the inner one; it is a backstop, not the primary control.
OUTER_SECS=$(( WATCHDOG_SECS * 2 + 120 ))
_tmpfiles=""
_cleanup() { [ -n "${_wd_pid:-}" ] && kill "$_wd_pid" 2>/dev/null; [ -n "$_tmpfiles" ] && rm -f $_tmpfiles; return 0; }
# TWO traps, not one: a handler that RETURNS makes the signal a no-op, so the TERM half must exit.
#
# BUT THE TERM IS STILL BEST-EFFORT, AND THE KILL IS THE ACTUAL BOUND. Measured, after the two-trap
# fix did NOT change the outcome: a run blocked in `sleep 30` still died at 9s with 137 (SIGKILL),
# not at 4s with 143. Bash DEFERS a trapped signal until the foreground external command it is
# waiting on returns -- so while this script sits inside a blocking `gh` call, the TERM is queued and
# cannot preempt it. run_bounded's own loop polls in 1s sleeps and can therefore honour a TERM
# promptly; a hung `gh` cannot. The kill -KILL five seconds later is what actually bounds the run,
# and the traps exist so the tidy path stays tidy, not because they are the guarantee.
#
# Recorded rather than quietly left: the previous version of this comment claimed the two-trap fix
# made TERM work. It did not, and the measurement that would have caught that is the same one that
# found the problem.
trap _cleanup EXIT
trap '_cleanup; exit 143' HUP INT TERM
( sleep "$OUTER_SECS"; kill -TERM "$$" 2>/dev/null; sleep 5; kill -KILL "$$" 2>/dev/null ) &
_wd_pid=$!
run_bounded() {
  local out_file rc pid waited
  out_file=$(mktemp) || { printf 'watchdog: mktemp failed'; return 125; }
  _tmpfiles="$_tmpfiles $out_file"
  ( "$@" ) >"$out_file" 2>&1 &
  pid=$!
  waited=0
  while kill -0 "$pid" 2>/dev/null; do
    if [ "$waited" -ge "$WATCHDOG_SECS" ]; then
      kill -TERM "$pid" 2>/dev/null
      sleep 2
      kill -KILL "$pid" 2>/dev/null
      wait "$pid" 2>/dev/null
      printf '%s' "$(cat "$out_file")
watchdog: killed after ${WATCHDOG_SECS}s -- the child never returned"
      rm -f "$out_file"
      return 124
    fi
    sleep 1
    waited=$((waited + 1))
  done
  wait "$pid"; rc=$?
  printf '%s' "$(cat "$out_file")"
  rm -f "$out_file"
  return "$rc"
}

# Shared with airaccount-contract's monitor so the two repos' alerts are recognisable by the same
# rule. It is also the SAFE-TO-CLOSE predicate below: only an issue carrying this marker was opened
# by a heartbeat, so auto-recovery can never close an issue a human filed under the same label.
MARKER_PREFIX="<!-- committee-health-alert-v1:"

log() { echo "[$(stamp)] $*" | tee -a "$LOG" >&2; }

# $out is pasted into a GitHub issue on a PUBLIC repository, and the scripts it wraps are handed
# --env pointing at a file that holds real private keys.
#
# THIS IS LOAD-BEARING, NOT BELT-AND-BRACES. An earlier version of this comment claimed ethers
# redacts a malformed privateKey in its own error. IT DOES NOT -- verified directly on the pinned
# ethers 6.17.0:
#     new ethers.Wallet("0x59c6…ZZ")
#     -> invalid BytesLike value (argument="value", value="0x59c6…ZZ", code=INVALID_ARGUMENT)
# The raw value is in the message. So a malformed key in the env file produces an ethers error
# CONTAINING THE KEY, which $out would carry straight into a world-readable issue. Redaction is the
# only thing standing between that and publication, which is why load_secrets() below must parse the
# env file exactly the way the Node scripts do -- a key it fails to recognise is a key it cannot
# remove.
#
# EXACT VALUES, NOT A SHAPE. The obvious implementation -- redact anything matching 64 hex digits --
# also redacts every TRANSACTION HASH, and a revert report without its tx hash is close to useless.
# Keys and hashes are syntactically identical, so no pattern can separate them. Reading the actual
# secrets out of the env file and replacing those exact strings has neither problem: it cannot hit a
# tx hash, and it catches a key however it happens to be formatted.
#
# Pure bash substitution, deliberately not sed: a secret passed as a sed argument is visible in the
# process table to every user on the machine for the life of the call.
declare -a SECRETS=()
trim() { local v="$1"; v="${v#"${v%%[![:space:]]*}"}"; v="${v%"${v##*[![:space:]]}"}"; printf '%s' "$v"; }
load_secrets() {
  [ -r "$ENV_FILE" ] || return 0
  local line name val
  while IFS= read -r line; do
    line=$(trim "$line")
    case "$line" in \#*|"") continue;; esac
    # PARSE PARITY WITH THE NODE SIDE, and the reason it matters is above: a form this misses but the
    # Node parser accepts is a secret that reaches a public issue. Spaces around `=` and quotes that
    # only appear after trimming are accepted there and were missed here.
    #
    # `export FOO=…` is handled too, but NOT for parity: the Node side parses that into the key
    # "export FOO", which nothing ever looks up, so such a line is never USED as a credential there.
    # Stripping it here is strictly-wider capture, which is the safe direction for a redactor. An
    # earlier version of this comment claimed the Node parser accepts `export`; it does not, and
    # asserting a false fact in support of a true conclusion is still a false fact.
    line="${line#export }"
    line=$(trim "$line")
    case "$line" in *=*) ;; *) continue;; esac
    name=$(trim "${line%%=*}")
    val=$(trim "${line#*=}")
    val="${val%\"}"; val="${val#\"}"; val="${val%\'}"; val="${val#\'}"
    val=$(trim "$val")
    [ "${#val}" -ge 16 ] || continue
    # SELECT BY NAME, not by length. Selecting every long value would redact CONTRACT ADDRESSES --
    # this env file holds several -- and an alert reading "validator [REDACTED] is failing" is worse
    # than no alert: it is an alert that withholds the one field you need. Names that denote a
    # credential, plus any URL carrying userinfo or a key-ish query parameter.
    case "$name" in
      *KEY*|*SECRET*|*PRIVATE*|*TOKEN*|*PASSWORD*|*PASSWD*|*MNEMONIC*|*SEED*)
        SECRETS+=("$val") ;;
      *)
        case "$val" in
          # A 32-byte hex value in an env file is a private key whatever it is named. Selecting by
          # SHAPE HERE is not the thing rejected above: that argument was against deleting by shape
          # from the OUTPUT, where 64 hex is indistinguishable from a transaction hash. Inside the
          # env file there are no transaction hashes, and contract addresses are 42 characters, not
          # 66 -- verified against the live file: 7 key-shaped values selected, all 20 addresses
          # untouched. Without this, coverage rests on ANOTHER repository's naming discipline: a
          # `SIGNER_A=0x…` added to SuperPaymaster tomorrow is simply not redacted, with no error and
          # no missing log line. Raised by pr-daemon.
          0x????????????????????????????????????????????????????????????????|\
          ????????????????????????????????????????????????????????????????)
            SECRETS+=("$val") ;;
          http*://*@*|http*://*/v2/*|http*://*/v3/*|*apikey=*|*api_key=*|*"?key="*|*"&key="*)
            SECRETS+=("$val") ;;
        esac ;;
    esac
  done < "$ENV_FILE"
}
# GitHub rejects an oversized body outright, which loses the WHOLE alert -- the loudest possible
# failure turning silent. And a ``` inside the captured output closes the fence early, after which
# the rest renders as markdown: an @-string becomes a mention, HTML becomes markup. Bound it and
# neutralise the fence.
MAX_BODY=6000
safe_block() {
  local t="$1"
  t="${t//\`\`\`/[fence]}"
  if [ "${#t}" -gt "$MAX_BODY" ]; then
    t="${t:0:$MAX_BODY}
[... truncated at ${MAX_BODY} chars; the full text is in deploy/.run/heartbeat-*.log on the monitor host]"
  fi
  printf '%s' "$t"
}

redact() {
  local text="$1" sec
  # ${arr[@]+"${arr[@]}"} , not "${arr[@]}". The shebang is /bin/bash and macOS ships bash 3.2, where
  # expanding an EMPTY array under `set -u` is an "unbound variable" error. SECRETS is empty whenever
  # the env file is unreadable -- and the failure was silent in the worst possible way: redact() died
  # inside a command substitution, $out became the EMPTY STRING, and the alert was filed anyway with
  # an empty diagnostic block. The issue looked completely normal and carried nothing. Observed, not
  # theorised: issue #270 was opened that way while testing an unreadable env path.
  for sec in ${SECRETS[@]+"${SECRETS[@]}"}; do
    text="${text//"$sec"/[REDACTED]}"
  done
  printf '%s' "$text"
}

# ONE gate, applied where $out is PRODUCED rather than where it is consumed. The previous version
# threaded safe_block through the alert call sites and reached exactly one of five -- and it was the
# 124 branch, whose $out is a short string the watchdog assembles itself. The four carrying the
# checker's raw output, which is the whole reason the gate exists, were bare. Part of that raw output
# is error text from a PUBLIC RPC NODE: not input this repo controls, on a path that publishes to a
# public repository. Caught by pr-daemon, who quoted this PR's own sentence back at me -- "a correct
# argument in the wrong place is harder to find than no argument at all" -- which is precisely the
# beforeWindow bug this same PR fixes, committed again two files away.
#
# Producing-side is the structural fix: a call site added later cannot forget it.
#
# ORDER IS LOad-BEARING: redact BEFORE truncate. Truncating first can cut a secret in half, and half
# a secret no longer matches the exact-value substitution, so it would survive into the issue.
sanitise() {
  local raw="$1" red
  red=$(redact "$raw")
  if [ -n "$raw" ] && [ -z "$red" ]; then
    log "redact() produced empty output from non-empty input -- publishing a placeholder, NOT the raw text"
    printf '%s' "(diagnostics withheld: redaction failed, and unredacted output must not be published to a public issue)"
    return
  fi
  safe_block "$red"
}

# One open issue per category, deduped on LABELS and deliberately NOT on author: the Actions
# workflow and this script are two monitors watching one stack, and they must find each other's
# issue rather than each opening its own. (The workflow filters on `github-actions[bot]`; a local
# run is authored by the human, so an author filter would defeat the dedup across the two.)
alert() {
  local catlabel="$1" title="$2" body="$3"
  body="${MARKER_PREFIX}${catlabel} -->
${body}"
  if ! command -v gh >/dev/null 2>&1; then
    log "ALERT (gh unavailable, not filed): $title"
    return
  fi
  # Ensure the labels EXIST before anything relies on them. `gh issue edit --add-label` fails on an
  # unknown label, and the dedup below queries BY label -- so a missing label silently degrades this
  # into "open a fresh issue every 15 minutes". Observed exactly that on the first two runs of this
  # script: the issues were filed, unlabelled, and would never have deduped. Idempotent; `|| true`
  # because "already exists" is the normal case.
  gh label create committee-health --repo "$GH_REPO_SLUG" \
     --description "Automated committee liveness alerts" --color B60205 >/dev/null 2>&1 || true
  gh label create "$catlabel" --repo "$GH_REPO_SLUG" \
     --description "Committee liveness alert category: $catlabel" --color D93F0B >/dev/null 2>&1 || true

  # `|| true` on the query would turn a FAILED query into "no issue exists", and the consequence is
  # not a missed comment -- it is a brand-new issue every run. Separate the two.
  local listing lrc existing=""
  listing=$(gh issue list --repo "$GH_REPO_SLUG" --state open \
              --label committee-health --label "$catlabel" \
              --json number -q '.[].number' 2>/dev/null); lrc=$?
  if [ "$lrc" -ne 0 ]; then
    log "dedup query FAILED (rc=$lrc) -- not creating an issue this run rather than risking a duplicate; will retry next tick"
    return
  fi
  # Require the marker here too, not only when closing. Without it a human-filed issue carrying the
  # same labels becomes the dedup target and silently suppresses every future alert in its category
  # -- which is the exact risk the workflow's author filter was written to avoid, solved properly.
  local n
  for n in $listing; do
    case "$n" in (*[!0-9]*|"") continue;; esac
    if gh issue view "$n" --repo "$GH_REPO_SLUG" --json body -q .body 2>/dev/null \
       | grep -qF "${MARKER_PREFIX}${catlabel} -->"; then existing="$n"; break; fi
  done
  if [ -n "$existing" ]; then
    printf '%s' "$body" | gh issue comment "$existing" --repo "$GH_REPO_SLUG" --body-file - >/dev/null 2>&1 \
      && log "appended to existing issue #$existing" \
      || log "FAILED to comment on #$existing"
    return
  fi
  # Create first, label second: `gh issue create --label` resolves every label BEFORE creating
  # anything, so one missing label would veto the whole alert.
  # NOT 2>&1. `gh` writes request tracing to stderr, and merging it into stdout puts those lines
  # into $url -- which is how the first run of this script filed a real issue, parsed the number out
  # of a debug line, and then failed to label it. Keep the streams apart: stdout is the URL, stderr
  # is diagnostics kept only for the failure message.
  local url num err
  err=$(mktemp) || { log "FAILED to create issue: mktemp failed"; return; }
  # Register with the GLOBAL cleanup rather than installing a local trap. Bash traps are process-wide:
  # a local `trap ... EXIT` here would REPLACE the outer watchdog's cleanup, and the `trap -` that
  # removed it would leave the script with no EXIT handler at all -- the outer watchdog process would
  # then outlive it. Registering is the only version that composes.
  _tmpfiles="$_tmpfiles $err"
  # --body-file - , not --body "$body". The body carries the checker's raw output, and redaction is
  # load-bearing rather than decorative (see above), so anything it missed would otherwise sit in the
  # PROCESS TABLE for every user on this machine for the life of the call. stdin never appears there.
  url=$(printf '%s' "$body" | gh issue create --repo "$GH_REPO_SLUG" --title "$title" --body-file - 2>"$err") || {
    log "FAILED to create issue: $(tail -3 "$err")"; rm -f "$err"; return; }
  rm -f "$err"
  url=$(echo "$url" | grep -oE 'https://github\.com/[^[:space:]]+/issues/[0-9]+' | tail -1)
  if [ -z "$url" ]; then log "issue created but its URL could not be parsed -- not labelling"; return; fi
  num="${url##*/}"
  # A number, or the label call silently edits nothing.
  case "$num" in (*[!0-9]*|"") log "parsed issue number '$num' is not numeric -- not labelling"; return;; esac
  if ! gh issue edit "$num" --repo "$GH_REPO_SLUG" \
        --add-label committee-health --add-label "$catlabel" >/dev/null 2>&1; then
    log "issue #$num created but labelling failed -- dedup is BROKEN, this will open a new issue every run"
    # Say it in the issue too. A log line on a laptop is not where anyone looks.
    gh issue comment "$num" --repo "$GH_REPO_SLUG" --body \
      "⚠️ This issue could not be labelled \`committee-health\`/\`$catlabel\`, so the heartbeat cannot dedup against it and will open a NEW issue on every failing run until that is fixed." >/dev/null 2>&1 || true
  fi
  log "opened issue $url"
}

# The other half of dedup, and the reason it is not optional. Deduplicating means the EXISTENCE of an
# open issue stops meaning "something is wrong now" and starts meaning "something was wrong once".
# A long-lived open issue trains people to ignore the label, which is not different from not alerting
# -- the same alert fatigue, arriving from the other end. So a healthy run closes what it fixed, and
# the open set stays equal to the current fault set.
#
# Closes ONLY issues carrying this monitor's marker, so a human-filed issue that happens to share the
# label is never touched.
resolve() {
  command -v gh >/dev/null 2>&1 || return 0
  local catlabel
  for catlabel in "$@"; do
    local nums
    nums=$(gh issue list --repo "$GH_REPO_SLUG" --state open \
             --label committee-health --label "$catlabel" \
             --json number -q '.[].number' 2>/dev/null || true)
    local n
    for n in $nums; do
      case "$n" in (*[!0-9]*|"") continue;; esac
      if ! gh issue view "$n" --repo "$GH_REPO_SLUG" --json body -q .body 2>/dev/null \
           | grep -qF "${MARKER_PREFIX}${catlabel} -->"; then
        log "issue #$n carries the label but not this monitor's marker -- leaving it open"
        continue
      fi
      gh issue close "$n" --repo "$GH_REPO_SLUG" \
        --comment "Recovered at $(stamp): the heartbeat now reports healthy. Closed automatically so the set of open \`committee-health\` issues keeps meaning \"failing right now\" rather than \"failed at some point\". Reopen if this was premature." \
        >/dev/null 2>&1 && log "closed #$n on recovery" || log "FAILED to close #$n on recovery"
    done
  done
}

load_secrets

case "$MODE" in
  health)
    stamp > "$HEARTBEAT"          # BEFORE the work: proves the trigger fired even if the work dies.
    # 2>&1 IS DELIBERATE HERE, and is the opposite of the bug it caused in alert(): there the merged
    # stream corrupted a URL being parsed; here nothing is parsed and the stderr (ethers' own chatter,
    # RPC errors) is the most useful part of a failure report. Do not "fix" this one into losing it.
    # --expect-armed IS REQUIRED HERE, and its absence was a silent false negative: without it
    # `epochLength == 0` -- the committee switched OFF entirely -- reports OK and exits 0. This
    # heartbeat watches a router-mounted validator that is SUPPOSED to be armed, so a disarmed
    # committee is the single most serious thing it could find, and it was the one thing it would
    # have stayed quiet about.
    out=$(cd "$REPO_DIR" && run_bounded node deploy/committee-health.mjs --expect-armed --router "$ROUTER" --env "$ENV_FILE" --json)
    rc=$?
    # Belt AND braces: if redact ever fails again for a reason not yet imagined, an EMPTY $out is the
    # one outcome that must not reach an issue -- a normal-looking alert carrying nothing is worse
    # than a noisy one. Keep the unredacted text only if redaction produced nothing from non-empty
    # input, and say so, rather than publishing silence.
    out=$(sanitise "$out")
    echo "[$(stamp)] rc=$rc $out" >> "$LOG"
    case "$rc" in
      # committee-health-infrastructure is in this list even though THIS script never opens it: the
      # workflow does, and the workflow closes nothing (its recovery path only runs on a schedule
      # trigger that is delivered unreliably or late here -- see deploy/README-heartbeat.md -- so it
      # cannot be relied on to arrive). Left out, an infrastructure issue stays open forever, which
      # by this file's own argument is the same as not alerting.
      0) resolve committee-health-failing committee-health-undetermined committee-health-hung \
                 committee-health-infrastructure ;;   # healthy (or a WARN already judged benign)
      1) alert "committee-health-failing" \
           "Committee validator is failing checks (local heartbeat)" \
           $'The local launchd heartbeat ran `committee-health.mjs` and it exited 1 -- the committee stack is not serving.\n\n```\n'"$out"$'\n```\n\nRouter: `'"$ROUTER"$'`\nSource: local launchd `io.aastar.dvt-committee-health` (GitHub Actions `schedule` is delivered sparsely or hours late here, so it is not a deadline guarantee -- see deploy/README-heartbeat.md).' ;;
      2) alert "committee-health-undetermined" \
           "Committee health could not be determined (local heartbeat)" \
           $'`committee-health.mjs` exited 2: it could not reach a conclusion (RPC, config, or wrong directory). That is NOT benign -- it reports nothing, which is the silence this monitor exists to end.\n\n```\n'"$out"$'\n```' ;;
      124) alert "committee-health-hung" \
           "Committee health check HUNG and was killed (local heartbeat)" \
           $'The checker did not return within '"$WATCHDOG_SECS"$'s and was killed. This is NOT a verdict on the committee: while a child hangs, launchd will not start the next interval, so the monitor is retired for as long as it lasts. Deliberately its own category -- "it hung" and "the committee is down" need different responses.\n\n```\n'"$out"$'\n```' ;;
      *) alert "committee-health-undetermined" \
           "Committee health exited $rc (local heartbeat)" \
           $'Unexpected exit code '"$rc"$'.\n\n```\n'"$out"$'\n```' ;;
    esac
    exit "$rc"
    ;;

  apply)
    stamp > "$HEARTBEAT"
    out=$(cd "$REPO_DIR" && run_bounded node deploy/apply-verifier-rotation.mjs --env "$ENV_FILE" --broadcast)
    rc=$?
    # Belt AND braces: if redact ever fails again for a reason not yet imagined, an EMPTY $out is the
    # one outcome that must not reach an issue -- a normal-looking alert carrying nothing is worse
    # than a noisy one. Keep the unredacted text only if redaction produced nothing from non-empty
    # input, and say so, rather than publishing silence.
    out=$(sanitise "$out")
    echo "[$(stamp)] rc=$rc" >> "$LOG"
    echo "$out" >> "$LOG"
    # Waiting out the delay exits 0 and says so; only a real problem is non-zero.
    if [ "$rc" -eq 0 ]; then
      resolve committee-health-verifier-rotation
    else
      alert "committee-health-verifier-rotation" \
        "Verifier rotation apply failed (local heartbeat)" \
        $'`apply-verifier-rotation.mjs --broadcast` exited '"$rc"$'. Waiting out the four-day delay exits 0, so this is a real problem, not the countdown.\n\n```\n'"$out"$'\n```'
    fi
    exit "$rc"
    ;;

  check)
    # For a human, and for anything that wants to verify the monitor rather than trust it.
    #
    # DISTINCT EXIT CODES, because "never installed" and "installed and has stopped firing" call for
    # different actions and collapsing them makes the number stop being read. Same reason the checker
    # this wraps separates 1 (found a problem) from 2 (could not reach a conclusion): a column of
    # non-zeros that all mean "something" means nothing within a week.
    #   0 both heartbeats fresh
    #   1 at least one is STALE -- the agent is loaded but its interval is not firing
    #   3 at least one has NEVER RUN -- not installed, or bootstrap failed
    # (3, not 2: 2 is the checker's "undetermined" and this is not that.)
    rc=0
    never=0
    for m in health apply; do
      f="$RUN_DIR/heartbeat-$m.txt"
      if [ ! -f "$f" ]; then
        echo "$m: NEVER RAN (no $f) -- not installed, or bootstrap failed"; never=1; continue
      fi
      last=$(cat "$f")
      age=$(( $(date -u +%s) - $(date -u -j -f "%Y-%m-%dT%H:%M:%SZ" "$last" +%s 2>/dev/null || echo 0) ))
      # health every 15 min, apply daily; allow 3x before calling it stale.
      # Three intervals of each job's OWN period: health runs every 900s, apply every 3600s. The
      # apply limit was 259200 -- written when that job was daily, and left behind when it became
      # hourly, so it tolerated 72 consecutive misses.
      limit=$([ "$m" = health ] && echo 2700 || echo 10800)
      # A negative age means a FUTURE timestamp -- a corrupt file or a clock that moved. Treating it
      # as fresh is the one direction this must never fail in.
      if [ "$age" -lt 0 ]; then
        echo "$m: INVALID -- stamp $last is in the future (${age}s); treating as stale"; rc=1
      elif [ "$age" -gt "$limit" ]; then
        echo "$m: STALE -- last ran $last (${age}s ago, limit ${limit}s) -- loaded but not firing"; rc=1
      else
        echo "$m: ok -- last ran $last (${age}s ago)"
      fi
    done
    # NEVER RAN outranks STALE: it is the more actionable of the two.
    [ "$never" -eq 1 ] && exit 3
    exit "$rc"
    ;;

  *)
    echo "usage: $(basename "$0") {health|apply|check}" >&2
    exit 64
    ;;
esac
