#!/bin/bash
# Local heartbeat for the committee stack -- the trigger that actually fires.
#
# WHY THIS EXISTS, measured rather than assumed. GitHub Actions `schedule` does not run in this
# repository. committee-health.yml sat on the default branch for 6h33m on 2026-08-31 with
# `cron: "7,22,37,52 * * * *"`: 26 expected ticks, ZERO scheduled runs, while the `on:` block parsed
# to a valid schedule, the API reported state=active, the repo was neither archived nor disabled,
# pushes happened throughout, and workflow_dispatch on the same workflow was green. The job could
# run; nothing pressed it. airaccount-contract measured the same on its own offset cron, which
# retires the earlier reading that offsetting the minutes is the fix.
#
# So the monitor's CAPABILITY was verified and its TRIGGER was not, and "monitoring is switched to
# the v0.33.0 router" was an empty claim for as long as that went unnoticed. This script is the
# trigger. The Actions workflows stay as redundancy: they cost nothing and might fire.
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

# Shared with airaccount-contract's monitor so the two repos' alerts are recognisable by the same
# rule. It is also the SAFE-TO-CLOSE predicate below: only an issue carrying this marker was opened
# by a heartbeat, so auto-recovery can never close an issue a human filed under the same label.
MARKER_PREFIX="<!-- committee-health-alert-v1:"

log() { echo "[$(stamp)] $*" | tee -a "$LOG" >&2; }

# $out is pasted verbatim into a GitHub issue on a PUBLIC repository, and the scripts it wraps are
# handed --env pointing at a file that holds real private keys. Nothing observed has ever leaked one
# (ethers redacts a bad privateKey in its own error, and the checkers never echo the file), but that
# is a property of code this script does not own, on a path where one mistake is world-readable and
# permanent. So scrub before publishing rather than trusting someone else's error formatting.
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
load_secrets() {
  [ -r "$ENV_FILE" ] || return 0
  local line name val
  while IFS= read -r line; do
    case "$line" in \#*|"") continue;; esac
    case "$line" in *=*) ;; *) continue;; esac
    name="${line%%=*}"
    val="${line#*=}"
    val="${val%\"}"; val="${val#\"}"; val="${val%\'}"; val="${val#\'}"
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
          http*://*@*|http*://*/v2/*|http*://*/v3/*|*apikey=*|*api_key=*|*"?key="*|*"&key="*)
            SECRETS+=("$val") ;;
        esac ;;
    esac
  done < "$ENV_FILE"
}
redact() {
  local text="$1" sec
  for sec in "${SECRETS[@]}"; do
    text="${text//"$sec"/[REDACTED]}"
  done
  printf '%s' "$text"
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

  local existing
  existing=$(gh issue list --repo "$GH_REPO_SLUG" --state open \
               --label committee-health --label "$catlabel" \
               --json number -q '.[0].number' 2>/dev/null || true)
  if [ -n "$existing" ] && [ "$existing" != "null" ]; then
    gh issue comment "$existing" --repo "$GH_REPO_SLUG" --body "$body" >/dev/null 2>&1 \
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
  err=$(mktemp)
  url=$(gh issue create --repo "$GH_REPO_SLUG" --title "$title" --body "$body" 2>"$err") || {
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
    out=$(cd "$REPO_DIR" && node deploy/committee-health.mjs --router "$ROUTER" --env "$ENV_FILE" --json 2>&1)
    rc=$?
    out=$(redact "$out")
    echo "[$(stamp)] rc=$rc $out" >> "$LOG"
    case "$rc" in
      0) resolve committee-failing committee-undetermined ;;   # healthy (or a WARN already judged benign)
      1) alert "committee-failing" \
           "Committee validator is failing checks (local heartbeat)" \
           $'The local launchd heartbeat ran `committee-health.mjs` and it exited 1 -- the committee stack is not serving.\n\n```\n'"$out"$'\n```\n\nRouter: `'"$ROUTER"$'`\nSource: local launchd `io.aastar.dvt-committee-health` (GitHub Actions `schedule` does not fire in this repo -- see deploy/local-heartbeat.sh).' ;;
      2) alert "committee-undetermined" \
           "Committee health could not be determined (local heartbeat)" \
           $'`committee-health.mjs` exited 2: it could not reach a conclusion (RPC, config, or wrong directory). That is NOT benign -- it reports nothing, which is the silence this monitor exists to end.\n\n```\n'"$out"$'\n```' ;;
      *) alert "committee-undetermined" \
           "Committee health exited $rc (local heartbeat)" \
           $'Unexpected exit code '"$rc"$'.\n\n```\n'"$out"$'\n```' ;;
    esac
    exit "$rc"
    ;;

  apply)
    stamp > "$HEARTBEAT"
    out=$(cd "$REPO_DIR" && node deploy/apply-verifier-rotation.mjs --env "$ENV_FILE" --broadcast 2>&1)
    rc=$?
    out=$(redact "$out")
    echo "[$(stamp)] rc=$rc" >> "$LOG"
    echo "$out" >> "$LOG"
    # Waiting out the delay exits 0 and says so; only a real problem is non-zero.
    if [ "$rc" -eq 0 ]; then
      resolve verifier-rotation
    else
      alert "verifier-rotation" \
        "Verifier rotation apply failed (local heartbeat)" \
        $'`apply-verifier-rotation.mjs --broadcast` exited '"$rc"$'. Waiting out the four-day delay exits 0, so this is a real problem, not the countdown.\n\n```\n'"$out"$'\n```'
    fi
    exit "$rc"
    ;;

  check)
    # For a human, and for anything that wants to verify the monitor rather than trust it.
    rc=0
    for m in health apply; do
      f="$RUN_DIR/heartbeat-$m.txt"
      if [ ! -f "$f" ]; then
        echo "$m: NEVER RAN (no $f)"; rc=1; continue
      fi
      last=$(cat "$f")
      age=$(( $(date -u +%s) - $(date -u -j -f "%Y-%m-%dT%H:%M:%SZ" "$last" +%s 2>/dev/null || echo 0) ))
      # health every 15 min, apply daily; allow 3x before calling it stale.
      limit=$([ "$m" = health ] && echo 2700 || echo 259200)
      if [ "$age" -gt "$limit" ]; then
        echo "$m: STALE -- last ran $last (${age}s ago, limit ${limit}s)"; rc=1
      else
        echo "$m: ok -- last ran $last (${age}s ago)"
      fi
    done
    exit "$rc"
    ;;

  *)
    echo "usage: $(basename "$0") {health|apply|check}" >&2
    exit 64
    ;;
esac
