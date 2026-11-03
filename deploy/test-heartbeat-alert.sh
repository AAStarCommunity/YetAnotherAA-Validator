#!/bin/bash
# Offline test for alert() in local-heartbeat.sh: comment throttling and rollover at the comment cap.
# Extracts the function and drives it against a stub `gh`; nothing touches GitHub or the chain.
#
#   bash deploy/test-heartbeat-alert.sh      exit 0 = all cases pass
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$HERE/local-heartbeat.sh"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
mkdir -p "$T/bin"

# Stub gh. Behaviour comes from env; every call is appended to $T/calls.
cat > "$T/bin/gh" <<'STUB'
#!/bin/bash
echo "$*" >> "$GH_CALLS"
case "$1 $2" in
  "label create") exit 0 ;;
  "issue list") for n in ${STUB_LIST:-381}; do echo "$n"; done ;;
  "issue view") case "$*" in *"state"*) [ "${STUB_STATE_FAIL:-0}" = 1 ] && exit 1; echo "${STUB_STATE-OPEN}" ;; *) echo "<!-- committee-health-alert-v1:committee-health-failing --> body" ;; esac ;;
  "issue comment") cat > /dev/null; [ "${STUB_COMMENT_OK:-1}" = 1 ] ;;
  "issue close") [ "${STUB_CLOSE_OK:-1}" = 1 ] ;;
  "issue create") cat > "$GH_CREATE_BODY"; [ "${STUB_CREATE_OK:-1}" = 1 ] || exit 1; echo "https://github.com/o/r/issues/999" ;;
  "issue edit") [ "${STUB_EDIT_OK:-1}" = 1 ] ;;
  "api repos/o/r/issues/381"|"api repos/o/r/issues/400") echo "${STUB_COUNT:-2500}" ;;
  *) exit 1 ;;
esac
STUB
chmod +x "$T/bin/gh"

# Pull alert() and the definitions it uses out of the real script, so the test runs that code.
{
  echo 'stamp() { date -u +%Y-%m-%dT%H:%M:%SZ; }'
  echo 'log() { echo "LOG: $*" >> "$LOGF"; }'
  sed -n '/^MARKER_PREFIX=/,/^COMMENT_CAP=/p' "$SRC"
  sed -n '/^alert() {/,/^}/p' "$SRC"
  sed -n '/^resolve() {/,/^}/p' "$SRC"
} > "$T/fns.sh"
grep -q '^alert() {' "$T/fns.sh" && grep -q '^COMMENT_CAP=' "$T/fns.sh" || { echo "FAIL: could not extract alert()"; exit 1; }

fail=0
run() { # name expect-pattern [env...] -- runs alert once in a fresh environment
  local name="$1" want="$2"; shift 2
  rm -f "$T/calls" "$T/log" "$T/create"
  env "$@" PATH="$T/bin:/usr/bin:/bin" GH_CALLS="$T/calls" GH_CREATE_BODY="$T/create" LOGF="$T/log" \
    RUN_DIR="$T" GH_REPO_SLUG=o/r bash -c ". '$T/fns.sh'; alert committee-health-failing 'Committee health check is failing' 'diag'"
  if grep -qE "$want" "$T/log" 2>/dev/null; then echo "ok   $name"; else echo "FAIL $name"; cat "$T/log" 2>/dev/null; fail=1; fi
}
stampfile="$T/last-comment-committee-health-failing-381.txt"

rm -f "$stampfile"
run "comment succeeds and is stamped" "appended to existing issue #381" STUB_COMMENT_OK=1
[ -s "$stampfile" ] || { echo "FAIL stamp not written"; fail=1; }

run "second tick within the interval does not comment" "not commenting" STUB_COMMENT_OK=1
grep -q "issue comment" "$T/calls" && { echo "FAIL throttled tick still called gh issue comment"; fail=1; }

rm -f "$stampfile"
run "full issue is closed and a successor opened" "opened issue https://github.com/o/r/issues/999" STUB_COMMENT_OK=0 STUB_COUNT=2500
grep -q "issue close 381" "$T/calls" || { echo "FAIL #381 was not closed"; fail=1; }
# Order matters: the successor must exist before the full issue is closed.
c=$(grep -n "issue create" "$T/calls" | cut -d: -f1); k=$(grep -n "issue close 381" "$T/calls" | cut -d: -f1)
[ -n "$c" ] && [ -n "$k" ] && [ "$c" -lt "$k" ] || { echo "FAIL closed #381 before creating its successor"; fail=1; }
grep -q "Continues #381" "$T/create" || { echo "FAIL successor body does not point back"; fail=1; }
head -1 "$T/create" | grep -qF "<!-- committee-health-alert-v1:committee-health-failing -->" \
  || { echo "FAIL successor does not start with the dedup marker"; fail=1; }

rm -f "$stampfile"
run "failure below the cap only retries" "below the cap" STUB_COMMENT_OK=0 STUB_COUNT=12
grep -qE "issue (close|create)" "$T/calls" && { echo "FAIL rolled over without reaching the cap"; fail=1; }

rm -f "$stampfile"
run "unreadable count does not roll over" "below the cap" STUB_COMMENT_OK=0 STUB_COUNT=oops
grep -qE "issue (close|create)" "$T/calls" && { echo "FAIL rolled over on an unreadable count"; fail=1; }

rm -f "$stampfile"
run "create failure keeps the full issue open" "FAILED to create issue" STUB_COMMENT_OK=0 STUB_COUNT=2500 STUB_CREATE_OK=0
grep -q "issue close" "$T/calls" && { echo "FAIL closed #381 although no successor was created"; fail=1; }

rm -f "$stampfile"
run "close failure after create is logged" "FAILED to close full #381" STUB_COMMENT_OK=0 STUB_COUNT=2500 STUB_CLOSE_OK=0

rm -f "$T"/last-comment-*
run "newest marked issue is the dedup target" "appended to existing issue #400" STUB_COMMENT_OK=1 STUB_LIST="381 400"

date -u -v+1d +%s > "$stampfile" 2>/dev/null || echo 99999999999 > "$stampfile"
run "future stamp does not mute comments" "appended to existing issue #381" STUB_COMMENT_OK=1

rm -f "$stampfile" "$T"/successor-*
run "unlabelled successor keeps the full issue open" "keeping full #381 open" STUB_COMMENT_OK=0 STUB_COUNT=2500 STUB_EDIT_OK=0
grep -q "issue close" "$T/calls" && { echo "FAIL closed #381 although its successor is unlabelled"; fail=1; }
[ "$(cat "$T/successor-committee-health-failing-381.txt" 2>/dev/null)" = 999 ] || { echo "FAIL successor not recorded"; fail=1; }

run "next tick labels the recorded successor, opens nothing" "labelled successor #999" STUB_COMMENT_OK=0 STUB_COUNT=2500
grep -q "issue create" "$T/calls" && { echo "FAIL opened another successor"; fail=1; }
grep -q "issue close 381" "$T/calls" || { echo "FAIL did not close #381 after labelling"; fail=1; }

rm -f "$stampfile"; echo 999 > "$T/successor-committee-health-failing-381.txt"
run "closed successor is discarded, a fresh one opened" "was closed -- discarding" STUB_COMMENT_OK=0 STUB_COUNT=2500 STUB_STATE=CLOSED
grep -q "issue create" "$T/calls" || { echo "FAIL did not open a fresh successor"; fail=1; }

rm -f "$stampfile"; echo 999 > "$T/successor-committee-health-failing-381.txt"
for case in "STUB_STATE=" "STUB_STATE_FAIL=1"; do
  rm -f "$stampfile"; echo 999 > "$T/successor-committee-health-failing-381.txt"
  run "unreadable successor state keeps the record ($case)" "keeping the record" STUB_COMMENT_OK=0 STUB_COUNT=2500 "$case"
  grep -qE "issue (create|close|edit)" "$T/calls" && { echo "FAIL acted on an unreadable successor state ($case)"; fail=1; }
  [ -f "$T/successor-committee-health-failing-381.txt" ] || { echo "FAIL dropped the successor record ($case)"; fail=1; }
done

# Recovery must close an unlabelled successor that only the local record knows about.
echo 999 > "$T/successor-committee-health-failing-381.txt"; rm -f "$T/calls" "$T/log"
env PATH="$T/bin:/usr/bin:/bin" GH_CALLS="$T/calls" LOGF="$T/log" RUN_DIR="$T" GH_REPO_SLUG=o/r STUB_LIST="" \
  bash -c ". '$T/fns.sh'; resolve committee-health-failing"
if grep -q "issue close 999" "$T/calls" && [ ! -f "$T/successor-committee-health-failing-381.txt" ]; then
  echo "ok   recovery closes an unlabelled successor"; else echo "FAIL recovery left the unlabelled successor"; cat "$T/log"; fail=1; fi

rm -f "$T"/successor-*
echo garbage > "$stampfile"
run "corrupt stamp counts as never commented" "appended to existing issue #381" STUB_COMMENT_OK=1

exit "$fail"
