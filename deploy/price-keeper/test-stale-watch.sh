#!/bin/bash
# Offline test for stale-watch.sh: a stub status command and a stub curl, no chain and no Telegram.
#   bash deploy/price-keeper/test-stale-watch.sh      exit 0 = all cases pass
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
T="$(mktemp -d)"; trap 'chmod -R u+w "$T" 2>/dev/null; rm -rf "$T"' EXIT
mkdir -p "$T/cfg"
printf 'TELEGRAM_BOT_TOKEN=tok-SECRET\nTELEGRAM_CHAT_ID=42\n' > "$T/cfg/telegram.env"

cat > "$T/status" <<'S'
#!/bin/bash
# STUB_SLEEP runs in a child (bash -c), so a hang is held by a DESCENDANT of the status command.
[ -n "${STUB_SLEEP:-}" ] && bash -c "sleep $STUB_SLEEP"
# STUB_FDS: report any open fd above 2 (the lock must not leak into the status command).
[ -n "${STUB_FDS:-}" ] && for fd in /dev/fd/*; do n="${fd##*/}"; [ "$n" -gt 2 ] && [ "$n" != 255 ] && [ -e "$fd" ] && echo "FDLEAK $n"; done
# STUB_BG: leave a background descendant holding stdout and exit at once.
# STUB_BG_IGNTERM: that descendant ignores TERM, so only the KILL step can end it. Its pid goes to $PIDS.
if [ -n "${STUB_BG:-}" ]; then
  if [ -n "${STUB_BG_IGNTERM:-}" ]; then
    # Handshake: the stub exits only after the trap is installed, so TERM cannot land before it.
    ready="$(mktemp -u)"; bash -c "trap '' TERM; : > '$ready'; exec sleep $STUB_BG" &
    for _ in $(seq 1 50); do [ -e "$ready" ] && break; sleep 0.1; done
    # No handshake means TERM could kill it before the trap: fail the case instead of passing untested.
    [ -e "$ready" ] || { echo "NOREADY"; exit 99; }; rm -f "$ready"
  else sleep "$STUB_BG" & fi
  echo $! >> "${PIDS:-/dev/null}"
fi
printf '%s\n' "${STUB_OUT:-FRESH SuperPaymaster age=1s limit=4200s}"; exit "${STUB_CODE:-0}"
S
cat > "$T/curl" <<'S'
#!/bin/bash
cfg="$(cat)"; echo "ARGS $*" >> "$SENT"; echo "CFG $cfg" >> "$SENT.cfg"
if [ "${STUB_TG_OK:-1}" = 1 ]; then body="${STUB_TG_BODY:-}"; [ -n "$body" ] || body='{"ok":true}'; printf '%s\n' "$body"; else echo '{"ok":false,"description":"Unauthorized"}'; fi
exit "${STUB_CURL_RC:-0}"
S
chmod +x "$T/status" "$T/curl"

fail=0
# run NAME [WANT_RC=n] [VAR=value ...] -- one check; its exit code must equal WANT_RC (default 0).
run() {
  local name="$1"; shift; local want=0
  case "${1:-}" in WANT_RC=*) want="${1#WANT_RC=}"; shift ;; esac
  : > "$T/sent"; : > "$T/pids"
  local t0; t0=$(date +%s)
  env "$@" KEEPER_CONFIG_DIR="$T/cfg" STALE_WATCH_STATE_DIR="${SD:-$T/state}" STALE_WATCH_STATUS_CMD="$T/status" \
    STALE_WATCH_CURL="$T/curl" SENT="$T/sent" PIDS="$T/pids" bash "$HERE/stale-watch.sh" ${ARGS:-} > "$T/log" 2>&1
  RC=$?; ELAPSED=$(( $(date +%s) - t0 )); CUR="$name"
  if [ "$RC" != "$want" ]; then echo "FAIL $CUR: exit $RC, wanted $want"; cat "$T/log"; fail=1; fi
}
sent() { grep -c . "$T/sent"; }
# 0 when every descendant pid the stub recorded is gone (and at least one was recorded)
# A pid counts as gone when it no longer exists, is a zombie waiting for its new parent, or now
# belongs to something other than the stub's sleep (pid reuse). Polls up to 3s for the reaping.
reaped() {
  [ -s "$T/pids" ] || return 1
  local p st gone _
  while read -r p; do
    gone=""
    for _ in $(seq 1 30); do
      st="$(ps -o stat=,comm= -p "$p" 2>/dev/null)"
      if [ -z "$st" ]; then gone=1; break; fi            # no such process
      case "$st" in Z*) gone=1; break ;; esac             # zombie: dead, not yet reaped
      case "$st" in *sleep) ;; *) gone=1; break ;; esac   # pid reused by something else
      sleep 0.1
    done
    [ -n "$gone" ] || return 1
  done < "$T/pids"
  return 0
}
expect() { # description, condition
  if eval "$2"; then echo "ok   $CUR: $1"; else echo "FAIL $CUR: $1"; cat "$T/log"; fail=1; fi
}

run "fresh, nothing outstanding"
expect "no message" '[ "$(sent)" = 0 ]'
expect "last-run stamped" '[ -s "$T/state/last-run" ]'

run "stale cache" STUB_CODE=1 STUB_OUT="STALE PaymasterV4 0x2118 age=517632s limit=4200s"
expect "one alert" '[ "$(sent)" = 1 ] && grep -q "ALERT.*STALE PaymasterV4" "$T/sent"'
expect "token never on argv" '! grep -q "tok-SECRET" "$T/sent" && grep -q "CFG.*tok-SECRET" "$T/sent.cfg"'

run "still stale within the interval" STUB_CODE=1 STUB_OUT="STALE PaymasterV4"
expect "not repeated" '[ "$(sent)" = 0 ] && grep -q "not repeating" "$T/log"'

echo 1 > "$T/state/alerted-stale"
run "still stale after the interval" STUB_CODE=1 STUB_OUT="STALE PaymasterV4"
expect "repeated" '[ "$(sent)" = 1 ]'

echo 99999999999 > "$T/state/alerted-stale"
run "future stamp" STUB_CODE=1 STUB_OUT="STALE PaymasterV4"
expect "does not mute" '[ "$(sent)" = 1 ]'

run "a second item starts failing within the interval" STUB_CODE=1 STUB_OUT="STALE PaymasterV4 x
LOW_GAS keeper balance=0.001 ETH"
expect "re-alerts at once with both lines" '[ "$(sent)" = 1 ] && grep -q "LOW_GAS keeper" "$T/sent"'
run "same two items again" STUB_CODE=1 STUB_OUT="LOW_GAS keeper y
STALE PaymasterV4 z"
expect "not repeated (order and detail do not matter)" '[ "$(sent)" = 0 ]'
stamp_before="$(cat "$T/state/alerted-stale")"; kinds_before="$(cat "$T/state/alerted-stale-kinds")"
run "a new set, but Telegram rejects it" STUB_CODE=1 STUB_TG_OK=0 STUB_OUT="STALE SuperPaymaster x
STALE PaymasterV4 y"
expect "state left as it was, so the next run retries" \
  '[ "$(cat "$T/state/alerted-stale")" = "$stamp_before" ] && [ "$(cat "$T/state/alerted-stale-kinds")" = "$kinds_before" ]'
run "the same new set, Telegram accepts" STUB_CODE=1 STUB_OUT="STALE SuperPaymaster x
STALE PaymasterV4 y"
expect "retried within the interval and delivered" '[ "$(sent)" = 1 ] && grep -q "STALE SuperPaymaster" "$T/sent"'

run "recovered"
expect "one RECOVERED, stamp cleared" '[ "$(sent)" = 1 ] && grep -q RECOVERED "$T/sent" && [ ! -f "$T/state/alerted-stale" ] && [ ! -f "$T/state/alerted-stale-kinds" ]'

run "fresh again"
expect "no second RECOVERED" '[ "$(sent)" = 0 ] && grep -q "status exit 0" "$T/log"'

run "low gas" STUB_CODE=1 STUB_OUT="FUNDED x
LOW_GAS keeper balance=0.001 ETH"
expect "alerts with the LOW_GAS line" '[ "$(sent)" = 1 ] && grep -q "LOW_GAS keeper" "$T/sent"'
rm -rf "$T/state"

for i in 1 2; do
  run "undetermined #$i" STUB_CODE=2 STUB_OUT="UNDETERMINED rpc down"
  expect "silent below the threshold" '[ "$(sent)" = 0 ] && [ "$(cat "$T/state/undetermined-count")" = '$i' ]'
done
run "undetermined #3" STUB_CODE=2 STUB_OUT="UNDETERMINED rpc down"
expect "alerts at the threshold" '[ "$(sent)" = 1 ] && grep -q UNDETERMINED "$T/sent"'
run "then stale" STUB_CODE=1 STUB_OUT="STALE SuperPaymaster"
expect "an UNDETERMINED alert does not mute a STALE one" '[ "$(sent)" = 1 ] && grep -q "ALERT.*STALE SuperPaymaster" "$T/sent"'
rm -rf "$T/state"

run "telegram rejects" STUB_CODE=1 STUB_OUT="STALE x" STUB_TG_OK=0
expect "failure logged, no stamp so the next run retries" 'grep -q "telegram send FAILED" "$T/log" && [ ! -f "$T/state/alerted-stale" ]'
run "curl fails after printing ok" STUB_CODE=1 STUB_OUT="STALE x" STUB_CURL_RC=56
expect "not counted as delivered" 'grep -q "curl exit 56" "$T/log" && [ ! -f "$T/state/alerted-stale" ]'
run "truncated body" STUB_CODE=1 STUB_OUT="STALE x" STUB_TG_BODY='{"ok":trueBROKEN'
expect "not counted as delivered" '[ ! -f "$T/state/alerted-stale" ]'
run "ok as a string" STUB_CODE=1 STUB_OUT="STALE x" STUB_TG_BODY='{"ok":"true"}'
expect "not counted as delivered" '[ ! -f "$T/state/alerted-stale" ]'
run "valid JSON, ok not first, spaces" STUB_CODE=1 STUB_OUT="STALE x" STUB_TG_BODY='{ "result": {}, "ok" : true }'
expect "counted as delivered" '[ -f "$T/state/alerted-stale" ]'
rm -rf "$T/state"

ARGS=--test run "--test"
expect "sends one TEST message" '[ "$(sent)" = 1 ] && grep -q TEST "$T/sent"'
ARGS=--test run "--test, Telegram rejects" WANT_RC=1 STUB_TG_OK=0
expect "exit 1" 'true'

run "status hangs in a descendant" STUB_SLEEP=30 STALE_WATCH_STATUS_TIMEOUT=1 STALE_WATCH_UNDETERMINED_AFTER=1
expect "UNDETERMINED alert, and the run ends in seconds, not 30" \
  'grep -q "did not finish within 1s" "$T/sent" && [ "$ELAPSED" -lt 10 ]'
rm -rf "$T/state"

run "status command fds" STUB_FDS=1
expect "inherits no fd above 2" '! grep -q FDLEAK "$T/log"'

run "child exits 0 but a descendant keeps the pipe" STUB_BG=30 STALE_WATCH_STATUS_TIMEOUT=1 STALE_WATCH_UNDETERMINED_AFTER=1
expect "the child's result stands: exit 0, no alert, ends in seconds" \
  '[ "$(sent)" = 0 ] && grep -q "status exit 0: FRESH" "$T/log" && [ "$ELAPSED" -lt 10 ]'
expect "the descendant holding the pipe was killed" 'reaped'
run "child exits 1 but a descendant keeps the pipe" STUB_BG=30 STUB_CODE=1 STUB_OUT="STALE PaymasterV4" STALE_WATCH_UNDETERMINED_AFTER=1
expect "STALE alert, not UNDETERMINED; a short grace, not the 120s timeout" \
  'grep -q "ALERT.*STALE PaymasterV4" "$T/sent" && ! grep -q UNDETERMINED "$T/sent" && [ "$ELAPSED" -lt 15 ]'
expect "the descendant holding the pipe was killed" 'reaped'
rm -rf "$T/state"
run "a descendant that ignores TERM keeps the pipe" STUB_BG=30 STUB_BG_IGNTERM=1 STUB_CODE=1 STUB_OUT="STALE PaymasterV4"
expect "KILL ends it; the child's result still stands" 'reaped && grep -q "ALERT.*STALE PaymasterV4" "$T/sent" && [ "$ELAPSED" -lt 15 ]'
rm -rf "$T/state"

mkdir -p "$T/state"; echo 0008 > "$T/state/undetermined-count"
run "counter with leading zeros" STUB_CODE=2 STUB_OUT="UNDETERMINED x" STALE_WATCH_UNDETERMINED_AFTER=9
expect "read as decimal 8, so the 9th check alerts" '[ "$(cat "$T/state/undetermined-count")" = 9 ] && [ "$(sent)" = 1 ]'
rm -rf "$T/state"

# Hold the flock from another process, as an overlapping manual run would.
mkdir -p "$T/state"
perl -e 'use Fcntl qw(:flock); open(my $f, ">>", shift) or die; flock($f, LOCK_EX) or die; print "held\n"; $|=1; sleep 20' \
  "$T/state/lock" > "$T/holder" & holder=$!
for _ in 1 2 3 4 5 6 7 8 9 10; do grep -q held "$T/holder" 2>/dev/null && break; sleep 0.2; done
run "another check holds the lock" STUB_CODE=1 STUB_OUT="STALE x"
expect "skips without touching state" '[ "$(sent)" = 0 ] && [ ! -f "$T/state/last-run" ] && grep -q "holds the lock" "$T/log"'
kill "$holder" 2>/dev/null; wait "$holder" 2>/dev/null
run "lock file left behind after the holder died" STUB_CODE=1 STUB_OUT="STALE x"
expect "not blocking: alert sent" '[ "$(sent)" = 1 ]'
rm -rf "$T/state"

# The worker (not a parent that could be killed separately) must hold the lock for the whole check.
env KEEPER_CONFIG_DIR="$T/cfg" STALE_WATCH_STATE_DIR="$T/state" STALE_WATCH_STATUS_CMD="$T/status" \
  STALE_WATCH_CURL="$T/curl" SENT="$T/sent.bg" STUB_SLEEP=4 STALE_WATCH_STATUS_TIMEOUT=30 \
  bash "$HERE/stale-watch.sh" > "$T/log.bg" 2>&1 & bg=$!
sleep 1
# $bg runs perl as a child; perl must have exec'd into the bash worker, not stayed around as its parent.
kid=$(pgrep -P "$bg" | head -1); comm=$(ps -o comm= -p "$kid" 2>/dev/null)
case "$comm" in */bash|bash) echo "ok   lock: the lock holder is the bash worker itself ($comm)" ;;
  *) echo "FAIL lock: child of $bg is '$comm', not the bash worker"; fail=1 ;; esac
run "second check while the first is running" STUB_CODE=1 STUB_OUT="STALE x"
expect "skipped" 'grep -q "holds the lock" "$T/log"'
wait "$bg"
rm -rf "$T/state"

# status.mjs itself: a broken setup must exit 2, not 1, so it reads UNDETERMINED, not STALE.
if command -v node >/dev/null; then
  mjs() { # name, expected message, setup of $H -- run status.mjs under a fake HOME
    local H="$T/home-$1"; mkdir -p "$H/.config/aastar-price-keeper"; eval "$3"
    out=$(HOME="$H" node "$HERE/status.mjs" 2>&1); rc=$?; CUR="status.mjs: $1"
    expect "exit 2, UNDETERMINED $2" '[ "$rc" = 2 ] && printf "%s" "$out" | grep -q "^UNDETERMINED.*'"$2"'"'
  }
  mjs no-viem "" ':'
  # A stub viem, so the config paths are reached; any RPC call it would make fails the test (exit 9).
  viem='v="$H/Dev/aastar/aastar-sdk-price-keeper/packages/core/node_modules/viem"; mkdir -p "$v"
    echo "{\"name\":\"viem\",\"main\":\"index.js\"}" > "$v/package.json"
    echo "const no=()=>process.exit(9); module.exports={createPublicClient:no,http:()=>0,parseAbi:()=>[],formatEther:String}" > "$v/index.js"'
  mjs no-rpc-env ENOENT "$viem"
  mjs no-rpc-url "RPC_URL missing" "$viem; echo OTHER=1 > \$H/.config/aastar-price-keeper/rpc.env"
  mjs no-address ENOENT "$viem; echo RPC_URL=http://127.0.0.1:9 > \$H/.config/aastar-price-keeper/rpc.env"
else
  echo "skip status.mjs check: no node"
fi

mkdir -p "$T/ro"; chmod 500 "$T/ro"
SD="$T/ro/state" run "state dir cannot be created" WANT_RC=1 STUB_CODE=2
expect "alerts at once" 'grep -q "cannot write its state" "$T/sent"'
mkdir -p "$T/ro2/state"; chmod 500 "$T/ro2/state"
SD="$T/ro2/state" run "state dir exists but is read-only" WANT_RC=1 STUB_CODE=2
expect "alerts at once instead of skipping as if locked" 'grep -q "cannot write its state" "$T/sent"'

exit "$fail"
