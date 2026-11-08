#!/bin/bash
# Offline test for stale-watch.sh: a stub status command and a stub curl, no chain and no Telegram.
#   bash deploy/price-keeper/test-stale-watch.sh      exit 0 = all cases pass
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
mkdir -p "$T/cfg"
printf 'TELEGRAM_BOT_TOKEN=tok-SECRET\nTELEGRAM_CHAT_ID=42\n' > "$T/cfg/telegram.env"

cat > "$T/status" <<'S'
#!/bin/bash
[ -n "${STUB_SLEEP:-}" ] && sleep "$STUB_SLEEP"
printf '%s\n' "${STUB_OUT:-FRESH SuperPaymaster age=1s limit=4200s}"; exit "${STUB_CODE:-0}"
S
cat > "$T/curl" <<'S'
#!/bin/bash
cfg="$(cat)"; echo "ARGS $*" >> "$SENT"; echo "CFG $cfg" >> "$SENT.cfg"
if [ "${STUB_TG_OK:-1}" = 1 ]; then printf '%s\n' "${STUB_TG_BODY:-{\"ok\":true}}"; else echo '{"ok":false,"description":"Unauthorized"}'; fi
exit "${STUB_CURL_RC:-0}"
S
chmod +x "$T/status" "$T/curl"

fail=0
run() { # name, then env assignments; runs one check
  local name="$1"; shift
  : > "$T/sent"
  env "$@" KEEPER_CONFIG_DIR="$T/cfg" STALE_WATCH_STATE_DIR="$T/state" STALE_WATCH_STATUS_CMD="$T/status" \
    STALE_WATCH_CURL="$T/curl" SENT="$T/sent" bash "$HERE/stale-watch.sh" > "$T/log" 2>&1
  RC=$?; CUR="$name"
}
sent() { grep -c . "$T/sent"; }
expect() { # description, condition
  if eval "$2"; then echo "ok   $CUR: $1"; else echo "FAIL $CUR: $1"; cat "$T/log"; fail=1; fi
}

run "fresh, nothing outstanding"
expect "exit 0" '[ "$RC" = 0 ]'
expect "no message" '[ "$(sent)" = 0 ]'
expect "last-run stamped" '[ -s "$T/state/last-run" ]'

run "stale cache" STUB_CODE=1 STUB_OUT="STALE PaymasterV4 0x2118 age=517632s limit=4200s"
expect "one alert" '[ "$(sent)" = 1 ] && grep -q "ALERT.*STALE PaymasterV4" "$T/sent"'
expect "token never on argv" '! grep -q "tok-SECRET" "$T/sent" && grep -q "CFG.*tok-SECRET" "$T/sent.cfg"'

run "still stale within the interval" STUB_CODE=1 STUB_OUT="STALE PaymasterV4"
expect "not repeated, and the run itself succeeded" '[ "$(sent)" = 0 ] && [ "$RC" = 0 ] && grep -q "not repeating" "$T/log"'

echo 1 > "$T/state/alerted-stale"
run "still stale after the interval" STUB_CODE=1 STUB_OUT="STALE PaymasterV4"
expect "repeated" '[ "$(sent)" = 1 ]'

echo 99999999999 > "$T/state/alerted-stale"
run "future stamp" STUB_CODE=1 STUB_OUT="STALE PaymasterV4"
expect "does not mute" '[ "$(sent)" = 1 ]'

run "recovered"
expect "one RECOVERED, stamp cleared" '[ "$(sent)" = 1 ] && grep -q RECOVERED "$T/sent" && [ ! -f "$T/state/alerted-stale" ]'

run "fresh again" ; expect "no second RECOVERED" '[ "$(sent)" = 0 ]'

run "low gas" STUB_CODE=1 STUB_OUT="FUNDED x
LOW_GAS keeper balance=0.001 ETH"
expect "alerts with the LOW_GAS line" '[ "$(sent)" = 1 ] && grep -q "LOW_GAS keeper" "$T/sent"'
run "clear" ; rm -rf "$T/state"

for i in 1 2; do run "undetermined #$i" STUB_CODE=2 STUB_OUT="UNDETERMINED rpc down"; expect "silent below the threshold" '[ "$(sent)" = 0 ]'; done
run "undetermined #3" STUB_CODE=2 STUB_OUT="UNDETERMINED rpc down"
expect "alerts at the threshold" '[ "$(sent)" = 1 ] && grep -q UNDETERMINED "$T/sent"'
run "then stale" STUB_CODE=1 STUB_OUT="STALE SuperPaymaster"
expect "an UNDETERMINED alert does not mute a STALE one" '[ "$(sent)" = 1 ] && grep -q "ALERT.*STALE SuperPaymaster" "$T/sent"'
run "clear" ; rm -rf "$T/state"

run "telegram rejects" STUB_CODE=1 STUB_OUT="STALE x" STUB_TG_OK=0
expect "failure logged, no stamp so the next run retries" 'grep -q "telegram send FAILED" "$T/log" && [ ! -f "$T/state/alerted-stale" ]'

: > "$T/sent"
env KEEPER_CONFIG_DIR="$T/cfg" STALE_WATCH_STATE_DIR="$T/state" STALE_WATCH_CURL="$T/curl" SENT="$T/sent" \
  bash "$HERE/stale-watch.sh" --test > "$T/log" 2>&1; rc=$?
CUR="--test"; expect "sends one TEST message, exit 0" '[ $rc = 0 ] && [ "$(sent)" = 1 ] && grep -q TEST "$T/sent"'

rm -rf "$T/state"
run "curl fails after printing ok" STUB_CODE=1 STUB_OUT="STALE x" STUB_CURL_RC=56
expect "not counted as delivered" 'grep -q "curl exit 56" "$T/log" && [ ! -f "$T/state/alerted-stale" ]'
run "Telegram JSON with spaces" STUB_CODE=1 STUB_OUT="STALE x" STUB_TG_BODY='{ "ok" : true, "result": {} }'
expect "counted as delivered" '[ -f "$T/state/alerted-stale" ]'
run "clear" ; rm -rf "$T/state"

run "status hangs" STUB_SLEEP=5 STALE_WATCH_STATUS_TIMEOUT=1 STALE_WATCH_UNDETERMINED_AFTER=1
expect "treated as UNDETERMINED, run exits" '[ "$RC" = 0 ] && grep -q "did not finish within 1s" "$T/sent"'
rm -rf "$T/state"

mkdir -p "$T/state"; echo 0008 > "$T/state/undetermined-count"
run "counter with leading zeros" STUB_CODE=2 STUB_OUT="UNDETERMINED x" STALE_WATCH_UNDETERMINED_AFTER=9
expect "read as decimal 8, so the 9th check alerts" '[ "$RC" = 0 ] && [ "$(cat "$T/state/undetermined-count")" = 9 ] && [ "$(sent)" = 1 ]'
rm -rf "$T/state"

mkdir -p "$T/state/lock"; date -u +%s > "$T/state/lock/since"
run "another check holds the lock" STUB_CODE=1 STUB_OUT="STALE x"
expect "skips without touching state" '[ "$RC" = 0 ] && [ "$(sent)" = 0 ] && [ ! -f "$T/state/last-run" ] && [ -d "$T/state/lock" ]'
echo 1 > "$T/state/lock/since"
run "lock left by a killed run" STUB_CODE=1 STUB_OUT="STALE x"
expect "taken over, alert sent, lock released" '[ "$(sent)" = 1 ] && [ ! -d "$T/state/lock" ]'
rm -rf "$T/state"
mkdir -p "$T/state/lock"; touch -t 202001010000 "$T/state/lock"
run "old lock with no stamp" STUB_CODE=1 STUB_OUT="STALE x"
expect "expires by mtime" '[ "$(sent)" = 1 ] && [ ! -d "$T/state/lock" ]'
mkdir -p "$T/state/lock"
run "fresh lock with no stamp" STUB_CODE=1 STUB_OUT="STALE x"
expect "still respected" '[ "$(sent)" = 0 ] && [ -d "$T/state/lock" ]'
rm -rf "$T/state"

mkdir -p "$T/ro"; chmod 500 "$T/ro"
: > "$T/sent"; env KEEPER_CONFIG_DIR="$T/cfg" STALE_WATCH_STATE_DIR="$T/ro/state" STALE_WATCH_STATUS_CMD="$T/status" \
  STALE_WATCH_CURL="$T/curl" SENT="$T/sent" STUB_CODE=2 bash "$HERE/stale-watch.sh" > "$T/log" 2>&1; RC=$?
CUR="state dir not writable"; expect "alerts at once and exits non-zero" '[ "$RC" = 1 ] && grep -q "cannot write its state" "$T/sent"'
chmod 700 "$T/ro"

exit "$fail"
