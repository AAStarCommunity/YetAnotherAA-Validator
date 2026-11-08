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
printf '%s\n' "${STUB_OUT:-FRESH SuperPaymaster age=1s limit=4200s}"; exit "${STUB_CODE:-0}"
S
cat > "$T/curl" <<'S'
#!/bin/bash
cfg="$(cat)"; echo "ARGS $*" >> "$SENT"; echo "CFG $cfg" >> "$SENT.cfg"
[ "${STUB_TG_OK:-1}" = 1 ] && echo '{"ok":true}' || echo '{"ok":false,"description":"Unauthorized"}'
S
chmod +x "$T/status" "$T/curl"

fail=0
run() { # name, then env assignments; runs one check
  local name="$1"; shift
  : > "$T/sent"
  env "$@" KEEPER_CONFIG_DIR="$T/cfg" STALE_WATCH_STATE_DIR="$T/state" STALE_WATCH_STATUS_CMD="$T/status" \
    STALE_WATCH_CURL="$T/curl" SENT="$T/sent" bash "$HERE/stale-watch.sh" > "$T/log" 2>&1
  CUR="$name"
}
sent() { grep -c . "$T/sent"; }
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
expect "not repeated" '[ "$(sent)" = 0 ]'

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

exit "$fail"
