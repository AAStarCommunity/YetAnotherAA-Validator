#!/bin/bash
# Offline test for stale-watch.sh: a stub status command and a stub curl, no chain and no Telegram.
#   bash deploy/price-keeper/test_stale_watch.sh      exit 0 = all cases pass
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
T="$(mktemp -d)"; trap 'chmod -R u+w "$T" 2>/dev/null; rm -rf "$T"' EXIT
mkdir -p "$T/cfg"; cp "$HERE/stale-watch.sh" "$T/cfg/stale-watch.sh"   # it runs as the entry it is installed in
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
  env "$@" STALE_WATCH_STATE_DIR="${SD:-$T/state}" STALE_WATCH_STATUS_CMD="$T/status" \
    STALE_WATCH_CURL="$T/curl" SENT="$T/sent" PIDS="$T/pids" bash "$T/cfg/stale-watch.sh" ${ARGS:-} > "$T/log" 2>&1
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
cp "$T/cfg/telegram.env" "$T/tg.good"; printf 'exit 0\nTELEGRAM_BOT_TOKEN="tok-SECRET"\nTELEGRAM_CHAT_ID=42\n' > "$T/cfg/telegram.env"
rm -rf "$T/state"; run "telegram.env is data, not code" STUB_CODE=1 STUB_OUT="STALE PaymasterV4 age=9s limit=1s"
expect "a stray exit line is refused as data, never run (the watcher logs and records the run)" \
  '[ "$(sent)" = 0 ] && grep -q "not TELEGRAM_BOT_TOKEN= or TELEGRAM_CHAT_ID= -- cannot alert" "$T/log" && [ -f "$T/state/last-run" ]'
printf 'TELEGRAM_BOT_TOKEN="tok-SECRET"\n# chat\nTELEGRAM_CHAT_ID=42\n' > "$T/cfg/telegram.env"; rm -rf "$T/state"
run "telegram.env: quoted token and a comment" STUB_CODE=1 STUB_OUT="STALE PaymasterV4 age=9s limit=1s"
expect "CONTROL accepted; the quoted token is used" '[ "$(sent)" = 1 ] && grep -q "CFG.*bottok-SECRET/sendMessage" "$T/sent.cfg"'
for bad in 'TELEGRAM_CHAT_ID="42" # current' 'TELEGRAM_CHAT_ID="42' "$(printf 'TELEGRAM_CHAT_ID=42\r')"; do
  printf 'TELEGRAM_BOT_TOKEN=tok-SECRET\n%s\n' "$bad" > "$T/cfg/telegram.env"; rm -rf "$T/state"
  run "telegram.env: malformed chat line" STUB_CODE=1 STUB_OUT="STALE PaymasterV4 age=9s limit=1s"
  expect "refused, nothing sent, said in the log" '[ "$(sent)" = 0 ] && grep -qE "TELEGRAM_CHAT_ID has an unsupported value|outside printable ASCII" "$T/log"'
done
for bad in 'TELEGRAM_CHAT_ID =42' 'TELEGRAM_CHAT_ID=42;' "$(printf 'TELEGRAM_CHAT_ID=4\3022')"; do
  printf 'TELEGRAM_BOT_TOKEN=tok-SECRET\n%s\n' "$bad" > "$T/cfg/telegram.env"; rm -rf "$T/state"
  run "telegram.env: a line run.sh would refuse" STUB_CODE=1 STUB_OUT="STALE PaymasterV4 age=9s limit=1s"
  expect "refused, nothing sent, said in the log" '[ "$(sent)" = 0 ] && grep -q "telegram.env.*cannot alert" "$T/log"'
done
printf 'TELEGRAM_BOT_TOKEN=tok-SECRET\nTELEGRAM_CHAT_ID=41\nTELEGRAM_CHAT_ID=42\n' > "$T/cfg/telegram.env"; rm -rf "$T/state"
run "telegram.env: chat set twice" STUB_CODE=1 STUB_OUT="STALE PaymasterV4 age=9s limit=1s"
expect "refused rather than picking one" '[ "$(sent)" = 0 ] && grep -q "TELEGRAM_CHAT_ID is set twice" "$T/log"'
cp "$T/tg.good" "$T/cfg/telegram.env"; rm -rf "$T/state"
run "re-arm the first alert" STUB_CODE=1 STUB_OUT="STALE PaymasterV4 age=9s limit=1s"
expect "the alert names the entry (the config dir is cfg)" 'grep -q "\[price-keeper cfg\] ALERT" "$T/sent"'
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
run "one item recovers, the set only shrinks" STUB_CODE=1 STUB_OUT="STALE PaymasterV4 y"
expect "not repeated within the interval" '[ "$(sent)" = 0 ] && grep -q "not repeating" "$T/log"'
run "the item flaps back" STUB_CODE=1 STUB_OUT="STALE SuperPaymaster x
STALE PaymasterV4 y"
expect "not repeated: it was in the last alert" '[ "$(sent)" = 0 ]'
rm -rf "$T/state"
run "one STALE item" STUB_CODE=1 STUB_OUT="STALE PaymasterV4 y"
expect "alerts" '[ "$(sent)" = 1 ]'
run "a different item of the same kind" STUB_CODE=1 STUB_OUT="STALE SuperPaymaster x"
expect "re-alerts at once" '[ "$(sent)" = 1 ] && grep -q "STALE SuperPaymaster" "$T/sent"'

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
env STALE_WATCH_STATE_DIR="$T/state" STALE_WATCH_STATUS_CMD="$T/status" \
  STALE_WATCH_CURL="$T/curl" SENT="$T/sent.bg" STUB_SLEEP=4 STALE_WATCH_STATUS_TIMEOUT=30 \
  bash "$T/cfg/stale-watch.sh" > "$T/log.bg" 2>&1 & bg=$!
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
  # a launchable entry "t" (run.sh would start it); each case changes one thing
  base='KEEPER_ENTRY=t
KEEPER_NETWORK=op-sepolia
KEEPER_SDK_DIR="~/Dev/aastar/aastar-sdk-t"
KEEPER_SUPERPAYMASTER=0x00000000000000000000000000000000000000a1
KEEPER_PAYMASTER=
KEEPER_HARD_MAX_FEE_GWEI=2
KEEPER_MIN_BALANCE_WEI=1000000000000000'
  # A stub viem that answers chain 11155420, block 7 at time 5000, every cache updated at 4000 (age
  # 1000s), limit 4200s, balance 5e15 wei, and records every read with its block. STUB_* change one answer.
  fake='v="$H/Dev/aastar/aastar-sdk-t/packages/core/node_modules/viem"; mkdir -p "$v"
    echo "{\"name\":\"viem\",\"main\":\"index.js\"}" > "$v/package.json"
    cat > "$v/index.js" <<"J"
const fs=require("fs"),log=s=>fs.appendFileSync(process.env.READS,s+"\n");
module.exports={http:u=>{log("rpc "+u);return 0},parseAbi:()=>[],formatEther:w=>String(Number(w)/1e18),createPublicClient:()=>({
  getChainId:async()=>Number(process.env.STUB_CHAIN||11155420),
  getBlock:async()=>({number:7n,timestamp:5000n}),
  getBalance:async({address,blockNumber})=>{log("balance "+address+"@"+blockNumber);return 5000000000000000n},
  readContract:async({address,functionName,blockNumber})=>{log(address+" "+functionName+"@"+blockNumber);
    return functionName==="cachedPrice"?[1n,BigInt(process.env.STUB_UPDATED||4000)]:4200n}})};
J
    echo RPC_URL=http://127.0.0.1:9 > "$E/rpc.env"; echo 0x00000000000000000000000000000000000000c1 > "$E/address"'
  # mjs NAME SETUP [ENV...] -- a fresh fake HOME and entry dir from $base, then SETUP, then status.mjs
  mjs() {
    local H="$T/home-$1"; local E="$H/.config/aastar-price-keeper-t"; mkdir -p "$E"
    printf '%s\n' "$base" > "$E/entry.env"; cp "$HERE/status.mjs" "$E/status.mjs"; echo KEEPER_PRIVATE_KEY=0x1111111111111111111111111111111111111111111111111111111111111111 > "$E/key.env"
    eval "$2"; : > "$T/reads"; CUR="status.mjs: $1"; shift 2
    out=$(env "$@" HOME="$H" READS="$T/reads" node "$E/status.mjs" 2>&1); rc=$?
  }
  und() { expect "exit 2, UNDETERMINED $1" '[ "$rc" = 2 ] && printf "%s" "$out" | grep -q "^UNDETERMINED.*'"$1"'"'; }
  mjs no-viem ':'; und "Cannot find module"
  mjs no-rpc-env "$fake; rm \$E/rpc.env"; und ENOENT
  mjs no-rpc-url "$fake; echo '# none' > \$E/rpc.env"; und "RPC_URL missing"
  mjs rpc-env-extra "$fake; echo KEEPER_PAYMASTER=0x00000000000000000000000000000000000000b2 >> \$E/rpc.env"; und "KEEPER_PAYMASTER is not allowed"
  mjs no-address "$fake; rm \$E/address"; und ENOENT
  mjs no-entry-env "$fake; rm \$E/entry.env"; und ENOENT
  mjs bad-superpaymaster "$fake; sed -i '' 's/=0x0*a1\$/=0x12/' \$E/entry.env"; und "KEEPER_SUPERPAYMASTER missing"
  mjs bad-paymaster "$fake; sed -i '' 's/^KEEPER_PAYMASTER=\$/KEEPER_PAYMASTER=0x12/' \$E/entry.env"; und "KEEPER_PAYMASTER is not an address"
  mjs no-min-balance "$fake; sed -i '' '/MIN_BALANCE/d' \$E/entry.env"; und "KEEPER_MIN_BALANCE_WEI missing"
  mjs no-fee-ceiling "$fake; sed -i '' '/HARD_MAX_FEE/d' \$E/entry.env"; und "KEEPER_HARD_MAX_FEE_GWEI missing"
  mjs a-command-line "$fake; echo false >> \$E/entry.env"; und "line 8 is not NAME=value"
  mjs export-form "$fake; sed -i '' 's/^KEEPER_PAYMASTER=/export KEEPER_PAYMASTER=/' \$E/entry.env"; und "is not NAME=value"
  mjs set-twice "$fake; echo KEEPER_PAYMASTER=0x00000000000000000000000000000000000000b2 >> \$E/entry.env"; und "KEEPER_PAYMASTER is set twice"
  mjs wrong-entry-name "$fake; sed -i '' 's/^KEEPER_ENTRY=t/KEEPER_ENTRY=u/' \$E/entry.env"; und "does not name this directory"
  mjs mainnet-linked-key "$fake; sed -i '' 's/=op-sepolia/=op-mainnet/' \$E/entry.env; echo x > \$H/k; rm \$E/key.env; echo KEEPER_PRIVATE_KEY=0x1111111111111111111111111111111111111111111111111111111111111111 > \$H/k; ln -s \$H/k \$E/key.env"; und "a mainnet entry needs its own key"
  mjs wrong-chain "$fake" STUB_CHAIN=11155111; und "is chain 11155111, entry t is chain 11155420"
  mjs cache-after-block "$fake" STUB_UPDATED=5100; und "cache time is after its block time"

  mjs bad-interval "$fake; echo KEEPER_POLL_INTERVAL=1s >> \$E/entry.env"; und "KEEPER_POLL_INTERVAL must be an integer"
  mjs no-key-env "$fake; rm \$E/key.env"; und ENOENT
  mjs bad-telegram "$fake; echo 'TELEGRAM_BOT_TOKEN=a b' > \$E/telegram.env"; und "telegram.env line 1: TELEGRAM_BOT_TOKEN has an unsupported value"
  mjs sdk-dotenv "$fake; touch \$H/Dev/aastar/aastar-sdk-t/.env.op-sepolia"; und "run.sh refuses to start"
  mjs non-ascii "$fake; printf 'KEEPER_ETHUSD_URL=a\\302\\240b\\n' >> \$E/entry.env"; und "byte outside printable ASCII"
  mjs inherited-dir "$fake" KEEPER_CONFIG_DIR=/nonexistent
  expect "an inherited KEEPER_CONFIG_DIR is ignored (still checks its own dir)" '[ "$rc" = 0 ]'
  mjs bad-key-format "$fake; echo KEEPER_PRIVATE_KEY=0xk > \$E/key.env"; und "must be 0x and 64 hex digits"
  mjs key-fifo "$fake; rm \$E/key.env; mkfifo \$E/key.env"; und "key.env is not a regular file"
  mjs network-proto "$fake; sed -i '' 's/=op-sepolia/=constructor/' \$E/entry.env"; und "KEEPER_NETWORK must be"
  mjs address-two-lines "$fake; printf '0x0000000000000000000\\n000000000000000000000c1\\n' > \$E/address"; und "exactly one address on one line"
  mjs no-v4 "$fake"
  expect "exit 0, SuperPaymaster only, every read at block 7" \
    '[ "$rc" = 0 ] && printf "%s" "$out" | grep -q "^FRESH SuperPaymaster 0x0*a1 age=1000s" && ! printf "%s" "$out" | grep -q PaymasterV4 &&
     [ "$(tr "\n" " " < "$T/reads")" = "rpc http://127.0.0.1:9 0x00000000000000000000000000000000000000a1 cachedPrice@7 0x00000000000000000000000000000000000000a1 priceStalenessThreshold@7 balance 0x00000000000000000000000000000000000000c1@7 " ]'
  mjs with-v4 "$fake; sed -i '' 's/^KEEPER_PAYMASTER=\$/KEEPER_PAYMASTER=0x00000000000000000000000000000000000000b2/' \$E/entry.env"
  expect "a V4 in entry.env is checked too" '[ "$rc" = 0 ] && printf "%s" "$out" | grep -q "^FRESH PaymasterV4 0x0*b2" && grep -q "^0x0*b2 cachedPrice@7" "$T/reads"'
  mjs low-gas "$fake; sed -i '' 's/^KEEPER_MIN_BALANCE_WEI=.*/KEEPER_MIN_BALANCE_WEI=6000000000000000/' \$E/entry.env"
  expect "the floor comes from entry.env: 0.005 ETH below 0.006 is LOW_GAS, exit 1" '[ "$rc" = 1 ] && printf "%s" "$out" | grep -q "^LOW_GAS keeper"'
  mjs stale "$fake" STUB_UPDATED=100
  expect "a cache older than its limit is STALE, exit 1" '[ "$rc" = 1 ] && printf "%s" "$out" | grep -q "^STALE SuperPaymaster"'
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
