#!/usr/bin/env bash
# External check on the price keeper, run by launchd on the Mac Mini every 10 minutes.
# It does not trust the keeper process: it runs status.mjs, which reads the on-chain caches and the
# keeper balance, and sends a Telegram alert through the same bot and chat the keeper uses.
#
#   stale-watch.sh          one check (what launchd runs)
#   stale-watch.sh --test   send one test message and exit
#
# Alert rules:
#   status exit 1 (a cache STALE or keeper LOW_GAS)  alert at once, repeat at most every REALERT_SECONDS
#   status exit 2 (could not tell, e.g. RPC failed)  alert after UNDETERMINED_AFTER checks in a row
#   back to exit 0 after an alert                    one RECOVERED message
set -uo pipefail
export PATH="/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin"
CONFIG_DIR="${KEEPER_CONFIG_DIR:-$HOME/.config/aastar-price-keeper}"
STATE_DIR="${STALE_WATCH_STATE_DIR:-$CONFIG_DIR/stale-watch}"
STATUS_CMD="${STALE_WATCH_STATUS_CMD:-node $CONFIG_DIR/status.mjs}"
REALERT_SECONDS="${STALE_WATCH_REALERT_SECONDS:-3600}"
UNDETERMINED_AFTER="${STALE_WATCH_UNDETERMINED_AFTER:-3}"
TG_API="${STALE_WATCH_TG_API:-https://api.telegram.org}"
CURL="${STALE_WATCH_CURL:-curl}"   # the test swaps in a stub
mkdir -p "$STATE_DIR"

now() { date -u +%s; }
log() { echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*"; }

# Reads a non-negative integer from a state file; anything else counts as 0.
read_int() { local v; v="$(cat "$1" 2>/dev/null)"; case "$v" in ''|*[!0-9]*) echo 0 ;; *) echo "$v" ;; esac; }

send() { # text -> 0 when Telegram accepted it
  [ -f "$CONFIG_DIR/telegram.env" ] || { log "no telegram.env -- cannot alert: $1"; return 1; }
  local TELEGRAM_BOT_TOKEN="" TELEGRAM_CHAT_ID=""
  # shellcheck disable=SC1091
  . "$CONFIG_DIR/telegram.env"
  [ -n "$TELEGRAM_BOT_TOKEN" ] && [ -n "$TELEGRAM_CHAT_ID" ] || { log "telegram.env incomplete -- cannot alert"; return 1; }
  # The token goes through curl's config on stdin, so it never appears in the process list.
  local resp
  resp="$(printf 'url = "%s/bot%s/sendMessage"\n' "$TG_API" "$TELEGRAM_BOT_TOKEN" |
    $CURL -sS -m 20 -K - --data-urlencode "chat_id=$TELEGRAM_CHAT_ID" --data-urlencode "text=$1" 2>&1)"
  case "$resp" in *'"ok":true'*) return 0 ;; esac
  log "telegram send FAILED: $(printf '%s' "$resp" | head -c 200)"
  return 1
}

host="$(scutil --get LocalHostName 2>/dev/null || hostname)"

if [ "${1:-}" = "--test" ]; then
  if send "[price-keeper stale-watch] TEST from $host at $(date -u +%Y-%m-%dT%H:%M:%SZ) -- alerts reach this chat"; then
    log "test message sent"; exit 0
  fi
  exit 1
fi

out="$($STATUS_CMD 2>&1)"; code=$?
log "status exit $code: $(printf '%s' "$out" | tr '\n' ';')"
now_s="$(now)"
echo "$now_s $code" > "$STATE_DIR/last-run"   # evidence that the job fires

# One stamp per alert kind, so an UNDETERMINED alert never mutes a later STALE one.
stale_stamp="$STATE_DIR/alerted-stale"
undet_stamp="$STATE_DIR/alerted-undetermined"
undet_file="$STATE_DIR/undetermined-count"

due() { # stamp-file -> 0 when no alert is outstanding or the last one is older than REALERT_SECONDS
  [ -f "$1" ] || return 0
  local last; last="$(read_int "$1")"
  # A stamp in the future (clock moved back) counts as expired, so it can never mute alerts.
  [ "$last" -gt "$now_s" ] || [ $((now_s - last)) -ge "$REALERT_SECONDS" ]
}

case "$code" in
  0)
    echo 0 > "$undet_file"
    if [ -f "$stale_stamp" ] || [ -f "$undet_stamp" ]; then
      send "[price-keeper] RECOVERED on $host: $(printf '%s' "$out" | tr '\n' ' ')" && rm -f "$stale_stamp" "$undet_stamp"
    fi
    ;;
  1)
    echo 0 > "$undet_file"
    if due "$stale_stamp"; then
      bad="$(printf '%s\n' "$out" | grep -E '^(STALE|LOW_GAS)' | tr '\n' ' ')"
      send "[price-keeper] ALERT on $host: ${bad:-status exit 1 }-- run keeperctl.sh status" && echo "$now_s" > "$stale_stamp"
    else
      log "still failing; not repeating within ${REALERT_SECONDS}s"
    fi
    ;;
  *)
    n=$(( $(read_int "$undet_file") + 1 )); echo "$n" > "$undet_file"
    if [ "$n" -ge "$UNDETERMINED_AFTER" ] && due "$undet_stamp"; then
      send "[price-keeper] UNDETERMINED on $host for $n checks in a row: $(printf '%s' "$out" | tail -1)" \
        && echo "$now_s" > "$undet_stamp"
    fi
    ;;
esac
exit 0
