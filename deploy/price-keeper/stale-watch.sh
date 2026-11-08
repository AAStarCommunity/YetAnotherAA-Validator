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
#   status exit 2, or a status run that hangs        alert after UNDETERMINED_AFTER checks in a row
#   back to exit 0 after an alert                    one RECOVERED message
#   state that cannot be written                     alert at once (it would otherwise mute the rules above)
set -uo pipefail
export PATH="/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin"
CONFIG_DIR="${KEEPER_CONFIG_DIR:-$HOME/.config/aastar-price-keeper}"
STATE_DIR="${STALE_WATCH_STATE_DIR:-$CONFIG_DIR/stale-watch}"
STATUS_CMD="${STALE_WATCH_STATUS_CMD:-node $CONFIG_DIR/status.mjs}"
STATUS_TIMEOUT="${STALE_WATCH_STATUS_TIMEOUT:-120}"
REALERT_SECONDS="${STALE_WATCH_REALERT_SECONDS:-3600}"
UNDETERMINED_AFTER="${STALE_WATCH_UNDETERMINED_AFTER:-3}"
LOCK_STALE_SECONDS="${STALE_WATCH_LOCK_STALE_SECONDS:-900}"
TG_API="${STALE_WATCH_TG_API:-https://api.telegram.org}"
CURL="${STALE_WATCH_CURL:-curl}"   # the test swaps in a stub

now() { date -u +%s; }
log() { echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*"; }

# A decimal integer from a state file. Leading zeros are dropped (bash would read 0008 as bad octal);
# empty, non-digit or longer than 12 digits counts as 0.
read_int() {
  local v; v="$(cat "$1" 2>/dev/null)"
  case "$v" in ''|*[!0-9]*) echo 0; return ;; esac
  [ "${#v}" -le 12 ] || { echo 0; return; }
  echo $((10#$v))
}

send() { # text -> 0 only when curl succeeded and Telegram answered ok:true
  [ -f "$CONFIG_DIR/telegram.env" ] || { log "no telegram.env -- cannot alert: $1"; return 1; }
  local TELEGRAM_BOT_TOKEN="" TELEGRAM_CHAT_ID=""
  # shellcheck disable=SC1091
  . "$CONFIG_DIR/telegram.env"
  [ -n "$TELEGRAM_BOT_TOKEN" ] && [ -n "$TELEGRAM_CHAT_ID" ] || { log "telegram.env incomplete -- cannot alert"; return 1; }
  # The token goes through curl's config on stdin, so it never appears in the process list.
  local resp rc errf; errf="$(mktemp)"
  resp="$(printf 'url = "%s/bot%s/sendMessage"\n' "$TG_API" "$TELEGRAM_BOT_TOKEN" |
    $CURL -sS -m 20 -K - --data-urlencode "chat_id=$TELEGRAM_CHAT_ID" --data-urlencode "text=$1" 2>"$errf")"
  rc=$?
  # Delivered only if curl succeeded and the whole body parses as JSON whose top-level ok is boolean true.
  if [ "$rc" -eq 0 ] && [ "$(printf '%s' "$resp" | plutil -type ok - 2>/dev/null)" = bool ] &&
     [ "$(printf '%s' "$resp" | plutil -extract ok raw -o - - 2>/dev/null)" = true ]; then
    rm -f "$errf"; return 0
  fi
  log "telegram send FAILED (curl exit $rc): $(printf '%s' "$resp" | head -c 200) $(head -c 200 "$errf")"
  rm -f "$errf"; return 1
}

put() { # file value -> atomic replace; 1 on failure
  local tmp="$1.tmp.$$"
  printf '%s\n' "$2" > "$tmp" 2>/dev/null && mv -f "$tmp" "$1" 2>/dev/null && return 0
  rm -f "$tmp" 2>/dev/null; return 1
}

host="$(scutil --get LocalHostName 2>/dev/null || hostname)"

if [ "${1:-}" = "--test" ]; then
  if send "[price-keeper stale-watch] TEST from $host at $(date -u +%Y-%m-%dT%H:%M:%SZ) -- alerts reach this chat"; then
    log "test message sent"; exit 0
  fi
  exit 1
fi

state_broken() {
  log "state dir $STATE_DIR not writable: $1"
  send "[price-keeper] stale-watch on $host cannot write its state ($1) -- alerts may be muted until fixed"
  exit 1
}
mkdir -p "$STATE_DIR" 2>/dev/null || state_broken "mkdir failed"

# One check at a time (a manual run can overlap the scheduled one). perl takes an exclusive flock on
# the lock file and runs the rest of this script as its child; the kernel drops the lock when perl
# exits, so a killed run cannot leave a lock behind.
if [ -z "${STALE_WATCH_LOCKED:-}" ]; then
  STALE_WATCH_LOCKED=1 perl -e '
    use Fcntl qw(:flock); my $lock = shift;
    open(my $fh, ">>", $lock) or exit 3;
    flock($fh, LOCK_EX | LOCK_NB) or exit 75;
    system(@ARGV); exit($? == -1 ? 127 : ($? & 127) ? 128 + ($? & 127) : $? >> 8);
  ' "$STATE_DIR/lock" bash "$0" "$@"
  rc=$?
  case "$rc" in
    75) log "another check holds the lock -- skipping this run"; exit 0 ;;
    3) state_broken "cannot open lock file" ;;
  esac
  exit "$rc"
fi

# Bounded run: a hung RPC call would otherwise keep this job alive, and launchd starts no new run
# while one is still going. A timeout counts as UNDETERMINED.
# The command runs in its own process group and the whole group is killed on timeout, so a
# descendant holding the output pipe cannot keep this run waiting.
out="$(perl -e '
  my $t = shift; my $pid = fork; defined $pid or exit 127;
  if (!$pid) { setpgrp(0, 0); exec @ARGV; exit 127 }
  $SIG{ALRM} = sub { kill "TERM", -$pid, $pid; sleep 2; kill "KILL", -$pid, $pid; waitpid($pid, 0); exit 142 };
  alarm $t; waitpid($pid, 0);
  exit(($? & 127) ? 128 + ($? & 127) : $? >> 8);
' "$STATUS_TIMEOUT" $STATUS_CMD 2>&1)"; code=$?
if [ "$code" -eq 142 ]; then out="UNDETERMINED status did not finish within ${STATUS_TIMEOUT}s"; code=2; fi
log "status exit $code: $(printf '%s' "$out" | tr '\n' ';')"
now_s="$(now)"
put "$STATE_DIR/last-run" "$now_s $code" || state_broken "last-run"   # evidence that the job fires

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
    put "$undet_file" 0 || state_broken "undetermined-count"
    if [ -f "$stale_stamp" ] || [ -f "$undet_stamp" ]; then
      if send "[price-keeper] RECOVERED on $host: $(printf '%s' "$out" | tr '\n' ' ')"; then
        rm -f "$stale_stamp" "$undet_stamp" || state_broken "clear stamps"
      fi
    fi
    ;;
  1)
    put "$undet_file" 0 || state_broken "undetermined-count"
    if due "$stale_stamp"; then
      bad="$(printf '%s\n' "$out" | grep -E '^(STALE|LOW_GAS)' | tr '\n' ' ')"
      if send "[price-keeper] ALERT on $host: ${bad:-status exit 1 }-- run keeperctl.sh status"; then
        put "$stale_stamp" "$now_s" || state_broken "alerted-stale"
      fi
    else
      log "still failing; not repeating within ${REALERT_SECONDS}s"
    fi
    ;;
  *)
    n=$(( $(read_int "$undet_file") + 1 ))
    put "$undet_file" "$n" || state_broken "undetermined-count"
    if [ "$n" -ge "$UNDETERMINED_AFTER" ] && due "$undet_stamp"; then
      if send "[price-keeper] UNDETERMINED on $host for $n checks in a row: $(printf '%s' "$out" | tail -1)"; then
        put "$undet_stamp" "$now_s" || state_broken "alerted-undetermined"
      fi
    fi
    ;;
esac
exit 0
