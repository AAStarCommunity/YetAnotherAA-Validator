#!/usr/bin/env bash
# Observe or control one price-keeper entry. On any other machine it re-runs itself on the Mac Mini over SSH.
#   keeperctl.sh <entry> status | pause | resume | restart | logs [lines] | dry-run
#   keeperctl.sh list
# <entry> is the name in entries/<entry>.env, e.g. op-sepolia. Each entry has two launchd jobs,
# io.aastar.price-keeper-<entry> (the keeper) and io.aastar.price-keeper-<entry>-stale-watch.
#
# pause  = disable both jobs (and confirm launchd records both as disabled), then boot both out, then
#          wait until no process of the keeper job's process group is left. Disabled first, so neither
#          KeepAlive, a reboot nor a stray bootstrap can start a new one meanwhile. PAUSED (exit 0)
#          only when all of that is confirmed; any failure is NOT PAUSED (exit 1).
# resume = check both plists name their own labels, enable + bootstrap both, then wait until the
#          keeper job's process runs scripts/keeper.ts with its worker child, and 10 s later is still
#          the same process (launchd's run count unchanged, so no KeepAlive restart in between) with
#          its child (run.sh refuses a bad config within a second). RESUMED (exit 0) only then.
# restart = kickstart -k the keeper job (it must be loaded; a paused entry stays paused).
# pause, resume and install.sh of one entry are serialized by a lock directory holding the holder's
# pid; a lock whose holder is gone is taken over.
set -uo pipefail
HOST_ALIAS="${KEEPER_SSH_HOST:-mac-mini}"

# KEEPER_LOCAL=1 runs here instead (test_keeperctl.sh uses it with a throwaway entry).
if [ -z "${KEEPER_LOCAL:-}" ] && [ "$(scutil --get LocalHostName 2>/dev/null)" != "Jasons-Mac-mini" ]; then
  q=""; for a in "$@"; do q+=" $(printf '%q' "$a")"; done
  exec ssh -o BatchMode=yes -o ConnectTimeout=10 "$HOST_ALIAS" "/bin/bash \"\$HOME/.config/aastar-price-keeper-bin/keeperctl.sh\"$q"
fi

export PATH="/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin"
# Only a test (KEEPER_LOCAL=1) may swap launchctl for a stub.
LAUNCHCTL=launchctl; [ -n "${KEEPER_LOCAL:-}" ] && LAUNCHCTL="${KEEPER_LAUNCHCTL:-launchctl}"
usage() { echo "usage: keeperctl.sh <entry> status|pause|resume|restart|logs [lines]|dry-run   |   keeperctl.sh list" >&2; exit 64; }
DOM="gui/$(id -u)"
LA="$HOME/Library/LaunchAgents"
# 0 loaded, 1 not loaded (launchctl: "Could not find service", exit 113), 2 launchctl failed otherwise
job_state() { "$LAUNCHCTL" print "$DOM/$1" >/dev/null 2>&1; case $? in 0) return 0 ;; 113) return 1 ;; *) return 2 ;; esac; }
loaded() { job_state "$1"; }
disabled() { "$LAUNCHCTL" print-disabled "$DOM" 2>/dev/null | grep -qxF "		\"$1\" => disabled"; }

if [ "${1:-}" = list ]; then
  [ $# = 1 ] || usage
  for d in "$HOME"/.config/aastar-price-keeper-*/; do
    e="$(basename "$d")"; e="${e#aastar-price-keeper-}"
    [ -f "$d/entry.env" ] || continue
    printf '%-14s keeper %-10s stale-watch %s\n' "$e" \
      "$(loaded "io.aastar.price-keeper-$e" && echo loaded || echo unloaded)" \
      "$(loaded "io.aastar.price-keeper-$e-stale-watch" && echo loaded || echo unloaded)"
  done
  exit 0
fi

ENTRY="${1:-}"; CMD="${2:-status}"
# the same names install.sh accepts: no reserved word, no name whose keeper label is another's watcher
[[ "$ENTRY" =~ ^[a-z0-9][a-z0-9-]*$ ]] || usage
case "$ENTRY" in bin | list | stale-watch | *-stale-watch) usage ;; esac
CONFIG_DIR="$HOME/.config/aastar-price-keeper-$ENTRY"
[ -f "$CONFIG_DIR/entry.env" ] || { echo "no entry $ENTRY: $CONFIG_DIR/entry.env is missing (run install.sh $ENTRY)" >&2; exit 66; }
LABEL="io.aastar.price-keeper-$ENTRY"
WATCH="$LABEL-stale-watch"
LOG="$HOME/Library/Logs/aastar-price-keeper-$ENTRY.log"
job_pid() { "$LAUNCHCTL" print "$DOM/$LABEL" 2>/dev/null | awk '/^\tpid = /{print $3}'; }
job_runs() { "$LAUNCHCTL" print "$DOM/$LABEL" 2>/dev/null | awk '/^\truns = /{print $3}'; }
group_of() { ps -o pgid= -p "$1" 2>/dev/null | tr -d ' '; }
# This entry's keeper processes, found two independent ways: the job's process group, and the
# keeper command line run.sh builds from this entry's network and SuperPaymaster (so a process that
# left the group, or a group id that could not be read, is still seen).
# Read as run.sh reads them (one level of double quotes dropped), matched without case. This can only
# over-match (two entries with the same network and SuperPaymaster block each other's PAUSED), the
# safe direction; a keeper still running with values changed since it started is covered by the group.
field() { sed -nE "s/^$1=\"?([^\"]*)\"?\$/\\1/p" "$CONFIG_DIR/entry.env" | tail -1; }
SIG_NET="$(field KEEPER_NETWORK)"; SIG_SP="$(field KEEPER_SUPERPAYMASTER)"
keeper_procs() {
  { [ -n "${1:-}" ] && pgrep -g "$1" 2>/dev/null
    [ -n "$SIG_NET" ] && [ -n "$SIG_SP" ] && pgrep -if "scripts/keeper\.ts --network $SIG_NET --superpaymaster $SIG_SP" 2>/dev/null; } |
    sort -u | tr '\n' ' '
}
# take_lock FILE FD: an exclusive flock(2) on FILE through descriptor FD of this shell. The kernel
# drops it when this process exits, however it exits, so there is no stale lock and no takeover race.
take_lock() {
  eval "exec $2>>\"\$1\"" || return 3
  perl -e 'use Fcntl qw(:flock); open(my $f, ">&=", $ARGV[0]) or exit 3; flock($f, LOCK_EX | LOCK_NB) or exit 75; exit 0' "$2"
}
lock() {
  [ -d "$CONFIG_DIR" ] && [ -w "$CONFIG_DIR" ] || { echo "$CONFIG_DIR is missing or not writable" >&2; exit 66; }
  take_lock "$CONFIG_DIR/.keeperctl.lock" 9; case $? in
    0) ;; 75) echo "another keeperctl.sh / install.sh for $ENTRY holds $CONFIG_DIR/.keeperctl.lock" >&2; exit 75 ;;
    *) echo "cannot lock $CONFIG_DIR/.keeperctl.lock" >&2; exit 75 ;; esac
}
not_paused() { echo "NOT PAUSED $ENTRY: $*" >&2; exit 1; }
do_pause() { # the pause steps; exits 0 with PAUSED, or 1 via not_paused (no lock: the caller holds it)
  # Without both fields the command-line scan cannot run, so a keeper outside the job's group
  # could not be seen: unconfirmed is NOT PAUSED, never an empty scan.
  [ -n "$SIG_NET" ] && [ -n "$SIG_SP" ] || not_paused "entry.env has no KEEPER_NETWORK or KEEPER_SUPERPAYMASTER to find its keeper by"
  p="$(job_pid)"; g=""; [ -n "$p" ] && g="$(group_of "$p")"
  for j in "$LABEL" "$WATCH"; do
    "$LAUNCHCTL" disable "$DOM/$j" || not_paused "launchctl disable $j failed"
    disabled "$j" || not_paused "launchd does not list $j as disabled"
  done
  for j in "$LABEL" "$WATCH"; do
    job_state "$j"; st=$?
    [ "$st" = 2 ] && not_paused "launchctl print $j failed"
    [ "$st" = 0 ] && { "$LAUNCHCTL" bootout "$DOM/$j" 2>/dev/null || true; }   # judged below, by state
  done
  # bootout sends SIGTERM and waits; the keeper exits within 15 s (its own shutdown budget).
  for _ in $(seq 1 30); do
    job_state "$LABEL"; a=$?; job_state "$WATCH"; b=$?
    { [ "$a" = 2 ] || [ "$b" = 2 ]; } && not_paused "launchctl print failed while waiting"
    if [ "$a" = 1 ] && [ "$b" = 1 ] && [ -z "$(keeper_procs "$g")" ]; then
      echo "PAUSED $ENTRY $(date -u +%Y-%m-%dT%H:%M:%SZ) (stopped: ${p:-none running}${g:+, process group $g})"; exit 0
    fi
    sleep 1
  done
  not_paused "keeper job state $a, keeper processes left: $(keeper_procs "$g")"
}

case "$CMD" in
  status)
    for j in "$LABEL" "$WATCH"; do
      if loaded "$j"; then echo "$j: loaded"; "$LAUNCHCTL" print "$DOM/$j" | grep -E '^\s+(state|pid|runs|last exit code) ='
      else echo "$j: not loaded"; fi
      "$LAUNCHCTL" print-disabled "$DOM" | grep -F "\"$j\"" || true
    done
    grep -E '^TICK ' "$LOG" 2>/dev/null | tail -1
    grep -E '^(confirmed|updated):' "$LOG" 2>/dev/null | tail -2
    exec node "$CONFIG_DIR/status.mjs"
    ;;
  pause)
    lock
    do_pause
    ;;
  resume)
    lock
    [ ! -e "$CONFIG_DIR/INSTALL-INCOMPLETE" ] ||
      { echo "NOT RESUMED $ENTRY: an install did not complete ($(cat "$CONFIG_DIR/INSTALL-INCOMPLETE")); re-run install.sh $ENTRY" >&2; exit 1; }
    for j in "$LABEL" "$WATCH"; do
      [ -f "$LA/$j.plist" ] || { echo "missing $LA/$j.plist (run install.sh $ENTRY)" >&2; exit 66; }
      [ "$(plutil -extract Label raw -o - "$LA/$j.plist" 2>/dev/null)" = "$j" ] ||
        { echo "$LA/$j.plist does not have Label $j (reinstall: install.sh $ENTRY)" >&2; exit 65; }
    done
    for j in "$LABEL" "$WATCH"; do
      "$LAUNCHCTL" enable "$DOM/$j" || { echo "launchctl enable $j failed" >&2; exit 1; }
      loaded "$j" || "$LAUNCHCTL" bootstrap "$DOM" "$LA/$j.plist" || { echo "launchctl bootstrap $j failed" >&2; exit 1; }
    done
    end=$((SECONDS + 60))
    while [ "$SECONDS" -lt "$end" ]; do
      p="$(job_pid)"
      # the job's process is the keeper (run.sh exec'd tsx) and has its worker child
      if [ -n "$p" ] && ps -o command= -p "$p" 2>/dev/null | grep -q 'scripts/keeper\.ts' && [ -n "$(pgrep -P "$p")" ]; then
        r="$(job_runs)"; [[ "$r" =~ ^[0-9]+$ ]] || { sleep 1; continue; }
        [ $((SECONDS + 11)) -le "$end" ] || break   # no sample that would end past the bound
        sleep 10
        # still the same process, not restarted by KeepAlive in between, worker still there
        if [ "$(job_pid)" = "$p" ] && [ "$(job_runs)" = "$r" ] && [ -n "$(pgrep -P "$p")" ] && loaded "$WATCH"; then
          echo "RESUMED $ENTRY $(date -u +%Y-%m-%dT%H:%M:%SZ) pid $p"; exit 0
        fi
      fi
      sleep 1
    done
    # A failed resume does not leave the entry enabled for KeepAlive to keep restarting: it is paused
    # again, by the same steps as pause, and the result of that is part of the answer.
    if out="$(do_pause 2>&1)"; then
      echo "NOT RESUMED $ENTRY: the keeper is not running scripts/keeper.ts (see keeperctl.sh $ENTRY logs); the entry is paused again: $out" >&2
    else
      echo "NOT RESUMED $ENTRY: the keeper is not running scripts/keeper.ts, AND pausing it again failed: $out" >&2
    fi
    exit 1
    ;;
  restart)
    loaded "$LABEL" || { echo "$LABEL is not loaded (paused?); use resume" >&2; exit 1; }
    "$LAUNCHCTL" kickstart -k "$DOM/$LABEL"
    ;;
  logs) tail -n "${3:-50}" "$LOG" | sed -E 's#https?://[^ ]*#<url>#g' ;;
  dry-run) exec bash "$CONFIG_DIR/run.sh" --once --dry-run ;;
  *) usage ;;
esac
