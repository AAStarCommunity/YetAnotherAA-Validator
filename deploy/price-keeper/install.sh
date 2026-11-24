#!/usr/bin/env bash
# Install or update one price-keeper entry on the machine that runs it (the Mac Mini):
#   bash deploy/price-keeper/install.sh <entry>
# <entry> names entries/<entry>.env. The script
#   - copies run.sh, stale-watch.sh, status.mjs and entries/<entry>.env (as entry.env) into
#     ~/.config/aastar-price-keeper-<entry>/ (mode 700), backing up any file it replaces;
#   - copies keeperctl.sh into ~/.config/aastar-price-keeper-bin/;
#   - writes the two plists io.aastar.price-keeper-<entry>{,-stale-watch}.plist to ~/Library/LaunchAgents;
#   - on a FIRST install, disables both jobs, so nothing runs (and a reboot starts nothing) until
#     `keeperctl.sh <entry> resume`. On an update of a loaded entry it changes no launchd state:
#     the new files take effect at the next pause + resume.
# It never creates or reads secrets. It reports which of rpc.env / key.env / address / telegram.env
# are missing; exit 0 = installed and ready to resume, 2 = installed but a required file is missing.
set -euo pipefail
export PATH="/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin"
LAUNCHCTL="${KEEPER_LAUNCHCTL:-launchctl}"   # the test swaps in a stub
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENTRY="${1:-}"
# Reserved: bin (the shared control dir), list (a keeperctl command), and any name ending in
# -stale-watch, whose keeper label would be another entry's watcher label.
[[ "$ENTRY" =~ ^[a-z0-9][a-z0-9-]*$ ]] && case "$ENTRY" in bin | list | *-stale-watch) false ;; esac || { echo "usage: install.sh <entry>  (entries/: $(cd "$HERE/entries" && ls | sed 's/\.env$//' | tr '\n' ' '))" >&2; exit 64; }
SRC="$HERE/entries/$ENTRY.env"
[ -f "$SRC" ] || { echo "no entries/$ENTRY.env" >&2; exit 66; }
grep -qx "KEEPER_ENTRY=$ENTRY" "$SRC" || { echo "entries/$ENTRY.env must contain KEEPER_ENTRY=$ENTRY" >&2; exit 65; }

D="$HOME/.config/aastar-price-keeper-$ENTRY"
BIN="$HOME/.config/aastar-price-keeper-bin"
LA="$HOME/Library/LaunchAgents"
DOM="gui/$(id -u)"
LABEL="io.aastar.price-keeper-$ENTRY"
WATCH="$LABEL-stale-watch"
mkdir -p -m 700 "$D" "$D/stale-watch" "$BIN"
# take_lock FILE FD: an exclusive flock(2) on FILE through descriptor FD of this shell. The kernel
# drops it when this process exits, however it exits, so there is no stale lock and no takeover race.
take_lock() {
  eval "exec $2>>\"\$1\"" || return 3
  perl -e 'use Fcntl qw(:flock); open(my $f, ">&=", $ARGV[0]) or exit 3; flock($f, LOCK_EX | LOCK_NB) or exit 75; exit 0' "$2"
}
# The entry's lock (the one keeperctl.sh takes for pause/resume) and one lock for all installs, since
# every entry publishes the shared keeperctl.sh.
take_lock "$D/.keeperctl.lock" 8 || { echo "keeperctl.sh or install.sh for $ENTRY is running" >&2; exit 75; }
take_lock "$BIN/.install.lock" 7 || { echo "another install.sh is running" >&2; exit 75; }
# Decided under both locks: a first install is one with no entry.env published yet.
first=""; [ -f "$D/entry.env" ] || first=1
mkdir -p "$LA"
backup="$D/backup-$(date -u +%Y%m%dT%H%M%SZ)"

# $HOME goes into sed and the plists: only plain path characters.
[[ "$HOME" =~ ^/[A-Za-z0-9._/-]+$ ]] || { echo "HOME $HOME has characters install.sh does not write into a plist" >&2; exit 65; }
# Every managed destination is a plain file or absent: never a link (it could alias a secret).
for f in "$D/run.sh" "$D/stale-watch.sh" "$D/status.mjs" "$D/entry.env" "$BIN/keeperctl.sh" "$LA/$LABEL.plist" "$LA/$WATCH.plist"; do
  if [ -L "$f" ] || { [ -e "$f" ] && { [ ! -f "$f" ] || [ "$(stat -f %l "$f")" != 1 ]; }; }; then
    echo "$f is a link, not a regular file, or has other hard links; refusing to replace it" >&2; exit 65
  fi
done
# Stage every file first (rendered and linted), then publish each by rename, so a failure before
# publication changes nothing and no destination is ever half-written.
stage="$(mktemp -d "$D/.stage.XXXXXX")"; trap 'rm -rf "$stage"' EXIT
pending=()
put() { # src dst mode -> staged now, renamed into place by publish
  local s="$stage/$(basename "$2")"; install -m "$3" "$1" "$s"; pending+=("$s" "$2")
}
render() { # template dst
  local tmp="$stage/render.tmp"
  sed -e "s#@ENTRY@#$ENTRY#g" -e "s#@HOME@#$HOME#g" "$1" > "$tmp"
  plutil -lint "$tmp" >/dev/null
  [ "$(plutil -extract Label raw -o - "$tmp")" = "$(basename "$2" .plist)" ] || { echo "rendered $2 has the wrong Label" >&2; exit 70; }
  put "$tmp" "$2" 644; rm -f "$tmp"
}
# Each file is replaced by rename. If any step fails, every file already replaced is put back
# (from the copy taken just before) and files this run created are removed, so a failed install
# leaves the previous set, not a mix.
publish() {
  local i s dst tmp prev undo=() rc=0
  for ((i = 0; i < ${#pending[@]}; i += 2)); do
    s="${pending[$i]}"; dst="${pending[$((i + 1))]}"
    prev=""
    if [ -e "$dst" ]; then
      cp -p "$dst" "$stage/prev.$i" || { rc=1; break; }
      cmp -s "$s" "$dst" || { mkdir -p "$backup" && cp -p "$dst" "$backup/"; } || { rc=1; break; }
      prev="$stage/prev.$i"
    fi
    # a fresh temp name next to the target (same filesystem, so the rename is atomic)
    tmp="$(mktemp "$(dirname "$dst")/.$(basename "$dst").XXXXXX")" && cp -p "$s" "$tmp" && mv -f "$tmp" "$dst" ||
      { rm -f "$tmp"; rc=1; break; }
    undo+=("$prev" "$dst")   # only a file that was actually replaced or created is undone
  done
  if [ "$rc" != 0 ]; then
    local bad=""
    for ((i = 0; i < ${#undo[@]}; i += 2)); do
      # restored by rename too, so a concurrent reader never sees a half-written file
      if [ -n "${undo[$i]}" ]; then
        tmp="$(mktemp "$(dirname "${undo[$((i + 1))]}")/.restore.XXXXXX")" && cp -p "${undo[$i]}" "$tmp" &&
          mv -f "$tmp" "${undo[$((i + 1))]}" || { rm -f "$tmp"; bad+=" ${undo[$((i + 1))]}"; }
      else rm -f "${undo[$((i + 1))]}" || bad+=" ${undo[$((i + 1))]}"; fi
    done
    if [ -n "$bad" ]; then
      trap - EXIT   # keep the staged copies: they are the only good versions left
      echo "install.sh: publishing failed AND ROLLBACK INCOMPLETE for:$bad; previous files are in $stage (prev.*); do not resume" >&2; exit 2
    fi
    echo "install.sh: publishing failed; the previous files were put back" >&2; exit 1
  fi
}

# A first install disables the jobs BEFORE their plists exist, so no login or reboot can load them.
if [ -n "$first" ] || ! "$LAUNCHCTL" print "$DOM/$LABEL" >/dev/null 2>&1; then
  for j in "$LABEL" "$WATCH"; do
    "$LAUNCHCTL" disable "$DOM/$j" || { echo "launchctl disable $j failed; nothing installed" >&2; exit 1; }
    "$LAUNCHCTL" print-disabled "$DOM" | grep -qF "\"$j\" => disabled" ||
      { echo "launchd does not list $j as disabled; nothing installed" >&2; exit 1; }
  done
  state="paused (both jobs disabled; start with: keeperctl.sh $ENTRY resume)"
else
  # A running entry keeps its old settings until it restarts, while status.mjs would read new ones
  # at its next check: a settings change is installed only into a paused entry.
  if [ -f "$D/entry.env" ] && ! cmp -s "$SRC" "$D/entry.env"; then
    echo "entries/$ENTRY.env differs from the running entry's settings: pause it first (keeperctl.sh $ENTRY pause), install, then resume" >&2
    exit 3
  fi
  state="loaded and running the previous files until: keeperctl.sh $ENTRY pause, then resume"
fi
put "$HERE/run.sh" "$D/run.sh" 755
put "$HERE/stale-watch.sh" "$D/stale-watch.sh" 755
put "$HERE/status.mjs" "$D/status.mjs" 644
put "$SRC" "$D/entry.env" 644
put "$HERE/keeperctl.sh" "$BIN/keeperctl.sh" 755
render "$HERE/keeper.plist.in" "$LA/$LABEL.plist"
render "$HERE/stale-watch.plist.in" "$LA/$WATCH.plist"
publish

echo "installed entry $ENTRY in $D"
[ -d "$backup" ] && echo "replaced files backed up in $backup"
echo "launchd: $state"
missing=""
for f in rpc.env key.env address; do [ -e "$D/$f" ] || missing+=" $f"; done
for f in rpc.env key.env telegram.env; do
  [ -e "$D/$f" ] || continue
  m="$(stat -L -f %Lp "$D/$f")"; [ "$m" = 600 ] || echo "WARNING: $D/$f is mode $m; set 600"
done
[ -e "$D/telegram.env" ] || echo "note: no telegram.env, so no alerts"
if [ -n "$missing" ]; then echo "NOT READY: create$missing in $D (see README)"; exit 2; fi
echo "ready: run keeperctl.sh $ENTRY dry-run, then resume"
