#!/bin/bash
# macOS only, real launchd: keeperctl.sh pause/resume against a throwaway entry whose "keeper" is a
# shell that keeps a child sleep (like tsx keeps the keeper's node child) under KeepAlive.
# Nothing touches a real entry: the entry name is unique, HOME is a temp dir, and both jobs are
# booted out and their plists removed at the end, also on failure.
#   bash deploy/price-keeper/test_keeperctl.sh      exit 0 = all cases pass
set -uo pipefail
[ "$(uname)" = Darwin ] || { echo "skip: needs macOS launchd"; exit 0; }
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
E="zz-kctl-test-$$"; L="io.aastar.price-keeper-$E"; W="$L-stale-watch"; DOM="gui/$(id -u)"
T="$(mktemp -d)"; H="$T/home"; D="$H/.config/aastar-price-keeper-$E"; LA="$H/Library/LaunchAgents"
cleanup() {
  for j in "$L" "$W"; do launchctl bootout "$DOM/$j" 2>/dev/null; launchctl enable "$DOM/$j" 2>/dev/null; done
  pkill -f "kctl-test-sleep-$$" 2>/dev/null; rm -rf "$T"
}
trap cleanup EXIT
mkdir -p "$D" "$LA"; SPA=0x00000000000000000000000000000000000000a1
printf 'KEEPER_ENTRY=%s\nKEEPER_NETWORK=op-sepolia\nKEEPER_SUPERPAYMASTER=%s\n' "$E" "$SPA" > "$D/entry.env"
for j in "$L" "$W"; do
  cat > "$LA/$j.plist" <<P
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>Label</key><string>$j</string>
<key>ProgramArguments</key><array><string>/bin/bash</string><string>-c</string><string>exec -a "node scripts/keeper.ts kctl-test-$$" /bin/bash -c "/bin/bash -c 'exec -a kctl-test-sleep-$$ /bin/sleep 3600' &amp; wait"</string></array>
<key>RunAtLoad</key><true/><key>KeepAlive</key><true/><key>ThrottleInterval</key><integer>10</integer></dict></plist>
P
done
fail=0
expect() { if eval "$2"; then echo "ok   $1"; else echo "FAIL $1"; fail=1; fi; }
ctl() { HOME="$H" KEEPER_LOCAL=1 bash "$HERE/keeperctl.sh" "$E" "$@" > "$T/out" 2>&1; RC=$?; }
pid() { launchctl print "$DOM/$L" 2>/dev/null | awk '/^\tpid = /{print $3}'; }
loaded() { launchctl print "$DOM/$1" >/dev/null 2>&1; }
kids() { pgrep -f "kctl-test-sleep-$$" | tr '\n' ' '; }

ctl resume; p1="$(pid)"
for _ in 1 2 3 4 5 6; do [ -n "$p1" ] && [ -n "$(pgrep -P "$p1")" ] && break; sleep 0.5; done
expect "resume: exit 0, the keeper job runs with a child" '[ "$RC" = 0 ] && [ -n "$p1" ] && [ -n "$(pgrep -P "$p1")" ] && loaded "$W"'
kill -9 "$p1"; sleep 13; p2="$(pid)"
expect "CONTROL: KeepAlive restarts a killed keeper (pid $p1 -> ${p2:-none})" '[ -n "$p2" ] && [ "$p2" != "$p1" ]'
ctl restart; sleep 2; p3="$(pid)"
expect "restart: a new pid" '[ "$RC" = 0 ] && [ -n "$p3" ] && [ "$p3" != "$p2" ]'
for _ in 1 2 3 4 5 6; do child="$(pgrep -P "$p3" | head -1)"; [ -n "$child" ] && break; sleep 0.5; done
expect "the keeper job has an identified child before pause" '[ -n "$child" ] && kill -0 "$child"'
ctl pause
expect "pause: exit 0, PAUSED" '[ "$RC" = 0 ] && grep -q "^PAUSED $E" "$T/out"'
expect "when pause returns: neither job loaded, the job pid and its child already gone" \
  '! loaded "$L" && ! loaded "$W" && ! kill -0 "$p3" 2>/dev/null && ! kill -0 "$child" 2>/dev/null'
sleep 15
expect "15 s later still nothing (KeepAlive did not bring it back)" '[ -z "$(pid)" ] && [ -z "$(kids)" ]'
expect "both jobs disabled" 'launchctl print-disabled "$DOM" | grep -qF "\"$L\" => disabled" && launchctl print-disabled "$DOM" | grep -qF "\"$W\" => disabled"'
launchctl bootstrap "$DOM" "$LA/$L.plist" 2>/dev/null; sleep 2
expect "a stray bootstrap of a paused (disabled) job starts nothing" '[ -z "$(pid)" ]'
ctl pause; expect "pause again: exit 0" '[ "$RC" = 0 ]'
ctl restart; expect "restart of a paused entry refuses, stays paused" '[ "$RC" = 1 ] && [ -z "$(pid)" ]'
ctl resume; expect "resume after pause: exit 0, running" '[ "$RC" = 0 ] && [ -n "$(pid)" ]'
# a failed disable: NOT PAUSED, exit 1, and the keeper keeps running (nothing booted out half-way)
printf '#!/bin/bash\n[ "$1" = disable ] && exit 1\nexec launchctl "$@"\n' > "$T/lc-fail"; chmod +x "$T/lc-fail"
HOME="$H" KEEPER_LOCAL=1 KEEPER_LAUNCHCTL="$T/lc-fail" bash "$HERE/keeperctl.sh" "$E" pause > "$T/out" 2>&1; RC=$?
expect "a failed disable is NOT PAUSED (exit 1), never PAUSED" '[ "$RC" = 1 ] && grep -q "NOT PAUSED" "$T/out" && ! grep -q "^PAUSED" "$T/out"'
# a disable launchd does not record: NOT PAUSED as well
printf '#!/bin/bash\n[ "$1" = disable ] && exit 0\nexec launchctl "$@"\n' > "$T/lc-norec"; chmod +x "$T/lc-norec"
launchctl enable "$DOM/$L"; launchctl enable "$DOM/$W"
HOME="$H" KEEPER_LOCAL=1 KEEPER_LAUNCHCTL="$T/lc-norec" bash "$HERE/keeperctl.sh" "$E" pause > "$T/out" 2>&1; RC=$?
expect "an unrecorded disable is NOT PAUSED (exit 1)" '[ "$RC" = 1 ] && grep -q "does not list" "$T/out"'
# a resume whose keeper never reaches scripts/keeper.ts is NOT RESUMED
ctl pause
plutil -replace ProgramArguments -json '["/bin/bash","-c","exit 3"]' "$LA/$L.plist"
ctl resume; expect "a keeper that exits at once (as run.sh does on a bad config) is NOT RESUMED" '[ "$RC" = 1 ] && grep -q "NOT RESUMED" "$T/out"'
ctl pause
plutil -replace Label -string io.aastar.price-keeper-other "$LA/$L.plist"
ctl resume; expect "a plist whose Label is not its own is refused before launchd is touched" '[ "$RC" = 65 ] && [ -z "$(pid)" ]'
hold() { # FILE SECONDS -> a background process holds an flock on FILE; its pid in $HOLDER
  ( exec 9>>"$1"; perl -e 'use Fcntl qw(:flock); open(my $f, ">&=", 9) or exit 3; flock($f, LOCK_EX) or exit 1'; exec sleep "$2" ) &
  HOLDER=$!; sleep 1; }
hold "$D/.keeperctl.lock" 30; ctl pause; expect "a lock held by a live process: exit 75" '[ "$RC" = 75 ]'
kill -9 "$HOLDER"; wait "$HOLDER" 2>/dev/null || true; ctl pause; expect "after the holder is killed (kill -9) pause takes the lock" '[ "$RC" = 0 ]'
ctl pause & p1=$!; sleep 0.2; ctl_out2="$(HOME="$H" KEEPER_LOCAL=1 bash "$HERE/keeperctl.sh" "$E" pause 2>&1)"; rc2=$?; wait "$p1"
expect "two pauses at once: one waits out with 75 or both serialize, never both inside" '[ "$rc2" = 75 ] || [ "$rc2" = 0 ]'
# a keeper process of this entry outside the job's process group still blocks PAUSED
perl -e 'setpgrp(0,0); exec {"/bin/sleep"} "node scripts/keeper.ts --network op-sepolia --superpaymaster '"$SPA"' kctl-stray-'"$$"'", 60' & stray=$!
sleep 1; ctl pause
expect "a stray keeper process of this entry (another group) makes pause NOT PAUSED" '[ "$RC" = 1 ] && grep -q "NOT PAUSED" "$T/out" && grep -q "$stray" "$T/out"'
kill "$stray" 2>/dev/null; wait "$stray" 2>/dev/null || true
# launchctl failing (not "no such service") is not read as unloaded
printf '#!/bin/bash\n[ "$1" = print ] && exit 5\nexec launchctl "$@"\n' > "$T/lc-printerr"; chmod +x "$T/lc-printerr"
HOME="$H" KEEPER_LOCAL=1 KEEPER_LAUNCHCTL="$T/lc-printerr" bash "$HERE/keeperctl.sh" "$E" pause > "$T/out" 2>&1; RC=$?
expect "a failing launchctl print is NOT PAUSED, never PAUSED" '[ "$RC" = 1 ] && ! grep -q "^PAUSED" "$T/out"'
cp "$D/entry.env" "$T/entry.good"; grep -v '^KEEPER_SUPERPAYMASTER=' "$T/entry.good" > "$D/entry.env"; ctl pause
expect "an entry.env without KEEPER_SUPERPAYMASTER: pause is NOT PAUSED (cannot scan), never PAUSED" '[ "$RC" = 1 ] && grep -q "find its keeper by" "$T/out"'
cp "$T/entry.good" "$D/entry.env"
echo "install.sh test: rollback incomplete" > "$D/INSTALL-INCOMPLETE"; ctl resume
expect "resume refuses while INSTALL-INCOMPLETE exists" '[ "$RC" = 1 ] && grep -q "did not complete" "$T/out" && [ -z "$(pid)" ]'
rm "$D/INSTALL-INCOMPLETE"
HOME="$H" KEEPER_LOCAL=1 bash "$HERE/keeperctl.sh" stale-watch status > "$T/out" 2>&1; RC=$?
expect "the reserved name stale-watch is a usage error" '[ "$RC" = 64 ]'
HOME="$H" KEEPER_LOCAL=1 bash "$HERE/keeperctl.sh" list pause > "$T/out" 2>&1; RC=$?
expect "list with extra arguments is a usage error" '[ "$RC" = 64 ]'
# resume must see the keeper with its worker, stable for 10 s
cp "$LA/$L.plist" "$T/keeper.plist.good"
plutil -replace ProgramArguments -json '["/bin/bash","-c","exec -a \"node scripts/keeper.ts nochild\" /bin/sleep 3600"]' "$LA/$L.plist"
plutil -replace Label -string "$L" "$LA/$L.plist"
ctl resume; expect "a keeper.ts process without its worker child is NOT RESUMED" '[ "$RC" = 1 ] && grep -q "NOT RESUMED" "$T/out"'
ctl pause
plutil -replace ProgramArguments -json '["/bin/bash","-c","exec -a \"node scripts/keeper.ts crashy\" /bin/bash -c \"/bin/sleep 60 & /bin/sleep 6; exit 1\""]' "$LA/$L.plist"
ctl resume; expect "a keeper that dies after 6 s and is restarted by KeepAlive is NOT RESUMED" '[ "$RC" = 1 ] && grep -q "NOT RESUMED" "$T/out"'
ctl pause; cp "$T/keeper.plist.good" "$LA/$L.plist"
ctl pause; expect "and pause again: exit 0, nothing left" '[ "$RC" = 0 ] && sleep 3 && [ -z "$(kids)" ]'
HOME="$H" KEEPER_LOCAL=1 bash "$HERE/keeperctl.sh" "no-such-entry" status > "$T/out" 2>&1; RC=$?
expect "unknown entry: exit 66" '[ "$RC" = 66 ]'
HOME="$H" KEEPER_LOCAL=1 bash "$HERE/keeperctl.sh" '../x' pause > "$T/out" 2>&1; RC=$?
expect "entry name with a path: usage, exit 64" '[ "$RC" = 64 ]'
exit "$fail"
