#!/bin/bash
# Offline test for install.sh: a fake HOME and a stub launchctl. No chain, no launchd, no key.
#   bash deploy/price-keeper/test_install.sh      exit 0 = all cases pass
set -uo pipefail
[ "$(uname)" = Darwin ] || { echo "skip: install.sh is a macOS script (plutil, BSD stat)"; exit 0; }
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
fail=0
expect() { if eval "$2"; then echo "ok   $1"; else echo "FAIL $1"; fail=1; fi; }

# --- stub launchctl: logs each call; "print" says not loaded unless $LOADED names the label;
# "disable" records whether the job's plist already existed at that moment
cat > "$T/launchctl" <<'S'
#!/bin/bash
echo "$*" >> "$LCLOG"
case "$1" in
  print) [ -n "${LOADED:-}" ] && [ "$2" = "gui/$(id -u)/$LOADED" ] && exit 0; exit 113 ;;
  disable) l="${2##*/}"; [ -e "$HOME/Library/LaunchAgents/$l.plist" ] && echo "PLIST-EXISTED $l" >> "$LCLOG"
    [ -n "${STUB_DISABLE_FAIL:-}" ] && exit 1
    [ -n "${STUB_NO_RECORD:-}" ] || echo "$l" >> "$LCLOG.disabled"; exit 0 ;;
  print-disabled) sed 's/.*/\t\t"&" => disabled/' "$LCLOG.disabled" 2>/dev/null; exit 0 ;;
esac
exit 0
S
chmod +x "$T/launchctl"

H="$T/home"; mkdir -p "$H"
inst() { HOME="$H" KEEPER_LAUNCHCTL="$T/launchctl" LCLOG="$T/lc.log" bash "$HERE/install.sh" "$@" > "$T/inst.out" 2>&1; IRC=$?; }
D="$H/.config/aastar-price-keeper-op-sepolia"
LA="$H/Library/LaunchAgents"

# ---------- install.sh
: > "$T/lc.log"; inst op-sepolia
expect "first install without secrets exits 2 (NOT READY)" '[ "$IRC" = 2 ] && grep -q "NOT READY: create rpc.env key.env address" "$T/inst.out"'
expect "both jobs disabled, before their plists existed" \
  'grep -q "^disable gui/[0-9]*/io.aastar.price-keeper-op-sepolia$" "$T/lc.log" && grep -q "^disable gui/[0-9]*/io.aastar.price-keeper-op-sepolia-stale-watch$" "$T/lc.log" && ! grep -q PLIST-EXISTED "$T/lc.log"'
expect "never bootstraps, enables or kickstarts" '! grep -qE "^(bootstrap|enable|kickstart)" "$T/lc.log"'
expect "entry dir is mode 700 with entry.env, scripts and a state dir" \
  '[ "$(stat -f %Lp "$D")" = 700 ] && cmp -s "$D/entry.env" "$HERE/entries/op-sepolia.env" && [ -x "$D/run.sh" ] && [ -x "$D/stale-watch.sh" ] && [ -f "$D/status.mjs" ] && [ -d "$D/stale-watch" ]'
expect "keeperctl.sh in the shared bin dir" '[ -x "$H/.config/aastar-price-keeper-bin/keeperctl.sh" ]'
expect "both plists rendered, lint clean, no placeholder left" \
  'plutil -lint "$LA/io.aastar.price-keeper-op-sepolia.plist" "$LA/io.aastar.price-keeper-op-sepolia-stale-watch.plist" >/dev/null && ! grep -q @ "$LA"/io.aastar.price-keeper-op-sepolia*.plist'
expect "keeper plist runs this entry's run.sh and logs to its own file" \
  '[ "$(plutil -extract ProgramArguments.1 raw -o - "$LA/io.aastar.price-keeper-op-sepolia.plist")" = "$D/run.sh" ] && [ "$(plutil -extract StandardOutPath raw -o - "$LA/io.aastar.price-keeper-op-sepolia.plist")" = "$H/Library/Logs/aastar-price-keeper-op-sepolia.log" ]'
expect "stale-watch plist: StartInterval 600 at top level" '[ "$(plutil -extract StartInterval raw -o - "$LA/io.aastar.price-keeper-op-sepolia-stale-watch.plist")" = 600 ]'

printf 'RPC_URL=http://127.0.0.1:9\n' > "$D/rpc.env"; chmod 600 "$D/rpc.env"
printf 'KEEPER_PRIVATE_KEY=0xnot-a-key\n' > "$D/key.env"; chmod 644 "$D/key.env"
echo 0x00000000000000000000000000000000000000c1 > "$D/address"
echo "# changed" >> "$D/run.sh"
: > "$T/lc.log"; LOADED=io.aastar.price-keeper-op-sepolia inst op-sepolia
expect "update of a loaded entry: ready, exit 0" '[ "$IRC" = 0 ] && grep -q "^ready" "$T/inst.out"'
expect "update of a loaded entry changes no launchd state" '! grep -qE "^(disable|enable|bootstrap|bootout|kickstart)" "$T/lc.log"'
expect "the replaced run.sh is backed up, secrets untouched" \
  'ls "$D"/backup-*/run.sh >/dev/null 2>&1 && grep -q "# changed" "$D"/backup-*/run.sh && cmp -s "$D/run.sh" "$HERE/run.sh" && grep -q 0xnot-a-key "$D/key.env"'
# a publish that fails half-way puts the previous files back
echo "# marker-before" >> "$D/run.sh"; cp "$D/run.sh" "$T/run.before"; chmod 500 "$LA"
: > "$T/lc.log"; LOADED=io.aastar.price-keeper-op-sepolia inst op-sepolia; chmod 700 "$LA"
expect "a publish that fails (LaunchAgents not writable) exits 1 and restores the replaced run.sh" \
  '[ "$IRC" = 1 ] && grep -q "previous files were put back" "$T/inst.out" && cmp -s "$D/run.sh" "$T/run.before"'
expect "no temp file or staging dir left behind" '! ls -a "$D" "$LA" | grep -qE "^\.(run\.sh|io\.aastar|stage)"'
LOADED=io.aastar.price-keeper-op-sepolia inst op-sepolia
expect "CONTROL the same install then succeeds" '[ "$IRC" = 0 ] && cmp -s "$D/run.sh" "$HERE/run.sh"'
hold() { # FILE SECONDS -> a background process holds an flock on FILE; its pid in $HOLDER
  ( exec 9>>"$1"; perl -e 'use Fcntl qw(:flock); open(my $f, ">&=", 9) or exit 3; flock($f, LOCK_EX) or exit 1'; exec sleep "$2" ) &
  HOLDER=$!; sleep 1; }
hold "$D/.keeperctl.lock" 4; LOADED=io.aastar.price-keeper-op-sepolia inst op-sepolia
expect "the entry lock held (a pause or resume running): install exits 75" '[ "$IRC" = 75 ]'
wait "$HOLDER"; hold "$H/.config/aastar-price-keeper-bin/.install.lock" 4; LOADED=io.aastar.price-keeper-op-sepolia inst op-sepolia
expect "the install lock held (another entry installing): exit 75" '[ "$IRC" = 75 ]'
kill -9 "$HOLDER" 2>/dev/null; wait "$HOLDER" 2>/dev/null || true; LOADED=io.aastar.price-keeper-op-sepolia inst op-sepolia
expect "after the holder is killed (kill -9) the lock is free at once" '[ "$IRC" = 0 ]'
# two installs at the same moment: the locks let exactly one through, the other exits 75
for k in 1 2; do
  ( HOME="$H" KEEPER_LAUNCHCTL="$T/launchctl" LCLOG="$T/lc.c$k" LOADED=io.aastar.price-keeper-op-sepolia \
      bash "$HERE/install.sh" op-sepolia > "$T/conc.$k" 2>&1; echo $? > "$T/conc.rc$k" ) &
done; wait
expect "two concurrent installs: one exits 0, the other 75 (or both 0, one after the other), never a broken set" \
  '{ [ "$(sort "$T/conc.rc1" "$T/conc.rc2" | tr "\n" " ")" = "0 75 " ] || [ "$(cat "$T/conc.rc1" "$T/conc.rc2" | tr "\n" " ")" = "0 0 " ]; } && cmp -s "$D/run.sh" "$HERE/run.sh" && plutil -lint "$LA/io.aastar.price-keeper-op-sepolia.plist" >/dev/null'
expect "a key file that is not mode 600 is reported" 'grep -q "key.env is mode 644" "$T/inst.out"'
inst bin; expect "entry name bin refused" '[ "$IRC" = 64 ]'
inst list; expect "entry name list refused" '[ "$IRC" = 64 ]'
inst op-sepolia-stale-watch; expect "an entry name ending in -stale-watch refused (its label is a watcher label)" '[ "$IRC" = 64 ]'
# a failed or unrecorded disable on a first install: exit 1 and nothing written
H2="$T/home2"; mkdir -p "$H2"
for v in STUB_DISABLE_FAIL STUB_NO_RECORD; do
  rm -rf "$H2/.config" "$H2/Library"; : > "$T/lc2.log"
  env HOME="$H2" KEEPER_LAUNCHCTL="$T/launchctl" LCLOG="$T/lc2.log" "$v=1" bash "$HERE/install.sh" op-sepolia > "$T/inst.out" 2>&1; IRC=$?
  expect "first install with $v: exit 1, no plist and no script published" \
    '[ "$IRC" = 1 ] && [ ! -e "$H2/Library/LaunchAgents/io.aastar.price-keeper-op-sepolia.plist" ] && [ ! -e "$H2/.config/aastar-price-keeper-op-sepolia/run.sh" ]'
done
# a managed destination that is a link is refused before anything is read through it
mv "$D/entry.env" "$T/entry.keep"; ln -s "$D/key.env" "$D/entry.env"
: > "$T/lc.log"; LOADED=io.aastar.price-keeper-op-sepolia inst op-sepolia
expect "an entry.env that is a link refused, the link left alone" '[ "$IRC" = 65 ] && grep -q "is a link" "$T/inst.out" && [ -L "$D/entry.env" ] && ! grep -q 0x "$T/inst.out"'
rm "$D/entry.env"; mv "$T/entry.keep" "$D/entry.env"
H3="$T/home&x"; mkdir -p "$H3"
env HOME="$H3" KEEPER_LAUNCHCTL="$T/launchctl" LCLOG="$T/lc3.log" bash "$HERE/install.sh" op-sepolia > "$T/inst.out" 2>&1; IRC=$?
expect "a HOME with a sed/plist metacharacter refused" '[ "$IRC" = 65 ] && [ ! -e "$H3/Library/LaunchAgents/io.aastar.price-keeper-op-sepolia.plist" ]'
expect "no staging dir left behind" '! ls -d "$D"/.stage.* >/dev/null 2>&1'
inst 'op;rm'; expect "entry name with a metacharacter refused" '[ "$IRC" = 64 ]'
inst no-such; expect "unknown entry refused" '[ "$IRC" = 66 ]'

exit "$fail"
