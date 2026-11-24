#!/bin/bash
# Offline test for install.sh: a fake HOME and a stub launchctl. No chain, no launchd, no key.
#   bash deploy/price-keeper/test_install.sh      exit 0 = all cases pass
set -uo pipefail
[ "$(uname)" = Darwin ] || { echo "skip: install.sh is a macOS script (plutil, BSD stat)"; exit 0; }
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
T="$(mktemp -d)"; trap 'chmod -R u+w "$T" 2>/dev/null; rm -rf "$T"' EXIT
fail=0
expect() { if eval "$2"; then echo "ok   $1"; else echo "FAIL $1"; fail=1; fi; }

# --- stub launchctl: logs each call. "print" answers 0 (loaded) for the label in $LOADED, $PRINT_RC
# for every other label (default 113, not found). "disable" records whether the job's plist already
# existed at that moment, and the label for print-disabled (unless $STUB_NO_RECORD).
cat > "$T/launchctl" <<'S'
#!/bin/bash
echo "$*" >> "$LCLOG"
case "$1" in
  print) [ -n "${LOADED:-}" ] && [ "$2" = "gui/$(id -u)/$LOADED" ] && exit 0; exit "${PRINT_RC:-113}" ;;
  disable) l="${2##*/}"; [ -e "$HOME/Library/LaunchAgents/$l.plist" ] && echo "PLIST-EXISTED $l" >> "$LCLOG"
    [ -n "${STUB_DISABLE_FAIL:-}" ] && exit 1
    [ -n "${STUB_NO_RECORD:-}" ] || echo "$l" >> "$LCLOG.disabled"; exit 0 ;;
  print-disabled) sed "s/.*/${STUB_PD_PREFIX-		}\"&\" => disabled/" "$LCLOG.disabled" 2>/dev/null; exit 0 ;;
esac
exit 0
S
chmod +x "$T/launchctl"

H="$T/home"; mkdir -p "$H"
# inst [VAR=value ...] ENTRY -- install.sh under the fake HOME; exit code in IRC, output in inst.out
inst() { env HOME="$H" KEEPER_LAUNCHCTL="$T/launchctl" LCLOG="$T/lc.log" "$@" bash "$HERE/install.sh" > "$T/inst.out" 2>&1 <<< "" ; IRC=$?; }
in2() { local e="${!#}"; set -- "${@:1:$(($# - 1))}"; env HOME="$H" KEEPER_LAUNCHCTL="$T/launchctl" LCLOG="$T/lc.log" "$@" bash "$HERE/install.sh" "$e" > "$T/inst.out" 2>&1; IRC=$?; }
D="$H/.config/aastar-price-keeper-op-sepolia"
LA="$H/Library/LaunchAgents"
KP="$LA/io.aastar.price-keeper-op-sepolia.plist"; WP="$LA/io.aastar.price-keeper-op-sepolia-stale-watch.plist"
L=io.aastar.price-keeper-op-sepolia

# ---------- first install
: > "$T/lc.log"; in2 op-sepolia
expect "first install without secrets exits 2 (NOT READY)" '[ "$IRC" = 2 ] && grep -q "NOT READY: create rpc.env key.env address" "$T/inst.out"'
expect "both jobs disabled, before their plists existed" \
  'grep -q "^disable gui/[0-9]*/$L$" "$T/lc.log" && grep -q "^disable gui/[0-9]*/$L-stale-watch$" "$T/lc.log" && ! grep -q PLIST-EXISTED "$T/lc.log"'
expect "never bootstraps, enables or kickstarts" '! grep -qE "^(bootstrap|enable|kickstart)" "$T/lc.log"'
expect "entry dir is mode 700 with entry.env, scripts and a state dir" \
  '[ "$(stat -f %Lp "$D")" = 700 ] && cmp -s "$D/entry.env" "$HERE/entries/op-sepolia.env" && [ -x "$D/run.sh" ] && [ -x "$D/stale-watch.sh" ] && [ -f "$D/status.mjs" ] && [ -d "$D/stale-watch" ]'
expect "keeperctl.sh in the shared bin dir" '[ -x "$H/.config/aastar-price-keeper-bin/keeperctl.sh" ]'
expect "both plists rendered, lint clean, no placeholder left" 'plutil -lint "$KP" "$WP" >/dev/null && ! grep -q @ "$KP" "$WP"'
expect "keeper plist runs this entry's run.sh and logs to its own file" \
  '[ "$(plutil -extract ProgramArguments.1 raw -o - "$KP")" = "$D/run.sh" ] && [ "$(plutil -extract StandardOutPath raw -o - "$KP")" = "$H/Library/Logs/aastar-price-keeper-op-sepolia.log" ]'
expect "stale-watch plist: StartInterval 600 at top level" '[ "$(plutil -extract StartInterval raw -o - "$WP")" = 600 ]'

printf 'RPC_URL=http://127.0.0.1:9\n' > "$D/rpc.env"; chmod 600 "$D/rpc.env"
printf 'KEEPER_PRIVATE_KEY=0xnot-a-key\n' > "$D/key.env"; chmod 644 "$D/key.env"
echo 0x00000000000000000000000000000000000000c1 > "$D/address"

# ---------- a loaded entry is never installed into (#473 B1)
for lab in "$L" "$L-stale-watch"; do
  echo "# changed" >> "$D/run.sh"; cp "$D/run.sh" "$T/run.before"; : > "$T/lc.log"
  in2 LOADED="$lab" op-sepolia
  expect "with $lab loaded: exit 75, nothing replaced, no launchctl change" \
    '[ "$IRC" = 75 ] && grep -q "pause the entry first" "$T/inst.out" && cmp -s "$D/run.sh" "$T/run.before" && ! grep -qE "^(disable|enable|bootstrap|bootout|kickstart)" "$T/lc.log"'
done
: > "$T/lc.log"; in2 PRINT_RC=5 op-sepolia
expect "launchctl print failing (not 113): exit 75, nothing replaced" '[ "$IRC" = 75 ] && grep -q "cannot tell" "$T/inst.out" && cmp -s "$D/run.sh" "$T/run.before"'
mv "$D/entry.env" "$T/entry.keep"; in2 LOADED="$L" op-sepolia
expect "a loaded job with entry.env deleted is still refused (B1b)" '[ "$IRC" = 75 ] && [ ! -e "$D/entry.env" ]'
mv "$T/entry.keep" "$D/entry.env"

# ---------- update of a paused entry
: > "$T/lc.log"; in2 op-sepolia
expect "update of a paused entry: ready, exit 0" '[ "$IRC" = 0 ] && grep -q "^ready" "$T/inst.out"'
expect "the update disables both jobs again before publishing" \
  '[ "$(grep -c "^disable " "$T/lc.log")" = 2 ] && ! grep -qE "^(enable|bootstrap|kickstart)" "$T/lc.log"'
expect "the replaced run.sh is backed up, secrets untouched" \
  'ls "$D"/backup-*/run.sh >/dev/null 2>&1 && grep -q "# changed" "$D"/backup-*/run.sh && cmp -s "$D/run.sh" "$HERE/run.sh" && grep -q 0xnot-a-key "$D/key.env"'
expect "a key file that is not mode 600 is reported" 'grep -q "key.env is mode 644" "$T/inst.out"'
chmod 755 "$D"; in2 op-sepolia
expect "an existing entry dir with mode 755 is set to 700" '[ "$IRC" = 0 ] && [ "$(stat -f %Lp "$D")" = 700 ]'

# ---------- failed or unrecorded disable, and a loose print-disabled match
H2="$T/home2"; mkdir -p "$H2"
for v in STUB_DISABLE_FAIL=1 STUB_NO_RECORD=1 "STUB_PD_PREFIX=x"; do
  rm -rf "$H2/.config" "$H2/Library"; : > "$T/lc2.log"; rm -f "$T/lc2.log.disabled"
  env HOME="$H2" KEEPER_LAUNCHCTL="$T/launchctl" LCLOG="$T/lc2.log" "$v" bash "$HERE/install.sh" op-sepolia > "$T/inst.out" 2>&1; IRC=$?
  expect "first install with $v: exit 1, no plist and no script published" \
    '[ "$IRC" = 1 ] && [ ! -e "$H2/Library/LaunchAgents/$L.plist" ] && [ ! -e "$H2/.config/aastar-price-keeper-op-sepolia/run.sh" ]'
done

# ---------- publish failures and rollback
echo "# marker-before" >> "$D/run.sh"; cp "$D/run.sh" "$T/run.before"; chmod 500 "$LA"
: > "$T/lc.log"; in2 op-sepolia; chmod 700 "$LA"
expect "a publish that fails (LaunchAgents not writable) exits 1 and restores the replaced run.sh" \
  '[ "$IRC" = 1 ] && grep -q "previous files were put back" "$T/inst.out" && cmp -s "$D/run.sh" "$T/run.before"'
expect "no temp file or staging dir left behind" '! ls -a "$D" "$LA" | grep -qE "^\.(run\.sh|io\.aastar|stage|restore)"'
in2 op-sepolia; expect "CONTROL the same install then succeeds" '[ "$IRC" = 0 ] && cmp -s "$D/run.sh" "$HERE/run.sh"'
# a first install whose publish fails removes the files it created
H3="$T/home3"; mkdir -p "$H3/Library/LaunchAgents"; chmod 500 "$H3/Library/LaunchAgents"
env HOME="$H3" KEEPER_LAUNCHCTL="$T/launchctl" LCLOG="$T/lc3.log" bash "$HERE/install.sh" op-sepolia > "$T/inst.out" 2>&1; IRC=$?
chmod 700 "$H3/Library/LaunchAgents"
expect "a failed first install removes the files it created" \
  '[ "$IRC" = 1 ] && [ ! -e "$H3/.config/aastar-price-keeper-op-sepolia/run.sh" ] && [ ! -e "$H3/.config/aastar-price-keeper-op-sepolia/entry.env" ]'
# a rollback that cannot complete: exit 4, INSTALL-INCOMPLETE, the staged copies kept
cp "$D/run.sh" "$T/run.good"; echo "# marker-2" >> "$D/run.sh"; chmod 500 "$LA"
cat > "$T/mv" <<'S'
#!/bin/bash
# the second rename into the entry dir (the rollback's restore) fails
case "${@: -1}" in */aastar-price-keeper-op-sepolia/run.sh) n=$(cat "$MVCOUNT" 2>/dev/null || echo 0); echo $((n + 1)) > "$MVCOUNT"; [ "$n" -ge 1 ] && exit 1 ;; esac
exec /bin/mv "$@"
S
chmod +x "$T/mv"; mkdir -p "$T/mvbin"; ln -sf "$T/mv" "$T/mvbin/mv"; rm -f "$T/mvcount"
env HOME="$H" KEEPER_LAUNCHCTL="$T/launchctl" LCLOG="$T/lc.log" MVCOUNT="$T/mvcount" PATH="$T/mvbin:/usr/bin:/bin" \
  bash -c "sed 's#^export PATH=\"#export PATH=\"$T/mvbin:#' '$HERE/install.sh' > '$T/install-mv.sh'; cp -R '$HERE/entries' '$T/' ; cp '$HERE'/*.in '$HERE'/run.sh '$HERE'/stale-watch.sh '$HERE'/status.mjs '$HERE'/keeperctl.sh '$T/'; bash '$T/install-mv.sh' op-sepolia" > "$T/inst.out" 2>&1; IRC=$?
chmod 700 "$LA"
expect "a rollback that cannot complete: exit 4, INSTALL-INCOMPLETE written, staged copies kept" \
  '[ "$IRC" = 4 ] && [ -f "$D/INSTALL-INCOMPLETE" ] && ls -d "$D"/.stage.* >/dev/null 2>&1 && grep -q "ROLLBACK INCOMPLETE" "$T/inst.out"'
rm -rf "$D"/.stage.*; in2 op-sepolia
expect "the next successful install clears INSTALL-INCOMPLETE" '[ "$IRC" = 0 ] && [ ! -e "$D/INSTALL-INCOMPLETE" ]'

# the marker is in place before publishing: a SIGKILL in the middle leaves INSTALL-INCOMPLETE
cat > "$T/mvkill" <<'S'
#!/bin/bash
case "${@: -1}" in */aastar-price-keeper-op-sepolia/run.sh) kill -9 "$INSTALL_PID" ;; esac
exec /bin/mv "$@"
S
chmod +x "$T/mvkill"; mkdir -p "$T/killbin"; ln -sf "$T/mvkill" "$T/killbin/mv"
sed "s#^export PATH=\"#export PATH=\"$T/killbin:#" "$HERE/install.sh" > "$T/pk-kill.sh"
mkdir -p "$T/pkk"; cp -R "$HERE/entries" "$HERE"/*.in "$HERE/run.sh" "$HERE/stale-watch.sh" "$HERE/status.mjs" "$HERE/keeperctl.sh" "$T/pkk/"
cp "$T/pk-kill.sh" "$T/pkk/install.sh"; echo "# before-kill" >> "$D/run.sh"
env HOME="$H" KEEPER_LAUNCHCTL="$T/launchctl" LCLOG="$T/lc.log" bash -c 'export INSTALL_PID=$$; exec bash "$0" op-sepolia' "$T/pkk/install.sh" > "$T/inst.out" 2>&1; IRC=$?
expect "an install killed (SIGKILL) while publishing leaves INSTALL-INCOMPLETE behind" '[ "$IRC" = 137 ] && [ -f "$D/INSTALL-INCOMPLETE" ] && grep -q "publishing in progress" "$D/INSTALL-INCOMPLETE"'
rm -rf "$D"/.stage.* "$D"/.run.sh.* ; in2 op-sepolia
expect "the next install completes and removes the marker" '[ "$IRC" = 0 ] && [ ! -e "$D/INSTALL-INCOMPLETE" ]'
# a marker path that is a link to a secret: replaced by rename, the secret untouched
cp "$D/key.env" "$T/key.before"; ln -s "$D/key.env" "$D/INSTALL-INCOMPLETE"; chmod 500 "$LA"; in2 op-sepolia; chmod 700 "$LA"
expect "an INSTALL-INCOMPLETE link to key.env never writes key.env (publish failed, rollback ok)" \
  '[ "$IRC" = 1 ] && cmp -s "$D/key.env" "$T/key.before" && [ ! -e "$D/INSTALL-INCOMPLETE" ] && [ ! -L "$D/INSTALL-INCOMPLETE" ]'
mv "$D" "$T/entrydir"; ln -s "$T/entrydir" "$D"; in2 op-sepolia
expect "an entry dir that is a link refused" '[ "$IRC" = 65 ] && grep -q "is a link" "$T/inst.out"'
rm "$D"; mv "$T/entrydir" "$D"

# ---------- refused destinations and names
mv "$D/entry.env" "$T/entry.keep"; ln -s "$D/key.env" "$D/entry.env"; in2 op-sepolia
expect "an entry.env that is a link refused, the link left alone" '[ "$IRC" = 65 ] && grep -q "is a link" "$T/inst.out" && [ -L "$D/entry.env" ] && ! grep -q 0x "$T/inst.out"'
rm "$D/entry.env"; cp "$T/entry.keep" "$D/entry.env"; ln "$D/entry.env" "$T/entry.hardlink"; in2 op-sepolia
expect "an entry.env with another hard link refused" '[ "$IRC" = 65 ] && grep -q "other hard links" "$T/inst.out"'
rm "$T/entry.hardlink"; mv "$D/run.sh" "$T/run.keep"; mkdir "$D/run.sh"; in2 op-sepolia
expect "a run.sh that is a directory refused" '[ "$IRC" = 65 ] && grep -q "not a regular file" "$T/inst.out"'
rmdir "$D/run.sh"; mv "$T/run.keep" "$D/run.sh"
H4="$T/home&x"; mkdir -p "$H4"
env HOME="$H4" KEEPER_LAUNCHCTL="$T/launchctl" LCLOG="$T/lc4.log" bash "$HERE/install.sh" op-sepolia > "$T/inst.out" 2>&1; IRC=$?
expect "a HOME with a sed/plist metacharacter refused before anything is created" '[ "$IRC" = 65 ] && [ ! -e "$H4/.config" ] && [ ! -e "$H4/Library" ]'
cp -R "$HERE" "$T/pk"; sed -i '' 's#<string>io.aastar.price-keeper-@ENTRY@</string>#<string>io.aastar.price-keeper-other</string>#' "$T/pk/keeper.plist.in"
env HOME="$H" KEEPER_LAUNCHCTL="$T/launchctl" LCLOG="$T/lc.log" bash "$T/pk/install.sh" op-sepolia > "$T/inst.out" 2>&1; IRC=$?
expect "a template whose rendered Label is not its own refused, nothing published" '[ "$IRC" = 70 ] && grep -q "wrong Label" "$T/inst.out" && [ "$(plutil -extract Label raw -o - "$KP")" = "$L" ]'
for n in bin list stale-watch op-sepolia-stale-watch 'op;rm' 'Op'; do
  in2 "$n"; expect "entry name '$n' refused (usage)" '[ "$IRC" = 64 ]'
done
in2 no-such; expect "unknown entry refused" '[ "$IRC" = 66 ]'

# ---------- locks
hold() { # FILE SECONDS -> a background process holds an flock on FILE; its pid in $HOLDER
  ( exec 9>>"$1"; perl -e 'use Fcntl qw(:flock); open(my $f, ">&=", 9) or exit 3; flock($f, LOCK_EX) or exit 1'; exec sleep "$2" ) &
  HOLDER=$!; sleep 1; }
hold "$D/.keeperctl.lock" 4; in2 op-sepolia
expect "the entry lock held (a pause or resume running): install exits 75" '[ "$IRC" = 75 ]'
wait "$HOLDER"; hold "$H/.config/aastar-price-keeper-bin/.install.lock" 30; in2 op-sepolia
expect "the install lock held (another entry installing): exit 75" '[ "$IRC" = 75 ]'
kill -9 "$HOLDER" 2>/dev/null; wait "$HOLDER" 2>/dev/null || true; in2 op-sepolia
expect "after the holder is killed (kill -9) the lock is free at once" '[ "$IRC" = 0 ]'
for k in 1 2; do
  ( env HOME="$H" KEEPER_LAUNCHCTL="$T/launchctl" LCLOG="$T/lc.c$k" bash "$HERE/install.sh" op-sepolia > "$T/conc.$k" 2>&1; echo $? > "$T/conc.rc$k" ) &
done; wait
expect "two concurrent installs: one 0 and one 75 (or both 0 in turn), and a consistent set" \
  '{ [ "$(sort "$T/conc.rc1" "$T/conc.rc2" | tr "\n" " ")" = "0 75 " ] || [ "$(cat "$T/conc.rc1" "$T/conc.rc2" | tr "\n" " ")" = "0 0 " ]; } && cmp -s "$D/run.sh" "$HERE/run.sh" && plutil -lint "$KP" >/dev/null'

exit "$fail"
