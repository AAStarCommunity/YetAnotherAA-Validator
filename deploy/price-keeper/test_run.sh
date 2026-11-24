#!/bin/bash
# Offline test for run.sh: a fake HOME with one entry dir and a stub tsx that prints the keeper
# arguments. No chain, no launchd, no key.
#   bash deploy/price-keeper/test_run.sh      exit 0 = all cases pass
set -uo pipefail
[ "$(uname)" = Darwin ] || { echo "skip: run.sh is a macOS script (plutil, BSD stat)"; exit 0; }
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
fail=0
expect() { if eval "$2"; then echo "ok   $1"; else echo "FAIL $1"; fail=1; fi; }

H="$T/home"; D="$H/.config/aastar-price-keeper-op-sepolia"; mkdir -p -m 700 "$D"
# run.sh fixes PATH to the Mini's (node in /opt/homebrew/bin). The copy under test gets this test's
# bin dir in front of it, holding a link to this machine's node; that one line is the only change.
mkdir -p "$T/bin"; ln -s "$(command -v node)" "$T/bin/node"
sed "s#^export PATH=\"#export PATH=\"$T/bin:#" "$HERE/run.sh" > "$D/run.sh"
[ "$(diff "$HERE/run.sh" "$D/run.sh" | grep -c '^[<>]')" = 2 ] || { echo "FAIL the PATH line could not be adjusted"; exit 1; }
cp "$HERE/entries/op-sepolia.env" "$D/entry.env"
printf 'RPC_URL=http://127.0.0.1:9\n' > "$D/rpc.env"
printf 'KEEPER_PRIVATE_KEY=0x1111111111111111111111111111111111111111111111111111111111111111\n' > "$D/key.env"

# ---------- run.sh with a stub tsx
SDK="$H/Dev/aastar/aastar-sdk-price-keeper-next"; mkdir -p "$SDK/node_modules/.bin"
printf '#!/bin/bash\necho "CWD $(pwd -P)"\necho "KEY ${KEEPER_PRIVATE_KEY:-}"\necho "RPC ${RPC_URL:-}"\nenv | sed "s/^/ENV /"\nfor a in "$@"; do echo "ARG $a"; done\n' > "$SDK/node_modules/.bin/tsx"
chmod +x "$SDK/node_modules/.bin/tsx"
# a stub viem/accounts: each test key maps to one address; anything else throws like a malformed key
mkdir -p "$SDK/packages/core/node_modules/viem"; echo '{"name":"core"}' > "$SDK/packages/core/package.json"
echo '{"name":"viem"}' > "$SDK/packages/core/node_modules/viem/package.json"
cat > "$SDK/packages/core/node_modules/viem/accounts.js" <<'J'
const m = { "0x1111111111111111111111111111111111111111111111111111111111111111": "0x00000000000000000000000000000000000000C1", "0x2222222222222222222222222222222222222222222222222222222222222222": "0x00000000000000000000000000000000000000c2" };
exports.privateKeyToAccount = k => { if (!m[k]) throw new Error("bad key"); return { address: m[k] }; };
J
echo 0x00000000000000000000000000000000000000c1 > "$D/address"
mkdir -p "$H/Library/Logs"
runk() { env -i HOME="$H" PATH="/usr/bin:/bin" "$@" /bin/bash "$D/run.sh" > "$T/run.out" 2>&1; RRC=$?; }
arg() { grep -qxF "ARG $1" "$T/run.out"; }
next() { awk -v a="ARG $1" 'f{print substr($0,5); exit} $0==a{f=1}' "$T/run.out"; }

runk
expect "op-sepolia: exits 0 into the stub, cwd is the SDK dir" '[ "$RRC" = 0 ] && grep -qxF "CWD $(cd "$SDK" && pwd -P)" "$T/run.out"'
expect "the keeper's environment is PATH, HOME, RPC_URL and KEEPER_PRIVATE_KEY only" \
  '[ "$(grep "^ENV " "$T/run.out" | cut -d= -f1 | sed "s/^ENV //" | grep -vxE "PATH|HOME|RPC_URL|KEEPER_PRIVATE_KEY|PWD|SHLVL|_|OLDPWD" | wc -l | tr -d " ")" = 0 ]'
expect "op-sepolia: --network op-sepolia, the rc.8 SuperPaymaster, --hard-max-fee-gwei 2" \
  '[ "$(next --network)" = op-sepolia ] && [ "$(next --superpaymaster)" = 0x3c73dd3c576a594dd1e7afdeec9f8757c35a31e7 ] && [ "$(next --hard-max-fee-gwei)" = 2 ]'
expect "op-sepolia: explicit --no-paymaster and no --paymaster" 'arg --no-paymaster && ! arg --paymaster'
expect "op-sepolia: no retired address anywhere in the arguments" '! grep -qiE "0x09DF0d2e|0x2118e9a4|0xf250416C" "$T/run.out"'
expect "secrets come from rpc.env and key.env" 'grep -qxF "KEY 0x1111111111111111111111111111111111111111111111111111111111111111" "$T/run.out" && grep -qxF "RPC http://127.0.0.1:9" "$T/run.out"'
runk KEEPER_PAYMASTER=0x2118e9a404C15F70B1D4f53b400c8a566A5ea4B6 KEEPER_SUPERPAYMASTER=0x09DF0d2e3722EC0e401fE3819E64278a42ae4DE9 KEEPER_NETWORK=sepolia
expect "inherited KEEPER_* variables do not reach the entry" \
  '[ "$RRC" = 0 ] && arg --no-paymaster && [ "$(next --network)" = op-sepolia ] && ! grep -qiE "0x09DF0d2e|0x2118e9a4" "$T/run.out"'
env -i HOME="$H" PATH="/usr/bin:/bin" /bin/bash "$D/run.sh" --once --dry-run > "$T/run.out" 2>&1
expect "extra arguments are passed through last" '[ "$(tail -2 "$T/run.out" | tr "\n" " ")" = "ARG --once ARG --dry-run " ]'

cp "$D/entry.env" "$T/entry.good"
# what clearing KEEPER_* defends: a variable entry.env does not set
runk KEEPER_POLL_INTERVAL=1 KEEPER_ETHUSD_URL=http://evil.invalid/
expect "an inherited KEEPER_ setting that entry.env does not set is not used" \
  '[ "$RRC" = 0 ] && [ "$(next --poll-interval)" = 180 ] && ! grep -q evil.invalid "$T/run.out"'
grep -v '^KEEPER_PAYMASTER=' "$T/entry.good" > "$D/entry.env"
runk KEEPER_PAYMASTER=0x2118e9a404C15F70B1D4f53b400c8a566A5ea4B6
expect "entry.env without a KEEPER_PAYMASTER line: an inherited one does not reach it" \
  '[ "$RRC" = 0 ] && arg --no-paymaster && ! grep -qi 0x2118e9a4 "$T/run.out"'
cp "$T/entry.good" "$D/entry.env"
edit() { # replace (or add) each NAME=value line given; a line without a NAME= is appended as is
  cp "$T/entry.good" "$D/entry.env"
  local l; for l in "$@"; do
    case "$l" in [A-Z_]*=*) grep -v "^${l%%=*}=" "$D/entry.env" > "$T/e" || true; mv "$T/e" "$D/entry.env" ;; esac
    printf '%s\n' "$l" >> "$D/entry.env"
  done; runk; }
edit "KEEPER_PAYMASTER=0x00000000000000000000000000000000000000a4"
expect "a V4 address in entry.env gives --paymaster <it> and no --no-paymaster" '[ "$RRC" = 0 ] && [ "$(next --paymaster)" = 0x00000000000000000000000000000000000000a4 ] && ! arg --no-paymaster'
edit "KEEPER_PAYMASTER=0x123"; expect "a malformed V4 address refused" '[ "$RRC" = 78 ] && grep -q "KEEPER_PAYMASTER must be" "$T/run.out"'
edit "RPC_URL=http://x"; expect "entry.env with RPC_URL refused" '[ "$RRC" = 78 ] && grep -q "RPC_URL is not allowed in this file" "$T/run.out"'
edit "TELEGRAM_BOT_TOKEN=x"; expect "entry.env with a Telegram value refused" '[ "$RRC" = 78 ] && grep -q "TELEGRAM_BOT_TOKEN is not allowed" "$T/run.out"'
edit "CONFIG_DIR=/tmp/other"; expect "entry.env cannot set a launcher variable (unknown field)" '[ "$RRC" = 78 ] && grep -q "CONFIG_DIR is not allowed" "$T/run.out"'
edit "PRIVATE_KEY=x"; expect "entry.env: any name outside the field list refused" '[ "$RRC" = 78 ] && ! grep -q "^ARG" "$T/run.out"'
cp "$T/entry.good" "$D/entry.env"; echo "KEEPER_HARD_MAX_FEE_GWEI=9" >> "$D/entry.env"; runk
expect "a field set twice refused" '[ "$RRC" = 78 ] && grep -q "KEEPER_HARD_MAX_FEE_GWEI is set twice" "$T/run.out"'
edit "KEEPER_PAYMASTER='"; expect "a single quote in a bare value refused" '[ "$RRC" = 78 ] && grep -q "unsupported value" "$T/run.out"'
edit "KEEPER_SDK_DIR=/tmp/other-sdk"; expect "an SDK dir outside ~/Dev/aastar/aastar-sdk* refused" '[ "$RRC" = 78 ] && grep -q "KEEPER_SDK_DIR must be" "$T/run.out"'
edit "KEEPER_POLL_INTERVAL=1s"; expect "a non-integer interval refused" '[ "$RRC" = 78 ]'
edit "KEEPER_HARD_MAX_FEE_GWEI="; expect "no fee ceiling refused" '[ "$RRC" = 78 ] && grep -q HARD_MAX_FEE "$T/run.out"'
edit "KEEPER_NETWORK=base"; expect "unknown network refused" '[ "$RRC" = 78 ]'
edit "KEEPER_SUPERPAYMASTER=0x3c73"; expect "malformed SuperPaymaster refused" '[ "$RRC" = 78 ]'
edit "false"; expect "a command line in entry.env refused, with the line number" '[ "$RRC" = 78 ] && grep -q "line 16 is not NAME=value" "$T/run.out" && ! grep -q "^ARG" "$T/run.out"'
edit 'KEEPER_POLL_INTERVAL=$(echo 1)'; expect "a command substitution in entry.env refused" '[ "$RRC" = 78 ] && ! grep -q "^ARG" "$T/run.out"'
edit 'KEEPER_ETHUSD_URL="x"; echo hi'; expect "a second command after a value refused" '[ "$RRC" = 78 ] && ! grep -q "^ARG" "$T/run.out"'
edit "if then"; expect "a syntax error in entry.env refused before sourcing" '[ "$RRC" = 78 ] && ! grep -q "syntax error" "$T/run.out"'
edit 'KEEPER_ETHUSD_URL="https://api.example/x?symbol=ETHUSDT"' '# a comment' '' ; expect "CONTROL quoted URL, comment and blank line are accepted" '[ "$RRC" = 0 ] && [ "$(next --external-ethusd-url)" = "https://api.example/x?symbol=ETHUSDT" ]'
for n in bin list op-sepolia-stale-watch; do
  edit "KEEPER_ENTRY=$n"; expect "reserved entry name $n refused" '[ "$RRC" = 78 ] && grep -qE "reserved name|must live in" "$T/run.out"'
done
edit "KEEPER_ENTRY=op-mainnet"; expect "entry name not matching its directory refused" '[ "$RRC" = 78 ] && grep -q "must live in" "$T/run.out"'
cp "$T/entry.good" "$D/entry.env"

# a mainnet entry must have its own key file, not a link to a testnet entry's
M="$H/.config/aastar-price-keeper-op-mainnet"; mkdir -p "$M"; cp "$D/run.sh" "$D/rpc.env" "$M/"
echo 0x00000000000000000000000000000000000000c2 > "$M/address"
sed -e 's/^KEEPER_ENTRY=.*/KEEPER_ENTRY=op-mainnet/' -e 's/^KEEPER_NETWORK=.*/KEEPER_NETWORK=op-mainnet/' "$T/entry.good" > "$M/entry.env"
ln -s "$D/key.env" "$M/key.env"
env -i HOME="$H" PATH="/usr/bin:/bin" /bin/bash "$M/run.sh" > "$T/run.out" 2>&1; RRC=$?
expect "op-mainnet with a linked key.env refused" '[ "$RRC" = 78 ] && grep -q "needs its own key.env" "$T/run.out"'
rm "$M/key.env"; printf 'KEEPER_PRIVATE_KEY=0x2222222222222222222222222222222222222222222222222222222222222222\n' > "$M/key.env"
env -i HOME="$H" PATH="/usr/bin:/bin" /bin/bash "$M/run.sh" > "$T/run.out" 2>&1; RRC=$?
expect "CONTROL op-mainnet with its own key.env starts" '[ "$RRC" = 0 ] && grep -qxF "KEY 0x2222222222222222222222222222222222222222222222222222222222222222" "$T/run.out" && [ "$(next --network)" = op-mainnet ]'

# arguments, credential files and the SDK dir
env -i HOME="$H" PATH="/usr/bin:/bin" /bin/bash "$D/run.sh" --paymaster 0x2118e9a404C15F70B1D4f53b400c8a566A5ea4B6 > "$T/run.out" 2>&1; RRC=$?
expect "a --paymaster argument is not passed through" '[ "$RRC" = 78 ] && grep -q "argument --paymaster is not accepted" "$T/run.out" && ! grep -q "^ARG" "$T/run.out"'
cp "$D/rpc.env" "$T/rpc.good"; echo "# no url" > "$D/rpc.env"; runk RPC_URL=http://inherited.invalid
expect "an inherited RPC_URL is not used when rpc.env has none" '[ "$RRC" = 78 ] && grep -q "rpc.env has no RPC_URL" "$T/run.out" && ! grep -q inherited.invalid "$T/run.out"'
printf 'RPC_URL=http://127.0.0.1:9\nKEEPER_PAYMASTER=0x2118e9a404C15F70B1D4f53b400c8a566A5ea4B6\n' > "$D/rpc.env"; runk
expect "a credential file cannot set an entry field" '[ "$RRC" = 78 ] && grep -q "rpc.env line 2: KEEPER_PAYMASTER is not allowed" "$T/run.out"'
cp "$T/rpc.good" "$D/rpc.env"
runk FOO_INHERITED=1 OFFICIAL_OPERATOR=0x00000000000000000000000000000000000000ee
expect "inherited variables do not reach the keeper" '[ "$RRC" = 0 ] && ! grep -qE "^ENV (FOO_INHERITED|OFFICIAL_OPERATOR)=" "$T/run.out"'
touch "$SDK/.env.op-sepolia"; runk
expect "a .env.op-sepolia in the SDK dir refused" '[ "$RRC" = 78 ] && grep -q "keeper.ts would read it" "$T/run.out"'
rm "$SDK/.env.op-sepolia"; runk; expect "CONTROL without it, starts again" '[ "$RRC" = 0 ]'

# Codex round 2
printf 'KEEPER_PRIVATE_KEY=0x2222222222222222222222222222222222222222222222222222222222222222\n' > "$D/key.env"; runk
expect "a key that does not sign as the address file refused" '[ "$RRC" = 78 ] && grep -q "key.env signs as 0x0*c2, but this entry.s address file names 0x0*c1" "$T/run.out" && ! grep -q "^ARG" "$T/run.out"'
printf 'KEEPER_PRIVATE_KEY=0xgarbage\n' > "$D/key.env"; runk
expect "a key that is not 0x and 64 hex digits refused" '[ "$RRC" = 78 ] && grep -q "must be 0x and 64 hex digits" "$T/run.out"'
printf 'KEEPER_PRIVATE_KEY=0x3333333333333333333333333333333333333333333333333333333333333333\n' > "$D/key.env"; runk
expect "a key viem rejects refused" '[ "$RRC" = 78 ] && grep -q "cannot derive the signer address" "$T/run.out"'
printf 'KEEPER_PRIVATE_KEY=0x1111111111111111111111111111111111111111111111111111111111111111\n' > "$D/key.env"
runk SHELLOPTS=xtrace:allexport
expect "an inherited SHELLOPTS (xtrace, allexport) neither traces the key nor exports extra copies" \
  '[ "$RRC" = 0 ] && [ "$(grep -c "^+ " "$T/run.out")" -le 2 ] && ! grep -q "^+ .*KEEPER_PRIVATE_KEY" "$T/run.out" && ! grep -qE "^ENV F_" "$T/run.out"'
cp "$D/address" "$T/addr.good"; printf '0x0000000000000000000\n000000000000000000000c1\n' > "$D/address"; runk
expect "an address split over two lines refused" '[ "$RRC" = 78 ] && grep -q "exactly one address on one line" "$T/run.out"'
printf '0x00000000000000000000000000000000000000c1\n\n' > "$D/address"; runk
expect "an address followed by a blank line refused (as status.mjs does)" '[ "$RRC" = 78 ] && grep -q "exactly one address on one line" "$T/run.out"'
printf '0x00000000000000000000000000000000000000c1' > "$D/address"; runk
expect "CONTROL an address without a trailing newline is accepted" '[ "$RRC" = 0 ]'
cp "$T/addr.good" "$D/address"
printf 'KEEPER_PRIVATE_KEY=0x1111111111111111111111111111111111111111111111111111111111111111\n' > "$D/key.env"
grep -v '^KEEPER_PAYMASTER=' "$T/entry.good" > "$D/entry.env"
runk F_KEEPER_PAYMASTER=0x2118e9a404C15F70B1D4f53b400c8a566A5ea4B6 F_KEEPER_NETWORK=op-mainnet
expect "an inherited F_* cannot set a field (KEEPER_PAYMASTER line omitted)" \
  '[ "$RRC" = 0 ] && arg --no-paymaster && ! arg --paymaster && [ "$(next --network)" = op-sepolia ]'
cp "$T/entry.good" "$D/entry.env"
runk args=placeholder paymaster=x
expect "CONTROL an inherited exported args/paymaster does not break the launch" '[ "$RRC" = 0 ] && arg --no-paymaster'
expect "each target flag appears exactly once" \
  '[ "$(grep -cxE "ARG --(network|superpaymaster|no-paymaster|hard-max-fee-gwei)" "$T/run.out")" = 4 ] && ! arg --paymaster'
printf 'KEEPER_ENTRY=op-sepolia\000x\n' > "$T/nul"; cat "$T/entry.good" >> "$T/nul"; cp "$T/nul" "$D/entry.env"; runk
expect "a NUL byte in entry.env refused" '[ "$RRC" = 78 ] && grep -q "byte outside printable ASCII" "$T/run.out"'
edit "$(printf 'KEEPER_ETHUSD_URL=a\302\240b')"; expect "a non-ASCII byte (NBSP) refused" '[ "$RRC" = 78 ] && grep -q "byte outside printable ASCII" "$T/run.out"'
edit "$(printf 'KEEPER_ETHUSD_URL=ab\r')"; expect "a CR refused" '[ "$RRC" = 78 ] && grep -q "byte outside printable ASCII" "$T/run.out"'
edit "KEEPER_MIN_BALANCE_WEI="; expect "no gas floor refused" '[ "$RRC" = 78 ] && grep -q "KEEPER_MIN_BALANCE_WEI is required" "$T/run.out"'
cp "$T/entry.good" "$D/entry.env"; runk; expect "CONTROL the good entry still starts" '[ "$RRC" = 0 ]'

exit "$fail"
