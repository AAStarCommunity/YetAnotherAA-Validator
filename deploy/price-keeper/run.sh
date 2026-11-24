#!/usr/bin/env bash
# Launchd entry point for one price-keeper entry on the Mac Mini. The entry's plist runs the copy of
# this file inside ~/.config/aastar-price-keeper-<entry>/; the entry is that directory, nothing else.
# Calls tsx directly: `pnpm exec` on pnpm 12 re-runs install and fails on ignored build scripts.
#
# No file is sourced. entry.env, rpc.env, key.env and telegram.env are read as data, each for its own
# fields only, and the keeper starts with an environment built from those fields alone.
set -euo pipefail
set +o xtrace +o allexport   # an inherited SHELLOPTS must not trace the key or export every assignment
# Nothing inherited survives, before any variable of this script exists: an exported F_* or args from
# launchd or a caller cannot reach a setting. PATH and HOME are kept; PATH is then fixed.
for v in $(compgen -e); do case "$v" in PATH | HOME) ;; *) unset "$v" 2>/dev/null || true ;; esac; done
export PATH="/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin"
CONFIG_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
die() { echo "run.sh: $*" >&2; exit 78; }   # 78 = EX_CONFIG

# The settings an entry may have. Anything else in entry.env is refused.
ENTRY_FIELDS=" KEEPER_ENTRY KEEPER_NETWORK KEEPER_SDK_DIR KEEPER_SUPERPAYMASTER KEEPER_PAYMASTER
  KEEPER_HARD_MAX_FEE_GWEI KEEPER_MIN_BALANCE_WEI KEEPER_ETHUSD_URL KEEPER_POLL_INTERVAL
  KEEPER_SAFETY_MARGIN KEEPER_HEALTH_INTERVAL KEEPER_CHAINLINK_STALE_SEC KEEPER_VOL_BPS KEEPER_VOL_COOLDOWN "

# read_fields FILE "NAME ..." -> sets F_<NAME> for each NAME found. Every line must be blank, a
# comment, or NAME=value with NAME in the list, at most once; value is bare (no quote, $, backtick,
# backslash, space or shell metacharacter) or wholly inside double quotes with none of " $ ` \.
read_fields() {
  local file="$1" allowed n=0 line name value
  allowed=" $(printf '%s ' $2)"   # word-split on purpose: the list may span lines
  [ -f "$file" ] || die "missing $file"
  # printable ASCII and newlines only, so this reader and status.mjs see the same bytes
  [ "$(LC_ALL=C tr -d '\n -~' < "$file" | wc -c | tr -d ' ')" = 0 ] || die "$(basename "$file") holds a byte outside printable ASCII"
  while IFS= read -r line || [ -n "$line" ]; do
    n=$((n + 1))
    case "$line" in '' | '#'*) continue ;; esac
    [[ "$line" =~ ^([A-Z_][A-Z0-9_]*)=(.*)$ ]] || die "$(basename "$file") line $n is not NAME=value"
    name="${BASH_REMATCH[1]}"; value="${BASH_REMATCH[2]}"
    case "$allowed" in *" $name "*) ;; *) die "$(basename "$file") line $n: $name is not allowed in this file" ;; esac
    if [[ "$value" =~ ^\"([^\"\$\`\\]*)\"$ ]]; then value="${BASH_REMATCH[1]}"
    elif ! [[ "$value" =~ ^[^\"\'\$\`\\\;\&\|\<\>\(\)[:space:]]*$ ]]; then die "$(basename "$file") line $n: $name has an unsupported value"; fi
    eval "[ -z \"\${F_$name+x}\" ]" || die "$(basename "$file") line $n: $name is set twice"
    printf -v "F_$name" '%s' "$value"
  done < "$file"
}

read_fields "$CONFIG_DIR/entry.env" "$ENTRY_FIELDS"
get() { eval "printf '%s' \"\${F_$1:-}\""; }
ENTRY="$(get KEEPER_ENTRY)"; NETWORK="$(get KEEPER_NETWORK)"; SP="$(get KEEPER_SUPERPAYMASTER)"
PM="$(get KEEPER_PAYMASTER)"; FEE="$(get KEEPER_HARD_MAX_FEE_GWEI)"; SDK="$(get KEEPER_SDK_DIR)"

[[ "$ENTRY" =~ ^[a-z0-9][a-z0-9-]*$ ]] || die "KEEPER_ENTRY must be lowercase letters, digits and dashes"
# reserved as in install.sh and keeperctl.sh: bin, list, stale-watch and *-stale-watch (watcher labels)
case "$ENTRY" in bin | list | stale-watch | *-stale-watch) die "KEEPER_ENTRY $ENTRY is a reserved name" ;; esac
[ "$(basename "$CONFIG_DIR")" = "aastar-price-keeper-$ENTRY" ] ||
  die "entry $ENTRY must live in ~/.config/aastar-price-keeper-$ENTRY, not $CONFIG_DIR"
case "$NETWORK" in
  op-sepolia | sepolia) MAINNET="" ;;
  op-mainnet | mainnet) MAINNET=1 ;;
  *) die "KEEPER_NETWORK must be op-sepolia, sepolia, op-mainnet or mainnet" ;;
esac
addr='^0x[0-9a-fA-F]{40}$'
[[ "$SP" =~ $addr ]] || die "KEEPER_SUPERPAYMASTER must be a 0x-prefixed 20-byte address"
[ -z "$PM" ] || [[ "$PM" =~ $addr ]] || die "KEEPER_PAYMASTER must be empty or an address"
[[ "$FEE" =~ ^[0-9]+(\.[0-9]+)?$ ]] || die "KEEPER_HARD_MAX_FEE_GWEI is required (an absolute fee ceiling)"
[[ "$(get KEEPER_MIN_BALANCE_WEI)" =~ ^[0-9]+$ ]] || die "KEEPER_MIN_BALANCE_WEI is required (status.mjs alerts below it)"
# The keeper code is an aastar-sdk worktree next to the others, named in entry.env (reviewed by PR).
[[ "$SDK" =~ ^~/Dev/aastar/aastar-sdk[A-Za-z0-9._-]*$ ]] || die "KEEPER_SDK_DIR must be ~/Dev/aastar/aastar-sdk<suffix>"
SDK_DIR="$HOME/${SDK#\~/}"
for k in KEEPER_POLL_INTERVAL KEEPER_SAFETY_MARGIN KEEPER_HEALTH_INTERVAL KEEPER_CHAINLINK_STALE_SEC KEEPER_VOL_BPS KEEPER_VOL_COOLDOWN; do
  v="$(get "$k")"; [ -z "$v" ] || [[ "$v" =~ ^[0-9]+$ ]] || die "$k must be an integer"
done
# A mainnet entry has its own key, generated for it: never a link to another entry's key file.
if [ -n "$MAINNET" ] && [ -L "$CONFIG_DIR/key.env" ]; then
  die "a $NETWORK entry needs its own key.env, not a link to another entry's key"
fi

# Only the caller's operational flags pass through; target, network, paymaster and fee come from entry.env.
for a in "$@"; do case "$a" in --once | --dry-run) ;; *) die "argument $a is not accepted (only --once, --dry-run)" ;; esac; done

read_fields "$CONFIG_DIR/rpc.env" "RPC_URL"
read_fields "$CONFIG_DIR/key.env" "KEEPER_PRIVATE_KEY"
[ -n "${F_RPC_URL:-}" ] || die "rpc.env has no RPC_URL"
[ -n "${F_KEEPER_PRIVATE_KEY:-}" ] || die "key.env has no KEEPER_PRIVATE_KEY"
[ ! -f "$CONFIG_DIR/telegram.env" ] || read_fields "$CONFIG_DIR/telegram.env" "TELEGRAM_BOT_TOKEN TELEGRAM_CHAT_ID"

LOG="$HOME/Library/Logs/aastar-price-keeper-$ENTRY.log"
# A keeper log once reached 558k lines. launchd holds the fd, so rotate only at start.
if [ -f "$LOG" ] && [ "$(stat -f %z "$LOG")" -gt 52428800 ]; then
  : > "$LOG"
fi

if [ -n "$PM" ]; then paymaster=(--paymaster "$PM"); else paymaster=(--no-paymaster); fi
opt() { local v; v="$(get "$1")"; printf '%s' "${v:-$2}"; }   # an optional setting, or its default
args=(
  --network "$NETWORK" --superpaymaster "$SP" "${paymaster[@]}"
  --external-ethusd-url "$(opt KEEPER_ETHUSD_URL 'https://api.binance.com/api/v3/ticker/price?symbol=ETHUSDT')"
  --poll-interval "$(opt KEEPER_POLL_INTERVAL 180)"
  --safety-margin "$(opt KEEPER_SAFETY_MARGIN 600)"
  --health-interval "$(opt KEEPER_HEALTH_INTERVAL 1800)"
  --chainlink-stale-sec "$(opt KEEPER_CHAINLINK_STALE_SEC 4200)"
  --volatility-threshold-bps "$(opt KEEPER_VOL_BPS 150)"
  --volatility-cooldown "$(opt KEEPER_VOL_COOLDOWN 600)"
  --hard-max-fee-gwei "$FEE"
)

# keeper.ts also loads .env.<network> from its working directory; this entry's settings must be the only ones.
for f in ".env.$NETWORK" .env.optimism .env.op-mainnet; do
  [ ! -e "$SDK_DIR/$f" ] || die "$SDK_DIR/$f exists; keeper.ts would read it. Remove it: the entry's files are the only config"
done

# The key must be the one this entry's address file names, so status.mjs watches the account that
# pays: a key copied in from another entry is refused before the keeper starts. The key reaches the
# check through the environment of that one child, never its arguments.
[ -f "$CONFIG_DIR/address" ] || die "missing $CONFIG_DIR/address"
want="$(cat "$CONFIG_DIR/address"; printf x)"; want="${want%x}"; want="${want%$'\n'}"   # one line, at most one newline
[[ "$want" =~ $addr ]] || die "address file must hold exactly one address on one line"
[[ "$F_KEEPER_PRIVATE_KEY" =~ ^0x[0-9a-fA-F]{64}$ ]] || die "key.env: KEEPER_PRIVATE_KEY must be 0x and 64 hex digits"
command -v node >/dev/null || die "node is not on PATH ($PATH)"
cd "$SDK_DIR"
got="$(KEY="$F_KEEPER_PRIVATE_KEY" node -e '
  const { createRequire } = require("node:module");
  const r = createRequire(process.cwd() + "/packages/core/package.json");
  process.stdout.write(r("viem/accounts").privateKeyToAccount(process.env.KEY).address);' 2>/dev/null)" ||
  die "cannot derive the signer address: viem/accounts did not load from $SDK_DIR/packages/core, or rejected the key"
[ "$(printf '%s' "$got" | tr A-F a-f)" = "$(printf '%s' "$want" | tr A-F a-f)" ] ||
  die "key.env signs as $got, but this entry's address file names $want"

# The keeper's environment: PATH, HOME and the credential fields, nothing else.
export RPC_URL="$F_RPC_URL" KEEPER_PRIVATE_KEY="$F_KEEPER_PRIVATE_KEY"
[ -z "${F_TELEGRAM_BOT_TOKEN:-}" ] || export TELEGRAM_BOT_TOKEN="$F_TELEGRAM_BOT_TOKEN"
[ -z "${F_TELEGRAM_CHAT_ID:-}" ] || export TELEGRAM_CHAT_ID="$F_TELEGRAM_CHAT_ID"
exec node_modules/.bin/tsx scripts/keeper.ts "${args[@]}" "$@"
