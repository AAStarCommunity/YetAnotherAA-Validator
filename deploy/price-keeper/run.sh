#!/usr/bin/env bash
# Launchd entry point for the SuperPaymaster price keeper on the Mac Mini.
# Calls tsx directly: `pnpm exec` on pnpm 12 re-runs install and fails on ignored build scripts.
set -euo pipefail
export PATH="/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin"
CONFIG_DIR="$HOME/.config/aastar-price-keeper"
SDK_DIR="$HOME/Dev/aastar/aastar-sdk-price-keeper"
LOG="$HOME/Library/Logs/aastar-price-keeper.log"

# The previous keeper's log reached 558k lines. launchd holds the fd, so rotate only at start.
if [ -f "$LOG" ] && [ "$(stat -f %z "$LOG")" -gt 52428800 ]; then
  : > "$LOG"
fi

set -a
. "$CONFIG_DIR/rpc.env"
. "$CONFIG_DIR/key.env"
[ -f "$CONFIG_DIR/telegram.env" ] && . "$CONFIG_DIR/telegram.env"
set +a

cd "$SDK_DIR"
exec node_modules/.bin/tsx scripts/keeper.ts \
  --network sepolia \
  --superpaymaster "${KEEPER_SUPERPAYMASTER:-0x09DF0d2e3722EC0e401fE3819E64278a42ae4DE9}" \
  --paymaster "${KEEPER_PAYMASTER:-0x2118e9a404C15F70B1D4f53b400c8a566A5ea4B6}" \
  --external-ethusd-url "${KEEPER_ETHUSD_URL:-https://api.binance.com/api/v3/ticker/price?symbol=ETHUSDT}" \
  --poll-interval "${KEEPER_POLL_INTERVAL:-180}" \
  --safety-margin "${KEEPER_SAFETY_MARGIN:-600}" \
  --health-interval "${KEEPER_HEALTH_INTERVAL:-1800}" \
  --chainlink-stale-sec "${KEEPER_CHAINLINK_STALE_SEC:-4200}" \
  --volatility-threshold-bps "${KEEPER_VOL_BPS:-150}" \
  --volatility-cooldown "${KEEPER_VOL_COOLDOWN:-600}" \
  "$@"
