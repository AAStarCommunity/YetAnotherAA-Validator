#!/usr/bin/env bash
# Observe or control the price keeper. On any other machine it re-runs itself on the Mac Mini over SSH.
#   keeperctl.sh status | start | restart | stop | logs [lines] | dry-run
set -uo pipefail
LABEL="io.aastar.price-keeper"
HOST_ALIAS="${KEEPER_SSH_HOST:-mac-mini}"
INSTALL_DIR='$HOME/.config/aastar-price-keeper'

if [ "$(scutil --get LocalHostName 2>/dev/null)" != "Jasons-Mac-mini" ]; then
  exec ssh -o BatchMode=yes -o ConnectTimeout=10 "$HOST_ALIAS" "bash $INSTALL_DIR/keeperctl.sh $*"
fi

export PATH="/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin"
CONFIG_DIR="$HOME/.config/aastar-price-keeper"
LOG="$HOME/Library/Logs/aastar-price-keeper.log"
TARGET="gui/$(id -u)/$LABEL"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"

case "${1:-status}" in
  status)
    launchctl print "$TARGET" 2>/dev/null | grep -E '^\s+(state|pid|runs|last exit code) =' \
      || echo "launchd: not loaded"
    grep -E '^TICK ' "$LOG" 2>/dev/null | tail -1
    grep -E 'action=sendTx|txHash' "$LOG" 2>/dev/null | tail -2
    exec node "$CONFIG_DIR/status.mjs"
    ;;
  start)
    launchctl enable "$TARGET"
    launchctl bootstrap "gui/$(id -u)" "$PLIST" 2>/dev/null
    launchctl kickstart "$TARGET"
    ;;
  restart) launchctl kickstart -k "$TARGET" ;;
  stop)
    launchctl bootout "$TARGET"
    launchctl disable "$TARGET"
    ;;
  logs) tail -n "${2:-50}" "$LOG" | sed -E 's#https?://[^ ]*alchemy[^ ]*#<rpc>#g' ;;
  dry-run) exec bash "$CONFIG_DIR/run.sh" --once --dry-run ;;
  *) echo "usage: keeperctl.sh status|start|restart|stop|logs [lines]|dry-run" >&2; exit 64 ;;
esac
