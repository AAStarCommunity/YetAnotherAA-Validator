#!/bin/bash
# launchd entry of the guardian watcher (ai.aastar.aoa-watcher) on the Mac Mini.
# Both RPC URLs come from the macOS Keychain (account aoa-watcher, services aoa-dvt-rpc-primary and
# aoa-dvt-rpc-secondary, DSR 0829236d) into this process's environment only; no URL is written in
# this file, in the plist or in the config. Phase D (phase-d-check.mjs) checks that the running job
# is this wrapper, that it names the same config, and that it reads exactly these two services.
# Install: render it from the SAME checkout Phase D runs from, changing nothing else (Phase D requires
# the installed file to equal this template with exactly these two values; absolute paths, no quotes
# or $):
#   sed -e "s|^WATCHER_CONFIG=\"__WATCHER_CONFIG__\"\$|WATCHER_CONFIG=\"$HOME/.aoa-watcher/config.json\"|" \
#       -e "s|^WATCHER_ENTRY=\"__WATCHER_ENTRY__\"\$|WATCHER_ENTRY=\"$REPO/services/guardian-watcher/watcher.mjs\"|" \
#       deploy/guardian-watcher/run-watcher.sh > ~/.aoa-watcher/run-watcher.sh
#   chmod 700 ~/.aoa-watcher/run-watcher.sh
set -euo pipefail
export PATH="/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin"
WATCHER_CONFIG="__WATCHER_CONFIG__"
WATCHER_ENTRY="__WATCHER_ENTRY__"
RPC_URL="$(security find-generic-password -s aoa-dvt-rpc-primary -a aoa-watcher -w)"
RPC_URL_2="$(security find-generic-password -s aoa-dvt-rpc-secondary -a aoa-watcher -w)"
export RPC_URL RPC_URL_2
exec node "$WATCHER_ENTRY" --config "$WATCHER_CONFIG"
