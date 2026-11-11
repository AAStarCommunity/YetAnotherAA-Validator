#!/bin/bash
# launchd entry of the guardian watcher (ai.aastar.aoa-watcher) on the Mac Mini.
# Both RPC URLs come from the macOS Keychain (account aoa-watcher, services aoa-dvt-rpc-primary and
# aoa-dvt-rpc-secondary, DSR 0829236d) into this process's environment only; no URL is written in
# this file, in the plist or in the config. Phase D (phase-d-check.mjs) checks that the running job
# is this wrapper, that it names the same config, and that it reads exactly these two services.
set -euo pipefail
export PATH="/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin"
WATCHER_CONFIG="__WATCHER_CONFIG__"
WATCHER_ENTRY="__WATCHER_ENTRY__"
RPC_URL="$(security find-generic-password -s aoa-dvt-rpc-primary -a aoa-watcher -w)"
RPC_URL_2="$(security find-generic-password -s aoa-dvt-rpc-secondary -a aoa-watcher -w)"
export RPC_URL RPC_URL_2
exec node "$WATCHER_ENTRY" --config "$WATCHER_CONFIG"
