#!/usr/bin/env bash
# Manage AAStar's 3 testnet DVT nodes (independent keys, ports 4001/2/3) + the
# Cloudflare named tunnel that exposes them at dvt1/2/3.aastar.io.
#
#   ./deploy/dvt-testnet.sh start      # build (if needed) + boot 3 nodes + cloudflared
#   ./deploy/dvt-testnet.sh stop       # stop the 3 nodes + cloudflared
#   ./deploy/dvt-testnet.sh restart    # stop then start
#   ./deploy/dvt-testnet.sh status     # local nodes + cloudflared + public dvt*.aastar.io
#   ./deploy/dvt-testnet.sh info       # nodeId + public URL + pubkey
#   ./deploy/dvt-testnet.sh logs [N|cf] # tail node N (default 1) or cloudflared log
#
# Reads: deploy/.env.testnet, deploy/.cf-run-token, deploy/node{1,2,3}/node_state.json
# Runtime (logs/pids) in deploy/.run/ (git-ignored). For Docker instead, use
# docker-compose.testnet.yml (see deploy/README.md).
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"
DIST="$REPO/dist/main.js"
ENVF="$REPO/deploy/.env.testnet"
TOKENF="$REPO/deploy/.cf-run-token"
RUN="$REPO/deploy/.run"
mkdir -p "$RUN"
PORTS=(4001 4002 4003)
HOSTS=(dvt1 dvt2 dvt3)

# Precise: only OUR cloudflared, tracked by pid file — never pkill (would kill
# other tunnels on a shared host).
cf_running() { [ -f "$RUN/cloudflared.pid" ] && kill -0 "$(cat "$RUN/cloudflared.pid" 2>/dev/null)" 2>/dev/null; }

start() {
  [ -f "$DIST" ] || { echo "build dist…"; npm run build >/dev/null; }
  [ -f "$ENVF" ] || { echo "missing $ENVF — see deploy/README.md"; exit 1; }
  for i in 1 2 3; do
    local port="${PORTS[$((i - 1))]}"
    if lsof -ti "tcp:$port" >/dev/null 2>&1; then echo "node$i already up on :$port"; continue; fi
    [ -f "$REPO/deploy/node$i/node_state.json" ] || { echo "missing deploy/node$i/node_state.json — gen keys (deploy/README.md §1)"; exit 1; }
    (
      cd "$REPO/deploy/node$i"
      set -a; . "$ENVF"; set +a
      export PORT="$port"
      nohup node "$DIST" >"$RUN/node$i.log" 2>&1 &
      echo $! >"$RUN/node$i.pid"
    )
    echo "node$i starting on :$port (pid $(cat "$RUN/node$i.pid"))"
  done
  if cf_running; then
    echo "cloudflared already running"
  else
    [ -f "$TOKENF" ] || { echo "missing $TOKENF — run: node deploy/cf-tunnel-setup.mjs"; exit 1; }
    nohup cloudflared tunnel --no-autoupdate run --token "$(cat "$TOKENF")" >"$RUN/cloudflared.log" 2>&1 &
    echo $! >"$RUN/cloudflared.pid"
    echo "cloudflared starting (pid $(cat "$RUN/cloudflared.pid"))"
  fi
  echo "waiting for health…"
  sleep 9
  status
}

stop() {
  for i in 1 2 3; do
    [ -f "$RUN/node$i.pid" ] && kill "$(cat "$RUN/node$i.pid")" 2>/dev/null || true
    lsof -ti "tcp:${PORTS[$((i - 1))]}" 2>/dev/null | xargs kill 2>/dev/null || true
    rm -f "$RUN/node$i.pid"
  done
  # Precise: kill ONLY our tracked cloudflared pid — never pkill (a shared host may
  # run other tunnels). If the pid file is gone we leave all cloudflared alone.
  if [ -f "$RUN/cloudflared.pid" ]; then
    kill "$(cat "$RUN/cloudflared.pid")" 2>/dev/null || true
    rm -f "$RUN/cloudflared.pid"
    echo "stopped 3 nodes + our cloudflared"
  else
    echo "stopped 3 nodes (no tracked cloudflared.pid — other tunnels untouched)"
  fi
}

status() {
  echo "local nodes:"
  for i in 1 2 3; do
    local port="${PORTS[$((i - 1))]}"
    if curl -s -m 4 "http://localhost:$port/node/info" >/dev/null 2>&1; then echo "  node$i :$port  ✅ UP"; else echo "  node$i :$port  ❌ down"; fi
  done
  cf_running && echo "cloudflared:  ✅ running" || echo "cloudflared:  ❌ down"
  echo "public:"
  for h in "${HOSTS[@]}"; do
    if curl -s -m 8 "https://$h.aastar.io/node/info" >/dev/null 2>&1; then echo "  https://$h.aastar.io  ✅"; else echo "  https://$h.aastar.io  ❌"; fi
  done
}

info() {
  echo "# AAStar testnet DVT — endpoints for the coordinator / SDK"
  for i in 1 2 3; do
    node -e 'const s=require("./deploy/node'"$i"'/node_state.json");console.log(`dvt'"$i"' | https://dvt'"$i"'.aastar.io | nodeId=${s.nodeId} | pub=0x${s.publicKey}`)'
  done
}

case "${1:-}" in
  start) start ;;
  stop) stop ;;
  restart) stop; sleep 2; start ;;
  status) status ;;
  info) info ;;
  logs)
    f="$RUN/node${2:-1}.log"
    [ "${2:-}" = "cf" ] && f="$RUN/cloudflared.log"
    tail -n 40 -f "$f"
    ;;
  *) echo "usage: $0 {start|stop|restart|status|info|logs [N|cf]}"; exit 1 ;;
esac
