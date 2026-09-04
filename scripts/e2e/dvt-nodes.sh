#!/usr/bin/env bash
# DVT node service — one-click start / stop / logs / status / info for 3 DVT signer nodes.
# Provides /signature/sign URLs + node IDs + BLS public keys for upstream/downstream (aastar-sdk #63 etc.).
#
#   ./scripts/e2e/dvt-nodes.sh start     # build (if needed), gen keys (if needed), boot 3 nodes
#   ./scripts/e2e/dvt-nodes.sh status    # which nodes are up
#   ./scripts/e2e/dvt-nodes.sh info      # shareable table: URL / nodeId / publicKey
#   ./scripts/e2e/dvt-nodes.sh logs [N]  # tail node N log (default 1)
#   ./scripts/e2e/dvt-nodes.sh stop      # stop all 3
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
E2E="$REPO/.e2e"; DIST="$REPO/dist/main.js"
# Ports are configurable because the ALWAYS-ON testnet stack (docker-compose.testnet.yml, the nodes
# behind dvt1/2/3.aastar.io) binds 3001-3003 too. Booting this stack on the defaults would either
# refuse to start or, worse, require stopping the public nodes to run a local test. Override with
# E2E_PORTS="3011 3012 3013" to run both side by side.
read -r -a PORTS <<< "${E2E_PORTS:-3001 3002 3003}"
# Exactly three, checked here. Every loop below indexes PORTS[0..2]; a shorter list would fail at
# `${PORTS[2]}` under `set -u` with an unbound-variable message that names neither this variable nor
# the mistake. Fail where the input is.
[ "${#PORTS[@]}" -eq 3 ] || {
  echo "E2E_PORTS must name exactly 3 ports, got ${#PORTS[@]}: '${E2E_PORTS:-}'" >&2
  exit 1
}
# 127.0.0.1, not localhost: on a dual-stack host localhost resolves to ::1 first and an unrelated
# IPv6 listener answers instead of the node (that is exactly how selftest.mjs hit a Next.js dev
# server on *:3001). Override with DVT_NODE_HOST.
HOST="${DVT_NODE_HOST:-127.0.0.1}"
cd "$REPO"

ensure() {
  [ -f "$DIST" ] || { echo "build dist..."; npm run build >/dev/null; }
  [ -f "$E2E/node1/node_state.json" ] || { echo "gen node keys..."; node scripts/e2e/gen-nodes.mjs; }
  if [ ! -f "$E2E/common.env" ]; then
    node -e 'const fs=require("fs");const s=x=>x.replace(/^["\x27]|["\x27]$/g,"");const e=Object.fromEntries(fs.readFileSync(".env.sepolia","utf8").split("\n").filter(l=>l.includes("=")).map(l=>{const i=l.indexOf("=");return [l.slice(0,i).trim(),s(l.slice(i+1).trim())]}));fs.writeFileSync(".e2e/common.env",["ETH_RPC_URL="+(e.SEPOLIA_RPC_URL||e.RPC_URL),"VALIDATOR_CONTRACT_ADDRESS="+(e.AIRACCOUNT_V020_BLS_ALGORITHM||"0xAF525A161CB17e0A1b6254ef0B8d8473bdA05174"),"ENTRY_POINT_ADDRESS="+(e.ENTRY_POINT_ADDRESS||e.ENTRYPOINT_ADDRESS),"POLICY_ENABLED=false",""].join("\n"))'
  fi
}
start() {
  ensure
  for i in 1 2 3; do
    local port="${PORTS[$((i-1))]}"
    if lsof -ti "tcp:$port" >/dev/null 2>&1; then echo "node$i already up on :$port"; continue; fi
    ( cd "$E2E/node$i"; set -a; . "$E2E/common.env"; set +a; export PORT="$port"
      nohup node "$DIST" > "$E2E/node$i.log" 2>&1 & echo $! > "$E2E/node$i.pid" )
    echo "node$i starting on :$port (pid $(cat "$E2E/node$i.pid"))"
  done
  echo "waiting for health..."; sleep 10; status
}
stop() {
  for i in 1 2 3; do
    [ -f "$E2E/node$i.pid" ] && kill -9 "$(cat "$E2E/node$i.pid")" 2>/dev/null || true
    lsof -ti "tcp:${PORTS[$((i-1))]}" 2>/dev/null | xargs kill -9 2>/dev/null || true
    rm -f "$E2E/node$i.pid"
  done
  echo "all DVT nodes stopped"
}
status() {
  for i in 1 2 3; do
    local port="${PORTS[$((i-1))]}"
    if curl -s -m 4 "http://$HOST:$port/node/info" >/dev/null 2>&1; then echo "  node$i :$port  ✅ UP"; else echo "  node$i :$port  ❌ down"; fi
  done
}
info() {
  echo "# DVT DVT signer nodes — for aastar-sdk #63 / upstream-downstream"
  echo "# endpoint: POST {url}/signature/sign  body {userOp, ownerAuth}  → {nodeId, signature(EIP-2537), publicKey}"
  for i in 1 2 3; do
    local port="${PORTS[$((i-1))]}"
    # Values go through the ENVIRONMENT, not through shell string-splicing. The splice this replaces
    # left `$HOST` inside a single-quoted argument, so neither bash nor JS expanded it and the table
    # printed a literal `url=http://$HOST:3001` — a shareable table whose URLs do not resolve.
    NODE_I="$i" NODE_HOST="$HOST" NODE_PORT="$port" node -e 'const {NODE_I:i,NODE_HOST:h,NODE_PORT:p}=process.env;const s=require(`./.e2e/node${i}/node_state.json`);console.log(`node${i} | url=http://${h}:${p} | nodeId=${s.nodeId} | pubKey=0x${s.publicKey}`)'
  done
  echo "# node1/node2 BLS pubkeys are registered on AAStarBLSAlgorithm (BLS_TEST_1/2); node3 is fresh (register before on-chain use)."
}
case "${1:-}" in
  start) start ;; stop) stop ;; status) status ;; info) info ;;
  logs) tail -n 40 -f "$E2E/node${2:-1}.log" ;;
  *) echo "usage: $0 {start|stop|status|info|logs [N]}"; exit 1 ;;
esac
