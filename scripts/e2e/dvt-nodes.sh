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
E2E="$REPO/.e2e"; DIST="$REPO/dist/main.js"; PORTS=(3001 3002 3003)
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
    if curl -s -m 4 "http://localhost:$port/node/info" >/dev/null 2>&1; then echo "  node$i :$port  ✅ UP"; else echo "  node$i :$port  ❌ down"; fi
  done
}
info() {
  echo "# DVT DVT signer nodes — for aastar-sdk #63 / upstream-downstream"
  echo "# endpoint: POST {url}/signature/sign  body {userOp, ownerAuth}  → {nodeId, signature(EIP-2537), publicKey}"
  for i in 1 2 3; do
    local port="${PORTS[$((i-1))]}"
    node -e 'const s=require("./.e2e/node'"$i"'/node_state.json");console.log(`node'"$i"' | url=http://localhost:'"$port"' | nodeId=${s.nodeId} | pubKey=0x${s.publicKey}`)'
  done
  echo "# node1/node2 BLS pubkeys are registered on AAStarBLSAlgorithm (BLS_TEST_1/2); node3 is fresh (register before on-chain use)."
}
case "${1:-}" in
  start) start ;; stop) stop ;; status) status ;; info) info ;;
  logs) tail -n 40 -f "$E2E/node${2:-1}.log" ;;
  *) echo "usage: $0 {start|stop|status|info|logs [N]}"; exit 1 ;;
esac
