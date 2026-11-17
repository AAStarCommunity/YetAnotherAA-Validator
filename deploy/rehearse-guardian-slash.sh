#!/bin/bash
# #441 acceptance: fresh local anvil + SP DeployAnvil, then deploy/rehearse-guardian-slash.mjs.
#   SP_DIR     an SP checkout already built with `forge build`. Fetch it into its own directory with
#              `gh api repos/AAStarCommunity/SuperPaymaster/tarball/<sha>` plus its contracts/lib
#              submodules; never use another session's worktree.
#   SP_COMMIT  the 40-hex commit SP_DIR was fetched at (recorded in the report).
#   PORT       anvil port (default 18645; must be free).
# This repo's contracts must be built first (`cd contracts && forge build`).
# Usage: SP_DIR=... SP_COMMIT=... deploy/rehearse-guardian-slash.sh [report.json]
set -euo pipefail
: "${SP_DIR:?set SP_DIR}" "${SP_COMMIT:?set SP_COMMIT}"
PORT=${PORT:-18645}
WT=$(cd "$(dirname "$0")/.." && pwd)
REPORT=${1:-$WT/docs/evidence/441-acceptance-report.json}
B=$(mktemp -d "${TMPDIR:-/tmp}/rehearse-441.XXXXXX")
ANVIL=${ANVIL:-$(command -v anvil || echo "$HOME/.foundry/bin/anvil")}
FORGE=${FORGE:-$(command -v forge || echo "$HOME/.foundry/bin/forge")}
R=http://127.0.0.1:$PORT
K0=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 # anvil account 0, chain 31337 only

[ -f "$WT/contracts/out/OverIssueFraudProofVerifier.sol/OverIssueFraudProofVerifier.json" ] || { echo "build contracts/ first"; exit 1; }
lsof -nP -iTCP:"$PORT" -sTCP:LISTEN >/dev/null && { echo "port $PORT is busy"; exit 1; }
"$ANVIL" --port "$PORT" --chain-id 31337 --hardfork prague --code-size-limit 100000 --silent > "$B/anvil.log" 2>&1 &
APID=$!
trap 'kill $APID 2>/dev/null || true' EXIT
sleep 3
( cd "$SP_DIR" && LOCAL_DEV_GOVERNANCE_ACK=true "$FORGE" script "contracts/script/v3/DeployAnvil.s.sol:DeployAnvil" \
    --rpc-url "$R" --broadcast --slow --disable-code-size-limit --timeout 300 --non-interactive \
    --private-key "$K0" --offline > "$B/deploy.log" 2>&1 )
mkdir -p "$(dirname "$REPORT")"
( cd "$WT" && node deploy/rehearse-guardian-slash.mjs "$R" "$SP_DIR/deployments/config.anvil.json" "$WT/contracts/out" "$REPORT" )
RC=$?
python3 - "$REPORT" "$SP_COMMIT" <<'PY'
import json, sys
p, c = sys.argv[1:]
r = json.load(open(p)); r["spCommit"] = c
json.dump(r, open(p, "w"), indent=2); open(p, "a").write("\n")
PY
exit $RC
