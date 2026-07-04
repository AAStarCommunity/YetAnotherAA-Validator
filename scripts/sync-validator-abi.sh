#!/usr/bin/env bash
# Export the AAStarValidator ABI + a deployed-address record for the SDK to consume
# (aastar-sdk#270). Run after a validator (re)deploy. No secrets touched.
#
#   VALIDATOR=0x… NETWORK=sepolia ./scripts/sync-validator-abi.sh [sdk-path]
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NETWORK="${NETWORK:-sepolia}"
VALIDATOR="${VALIDATOR:?set VALIDATOR=0x… (the deployed Plan A v3 validator)}"
OUT="$REPO/deployments"; mkdir -p "$OUT"

# 1. ABI from the forge artifact (source of truth after `forge build`).
( cd "$REPO/contracts" && forge build src/AAStarValidator.sol >/dev/null )
jq '.abi' "$REPO/contracts/out/AAStarValidator.sol/AAStarValidator.json" > "$OUT/AAStarValidator.abi.json"
echo "✅ ABI → $OUT/AAStarValidator.abi.json"

# 2. Address record (append/replace per network).
ADDR_FILE="$OUT/validator.$NETWORK.json"
jq -n --arg v "$VALIDATOR" --arg n "$NETWORK" \
  '{network:$n, aaStarValidator:$v, note:"Plan A v3 stake-bound (#163)"}' > "$ADDR_FILE"
echo "✅ address → $ADDR_FILE ($VALIDATOR)"

# 3. Optional: copy into the SDK if a path is given.
SDK="${1:-}"
if [ -n "$SDK" ] && [ -d "$SDK" ]; then
  mkdir -p "$SDK/abi" "$SDK/deployments"
  cp "$OUT/AAStarValidator.abi.json" "$SDK/abi/AAStarValidator.abi.json"
  cp "$ADDR_FILE" "$SDK/deployments/"
  echo "✅ synced into SDK at $SDK (abi/ + deployments/) — commit + bump there"
else
  echo "ℹ  pass the aastar-sdk path to auto-copy: ./scripts/sync-validator-abi.sh ../aastar-sdk"
fi
