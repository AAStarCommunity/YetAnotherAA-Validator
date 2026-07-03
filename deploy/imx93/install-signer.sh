#!/usr/bin/env bash
# Install the Rust BLS signer (hybrid, plan c) on the i.MX93 board, ALONGSIDE an
# already-installed DVT node (see install.sh). Runs ON THE BOARD.
#
#   ./install-signer.sh <aastar-bls-signer-arm64> [node1]
#
# It:
#   - drops the arm64 signer binary at /opt/aastar-dvt/signer/
#   - installs + enables the loopback signer service for the node
#   - points the DVT at it (RUST_SIGNER_URL=http://127.0.0.1:5001 in the node env)
#     and restarts the DVT so signing routes through the Rust signer.
# The DVT falls back to Node signing if the signer is down (unless you also set
# RUST_SIGNER_REQUIRED=true in the node env).
set -euo pipefail

BIN="${1:?usage: install-signer.sh <aastar-bls-signer-arm64> [node-id]}"
NODE_ID="${2:-node1}"
ROOT="/opt/aastar-dvt"
UNIT_DIR="/etc/systemd/system"
SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

[ -f "$BIN" ] || { echo "‼ signer binary not found: $BIN"; exit 1; }
[ -d "$ROOT" ] || { echo "‼ $ROOT missing — run install.sh (the DVT) first"; exit 1; }
ENVF="$ROOT/env/$NODE_ID.env"
[ -f "$ENVF" ] || { echo "‼ $ENVF missing — install the DVT node first"; exit 1; }

# 1. Place the signer binary.
mkdir -p "$ROOT/signer"
cp "$BIN" "$ROOT/signer/aastar-bls-signer"
chmod +x "$ROOT/signer/aastar-bls-signer"
echo "• signer binary → $ROOT/signer/"

# 2. Install the unit.
cp "$SELF/aastar-bls-signer@.service" "$UNIT_DIR/"
systemctl daemon-reload

# 3. Point the DVT at the local signer (idempotent).
if ! grep -q '^RUST_SIGNER_URL=' "$ENVF"; then
  printf '\n# Hybrid signing (plan c): delegate BLS to the local Rust signer.\nRUST_SIGNER_URL=http://127.0.0.1:5001\n' >>"$ENVF"
  echo "• added RUST_SIGNER_URL to $ENVF"
else
  echo "• RUST_SIGNER_URL already set in $ENVF (left as-is)"
fi

# 4. Enable + start the signer, then restart the DVT so it picks up the env.
systemctl enable "aastar-bls-signer@$NODE_ID.service" >/dev/null 2>&1 || true
systemctl restart "aastar-bls-signer@$NODE_ID.service"
systemctl restart "aastar-dvt@$NODE_ID.service"

echo ""
echo "✅ hybrid signing active for $NODE_ID"
echo "   systemctl status aastar-bls-signer@$NODE_ID"
echo "   curl -s http://127.0.0.1:5001/health          # OK"
echo "   journalctl -u aastar-dvt@$NODE_ID | grep -i 'Rust signer'   # 'Signed via Rust signer'"
