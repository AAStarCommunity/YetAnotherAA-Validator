#!/usr/bin/env bash
# Install / upgrade an AAStar DVT node on the i.MX93 board (Yocto, systemd).
# Runs ON THE BOARD. No compiler, no Docker, no firmware change — just unpack a
# self-contained bundle (built on your Mac via build-bundle.sh) and wire up systemd.
#
#   ./install.sh aastar-dvt-1.7.1-linux-arm64.tar.gz [node1]
#
# Layout it creates under /opt/aastar-dvt:
#   releases/<ver>/   unpacked bundles (node + dist + node_modules)
#   current ->        symlink to the active release (atomic upgrade / rollback)
#   env/<node>.env    per-node config (PORT, RPC, contract, relay/keeper keys)
#   state/<node>/     per-node node_state.json (its OWN secret BLS key)
set -euo pipefail

TARBALL="${1:?usage: install.sh <bundle.tar.gz> [node-id]}"
NODE_ID="${2:-node1}"
ROOT="/opt/aastar-dvt"
UNIT_DIR="/etc/systemd/system"

[ -f "$TARBALL" ] || { echo "‼ bundle not found: $TARBALL"; exit 1; }

# Preflight: rootfs must be writable here. Some hardened Yocto images ship a
# read-only rootfs — then point ROOT at a writable data partition and bind the units.
for d in "$ROOT" "$UNIT_DIR"; do
  mkdir -p "$d" 2>/dev/null || { echo "‼ $d not writable — read-only rootfs? use a writable partition"; exit 1; }
done

SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

mkdir -p "$ROOT/releases" "$ROOT/env" "$ROOT/state/$NODE_ID"

# 1. Unpack the bundle into releases/<VERSION>.
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
tar -xzf "$TARBALL" -C "$TMP"
VER="$(cat "$TMP/VERSION")"
REL="$ROOT/releases/$VER"
rm -rf "$REL"; mkdir -p "$REL"
cp -R "$TMP"/. "$REL/"
chmod +x "$REL/node"
echo "• unpacked v$VER → $REL"

# 2. Atomic switch: current -> this release (rollback = repoint + restart).
ln -sfn "$REL" "$ROOT/current"
echo "• current → v$VER"

# 3. Seed per-node env + state if absent (never overwrite existing secrets/config).
ENVF="$ROOT/env/$NODE_ID.env"
if [ ! -f "$ENVF" ]; then
  cat >"$ENVF" <<EOF
# AAStar DVT — $NODE_ID (fill these in)
PORT=4001
ETH_RPC_URL=
VALIDATOR_CONTRACT_ADDRESS=
ENTRY_POINT_ADDRESS=0x0000000071727De22E5E9d8BAf0edAc6f37da032
# Optional capabilities (need their OWN funded keys — keep separate from the BLS key):
# RELAY_ENABLED=false
# RELAY_OPERATOR_PK=
# KEEPER_ENABLED=false
# KEEPER_PRIVATE_KEY=
EOF
  chmod 600 "$ENVF"
  echo "• wrote env template → $ENVF  (EDIT IT before starting)"
fi
if [ ! -f "$ROOT/state/$NODE_ID/node_state.json" ]; then
  echo "⚠ missing $ROOT/state/$NODE_ID/node_state.json — put this node's OWN BLS key there (chmod 600)"
fi

# 4. Install systemd units (idempotent).
cp "$SELF/aastar-dvt@.service" "$SELF/aastar-dvt-health@.service" "$SELF/aastar-dvt-health@.timer" "$UNIT_DIR/"
chmod 600 "$ENVF" 2>/dev/null || true
systemctl daemon-reload
echo "• installed systemd units"

# 5. Enable + (re)start this node and its health probe.
systemctl enable "aastar-dvt@$NODE_ID.service" "aastar-dvt-health@$NODE_ID.timer" >/dev/null 2>&1 || true
systemctl restart "aastar-dvt@$NODE_ID.service"
systemctl restart "aastar-dvt-health@$NODE_ID.timer"

echo ""
echo "✅ v$VER active for $NODE_ID"
echo "   systemctl status aastar-dvt@$NODE_ID"
echo "   journalctl -u aastar-dvt@$NODE_ID -f"
PORT_VAL="$(grep -E '^PORT=' "$ENVF" | cut -d= -f2)"
echo "   curl -s http://127.0.0.1:${PORT_VAL:-4001}/health   # {version:\"$VER\",...}"
