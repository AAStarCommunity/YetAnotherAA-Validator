#!/usr/bin/env bash
# Install / upgrade a DVT-only AAStar node on the STM32MP157F-DK2 (ARMv7, 512 MB).
# Runs ON THE BOARD. No compiler, no Docker, no firmware change — just unpack a
# self-contained armv7l bundle (built on your Mac via build-bundle-dk2.sh) and
# wire up systemd.
#
#   ./install-dk2.sh aastar-dvt-1.11.0-linux-armv7l.tar.gz [node2]
#
# node2 is the DK2's slot in the AAStar 3-node topology (2-of-3 DVT + 1 KMS; see
# CC-30 / CC-32). Layout it creates under /opt/aastar-dvt is identical to the i.MX93
# path (releases/ + current-> + env/ + state/), so upgrade/rollback work the same.
#
# Delta vs deploy/imx93/install.sh:
#   - refuses to start on an arch mismatch (arm64 bundle on armv7 → "Exec format
#     error" is the #1 DK2 footgun) by exec-checking the bundled node first;
#   - DVT-only env template (PORT=4002, no RUST_SIGNER_URL — local keystore signing);
#   - installs this dir's 512 MB-tuned aastar-dvt@.service.
set -euo pipefail

TARBALL="${1:?usage: install-dk2.sh <bundle-linux-armv7l.tar.gz> [node-id]}"
NODE_ID="${2:-node2}"
ROOT="/opt/aastar-dvt"
UNIT_DIR="/etc/systemd/system"

[ -f "$TARBALL" ] || { echo "‼ bundle not found: $TARBALL"; exit 1; }

# Preflight: rootfs must be writable here. Some hardened images ship a read-only
# rootfs — then point ROOT at a writable data partition and bind the units.
for d in "$ROOT" "$UNIT_DIR"; do
  mkdir -p "$d" 2>/dev/null || { echo "‼ $d not writable — read-only rootfs? use a writable partition"; exit 1; }
done

SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

mkdir -p "$ROOT/releases" "$ROOT/env" "$ROOT/state/$NODE_ID"

# 1. Unpack the bundle into releases/<VERSION>.
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
tar -xzf "$TARBALL" -C "$TMP"
VER="$(cat "$TMP/VERSION")"

# 1a. ARCH GUARD (the DK2 footgun): the bundle must be armv7l and its node binary
#     must actually exec on this board. An arm64 bundle here dies with
#     "Exec format error" only once systemd tries to start it — catch it now.
BUNDLE_ARCH="$(cat "$TMP/ARCH" 2>/dev/null || echo unknown)"
BOARD_ARCH="$(uname -m)"   # DK2 → armv7l
if [ "$BUNDLE_ARCH" != "linux-armv7l" ]; then
  echo "‼ bundle arch is '$BUNDLE_ARCH', expected 'linux-armv7l' for the DK2."
  echo "  Rebuild with deploy/dk2/build-bundle-dk2.sh (NOT the arm64 imx93 build-bundle.sh)."
  exit 1
fi
if ! "$TMP/node" -v >/dev/null 2>&1; then
  echo "‼ bundled node does not exec on this board (uname -m = $BOARD_ARCH)."
  echo "  This is the classic arm64-bundle-on-armv7 'Exec format error'. Rebuild for armv7l."
  exit 1
fi
echo "• arch OK: bundle=$BUNDLE_ARCH, board=$BOARD_ARCH, node $("$TMP/node" -v)"

REL="$ROOT/releases/$VER"
# Stage into a scratch dir on the SAME filesystem, validate the payload, then atomically
# mv into place. Reinstalling the ACTIVE version must not clobber it if the copy fails
# — otherwise a bad/partial reinstall takes the running signer down with no rollback.
STAGE_REL="$ROOT/releases/.stage-$VER.$$"
rm -rf "$STAGE_REL"; mkdir -p "$STAGE_REL"
cp -R "$TMP"/. "$STAGE_REL/"
chmod +x "$STAGE_REL/node"
{ [ -x "$STAGE_REL/node" ] && [ -f "$STAGE_REL/dist/main.js" ] && [ -d "$STAGE_REL/node_modules" ]; } || {
  echo "‼ staged release incomplete (missing node/dist/node_modules) — aborting, active release untouched"
  rm -rf "$STAGE_REL"; exit 1
}
[ -e "$REL" ] && { rm -rf "$REL.prev"; mv "$REL" "$REL.prev"; }
mv "$STAGE_REL" "$REL"
echo "• unpacked v$VER → $REL"

# 2. Atomic switch: current -> this release (rollback = repoint at releases/<old> + restart).
ln -sfn "$REL" "$ROOT/current"
echo "• current → v$VER"

# 3. Seed per-node env + state if absent (never overwrite existing secrets/config).
ENVF="$ROOT/env/$NODE_ID.env"
if [ ! -f "$ENVF" ]; then
  cat >"$ENVF" <<EOF
# AAStar DVT — $NODE_ID (DK2, DVT-only). Fill these in.
PORT=4002
ETH_RPC_URL=
# v1.9.0+ authoritative Sepolia validator (deploy/sdk-dvt-config.testnet.json):
VALIDATOR_CONTRACT_ADDRESS=0x539B9681aFd5BFbCaa655Fe4c6BdcFe1fa7864bC
ENTRY_POINT_ADDRESS=0x0000000071727De22E5E9d8BAf0edAc6f37da032
# DVT-only: this node signs with its OWN local BLS key (state/$NODE_ID/node_state.json).
# Do NOT set RUST_SIGNER_URL — that is only for the KMS-TEE co-located node (node1).
# Optional capabilities (need their OWN funded keys — keep separate from the BLS key):
# RELAY_ENABLED=false
# RELAY_OPERATOR_PK=
# KEEPER_ENABLED=false
# KEEPER_PRIVATE_KEY=
EOF
  chmod 600 "$ENVF"
  echo "• wrote env template → $ENVF  (EDIT IT before starting: set ETH_RPC_URL)"
fi
STATEF="$ROOT/state/$NODE_ID/node_state.json"
# Lock down the state dir; if a key is already present (e.g. scp'd from a Mac at 0644),
# tighten it — this file is a raw BLS private key and must never be world-readable.
chmod 700 "$ROOT/state/$NODE_ID" 2>/dev/null || true
if [ -f "$STATEF" ]; then
  chmod 600 "$STATEF" 2>/dev/null || true
else
  # The bundle ships only node/dist/node_modules — NOT scripts/ — so gen-node-state.mjs
  # is not runnable on the board. Generate on your Mac (repo has the script) and scp it in.
  echo "⚠ missing $STATEF — this node's OWN BLS key."
  echo "  On your Mac (in the repo): node scripts/gen-node-state.mjs"
  echo "  then: scp node_state.json root@<board>:$STATEF   (chmod 600 — never reuse a repo/test key)"
fi

# 4. Install systemd units (idempotent) — this dir's 512 MB-tuned service + health.
cp "$SELF/aastar-dvt@.service" "$SELF/aastar-dvt-health@.service" "$SELF/aastar-dvt-health@.timer" "$UNIT_DIR/"
chmod 600 "$ENVF" 2>/dev/null || true
systemctl daemon-reload
echo "• installed systemd units (MemoryMax=320M, --max-old-space-size=256)"

# 5. Enable for boot. Only START when actually configured — starting with an empty
#    ETH_RPC_URL (config validation throws) or a missing node_state.json (node.service
#    errors on boot) would just crash-loop until StartLimitBurst trips, which on a
#    headless board reads as "install failed". So gate the start on both being present;
#    on a first provision we enable + print the next steps instead of thrashing systemd.
systemctl enable "aastar-dvt@$NODE_ID.service" "aastar-dvt-health@$NODE_ID.timer" >/dev/null 2>&1 || true

# Read env values with sed (not `grep | cut`): a missing key makes grep exit 1, which
# under `set -o pipefail` would abort the installer before the helpful branch below.
# sed prints nothing and exits 0 for an absent key.
env_val() { sed -n "s/^$1=//p" "$ENVF" | tail -n1; }
RPC_VAL="$(env_val ETH_RPC_URL)"
VALIDATOR_VAL="$(env_val VALIDATOR_CONTRACT_ADDRESS)"
PORT_VAL="$(env_val PORT)"

# App startup (config/configuration.ts) throws without BOTH ETH_RPC_URL and
# VALIDATOR_CONTRACT_ADDRESS, and node.service errors without node_state.json. Only
# start when all three are present — otherwise enable-for-boot and print what's missing.
if [ -n "$RPC_VAL" ] && [ -n "$VALIDATOR_VAL" ] && [ -f "$STATEF" ]; then
  systemctl restart "aastar-dvt@$NODE_ID.service"
  systemctl restart "aastar-dvt-health@$NODE_ID.timer"
  echo ""
  echo "✅ v$VER active for $NODE_ID (DK2 armv7, DVT-only)"
  echo "   systemctl status aastar-dvt@$NODE_ID"
  echo "   journalctl -u aastar-dvt@$NODE_ID -f"
  echo "   curl -s http://127.0.0.1:${PORT_VAL:-4002}/health   # {version:\"$VER\",...}"
else
  echo ""
  echo "✅ v$VER installed + enabled for boot — NOT started yet (needs config):"
  [ -z "$RPC_VAL" ]       && echo "   • set ETH_RPC_URL in $ENVF"
  [ -z "$VALIDATOR_VAL" ] && echo "   • set VALIDATOR_CONTRACT_ADDRESS in $ENVF"
  [ ! -f "$STATEF" ]      && echo "   • put this node's BLS key at $STATEF (see the ⚠ above)"
  echo "   then start:  systemctl start aastar-dvt@$NODE_ID aastar-dvt-health@$NODE_ID.timer"
  echo "   verify:      curl -s http://127.0.0.1:${PORT_VAL:-4002}/health"
fi
