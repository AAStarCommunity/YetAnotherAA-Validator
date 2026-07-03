#!/usr/bin/env bash
# Build a self-contained arm64 DVT bundle for i.MX93 (Yocto, systemd, glibc).
#
# Runs on your dev Mac / CI — NOT on the board. Produces a tarball containing
# everything the board needs to run the DVT with ZERO firmware changes:
#   - a glibc linux-arm64 Node runtime  (board's Yocto image has no Node)
#   - dist/            (compiled app)
#   - node_modules/    (production deps only — all pure-JS, cross-arch safe)
#   - package.json
#
# The board never compiles anything: it just unpacks + `systemctl start`.
#
#   ./deploy/imx93/build-bundle.sh                 # → dist-bundle/aastar-dvt-<ver>-linux-arm64.tar.gz
#   NODE_MAJOR=20 OUT=/tmp ./deploy/imx93/build-bundle.sh
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO"

NODE_MAJOR="${NODE_MAJOR:-20}" # match the repo's Node line (Dockerfile: node:20)
OUT="${OUT:-$REPO/dist-bundle}"
VERSION="$(node -p "require('./package.json').version")"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

echo "▶ building DVT bundle v$VERSION for linux-arm64 (Node $NODE_MAJOR)"

# 1. Compile the app.
echo "  • nest build"
npm run build >/dev/null

# 2. Production node_modules for the TARGET platform. --os/--cpu make npm resolve
#    optional deps for linux-arm64 (not the host Mac), so no darwin junk sneaks in.
#    All our prod deps are pure-JS (noble/ethers/nestjs), so this tree runs as-is.
echo "  • npm ci --omit=dev (linux/arm64 resolution)"
cp package.json package-lock.json "$STAGE/"
( cd "$STAGE" && npm ci --omit=dev --os=linux --cpu=arm64 --ignore-scripts >/dev/null )

# 3. Fetch the glibc linux-arm64 Node runtime (NXP Yocto is glibc → official build works).
#    latest-vNN.x always points at the newest LTS patch, so we never pin a dead URL.
BASE="https://nodejs.org/dist/latest-v${NODE_MAJOR}.x"
TARBALL="$(curl -fsSL "$BASE/" | grep -oE "node-v${NODE_MAJOR}\.[0-9]+\.[0-9]+-linux-arm64\.tar\.xz" | head -1)"
[ -n "$TARBALL" ] || { echo "‼ could not resolve Node linux-arm64 tarball from $BASE"; exit 1; }
echo "  • fetching $TARBALL"
curl -fsSL "$BASE/$TARBALL" -o "$STAGE/node.tar.xz"
tar -xJf "$STAGE/node.tar.xz" -C "$STAGE"
NODE_BIN="$STAGE/${TARBALL%.tar.xz}/bin/node"
[ -x "$NODE_BIN" ] || { echo "‼ node binary not found after extract"; exit 1; }

# 4. Assemble the bundle.
BUNDLE="$STAGE/bundle"
mkdir -p "$BUNDLE"
cp "$NODE_BIN" "$BUNDLE/node"
cp -R dist "$BUNDLE/dist"
cp -R "$STAGE/node_modules" "$BUNDLE/node_modules"
cp package.json "$BUNDLE/package.json"
printf '%s\n' "$VERSION" >"$BUNDLE/VERSION"

# 5. Tar it up.
mkdir -p "$OUT"
ARCHIVE="$OUT/aastar-dvt-${VERSION}-linux-arm64.tar.gz"
tar -czf "$ARCHIVE" -C "$BUNDLE" .
SIZE="$(du -h "$ARCHIVE" | cut -f1)"

# Node version comes from the tarball name — we CAN'T exec the linux-arm64 binary
# on the (macOS/x86) build host to ask it.
NODE_VER="${TARBALL#node-}"; NODE_VER="${NODE_VER%%-linux-arm64*}"
echo "✅ $ARCHIVE ($SIZE)"
echo "   node: $NODE_VER (linux-arm64/glibc)  |  app: v$VERSION"
echo "   copy to the board, then run deploy/imx93/install.sh there."
