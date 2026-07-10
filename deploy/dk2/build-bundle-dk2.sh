#!/usr/bin/env bash
# Build a self-contained ARMv7 (32-bit) DVT bundle for the STM32MP157F-DK2
# (Dual Cortex-A7, ARMv7-A, 512 MB, OP-TEE). DVT-only node — no KMS co-located.
#
# Runs on your dev Mac / CI — NOT on the board. This is the whole point: the DK2
# has only 512 MB RAM, so `npm ci && npm run build` on-board is risky (V8 + tsc
# peak easily blow past what's free). We CROSS-PACKAGE here and the board only
# unpacks — zero compile, zero firmware change. Produces a tarball with:
#   - a glibc linux-armv7l Node runtime  (DK2 image has no Node)
#   - dist/            (compiled app)
#   - node_modules/    (production deps only — all pure-JS, cross-arch safe)
#   - package.json
#
#   ./deploy/dk2/build-bundle-dk2.sh               # → dist-bundle/aastar-dvt-<ver>-linux-armv7l.tar.gz
#   NODE_MAJOR=20 OUT=/tmp ./deploy/dk2/build-bundle-dk2.sh
#
# Delta vs deploy/imx93/build-bundle.sh: target arch is linux-armv7l (npm --cpu=arm,
# 32-bit) instead of linux-arm64. Everything else is identical — our prod deps
# (@noble/curves, ethers, nestjs) are pure JS with no native addon, so the same
# node_modules tree runs on armv7l as-is.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO"

NODE_MAJOR="${NODE_MAJOR:-20}" # match the repo's Node line (Dockerfile: node:20)
OUT="${OUT:-$REPO/dist-bundle}"
VERSION="$(node -p "require('./package.json').version")"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

echo "▶ building DVT bundle v$VERSION for linux-armv7l (Node $NODE_MAJOR, 32-bit ARM)"

# 1. Compile the app.
echo "  • nest build"
npm run build >/dev/null

# 2. Production node_modules for the TARGET platform. --os=linux --cpu=arm makes npm
#    resolve optional deps for 32-bit ARM (process.arch === 'arm' on armv7l), not the
#    host Mac. All our prod deps are pure-JS so this tree runs as-is on the DK2.
echo "  • npm ci --omit=dev (linux/arm — 32-bit)"
cp package.json package-lock.json "$STAGE/"
( cd "$STAGE" && npm ci --omit=dev --os=linux --cpu=arm --ignore-scripts >/dev/null )

# 3. Fetch the glibc linux-armv7l Node runtime. latest-vNN.x always points at the
#    newest LTS patch, so we never pin a dead URL. (Verified upstream: e.g.
#    node-v20.20.2-linux-armv7l.tar.xz exists.)
BASE="https://nodejs.org/dist/latest-v${NODE_MAJOR}.x"
TARBALL="$(curl -fsSL "$BASE/" | grep -oE "node-v${NODE_MAJOR}\.[0-9]+\.[0-9]+-linux-armv7l\.tar\.xz" | head -1)"
[ -n "$TARBALL" ] || { echo "‼ could not resolve Node linux-armv7l tarball from $BASE"; exit 1; }
echo "  • fetching $TARBALL"
curl -fsSL "$BASE/$TARBALL" -o "$STAGE/node.tar.xz"
# Verify the runtime against Node's published SHASUMS256 — this binary runs as root
# under systemd on the board, so a tampered/corrupted download must not slip through.
echo "  • verifying SHA-256"
curl -fsSL "$BASE/SHASUMS256.txt" -o "$STAGE/SHASUMS256.txt"
EXPECTED="$(grep " $TARBALL\$" "$STAGE/SHASUMS256.txt" | awk '{print $1}')"
[ -n "$EXPECTED" ] || { echo "‼ $TARBALL not found in SHASUMS256.txt"; exit 1; }
ACTUAL="$(shasum -a 256 "$STAGE/node.tar.xz" | awk '{print $1}')"
[ "$EXPECTED" = "$ACTUAL" ] || { echo "‼ SHA-256 mismatch for $TARBALL (expected $EXPECTED, got $ACTUAL)"; exit 1; }
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
# Stamp the target arch so install-dk2.sh can sanity-check before starting systemd.
printf 'linux-armv7l\n' >"$BUNDLE/ARCH"

# 5. Tar it up.
mkdir -p "$OUT"
ARCHIVE="$OUT/aastar-dvt-${VERSION}-linux-armv7l.tar.gz"
tar -czf "$ARCHIVE" -C "$BUNDLE" .
SIZE="$(du -h "$ARCHIVE" | cut -f1)"

# Node version comes from the tarball name — we CAN'T exec the linux-armv7l binary
# on the (macOS/x86) build host to ask it.
NODE_VER="${TARBALL#node-}"; NODE_VER="${NODE_VER%%-linux-armv7l*}"
echo "✅ $ARCHIVE ($SIZE)"
echo "   node: $NODE_VER (linux-armv7l/glibc, 32-bit)  |  app: v$VERSION"
echo "   copy to the DK2, then run deploy/dk2/install-dk2.sh there."
