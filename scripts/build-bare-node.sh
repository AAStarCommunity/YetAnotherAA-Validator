#!/usr/bin/env bash
# Bare-node build for restricted embedded boards (e.g. NXP FRDM-IMX93, arm64 / OP-TEE).
#
# WHY: the official Dockerfile needs buildx / a working layer-export, which many embedded
# boards lack (legacy docker builder fails to export layers on ext4 without xattr support;
# no buildx; kernel without the iptables `raw` table). DVT is pure JS (@noble/curves has no
# native addon; the build output is plain JS), so it builds and runs fine on a bare glibc
# arm64 Node 20 with no container at all. This is the recommended standalone-build posture
# for such boards (CC-22). On a normal host with buildx, use the Dockerfile instead.
#
# Usage (from the repo root, on the board):
#   ./scripts/build-bare-node.sh
# Then configure env + node_state.json (see deploy/imx93/README.md) and start:
#   node dist/main
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$(pwd)"

echo "==> Bare-node build in ${ROOT}"

# 1. Node 20 (glibc arm64). @noble/curves is pure JS → no native toolchain needed.
if ! command -v node >/dev/null 2>&1; then
  echo "‼ node not found. Install a glibc arm64 Node 20 LTS first (e.g. from nodejs.org" >&2
  echo "  arm64 tarball, or your distro), then re-run. Musl/alpine also works but glibc is" >&2
  echo "  the tested baseline (Node v20.20.2 on imx93)." >&2
  exit 1
fi
NODE_MAJOR="$(node -p 'process.versions.node.split(".")[0]')"
if [ "${NODE_MAJOR}" -lt 20 ]; then
  echo "‼ Node ${NODE_MAJOR}.x too old — DVT needs Node >= 20 (ESM + build)." >&2
  exit 1
fi
echo "==> node $(node -v) ($(node -p 'process.arch'))"

# 2. Deterministic install from the committed lockfile (npm, per this repo's convention).
echo "==> npm ci"
npm ci

# 3. Compile (nest build → dist/, pure JS).
echo "==> npm run build"
npm run build

# 4. Sanity: the entrypoint exists.
if [ ! -f "${ROOT}/dist/main.js" ]; then
  echo "‼ build did not produce dist/main.js" >&2
  exit 1
fi

echo ""
echo "✔ Bare-node build complete → dist/main.js"
echo "  Next:"
echo "   1. Generate an INDEPENDENT node key:  node scripts/gen-node-state.mjs"
echo "      (optional at-rest encryption:       node scripts/encrypt-node-key.mjs, KDF=pbkdf2)"
echo "   2. Set env: ETH_RPC_URL, VALIDATOR_CONTRACT_ADDRESS, ENTRY_POINT_ADDRESS, PORT"
echo "   3. Start:   node dist/main   (or a systemd unit — see deploy/imx93/README.md)"
