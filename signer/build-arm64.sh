#!/usr/bin/env bash
# Cross-build the BLS signer for linux/arm64 (glibc) — for the i.MX93 board.
# Runs on your Mac/CI. Uses cargo-zigbuild (zig as the cross C-compiler/linker) so no
# Docker or aarch64 gcc toolchain is needed. Output: signer/dist-arm64/aastar-bls-signer
# (a stripped aarch64 glibc ELF that runs on NXP i.MX93 Yocto).
#
#   ./signer/build-arm64.sh
#
# One-time prerequisites (the script checks and tells you):
#   rustup target add aarch64-unknown-linux-gnu
#   brew install zig          # or from https://ziglang.org/download/
#   cargo install cargo-zigbuild
set -euo pipefail

SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="aarch64-unknown-linux-gnu"
OUT="$SELF/dist-arm64"

command -v zig >/dev/null || { echo "‼ zig not found — brew install zig"; exit 1; }
command -v cargo-zigbuild >/dev/null || { echo "‼ cargo-zigbuild not found — cargo install cargo-zigbuild"; exit 1; }
rustup target list --installed 2>/dev/null | grep -q "$TARGET" || {
  echo "‼ rust target missing — rustup target add $TARGET"; exit 1;
}

echo "▶ cross-building aastar-bls-signer for $TARGET (glibc)…"
( cd "$SELF" && cargo zigbuild --release --target "$TARGET" )

mkdir -p "$OUT"
cp "$SELF/target/$TARGET/release/aastar-bls-signer" "$OUT/aastar-bls-signer"
chmod +x "$OUT/aastar-bls-signer"
BIN="$OUT/aastar-bls-signer"

echo "✅ $BIN ($(du -h "$BIN" | cut -f1))"
file "$BIN" 2>/dev/null || true
echo ""
echo "Next:"
echo "  # (plan b) benchmark on the board:"
echo "  scp $BIN root@<board>:/tmp/ && ssh root@<board> '/tmp/aastar-bls-signer --bench'"
echo "  # (plan c) deploy as a loopback service: see deploy/imx93/README.md"
