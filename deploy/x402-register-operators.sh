#!/usr/bin/env bash
# Register the 3 DVT x402 operators as staked community paymasters (#130 §6).
#
# This is the REAL way to give an operator ROLE_PAYMASTER_SUPER (the Registry is
# staking-based, NOT owner grantRole). It uses Registry.safeMintForRole, which lets a
# caller that ALREADY holds ROLE_COMMUNITY register roles FOR another address and pay
# the stake/ticket from the caller's own GToken. AAStar's owner (0xb560) holds
# ROLE_COMMUNITY + GToken, so it sponsors all three operators — no operator self-sign.
#
# Per operator (idempotent; skips a role already held):
#   1. ROLE_COMMUNITY      : ticket 30 GToken (no stake). Unique community `name`,
#      empty ensName. Required first — PAYMASTER_SUPER gates on the operator's COMMUNITY.
#   2. ROLE_PAYMASTER_SUPER : stake 50 GToken (recoverable on exit) + ticket 5 GToken.
#   ⇒ ~85 GToken/operator from the sponsor (≈255 total; 150 recoverable stake).
#
# Usage:  RPC_URL=… AASTAR_OWNER_KEY=0x<0xb560 key> ./deploy/x402-register-operators.sh
# Needs foundry (cast). The sponsor (AASTAR_OWNER_KEY) must hold ROLE_COMMUNITY + ≥255 GToken.
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
: "${RPC_URL:?set RPC_URL (Sepolia)}"
: "${AASTAR_OWNER_KEY:?set AASTAR_OWNER_KEY (0xb560 — holds ROLE_COMMUNITY + GToken)}"

REGISTRY=0xf5Bf37ca83AfdAab73691bA7eCcDfA69b8708E71
STAKING=0x472297B557c1d0F030f281a5Bb8A535f6c5AB65e
GTOKEN=0x4c09aE57503Aa1E2A43b05621A38DbdD43b0Aa08
ROLE_COMMUNITY="$(cast keccak 'COMMUNITY')"
ROLE_SUPER="$(cast keccak 'PAYMASTER_SUPER')"
AUTH=(--private-key "$AASTAR_OWNER_KEY")
[ -n "${AASTAR_ACCOUNT:-}" ] && AUTH=(--account "$AASTAR_ACCOUNT")

has() { [ "$(cast call "$REGISTRY" 'hasRole(bytes32,address)(bool)' "$1" "$2" --rpc-url "$RPC_URL")" = "true" ]; }
approve() { cast send "$GTOKEN" 'approve(address,uint256)' "$STAKING" "$1" "${AUTH[@]}" --rpc-url "$RPC_URL" >/dev/null; }
mint() { echo "  + safeMintForRole $3"; cast send "$REGISTRY" 'safeMintForRole(bytes32,address,bytes)' "$1" "$2" "$4" "${AUTH[@]}" --rpc-url "$RPC_URL" >/dev/null; }

for i in 1 2 3; do
  pk="$(grep -E '^X402_OPERATOR_PK=' "$REPO/deploy/node$i/.env" | cut -d= -f2)"
  OP="$(cast wallet address --private-key "$pk")"
  echo "== dvt$i operator $OP =="

  if has "$ROLE_COMMUNITY" "$OP"; then
    echo "  = already ROLE_COMMUNITY"
  else
    DATA="$(cast abi-encode 'f((string,string,uint256))' "(\"AAStar DVT$i x402\",\"dvt$i-x402.aastar.eth\",30000000000000000000)")"
    approve 35000000000000000000   # 35 GToken (ticket 30 + buffer)
    mint "$ROLE_COMMUNITY" "$OP" "ROLE_COMMUNITY (AAStar DVT$i x402)" "$DATA"
  fi

  if has "$ROLE_SUPER" "$OP"; then
    echo "  = already ROLE_PAYMASTER_SUPER"
  else
    approve 60000000000000000000   # 60 GToken (stake 50 + ticket 5 + buffer)
    mint "$ROLE_SUPER" "$OP" "ROLE_PAYMASTER_SUPER" "0x"
  fi
done
echo "done — operators are staked PAYMASTER_SUPER. Next: approvedFacilitators + funding (x402-provision.sh), then a live settle."
