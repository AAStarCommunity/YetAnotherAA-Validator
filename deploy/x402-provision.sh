#!/usr/bin/env bash
# Provision the 3 testnet DVT x402 facilitator operators on-chain (#130 §6).
#
# The node services are already LIVE (/x402/verify + /x402/supported work). This
# script does the remaining ON-CHAIN, OWNER-KEY steps that let /x402/settle succeed.
# It needs PRIVILEGED keys that do NOT live in this repo:
#
#   AASTAR_OWNER_KEY   controls X402Facilitator + aPNTs + Registry  (owner 0xb5600060e6de5E11D3636731964218E53caadf0E)
#   MYCELIUM_OWNER_KEY controls PNTs                                (owner 0xEcAACb915f7D92e9916f449F7ad42BD0408733c9)  [optional — only for PNTs settlement]
#   FUNDER_KEY         any funded Sepolia EOA, to gas the 3 operators            [optional — skip if you fund them another way]
#
# Per-operator this does the steps an owner key CAN do:
#   1. PAYMASTER_SUPER role — DETECT ONLY. The Registry is staking-based (registerRole,
#      msg.sender==user, needs ROLE_COMMUNITY + ~50 GToken stake); an owner CANNOT grant
#      it. Settle reverts without it — the script flags this; resolve per docs §6.
#   2. aPNTs.addApprovedFacilitator(operator)                       — direct (xPNTs) path
#      PNTs.addApprovedFacilitator(operator)                        — direct path (Mycelium key)
#   3. X402Facilitator.setOperatorFacilitatorFee(operator, 200)     — optional fee override
#   4. fund operator with FUND_ETH Sepolia ETH                      — gas to submit settlements
#
# Usage:
#   RPC_URL=https://… AASTAR_OWNER_KEY=0x… [MYCELIUM_OWNER_KEY=0x…] [FUNDER_KEY=0x…] \
#     ./deploy/x402-provision.sh
#
# Idempotent: skips every step the chain already reflects (role granted, facilitator
# approved, fee already 200, operator already funded) — safe to re-run with no extra txs.
# Keys are read from env (or a keystore account, *_ACCOUNT, to keep them off `ps`). Needs foundry (cast).
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

: "${RPC_URL:?set RPC_URL (Sepolia)}"
: "${AASTAR_OWNER_KEY:?set AASTAR_OWNER_KEY (owns X402Facilitator + aPNTs + Registry)}"
FUND_ETH="${FUND_ETH:-0.05}"

X402_FACILITATOR=0xfe1DB01e1d6622e722B92ed5993af61325DB92aF
REGISTRY=0xf5Bf37ca83AfdAab73691bA7eCcDfA69b8708E71
APNTS=0x696A73701b104c6cCBbAadDD2216788ea08EaB89
PNTS=0xE6579A90dc498a710008de12119812D0FB7aA224
ROLE_PAYMASTER_SUPER="$(cast keccak 'PAYMASTER_SUPER')" # 0x2024516755f4…

# Read the 3 operator ADDRESSES from the per-node env (never the keys — so no operator
# private key reaches a cast CLI / `ps`). X402_OPERATOR_ADDRESS is written alongside
# X402_OPERATOR_PK when the keys are generated.
ops=()
for i in 1 2 3; do
  addr="$(grep -E '^X402_OPERATOR_ADDRESS=' "$REPO/deploy/node$i/.env" | cut -d= -f2)"
  [ -n "$addr" ] || { echo "node$i: no X402_OPERATOR_ADDRESS in deploy/node$i/.env"; exit 1; }
  ops+=("$addr")
done
echo "operators: dvt1=${ops[0]} dvt2=${ops[1]} dvt3=${ops[2]}"

# Auth flags: PREFER a foundry keystore account (the key never appears on the cast
# CLI, so it is not visible in `ps aux`). Set AASTAR_ACCOUNT / MYCELIUM_ACCOUNT /
# FUNDER_ACCOUNT to a `cast wallet import`-ed account name; otherwise fall back to the
# raw env key via --private-key (fine on a single-user host, but the expanded value
# is briefly visible in `ps` — use the keystore mode on shared/CI hosts).
aastar_auth()   { if [ -n "${AASTAR_ACCOUNT:-}" ];   then printf '%s\n%s\n' --account "$AASTAR_ACCOUNT";   else printf '%s\n%s\n' --private-key "$AASTAR_OWNER_KEY"; fi; }
mycelium_auth() { if [ -n "${MYCELIUM_ACCOUNT:-}" ]; then printf '%s\n%s\n' --account "$MYCELIUM_ACCOUNT"; else printf '%s\n%s\n' --private-key "${MYCELIUM_OWNER_KEY:-}"; fi; }
funder_auth()   { if [ -n "${FUNDER_ACCOUNT:-}" ];   then printf '%s\n%s\n' --account "$FUNDER_ACCOUNT";   else printf '%s\n%s\n' --private-key "${FUNDER_KEY:-}"; fi; }
AASTAR_AUTH=();   while IFS= read -r l; do AASTAR_AUTH+=("$l");     done < <(aastar_auth)
MYCELIUM_AUTH=(); while IFS= read -r l; do MYCELIUM_AUTH+=("$l"); done < <(mycelium_auth)
FUNDER_AUTH=();   while IFS= read -r l; do FUNDER_AUTH+=("$l");     done < <(funder_auth)

send() { echo "  + $1"; cast send "$2" "$3" "${@:4}" --rpc-url "$RPC_URL" >/dev/null; }

ROLE_BLOCKED=0
for idx in 0 1 2; do
  OP="${ops[$idx]}"; n=$((idx + 1))
  echo "== dvt$n operator $OP =="

  # 1. PAYMASTER_SUPER role (MANDATORY for both settle paths) — DETECT ONLY.
  #    Registry (contracts/src/core/Registry.sol) is NOT OZ AccessControl: there is no
  #    owner `grantRole`. The role is acquired ONLY by the OPERATOR ITSELF calling
  #    Registry.registerRole(ROLE_PAYMASTER_SUPER, op, data) (msg.sender == user), which
  #    requires (a) the operator already holds ROLE_COMMUNITY, and (b) staking minStake
  #    GToken (50e18) + ticketPrice via GTOKEN_STAKING + an SBT mint. That is a
  #    community-onboarding + staking flow an owner key CANNOT perform on the operator's
  #    behalf — so this script does NOT attempt it. See docs/x402-facilitator.md §6.
  if [ "$(cast call "$REGISTRY" 'hasRole(bytes32,address)(bool)' "$ROLE_PAYMASTER_SUPER" "$OP" --rpc-url "$RPC_URL")" = "true" ]; then
    echo "  = has PAYMASTER_SUPER"
  else
    echo "  ✗ MISSING PAYMASTER_SUPER → settle WILL revert. The operator must self-register"
    echo "    (Registry.registerRole: needs ROLE_COMMUNITY + ~50 GToken stake + ticket). docs §6."
    ROLE_BLOCKED=1
  fi

  # 2. aPNTs approved facilitator (direct path)
  if [ "$(cast call "$APNTS" 'approvedFacilitators(address)(bool)' "$OP" --rpc-url "$RPC_URL")" = "true" ]; then
    echo "  = already approved on aPNTs"
  else
    send "aPNTs addApprovedFacilitator" "$APNTS" 'addApprovedFacilitator(address)' "$OP" "${AASTAR_AUTH[@]}"
  fi

  # 2b. PNTs approved facilitator (needs the Mycelium owner key/account; optional)
  if [ -n "${MYCELIUM_OWNER_KEY:-}" ] || [ -n "${MYCELIUM_ACCOUNT:-}" ]; then
    if [ "$(cast call "$PNTS" 'approvedFacilitators(address)(bool)' "$OP" --rpc-url "$RPC_URL")" = "true" ]; then
      echo "  = already approved on PNTs"
    else
      send "PNTs addApprovedFacilitator" "$PNTS" 'addApprovedFacilitator(address)' "$OP" "${MYCELIUM_AUTH[@]}"
    fi
  else
    echo "  ~ skipping PNTs (set MYCELIUM_OWNER_KEY/MYCELIUM_ACCOUNT to enable PNTs settlement)"
  fi

  # 3. operator fee override (optional) — idempotent: skip when already 200, so a
  #    re-run doesn't burn 3 redundant on-chain txs.
  curfee="$(cast call "$X402_FACILITATOR" 'operatorFacilitatorFees(address)(uint256)' "$OP" --rpc-url "$RPC_URL" | awk '{print $1}')"
  if [ "$curfee" = "200" ]; then
    echo "  = operator fee already 200"
  else
    send "setOperatorFacilitatorFee 200" "$X402_FACILITATOR" 'setOperatorFacilitatorFee(address,uint256)' "$OP" 200 "${AASTAR_AUTH[@]}"
  fi

  # 4. gas funding (optional)
  if [ -n "${FUNDER_KEY:-}" ] || [ -n "${FUNDER_ACCOUNT:-}" ]; then
    bal="$(cast balance "$OP" --rpc-url "$RPC_URL")"
    if [ "$bal" = "0" ]; then
      echo "  + fund $FUND_ETH ETH"; cast send "$OP" --value "${FUND_ETH}ether" "${FUNDER_AUTH[@]}" --rpc-url "$RPC_URL" >/dev/null
    else
      echo "  = already funded ($bal wei)"
    fi
  else
    echo "  ~ skipping funding (set FUNDER_KEY/FUNDER_ACCOUNT, or fund $OP with ~$FUND_ETH Sepolia ETH manually)"
  fi
done

if [ "$ROLE_BLOCKED" = "1" ]; then
  echo
  echo "⚠ One or more operators lack PAYMASTER_SUPER — /x402/settle stays BLOCKED until they"
  echo "  are registered via the Registry staking flow (NOT this script). approvedFacilitators"
  echo "  + funding above are correct prep, but settle reverts without the role. See docs §6."
fi
echo "done. Verify: curl -s https://dvt1.aastar.io/x402/supported | jq, then a live settle round-trip per docs §7."
