#!/bin/bash
# rc.8 guardian PoP rehearsal on a LOCAL anvil:
#   SP pin -> DVT `--plan` export -> A7.dvt / A7 deploy -> A8 wiring -> A10-equivalent assertions
#   -> A10 sends to the DVTValidator -> read-back.
# It mirrors the checks SP's manifest_exec.py A10 makes; it is not SP's manifest.
#
# Inputs (nothing defaults to a real chain or a real key):
#   SP_DIR     an SP checkout already built with `forge build`. Fetch it into its own directory with
#              `gh api repos/AAStarCommunity/SuperPaymaster/tarball/<sha>` plus its contracts/lib
#              submodules; never use another session's worktree.
#   SP_COMMIT  the 40-hex commit SP_DIR was fetched at.
#   PORT       anvil port (default 18645; must be free).
# The three guardian BLS keys are generated fresh inside the run's temporary directory, so no real
# guardian key can be used by accident (Codex round 3, L5).
#
# Usage: SP_DIR=... SP_COMMIT=... deploy/rehearse-reregister-plan.sh [good|nonce-moved]
#   good         exit 0 and "REHEARSAL PASSED"; any failed assertion exits non-zero.
#   nonce-moved  the deployer sends one unplanned transaction after the export. The re-export must stop
#                on the nonce check and the address assertion must stop the send: exit 3.
set -euo pipefail
: "${SP_DIR:?set SP_DIR}" "${SP_COMMIT:?set SP_COMMIT}"
[ -z "${NODES_DIR:-}" ] || { echo "NODES_DIR is no longer accepted: keys are generated per run"; exit 1; }
PORT=${PORT:-18645}
MODE=${1:-good}
WT=$(cd "$(dirname "$0")/.." && pwd)
B=$(mktemp -d "${TMPDIR:-/tmp}/rehearse-reregister.XXXXXX")
C=${CAST:-$(command -v cast || echo "$HOME/.foundry/bin/cast")}
ANVIL=${ANVIL:-$(command -v anvil || echo "$HOME/.foundry/bin/anvil")}
FORGE=${FORGE:-$(command -v forge || echo "$HOME/.foundry/bin/forge")}
R=http://127.0.0.1:$PORT
# anvil's well-known account 0, chain 31337 only.
K0=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
D=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
SRC=$SP_DIR/contracts/src/modules/monitoring/BLSAggregator.sol
NODES_DIR=$B/nodes
NODES="$NODES_DIR/node_test_1.json,$NODES_DIR/node_test_2.json,$NODES_DIR/node_test_3.json"
( umask 077; printf 'RPC_URL=%s\nREREGISTER_OWNER_PRIVATE_KEY=%s\n' "$R" "$K0" > "$B/anvil.env" )
# Fresh throwaway guardians: random BLS keys and random, never-funded validator addresses.
( umask 077; mkdir -p "$NODES_DIR" && cd "$WT" && node --input-type=module - "$NODES_DIR" <<'JS'
import { bls12_381 as bls } from "@noble/curves/bls12-381.js";
import { ethers } from "ethers";
import { writeFileSync } from "fs";
const enc = p => {
  const o = new Uint8Array(128), a = p.toAffine();
  o.set(ethers.getBytes("0x" + a.x.toString(16).padStart(96, "0")), 16);
  o.set(ethers.getBytes("0x" + a.y.toString(16).padStart(96, "0")), 80);
  return ethers.hexlify(o);
};
for (let i = 1; i <= 3; i++) {
  const sk = bls.utils.randomSecretKey();
  writeFileSync(`${process.argv[2]}/node_test_${i}.json`, JSON.stringify({
    nodeName: `rehearsal-${i}`, operator: ethers.Wallet.createRandom().address, slot: i,
    privateKey: ethers.hexlify(sk), publicKeyEip2537: enc(bls.longSignatures.getPublicKey(sk)) }), { mode: 0o600 });
}
JS
)

lsof -nP -iTCP:"$PORT" -sTCP:LISTEN >/dev/null && { echo "port $PORT is busy"; exit 1; }
"$ANVIL" --port "$PORT" --chain-id 31337 --hardfork prague --code-size-limit 100000 --silent > "$B/anvil.log" 2>&1 &
APID=$!
trap 'kill $APID 2>/dev/null || true' EXIT
sleep 3
[ "$("$C" chain-id --rpc-url "$R")" = 31337 ] || { echo "not a local anvil"; exit 1; }

# ---- generation 1 plays the OLD stack (old aggregator, Registry) -----------------------------------
( cd "$SP_DIR" && LOCAL_DEV_GOVERNANCE_ACK=true "$FORGE" script "contracts/script/v3/DeployAnvil.s.sol:DeployAnvil" \
    --rpc-url "$R" --broadcast --slow --disable-code-size-limit --timeout 300 --non-interactive \
    --private-key "$K0" --offline > "$B/deploy-gen1.log" 2>&1 )
G1=$SP_DIR/deployments/config.anvil.json
jget() { python3 -c "import json,sys;print(json.load(open(sys.argv[1]))[sys.argv[2]])" "$1" "$2"; }
OLDAGG=$(jget "$G1" blsAggregator); REG=$(jget "$G1" registry); SPX=$(jget "$G1" superPaymaster)
echo "gen1 (old) aggregator $OLDAGG registry $REG"

# ---- SP pin: nonce, block, and the precomputed addresses of the next two CREATEs ---------------------
N=$("$C" nonce "$D" --rpc-url "$R"); BLK=$("$C" block-number --rpc-url "$R")
BH=$("$C" block "$BLK" --field hash --rpc-url "$R")
PDVT=$("$C" compute-address "$D" --nonce "$N" | awk '{print $NF}')
PAGG=$("$C" compute-address "$D" --nonce $((N + 1)) | awk '{print $NF}')
python3 - "$B/plan.json" "$PAGG" "$PDVT" "$BLK" "$BH" "$OLDAGG" "$D" "$N" <<'PY'
import json, sys
out, agg, dvt, blk, bh, old, dep, n = sys.argv[1:]
json.dump({"addresses": {"BLSAggregator": agg.lower(), "DVTValidator": dvt.lower()},
           "pin": {"block": int(blk), "blockHash": bh, "oldAggregator": old.lower(),
                   "senders": {"deployer": {"address": dep.lower(), "nonce": int(n), "balance": 0}}}},
          open(out, "w"), indent=2)
PY
echo "pin: deployer nonce $N block $BLK; planned DVT $PDVT AGG $PAGG"

export_pop() {
  ( cd "$WT" && env -u SEPOLIA_RPC_URL node deploy/reregister-guardians.mjs --env "$B/anvil.env" \
      --chain-id 31337 --plan "$B/plan.json" --sp-aggregator-source "$SRC" --sp-commit "$SP_COMMIT" \
      --nodes "$NODES" --export-pop "$1" )
}
# ---- DVT: export from the plan, before the contracts exist -----------------------------------------
export_pop "$B/plan-pop.json"

if [ "$MODE" = nonce-moved ]; then
  echo "== deployer sends one unplanned transaction after the export"
  "$C" send 0x000000000000000000000000000000000000dEaD --value 1 --private-key "$K0" --rpc-url "$R" >/dev/null
  # Must stop, and stop for THIS reason: any other failure (RPC, source file) is not evidence.
  if OUT=$(export_pop "$B/plan-pop-2.json" 2>&1); then
    echo "FAIL: re-export did not stop after the nonce moved"; exit 1
  fi
  echo "$OUT" | grep -q "the pin says $N\." || { echo "FAIL: re-export stopped for another reason:"; echo "$OUT" | grep '✗'; exit 1; }
  echo "re-export stopped on the nonce check (expected)"
fi

# ---- SP A7.dvt + A7, in the order the pin assumed --------------------------------------------------
DBC=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['bytecode']['object'])" "$SP_DIR/out/DVTValidator.sol/DVTValidator.json")
ABC=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['bytecode']['object'])" "$SP_DIR/out/BLSAggregator.sol/BLSAggregator.json")
DARGS=$("$C" abi-encode 'c(address,uint256)' "$REG" 1)
"$C" send --private-key "$K0" --rpc-url "$R" --create "$DBC${DARGS:2}" >/dev/null
NDVT=$("$C" compute-address "$D" --nonce $(( $("$C" nonce "$D" --rpc-url "$R") - 1 )) | awk '{print $NF}')
AARGS=$("$C" abi-encode 'c(address,address,address)' "$REG" "$SPX" "$NDVT")
"$C" send --private-key "$K0" --rpc-url "$R" --create "$ABC${AARGS:2}" >/dev/null
NAGG=$("$C" compute-address "$D" --nonce $(( $("$C" nonce "$D" --rpc-url "$R") - 1 )) | awk '{print $NF}')
echo "deployed: DVT $NDVT AGG $NAGG"

# ---- A10-equivalent: deployed addresses == the export's, else STOP ---------------------------------
# Exit 0 = match, 10 = verified mismatch, anything else = the check itself failed (Codex round 3, M2).
set +e
python3 - "$B/plan-pop.json" "$NDVT" "$NAGG" <<'PY'
import json, sys
p = json.load(open(sys.argv[1]))["popContext"]
ok = sys.argv[2].lower() == p["dvt"].lower() and sys.argv[3].lower() == p["aggregator"].lower()
print("A10 address assertion:", "deployed == plan" if ok else "MISMATCH")
sys.exit(0 if ok else 10)
PY
RC=$?
set -e
case $RC in
  0) ;;
  10) echo "A10 address assertion STOPPED the send"; exit 3 ;;
  *) echo "FAIL: the address assertion could not run (exit $RC)"; exit 1 ;;
esac
[ "$MODE" = nonce-moved ] && { echo "FAIL: addresses matched although the nonce moved"; exit 1; }

# ---- A8 wiring ---------------------------------------------------------------------------------------
"$C" send "$NDVT" 'setBLSAggregator(address)' "$NAGG" --private-key "$K0" --rpc-url "$R" >/dev/null
"$C" send "$REG" 'setBLSAggregator(address)' "$NAGG" --private-key "$K0" --rpc-url "$R" >/dev/null

# ---- A10-equivalent pre-send assertions: keys, on-chain domainSeparator and popDigest == export ------
python3 - "$C" "$R" "$NAGG" "$B/plan-pop.json" "$NODES_DIR" <<'PY'
import json, subprocess, sys
C, R, AGG, pop_file, nodes = sys.argv[1:]
call = lambda *a: subprocess.check_output([C, "call", AGG, *a, "--rpc-url", R], text=True).strip()
# Explicit checks, not `assert`: PYTHONOPTIMIZE would strip asserts (Codex round 3, M3).
def need(ok, what):
    if not ok:
        print("FAIL:", what); sys.exit(1)
p = json.load(open(pop_file)); ctx = p["popContext"]
need(sorted(ctx) == sorted(["dvt", "aggregator", "registry", "chainId", "deployerAddress", "deployerNonce",
    "pinBlock", "pinBlockHash", "spCommit", "spAggregatorSourceSha256", "popDigests"]), "popContext keys")
need(len(p["pop"]) == 3 and len(ctx["popDigests"]) == 3, "pop count")
for e in p["pop"]:
    need(sorted(e) == sorted(["validator", "slot", "calldata", "aggregator", "pinBlockHash", "domainSeparator"]), "pop keys")
ds = call("domainSeparator()(bytes32)")
need(all(e["domainSeparator"].lower() == ds.lower() for e in p["pop"]), "domainSeparator differs")
print("domainSeparator on-chain == export")
for i, e in enumerate(p["pop"]):
    n = json.load(open("%s/node_test_%d.json" % (nodes, e["slot"]))); w = n["publicKeyEip2537"][2:]
    key = "(%s)" % ",".join("0x" + w[j:j + 64] for j in range(0, 256, 64))
    d = call("popDigest(address,(bytes32,bytes32,bytes32,bytes32))(bytes32)", n["operator"], key)
    need(d.lower() == ctx["popDigests"][i].lower(), "popDigest differs for slot %d" % e["slot"])
    print("slot %d popDigest on-chain == export" % e["slot"])
PY

# ---- A10 sends (deployer = owner before the hand-off), target = the DVTValidator ----------------------
for CD in $(python3 -c "import json,sys;[print(e['calldata']) for e in json.load(open(sys.argv[1]))['pop']]" "$B/plan-pop.json"); do
  ST=$("$C" send "$NDVT" "$CD" --private-key "$K0" --rpc-url "$R" --json | python3 -c "import json,sys;print(json.load(sys.stdin)['status'])")
  [ "$ST" = 0x1 ] || { echo "FAIL: A10 send status $ST"; exit 1; }
  echo "A10 send status $ST"
done

# ---- read-back ----------------------------------------------------------------------------------------
python3 - "$C" "$R" "$NAGG" "$NODES_DIR" <<'PY'
import json, subprocess, sys
C, R, AGG, nodes = sys.argv[1:]
call = lambda *a: subprocess.check_output([C, "call", AGG, *a, "--rpc-url", R], text=True).strip()
ok = True
for i in (1, 2, 3):
    n = json.load(open("%s/node_test_%d.json" % (nodes, i)))
    out = call("getBLSPublicKey(address)((bytes32,bytes32,bytes32,bytes32),uint8,bool)", n["operator"]).split("\n")
    key = "".join(x[2:] for x in out[0].strip("()").replace(" ", "").split(","))
    good = (key.lower() == n["publicKeyEip2537"][2:].lower() and out[1] == str(i) and out[2] == "true"
            and call("validatorAtSlot(uint8)(address)", str(i)).lower() == n["operator"].lower()
            and call("suspended(address)(bool)", n["operator"]) == "false")
    ok &= good
    print("read-back slot %d: %s" % (i, "OK" if good else "BAD"))
print("REHEARSAL", "PASSED" if ok else "FAILED")
sys.exit(0 if ok else 1)
PY
