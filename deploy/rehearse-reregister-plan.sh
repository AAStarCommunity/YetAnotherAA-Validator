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
#   SP_COMMIT  the 40-hex commit SP_DIR was fetched at. CHECKED, not just a label (Daybreak on 63a484d0,
#              M4): a git checkout must be at SP_COMMIT with no change to a tracked file. Every source
#              the two artifacts were compiled from must be on disk with the recorded keccak256 and
#              have the git blob SP_COMMIT pins (OpenZeppelin files: the v5.0.2 tag). Needs `gh`.
#   EXPECT_VERSIONS  "BLSAggregator-<x>,DVTValidator-<y>"; must equal the version() strings in those
#              two sources, and both generations deployed by the rehearsal must report exactly these.
#   PORT       anvil port (default 18645; must be free).
# A run rewrites SP_DIR/deployments/config.anvil.json (forge script). With a git checkout, restore it
# before the next run, or the clean-checkout check stops it (clestons #444).
# The three guardian BLS keys are generated fresh inside the run's temporary directory, so no real
# guardian key can be used by accident (Codex round 3, L5).
#
# Usage: SP_DIR=... SP_COMMIT=... EXPECT_VERSIONS=... deploy/rehearse-reregister-plan.sh [good|nonce-moved]
#   good         exit 0 and "REHEARSAL PASSED"; any failed assertion exits non-zero. After the A10 sends
#                it also runs the --deployment --export-pop path (the return-after-exit path) against
#                the new pair: it must stop on a guardian without ROLE_DVT, pass once each holds
#                ROLE_DVT and minStake, reproduce the same readsDigest on a later block, and stop on a
#                node file whose key differs from the active one and on a suspended guardian.
#   nonce-moved  the deployer sends one unplanned transaction after the export. The re-export must stop
#                on the nonce check and the address assertion must stop the send: exit 3.
set -euo pipefail
: "${SP_DIR:?set SP_DIR}" "${SP_COMMIT:?set SP_COMMIT}" "${EXPECT_VERSIONS:?set EXPECT_VERSIONS=BLSAggregator-<x>,DVTValidator-<y>}"
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
DSRC=$SP_DIR/contracts/src/modules/monitoring/DVTValidator.sol
[[ "$SP_COMMIT" =~ ^[0-9a-f]{40}$ ]] || { echo "SP_COMMIT must be 40 lowercase hex"; exit 1; }

# ---- SP_COMMIT is what SP_DIR holds, and the artifacts are built from it (Daybreak on 63a484d0, M4) ---
# Every source in the two artifacts' metadata must (1) have the keccak256 the metadata records, on disk
# in SP_DIR, and (2) have the git blob SP_COMMIT pins: SP's own files from SP_COMMIT's tree, and the
# OpenZeppelin files vendored under singleton-paymaster from OpenZeppelin's v5.0.2 tag, the version
# their directory names. Any other source path stops the run (Codex on the #444 delta, M1). Not
# checked: the compiler settings, and that bytecode was produced by them (printed, not compared).
BLOBS=$B/sp-blobs.tsv
if git -C "$SP_DIR" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  HEAD_SHA=$(git -C "$SP_DIR" rev-parse HEAD)
  [ "$HEAD_SHA" = "$SP_COMMIT" ] || { echo "FAIL: SP_DIR is at $HEAD_SHA, SP_COMMIT is $SP_COMMIT"; exit 1; }
  git -C "$SP_DIR" diff --quiet HEAD -- || { echo "FAIL: SP_DIR has changes to tracked files"; exit 1; }
  git -C "$SP_DIR" ls-tree -r "$SP_COMMIT" | awk -F'\t' '$1 ~ / blob / {split($1, a, " "); print $2 "\t" a[3]}' > "$BLOBS"
  echo "SP_DIR is a clean checkout at $SP_COMMIT"
else
  TREE=$(gh api "repos/AAStarCommunity/SuperPaymaster/git/trees/$SP_COMMIT?recursive=1")
  [ "$(printf '%s' "$TREE" | python3 -c 'import json,sys;print(json.load(sys.stdin)["truncated"])')" = False ] \
    || { echo "FAIL: GitHub truncated SP_COMMIT's tree listing"; exit 1; }
  printf '%s' "$TREE" | python3 -c 'import json,sys;[print(e["path"]+"\t"+e["sha"]) for e in json.load(sys.stdin)["tree"] if e["type"]=="blob"]' > "$BLOBS"
  echo "SP_COMMIT's tree: $(wc -l < "$BLOBS" | tr -d ' ') blobs (from GitHub)"
fi
[ -s "$BLOBS" ] || { echo "FAIL: no blob list for SP_COMMIT"; exit 1; }
# The expected versions are the ones the two sources return.
( cd "$WT" && node --input-type=module - "$SP_DIR" "$EXPECT_VERSIONS" "$BLOBS" <<'JS'
import { readFileSync } from "fs";
import { createHash } from "crypto";
import { execFileSync } from "child_process";
import { ethers } from "ethers";
const [dir, expect, blobsFile] = process.argv.slice(2);
const fail = m => { console.log(`FAIL: ${m}`); process.exit(1); };
const spBlobs = new Map(readFileSync(blobsFile, "utf8").split("\n").filter(Boolean).map(l => l.split("\t")));
const gitBlob = buf => createHash("sha1").update(`blob ${buf.length}\0`).update(buf).digest("hex");
const OZ = "singleton-paymaster/lib/openzeppelin-contracts-v5.0.2/";
const ozBlob = rel => execFileSync("gh", ["api", `repos/OpenZeppelin/openzeppelin-contracts/contents/${rel}?ref=v5.0.2`, "--jq", ".sha"], { encoding: "utf8" }).trim();
const want = {};
let n = 0;
for (const [name, prefix] of [["BLSAggregator", "BLSAggregator-"], ["DVTValidator", "DVTValidator-"]]) {
  const art = JSON.parse(readFileSync(`${dir}/out/${name}.sol/${name}.json`, "utf8"));
  const sources = art.metadata?.sources;
  if (!sources || !Object.keys(sources).length) fail(`out/${name}.sol has no metadata sources`);
  const c = art.metadata.compiler?.version, st = art.metadata.settings ?? {};
  console.log(`${name}: solc ${c}, viaIR ${st.viaIR}, optimizer ${JSON.stringify(st.optimizer)}, evm ${st.evmVersion} (printed, not compared)`);
  for (const [rel, meta] of Object.entries(sources)) {
    let buf;
    try { buf = readFileSync(`${dir}/${rel}`); } catch { fail(`${rel} (a source of out/${name}.sol) is missing from SP_DIR`); }
    if (meta.keccak256 !== ethers.keccak256(buf)) fail(`out/${name}.sol was not compiled from SP_DIR's ${rel}`);
    const expected = rel.startsWith(OZ) ? ozBlob(rel.slice(OZ.length)) : rel.startsWith("contracts/src/") ? spBlobs.get(rel) : null;
    if (!expected) fail(`${rel}: no pinned blob for this path (only contracts/src/ and ${OZ} are known)`);
    if (gitBlob(buf) !== expected) fail(`${rel}: blob ${gitBlob(buf)}, pinned ${expected}`);
    n++;
  }
  const rel = `contracts/src/modules/monitoring/${name}.sol`;
  if (!sources[rel]) fail(`out/${name}.sol does not list ${rel}`);
  const m = readFileSync(`${dir}/${rel}`, "utf8").match(new RegExp(`return "(${prefix}[^"]+)";`, "g")) ?? [];
  if (m.length !== 1) fail(`${rel} has ${m.length} "return \\"${prefix}…\\"" lines, expected exactly 1`);
  want[name] = m[0].slice(8, -2);
}
const got = `${want.BLSAggregator},${want.DVTValidator}`;
if (got !== expect) fail(`the sources return ${got}; EXPECT_VERSIONS is ${expect}`);
console.log(`artifacts: ${n} source entries, each on disk with the recorded keccak256 and the pinned blob; they return ${got}`);
JS
)
NODES_DIR=$B/nodes
NODES="$NODES_DIR/node_test_1.json,$NODES_DIR/node_test_2.json,$NODES_DIR/node_test_3.json"
( umask 077; printf 'RPC_URL=%s\n' "$R" > "$B/anvil.env" )
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

# The versions the deployed contracts must report, e.g. "BLSAggregator-4.14.1,DVTValidator-0.9.0".
# Required: taken from the SP commit's tree, never assumed here.
check_versions() { # $1 aggregator  $2 dvtValidator  $3 label
  local a d
  a=$("$C" call "$1" 'version()(string)' --rpc-url "$R" | tr -d '"'); d=$("$C" call "$2" 'version()(string)' --rpc-url "$R" | tr -d '"')
  [ "$a,$d" = "$EXPECT_VERSIONS" ] || { echo "FAIL: $3 versions are $a,$d; EXPECT_VERSIONS is $EXPECT_VERSIONS"; exit 1; }
  echo "$3 versions: $a, $d (as expected)"
}

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
check_versions "$OLDAGG" "$(jget "$G1" dvtValidator)" "gen1"

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
# DVTValidator-0.9.0 (SP #635): (registry, firstProposalId, bytes32[] categories, address[] checkers).
# rc.8 deploys no evidence category (categoryCount() == 0), so both lists are empty here.
DARGS=$("$C" abi-encode 'c(address,uint256,bytes32[],address[])' "$REG" 1 '[]' '[]')
"$C" send --private-key "$K0" --rpc-url "$R" --create "$DBC${DARGS:2}" >/dev/null
NDVT=$("$C" compute-address "$D" --nonce $(( $("$C" nonce "$D" --rpc-url "$R") - 1 )) | awk '{print $NF}')
AARGS=$("$C" abi-encode 'c(address,address,address)' "$REG" "$SPX" "$NDVT")
"$C" send --private-key "$K0" --rpc-url "$R" --create "$ABC${AARGS:2}" >/dev/null
NAGG=$("$C" compute-address "$D" --nonce $(( $("$C" nonce "$D" --rpc-url "$R") - 1 )) | awk '{print $NF}')
echo "deployed: DVT $NDVT AGG $NAGG"
check_versions "$NAGG" "$NDVT" "new pair"

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
sys.exit(0 if ok else 1)
PY

# ---- the --deployment --export-pop path (return after exit) against the new pair ---------------------
# Daybreak on 63a484d0, M1-M3 (DSR 2026-11-18). The deployer is still the owner here (no hand-off).
DEP=$B/deployment.json
printf '{"dvtValidator":"%s","blsAggregator":"%s","registry":"%s"}\n' "$NDVT" "$NAGG" "$REG" > "$DEP"
dep_export() { # $1 nodes  $2 output file
  ( cd "$WT" && env -u SEPOLIA_RPC_URL node deploy/reregister-guardians.mjs --env "$B/anvil.env" \
      --chain-id 31337 --deployment "$DEP" --expect-versions "$EXPECT_VERSIONS" --expect-owner "$D" \
      --nodes "$1" --export-pop "$2" )
}
must_stop() { # $1 what  $2 pattern  $3 nodes  -- the export must fail, and for THIS reason
  local out
  if out=$(dep_export "$3" "$B/must-stop.json" 2>&1); then echo "FAIL: $1: the export passed"; exit 1; fi
  echo "$out" | grep -q -- "$2" || { echo "FAIL: $1: stopped for another reason:"; echo "$out" | grep '✗'; exit 1; }
  echo "$1: stopped (expected)"
}
must_stop "M2 guardians without ROLE_DVT" "does not hold ROLE_DVT" "$NODES"

# Give each throwaway guardian ROLE_DVT with minStake, as a real one would: GToken from the anvil
# deployer, then approve + registerRole from the guardian itself (impersonated; never-funded address).
GT=$(jget "$G1" gToken)
STK=$("$C" call "$REG" 'GTOKEN_STAKING()(address)' --rpc-url "$R")
ROLE=$("$C" keccak DVT)
for i in 1 2 3; do
  V=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['operator'])" "$NODES_DIR/node_test_$i.json")
  "$C" rpc anvil_setBalance "$V" 0x8AC7230489E80000 --rpc-url "$R" >/dev/null
  "$C" send "$GT" 'transfer(address,uint256)' "$V" 33ether --private-key "$K0" --rpc-url "$R" >/dev/null
  "$C" rpc anvil_impersonateAccount "$V" --rpc-url "$R" >/dev/null
  "$C" send "$GT" 'approve(address,uint256)' "$STK" 33ether --from "$V" --unlocked --rpc-url "$R" >/dev/null
  "$C" send "$REG" 'registerRole(bytes32,address,bytes)' "$ROLE" "$V" 0x --from "$V" --unlocked --rpc-url "$R" >/dev/null
  "$C" rpc anvil_stopImpersonatingAccount "$V" --rpc-url "$R" >/dev/null
  [ "$("$C" call "$REG" 'hasRole(bytes32,address)(bool)' "$ROLE" "$V" --rpc-url "$R")" = true ] \
    || { echo "FAIL: guardian $i did not get ROLE_DVT"; exit 1; }
done
echo "three guardians hold ROLE_DVT with minStake"

dep_export "$NODES" "$B/dep-1.json"
"$C" rpc anvil_mine 3 --rpc-url "$R" >/dev/null
dep_export "$NODES" "$B/dep-2.json"
python3 - "$B/dep-1.json" "$B/dep-2.json" <<'PY'
import json, sys
a, b = (json.load(open(f)) for f in sys.argv[1:])
def need(ok, what):
    if not ok:
        print("FAIL:", what); sys.exit(1)
for x in (a, b):
    need(sorted(x["basis"]) == ["block", "blockHash", "timestamp"], "basis keys")
    need(len(x["reads"]["validators"]) == 3, "reads.validators count")
    need(all(v["hasRoleDvt"] and v["active"] and not v["suspended"] for v in x["reads"]["validators"]), "validator state")
need(b["basis"]["block"] > a["basis"]["block"], "the second export read a later block")
need(a["reads"] == b["reads"] and a["readsDigest"] == b["readsDigest"], "reads changed with no state change")
need([r["calldata"] for r in a["registrations"]] == [r["calldata"] for r in b["registrations"]], "calldata changed")
print("M3: re-export on block %d reproduces block %d's reads and digest %s" % (b["basis"]["block"], a["basis"]["block"], a["readsDigest"]))
PY

# M1: a node file with a different key for an ACTIVE guardian (same operator, same slot) must stop,
# and the message shows only each key's ends.
STALE=$NODES_DIR/node_stale_1.json
( umask 077; cd "$WT" && node --input-type=module - "$NODES_DIR/node_test_1.json" "$STALE" <<'JS'
import { bls12_381 as bls } from "@noble/curves/bls12-381.js";
import { ethers } from "ethers";
import { readFileSync, writeFileSync } from "fs";
const n = JSON.parse(readFileSync(process.argv[2], "utf8"));
const enc = p => {
  const o = new Uint8Array(128), a = p.toAffine();
  o.set(ethers.getBytes("0x" + a.x.toString(16).padStart(96, "0")), 16);
  o.set(ethers.getBytes("0x" + a.y.toString(16).padStart(96, "0")), 80);
  return ethers.hexlify(o);
};
const sk = bls.utils.randomSecretKey();
writeFileSync(process.argv[3], JSON.stringify({ ...n, nodeName: "stale-1", privateKey: ethers.hexlify(sk),
  publicKeyEip2537: enc(bls.longSignatures.getPublicKey(sk)) }), { mode: 0o600 });
JS
)
OUT=$(dep_export "$STALE" "$B/must-stop.json" 2>&1) && { echo "FAIL: M1: a different key for an active guardian passed"; exit 1; }
echo "$OUT" | grep -q "with a DIFFERENT BLS key" || { echo "FAIL: M1 stopped for another reason:"; echo "$OUT" | grep '✗'; exit 1; }
for F in "$NODES_DIR/node_test_1.json" "$STALE"; do
  K=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['publicKeyEip2537'][2:].lower())" "$F")
  echo "$OUT" | tr 'A-F' 'a-f' | grep -q "$K" && { echo "FAIL: M1 message prints a whole key"; exit 1; }
done
echo "M1 a different key for an active guardian: stopped (expected), message shows key ends only"

# A guardian suspended after the export: the re-run before the SAFE executes must stop.
V1=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['operator'])" "$NODES_DIR/node_test_1.json")
"$C" send "$NAGG" 'setSuspended(address,bool)' "$V1" true --private-key "$K0" --rpc-url "$R" >/dev/null
must_stop "M3 a guardian suspended after the export" "is suspended on this aggregator" "$NODES"
echo "REHEARSAL PASSED"
