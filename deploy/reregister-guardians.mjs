// CC-115 B3 — re-register DVT guardian BLS keys on a NEW SuperPaymaster BLSAggregator.
//
// WHY THIS EXISTS
// ---------------
// BLSAggregator is NOT upgradeable, so SP's 4.3.0 -> 4.11.0 rotation deploys a fresh contract with
// EMPTY state: zero registered validators. The MINOR consensus threshold is 3, so until the guardian
// keys are re-registered the new aggregator cannot reach quorum on ANY path.
//
// SP cannot do this step. `popDigest` binds the proof-of-possession to `address(this)` (via
// `domainSeparator()`), so PoPs from the old aggregator are worthless on the new one — each key must
// re-sign, and SP does not hold the BLS secrets. This script is the DVT half of that handoff.
//
// AUTHORIZATION — READ BEFORE RUNNING
// -----------------------------------
// `registerBLSPublicKey` has two paths (BLSAggregator.sol:702-742):
//
//   owner path         msg.sender == owner()  -> may register ANY validator, and CHOOSES the slot.
//   self-register path needs `permissionlessBLSRegistration` on, msg.sender == validator, AND passes
//                      `_requireDVTStake(validator, slot)`; the slot is then assigned as the lowest
//                      free one — the caller does not get to pick.
//
// The self-register path CANNOT be used here: SP measured `getEffectiveStake(validator, ROLE_DVT) == 0`
// for these addresses on Sepolia, so `_requireDVTStake` reverts. It would also renumber the slots.
// Slot identity matters — historical proofs and mask bits reference it — so this script requires the
// owner path and refuses to run as anyone else. That refusal is a feature: silently falling back
// would either revert after paying for the G1/pairing precompiles, or quietly move a guardian's slot.
//
// WHAT IT VERIFIES BEFORE SPENDING GAS
// ------------------------------------
// Every gate below runs for ALL nodes before ANY transaction is sent, and a single failure aborts the
// whole run (no partial registration):
//   1. aggregator has code, and `version()` equals the pinned expectation (override: --expect-version)
//   2. `owner()` == the signer -> otherwise abort (see AUTHORIZATION)
//   3. the private key in each node file actually owns the public key in that same file
//      (derived pubkey must byte-match `publicKeyEip2537`) — catches a mixed-up/rotated key file
//   4. the PoP verifies locally under the pairing check before it is ever submitted
//   5. locally recomputed `popDigest` byte-matches the aggregator's own `popDigest()` view — this is
//      what catches an abi.encode layout drift between SP's contract and this script
//   6. `validatorAtSlot(slot)` is free or already this validator; `blsKeyOwner(keyHash)` is unset or
//      already this validator (SP rejects one key under two addresses: DuplicatePublicKey)
//   7. an eth_call dry-run of the real registration
//
// Dry-run is the DEFAULT. Nothing is broadcast without --broadcast.
//
// PARTIAL FAILURE IS SAFE TO RETRY. All gates run before the first transaction, so a pre-flight
// failure sends nothing. If a LATER broadcast reverts, earlier registrations stay — just re-run.
// SP makes re-registration idempotent for an unchanged (validator, slot, key): re-registering the
// same validator reuses its prior slot, and `blsKeyOwner[keyHash] == validator` is accepted rather
// than rejected as a duplicate (BLSAggregator.sol:746-763).
//
// env file (default .env.sepolia; Sepolia creds actually live in SuperPaymaster/.env.sepolia):
//   SEPOLIA_RPC_URL (or ETH_RPC_URL/RPC_URL), and one of
//   OWNER_PRIVATE_KEY / DEPLOYER_PRIVATE_KEY / PRIVATE_KEY
//
// Usage:
//   node deploy/reregister-guardians.mjs --aggregator 0x... --env ../SuperPaymaster/.env.sepolia
//   node deploy/reregister-guardians.mjs --aggregator 0x... --env <path> --broadcast
//   optional: --nodes node_dev_001.json,node_dev_002.json,node_dev_003.json
//             --expect-version "BLSAggregator-4.11.0"   (only after re-verifying the new release)
import { ethers } from "ethers";
import { readFileSync } from "fs";
import { bls12_381 as bls } from "@noble/curves/bls12-381.js";

const POP_DST = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
const DEFAULT_NODES = ["node_dev_001.json", "node_dev_002.json", "node_dev_003.json"];
const DEFAULT_VERSION = "BLSAggregator-4.11.0";

const argv = process.argv.slice(2);
const flag = name => {
  const i = argv.indexOf(name);
  return i === -1 ? undefined : argv[i + 1];
};
const BROADCAST = argv.includes("--broadcast");
const AGGREGATOR = flag("--aggregator") || process.env.BLS_AGGREGATOR_ADDRESS;
const ENV_FILE = flag("--env") || process.env.DVT_ENV_FILE || ".env.sepolia";
const NODE_FILES = (flag("--nodes") || DEFAULT_NODES.join(",")).split(",").map(s => s.trim()).filter(Boolean);
const EXPECT_VERSION = flag("--expect-version") || DEFAULT_VERSION;

const die = msg => {
  console.error(`\n✗ ${msg}`);
  process.exit(1);
};

if (!AGGREGATOR) die("missing --aggregator <address> (the NEW BLSAggregator, from SP's B3 handoff)");
if (!ethers.isAddress(AGGREGATOR)) die(`--aggregator is not an address: ${AGGREGATOR}`);

const strip = s => s.replace(/^["']|["']$/g, "");
let env;
try {
  env = Object.fromEntries(
    readFileSync(ENV_FILE, "utf8")
      .split("\n")
      .filter(l => l.includes("=") && !l.trim().startsWith("#"))
      .map(l => {
        const i = l.indexOf("=");
        return [l.slice(0, i).trim(), strip(l.slice(i + 1).trim())];
      })
  );
} catch (e) {
  die(`cannot read env file ${ENV_FILE}: ${e.message}\n  Sepolia credentials live in SuperPaymaster/.env.sepolia — pass --env <path>.`);
}

const RPC = process.env.SEPOLIA_RPC_URL || env.SEPOLIA_RPC_URL || env.ETH_RPC_URL || env.RPC_URL;
const KEY = process.env.OWNER_PRIVATE_KEY || env.OWNER_PRIVATE_KEY || env.DEPLOYER_PRIVATE_KEY || env.PRIVATE_KEY;
if (!RPC) die(`no RPC url in ${ENV_FILE} (SEPOLIA_RPC_URL / ETH_RPC_URL / RPC_URL)`);
if (!KEY) die(`no signing key in ${ENV_FILE} (OWNER_PRIVATE_KEY / DEPLOYER_PRIVATE_KEY / PRIVATE_KEY)`);

const ABI = [
  "function version() view returns (string)",
  "function owner() view returns (address)",
  "function domainSeparator() view returns (bytes32)",
  "function TAG_POP() view returns (bytes32)",
  "function MAX_VALIDATORS() view returns (uint256)",
  "function validatorAtSlot(uint8) view returns (address)",
  "function blsKeyOwner(bytes32) view returns (address)",
  "function popDigest(address validator, (bytes32,bytes32,bytes32,bytes32) publicKey) view returns (bytes32)",
  "function registerBLSPublicKey(address validator, (bytes32,bytes32,bytes32,bytes32) publicKey, uint8 slot, (bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32) popSignature)",
];

/// Split a 0x-prefixed byte string into 32-byte words. EIP-2537 G1 is 128 bytes (4 words) and G2 is
/// 256 bytes (8 words); those map 1:1 onto SP's BLS.G1Point / BLS.G2Point structs.
function toWords(hex, expectedBytes) {
  const b = ethers.getBytes(hex);
  if (b.length !== expectedBytes) throw new Error(`expected ${expectedBytes} bytes, got ${b.length}`);
  const words = [];
  for (let i = 0; i < b.length; i += 32) words.push(ethers.hexlify(b.slice(i, i + 32)));
  return words;
}

/// EIP-2537 wire encoding for a G2 point: four 64-byte limbs, each a 48-byte field element
/// left-padded with 16 zero bytes. Order matches BLS.G2Point: x.c0, x.c1, y.c0, y.c1.
function encodeG2(point) {
  const out = new Uint8Array(256);
  const a = point.toAffine();
  const put = (v, at) => out.set(ethers.getBytes("0x" + v.toString(16).padStart(96, "0")), at);
  put(a.x.c0, 16);
  put(a.x.c1, 80);
  put(a.y.c0, 144);
  put(a.y.c1, 208);
  return ethers.hexlify(out);
}

/// Same wire shape for G1: two 64-byte limbs (x, y).
function encodeG1(point) {
  const out = new Uint8Array(128);
  const a = point.toAffine();
  const put = (v, at) => out.set(ethers.getBytes("0x" + v.toString(16).padStart(96, "0")), at);
  put(a.x, 16);
  put(a.y, 80);
  return ethers.hexlify(out);
}

async function main() {
  const provider = new ethers.JsonRpcProvider(RPC);
  const wallet = new ethers.Wallet(KEY, provider);
  const agg = new ethers.Contract(AGGREGATOR, ABI, wallet);

  console.log(`aggregator : ${AGGREGATOR}`);
  console.log(`signer     : ${wallet.address}`);
  console.log(`env file   : ${ENV_FILE}`);
  console.log(`mode       : ${BROADCAST ? "BROADCAST" : "dry-run (pass --broadcast to send)"}\n`);

  // ---- gate 1: the contract is the release we expect -------------------------------------------
  if ((await provider.getCode(AGGREGATOR)) === "0x") die(`no code at ${AGGREGATOR} on this chain`);
  const version = await agg.version();
  console.log(`version()  : ${version}`);
  if (version !== EXPECT_VERSION) {
    die(
      `version mismatch: on-chain "${version}" != expected "${EXPECT_VERSION}".\n` +
        `  This script is written against ${DEFAULT_VERSION}'s registerBLSPublicKey/popDigest surface.\n` +
        `  Override with --expect-version ONLY after re-checking that the new release keeps the same\n` +
        `  PoP domain (address-bound popDigest) and the same owner-path slot semantics.`
    );
  }

  // ---- gate 2: owner path is the only usable path (see AUTHORIZATION) ---------------------------
  const owner = await agg.owner();
  console.log(`owner()    : ${owner}`);
  if (owner.toLowerCase() !== wallet.address.toLowerCase()) {
    die(
      `signer is not the aggregator owner.\n` +
        `  owner()  = ${owner}\n` +
        `  signer   = ${wallet.address}\n` +
        `  The self-registration path is NOT a fallback here: these validators have zero effective\n` +
        `  ROLE_DVT stake, so _requireDVTStake reverts, and that path also reassigns slots.`
    );
  }

  // Read the PoP domain members explicitly rather than in a bare Promise.all: if --expect-version was
  // overridden onto a release that predates them, a raw ethers decode stack is useless to an operator.
  const read = async (name, call) => {
    try {
      return await call();
    } catch (e) {
      die(
        `${AGGREGATOR} does not answer ${name} (${e.shortMessage ?? e.message}).\n` +
          `  Releases before ${DEFAULT_VERSION} lack the PoP-domain surface this script needs.\n` +
          `  If you reached here via --expect-version, that override was wrong: the contract cannot\n` +
          `  produce the address-bound popDigest these registrations must sign.`
      );
    }
  };
  const domainSep = await read("domainSeparator()", () => agg.domainSeparator());
  const tagPop = await read("TAG_POP()", () => agg.TAG_POP());
  const maxValidators = await read("MAX_VALIDATORS()", () => agg.MAX_VALIDATORS());
  console.log(`domainSep  : ${domainSep}`);
  console.log(`MAX_VALIDATORS: ${maxValidators}\n`);

  const coder = ethers.AbiCoder.defaultAbiCoder();
  const plans = [];

  for (const file of NODE_FILES) {
    let node;
    try {
      node = JSON.parse(readFileSync(file, "utf8"));
    } catch (e) {
      die(`cannot read node file ${file}: ${e.message}`);
    }
    const label = `${file} (${node.nodeName ?? "?"})`;
    const validator = node.operator;
    const slot = Number(node.slot);
    if (!validator || !ethers.isAddress(validator)) die(`${label}: missing/invalid "operator" address`);
    if (!Number.isInteger(slot) || slot < 1 || slot > Number(maxValidators)) {
      die(`${label}: slot ${node.slot} out of range 1..${maxValidators}`);
    }
    if (!node.publicKeyEip2537) die(`${label}: missing "publicKeyEip2537"`);
    if (!node.privateKey) die(`${label}: missing "privateKey"`);

    // ---- gate 3: this private key really owns this public key ----------------------------------
    const sk = ethers.getBytes(node.privateKey);
    const pkPoint = bls.longSignatures.getPublicKey(sk);
    const derived = encodeG1(pkPoint);
    if (derived.toLowerCase() !== node.publicKeyEip2537.toLowerCase()) {
      die(
        `${label}: the private key does not match publicKeyEip2537 in the same file.\n` +
          `  derived : ${derived}\n` +
          `  in file : ${node.publicKeyEip2537}\n` +
          `  Registering would bind a key nobody can sign with. Fix the node file first.`
      );
    }
    const pkWords = toWords(node.publicKeyEip2537, 128);

    // ---- gate 5a: our understanding of popDigest must match the contract's ---------------------
    const onchainDigest = await agg.popDigest(validator, pkWords);
    const localDigest = ethers.keccak256(
      coder.encode(
        ["bytes32", "bytes32", "address", "bytes32", "bytes32", "bytes32", "bytes32"],
        [domainSep, tagPop, validator, ...pkWords]
      )
    );
    if (onchainDigest.toLowerCase() !== localDigest.toLowerCase()) {
      die(
        `${label}: popDigest layout drift — the contract and this script disagree.\n` +
          `  on-chain : ${onchainDigest}\n` +
          `  local    : ${localDigest}\n` +
          `  Do NOT override this. It means SP changed the PoP encoding; update this script instead.`
      );
    }

    // Sign the digest bytes. The contract hashes abi.encodePacked(popDigest) — i.e. the raw 32
    // bytes — to G2 under the PoP DST, so that is exactly what we sign.
    const msgPoint = await bls.G2.hashToCurve(ethers.getBytes(onchainDigest), { DST: POP_DST });
    const sigPoint = bls.longSignatures.sign(msgPoint, sk);

    // ---- gate 4: verify the pairing locally before paying for it on-chain ----------------------
    if (!bls.longSignatures.verify(sigPoint, msgPoint, pkPoint)) {
      die(`${label}: locally produced PoP fails its own pairing check — refusing to submit`);
    }
    const popWords = toWords(encodeG2(sigPoint), 256);

    // ---- gate 6: slot and key-ownership collisions ---------------------------------------------
    const keyHash = ethers.keccak256(coder.encode(["bytes32", "bytes32", "bytes32", "bytes32"], pkWords));
    const [slotHolder, keyOwner] = await Promise.all([agg.validatorAtSlot(slot), agg.blsKeyOwner(keyHash)]);
    if (slotHolder !== ethers.ZeroAddress && slotHolder.toLowerCase() !== validator.toLowerCase()) {
      die(`${label}: slot ${slot} is already held by ${slotHolder} — SP reverts SlotAlreadyTaken`);
    }
    if (keyOwner !== ethers.ZeroAddress && keyOwner.toLowerCase() !== validator.toLowerCase()) {
      die(`${label}: this BLS key is already bound to ${keyOwner} — SP reverts DuplicatePublicKey`);
    }

    // ---- gate 7: dry-run the real call ---------------------------------------------------------
    try {
      await agg.registerBLSPublicKey.staticCall(validator, pkWords, slot, popWords);
    } catch (e) {
      die(`${label}: eth_call dry-run of registerBLSPublicKey reverted: ${e.shortMessage ?? e.message}`);
    }

    console.log(`✓ ${label}`);
    console.log(`    validator ${validator}  slot ${slot}`);
    console.log(`    popDigest ${onchainDigest}`);
    console.log(`    slot now  ${slotHolder === ethers.ZeroAddress ? "free" : slotHolder}`);
    plans.push({ label, validator, slot, pkWords, popWords });
  }

  if (!BROADCAST) {
    console.log(`\nAll ${plans.length} registrations passed every pre-flight gate. Nothing was sent.`);
    console.log("Re-run with --broadcast to submit.");
    return;
  }

  console.log(`\nBroadcasting ${plans.length} registrations…`);
  const receipts = [];
  for (const p of plans) {
    const tx = await agg.registerBLSPublicKey(p.validator, p.pkWords, p.slot, p.popWords);
    const rc = await tx.wait();
    if (rc.status !== 1) die(`${p.label}: tx ${tx.hash} reverted on-chain`);
    console.log(`✓ ${p.label}  slot ${p.slot}  tx ${tx.hash}  block ${rc.blockNumber}`);
    receipts.push({ ...p, hash: tx.hash, block: rc.blockNumber });
  }

  // Read the state back rather than trusting the receipts: a status-1 receipt only proves the tx was
  // mined, not that the slot now points where we intended.
  console.log("\nPost-verify (read back from chain):");
  let bad = 0;
  for (const p of receipts) {
    const holder = await agg.validatorAtSlot(p.slot);
    const ok = holder.toLowerCase() === p.validator.toLowerCase();
    if (!ok) bad++;
    console.log(`  slot ${p.slot} -> ${holder} ${ok ? "✓" : `✗ expected ${p.validator}`}`);
  }
  if (bad) die(`${bad} slot(s) did not read back as expected`);
  console.log("\nAll slots verified. Hand these tx hashes back to the B3 manifest:");
  for (const p of receipts) console.log(`  slot ${p.slot}  ${p.validator}  ${p.hash}`);
}

main().catch(e => die(e.stack ?? e.message));
