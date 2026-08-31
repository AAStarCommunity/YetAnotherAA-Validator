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
//   1. the connected chainId must equal 11155111 (Sepolia) unless --chain-id overrides it
//   2. aggregator has code, and `version()` equals the pinned expectation (override: --expect-version)
//   3. `owner()` == the signer -> otherwise abort (see AUTHORIZATION)
//   4. `keccak(abi.encode(DOMAIN_NAME, chainid, address(this), REGISTRY))` reproduces the contract's
//      own `domainSeparator()` — proves the PoP domain is bound to THIS aggregator (a PoP cannot be
//      lifted from the old one) and that our view of the domain layout still matches SP's
//   5. the private key in each node file actually owns the public key in that same file
//      (derived pubkey must byte-match `publicKeyEip2537`) — catches a mixed-up/rotated key file
//   6. the PoP verifies locally under the pairing check before it is ever submitted
//   7. locally recomputed `popDigest` byte-matches the aggregator's own `popDigest()` view — this is
//      what catches an abi.encode layout drift between SP's contract and this script
//   8. `validatorAtSlot(slot)` is free or already this validator; `blsKeyOwner(keyHash)` is unset or
//      already this validator (SP rejects one key under two addresses: DuplicatePublicKey)
//   9. an eth_call dry-run of the real registration
//  10. no two plans in the batch claim the same slot, validator, or BLS key — every gate above reads
//      CHAIN state, so a collision between two PENDING plans is invisible to all of them
//
// Post-broadcast it reads back both `validatorAtSlot` AND `getBLSPublicKey`: the first answers "is
// anyone in this slot", the second answers "is the key I just registered the one sitting there".
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
//             --chain-id <n>                             (default 11155111; override for a fork)
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
// Defaults to Sepolia, overridable, same shape as --expect-version. NOT opt-in: a fork of Sepolia
// shares its bytecode, version() and owner(), and can even host a contract at the same CREATE
// address, so every other gate reads identically on both. The chain is the one thing only this
// check can tell you.
const EXPECT_CHAIN_ID = Number(flag("--chain-id") ?? 11155111);

const die = msg => {
  console.error(`\n✗ ${msg}`);
  process.exit(1);
};

/// Last-resort rendering for something thrown that is not an Error. String(e) on a plain object
/// gives "[object Object]", which is useless but still better than "undefined"; try JSON first.
function describe(e) {
  try {
    const j = JSON.stringify(e);
    if (j && j !== "{}") return j;
  } catch {
    /* circular or non-serialisable — fall through */
  }
  return String(e);
}

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

// THE ENV FILE WINS over ambient process.env. This is deliberate and was learned the hard way: an
// exported SEPOLIA_RPC_URL left over in the shell silently overrode an explicitly-passed --env that
// pointed at a local fork, so the script connected to REAL Sepolia while the operator believed it was
// on the fork. It got worse: the fork deployment had landed on the same CREATE address as a real
// deployment from the same account/nonce, so the address looked right too. Only the version() gate
// caught it. `--env <path>` is an explicit instruction; ambient variables are the fallback, never the
// override — this script signs transactions, so the quiet direction must be the safe one.
const RPC = env.SEPOLIA_RPC_URL || env.ETH_RPC_URL || env.RPC_URL || process.env.SEPOLIA_RPC_URL;
const KEY = env.OWNER_PRIVATE_KEY || env.DEPLOYER_PRIVATE_KEY || env.PRIVATE_KEY || process.env.OWNER_PRIVATE_KEY;
if (!RPC) die(`no RPC url in ${ENV_FILE} (SEPOLIA_RPC_URL / ETH_RPC_URL / RPC_URL)`);
if (!KEY) die(`no signing key in ${ENV_FILE} (OWNER_PRIVATE_KEY / DEPLOYER_PRIVATE_KEY / PRIVATE_KEY)`);
if (process.env.SEPOLIA_RPC_URL && process.env.SEPOLIA_RPC_URL !== RPC) {
  console.warn(`! ignoring ambient SEPOLIA_RPC_URL; ${ENV_FILE} wins (see the note above this check)`);
}

const ABI = [
  "function version() view returns (string)",
  "function owner() view returns (address)",
  "function domainSeparator() view returns (bytes32)",
  "function TAG_POP() view returns (bytes32)",
  "function DOMAIN_NAME() view returns (bytes32)",
  "function REGISTRY() view returns (address)",
  "function MAX_VALIDATORS() view returns (uint256)",
  "function validatorAtSlot(uint8) view returns (address)",
  "function blsKeyOwner(bytes32) view returns (address)",
  "function getBLSPublicKey(address) view returns ((bytes32,bytes32,bytes32,bytes32))",
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

  // Print the network before anything else. The address alone is NOT enough to tell you which chain
  // you are on: a CREATE from the same account at the same nonce lands on the same address on every
  // chain, so a fork and its parent can host different contracts at one address.
  const net = await provider.getNetwork();
  const chainId = Number(net.chainId);
  console.log(`rpc        : ${RPC.replace(/\/[^/]{16,}$/, "/<redacted>")}`);
  console.log(`chainId    : ${chainId}${EXPECT_CHAIN_ID ? ` (expected ${EXPECT_CHAIN_ID})` : ""}`);
  console.log(`block      : ${await provider.getBlockNumber()}`);
  console.log(`aggregator : ${AGGREGATOR}`);
  console.log(`signer     : ${wallet.address}`);
  console.log(`env file   : ${ENV_FILE}`);
  console.log(`mode       : ${BROADCAST ? "BROADCAST" : "dry-run (pass --broadcast to send)"}\n`);
  if (EXPECT_CHAIN_ID && chainId !== EXPECT_CHAIN_ID) {
    die(`wrong network: connected to chainId ${chainId}, expected ${EXPECT_CHAIN_ID}`);
  }

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
  const domainName = await read("DOMAIN_NAME()", () => agg.DOMAIN_NAME());
  const registryAddr = await read("REGISTRY()", () => agg.REGISTRY());

  // Recompute the domain from its four inputs. This proves two things a bare read cannot: that the
  // PoP domain really is bound to THIS aggregator address (so a PoP cannot be lifted from the old
  // contract), and that this script's understanding of the domain layout still matches SP's.
  const localDomain = ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes32", "uint256", "address", "address"],
      [domainName, chainId, AGGREGATOR, registryAddr]
    )
  );
  if (localDomain.toLowerCase() !== domainSep.toLowerCase()) {
    die(
      `domainSeparator layout drift.\n` +
        `  on-chain : ${domainSep}\n` +
        `  local    : ${localDomain}\n` +
        `  keccak(abi.encode(DOMAIN_NAME, chainid, address(this), REGISTRY)) no longer reproduces it.`
    );
  }
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

    // ---- gate 5: this private key really owns this public key ----------------------------------
    // Parse inside a try so a corrupt key is never echoed: ethers puts the offending value straight
    // into the message, and that would sit in terminal scrollback. Only a BROKEN key can throw here,
    // but naming the file is enough to fix it and leaks nothing.
    let sk;
    try {
      sk = ethers.getBytes(node.privateKey);
    } catch {
      die(`${label}: "privateKey" is not a valid hex byte string (value withheld) — fix the node file`);
    }
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
    const onchainDigest = await read(`popDigest() for ${label}`, () => agg.popDigest(validator, pkWords));
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

  // ---- gate 10: the plans must not collide with EACH OTHER ---------------------------------------
  // Every gate above reads CHAIN state, so two pending plans that clash are invisible to all of them:
  // three copies of one node file each pass individually, then land as ONE guardian while the run
  // reports three. Threshold is 3, so quorum stays unreachable while the operator holds "evidence"
  // saying otherwise. Found by pr-daemon on #248, with all three shapes reproduced on-chain.
  const seenSlot = new Map(),
    seenValidator = new Map(),
    seenKey = new Map();
  for (const p of plans) {
    const kh = ethers.keccak256(coder.encode(["bytes32", "bytes32", "bytes32", "bytes32"], p.pkWords));
    for (const [m, k, what] of [
      [seenSlot, p.slot, `slot ${p.slot}`],
      [seenValidator, p.validator.toLowerCase(), `validator ${p.validator}`],
      [seenKey, kh, `BLS key ${kh}`],
    ]) {
      if (m.has(k)) {
        die(
          `${m.get(k)} and ${p.label} both claim ${what}.\n` +
            `  Every gate above reads CHAIN state, so a collision between two pending plans is\n` +
            `  invisible to all of them. Fix the --nodes list.`
        );
      }
      m.set(k, p.label);
    }
  }

  if (!BROADCAST) {
    console.log(`\nAll ${plans.length} registrations passed every pre-flight gate. Nothing was sent.`);
    console.log("Re-run with --broadcast to submit.");
    return;
  }

  console.log(`\nBroadcasting ${plans.length} registrations…`);
  // Drive the nonce ourselves. Letting ethers infer it per call fails here: sending back-to-back from
  // one wallet, the node can still answer eth_getTransactionCount with a pre-inclusion value even
  // after `wait()` returned, and the next tx is rejected `nonce too low` — observed on the fork run,
  // where slots 1 and 2 landed and slot 3 was rejected. An explicit counter is deterministic and
  // makes the failure mode "this tx reverted", never "the tooling raced itself".
  let nonce = await provider.getTransactionCount(wallet.address, "pending");
  const receipts = [];
  for (const p of plans) {
    const tx = await agg.registerBLSPublicKey(p.validator, p.pkWords, p.slot, p.popWords, { nonce: nonce++ });
    const rc = await tx.wait();
    if (rc.status !== 1) die(`${p.label}: tx ${tx.hash} reverted on-chain`);
    console.log(`✓ ${p.label}  slot ${p.slot}  tx ${tx.hash}  block ${rc.blockNumber}`);
    receipts.push({ ...p, hash: tx.hash, block: rc.blockNumber });
  }

  // Read the state back rather than trusting the receipts: a status-1 receipt only proves the tx was
  // mined. And read the KEY, not just the slot occupant: `validatorAtSlot` answers "is anyone in this
  // slot", while the question is "is the key I just registered the one sitting there now". A stale
  // node file re-binding a live guardian's slot to the wrong key satisfies the first and fails the
  // second — SP accepts it (different keyHash is a fresh blsKeyOwner binding, and existing.index ==
  // slot so SlotAlreadyTaken never fires), and that guardian can then never sign for its own slot.
  console.log("\nPost-verify (read back from chain):");
  let bad = 0;
  for (const p of receipts) {
    const holder = await agg.validatorAtSlot(p.slot);
    const slotOk = holder.toLowerCase() === p.validator.toLowerCase();
    let keyOk = false;
    let onchainKey = "<unreadable>";
    try {
      const k = await agg.getBLSPublicKey(p.validator);
      onchainKey = ethers.concat([k[0], k[1], k[2], k[3]]);
      keyOk = onchainKey.toLowerCase() === ethers.concat(p.pkWords).toLowerCase();
    } catch (e) {
      onchainKey = `<read failed: ${e.shortMessage ?? e.message}>`;
    }
    if (!slotOk || !keyOk) bad++;
    console.log(`  slot ${p.slot} -> ${holder} ${slotOk ? "✓" : `✗ expected ${p.validator}`}`);
    console.log(`    key      ${keyOk ? "✓ matches the key this run registered" : `✗ on-chain ${onchainKey}`}`);
  }
  if (bad) die(`${bad} registration(s) did not read back as expected`);
  console.log("\nAll slots verified. Hand these tx hashes back to the B3 manifest:");
  for (const p of receipts) console.log(`  slot ${p.slot}  ${p.validator}  ${p.hash}`);
}

// A non-Error throw (a bare string, a rejected object) has neither .stack nor .message, so
// `e.stack ?? e.message` printed literally "✗ undefined" and swallowed the only clue there was.
// Verified: `Promise.reject("boom").catch(e => die(e.stack ?? e.message))` prints "✗ undefined".
main().catch(e => die(e?.stack ?? e?.message ?? describe(e)));
