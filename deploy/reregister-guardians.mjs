// rc.8 A7.dvt — register the DVT guardians' BLS keys on a NEW SuperPaymaster DVTValidator +
// BLSAggregator pair. Written against SP main b5e7544e (BLSAggregator-4.14.0, DVTValidator-0.8.0);
// the versions to expect are NOT written in this file — pass them with --expect-versions, taken from
// the version() strings in the rc.8 tag's tree.
//
// WHY THIS EXISTS
// ---------------
// Neither contract is upgradeable, so rc.8 deploys a fresh pair with EMPTY state: zero registered
// validators. The MINOR consensus threshold is 3, so until the guardian keys are registered again
// the new aggregator cannot reach quorum on ANY path.
//
// SP cannot do this step. `popDigest` binds the proof-of-possession to the AGGREGATOR address (via
// `domainSeparator()`) and to the validator address, so PoPs from the old aggregator are worthless on
// the new one — each key must sign again, and SP does not hold the BLS secrets.
//
// ADDRESSES COME FROM SP'S DEPLOY OUTPUT, NEVER FROM THIS FILE
// -----------------------------------------------------------
// --deployment <file> is SP's deploy output JSON (DeployAnvil's config file, or the rc.8 deploy
// log/manifest output). The script reads `dvtValidator` and `blsAggregator` (and `registry` if
// present) from it. There is no --aggregator flag and no address default.
//
// AUTHORIZATION — READ BEFORE RUNNING
// -----------------------------------
// On 4.14.0 `BLSAggregator.registerBLSPublicKey` accepts ONLY msg.sender == DVT_VALIDATOR. The entry
// point is `DVTValidator.registerBLSPublicKey` (DVTValidator.sol:209), which has two paths:
//
//   owner path       msg.sender == DVTValidator.owner() AND == aggregator.owner() -> may register ANY
//                    validator, and CHOOSES the slot.
//   permissionless   needs `permissionlessBLSRegistration()`, msg.sender == validator, and live role/
//                    stake; the slot is assigned as the lowest free one — the caller does not pick it.
//
// Slot identity matters — historical proofs and mask bits reference it — so this script uses the
// owner path only, and refuses to run unless the two owners are the SAME address (DSR 2026-11-15).
// It reads and records `permissionlessBLSRegistration()` either way.
//
// THIS SCRIPT SENDS NOTHING AND USES NO EOA KEY. --broadcast is disabled (Daybreak on 63a484d0,
// High; DSR 2026-11-18): it is refused before any file or RPC is read. The owner (the SAFE) executes
// the calldata --export-pop writes.
//
// WHAT IT VERIFIES BEFORE EXPORTING
// ---------------------------------
// Every gate below runs for ALL nodes, at ONE block, before anything is written, and a single failure
// aborts the whole run:
//   1. the connected chainId must equal 11155111 (Sepolia) unless --chain-id overrides it
//   2. both contracts have code; `version()` of each equals --expect-versions (required for
//      --export-pop; a dry run without it prints the versions and says so)
//   3. the pair is wired to each other: DVTValidator.BLS_AGGREGATOR() == aggregator,
//      aggregator.DVT_VALIDATOR() == DVTValidator, both REGISTRY() agree (and match the deployment
//      file if it names one), and Registry.blsAggregator() == aggregator
//   4. DVTValidator.owner() == aggregator.owner() (== --expect-owner) -> otherwise abort
//   5. `keccak(abi.encode(DOMAIN_NAME, chainid, aggregator, REGISTRY))` reproduces the aggregator's
//      own `domainSeparator()` — proves the PoP domain is bound to THIS aggregator
//   6. the private key in each node file owns the public key in that same file
//   7. locally recomputed `popDigest` byte-matches the aggregator's own `popDigest()` view
//   8. the PoP verifies locally under the pairing check before it is ever submitted
//   9. the validator is not suspended; if it already has an active key, it is in this same slot AND
//      it is this same key (no silent rotation); `validatorAtSlot(slot)` is free or this validator;
//      `blsKeyOwner(keyHash)` is unset or this validator
//  9b. it can sign once registered: ROLE_DVT, a ROLE_DVT lock >= minStake, no exit notice in effect
//      (the checks SP's _reconstructPkAgg makes at every aggregation)
//  10. an eth_call dry-run of the real DVTValidator call, from the owner
//  11. no two plans in the batch claim the same slot, validator, or BLS key
//
// Without --export-pop it is a dry run: the gates, then nothing written.
//
// --export-pop <file> writes the public PoP data plus the DVTValidator calldata for the owner to
// execute, with the block the gates read and those reads (`basis`, `reads`, `readsDigest`).
//
// --plan <frozen plan.json> --export-pop <file> IS THE rc.8 DEPLOY-DAY MODE (SP manifest step A10). The
// contracts do not exist yet: their addresses are SP's precomputed ones from the pin. The script
// checks only that those addresses are empty, the pin block hash matches, the deployer's nonce is
// unchanged since the pin, and the Registry (read from pin.oldAggregator) has code. It computes the
// domain and popDigests locally, with DOMAIN_NAME / TAG_POP extracted from --sp-aggregator-source,
// and writes SP's six-key `pop` entries plus `popContext`, and, outside it, aggregatorSourceVersion
// (the release the source's version() returns). SP's A10 asserts versions, wiring, owner and
// on-chain popDigest() equality at send time. If the deployer nonce moves, export again after SP re-pins.
//
// --export-fraud-drill <file> IS FOR A FORK REHEARSAL ONLY, and is STALE against 4.14.0: the 4.14.0
// signer commitment adds the parent block hash, which the drill does not include (issue #441). It
// writes one valid over-issue fraud proof plus four cases that must be rejected, and NO BLS SIGNATURE.
//
// A PARTLY EXECUTED EXPORT IS SAFE TO RE-EXPORT: re-registering the same (validator, slot, key) is
// accepted (BLSAggregator.sol, `blsKeyOwner[keyHash] == validator` and the same-slot rule).
//
// env file (default .env.sepolia; Sepolia creds actually live in SuperPaymaster/.env.sepolia): only
// SEPOLIA_RPC_URL / ETH_RPC_URL / RPC_URL are kept from it; every other line, keys included, is
// dropped as it is split. The file is still read whole, so a shared env file's keys pass through
// memory; no key is selected, kept, used or printed. Pass an RPC-only file to avoid even that.
//
// Usage:
//   node deploy/reregister-guardians.mjs --deployment <sp-deploy.json> --env ../SuperPaymaster/.env.sepolia
//   node deploy/reregister-guardians.mjs --deployment <file> --env <path> --export-pop <file>
//   node deploy/reregister-guardians.mjs --deployment <file> --env <path> --export-fraud-drill <file> --verifier 0x...
//   node deploy/reregister-guardians.mjs --plan <plan.json> --sp-aggregator-source <BLSAggregator.sol> --sp-commit <sha> --export-pop <file> --env <path>
//   optional: --nodes node_dev_001.json,node_dev_002.json,node_dev_003.json
//             --expect-versions BLSAggregator-<x>,DVTValidator-<y>  (from the rc.8 tag's tree)
//             --expect-owner 0x...                         (from SP's rc.8 owner table; required in practice)
//             --chain-id <n>                               (default 11155111; override for a fork/anvil)
import { ethers } from "ethers";
import { createHash } from "crypto";
import { readFileSync, writeFileSync } from "fs";
import { dirname, resolve } from "path";
import { fileURLToPath } from "url";
import { bls12_381 as bls } from "@noble/curves/bls12-381.js";
import { keyEnds, fieldShape, pubKeyShape, nodeNameShape } from "./lib/redact.mjs";
import { aggregatorSourceVersion } from "./lib/sp-source.mjs";

const POP_DST = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
const DEFAULT_NODES = ["node_dev_001.json", "node_dev_002.json", "node_dev_003.json"];

const argv = process.argv.slice(2);
// STRICT PARSING (Codex review of 20a0088, M1). The old `indexOf` lookup took the FIRST occurrence, so a
// corrected --deployment / --expect-owner / --expect-versions appended after a stale one was silently
// ignored and the stale value authorised the run. Every option is now known, given at most once, and a
// value option must have a value.
const VALUE_FLAGS = new Set([
  "--export-pop",
  "--export-fraud-drill",
  "--verifier",
  "--deployment",
  "--expect-owner",
  "--env",
  "--nodes",
  "--expect-versions",
  "--chain-id",
  "--plan",
  "--sp-aggregator-source",
  "--sp-commit",
]);
const BOOL_FLAGS = new Set();
// --broadcast IS DISABLED (Daybreak on 63a484d0, High; DSR 2026-11-18). Its only check that the RPC is
// the real chain was chainId, which a Sepolia fork shares, so a live key could sign a valid Sepolia
// transaction for a fork (and that transaction could be replayed on Sepolia). On rc.8 the SAFE sends,
// so this script has no signing path at all: it is refused here, before any file, env var or RPC is
// read. Restoring it needs a two-provider finalized-block comparison first (docs/rc8-deploy-day-dvt.md,
// "Follow-ups").
const DISABLED_FLAGS = {
  "--broadcast":
    "--broadcast is disabled in rc.8: this script sends no transaction and uses no EOA key.\n" +
    "  The owner (the SAFE) executes the calldata from --export-pop; see docs/rc8-deploy-day-dvt.md,\n" +
    '  "After the hand-off". Restoring --broadcast needs the two-provider check in "Follow-ups".',
};
const REMOVED_FLAGS = {
  "--aggregator":
    "pass --deployment <SP deploy output JSON> or --plan <SP frozen plan>; addresses are never typed in",
  "--expect-version": "use --expect-versions BLSAggregator-<x>,DVTValidator-<y>",
  "--expect-dvt-version": "use --expect-versions BLSAggregator-<x>,DVTValidator-<y>",
};
const opts = new Map();
for (let i = 0; i < argv.length; i++) {
  const a = argv[i];
  const fail = m => {
    console.error(`\n✗ ${m}`);
    process.exit(1);
  };
  if (DISABLED_FLAGS[a]) fail(DISABLED_FLAGS[a]);
  if (REMOVED_FLAGS[a]) fail(`${a} was removed: ${REMOVED_FLAGS[a]}`);
  if (!VALUE_FLAGS.has(a) && !BOOL_FLAGS.has(a)) fail(`unknown argument ${JSON.stringify(a)}`);
  if (opts.has(a)) fail(`${a} given twice: give each option once`);
  if (BOOL_FLAGS.has(a)) {
    opts.set(a, true);
    continue;
  }
  const v = argv[i + 1];
  if (v === undefined || v.startsWith("--")) fail(`${a} needs a value`);
  opts.set(a, v);
  i++;
}
const flag = name => opts.get(name);
const EXPORT_FILE = flag("--export-pop");
const DRILL_FILE = flag("--export-fraud-drill");
const VERIFIER = flag("--verifier");
const DEPLOYMENT_FILE = flag("--deployment");
// The owner both contracts must have. Its value comes from SP's rc.8 owner table
// (SuperPaymaster docs/security/rc8-owner-table.md), never from this file (DSR 2026-11-17).
const EXPECT_OWNER = flag("--expect-owner");
const ENV_FILE = flag("--env") || process.env.DVT_ENV_FILE || ".env.sepolia";
const NODE_FILES = (flag("--nodes") ?? DEFAULT_NODES.join(",")).split(",").map(s => s.trim());
// Codex round 3, L6: `--nodes ,` used to become an empty list and a "successful" zero-registration run.
if (NODE_FILES.length === 0 || NODE_FILES.some(f => f === "")) {
  console.error("\n✗ --nodes needs a comma-separated list of node files with no empty entries");
  process.exit(1);
}
// The version() strings both contracts must return, e.g.
// "BLSAggregator-4.14.1,DVTValidator-0.8.1". Taken from the rc.8 tag's tree, never written here.
const EXPECT_VERSIONS_RAW = flag("--expect-versions");
// Defaults to Sepolia, overridable. NOT opt-in: a fork of Sepolia
// shares its bytecode, version() and owner(), and can even host a contract at the same CREATE
// address, so every other gate reads identically on both. The chain is the one thing only this
// check can tell you.
// Codex M4: a typo or 0 used to become NaN / 0, which is falsy, and the network gate was skipped.
const EXPECT_CHAIN_ID = Number(flag("--chain-id") ?? 11155111);
if (!Number.isSafeInteger(EXPECT_CHAIN_ID) || EXPECT_CHAIN_ID <= 0) {
  console.error(
    `\n✗ --chain-id must be a positive integer, got ${JSON.stringify(flag("--chain-id"))}`
  );
  process.exit(1);
}

/// Codex M5: print only scheme://host[:port]. Path tokens, query keys and user:pass never reach a log.
function redactRpc(url) {
  try {
    const u = new URL(url);
    return `${u.protocol}//${u.host}${u.pathname !== "/" || u.search ? "/<redacted>" : ""}`;
  } catch {
    return "<unparseable RPC url, withheld>";
  }
}
let RPC_FOR_SCRUB = null;
/// Every error text that reaches a log goes through here (Codex round 2, M1): provider errors can embed
/// the request URL. No EOA key is kept any more (--broadcast is disabled), so there is none to scrub.
function scrub(msg) {
  let text = String(msg);
  if (RPC_FOR_SCRUB) text = text.split(RPC_FOR_SCRUB).join(redactRpc(RPC_FOR_SCRUB));
  return text;
}
const die = msg => {
  console.error(`\n✗ ${scrub(msg)}`);
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

if (argv.includes("--export-pop") && (!EXPORT_FILE || EXPORT_FILE.startsWith("--"))) {
  die("--export-pop needs an output file path");
}
if (argv.includes("--export-fraud-drill") && (!DRILL_FILE || DRILL_FILE.startsWith("--"))) {
  die("--export-fraud-drill needs an output file path");
}
if (DRILL_FILE && EXPORT_FILE) die("use --export-pop or --export-fraud-drill, not both");
if (DRILL_FILE && !ethers.isAddress(VERIFIER ?? ""))
  die("--export-fraud-drill needs --verifier <address>");
if (
  argv.includes("--expect-owner") &&
  (!ethers.isAddress(EXPECT_OWNER ?? "") || ethers.getAddress(EXPECT_OWNER) === ethers.ZeroAddress)
) {
  // clestons #444 Low 3: the zero address passed isAddress
  die("--expect-owner needs a non-zero address (the owner from SP's rc.8 owner table)");
}
let EXPECT_VERSION = null;
let EXPECT_DVT_VERSION = null;
if (argv.includes("--expect-versions")) {
  const parts = (EXPECT_VERSIONS_RAW ?? "")
    .split(",")
    .map(v => v.trim())
    .filter(Boolean);
  EXPECT_VERSION = parts.find(v => v.startsWith("BLSAggregator-")) ?? null;
  EXPECT_DVT_VERSION = parts.find(v => v.startsWith("DVTValidator-")) ?? null;
  if (parts.length !== 2 || !EXPECT_VERSION || !EXPECT_DVT_VERSION) {
    die("--expect-versions needs exactly BLSAggregator-<x>,DVTValidator-<y>");
  }
}
// --plan: SP's frozen plan JSON from BEFORE the contracts exist (rc.8: PoPs are generated between
// SP's pin and the send; the addresses are SP's precomputed ones). Export-only; see exportFromPlan.
const PLAN_FILE = flag("--plan");
const SP_SOURCE = flag("--sp-aggregator-source");
const SP_COMMIT = flag("--sp-commit");
if (PLAN_FILE !== undefined) {
  if (!PLAN_FILE || PLAN_FILE.startsWith("--")) die("--plan needs SP's frozen plan JSON");
  if (!EXPORT_FILE) die("--plan only exports: add --export-pop <file>");
  if (DEPLOYMENT_FILE) die("use --plan (before deployment) or --deployment (after), not both");
  if (EXPECT_VERSION || EXPECT_OWNER) {
    die(
      "--expect-versions / --expect-owner cannot be checked before the contracts exist; SP's A10 asserts them"
    );
  }
  if (!SP_SOURCE || SP_SOURCE.startsWith("--")) {
    die(
      "--plan needs --sp-aggregator-source <BLSAggregator.sol from the SP commit being deployed>"
    );
  }
  if (!/^[0-9a-f]{40}$/.test(SP_COMMIT ?? ""))
    die("--plan needs --sp-commit <40-hex SP commit of that source>");
}
if (!PLAN_FILE && EXPORT_FILE && !EXPECT_VERSION) {
  die("--export-pop needs --expect-versions BLSAggregator-<x>,DVTValidator-<y>");
}
if (!PLAN_FILE && EXPORT_FILE && !EXPECT_OWNER) {
  die("--export-pop needs --expect-owner <owner from SP's rc.8 owner table>");
}
if (!PLAN_FILE && (!DEPLOYMENT_FILE || DEPLOYMENT_FILE.startsWith("--"))) {
  die(
    "missing --deployment <file> (SP's deploy output JSON naming dvtValidator and blsAggregator),\n" +
      "  or --plan <SP frozen plan JSON> before the contracts are deployed"
  );
}
const SOURCE_FILE = PLAN_FILE || DEPLOYMENT_FILE;
let deployment;
try {
  deployment = JSON.parse(readFileSync(SOURCE_FILE, "utf8"));
} catch (e) {
  die(`cannot read ${PLAN_FILE ? "--plan" : "--deployment"} ${SOURCE_FILE}: ${e.message}`);
}
const addressAt = (obj, path) => {
  const v = path.split(".").reduce((o, k) => o?.[k], obj);
  if (typeof v !== "string" || !ethers.isAddress(v) || v === ethers.ZeroAddress) {
    die(`${SOURCE_FILE}: "${path}" is missing or not a non-zero address`);
  }
  return v;
};
// Plan keys follow SP's manifest (manifest_exec.py plan['addresses'], sp_upgrade_exec.py PIN_KEYS).
const DVT = ethers.getAddress(
  addressAt(deployment, PLAN_FILE ? "addresses.DVTValidator" : "dvtValidator")
);
const AGGREGATOR = ethers.getAddress(
  addressAt(deployment, PLAN_FILE ? "addresses.BLSAggregator" : "blsAggregator")
);
const DEPLOYMENT_REGISTRY =
  PLAN_FILE || deployment?.registry === undefined
    ? null
    : ethers.getAddress(addressAt(deployment, "registry"));

const strip = s => s.replace(/^["']|["']$/g, "");
// Only the three RPC names are kept; every other line (the Sepolia env files also hold deployer keys)
// is dropped as it is split, never parsed into a value (Daybreak on 63a484d0, Low). The file is still
// read whole, so its text is in memory while it is split (Codex: "reads no key" is not literally
// true); nothing else from it is kept or printed. An RPC-only env file avoids even that.
const RPC_NAMES = new Set(["SEPOLIA_RPC_URL", "ETH_RPC_URL", "RPC_URL"]);
let env;
try {
  env = Object.fromEntries(
    readFileSync(ENV_FILE, "utf8")
      .split("\n")
      .map(l => [l.slice(0, l.indexOf("=")).trim(), l])
      .filter(([k, l]) => l.includes("=") && !l.trim().startsWith("#") && RPC_NAMES.has(k))
      .map(([k, l]) => [k, strip(l.slice(l.indexOf("=") + 1).trim())])
  );
} catch (e) {
  die(
    `cannot read env file ${ENV_FILE}: ${e.message}\n  Sepolia credentials live in SuperPaymaster/.env.sepolia — pass --env <path>.`
  );
}

// THE ENV FILE WINS over ambient process.env. This is deliberate and was learned the hard way: an
// exported SEPOLIA_RPC_URL left over in the shell silently overrode an explicitly-passed --env that
// pointed at a local fork, so the script connected to REAL Sepolia while the operator believed it was
// on the fork. It got worse: the fork deployment had landed on the same CREATE address as a real
// deployment from the same account/nonce, so the address looked right too. Only the version() gate
// caught it. `--env <path>` is an explicit instruction; ambient variables are the fallback, never the
// override — the export decides what the SAFE signs, so the quiet direction must be the safe one.
const RPC = env.SEPOLIA_RPC_URL || env.ETH_RPC_URL || env.RPC_URL || process.env.SEPOLIA_RPC_URL;
if (!RPC) die(`no RPC url in ${ENV_FILE} (SEPOLIA_RPC_URL / ETH_RPC_URL / RPC_URL)`);
RPC_FOR_SCRUB = RPC;
if (process.env.SEPOLIA_RPC_URL && process.env.SEPOLIA_RPC_URL !== RPC) {
  console.warn(
    `! ignoring ambient SEPOLIA_RPC_URL; ${ENV_FILE} wins (see the note above this check)`
  );
}

const ABI = [
  "function version() view returns (string)",
  "function owner() view returns (address)",
  "function domainSeparator() view returns (bytes32)",
  "function TAG_POP() view returns (bytes32)",
  "function DOMAIN_NAME() view returns (bytes32)",
  "function REGISTRY() view returns (address)",
  "function fraudProofVerifier() view returns (address)",
  "function MAX_VALIDATORS() view returns (uint256)",
  "function validatorAtSlot(uint8) view returns (address)",
  "function blsKeyOwner(bytes32) view returns (address)",
  "function getBLSPublicKey(address) view returns ((bytes32,bytes32,bytes32,bytes32) publicKey, uint8 slot, bool active)",
  "function DVT_VALIDATOR() view returns (address)",
  "function permissionlessBLSRegistration() view returns (bool)",
  "function suspended(address) view returns (bool)",
  "function guardianExitRequests(address) view returns (uint64 readyAt, uint64 expiresAt)",
  "function fraudProofDigest(uint256 fraudProofId, address[] guiltyGuardians) view returns (bytes32)",
  "function popDigest(address validator, (bytes32,bytes32,bytes32,bytes32) publicKey) view returns (bytes32)",
];

// SP main b5e7544e abis/DVTValidator.json. The aggregator's own registerBLSPublicKey is gone from
// this script on purpose: on 4.14.0 it reverts for any caller but the DVTValidator.
const DVT_ABI = [
  "function version() pure returns (string)",
  "function owner() view returns (address)",
  "function BLS_AGGREGATOR() view returns (address)",
  "function REGISTRY() view returns (address)",
  "function registerBLSPublicKey(address validator, (bytes32,bytes32,bytes32,bytes32) key, uint8 slot, (bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32) pop)",
];
// SP f2b2cd9b abis/Registry.json and abis/GTokenStaking.json: the reads _reconstructPkAgg makes.
const REGISTRY_ABI = [
  "function blsAggregator() view returns (address)",
  "function GTOKEN_STAKING() view returns (address)",
  "function hasRole(bytes32, address) view returns (bool)",
  "function getRoleConfig(bytes32) view returns ((uint256 minStake, uint256 ticketPrice, uint32 slashThreshold, uint32 slashBase, uint32 slashInc, uint32 slashMax, uint16 exitFeePercent, bool isActive, uint256 minExitFee, string description, address owner, uint256 roleLockDuration))",
];
const STAKING_ABI = [
  "function roleLocks(address, bytes32) view returns (uint128 amount, uint128 ticketPrice, uint48 lockedAt, bytes32 roleId, bytes metadata)",
];

/// Split a 0x-prefixed byte string into 32-byte words. EIP-2537 G1 is 128 bytes (4 words) and G2 is
/// 256 bytes (8 words); those map 1:1 onto SP's BLS.G1Point / BLS.G2Point structs.
function toWords(hex, expectedBytes) {
  const b = ethers.getBytes(hex);
  if (b.length !== expectedBytes)
    throw new Error(`expected ${expectedBytes} bytes, got ${b.length}`);
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

const DRILL_ABI = [
  "function AGGREGATOR() view returns (address)",
  "function REGISTRY() view returns (address)",
  "function domainSeparator() view returns (bytes32)",
  "function deriveFraudProofId(uint256) pure returns (uint256)",
  "function slashMessageHash(uint256,address,uint8,uint256,address) view returns (bytes32)",
];
// Ascending by uint160, as the verifier requires. Slots 2, 1 and 3 in that order.
const DRILL_GUARDIANS = [
  "0x40F0b12128f256B62Fa22b36D37012Ee004bbd1f",
  "0x5D870E132CC010E882E90f4aFaACDC4F19C7Eca3",
  "0xD904A706E355D6b48bAeDBec472CE94BC6981601",
];
const DRILL_SLASH_LEVEL = 1;
const DRILL_EPOCH = 1n;
const DRILL_MASK = 0x7n;

/// Everything is derived from the aggregator address, so a re-run gives the same file and the ID
/// cannot coincide with a real proposal by accident.
async function exportFraudDrill({ provider, agg, owner, version, chainId, domainSep, coder }) {
  const label = s =>
    ethers.keccak256(ethers.toUtf8Bytes(`DVT_FRAUD_DRILL_V1:${s}:${AGGREGATOR.toLowerCase()}`));
  const proposalId = BigInt(label("proposal"));
  const operator = ethers.getAddress(ethers.dataSlice(label("operator"), 12));
  const token = ethers.getAddress(ethers.dataSlice(label("token"), 12));

  const verifier = new ethers.Contract(VERIFIER, DRILL_ABI, provider);
  if ((await provider.getCode(VERIFIER)) === "0x") die(`no code at verifier ${VERIFIER}`);
  let boundAggregator, boundRegistry, verifierDomain, registry, activeVerifier;
  try {
    [boundAggregator, boundRegistry, verifierDomain, registry, activeVerifier] = await Promise.all([
      verifier.AGGREGATOR(),
      verifier.REGISTRY(),
      verifier.domainSeparator(),
      agg.REGISTRY(),
      agg.fraudProofVerifier(),
    ]);
  } catch (e) {
    die(
      `${VERIFIER} does not answer as an OverIssueFraudProofVerifier: ${e.shortMessage ?? e.message}`
    );
  }
  // queueGuardianSlash calls the aggregator's active verifier, so a drill built for any other one
  // would fail on the fork for a reason that says nothing about the proof.
  if (activeVerifier.toLowerCase() !== VERIFIER.toLowerCase()) {
    die(`aggregator.fraudProofVerifier() is ${activeVerifier}, expected ${VERIFIER}`);
  }
  if (boundAggregator.toLowerCase() !== AGGREGATOR.toLowerCase()) {
    die(`verifier.AGGREGATOR() is ${boundAggregator}, expected ${AGGREGATOR}`);
  }
  if (boundRegistry.toLowerCase() !== registry.toLowerCase()) {
    die(`verifier.REGISTRY() is ${boundRegistry}, aggregator.REGISTRY() is ${registry}`);
  }
  if (verifierDomain.toLowerCase() !== domainSep.toLowerCase())
    die("verifier and aggregator domain separators differ");
  if ((await provider.getCode(token)) !== "0x")
    die(`drill token address ${token} already has code on this chain`);

  const artifactPath = resolve(
    dirname(fileURLToPath(import.meta.url)),
    "../contracts/out/MockOverIssuableToken.sol/MockOverIssuableToken.json"
  );
  let tokenRuntime;
  try {
    tokenRuntime = JSON.parse(readFileSync(artifactPath, "utf8")).deployedBytecode.object;
  } catch (e) {
    die(`cannot read ${artifactPath}: ${e.message}\n  Run forge build in contracts/ first.`);
  }

  const fraudProofId = await verifier.deriveFraudProofId(proposalId);
  const messageHash = await verifier.slashMessageHash(
    proposalId,
    operator,
    DRILL_SLASH_LEVEL,
    DRILL_EPOCH,
    token
  );
  const commitment = ethers.keccak256(
    coder.encode(
      ["bytes32", "bytes32", "uint256", "bytes32", "uint256", "address[]"],
      [
        domainSep,
        ethers.id("SuperPaymaster.BLS.SignersCommitment.v1"),
        proposalId,
        messageHash,
        DRILL_MASK,
        DRILL_GUARDIANS,
      ]
    )
  );
  const encodeProof = mask =>
    coder.encode(
      ["uint256", "address", "uint8", "uint256", "address", "uint256", "address[]"],
      [proposalId, operator, DRILL_SLASH_LEVEL, DRILL_EPOCH, token, mask, DRILL_GUARDIANS]
    );
  const proof = encodeProof(DRILL_MASK);
  const digest = await agg.fraudProofDigest(fraudProofId, DRILL_GUARDIANS);
  const flipped = ethers.getBytes(digest);
  flipped[31] ^= 1;

  const drill = {
    purpose: "fork rehearsal only; contains no signature",
    chainId,
    aggregator: AGGREGATOR,
    version,
    owner,
    verifier: VERIFIER,
    registry,
    domainSeparator: domainSep,
    block: await provider.getBlockNumber(),
    forkState: {
      token: { address: token, runtimeBytecode: tokenRuntime, overIssuedStorageSlot: 0 },
      commitment: {
        mapping: "proposalSignersCommitment",
        key: proposalId.toString(),
        value: commitment,
        check: "proposalSignersCommitment(key) must read back as value, otherwise stop",
      },
    },
    valid: {
      call: "queueGuardianSlash(fraudProofId, guiltyGuardians, fraudProof)",
      expect: "succeeds and emits GuardianSlashQueued",
      proposalId: proposalId.toString(),
      fraudProofId: fraudProofId.toString(),
      guiltyGuardians: DRILL_GUARDIANS,
      fraudProof: proof,
      domainDigest: digest,
      signerMask: ethers.toBeHex(DRILL_MASK),
      operator,
      slashLevel: DRILL_SLASH_LEVEL,
      epoch: DRILL_EPOCH.toString(),
    },
    mustReject: [
      {
        id: "N1",
        change: "one guardian removed",
        guiltyGuardians: DRILL_GUARDIANS.slice(0, -1),
        fraudProof: proof,
        expect: "queueGuardianSlash reverts InvalidFraudProof",
      },
      {
        id: "N2",
        change: "set token storage slot 0 to 1 (over-issued), same proof",
        guiltyGuardians: DRILL_GUARDIANS,
        fraudProof: proof,
        expect: "queueGuardianSlash reverts InvalidFraudProof",
      },
      {
        id: "N3",
        change: "signerMask in the proof differs by one bit",
        guiltyGuardians: DRILL_GUARDIANS,
        fraudProof: encodeProof(DRILL_MASK ^ 1n),
        expect: "queueGuardianSlash reverts InvalidFraudProof",
      },
      {
        id: "N4",
        change:
          "digest differs by one bit; call the verifier directly because the aggregator computes its own digest",
        call: "verifier.verify(domainDigest, fraudProofId, guiltyGuardians, fraudProof)",
        domainDigest: ethers.hexlify(flipped),
        guiltyGuardians: DRILL_GUARDIANS,
        fraudProof: proof,
        expect: "returns false",
      },
    ],
  };
  writeFileSync(DRILL_FILE, JSON.stringify(drill, null, 2) + "\n");
  console.log(`Wrote ${DRILL_FILE}. Nothing was sent and nothing was signed.`);
}

/// Extract `NAME = keccak256("…")` from SP's BLSAggregator source, so the PoP domain constants are
/// read from SP's file rather than copied into this one (DSR 2026-11-17).
function spConstant(source, name) {
  const m = [
    ...source.matchAll(new RegExp(`\\b${name}\\s*=\\s*keccak256\\(\\s*"([^"]+)"\\s*\\)`, "g")),
  ];
  if (m.length !== 1)
    die(`${SP_SOURCE}: expected exactly one ${name} = keccak256("…"), found ${m.length}`);
  return { preimage: m[0][1], value: ethers.id(m[0][1]) };
}

/// Export the rc.8 A10 PoP input BEFORE the contracts exist. Nothing on the new addresses can be read,
/// so this mode computes the domain and digests locally and makes only consistency checks; the
/// on-chain checks (versions, wiring, owner, popDigest() equality) are SP's A10 assertions at send time.
async function exportFromPlan({ provider, chainId }) {
  const pin = deployment.pin;
  if (!pin || typeof pin !== "object") die(`${PLAN_FILE}: no "pin" object`);
  const deployer = addressAt(deployment, "pin.senders.deployer.address");
  const pinNonce = pin.senders.deployer.nonce;
  if (!Number.isInteger(pinNonce) || pinNonce < 0)
    die(`${PLAN_FILE}: pin.senders.deployer.nonce is not an integer`);
  if (!Number.isInteger(pin.block) || pin.block < 0)
    die(`${PLAN_FILE}: pin.block is not an integer`);
  if (!/^0x[0-9a-fA-F]{64}$/.test(pin.blockHash ?? ""))
    die(`${PLAN_FILE}: pin.blockHash is not a 32-byte hash`);
  const oldAggregator = addressAt(deployment, "pin.oldAggregator");

  let source;
  try {
    source = readFileSync(SP_SOURCE, "utf8");
  } catch (e) {
    die(`cannot read --sp-aggregator-source ${SP_SOURCE}: ${e.message}`);
  }
  const DOMAIN = spConstant(source, "DOMAIN_NAME");
  const POP_TAG = spConstant(source, "TAG_POP");
  const sourceSha256 = createHash("sha256").update(source).digest("hex");
  // The release this source is (DSR 2026-11-18): version() cannot be read before the deploy, so the
  // export records the string the source returns. SP is to make its adapter require it to equal
  // its RELEASE_VERSIONS aggregator entry, and reject an export without it (not yet on SP main).
  const sourceVersion = aggregatorSourceVersion(source);
  if (!sourceVersion) {
    die(
      `--sp-aggregator-source ${SP_SOURCE}: cannot read the release BLSAggregator's version() returns.\n` +
        `  It needs exactly one contract BLSAggregator with exactly one version() whose header is\n` +
        `  "() [external|public|pure|view|virtual|override(...)]* returns (string memory)" and whose body\n` +
        `  is exactly one 'return "BLSAggregator-x.y.z";' (comments are ignored; a bare CR is refused).`
    );
  }
  console.log(`version    : ${sourceVersion} (from the source)`);
  console.log(`SP source  : ${SP_SOURCE} (sha256 ${sourceSha256}, commit ${SP_COMMIT})`);
  console.log(`DOMAIN_NAME: keccak256("${DOMAIN.preimage}")`);
  console.log(`TAG_POP    : keccak256("${POP_TAG.preimage}")`);

  // ---- plan gate 1: the precomputed addresses are still empty ---------------------------------
  for (const [name, addr] of [
    ["DVTValidator", DVT],
    ["aggregator", AGGREGATOR],
  ]) {
    if ((await provider.getCode(addr)) !== "0x") {
      die(`${name} ${addr} already has code: this is not a pre-deployment plan; use --deployment`);
    }
  }
  // ---- plan gate 2: the pin block is this chain's block ---------------------------------------
  const block = await provider.getBlock(pin.block);
  if (!block || block.hash.toLowerCase() !== pin.blockHash.toLowerCase()) {
    die(
      `pin block ${pin.block} hash is ${block?.hash ?? "<missing>"} on this chain, plan says ${pin.blockHash}`
    );
  }
  // ---- plan gate 3: the deployer has not moved since the pin -----------------------------------
  // The precomputed addresses depend on the deployer nonce. If it moved, every address is void, SP's
  // manifest stops, and SP must pin again and these PoPs must be generated again.
  const [latestNonce, pendingNonce] = await Promise.all([
    provider.getTransactionCount(deployer, "latest"),
    provider.getTransactionCount(deployer, "pending"),
  ]);
  if (latestNonce !== pinNonce || pendingNonce !== pinNonce) {
    die(
      `deployer ${deployer} nonce is ${latestNonce} (pending ${pendingNonce}), the pin says ${pinNonce}.\n` +
        `  The precomputed addresses are void. SP must pin again; then re-run this export.`
    );
  }
  // ---- plan gate 4: the Registry the new aggregator will bind its domain to -------------------
  const registry = await new ethers.Contract(oldAggregator, ABI, provider).REGISTRY();
  if ((await provider.getCode(registry)) === "0x")
    die(`Registry ${registry} (from the old aggregator) has no code`);
  console.log(
    `deployer   : ${deployer} nonce ${pinNonce} (unchanged since pin block ${pin.block})`
  );
  console.log(`registry   : ${registry} (old aggregator ${oldAggregator}.REGISTRY())`);

  const coder = ethers.AbiCoder.defaultAbiCoder();
  const domainSep = ethers.keccak256(
    coder.encode(
      ["bytes32", "uint256", "address", "address"],
      [DOMAIN.value, chainId, AGGREGATOR, registry]
    )
  );
  console.log(`domainSep  : ${domainSep} (computed locally)\n`);
  const dvtIface = new ethers.Interface(DVT_ABI);

  const entries = [];
  const digests = [];
  const seen = { slot: new Map(), validator: new Map(), key: new Map() };
  for (const file of NODE_FILES) {
    let node;
    try {
      node = JSON.parse(readFileSync(file, "utf8"));
    } catch (e) {
      // Never the exception text: a JSON parse error can quote the file, and the file holds a BLS
      // secret that scrub() does not know (Codex round 3, M1).
      die(
        `cannot read node file ${file}: ${e.code === "ENOENT" ? "no such file" : "unreadable or not valid JSON"} (details withheld)`
      );
    }
    const label = `${file} (${nodeNameShape(node.nodeName)})`;
    const validator = node.operator;
    const slot = Number(node.slot);
    if (!validator || !ethers.isAddress(validator))
      die(`${label}: missing/invalid "operator" address`);
    // SP's manifest accepts slots 1..13 (manifest_exec.py pop_slot_range).
    if (!Number.isInteger(slot) || slot < 1 || slot > 13)
      die(`${label}: slot ${fieldShape(node.slot)} out of range 1..13`);
    if (!node.publicKeyEip2537 || !node.privateKey)
      die(`${label}: needs "publicKeyEip2537" and "privateKey"`);
    let sk;
    try {
      sk = ethers.getBytes(node.privateKey);
    } catch {
      die(
        `${label}: "privateKey" is not a valid hex byte string (value withheld) — fix the node file`
      );
    }
    const pkPoint = bls.longSignatures.getPublicKey(sk);
    if (encodeG1(pkPoint).toLowerCase() !== node.publicKeyEip2537.toLowerCase()) {
      die(`${label}: the private key does not match publicKeyEip2537 in the same file`);
    }
    const pkWords = toWords(node.publicKeyEip2537, 128);
    const keyHash = ethers.keccak256(
      coder.encode(["bytes32", "bytes32", "bytes32", "bytes32"], pkWords)
    );
    for (const [m, k, what] of [
      [seen.slot, slot, `slot ${slot}`],
      [seen.validator, validator.toLowerCase(), `validator ${validator}`],
      [seen.key, keyHash, `BLS key ${keyHash}`],
    ]) {
      if (m.has(k)) die(`${m.get(k)} and ${label} both claim ${what}. Fix the --nodes list.`);
      m.set(k, label);
    }
    const digest = ethers.keccak256(
      coder.encode(
        ["bytes32", "bytes32", "address", "bytes32", "bytes32", "bytes32", "bytes32"],
        [domainSep, POP_TAG.value, validator, ...pkWords]
      )
    );
    const msgPoint = await bls.G2.hashToCurve(ethers.getBytes(digest), { DST: POP_DST });
    const sigPoint = bls.longSignatures.sign(msgPoint, sk);
    if (!bls.longSignatures.verify(sigPoint, msgPoint, pkPoint)) {
      die(`${label}: locally produced PoP fails its own pairing check — refusing to export`);
    }
    const popWords = toWords(encodeG2(sigPoint), 256);
    const calldata = dvtIface.encodeFunctionData("registerBLSPublicKey", [
      validator,
      pkWords,
      slot,
      popWords,
    ]);
    // Exactly SP's six pop keys (manifest_exec.py exact_keys 'pop_fields'); nothing else per entry.
    entries.push({
      validator: validator.toLowerCase(),
      slot,
      calldata,
      aggregator: deployment.addresses.BLSAggregator,
      pinBlockHash: pin.blockHash,
      domainSeparator: domainSep,
    });
    digests.push(digest);
    console.log(`✓ ${label}  validator ${validator}  slot ${slot}  popDigest ${digest}`);
  }
  if (entries.length !== 3)
    die(`SP's manifest takes exactly 3 PoPs (pop_count); got ${entries.length}`);

  const out = {
    pop: entries,
    // Outside popContext, whose keys are SP's (DSR 2026-11-18). Next to spAggregatorSourceSha256.
    aggregatorSourceVersion: sourceVersion,
    // Exactly SP's popContext keys (DSR/SP 2026-11-17); A10 asserts each, popDigests in pop order.
    // The calldata's target is popContext.dvt: the 4.14.0 aggregator rejects any other caller.
    popContext: {
      dvt: DVT,
      aggregator: AGGREGATOR,
      registry,
      chainId,
      deployerAddress: deployer,
      deployerNonce: pinNonce,
      pinBlock: pin.block,
      pinBlockHash: pin.blockHash,
      spCommit: SP_COMMIT,
      spAggregatorSourceSha256: sourceSha256,
      popDigests: digests,
    },
  };
  writeFileSync(EXPORT_FILE, JSON.stringify(out, null, 2) + "\n");
  console.log(`\nWrote ${EXPORT_FILE}. Nothing was sent. Hand it to SP as the A10 pop input.`);
}

async function main() {
  const provider = new ethers.JsonRpcProvider(RPC);
  // No wallet exists in this script (--broadcast is disabled): every contract is read-only.
  const agg = new ethers.Contract(AGGREGATOR, ABI, provider);
  const dvt = new ethers.Contract(DVT, DVT_ABI, provider);

  // Print the network before anything else. The address alone is NOT enough to tell you which chain
  // you are on: a CREATE from the same account at the same nonce lands on the same address on every
  // chain, so a fork and its parent can host different contracts at one address.
  const net = await provider.getNetwork();
  const chainId = Number(net.chainId);
  console.log(`rpc        : ${redactRpc(RPC)}`);
  console.log(`chainId    : ${chainId} (expected ${EXPECT_CHAIN_ID})`);
  console.log(`block      : ${await provider.getBlockNumber()}`);
  console.log(`${PLAN_FILE ? "plan      " : "deployment"} : ${SOURCE_FILE}`);
  console.log(`dvt        : ${DVT}`);
  console.log(`aggregator : ${AGGREGATOR}`);
  console.log(`signer     : none (this script never signs or sends)`);
  console.log(`env file   : ${ENV_FILE}`);
  const mode = DRILL_FILE
    ? `export fraud drill to ${DRILL_FILE}`
    : EXPORT_FILE
      ? `export PoP data to ${EXPORT_FILE}`
      : "dry-run (pass --export-pop <file> to write the owner's calldata)";
  console.log(`mode       : ${mode}\n`);
  if (chainId !== EXPECT_CHAIN_ID) {
    die(`wrong network: connected to chainId ${chainId}, expected ${EXPECT_CHAIN_ID}`);
  }
  if (PLAN_FILE) {
    await exportFromPlan({ provider, chainId });
    return;
  }

  // EVERY READ OF THE REGISTRATION PATH (dry run and --export-pop) IS AT ONE BLOCK (Daybreak on
  // 63a484d0, M3; DSR 2026-11-18). The gates then describe one state, and the export records that
  // block's number and hash plus the reads the gates relied on, so the SAFE signers can re-run the
  // export just before executing and compare. --export-fraud-drill, already stale against 4.14.0
  // (#441), is NOT covered: its own reads after gate 5 use the latest block (Codex, Low).
  const basis = await provider.getBlock("latest");
  if (!basis || basis.hash == null) die("cannot read the latest block to pin the reads to");
  const AT = { blockTag: basis.number };
  console.log(`reads at   : block ${basis.number} ${basis.hash}`);

  // ---- gate 2: both contracts are the releases we expect -------------------------------------
  const codeHash = {};
  for (const [name, addr] of [
    ["DVTValidator", DVT],
    ["aggregator", AGGREGATOR],
  ]) {
    const code = await provider.getCode(addr, AT.blockTag);
    if (code === "0x") die(`no code at ${name} ${addr} on this chain`);
    codeHash[name] = ethers.keccak256(code);
  }
  const versionGate = async (name, contract, expected, override) => {
    let v;
    try {
      v = await contract.version(AT);
    } catch (e) {
      die(`${name} does not answer version() (${e.shortMessage ?? e.message})`);
    }
    console.log(`${name.padEnd(11)}: ${v}`);
    if (expected === null) {
      console.log(`! --expect-versions not given: ${name} version() was NOT checked`);
    } else if (v !== expected) {
      die(
        `${name} version mismatch: on-chain "${v}" != expected "${expected}" (--expect-versions).\n` +
          `  Take the expectation from the rc.8 tag's tree, and re-check that the release keeps the\n` +
          `  same registration path, PoP domain (address-bound popDigest) and owner-path slot semantics.`
      );
    }
    return v;
  };
  const version = await versionGate("aggregator", agg, EXPECT_VERSION);
  const dvtVersion = await versionGate("dvt", dvt, EXPECT_DVT_VERSION);

  // ---- gate 3: the pair is wired to each other and to the Registry ----------------------------
  const [dvtAgg, aggDvt, dvtRegistry, aggRegistry] = await Promise.all([
    dvt.BLS_AGGREGATOR(AT),
    agg.DVT_VALIDATOR(AT),
    dvt.REGISTRY(AT),
    agg.REGISTRY(AT),
  ]);
  const same = (a, b) => a.toLowerCase() === b.toLowerCase();
  if (!same(dvtAgg, AGGREGATOR))
    die(`DVTValidator.BLS_AGGREGATOR() is ${dvtAgg}, deployment says ${AGGREGATOR}`);
  if (!same(aggDvt, DVT)) die(`aggregator.DVT_VALIDATOR() is ${aggDvt}, deployment says ${DVT}`);
  if (!same(dvtRegistry, aggRegistry))
    die(`DVTValidator.REGISTRY() ${dvtRegistry} != aggregator.REGISTRY() ${aggRegistry}`);
  if (DEPLOYMENT_REGISTRY && !same(DEPLOYMENT_REGISTRY, aggRegistry)) {
    die(`aggregator.REGISTRY() is ${aggRegistry}, deployment says ${DEPLOYMENT_REGISTRY}`);
  }
  let registryAgg;
  try {
    registryAgg = await new ethers.Contract(aggRegistry, REGISTRY_ABI, provider).blsAggregator(AT);
  } catch (e) {
    die(`Registry ${aggRegistry} does not answer blsAggregator() (${e.shortMessage ?? e.message})`);
  }
  if (!same(registryAgg, AGGREGATOR)) {
    die(
      `Registry.blsAggregator() is ${registryAgg}, not this aggregator ${AGGREGATOR}.\n` +
        `  Keys registered here would sit on an aggregator the Registry does not use.`
    );
  }
  console.log(`registry   : ${aggRegistry} (blsAggregator() matches)`);
  // ---- gate 4: one shared owner (see AUTHORIZATION) --------------------------------------------
  const [dvtOwner, aggOwner, permissionless] = await Promise.all([
    dvt.owner(AT),
    agg.owner(AT),
    agg.permissionlessBLSRegistration(AT),
  ]);
  console.log(`dvt owner  : ${dvtOwner}`);
  console.log(`agg owner  : ${aggOwner}`);
  console.log(`permissionlessBLSRegistration: ${permissionless}`);
  if (!same(dvtOwner, aggOwner)) {
    die(
      `DVTValidator.owner() ${dvtOwner} != aggregator.owner() ${aggOwner}.\n` +
        `  The owner path needs one shared owner; stop and ask SP which one is wrong.`
    );
  }
  const owner = aggOwner;
  if (EXPECT_OWNER && !same(owner, EXPECT_OWNER)) {
    die(`shared owner is ${owner}, SP's owner table (--expect-owner) says ${EXPECT_OWNER}`);
  }
  if (!EXPECT_OWNER)
    console.log("! --expect-owner not given: the owner was NOT checked against SP's owner table");

  // Read the PoP domain members explicitly rather than in a bare Promise.all: if --expect-versions
  // names a release that predates them, a raw ethers decode stack is useless to an operator.
  const read = async (name, call) => {
    try {
      return await call();
    } catch (e) {
      die(
        `${AGGREGATOR} does not answer ${name} (${e.shortMessage ?? e.message}).\n` +
          `  Releases before BLSAggregator-4.11.0 lack the PoP-domain surface this script needs.\n` +
          `  If --expect-versions let this release through, that expectation was wrong: it cannot\n` +
          `  produce the address-bound popDigest these registrations must sign.`
      );
    }
  };
  const domainSep = await read("domainSeparator()", () => agg.domainSeparator(AT));
  const tagPop = await read("TAG_POP()", () => agg.TAG_POP(AT));
  const maxValidators = await read("MAX_VALIDATORS()", () => agg.MAX_VALIDATORS(AT));
  const domainName = await read("DOMAIN_NAME()", () => agg.DOMAIN_NAME(AT));
  const registryAddr = await read("REGISTRY()", () => agg.REGISTRY(AT));

  // Recompute the domain from its four inputs. This proves two things a bare read cannot: that the
  // PoP domain really is bound to THIS aggregator address (so a PoP cannot be lifted from the old
  // contract), and that this script's understanding of the domain layout still matches SP's.
  // ---- gate 5: the PoP domain is bound to THIS aggregator -------------------------------------
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
  if (DRILL_FILE) {
    await exportFraudDrill({ provider, agg, owner, version, chainId, domainSep, coder });
    return;
  }
  // Eligibility reads, the same as SP's _reconstructPkAgg: ROLE_DVT = keccak256("DVT"), the lock in
  // GTokenStaking.roleLocks, minStake from Registry.getRoleConfig, and the guardian exit notice.
  const ROLE_DVT = ethers.id("DVT");
  const readElig = async (name, call) => {
    try {
      return await call();
    } catch (e) {
      die(
        `${name} failed (${e.shortMessage ?? e.message}): the guardian's eligibility cannot be established, so nothing is exported`
      );
    }
  };
  const registry = new ethers.Contract(registryAddr, REGISTRY_ABI, provider);
  const stakingAddr = await readElig("Registry.GTOKEN_STAKING()", () =>
    registry.GTOKEN_STAKING(AT)
  );
  if (stakingAddr === ethers.ZeroAddress)
    die("Registry.GTOKEN_STAKING() is zero — SP reverts StakingNotConfigured");
  const staking = new ethers.Contract(stakingAddr, STAKING_ABI, provider);
  const minStake = (
    await readElig("Registry.getRoleConfig(ROLE_DVT)", () => registry.getRoleConfig(ROLE_DVT, AT))
  ).minStake;
  const eligibility = async v => ({
    hasRole: await readElig(`Registry.hasRole(ROLE_DVT, ${v})`, () =>
      registry.hasRole(ROLE_DVT, v, AT)
    ),
    locked: (await readElig(`roleLocks(${v}, ROLE_DVT)`, () => staking.roleLocks(v, ROLE_DVT, AT)))
      .amount,
    exitReadyAt: (
      await readElig(`guardianExitRequests(${v})`, () => agg.guardianExitRequests(v, AT))
    ).readyAt,
    minStake,
  });
  const plans = [];

  for (const file of NODE_FILES) {
    let node;
    try {
      node = JSON.parse(readFileSync(file, "utf8"));
    } catch (e) {
      // Never the exception text: a JSON parse error can quote the file, and the file holds a BLS
      // secret that scrub() does not know (Codex round 3, M1).
      die(
        `cannot read node file ${file}: ${e.code === "ENOENT" ? "no such file" : "unreadable or not valid JSON"} (details withheld)`
      );
    }
    const label = `${file} (${nodeNameShape(node.nodeName)})`;
    const validator = node.operator;
    const slot = Number(node.slot);
    if (!validator || !ethers.isAddress(validator))
      die(`${label}: missing/invalid "operator" address`);
    if (!Number.isInteger(slot) || slot < 1 || slot > Number(maxValidators)) {
      die(`${label}: slot ${fieldShape(node.slot)} out of range 1..${maxValidators}`);
    }
    if (!node.publicKeyEip2537) die(`${label}: missing "publicKeyEip2537"`);
    if (!node.privateKey) die(`${label}: missing "privateKey"`);

    // ---- gate 6: this private key really owns this public key ----------------------------------
    // Parse inside a try so a corrupt key is never echoed: ethers puts the offending value straight
    // into the message, and that would sit in terminal scrollback. Only a BROKEN key can throw here,
    // but naming the file is enough to fix it and leaks nothing.
    let sk;
    try {
      sk = ethers.getBytes(node.privateKey);
    } catch {
      die(
        `${label}: "privateKey" is not a valid hex byte string (value withheld) — fix the node file`
      );
    }
    const pkPoint = bls.longSignatures.getPublicKey(sk);
    const derived = encodeG1(pkPoint);
    if (derived.toLowerCase() !== node.publicKeyEip2537.toLowerCase()) {
      die(
        `${label}: the private key does not match publicKeyEip2537 in the same file.\n` +
          `  derived : ${keyEnds(derived)}\n` +
          `  in file : ${pubKeyShape(node.publicKeyEip2537)}\n` +
          `  Registering would bind a key nobody can sign with. Fix the node file first.`
      );
    }
    const pkWords = toWords(node.publicKeyEip2537, 128);

    // ---- gate 7: our understanding of popDigest must match the contract's ---------------------
    const onchainDigest = await read(`popDigest() for ${label}`, () =>
      agg.popDigest(validator, pkWords, AT)
    );
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

    // ---- gate 8: verify the pairing locally before paying for it on-chain ----------------------
    if (!bls.longSignatures.verify(sigPoint, msgPoint, pkPoint)) {
      die(`${label}: locally produced PoP fails its own pairing check — refusing to submit`);
    }
    const popWords = toWords(encodeG2(sigPoint), 256);

    // ---- gate 9: suspension, slot and key-ownership collisions ---------------------------------------------
    const keyHash = ethers.keccak256(
      coder.encode(["bytes32", "bytes32", "bytes32", "bytes32"], pkWords)
    );
    const [slotHolder, keyOwner, isSuspended, existing] = await Promise.all([
      agg.validatorAtSlot(slot, AT),
      agg.blsKeyOwner(keyHash, AT),
      agg.suspended(validator, AT),
      agg.getBLSPublicKey(validator, AT),
    ]);
    if (isSuspended) {
      die(`${label}: ${validator} is suspended on this aggregator — SP reverts ValidatorSuspended`);
    }
    if (existing.active && Number(existing.slot) !== slot) {
      die(
        `${label}: ${validator} already holds slot ${existing.slot}, node file says ${slot} — SP reverts SlotAlreadyTaken`
      );
    }
    // Daybreak on 63a484d0, M1: an ACTIVE validator re-registered with a different key passes every
    // check above (a new keyHash is a fresh blsKeyOwner binding, and the slot matches) and silently
    // rotates the live guardian's key. A stale or mistaken node file must stop here instead. The
    // message shows each key's first and last bytes only (DSR), enough to tell which side is stale.
    if (existing.active) {
      const onchainKey = ethers.concat([...existing.publicKey]).toLowerCase();
      const fileKey = ethers.concat(pkWords).toLowerCase();
      if (onchainKey !== fileKey) {
        die(
          `${label}: ${validator} is active in slot ${existing.slot} with a DIFFERENT BLS key.\n` +
            `  on-chain : ${keyEnds(onchainKey)}\n` +
            `  node file: ${keyEnds(fileKey)}\n` +
            `  Re-registering would rotate the live guardian's key. Check which side is stale;\n` +
            `  this script has no key-rotation mode.`
        );
      }
    }
    if (slotHolder !== ethers.ZeroAddress && slotHolder.toLowerCase() !== validator.toLowerCase()) {
      die(`${label}: slot ${slot} is already held by ${slotHolder} — SP reverts SlotAlreadyTaken`);
    }
    if (keyOwner !== ethers.ZeroAddress && keyOwner.toLowerCase() !== validator.toLowerCase()) {
      die(`${label}: this BLS key is already bound to ${keyOwner} — SP reverts DuplicatePublicKey`);
    }

    // ---- gate 9b: the guardian is eligible to sign (Daybreak on 63a484d0, M2) ------------------------------
    // The owner path admits any validator, so a registration can succeed for an address whose
    // signatures every aggregation then rejects. These are the checks SP's _reconstructPkAgg makes
    // per selected slot (BLSAggregator.sol at f2b2cd9b), read fail-closed: a read that fails stops
    // the run, it never counts as a pass.
    const elig = await eligibility(validator);
    if (!elig.hasRole)
      die(`${label}: ${validator} does not hold ROLE_DVT — SP reverts SlotValidatorRoleRevoked`);
    if (elig.locked < elig.minStake) {
      die(
        `${label}: ${validator}'s ROLE_DVT lock ${elig.locked} is below minStake ${elig.minStake} — SP reverts SlotValidatorStakeBelowMinimum`
      );
    }
    if (elig.exitReadyAt !== 0n && BigInt(basis.timestamp) >= elig.exitReadyAt) {
      die(
        `${label}: ${validator} has a guardian exit in effect since ${elig.exitReadyAt} — SP reverts SlotValidatorExitPending`
      );
    }

    // ---- gate 10: dry-run the real DVTValidator call ---------------------------------------------------------
    try {
      await dvt.registerBLSPublicKey.staticCall(validator, pkWords, slot, popWords, {
        from: owner,
        ...AT,
      });
    } catch (e) {
      die(
        `${label}: eth_call dry-run of DVTValidator.registerBLSPublicKey reverted: ${e.shortMessage ?? e.message}`
      );
    }

    console.log(`✓ ${label}`);
    console.log(`    validator ${validator}  slot ${slot}`);
    console.log(`    popDigest ${onchainDigest}`);
    console.log(`    slot now  ${slotHolder === ethers.ZeroAddress ? "free" : slotHolder}`);
    plans.push({
      label,
      validator,
      slot,
      pkWords,
      popWords,
      popDigest: onchainDigest,
      state: {
        slotHolder,
        suspended: isSuspended,
        active: existing.active,
        activeSlot: Number(existing.slot),
        activeKey: ethers.concat([...existing.publicKey]),
        keyOwner,
        hasRoleDvt: elig.hasRole,
        roleDvtLocked: elig.locked.toString(),
        exitReadyAt: elig.exitReadyAt.toString(),
      },
    });
  }

  // ---- gate 11: the plans must not collide with EACH OTHER ---------------------------------------
  // Every gate above reads CHAIN state, so two pending plans that clash are invisible to all of them:
  // three copies of one node file each pass individually, then land as ONE guardian while the run
  // reports three. Threshold is 3, so quorum stays unreachable while the operator holds "evidence"
  // saying otherwise. Found by pr-daemon on #248, with all three shapes reproduced on-chain.
  const seenSlot = new Map(),
    seenValidator = new Map(),
    seenKey = new Map();
  for (const p of plans) {
    const kh = ethers.keccak256(
      coder.encode(["bytes32", "bytes32", "bytes32", "bytes32"], p.pkWords)
    );
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

  // The block every read used must still be canonical, or the reads describe a dropped fork.
  const again = await provider.getBlock(basis.number);
  if (!again || again.hash !== basis.hash) {
    die(
      `block ${basis.number} changed while the gates ran (${basis.hash} -> ${again?.hash}): re-run`
    );
  }
  // What the SAFE signers compare against just before executing (Daybreak M3; DSR 2026-11-18):
  // re-run this export to a new file; `reads` must be identical, and only `basis` may differ.
  const reads = {
    dvtCodeHash: codeHash.DVTValidator,
    aggregatorCodeHash: codeHash.aggregator,
    dvtBlsAggregator: dvtAgg,
    aggDvtValidator: aggDvt,
    registry: aggRegistry,
    registryBlsAggregator: registryAgg,
    dvtOwner,
    aggOwner,
    aggregatorVersion: version,
    dvtVersion,
    permissionlessBLSRegistration: permissionless,
    domainSeparator: domainSep,
    domainName,
    tagPop,
    maxValidators: maxValidators.toString(),
    gTokenStaking: stakingAddr,
    roleDvtMinStake: minStake.toString(),
    validators: plans.map(p => ({ validator: p.validator, slot: p.slot, ...p.state })),
  };
  const readsDigest = ethers.keccak256(ethers.toUtf8Bytes(JSON.stringify(reads)));

  if (EXPORT_FILE) {
    // Listed field by field so a private key from a node file cannot reach this output.
    const exported = {
      chainId,
      deployment: DEPLOYMENT_FILE,
      target: DVT,
      dvtValidator: DVT,
      dvtVersion,
      aggregator: AGGREGATOR,
      version,
      owner,
      permissionlessBLSRegistration: permissionless,
      domainSeparator: domainSep,
      // Every gate read state at this block. `reads` and `readsDigest` are what a re-run before the
      // SAFE executes must reproduce (docs/rc8-deploy-day-dvt.md, "After the hand-off").
      basis: { block: basis.number, blockHash: basis.hash, timestamp: basis.timestamp },
      reads,
      readsDigest,
      registrations: plans.map(p => ({
        validator: p.validator,
        slot: p.slot,
        publicKey: p.pkWords,
        popDigest: p.popDigest,
        popSignature: p.popWords,
        // The exact bytes gate 10 dry-ran, so a consumer does not have to re-encode the call.
        // Send to `target` (the DVTValidator), from `owner`.
        calldata: dvt.interface.encodeFunctionData("registerBLSPublicKey", [
          p.validator,
          p.pkWords,
          p.slot,
          p.popWords,
        ]),
      })),
    };
    writeFileSync(EXPORT_FILE, JSON.stringify(exported, null, 2) + "\n");
    console.log(
      `\nAll ${plans.length} registrations passed. Wrote ${EXPORT_FILE}. Nothing was sent.`
    );
    return;
  }

  console.log(
    `\nAll ${plans.length} registrations passed every pre-flight gate at block ${basis.number}. Nothing was sent.`
  );
  console.log(`reads digest ${readsDigest}`);
  console.log(
    "Re-run with --export-pop <file> to write the calldata for the owner (the SAFE) to execute."
  );
}

// A non-Error throw (a bare string, a rejected object) has neither .stack nor .message, so
// `e.stack ?? e.message` printed literally "✗ undefined" and swallowed the only clue there was.
// Verified: `Promise.reject("boom").catch(e => die(e.stack ?? e.message))` prints "✗ undefined".
main().catch(e => die(e?.stack ?? e?.message ?? describe(e)));
