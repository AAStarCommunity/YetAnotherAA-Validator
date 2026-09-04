// Committee-mode E2E: drive the 3 RUNNING DVT nodes through a real co-sign and verify the result
// against the live AAStarCommitteeValidator with real Merkle proofs, real sortition and real on-chain
// BLS pairing.
//
// WHY THIS EXISTS. Every other driver in this repo (realnode-e2e, verify-prod-e2e, handleops-tx,
// selftest) verifies against the LEGACY whole-set path — `AAStarBLSAlgorithm.validate`, which knows
// nothing about epochs, snapshots, Merkle membership or sortition. Committee mode has been ON on the
// router-mounted validator since CC-115, and until this file the only evidence it worked end to end
// was a single manual run recorded in a design doc. A path proven once by hand is not covered; it is
// remembered.
//
// WHAT IS REAL HERE.
// Everything, on the default account: the three nodes' BLS keys, their owner-auth gate, the
// aggregate, the frozen setRoot replayed from chain logs, every Merkle proof, the sortition draw,
// and the pairing check inside validate(). `0x92EA8b02…` was enrolled for real on 2026-09-01 (tx
// 0xf8a68767…, `execute(validator, 0, enroll())` from its owner), so no simulation is involved.
// The one conditional exception: `enrolledAccount[account]` is supplied through an `eth_call` STATE
// OVERRIDE when the account under test has NOT self-enrolled. That flag is a one-bit, owner-controlled gate the
// contract itself documents as "DEFENSE-IN-DEPTH for the accountId invariant" -- it is not part of
// the cryptography, and enrolling for real costs a transaction from the account. The override is
// therefore declared loudly, and step 8 proves the gate is genuinely closed without it, so the run
// can never quietly pass because the override made everything true.
//
// Usage:
//   node scripts/e2e/committee-e2e.mjs
//   E2E_ACCOUNT=0x… DVT_NODE_URLS=http://127.0.0.1:3001,… node scripts/e2e/committee-e2e.mjs
//
// Reads .env.sepolia for SEPOLIA_RPC_URL, ENTRY_POINT_ADDRESS, PRIVATE_KEY_SUPPLIER.
import { ethers } from "ethers";
import { bls12_381 as bls } from "@noble/curves/bls12-381.js";
import { readFileSync } from "fs";
import { reconstructFrozenTree, buildCommitteePayload } from "../../deploy/committee-proofgen.mjs";

const sigs = bls.longSignatures;
const DST = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
const strip = s => s.replace(/^["']|["']$/g, "");
const env = Object.fromEntries(
  readFileSync(".env.sepolia", "utf8")
    .split("\n")
    .filter(l => l.includes("=") && !l.trim().startsWith("#"))
    .map(l => {
      const i = l.indexOf("=");
      return [l.slice(0, i).trim(), strip(l.slice(i + 1).trim())];
    })
);

const RPC = process.env.SEPOLIA_RPC_URL || env.SEPOLIA_RPC_URL;
const ENTRY =
  process.env.ENTRY_POINT_ADDRESS ||
  env.ENTRY_POINT_ADDRESS ||
  "0x0000000071727De22E5E9d8BAf0edAc6f37da032";
// 127.0.0.1, NOT localhost. On this machine `localhost` resolves to ::1 first, and an unrelated
// Next.js dev server holds *:3001 on IPv6 while the DVT containers bind 127.0.0.1 only -- so
// `localhost:3001` reaches a web app that answers 500, and the E2E reads as a broken node. Found by
// running this; it costs nothing to be explicit and it removes a genuinely confusing failure.
const NODE_URLS = (
  process.env.DVT_NODE_URLS || "http://127.0.0.1:3001,http://127.0.0.1:3002,http://127.0.0.1:3003"
).split(",");
// Same account the other drivers use by default: an AAStarAirAccountV7 whose owner() is
// PRIVATE_KEY_SUPPLIER and which implements isValidOwnerAuth -> 0xa0cf00cf.
// Normalised through `ethers.getAddress` rather than used as the raw string: it rejects a malformed
// address at the point it enters the run, with a message naming THIS variable, instead of surfacing
// later as an opaque ENS or ABI-encoding error from three frames down. It also checksums, so the
// address printed in the log is the one a block explorer will show.
const ACCOUNT_RAW = process.env.E2E_ACCOUNT || "0x92EA8b02D34A4D5d10f0Db9Ea894e8bC72e292e8";
// Describes the SHAPE of the bad value rather than echoing it. Two reasons, and the second is the
// real one: (a) after `ethers.getAddress` the accepted value is no longer flagged by CodeQL — the
// remaining sink was this line handing a raw `process.env` string straight to a log; (b) echoing back
// what the operator typed adds little they do not already have, whereas "44 chars, no 0x prefix"
// names the mistake directly. Length and prefix are derived facts about the input, not the input.
const shapeOf = v => `${v.length} char(s), ${v.startsWith("0x") ? "0x-prefixed" : "no 0x prefix"}`;
let ACCOUNT;
try {
  ACCOUNT = ethers.getAddress(ACCOUNT_RAW);
} catch {
  // console.error, not the `die` helper: that is declared further down the file, so calling it here
  // is a temporal-dead-zone crash — the malformed-address path would fail with a ReferenceError
  // about `die` instead of telling the operator what is wrong with their input.
  console.error(
    `\u203c E2E_ACCOUNT is not a valid address (${shapeOf(ACCOUNT_RAW)}); ` +
      `it must be a 0x-prefixed 20-byte hex address`
  );
  process.exit(1);
}
// Naming the STACK rather than an address, for the reason committee-health.mjs gives: algId 0x01 is
// what actually decides which validator an account stack uses, so a run derived from the router can
// never end up proving something about a contract nobody mounts. Defaulted exactly as
// deploy/local-heartbeat.sh:64 defaults it, and defensible for the same reason: the router must
// resolve algId 0x01 to a live committee validator or this script fails loudly a few lines below.
const ROUTER = process.env.COMMITTEE_ROUTER || "0xA97A752779ebfDA58612F6727Ec7C8366c39f897";
const VALIDATOR_EXPLICIT = process.env.COMMITTEE_VALIDATOR;

const ENROLLED_SLOT = 42n; // `mapping(address => bool) enrolledAccount` (forge inspect storage-layout)

let failures = 0;
const step = (n, label) => console.log(`\n[${n}] ${label}`);
const ok = m => console.log(`    ✅ ${m}`);
const bad = m => {
  console.log(`    ❌ ${m}`);
  failures++;
};
const die = m => {
  console.error(`\n✗ ${m}`);
  process.exit(1);
};

if (!RPC) die("no SEPOLIA_RPC_URL (in the environment or .env.sepolia)");
if (!env.PRIVATE_KEY_SUPPLIER) die("no PRIVATE_KEY_SUPPLIER in .env.sepolia (the account's owner)");
const provider = new ethers.JsonRpcProvider(RPC);
const owner = new ethers.Wallet(env.PRIVATE_KEY_SUPPLIER);

const b48 = n => ethers.getBytes("0x" + n.toString(16).padStart(96, "0"));
/// EIP-2537 G2 encoding: four 64-byte big-endian limbs, each left-padded to 16 bytes of zeros.
const encG2 = pt => {
  const a = pt.toAffine();
  const r = new Uint8Array(256);
  r.set(b48(a.x.c0), 16);
  r.set(b48(a.x.c1), 80);
  r.set(b48(a.y.c0), 144);
  r.set(b48(a.y.c1), 208);
  return ethers.hexlify(r);
};

const VABI = [
  "function epochLength() view returns (uint256)",
  "function committeeActive() view returns (bool)",
  "function configVersion() view returns (uint256)",
  "function epochPinned(uint256) view returns (bool)",
  "function epochConfigVersion(uint256) view returns (uint256)",
  "function epochSetValidUntil(uint256) view returns (uint256)",
  "function epochSetCount(uint256) view returns (uint256)",
  "function expectedCommittee(uint256) view returns (uint256)",
  "function requiredQuorum() view returns (uint256)",
  "function isRegistered(bytes32) view returns (bool)",
  "function enrolledAccount(address) view returns (bool)",
  "function validate(bytes32 hash, bytes signature) view returns (uint256)",
];

// ---------------------------------------------------------------------------------------------
step(0, "resolve the validator (EXPLICIT > router algId 0x01 > fail — the #283 rule)");
let VALIDATOR;
if (VALIDATOR_EXPLICIT) {
  VALIDATOR = ethers.getAddress(VALIDATOR_EXPLICIT);
  ok(`explicit COMMITTEE_VALIDATOR ${VALIDATOR}`);
} else {
  const r = new ethers.Contract(
    ROUTER,
    ["function getAlgorithm(uint8) view returns (address)"],
    provider
  );
  VALIDATOR = await r.getAlgorithm(1);
  if (VALIDATOR === ethers.ZeroAddress) die(`router ${ROUTER} mounts nothing at algId 0x01`);
  ok(`derived from router ${ROUTER}: ${VALIDATOR}`);
}
const V = new ethers.Contract(VALIDATOR, VABI, provider);

// ---------------------------------------------------------------------------------------------
// Every read and the final eth_call are PINNED to one block. Committee state is epoch-indexed and
// epochLength is 64 blocks (~13 min on Sepolia): unpinned, an epoch rollover between building the
// payload and submitting it would silently prove nothing, and would do so intermittently. Same
// lesson the liveness keeper learned in #288 -- reads that describe different blocks are not a
// measurement.
const HEAD = await provider.getBlockNumber();
const AT = { blockTag: HEAD };
const headBlock = await provider.getBlock(HEAD);

step(1, `preconditions, all read at block ${HEAD}`);
const epochLength = await V.epochLength(AT);
const committeeActive = await V.committeeActive(AT);
if (!committeeActive) bad("committeeActive == false — this validator is not in committee mode");
else ok("committeeActive == true");
if (epochLength === 0n) die("epochLength == 0 — committee mode is off, nothing to prove");
const e = BigInt(HEAD) / epochLength;
const cfgV = await V.configVersion(AT);
const now = BigInt(headBlock.timestamp);

/// The contract's own `_epochUsable`, recomputed here so a failure says WHICH conjunct failed rather
/// than just "validate returned 1".
async function usable(ep) {
  const pinned = await V.epochPinned(ep, AT);
  const ecv = await V.epochConfigVersion(ep, AT);
  const until = await V.epochSetValidUntil(ep, AT);
  return { pinned, ecv, until, ok: pinned && ecv === cfgV && now < until };
}
const uE = await usable(e);
const uPrev = await usable(e - 1n);
for (const [label, ep, u] of [
  ["e", e, uE],
  ["e-1", e - 1n, uPrev],
]) {
  if (u.ok)
    ok(`epoch ${label} = ${ep} usable (pinned, cfgV ${u.ecv}, valid ${u.until - now}s more)`);
  else
    bad(
      `epoch ${label} = ${ep} NOT usable: pinned=${u.pinned} cfgV=${u.ecv} (want ${cfgV}) ` +
        `validUntil=${u.until} now=${now}`
    );
}
if (failures) die("committee preconditions unmet — a keeper must pin the current epoch first");

// validate() samples the LOOK-AHEAD set: the committee for ops in epoch e is drawn from setRoot[e-1].
const SAMPLED = e - 1n;
const committedCount = await V.epochSetCount(SAMPLED, AT);
const m = await V.expectedCommittee(committedCount, AT);
// WHICH SORTITION REGIME IS THIS RUN IN? `_thresholdOf(n, m)` returns `type(uint256).max` when
// `m >= n` (AAStarCommitteeValidator.sol:626) — the whole-set / tiny-pool case, where the draw admits
// every committed signer and filters nobody. With n = 3 and expectedCommittee(3) = 3 that is exactly
// where this stack sits, so a green run here does NOT demonstrate committee SELECTION; it
// demonstrates parsing, enrolment, quorum, Merkle proofs and the BLS pairing.
//
// This line exists because the run log claimed "real sortition" for four days before anyone checked
// the branch it lands in. Saying which regime the run is in is cheap; letting a report overstate what
// it covered is how a passing test becomes evidence for something it never touched.
const SAMPLING_REGIME = m < committedCount;
const quorum = await V.requiredQuorum(AT);
ok(
  `sampling epoch ${SAMPLED}: setCount=${committedCount}, expectedCommittee=${m}, quorum=${quorum}`
);

// ---------------------------------------------------------------------------------------------
step(2, `the ${NODE_URLS.length} live DVT nodes`);
const nodes = [];
for (const url of NODE_URLS) {
  let info;
  try {
    const r = await fetch(`${url}/node/info`, { signal: AbortSignal.timeout(8000) });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    info = await r.json();
  } catch (err) {
    bad(`${url} unreachable (${err.message}) — start the stack first`);
    continue;
  }
  const registered = await V.isRegistered(info.nodeId, AT);
  if (registered) ok(`${url}  ${info.nodeName}  ${info.nodeId.slice(0, 18)}…  registered`);
  else
    bad(`${url}  ${info.nodeName}  ${info.nodeId.slice(0, 18)}…  NOT registered on ${VALIDATOR}`);
  nodes.push({ url, ...info });
}
if (failures) die("node preconditions unmet");
if (BigInt(nodes.length) < quorum) die(`only ${nodes.length} nodes for a quorum of ${quorum}`);

// ---------------------------------------------------------------------------------------------
step(3, "userOpHash, derived by the EntryPoint (not by us)");
const userOp = {
  sender: ACCOUNT,
  nonce: "0",
  initCode: "0x",
  callData: "0x",
  accountGasLimits: "0x" + "00".repeat(32),
  preVerificationGas: "0",
  gasFees: "0x" + "00".repeat(32),
  paymasterAndData: "0x",
  signature: "0x",
};
const EP_ABI = [
  "function getUserOpHash((address sender,uint256 nonce,bytes initCode,bytes callData,bytes32 accountGasLimits,uint256 preVerificationGas,bytes32 gasFees,bytes paymasterAndData,bytes signature) userOp) view returns (bytes32)",
];
const userOpHash = await new ethers.Contract(ENTRY, EP_ABI, provider).getUserOpHash(userOp);
ok(`account ${ACCOUNT}\n       userOpHash ${userOpHash}`);

// ownerAuth = 1-byte tag ‖ payload; tag 0x01 = owner ECDSA over personal_sign(userOpHash).
// Exactly 66 bytes or the account returns 0xffffffff (docs/INTERFACES.md §1).
const ownerAuth = "0x01" + (await owner.signMessage(ethers.getBytes(userOpHash))).slice(2);

// ---------------------------------------------------------------------------------------------
step(4, "co-sign through each node's owner-auth gate");
const signed = [];
for (const n of nodes) {
  const r = await fetch(`${n.url}/signature/sign`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ userOp, ownerAuth }),
    signal: AbortSignal.timeout(30000),
  });
  if (!r.ok) {
    bad(`${n.url} -> ${r.status} ${(await r.text()).slice(0, 200)}`);
    continue;
  }
  const j = await r.json();
  // The node derives the hash itself from the full userOp. If its answer differs from the
  // EntryPoint's, the signature is over something else and the rest of this run is meaningless.
  if (j.message?.toLowerCase() !== userOpHash.toLowerCase()) {
    bad(`${n.url} signed a DIFFERENT hash: ${j.message}`);
    continue;
  }
  ok(`${n.url} signed, message == userOpHash`);
  signed.push(j);
}
if (failures) die("co-sign failed");

// ---------------------------------------------------------------------------------------------
step(5, "off-chain aggregate verify");
const aggregateOf = set => {
  const agg = sigs.aggregateSignatures(
    set.map(s => sigs.Signature.fromHex(s.signatureCompact.replace(/^0x/, "")))
  );
  const pk = set
    .map(s => bls.G1.Point.fromHex(s.publicKey.replace(/^0x/, "")))
    .reduce((a, b) => a.add(b));
  return { agg, pk };
};
const mp = bls.G2.hashToCurve(ethers.getBytes(userOpHash), { DST });
const all = aggregateOf(signed);
if (sigs.verify(all.agg, mp, all.pk)) ok(`${signed.length}-node aggregate verifies off-chain`);
else bad(`${signed.length}-node aggregate does NOT verify off-chain`);

// ---------------------------------------------------------------------------------------------
step(6, `replay the frozen set for epoch ${SAMPLED} from chain logs`);
// reconstructFrozenTree scans from DEPLOY_BLOCK (or block 0 with a warning). Find the creation block
// by bisection rather than making the operator supply it -- ~24 eth_getCode calls, and it cannot go
// stale the way a pinned constant would.
if (!process.env.DEPLOY_BLOCK) {
  let lo = 0,
    hi = HEAD;
  if ((await provider.getCode(VALIDATOR, hi)) === "0x") die("validator has no code at head");
  while (lo < hi) {
    const mid = Math.floor((lo + hi) / 2);
    if ((await provider.getCode(VALIDATOR, mid)) === "0x") lo = mid + 1;
    else hi = mid;
  }
  process.env.DEPLOY_BLOCK = String(lo);
  ok(`deploy block located by bisection: ${lo}`);
}
const frozen = await reconstructFrozenTree(provider, VALIDATOR, SAMPLED);
// reconstructFrozenTree already throws unless the replayed root equals the on-chain epochSetRoot;
// saying so here is what makes the next line's proofs meaningful rather than self-consistent.
ok(
  `replayed root matches on-chain setRoot[${SAMPLED}]: ${frozen.root} (${frozen.leafMap.size} leaves)`
);

// ---------------------------------------------------------------------------------------------
step(7, "build the committee payload");
const payloadFor = set =>
  buildCommitteePayload(
    frozen,
    ACCOUNT,
    set.map(s => s.nodeId),
    encG2(aggregateOf(set).agg)
  );
const payload = payloadFor(signed);
const perSigner = 64 + 14 * 32;
const k = (ethers.dataLength(payload) - 32 - 256) / perSigner;
ok(
  `${ethers.dataLength(payload)} bytes = accountId(32) + ${k} x signer(${perSigner}) + blsSig(256)`
);

// ---------------------------------------------------------------------------------------------
const enrollSlot = a =>
  ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(["address", "uint256"], [a, ENROLLED_SLOT])
  );
const ONE = "0x" + "0".repeat(63) + "1";
/// eth_call, optionally with `enrolledAccount[ACCOUNT] = true` injected for the duration of the call.
/// Pinned to HEAD so it observes exactly the state the payload was built against.
async function callValidate(hash, sig, { enroll = false } = {}) {
  const data = V.interface.encodeFunctionData("validate", [hash, sig]);
  const params = [{ to: VALIDATOR, data }, ethers.toBeHex(HEAD)];
  if (enroll) params.push({ [VALIDATOR]: { stateDiff: { [enrollSlot(ACCOUNT)]: ONE } } });
  return BigInt(await provider.send("eth_call", params));
}

step(8, "the enrollment gate is REAL (control for the override used below)");
const enrolled = await V.enrolledAccount(ACCOUNT, AT);
if (enrolled) {
  ok(`${ACCOUNT} is genuinely enrolled — no override needed anywhere in this run`);
} else {
  const plain = await callValidate(userOpHash, payload);
  if (plain === 1n)
    ok(
      `${ACCOUNT} is NOT enrolled and validate() rejects (returns 1). The override in step 9 is ` +
        `therefore supplying exactly one bit, and this line proves that bit is load-bearing.`
    );
  else
    bad(
      `expected validate() to reject an unenrolled account with 1, got ${plain} — the control is ` +
        `broken, so a pass in step 9 would mean nothing`
    );
  // Positive control on the override mechanism itself: a known-enrolled account must read 1 through
  // the same storage slot this script computes. Without it, a silently-wrong slot would make the
  // override a no-op and step 9 would fail for a reason nobody could see.
  const known = "0x0985785d1fc37978474C472E39391774DcB1C711";
  const raw = await provider.getStorage(VALIDATOR, enrollSlot(known), HEAD);
  if (BigInt(raw) === 1n) ok(`slot ${ENROLLED_SLOT} confirmed against a known-enrolled account`);
  else bad(`slot ${ENROLLED_SLOT} is wrong — ${known} is enrolled but reads ${raw}`);
}

// ---------------------------------------------------------------------------------------------
step(9, "ON-CHAIN committee validate()");
const verdict = await callValidate(userOpHash, payload, { enroll: !enrolled });
if (verdict === 0n)
  ok(
    `validate() == 0 ACCEPTED${enrolled ? "" : "  (enrolledAccount supplied by state override)"}\n` +
      `       real BLS pairing, real Merkle proofs against setRoot[${SAMPLED}], at block ${HEAD}\n` +
      `       sortition: ${
        SAMPLING_REGIME
          ? `SAMPLED regime (expectedCommittee ${m} < setCount ${committedCount}) — the draw filtered`
          : `WHOLE-SET regime (expectedCommittee ${m} >= setCount ${committedCount}) — _thresholdOf ` +
            `returns type(uint256).max, so the draw admitted everyone and this run does NOT cover ` +
            `committee selection`
      }`
  );
else bad(`validate() == ${verdict} REJECTED — the committee path did not accept a valid aggregate`);

// ---------------------------------------------------------------------------------------------
// Negative controls. A verifier that accepts everything also accepts the happy path, so the run is
// only informative if these are rejected for the RIGHT reasons.
step(10, "negative controls — each must be REJECTED");
// A THROWN ERROR IS NOT A VERDICT. This used to report any exception as "reverted", i.e. as the
// control passing — which meant a 429, an RPC timeout, a node that does not support state overrides,
// or a malformed response all printed a green line and the run finished clean having obtained no
// answer at all for that control. The whole purpose of these four is to be the part of the run that
// can fail, so they must not be the part that cannot.
//
// `validate()` is designed to RETURN 1 rather than revert, so an EVM revert is itself a regression
// here, not a pass. It is reported distinctly from a transport failure, because the two call for
// different actions: one is a contract change, the other is "run it again".
const expectReject = async (label, hash, sig) => {
  let v;
  try {
    v = await callValidate(hash, sig, { enroll: !enrolled });
  } catch (err) {
    const msg = (err.shortMessage || err.message || String(err)).slice(0, 80);
    if (err.code === "CALL_EXCEPTION")
      bad(`${label}: the call REVERTED — validate() is specified to return 1, not revert (${msg})`);
    else bad(`${label}: NO VERDICT — the call failed for a non-EVM reason (${err.code}: ${msg})`);
    return;
  }
  if (v === 1n) ok(`${label}: rejected (1)`);
  else bad(`${label}: ACCEPTED (${v}) — it should not have been`);
};

// (a) below quorum: quorum-1 signers, otherwise a perfectly valid aggregate.
if (BigInt(signed.length) > quorum - 1n && quorum > 1n) {
  const few = signed.slice(0, Number(quorum) - 1);
  await expectReject(
    `below quorum (${few.length} of ${quorum} signers)`,
    userOpHash,
    payloadFor(few)
  );
}
// (b) a tampered Merkle proof: flip one byte inside the first signer's proof.
{
  const bytes = ethers.getBytes(payload);
  bytes[32 + 64 + 5] ^= 0xff; // inside signer 0's proof, past nodeId(32)+slot(32)
  await expectReject("tampered Merkle proof", userOpHash, ethers.hexlify(bytes));
}
// (c) the right signature over the wrong hash.
await expectReject("valid aggregate, wrong hash", ethers.id("not-the-userOpHash"), payload);
// (d) an accountId nobody enrolled and the override does not cover: proves the gate is bound to the
//     account this run is about, not merely "some account was enrolled".
{
  const other = "0x000000000000000000000000000000000000dEaD";
  const p2 = buildCommitteePayload(
    frozen,
    other,
    signed.map(s => s.nodeId),
    encG2(all.agg)
  );
  await expectReject("payload for a different, unenrolled accountId", userOpHash, p2);
}

// ---------------------------------------------------------------------------------------------
console.log("");
if (failures) {
  console.error(`✗ committee E2E FAILED — ${failures} check(s) failed\n`);
  process.exit(1);
}
console.log(
  `✅ committee E2E PASSED — validator ${VALIDATOR}, epoch ${e} (sampling ${SAMPLED}), ` +
    `${signed.length} live nodes, block ${HEAD}\n`
);
