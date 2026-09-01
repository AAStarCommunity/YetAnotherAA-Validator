// CC-115 B3 — finalise the matured verifier rotation on SP's BLSAggregator.
//
// `applyFraudProofVerifier()` is PERMISSIONLESS by design: the decision was already taken by the
// aggregator owner and has served the full VERIFIER_ROTATION_DELAY, so keeping the last step
// owner-only would hand the owner a second, unbounded veto. Any funded key can run this.
//
// The four days are the security property, not an obstacle (CC-48 MEDIUM-1): a public window in
// which anyone can see which verifier is about to become authoritative. This script therefore
// REFUSES to act early rather than helping anyone around it, and it says how long is left.
//
// The pending proposal does NOT expire -- the contract checks only `readyAt != 0` and
// `block.timestamp >= readyAt` -- so running this late costs nothing.
//
// Usage:
//   node deploy/apply-verifier-rotation.mjs                       (dry-run: reports state, sends nothing)
//   node deploy/apply-verifier-rotation.mjs --broadcast
//   env: SEPOLIA_RPC_URL / ETH_RPC_URL / RPC_URL, and a key for --broadcast
import { ethers } from "ethers";
import { readFileSync, writeFileSync } from "fs";
import { dirname, resolve } from "path";
import { fileURLToPath } from "url";

const HERE = dirname(fileURLToPath(import.meta.url));
const argv = process.argv.slice(2);
const flag = n => {
  const i = argv.indexOf(n);
  if (i === -1) return undefined;
  const v = argv[i + 1];
  if (v === undefined || v.startsWith("--")) die(`${n} requires a value`);
  return v;
};
const die = m => {
  console.error(`\n✗ ${m}`);
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

const BROADCAST = argv.includes("--broadcast");
const ENV_EXPLICIT = flag("--env") || process.env.DVT_ENV_FILE;
const ENV_FILE = ENV_EXPLICIT || resolve(HERE, "..", ".env.sepolia");
const AGGREGATOR = flag("--aggregator") || "0xEaeC2F512eA50708211fa95533e4dBb60e3d2E5D";
// The verifier this rotation is EXPECTED to install. Checked against the chain before broadcasting:
// applying a rotation is not the moment to discover someone proposed a different contract.
const EXPECTED =
  flag("--expect-verifier") ||
  process.env.APPLY_EXPECTED_VERIFIER ||
  "0xa1346F1668cBf8D031Cc5D72eDA45F5788CA1cd3";

const strip = s => s.replace(/^["']|["']$/g, "");
let env = {};
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
} catch {
  /* optional when the environment supplies the RPC */
}
// Explicit beats implicit, symmetric: with --env the file wins, without it the environment does.
const pick = (...n) =>
  n.map(k => (ENV_EXPLICIT ? env[k] || process.env[k] : process.env[k] || env[k])).find(Boolean);
const RPC = pick("SEPOLIA_RPC_URL", "ETH_RPC_URL", "RPC_URL");
const KEY = pick("KEEPER_PRIVATE_KEY", "PRIVATE_KEY", "OWNER_PRIVATE_KEY", "DEPLOYER_PRIVATE_KEY");

const ABI = [
  "function version() view returns (string)",
  "function fraudProofVerifier() view returns (address)",
  "function pendingFraudProofVerifier() view returns (address)",
  "function pendingFraudProofVerifierReadyAt() view returns (uint64)",
  "function VERIFIER_ROTATION_DELAY() view returns (uint256)",
  "function applyFraudProofVerifier()",
];

async function main() {
  if (!RPC) die(`no RPC url (looked in ${ENV_FILE} and the environment)`);
  const provider = new ethers.JsonRpcProvider(RPC);
  const at = { blockTag: await provider.getBlockNumber() };
  const ro = new ethers.Contract(AGGREGATOR, ABI, provider);

  const [version, active, pending, readyAt, delay] = await Promise.all([
    ro.version(at),
    ro.fraudProofVerifier(at),
    ro.pendingFraudProofVerifier(at),
    ro.pendingFraudProofVerifierReadyAt(at),
    ro.VERIFIER_ROTATION_DELAY(at),
  ]);
  const now = BigInt((await provider.getBlock(at.blockTag)).timestamp);

  console.log(`aggregator : ${AGGREGATOR}  (${version})`);
  console.log(`block      : ${at.blockTag}`);
  console.log(`active     : ${active}`);
  console.log(`pending    : ${pending}`);
  console.log(`readyAt    : ${readyAt}  (${new Date(Number(readyAt) * 1000).toISOString()})`);
  console.log(`delay      : ${delay}s`);

  if (readyAt === 0n) {
    // Distinguish "already done" from "nothing to do and something is wrong". A scheduled runner
    // reaches this state on every tick AFTER it succeeds, and reporting that as a failure would train
    // whoever watches it to ignore the job -- the alert fatigue this repo keeps circling.
    if (active.toLowerCase() === EXPECTED.toLowerCase()) {
      console.log(
        `\nAlready applied: fraudProofVerifier is ${active} and no rotation is pending. Nothing to do.`
      );
      return;
    }
    die(
      `no rotation is pending, and the active verifier is ${active}, not the expected ${EXPECTED}.\n` +
        `  Three causes, and the third is NOT a fault:\n` +
        `    1. the rotation was disarmed (emergencyDisarmFraudProofVerifier is owner-only, immediate);\n` +
        `    2. a different verifier was applied;\n` +
        `    3. a LATER legitimate rotation has since completed, and this script is still pinned to the\n` +
        `       verifier of the previous one. EXPECTED is a constant here; after any future rotation set\n` +
        `       APPLY_EXPECTED_VERIFIER (or --expect-verifier) to the new address, or this job goes red\n` +
        `       every day for a correct chain state.`
    );
  }
  if (pending.toLowerCase() !== EXPECTED.toLowerCase()) {
    die(
      `pending verifier is ${pending}, expected ${EXPECTED}.\n` +
        `  Applying a rotation is not the moment to discover a different contract was proposed.\n` +
        `  Override with --expect-verifier only after establishing what that address is.`
    );
  }
  if (now < readyAt) {
    const left = Number(readyAt - now);
    // NOT a failure. A daily runner sits in this state for the WHOLE four-day delay by design, and
    // exiting non-zero here would paint the job red for four consecutive days before the one day it
    // matters -- at which point a real failure (no RPC, missing key, revert) is indistinguishable
    // from the four that preceded it. That is the same alert fatigue this script's readyAt==0 branch
    // was written to avoid, on the other side of the window: not silent, but SHAPED LIKE A FAULT.
    // Green plus a countdown says just as much and keeps a red exit meaningful.
    console.log(
      `\nWaiting: the delay has not matured. ${left}s left (~${(left / 86400).toFixed(2)} days), ready at ` +
        `${new Date(Number(readyAt) * 1000).toISOString()}.\n` +
        `  This wait IS the security property (CC-48 MEDIUM-1) -- a public window in which anyone can\n` +
        `  see which verifier is about to become authoritative. Nothing here can or should shorten it.\n` +
        `  Nothing to do; this run is a success.`
    );
    // MUST return. die() terminated; console.log does not -- without this the run would fall through
    // to the broadcast and send a transaction the contract is guaranteed to revert.
    return;
  }

  if (!BROADCAST) {
    console.log(`\nReady to apply. Nothing was sent — re-run with --broadcast.`);
    return;
  }
  if (!KEY) die(`no signing key (looked in ${ENV_FILE} and the environment)`);
  const wallet = new ethers.Wallet(KEY, provider);
  console.log(`\nsigner     : ${wallet.address}  (permissionless — no owner rights needed)`);
  const tx = await new ethers.Contract(AGGREGATOR, ABI, wallet).applyFraudProofVerifier();
  const rc = await tx.wait();
  console.log(`apply tx   : ${tx.hash}  block ${rc.blockNumber}`);

  // WRITE THE ARTIFACT BEFORE ANY ASSERTION.
  //
  // The first version wrote it at the very end, after four things that can `die()`: a reverted
  // receipt, an RPC hiccup on the three reads, the EXPECTED mismatch, and getNetwork(). Since `die()`
  // is process.exit(1), each of those made the step red AND left no file, so the workflow's
  // `if: success() && hashFiles(...)` guard never even got a chance.
  //
  // The mismatch path is the one that matters: the transaction has ALREADY LANDED. The rotation
  // happened, on a verifier that is not the one proposed. That is the single most important thing
  // this run could ever have to say, and the old shape said nothing but "a step failed" — leaving
  // whoever arrives on 09-04 to reconstruct chain state by hand. Which is the exact situation this
  // file exists to prevent, one step later. (Review B1 on PR #287.)
  //
  // So: read what can be read, record a STATUS, publish always, and only then assert. A red job AND
  // a published artifact is the right combination — not one or the other.
  const readback = {
    task: "CC-115 B3",
    records: "6 and 7",
    status: "unknown",
    appliedAtBlock: rc.blockNumber,
    applyTxHash: tx.hash,
    receiptStatus: rc.status,
    aggregator: AGGREGATOR,
    expectedVerifier: EXPECTED,
    appliedAtUtc: new Date().toISOString(),
  };
  const out = resolve(HERE, "..", "rotation-readback.json");
  const flush = () => {
    writeFileSync(out, JSON.stringify(readback, null, 2) + "\n");
    console.log(`\nReadback artifact written (${readback.status}): ${out}`);
  };

  if (rc.status !== 1) {
    readback.status = "reverted";
    flush();
    die(`tx ${tx.hash} reverted`);
  }

  // Read back rather than trusting the receipt: status 1 proves the tx was mined, not that the
  // verifier is now the active one.
  const after = { blockTag: rc.blockNumber };
  try {
    const [nowActive, nowPending, nowReady] = await Promise.all([
      ro.fraudProofVerifier(after),
      ro.pendingFraudProofVerifier(after),
      ro.pendingFraudProofVerifierReadyAt(after),
    ]);
    readback.fraudProofVerifier = nowActive;
    readback.pendingFraudProofVerifier = nowPending;
    readback.pendingFraudProofVerifierReadyAt = nowReady.toString();
  } catch (e) {
    readback.status = "readback-failed";
    readback.error = describe(e);
    flush();
    die(`post-apply readback failed: ${describe(e)}`);
  }
  try {
    readback.chainId = Number((await provider.getNetwork()).chainId);
  } catch {
    // Non-fatal: chainId is context, not evidence. Everything above is already recorded.
  }

  console.log(`\nFinal readback:`);
  console.log(
    `  fraudProofVerifier              : ${readback.fraudProofVerifier} ${readback.fraudProofVerifier.toLowerCase() === EXPECTED.toLowerCase() ? "✓" : "✗ UNEXPECTED"}`
  );
  console.log(
    `  pendingFraudProofVerifier       : ${readback.pendingFraudProofVerifier} ${readback.pendingFraudProofVerifier === ethers.ZeroAddress ? "✓ cleared" : "✗"}`
  );
  console.log(
    `  pendingFraudProofVerifierReadyAt: ${readback.pendingFraudProofVerifierReadyAt} ${readback.pendingFraudProofVerifierReadyAt === "0" ? "✓ cleared" : "✗"}`
  );

  if (readback.fraudProofVerifier.toLowerCase() !== EXPECTED.toLowerCase()) {
    readback.status = "mismatch";
    flush();
    die("the active verifier is not the one this rotation proposed");
  }

  readback.status = "ok";
  flush();
  console.log(`\nRecords 6 and 7 of docs/evidence/cc115-b3-arming-sepolia.md are now available.`);
}

// A non-Error throw (a bare string, a rejected object) has neither .stack nor .message, so
// `e.stack ?? e.message` printed literally "✗ undefined" and swallowed the only clue there was.
// Verified: `Promise.reject("boom").catch(e => die(e.stack ?? e.message))` prints "✗ undefined".
main().catch(e => die(e?.stack ?? e?.message ?? describe(e)));
