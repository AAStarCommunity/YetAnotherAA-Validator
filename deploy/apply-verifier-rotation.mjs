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
import { readFileSync } from "fs";
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

const BROADCAST = argv.includes("--broadcast");
const ENV_EXPLICIT = flag("--env") || process.env.DVT_ENV_FILE;
const ENV_FILE = ENV_EXPLICIT || resolve(HERE, "..", ".env.sepolia");
const AGGREGATOR = flag("--aggregator") || "0xEaeC2F512eA50708211fa95533e4dBb60e3d2E5D";
// The verifier this rotation is EXPECTED to install. Checked against the chain before broadcasting:
// applying a rotation is not the moment to discover someone proposed a different contract.
const EXPECTED = flag("--expect-verifier") || "0xa1346F1668cBf8D031Cc5D72eDA45F5788CA1cd3";

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
const pick = (...n) => n.map(k => (ENV_EXPLICIT ? env[k] || process.env[k] : process.env[k] || env[k])).find(Boolean);
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

  if (readyAt === 0n) die("no rotation is pending — nothing to apply (it may already have been applied, or disarmed)");
  if (pending.toLowerCase() !== EXPECTED.toLowerCase()) {
    die(
      `pending verifier is ${pending}, expected ${EXPECTED}.\n` +
        `  Applying a rotation is not the moment to discover a different contract was proposed.\n` +
        `  Override with --expect-verifier only after establishing what that address is.`
    );
  }
  if (now < readyAt) {
    const left = Number(readyAt - now);
    die(
      `the delay has not matured: ${left}s left (~${(left / 86400).toFixed(2)} days), ready at ` +
        `${new Date(Number(readyAt) * 1000).toISOString()}.\n` +
        `  This wait IS the security property (CC-48 MEDIUM-1) -- a public window in which anyone can\n` +
        `  see which verifier is about to become authoritative. Nothing here can or should shorten it.`
    );
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
  if (rc.status !== 1) die(`tx ${tx.hash} reverted`);
  console.log(`apply tx   : ${tx.hash}  block ${rc.blockNumber}`);

  // Read back rather than trusting the receipt: status 1 proves the tx was mined, not that the
  // verifier is now the active one.
  const after = { blockTag: rc.blockNumber };
  const [nowActive, nowPending, nowReady] = await Promise.all([
    ro.fraudProofVerifier(after),
    ro.pendingFraudProofVerifier(after),
    ro.pendingFraudProofVerifierReadyAt(after),
  ]);
  console.log(`\nFinal readback:`);
  console.log(`  fraudProofVerifier              : ${nowActive} ${nowActive.toLowerCase() === EXPECTED.toLowerCase() ? "✓" : "✗ UNEXPECTED"}`);
  console.log(`  pendingFraudProofVerifier       : ${nowPending} ${nowPending === ethers.ZeroAddress ? "✓ cleared" : "✗"}`);
  console.log(`  pendingFraudProofVerifierReadyAt: ${nowReady} ${nowReady === 0n ? "✓ cleared" : "✗"}`);
  if (nowActive.toLowerCase() !== EXPECTED.toLowerCase()) die("the active verifier is not the one this rotation proposed");
  console.log(`\nRecords 6 and 7 of docs/evidence/cc115-b3-arming-sepolia.md are now available.`);
}

main().catch(e => die(e.stack ?? e.message));
