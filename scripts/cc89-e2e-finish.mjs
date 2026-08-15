#!/usr/bin/env node
// CC-89 joint-testnet RESIDENT auto-finisher (DVT half).
// Arms once, waits for SP to submit verifyAndExecute (proposalSignersCommitment[pid] != 0), then
// auto-runs the entire DVT finish and verifies the outcome — no per-step human/polling handshake:
//   1. resolveClaimedSigners = sorted validatorAtSlot(slots in mask)  (watcher-core derivation)
//   2. assemble fraudProof + fraudProofId  (assembler logic)
//   3. preflight: verifier.verify(...) must be true
//   4. broadcast BLSAggregator.executeGuardianSlash(fraudProofId, guilty, fraudProof)  [jason key]
//   5. verify: each guilty guardian's ROLE_DVT lock -> 0, and a fresh verify(mask) now REVERTS
//      (auto-eject: _reconstructPkAgg rejects the slashed slot below minStake)
//
//   AGGREGATOR=.. VERIFIER=.. STAKING=.. TOKEN=.. PROPOSAL_ID=.. SEPOLIA_RPC_URL=.. \
//     node scripts/cc89-e2e-finish.mjs
import { ethers } from "ethers";
import { readFileSync } from "fs";

const RPC = process.env.SEPOLIA_RPC_URL;
const AGG = process.env.AGGREGATOR;
const VERIFIER = process.env.VERIFIER;
const STAKING = process.env.STAKING;
const TOKEN = process.env.TOKEN;
const PID = BigInt(process.env.PROPOSAL_ID);
const OPERATOR = ethers.ZeroAddress; // operator = op = 0 (verifier couples both)
const SLASH_LEVEL = 1;
const EPOCH = 1n;
const MASK = 0x7n;
const ROLE_DVT = ethers.keccak256(ethers.toUtf8Bytes("DVT"));
const FRAUD_ID_TAG = "GUARDIAN_FRAUD_V1";
const coder = ethers.AbiCoder.defaultAbiCoder();
const provider = new ethers.JsonRpcProvider(RPC);
const die = m => {
  console.error("✗ " + m);
  process.exit(1);
};

const PK = (() => {
  for (const line of readFileSync(".env.sepolia", "utf8").split("\n")) {
    const m = line.match(/^PRIVATE_KEY_JASON=(.*)$/);
    if (m)
      return m[1]
        .replace(/#.*/, "")
        .trim()
        .replace(/^["']|["']$/g, "");
  }
  die("PRIVATE_KEY_JASON not in .env.sepolia");
})();
const wallet = new ethers.Wallet(PK, provider);

const agg = new ethers.Contract(
  AGG,
  [
    "function proposalSignersCommitment(uint256) view returns (bytes32)",
    "function validatorAtSlot(uint8) view returns (address)",
    "function verify(bytes32,uint256,uint256,bytes) view returns (bool)",
    "function executeGuardianSlash(uint256,address[],bytes)",
  ],
  wallet
);
const verifier = new ethers.Contract(
  VERIFIER,
  ["function verify(uint256,address[],bytes) view returns (bool)"],
  provider
);
const staking = new ethers.Contract(
  STAKING,
  ["function roleLocks(address,bytes32) view returns (uint128,uint128,uint48,bytes32,bytes)"],
  provider
);

const lockOf = async g => (await staking.roleLocks(g, ROLE_DVT))[0];
const sleep = ms => new Promise(r => setTimeout(r, ms));

console.log(
  `CC-89 resident finisher armed — waiting for SP verifyAndExecute on proposal ${PID}...`
);

// ---- 1. wait for SP's verifyAndExecute (commitment set) ---------------------
let commitment = ethers.ZeroHash;
const deadline = Date.now() + 60 * 60 * 1000; // 1h
while (Date.now() < deadline) {
  commitment = await agg.proposalSignersCommitment(PID);
  if (commitment !== ethers.ZeroHash) break;
  await sleep(20000);
}
if (commitment === ethers.ZeroHash)
  die("timed out waiting for verifyAndExecute (commitment still 0)");
console.log(`\n✓ SP submitted — proposalSignersCommitment(${PID}) = ${commitment}`);

// ---- 2. resolveClaimedSigners = sorted validatorAtSlot over the mask --------
const slots = [];
for (let s = 1n; s <= 13n; s++) if ((MASK >> (s - 1n)) & 1n) slots.push(Number(s));
const raw = [];
for (const s of slots) raw.push(ethers.getAddress(await agg.validatorAtSlot(s)));
const claimedSigners = [...raw].sort((a, b) =>
  BigInt(a) < BigInt(b) ? -1 : BigInt(a) > BigInt(b) ? 1 : 0
);
console.log("claimedSigners (sorted):", claimedSigners);

// ---- 3. assemble fraudProof + fraudProofId ---------------------------------
const fraudProof = coder.encode(
  ["uint256", "address", "uint8", "uint256", "address", "uint256", "address[]"],
  [PID, OPERATOR, SLASH_LEVEL, EPOCH, TOKEN, MASK, claimedSigners]
);
const fraudProofId = BigInt(
  ethers.keccak256(coder.encode(["string", "uint256"], [FRAUD_ID_TAG, PID]))
);
const guilty = claimedSigners; // E2E: slash all 3 colluders (ascending, ⊆ claimedSigners)

// ---- 4. preflight ----------------------------------------------------------
const ok = await verifier.verify(fraudProofId, guilty, fraudProof);
console.log(`\nverifier.verify(fraudProofId, guilty, fraudProof) = ${ok}`);
if (!ok) die("verifier rejected the fraudProof — NOT submitting executeGuardianSlash");

// ---- 5. locks BEFORE -------------------------------------------------------
const before = {};
for (const g of guilty) before[g] = await lockOf(g);
console.log(
  "ROLE_DVT locks BEFORE:",
  Object.fromEntries(guilty.map(g => [g, before[g].toString()]))
);

// ---- 6. broadcast executeGuardianSlash -------------------------------------
console.log("\nbroadcasting executeGuardianSlash...");
const tx = await agg.executeGuardianSlash(fraudProofId, guilty, fraudProof);
const rcpt = await tx.wait();
console.log(
  `✓ executeGuardianSlash mined: ${rcpt.hash} (status ${rcpt.status}, gas ${rcpt.gasUsed})`
);

// ---- 7. locks AFTER (expect 0) ---------------------------------------------
const after = {};
for (const g of guilty) after[g] = await lockOf(g);
console.log(
  "ROLE_DVT locks AFTER: ",
  Object.fromEntries(guilty.map(g => [g, after[g].toString()]))
);
const allZero = guilty.every(g => after[g] === 0n);

// ---- 8. auto-eject: a fresh verify(mask) must now REVERT --------------------
let autoEject = false;
try {
  await agg.verify(
    ethers.keccak256(ethers.toUtf8Bytes("auto-eject-probe")),
    MASK,
    3n,
    "0x" + "00".repeat(256)
  );
  autoEject = false; // did NOT revert
} catch {
  autoEject = true; // reverted (SlotValidatorStakeBelowMinimum) → slashed slots ejected
}

console.log("\n=== CC-89 over-issue guardian-slash E2E RESULT ===");
console.log("executeGuardianSlash tx:", rcpt.hash);
console.log("all 3 guardian ROLE_DVT locks -> 0:", allZero);
console.log("auto-eject (verify(mask) now reverts):", autoEject);
console.log(allZero && autoEject ? "✅ E2E PASSED" : "⚠️ E2E INCOMPLETE — review above");
