// CC-98 snapshotEpoch keeper — permissionless per-epoch pin for AAStarCommitteeValidator.
//
// Committee mode fails closed unless each epoch is pinned within its 256-block window (blockhash
// availability). This keeper polls the validator and calls snapshotEpoch() when the CURRENT epoch is
// unpinned and still inside its window. Any funded key can run it (permissionless); run several for
// redundancy — a missed window fail-closes committee ops for that epoch and the next, then self-heals.
//
// While epochLength == 0 (committee mode OFF) snapshotEpoch reverts and this keeper idles.
//
// env (.env.sepolia): SEPOLIA_RPC_URL, KEEPER_PRIVATE_KEY (or PRIVATE_KEY), COMMITTEE_VALIDATOR
// Usage: node deploy/committee-keeper.mjs            (one pass)
//        node deploy/committee-keeper.mjs --watch    (loop every ~30s)
import { ethers } from "ethers";
import { readFileSync } from "fs";

const strip = s => s.replace(/^["']|["']$/g, "");
const env = Object.fromEntries(
  readFileSync(".env.sepolia", "utf8")
    .split("\n").filter(l => l.includes("="))
    .map(l => { const i = l.indexOf("="); return [l.slice(0, i).trim(), strip(l.slice(i + 1).trim())]; })
);
const RPC = env.SEPOLIA_RPC_URL || env.ETH_RPC_URL;
const KEY = env.KEEPER_PRIVATE_KEY || env.PRIVATE_KEY;
const VALIDATOR = process.env.COMMITTEE_VALIDATOR || env.COMMITTEE_VALIDATOR || "0x1A8Db639b5d8Bd5742edB083656EDD56f416cd64";
const WATCH = process.argv.includes("--watch");

const ABI = [
  "function epochLength() view returns(uint256)",
  "function epochPinned(uint256) view returns(bool)",
  "function epochConfigVersion(uint256) view returns(uint256)",
  "function configVersion() view returns(uint256)",
  "function snapshotEpoch()",
];

async function tick() {
  const provider = new ethers.JsonRpcProvider(RPC);
  const wallet = new ethers.Wallet(KEY, provider);
  const v = new ethers.Contract(VALIDATOR, ABI, wallet);

  const epochLength = await v.epochLength();
  if (epochLength === 0n) { console.log(new Date().toISOString(), "epochLength=0 (committee OFF) — idle"); return; }

  const bn = BigInt(await provider.getBlockNumber());
  const e = bn / epochLength;
  const start = e * epochLength;
  const pinned = await v.epochPinned(e);
  const usable = pinned && (await v.epochConfigVersion(e)) === (await v.configVersion());

  // Window: strictly after the epoch's first block, within 256 blocks (blockhash availability).
  const inWindow = bn > start && bn <= start + 256n;

  if (usable) { console.log(new Date().toISOString(), `epoch ${e} already pinned (usable) — nothing to do`); return; }
  if (!inWindow) {
    console.log(new Date().toISOString(), `epoch ${e}: block ${bn} outside pin window [${start + 1n}, ${start + 256n}] — cannot pin (self-heals next epoch)`);
    return;
  }
  console.log(new Date().toISOString(), `epoch ${e}: pinning (block ${bn}, window ok)...`);
  try {
    const tx = await v.snapshotEpoch();
    console.log("  snapshotEpoch tx:", tx.hash);
    const r = await tx.wait();
    console.log("  pinned in block", r.blockNumber, "status", r.status);
  } catch (err) {
    console.log("  snapshotEpoch failed:", err.shortMessage || err.reason || err.code || err.message);
  }
}

if (WATCH) {
  console.log("keeper watching", VALIDATOR, "— Ctrl-C to stop");
  const loop = async () => { try { await tick(); } catch (e) { console.log("tick err", e.shortMessage || e.message); } setTimeout(loop, 30000); };
  loop();
} else {
  tick().catch(e => { console.error(e.shortMessage || e.message); process.exit(1); });
}
