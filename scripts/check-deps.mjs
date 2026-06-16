// Built-in upstream/downstream dependency check for the aNode DVT node.
//
// Verifies this node's integration with its 3 cross-repo dependencies: the relationship,
// the pinned integration points (on-chain addresses + signing contract), the latest
// upstream release vs what we integrated against, and a live on-chain presence check.
// Run: node scripts/check-deps.mjs   (reads SEPOLIA_RPC_URL from .env.sepolia)
import { ethers } from "ethers";
import { execSync } from "child_process";
import { readFileSync, existsSync } from "fs";

const strip = s => s.replace(/^["']|["']$/g, "");
const env = existsSync(".env.sepolia")
  ? Object.fromEntries(
      readFileSync(".env.sepolia", "utf8")
        .split("\n")
        .filter(l => l.includes("="))
        .map(l => {
          const i = l.indexOf("=");
          return [l.slice(0, i).trim(), strip(l.slice(i + 1).trim())];
        })
    )
  : {};
const RPCS = [env.SEPOLIA_RPC_URL].filter(Boolean); // others rotated/dead

// What this node depends on, and the exact integration points we pinned.
const DEPS = [
  {
    repo: "AAStarCommunity/SuperPaymaster",
    relationship:
      "UPSTREAM — provides PolicyRegistry (node layer-1 reads checkPolicy) + ROLE_DVT (node BLS key registered) + BLSAggregator",
    integratedAgainst: "v5.4.0-beta.1",
    onchain: { name: "PolicyRegistry", address: "0x37e4E40e69Fb7d5C3fbAA0F52A4002D27472Ff29" },
    contract: "checkPolicy(sender,target,asset,amount,selector)->(decision,remainingDaily)",
  },
  {
    repo: "AAStarCommunity/airaccount-contract",
    relationship:
      "DOWNSTREAM — on-chain CONSUMER of this node's aggregated BLS signature (AAStarBLSAlgorithm.validate)",
    integratedAgainst: "v0.18.0-beta.2",
    onchain: { name: "AAStarBLSAlgorithm", address: "0xA9EE4f8A59fCE1B56f9da8e153c3f5F38D3C59ED" },
    contract:
      "validate(userOpHash, [nodeIds][blsSig]); DST=_POP_; messagePoint recomputed on-chain (#45)",
  },
  {
    repo: "AAStarCommunity/AirAccount",
    relationship:
      "UPSTREAM — KMS/TEE produces the account owner's secp256k1 sig that Stage-1 verifies (ownerAuth); C1 binding vector",
    integratedAgainst: "v0.23.0",
    onchain: null,
    contract:
      "ownerAuth = EIP-191 secp256k1 sig over userOpHash by account.owner(); C1: challenge=SHA256(nonce‖userOpHash)",
  },
];

function latestRelease(repo) {
  try {
    return execSync(`gh release view --repo ${repo} --json tagName -q .tagName`, {
      stdio: ["ignore", "pipe", "ignore"],
    })
      .toString()
      .trim();
  } catch {
    return "(none/unknown)";
  }
}

async function onchainPresent(addr) {
  for (const u of RPCS) {
    try {
      const code = await new ethers.JsonRpcProvider(u).getCode(addr);
      return code && code.length > 2;
    } catch {}
  }
  return null; // could not check
}

console.log("aNode DVT — upstream/downstream dependency check\n" + "=".repeat(60));
let drift = false;
for (const d of DEPS) {
  const latest = latestRelease(d.repo);
  const moved = latest !== "(none/unknown)" && latest !== d.integratedAgainst;
  let live = "—";
  if (d.onchain) {
    const present = await onchainPresent(d.onchain.address);
    live =
      present === null
        ? "rpc-unavailable"
        : present
          ? `✅ ${d.onchain.name} deployed`
          : `❌ no code @ ${d.onchain.address}`;
    if (present === false) drift = true;
  }
  if (moved) drift = true;
  console.log(`\n▸ ${d.repo}`);
  console.log(`  relationship : ${d.relationship}`);
  console.log(`  contract     : ${d.contract}`);
  console.log(
    `  integrated   : ${d.integratedAgainst}   latest: ${latest}   ${moved ? "⚠️ UPSTREAM MOVED — review alignment" : "✓ unchanged"}`
  );
  if (d.onchain) console.log(`  on-chain     : ${d.onchain.address} → ${live}`);
}
console.log("\n" + "=".repeat(60));
console.log(
  drift
    ? "⚠️ DRIFT DETECTED — review the flagged dependency before release."
    : "✅ All dependencies aligned with the integrated baseline."
);
process.exit(drift ? 1 : 0);
