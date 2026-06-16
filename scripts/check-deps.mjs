// Built-in upstream/downstream dependency-sync check for the aNode DVT node.
// Invoke: `npm run check-deps`  (or `node scripts/check-deps.mjs`).
//
// For each cross-repo dependency it compares the PINNED baseline against the CURRENT
// state pulled live: the latest GitHub release tag AND the canonical contract address
// parsed from that release's notes — so it catches a REDEPLOY (same/new tag, NEW
// address), which a plain getCode check misses (the old contract usually still exists).
// Also confirms the current address has on-chain code. Exits non-zero on any drift so it
// can gate a release / be wired into CI.
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
const RPCS = [env.SEPOLIA_RPC_URL].filter(Boolean); // other RPCs rotated/dead

// PINNED baseline = what this node is integrated against. `addressLabel` is the row
// label to find in the dep's release-notes "Deployed contracts" table.
const DEPS = [
  {
    repo: "AAStarCommunity/SuperPaymaster",
    relationship:
      "UPSTREAM — node reads PolicyRegistry.checkPolicy (layer-1) + registers BLS key in ROLE_DVT",
    version: "v5.4.0-beta.1",
    addressLabel: "PolicyRegistry",
    address: "0x37e4E40e69Fb7d5C3fbAA0F52A4002D27472Ff29",
  },
  {
    repo: "AAStarCommunity/airaccount-contract",
    relationship:
      "COLLABORATOR — on-chain CONSUMER of node's aggregated BLS sig (AAStarBLSAlgorithm.validate)",
    version: "v0.19.0-beta.2",
    addressLabel: "BLSAlgorithm",
    address: "0x68c381Ad3A2e3380F22840008027E9Ec2783F43A",
  },
  {
    repo: "AAStarCommunity/AirAccount",
    relationship:
      "UPSTREAM — KMS produces account owner secp256k1 sig (ownerAuth) Stage-1 verifies; C1 binding",
    version: "v0.23.0",
    addressLabel: null, // KMS/TA — no on-chain contract this node binds to
    address: null,
  },
];

function ghField(repo, field) {
  try {
    return execSync(`gh release view --repo ${repo} --json ${field} -q .${field}`, {
      stdio: ["ignore", "pipe", "ignore"],
    }).toString();
  } catch {
    return "";
  }
}
const latestTag = repo => ghField(repo, "tagName").trim() || "(unknown)";
function addressFromNotes(repo, label) {
  if (!label) return null;
  const body = ghField(repo, "body");
  const m = body.match(new RegExp(`${label}[^\\n]*?(0x[a-fA-F0-9]{40})`));
  return m ? m[1] : null;
}
async function hasCode(addr) {
  for (const u of RPCS) {
    try {
      const c = await new ethers.JsonRpcProvider(u).getCode(addr);
      return c && c.length > 2;
    } catch {}
  }
  return null;
}

console.log("aNode DVT — upstream/downstream dependency sync\n" + "=".repeat(64));
let drift = false;
for (const d of DEPS) {
  const tag = latestTag(d.repo);
  const curAddr = addressFromNotes(d.repo, d.addressLabel);
  const tagMoved = tag !== "(unknown)" && tag !== d.version;
  const addrMoved = curAddr && d.address && curAddr.toLowerCase() !== d.address.toLowerCase();
  let live = "—";
  if (d.address) {
    const present = await hasCode(curAddr || d.address);
    live = present === null ? "rpc-unavailable" : present ? "✅ code present" : "❌ no code";
    if (present === false) drift = true;
  }
  if (tagMoved || addrMoved) drift = true;
  console.log(`\n▸ ${d.repo}`);
  console.log(`  ${d.relationship}`);
  console.log(`  version : pinned ${d.version}  | latest ${tag}  ${tagMoved ? "⚠️ MOVED" : "✓"}`);
  if (d.addressLabel) {
    console.log(`  ${d.addressLabel} : pinned  ${d.address}`);
    console.log(
      `            current ${curAddr || "(unparsed)"}  ${addrMoved ? "⚠️ REDEPLOYED — update pin + re-register nodes" : "✓"}  | on-chain ${live}`
    );
  }
}
console.log("\n" + "=".repeat(64));
console.log(
  drift
    ? "⚠️ DRIFT — review/adapt before release (see ⚠️ above)."
    : "✅ All dependencies aligned with the integrated baseline."
);
process.exit(drift ? 1 : 0);
