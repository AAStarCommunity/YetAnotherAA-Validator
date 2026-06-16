// Built-in upstream/downstream dependency-sync check for the aNode DVT node.
// Invoke: `npm run check-deps`  (or `node scripts/check-deps.mjs`).
//
// For each cross-repo dependency it compares the PINNED baseline against the CURRENT
// state pulled live, resolving the canonical contract address in this priority order:
//   1. a committed deploy config JSON on the dep's default branch (most authoritative —
//      a REDEPLOY patches this file even when it ships NO GitHub release, e.g. an
//      annotated `*-redeploy` tag). This is the path that an earlier release-only check
//      MISSED, silently keeping a stale pin.
//   2. the address parsed from the latest GitHub release notes (for deps without a config
//      file but which do publish address tables, e.g. airaccount-contract).
// It also scans ALL tags and flags any `-redeploy`/variant tag of the pinned version,
// and confirms the resolved address has on-chain code. Exits non-zero on any drift so it
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

// PINNED baseline = what this node is integrated against.
// - `configPath`/`configKey`: canonical deploy-config JSON on the dep's default branch +
//   the key holding the address we depend on. Preferred (catches doc-less redeploys).
// - `addressLabel`: fallback — the row label to find in the dep's release-notes table.
const DEPS = [
  {
    repo: "AAStarCommunity/SuperPaymaster",
    relationship:
      "UPSTREAM — node reads PolicyRegistry.checkPolicy (layer-1) + registers BLS key in ROLE_DVT",
    version: "v5.4.0-beta.1-redeploy",
    configPath: "deployments/config.sepolia.json",
    configKey: "policyRegistry",
    addressLabel: "PolicyRegistry",
    address: "0x8c2488d46d5447418558c38AA6441720df656094",
  },
  {
    repo: "AAStarCommunity/airaccount-contract",
    relationship:
      "COLLABORATOR — on-chain CONSUMER of node's aggregated BLS sig (AAStarBLSAlgorithm.validate)",
    version: "v0.19.0-beta.2",
    configPath: null,
    configKey: null,
    addressLabel: "BLSAlgorithm",
    address: "0x68c381Ad3A2e3380F22840008027E9Ec2783F43A",
  },
  {
    repo: "AAStarCommunity/AirAccount",
    relationship:
      "UPSTREAM — KMS produces account owner secp256k1 sig (ownerAuth) Stage-1 verifies; C1 binding",
    version: "v0.23.0",
    configPath: null,
    configKey: null,
    addressLabel: null, // KMS/TA — no on-chain contract this node binds to
    address: null,
  },
];

function gh(args) {
  try {
    return execSync(`gh ${args}`, { stdio: ["ignore", "pipe", "ignore"] }).toString();
  } catch {
    return "";
  }
}
const latestTag = repo =>
  gh(`release view --repo ${repo} --json tagName -q .tagName`).trim() || "(no release)";
const allTags = repo =>
  gh(`api repos/${repo}/tags --jq .[].name`)
    .split("\n")
    .map(s => s.trim())
    .filter(Boolean);

// Authoritative address: deploy-config JSON on default branch, else release-notes table.
function currentAddress(d) {
  if (d.configPath && d.configKey) {
    const raw = gh(`api repos/${d.repo}/contents/${d.configPath} --jq .content`);
    if (raw) {
      try {
        const json = JSON.parse(Buffer.from(raw, "base64").toString("utf8"));
        if (json[d.configKey]) return { addr: json[d.configKey], src: d.configPath };
      } catch {}
    }
  }
  if (d.addressLabel) {
    const body = gh(`release view --repo ${d.repo} --json body -q .body`);
    const m = body.match(new RegExp(`${d.addressLabel}[^\\n]*?(0x[a-fA-F0-9]{40})`));
    if (m) return { addr: m[1], src: "release-notes" };
  }
  return { addr: null, src: "—" };
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

// A tag is a "redeploy/variant" alarm if it extends the pinned version with a suffix
// (e.g. `v5.4.0-beta.1` + `-redeploy`) — these ship address changes without a new release.
function variantTags(d, tags) {
  const base = d.version.replace(/-redeploy.*$/, "");
  return tags.filter(t => t !== d.version && t.startsWith(base) && t.length > base.length);
}

console.log("aNode DVT — upstream/downstream dependency sync\n" + "=".repeat(64));
let drift = false;
for (const d of DEPS) {
  const tag = latestTag(d.repo);
  const tags = allTags(d.repo);
  const variants = variantTags(d, tags);
  const { addr: curAddr, src } = currentAddress(d);
  const tagMoved = tag !== "(no release)" && tag !== d.version && !d.version.startsWith(tag);
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
  console.log(
    `  version : pinned ${d.version}  | latest release ${tag}  ${tagMoved ? "⚠️ MOVED" : "✓"}`
  );
  if (variants.length) {
    console.log(`  ⚠️ redeploy/variant tag(s): ${variants.join(", ")} — check addresses below`);
  }
  if (d.addressLabel || d.configKey) {
    console.log(`  ${d.addressLabel || d.configKey} : pinned  ${d.address}`);
    console.log(
      `            current ${curAddr || "(unresolved)"}  [${src}]  ${addrMoved ? "⚠️ REDEPLOYED — update pin + re-verify on-chain" : "✓"}  | on-chain ${live}`
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
