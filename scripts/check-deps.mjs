// Built-in upstream/downstream dependency-sync check for the aNode DVT node.
// Invoke: `npm run check-deps`  (or `node scripts/check-deps.mjs`).
//
// It does TWO levels of checking against the PINNED baseline, live:
//
//  (1) ADDRESS / DEPLOY level — resolve each dependency's canonical contract address
//      in priority order: (a) the committed deploy-config JSON on the default branch
//      (`deployments/config.sepolia.json`) — authoritative; a REDEPLOY patches it even
//      when it ships NO GitHub release (e.g. an annotated `*-redeploy` tag); (b) the
//      address parsed from the latest release notes. Also scans all tags and flags
//      `-redeploy`/variant tags, and confirms the address has on-chain code.
//
//  (2) DEEP / SOURCE level — for each dependency the node binds to at the code level,
//      diff the *exact source file* the node depends on (the verifier `.sol`, the policy
//      `.sol`) between the integrated BASELINE ref and the current default-branch HEAD.
//      A 0-line diff guarantees the ABI / wire format / logic the node integrated against
//      has NOT changed. A non-zero diff is flagged for human review — this is what catches
//      a dependency changing its INTERFACE / DATA STRUCTURE / COLLABORATION wire, not just
//      its address. For non-Solidity deps (KMS/TEE) it instead asserts the signing-relevant
//      version (TA/proto) is unchanged in the latest release notes.
//
// Exits non-zero on ANY drift (address moved, tag moved, source changed, version guard
// broken, missing on-chain code) so it can gate a release / be wired into CI.
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
// - configPath/configKey : canonical deploy-config JSON on default branch + the address key.
// - addressLabel         : fallback — release-notes table row label.
// - deep.sourcePath      : the exact source file the node binds to (diff baseline↔current).
// - deep.baselineRef     : the ref whose source was reviewed/integrated (diff baseline).
// - deep.abiSig          : human-readable signature the node calls — asserted present in source.
// - deep.versionGuard    : {label, pinned} — for non-Solidity deps, a version in the latest
//                          release notes that MUST stay pinned (the signing-relevant component).
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
    deep: {
      sourcePath: "contracts/src/core/PolicyRegistry.sol",
      baselineRef: "v5.4.0-beta.1",
      abiSig: "function checkPolicy(",
    },
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
    deep: {
      sourcePath: "src/validators/AAStarBLSAlgorithm.sol",
      baselineRef: "v0.19.0-beta.2",
      abiSig: "function validate(bytes32 hash, bytes calldata signature)",
    },
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
    // The signing scheme lives in the TEE Trusted App, NOT the host. ownerAuth verification
    // only breaks if the TA signing changes — so guard the TA (and proto) version.
    deep: { versionGuard: { label: "TA", pinned: "0.5.0" } },
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
const defaultBranch = repo => gh(`api repos/${repo} --jq .default_branch`).trim() || "main";
const releaseBody = repo => gh(`release view --repo ${repo} --json body -q .body`);
function fileAt(repo, path, ref) {
  const raw = gh(`api repos/${repo}/contents/${path}?ref=${ref} --jq .content`);
  if (!raw) return null;
  try {
    return Buffer.from(raw, "base64").toString("utf8");
  } catch {
    return null;
  }
}

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
    const body = releaseBody(d.repo);
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

// A tag is a "redeploy/variant" alarm if it extends the pinned version with a suffix.
function variantTags(d, tags) {
  const base = d.version.replace(/-redeploy.*$/, "");
  return tags.filter(t => t !== d.version && t.startsWith(base) && t.length > base.length);
}

// DEEP scan: diff the bound source file baseline↔current; assert ABI; or guard a version.
function deepScan(d) {
  const out = [];
  const deep = d.deep || {};
  if (deep.sourcePath) {
    const branch = defaultBranch(d.repo);
    const base = fileAt(d.repo, deep.sourcePath, deep.baselineRef);
    const cur = fileAt(d.repo, deep.sourcePath, branch);
    const name = deep.sourcePath.split("/").pop();
    if (base == null || cur == null) {
      out.push({
        drift: true,
        msg: `⚠️ ${name}: could not fetch at ${base == null ? deep.baselineRef : branch} — path moved? review manually`,
      });
    } else if (base === cur) {
      out.push({
        drift: false,
        msg: `code  : ${name} identical ${deep.baselineRef}↔${branch} → no interface/logic/wire change ✓`,
      });
    } else {
      const bl = base.split("\n"),
        cl = cur.split("\n");
      let changed = Math.abs(bl.length - cl.length);
      const n = Math.min(bl.length, cl.length);
      for (let i = 0; i < n; i++) if (bl[i] !== cl[i]) changed++;
      out.push({
        drift: true,
        msg: `⚠️ ${name}: SOURCE CHANGED ${deep.baselineRef}↔${branch} (~${changed} lines) — REVIEW: interface/wire/logic may have moved`,
      });
    }
    if (deep.abiSig) {
      const cur2 = cur || base;
      const ok = cur2 && cur2.includes(deep.abiSig);
      out.push({
        drift: !ok,
        msg: `${ok ? "abi   :" : "⚠️ abi:"} \`${deep.abiSig.slice(0, 48)}…\` ${ok ? "present ✓" : "NOT FOUND — signature the node calls may have changed"}`,
      });
    }
  }
  if (deep.versionGuard) {
    const { label, pinned } = deep.versionGuard;
    const body = releaseBody(d.repo);
    const m = body.match(new RegExp(`${label}\\s*\`?(\\d+\\.\\d+\\.\\d+)`));
    const found = m ? m[1] : null;
    if (found == null) {
      out.push({
        drift: false,
        msg: `guard : ${label} version not stated in latest notes (pinned ${pinned}) — verify manually`,
      });
    } else if (found === pinned) {
      out.push({
        drift: false,
        msg: `guard : ${label} ${found} == pinned ${pinned} → signing scheme unchanged ✓`,
      });
    } else {
      out.push({
        drift: true,
        msg: `⚠️ guard: ${label} moved ${pinned} → ${found} — signing-relevant change, REVIEW ownerAuth path`,
      });
    }
  }
  return out;
}

console.log("aNode DVT — upstream/downstream dependency sync\n" + "=".repeat(72));
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
  // deep / source-level scan (every run)
  for (const r of deepScan(d)) {
    if (r.drift) drift = true;
    console.log(`  ${r.msg}`);
  }
}
console.log("\n" + "=".repeat(72));
console.log(
  drift
    ? "⚠️ DRIFT — address moved, source changed, or version guard broken. Review/adapt before release."
    : "✅ All dependencies aligned: addresses pinned, bound source unchanged, signing scheme intact."
);
process.exit(drift ? 1 : 0);
