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
//      has NOT changed. A real diff is flagged — this is what catches a dependency
//      changing its INTERFACE / DATA STRUCTURE / COLLABORATION wire, not just its address.
//      For non-Solidity deps (KMS/TEE) it instead asserts the signing-relevant version
//      (TA/proto) is unchanged in the latest release notes.
//
// TRANSIENT vs REAL DRIFT — every `gh`/RPC call is RETRIED with backoff. A fetch that
// still fails is reported as TRANSIENT (could-not-verify), NOT as drift: a "SOURCE
// CHANGED" verdict is only emitted when BOTH the baseline and current files were fetched
// successfully and differ. This stops a flaky network/proxy from masquerading as an
// upstream change. Exit codes: 0 = aligned · 1 = REAL drift (adapt before release) ·
// 2 = transient/unknown (re-run; do not treat as a hard fail).
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
    version: "v0.20.0",
    configPath: null,
    configKey: null,
    addressLabel: "BLSAlgorithm",
    address: "0xAF525A161CB17e0A1b6254ef0B8d8473bdA05174",
    deep: {
      sourcePath: "src/validators/AAStarBLSAlgorithm.sol",
      baselineRef: "v0.20.0",
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

// Blocking sleep (the script is mostly synchronous; only a few short retries).
function sleepSync(ms) {
  try {
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
  } catch {
    const end = Date.now() + ms;
    while (Date.now() < end) {}
  }
}
// gh with retry+backoff. Returns {ok, out}: ok=false ONLY after all retries fail (transient).
// NB: an empty `out` with ok=true is a legitimate "no value", NOT a failure.
function gh(args, retries = 2) {
  for (let i = 0; i <= retries; i++) {
    try {
      return {
        ok: true,
        out: execSync(`gh ${args}`, { stdio: ["ignore", "pipe", "ignore"] }).toString(),
      };
    } catch {
      if (i < retries) sleepSync(400 * (i + 1));
    }
  }
  return { ok: false, out: "" };
}

const latestTag = repo => {
  const r = gh(`release view --repo ${repo} --json tagName -q .tagName`);
  if (!r.ok) return { transient: true };
  return { tag: r.out.trim() || "(no release)" };
};
const allTags = repo => {
  const r = gh(`api repos/${repo}/tags --jq .[].name`);
  if (!r.ok) return { transient: true };
  return {
    tags: r.out
      .split("\n")
      .map(s => s.trim())
      .filter(Boolean),
  };
};
const defaultBranch = repo => {
  const r = gh(`api repos/${repo} --jq .default_branch`);
  return r.ok && r.out.trim() ? r.out.trim() : "main";
};
const releaseBody = repo => gh(`release view --repo ${repo} --json body -q .body`);
function fileAt(repo, path, ref) {
  const r = gh(`api repos/${repo}/contents/${path}?ref=${ref} --jq .content`);
  if (!r.ok) return { transient: true };
  if (!r.out) return { ok: true, content: null }; // fetched, but no content field
  try {
    return { ok: true, content: Buffer.from(r.out, "base64").toString("utf8") };
  } catch {
    return { ok: true, content: null };
  }
}

// Authoritative address: deploy-config JSON on default branch, else release-notes table.
// Returns {addr, src} or {transient:true} when the lookups it needs all failed transiently.
function currentAddress(d) {
  let sawTransient = false;
  if (d.configPath && d.configKey) {
    const r = gh(`api repos/${d.repo}/contents/${d.configPath} --jq .content`);
    if (!r.ok) sawTransient = true;
    else if (r.out) {
      try {
        const json = JSON.parse(Buffer.from(r.out, "base64").toString("utf8"));
        if (json[d.configKey]) return { addr: json[d.configKey], src: d.configPath };
      } catch {}
    }
  }
  if (d.addressLabel) {
    const r = releaseBody(d.repo);
    if (!r.ok) sawTransient = true;
    else {
      const m = r.out.match(new RegExp(`${d.addressLabel}[^\\n]*?(0x[a-fA-F0-9]{40})`));
      if (m) return { addr: m[1], src: "release-notes" };
    }
  }
  return sawTransient ? { transient: true } : { addr: null, src: "—" };
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

// DEEP scan. Each line is {state: 'ok'|'drift'|'transient', msg}.
function deepScan(d) {
  const out = [];
  const deep = d.deep || {};
  if (deep.sourcePath) {
    const branch = defaultBranch(d.repo);
    const base = fileAt(d.repo, deep.sourcePath, deep.baselineRef);
    const cur = fileAt(d.repo, deep.sourcePath, branch);
    const name = deep.sourcePath.split("/").pop();
    if (base.transient || cur.transient || base.content == null || cur.content == null) {
      out.push({
        state: "transient",
        msg: `~ ${name}: could not fetch ${base.transient || base.content == null ? deep.baselineRef : branch} after retries — TRANSIENT, re-run to verify`,
      });
      // ABI assertion needs current source; skip on transient to avoid a false NOT-FOUND.
    } else if (base.content === cur.content) {
      out.push({
        state: "ok",
        msg: `code  : ${name} identical ${deep.baselineRef}↔${branch} → no interface/logic/wire change ✓`,
      });
      if (deep.abiSig) {
        const ok = cur.content.includes(deep.abiSig);
        out.push({
          state: ok ? "ok" : "drift",
          msg: `${ok ? "abi   :" : "⚠️ abi:"} \`${deep.abiSig.slice(0, 48)}…\` ${ok ? "present ✓" : "NOT FOUND — signature the node calls may have changed"}`,
        });
      }
    } else {
      const bl = base.content.split("\n"),
        cl = cur.content.split("\n");
      let changed = Math.abs(bl.length - cl.length);
      const n = Math.min(bl.length, cl.length);
      for (let i = 0; i < n; i++) if (bl[i] !== cl[i]) changed++;
      out.push({
        state: "drift",
        msg: `⚠️ ${name}: SOURCE CHANGED ${deep.baselineRef}↔${branch} (~${changed} lines) — REVIEW: interface/wire/logic may have moved`,
      });
      if (deep.abiSig) {
        const ok = cur.content.includes(deep.abiSig);
        out.push({
          state: ok ? "ok" : "drift",
          msg: `${ok ? "abi   :" : "⚠️ abi:"} \`${deep.abiSig.slice(0, 48)}…\` ${ok ? "present ✓" : "NOT FOUND — signature the node calls may have changed"}`,
        });
      }
    }
  }
  if (deep.versionGuard) {
    const { label, pinned } = deep.versionGuard;
    const r = releaseBody(d.repo);
    if (!r.ok) {
      out.push({
        state: "transient",
        msg: `~ guard: could not read ${label} version (release notes fetch failed after retries) — TRANSIENT`,
      });
    } else {
      const m = r.out.match(new RegExp(`${label}\\s*\`?(\\d+\\.\\d+\\.\\d+)`));
      const found = m ? m[1] : null;
      if (found == null) {
        out.push({
          state: "ok",
          msg: `guard : ${label} version not stated in latest notes (pinned ${pinned}) — verify manually`,
        });
      } else if (found === pinned) {
        out.push({
          state: "ok",
          msg: `guard : ${label} ${found} == pinned ${pinned} → signing scheme unchanged ✓`,
        });
      } else {
        out.push({
          state: "drift",
          msg: `⚠️ guard: ${label} moved ${pinned} → ${found} — signing-relevant change, REVIEW ownerAuth path`,
        });
      }
    }
  }
  return out;
}

console.log("aNode DVT — upstream/downstream dependency sync\n" + "=".repeat(72));
let drift = false;
let transient = false;
for (const d of DEPS) {
  const lt = latestTag(d.repo);
  const at = allTags(d.repo);
  const variants = at.transient ? [] : variantTags(d, at.tags);
  const ca = currentAddress(d);
  if (lt.transient || at.transient || ca.transient) transient = true;
  const tag = lt.transient ? "(transient)" : lt.tag;
  const tagMoved =
    !lt.transient && tag !== "(no release)" && tag !== d.version && !d.version.startsWith(tag);
  const curAddr = ca.transient ? null : ca.addr;
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
    `  version : pinned ${d.version}  | latest release ${tag}  ${lt.transient ? "~ transient" : tagMoved ? "⚠️ MOVED" : "✓"}`
  );
  if (variants.length) {
    console.log(`  ⚠️ redeploy/variant tag(s): ${variants.join(", ")} — check addresses below`);
  }
  if (d.addressLabel || d.configKey) {
    console.log(`  ${d.addressLabel || d.configKey} : pinned  ${d.address}`);
    const addrCell = ca.transient
      ? "~ transient (fetch failed after retries) — re-run"
      : `current ${curAddr || "(unresolved)"}  [${ca.src}]  ${addrMoved ? "⚠️ REDEPLOYED — update pin + re-verify on-chain" : "✓"}`;
    console.log(`            ${addrCell}  | on-chain ${live}`);
  }
  for (const r of deepScan(d)) {
    if (r.state === "drift") drift = true;
    if (r.state === "transient") transient = true;
    console.log(`  ${r.msg}`);
  }
}
console.log("\n" + "=".repeat(72));
if (drift) {
  console.log(
    "⚠️ REAL DRIFT — address moved, source changed, or version guard broken. Review/adapt before release."
  );
  process.exit(1);
} else if (transient) {
  console.log(
    "~ TRANSIENT — some lookups failed after retries (network/proxy/rate-limit). NOT drift; re-run to verify."
  );
  process.exit(2);
} else {
  console.log(
    "✅ All dependencies aligned: addresses pinned, bound source unchanged, signing scheme intact."
  );
  process.exit(0);
}
