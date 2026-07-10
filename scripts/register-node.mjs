#!/usr/bin/env node
// Automated, IDEMPOTENT on-chain registration for a DVT node on AAStarValidator.
// Re-running is always safe: it no-ops the moment the node is registered.
//
//   ETH_RPC_URL=… VALIDATOR_CONTRACT_ADDRESS=0x… OPERATOR_PRIVATE_KEY=0x… \
//     node scripts/register-node.mjs [--node-state ./node_state.json] [--dry-run]
//
// It reads the validator's mode and does the right thing:
//   • requireStake == false (bootstrap)  → owner calls registerPublicKey(nodeId, pubkey)
//   • requireStake == true  (staked)     → staked operator calls
//        registerWithProof(pubkey, popPoint, popSig)  with a BLS proof-of-possession.
//
// The PoP needs the node's BLS private key:
//   • local-key node_state (has privateKey)      → PoP computed here.
//   • key-less (KMS-TEE) node_state (no key)      → PoP signed by the KMS TEE over
//     RUST_SIGNER_URL (POST /pop {node_id, pop_point} → {pop_sig}); if the KMS has no
//     /pop endpoint yet the script stops with the exact cross-repo ask (never a silent fail).
//
// Prereqs it CHECKS (and reports precisely, so a re-run after fixing them just works):
//   • operator funded with gas • operator staked (ROLE_DVT + minStake) in staked mode
//   • operator has no other node (contract enforces one node per operator in staked mode).
import { readFileSync, existsSync } from "fs";
import { execFileSync } from "child_process";
import { bls12_381 as bls } from "@noble/curves/bls12-381.js";
import { ethers } from "ethers";

const sigs = bls.longSignatures;
const args = process.argv.slice(2);
const flag = n => args.includes(n);
const opt = (n, d) => {
  const i = args.indexOf(n);
  return i >= 0 && args[i + 1] ? args[i + 1] : d;
};
const die = m => {
  console.error(`\n‼ ${m}`);
  process.exit(1);
};
const ok = m => console.log(`✅ ${m}`);
const info = m => console.log(`•  ${m}`);

// PoP domain. Aligned with the PRODUCTION signer stack — SDK core buildDvtPop + the KMS-TEE /
// Rust signer golden vectors (@aastar/sdk 0.42.0, CC-36/CC-37): the PoP is signed under the same
// suite DST as normal signing. The on-chain contract is DST-agnostic (registerWithProof takes
// popPoint as a free calldata param and only pairing-checks popSig = sk·popPoint), so any DST
// passes — BUT a KMS-TEE node's PoP is produced by KMS /pop, which uses THIS DST, so the popPoint
// we derive here must match it. (The Solidity KAT in AAStarValidatorStakeBinding.t.sol still uses
// the old AASTAR_DVT_POP_ vectors — self-consistent + still pass, since the contract is DST-agnostic.)
const POP_DST = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

// EIP-2537 wire encodings (G1 = 128B, G2 = 256B; each Fp padded 16-zero+48). Matches the contract.
const _fp = x => {
  const s = x.toString(16).padStart(96, "0");
  const b = new Uint8Array(48);
  for (let i = 0; i < 48; i++) b[i] = parseInt(s.substr(i * 2, 2), 16);
  return b;
};
const eip2537G1 = p => {
  const a = p.toAffine();
  const r = new Uint8Array(128);
  r.set(_fp(a.x), 16);
  r.set(_fp(a.y), 80);
  return "0x" + Buffer.from(r).toString("hex");
};
const eip2537G2 = p => {
  const a = p.toAffine();
  const r = new Uint8Array(256);
  r.set(_fp(a.x.c0), 16);
  r.set(_fp(a.x.c1), 80);
  r.set(_fp(a.y.c0), 144);
  r.set(_fp(a.y.c1), 208);
  return "0x" + Buffer.from(r).toString("hex");
};

// Solidity signatures for the two register paths (used by the `cast send` broadcast path).
const REGISTER_SIGS = {
  registerPublicKey: "registerPublicKey(bytes32,bytes)",
  registerWithProof: "registerWithProof(bytes,bytes,bytes)",
};

// Load a dotenv-style deploy config (e.g. deploy/.env.testnet) — fills MISSING vars only, so an
// explicit env/CLI value always wins. Lets "deployed 资料" supply the operator + RPC + validator.
function loadEnvFile(path) {
  if (!existsSync(path)) die(`--env-file not found: ${path}`);
  for (const line of readFileSync(path, "utf8").split("\n")) {
    const m = line.match(/^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/);
    if (m && process.env[m[1]] === undefined) {
      process.env[m[1]] = m[2].replace(/\s*#.*$/, "").trim().replace(/^["']|["']$/g, "");
    }
  }
}

const VALIDATOR_ABI = [
  "function isRegistered(bytes32) view returns (bool)",
  "function requireStake() view returns (bool)",
  "function owner() view returns (address)",
  "function registry() view returns (address)",
  "function minStake() view returns (uint256)",
  "function ROLE_DVT() view returns (bytes32)",
  "function operatorNode(address) view returns (bytes32)",
  "function registerPublicKey(bytes32 nodeId, bytes publicKey)",
  "function registerWithProof(bytes publicKey, bytes popPoint, bytes popSig)",
];
const REGISTRY_ABI = [
  "function hasRole(bytes32,address) view returns (bool)",
  "function getEffectiveStake(address,bytes32) view returns (uint256)",
];

// --- load the node identity (works for local-key AND key-less KMS-TEE node_state) -----------
function loadNode(path) {
  if (!existsSync(path)) die(`node_state not found: ${path} (--node-state to point elsewhere)`);
  const s = JSON.parse(readFileSync(path, "utf8"));
  if (!s.publicKey) die(`${path} has no publicKey`);
  // publicKey is compressed 48B G1; expand to the 128B EIP-2537 wire the contract wants.
  let point;
  try {
    point = bls.G1.Point.fromHex(s.publicKey.replace(/^0x/, ""));
  } catch (e) {
    die(`bad publicKey in ${path}: ${e.message}`);
  }
  const pubEip2537 = s.publicKeyEip2537 || eip2537G1(point);
  const nodeId = ethers.keccak256(pubEip2537); // contract derives nodeId = keccak256(pubkey)
  if (s.nodeId && s.nodeId.toLowerCase() !== nodeId.toLowerCase()) {
    die(`nodeId mismatch: state=${s.nodeId} derived=${nodeId}`);
  }
  return { nodeId, pubEip2537, privateKey: s.privateKey, keyless: !s.privateKey };
}

// --- proof-of-possession: popPoint = hashToCurve(PUBLICKEY, POP_DST); popSig = sk · popPoint.
// Hashing the PUBLIC KEY (not the operator) under this DST matches SDK core buildDvtPop + the KMS
// /pop TEE golden (CC-36/CC-37), so a PoP is byte-identical however it is produced. The contract is
// message/DST-agnostic (popPoint is a free calldata param; the pairing only checks popSig=sk·popPoint).
async function buildPoP(node) {
  const pubBytes = ethers.getBytes(node.pubEip2537);
  if (!node.keyless) {
    const popPointPt = await bls.G2.hashToCurve(pubBytes, { DST: POP_DST });
    const sk = Uint8Array.from(Buffer.from(node.privateKey.replace(/^0x/, ""), "hex"));
    return { popPoint: eip2537G2(popPointPt), popSig: eip2537G2(await sigs.sign(popPointPt, sk)) };
  }
  // Key-less (KMS-TEE): the BLS key is sealed in the TEE. KMS /pop (CC-37) derives popPoint =
  // hashToCurve(publicKey) AND signs it in the TEE, returning both — we never touch the key.
  const url = process.env.RUST_SIGNER_URL;
  if (!url) {
    die(
      "key-less node (KMS-TEE) but RUST_SIGNER_URL not set — the PoP must be produced by the KMS TEE.\n" +
        "  Set RUST_SIGNER_URL (+ RUST_SIGNER_TOKEN); KMS must expose POST /pop (CC-37):\n" +
        "  { node_id | publicKey } → { publicKey, popPoint, popSig }. Until CC-37 lands, register a\n" +
        "  KMS-TEE node via SDK onboardDvtNode's popSigner (same /pop)."
    );
  }
  const headers = { "content-type": "application/json" };
  if (process.env.RUST_SIGNER_TOKEN) headers["X-Signer-Token"] = process.env.RUST_SIGNER_TOKEN;
  const res = await fetch(`${url.replace(/\/+$/, "")}/pop`, {
    method: "POST",
    headers,
    body: JSON.stringify({ node_id: node.nodeId, publicKey: node.pubEip2537 }),
    signal: AbortSignal.timeout(8000),
  }).catch(e => die(`KMS /pop request failed: ${e.message}`));
  if (!res.ok) die(`KMS /pop returned HTTP ${res.status}. If 404, KMS has no /pop yet (CC-37 pending).`);
  const { popPoint, popSig } = await res.json(); // CC-37 shape: { publicKey, popPoint, popSig }
  if (!popPoint || !popSig) die("KMS /pop response missing popPoint/popSig (expected CC-37 shape)");
  return { popPoint, popSig };
}

async function main() {
  const envFile = opt("--env-file", process.env.REGISTER_ENV_FILE);
  if (envFile) loadEnvFile(envFile); // must run BEFORE reading any env var below
  const rpc = process.env.ETH_RPC_URL || die("set ETH_RPC_URL");
  const validatorAddr = process.env.VALIDATOR_CONTRACT_ADDRESS || die("set VALIDATOR_CONTRACT_ADDRESS");
  const dryRun = flag("--dry-run");
  const node = loadNode(opt("--node-state", process.env.NODE_STATE_FILE || "./node_state.json"));
  info(`nodeId ${node.nodeId} (${node.keyless ? "key-less / KMS-TEE" : "local key"})`);

  const provider = new ethers.JsonRpcProvider(rpc);
  const readV = new ethers.Contract(validatorAddr, VALIDATOR_ABI, provider);

  // IDEMPOTENT: already registered → done, no tx.
  if (await readV.isRegistered(node.nodeId)) return ok(`already registered on-chain — nothing to do`);

  const [requireStake, owner, registryAddr, minStake, roleDvt] = await Promise.all([
    readV.requireStake(),
    readV.owner(),
    readV.registry(),
    readV.minStake(),
    readV.ROLE_DVT(),
  ]);
  info(`validator: requireStake=${requireStake} owner=${owner} minStake=${ethers.formatEther(minStake)} GToken`);

  // --- resolve the operator address (for PoP + stake check) + how to broadcast. Signer sources:
  //   • --cast (or SIGNER=cast): sign+send via Foundry `cast send` — keystore/account/ledger/pk via
  //     CAST_WALLET_ARGS (e.g. "--account dvt-op", "--keystore ks.json --password …", "--ledger").
  //     Operator address from OPERATOR_ADDRESS or `cast wallet address $CAST_WALLET_ARGS`.
  //   • OPERATOR_PRIVATE_KEY / ETH_PRIVATE_KEY: raw key → ethers.Wallet.
  //   • --keystore <json> (+ OPERATOR_KEYSTORE_PASSWORD): encrypted keystore → ethers.
  const useCast = flag("--cast") || process.env.SIGNER === "cast";
  let operator, broadcast;
  if (useCast) {
    const castArgs = (process.env.CAST_WALLET_ARGS || "").trim().split(/\s+/).filter(Boolean);
    if (!castArgs.length && !process.env.OPERATOR_ADDRESS) {
      die('--cast needs CAST_WALLET_ARGS (e.g. "--account dvt-op" / "--keystore ks.json" / "--ledger")');
    }
    operator = ethers.getAddress(
      process.env.OPERATOR_ADDRESS ||
        execFileSync("cast", ["wallet", "address", ...castArgs], { encoding: "utf8" }).trim()
    );
    broadcast = (method, argv) => {
      const cmd = ["send", validatorAddr, REGISTER_SIGS[method], ...argv, "--rpc-url", rpc, ...castArgs];
      info(`+ cast ${cmd.join(" ")}`);
      execFileSync("cast", cmd, { stdio: "inherit" }); // cast signs + waits + prints its own receipt
      return null;
    };
  } else {
    const pk = process.env.OPERATOR_PRIVATE_KEY || process.env.ETH_PRIVATE_KEY;
    const ksPath = opt("--keystore", process.env.OPERATOR_KEYSTORE);
    let wallet;
    if (pk) {
      wallet = new ethers.Wallet(pk, provider);
    } else if (ksPath) {
      const pw = process.env.OPERATOR_KEYSTORE_PASSWORD || die("set OPERATOR_KEYSTORE_PASSWORD for --keystore");
      wallet = (await ethers.Wallet.fromEncryptedJson(readFileSync(ksPath, "utf8"), pw)).connect(provider);
    } else {
      die("no signer — set OPERATOR_PRIVATE_KEY / ETH_PRIVATE_KEY, or --keystore <json>, or --cast (+ CAST_WALLET_ARGS)");
    }
    operator = wallet.address;
    const v = readV.connect(wallet);
    broadcast = async (method, argv) => {
      const tx = await v[method](...argv);
      info(`tx ${tx.hash} — waiting for confirmation`);
      return tx.wait();
    };
  }
  info(`operator (tx sender): ${operator}${useCast ? " (via cast)" : ""}`);

  // Resolve the method + args ONCE (so --dry-run and the real send use the same PoP — no double
  // KMS /pop call), then either static-call (preflight) or broadcast.
  let method, methodArgs;
  if (!requireStake) {
    // Bootstrap mode: owner-only, no PoP.
    if (operator.toLowerCase() !== owner.toLowerCase()) {
      die(`bootstrap mode: only the validator owner (${owner}) can register. Use its key.`);
    }
    info("bootstrap mode → registerPublicKey(nodeId, pubkey)");
    method = "registerPublicKey";
    methodArgs = [node.nodeId, node.pubEip2537];
  } else {
    // Staked mode: operator must be staked + have no other node, and provide a PoP.
    const reg = new ethers.Contract(registryAddr, REGISTRY_ABI, provider);
    const [hasRole, stake, existingNode] = await Promise.all([
      reg.hasRole(roleDvt, operator),
      reg.getEffectiveStake(operator, roleDvt),
      readV.operatorNode(operator),
    ]);
    if (!hasRole || stake < minStake) {
      die(
        `operator ${operator} is NOT staked for ROLE_DVT.\n` +
          `  hasRole=${hasRole}  effectiveStake=${ethers.formatEther(stake)} / need ${ethers.formatEther(minStake)} GToken.\n` +
          `  Stake first in the SuperPaymaster Registry (${registryAddr}): registerRole(ROLE_DVT) + lock ≥ minStake,\n` +
          `  then re-run this script (idempotent).`
      );
    }
    if (existingNode !== ethers.ZeroHash) {
      die(`operator ${operator} already anchors node ${existingNode} (one node per operator in staked mode).`);
    }
    info("staked mode → building BLS proof-of-possession");
    const { popPoint, popSig } = await buildPoP(node);
    ok("PoP built");
    method = "registerWithProof";
    methodArgs = [node.pubEip2537, popPoint, popSig];
  }

  if (dryRun) {
    // Preflight against the real contract with the operator as msg.sender — no key needed, no tx.
    await readV[method].staticCall(...methodArgs, { from: operator });
    return ok("dry-run: static call passed — a real run would register. No tx sent.");
  }

  info("sending register tx…");
  const rc = await broadcast(method, methodArgs);
  if (await readV.isRegistered(node.nodeId)) {
    ok(`registered on-chain${rc?.blockNumber ? " in block " + rc.blockNumber : ""} ✅`);
  } else {
    die("tx sent but isRegistered still false — check the validator");
  }
}

main().catch(e => die(e.shortMessage || e.message || String(e)));
