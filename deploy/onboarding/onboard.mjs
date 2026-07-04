#!/usr/bin/env node
// Community DVT self-onboarding helper (#157). Guides a new operator through the
// automatable parts of standing up an independent node and checks the path is clear.
// See deploy/COMMUNITY_OPERATORS.md for the full story.
//
//   node deploy/onboarding/onboard.mjs keygen                 # step 1: make your key
//   node deploy/onboarding/onboard.mjs register-request       # step 2: what to send AAStar
//   ETH_RPC_URL=… VALIDATOR_CONTRACT_ADDRESS=… \
//     node deploy/onboarding/onboard.mjs wait-register        # poll until registered on-chain
//   node deploy/onboarding/onboard.mjs verify https://dvt.you.org   # steps 4/5: is the path up?
//   node deploy/onboarding/onboard.mjs all  https://dvt.you.org     # run the guided flow
//
// Step 2 (on-chain registration) is owner-coordinated today (registerPublicKey is
// onlyOwner on the deployed validator). This tool generates the request + polls until
// AAStar registers you. When the permissionless PNT-staking path is wired, a `stake`
// subcommand will make step 2 fully self-service too.
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "fs";
import { randomBytes } from "crypto";
import { bls12_381 as bls } from "@noble/curves/bls12-381.js";
import { ethers } from "ethers";

const sigs = bls.longSignatures;
const STATE = process.env.NODE_STATE_FILE || "deploy/node1/node_state.json";
const cmd = process.argv[2];
const arg = process.argv[3];

const ok = m => console.log(`✅ ${m}`);
const info = m => console.log(`•  ${m}`);
const warn = m => console.log(`⚠️  ${m}`);
const die = m => {
  console.error(`‼ ${m}`);
  process.exit(1);
};

function loadState() {
  if (!existsSync(STATE)) return null;
  return JSON.parse(readFileSync(STATE, "utf8"));
}

// PoP domain (must match AAStarValidator's KAT / the contract's expected DST).
const POP_DST = "AASTAR_DVT_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_";

// EIP-2537 encodings (the on-chain wire): G1 = 128 bytes, G2 = 256 bytes, each Fp padded
// to 64 (16 zero + 48). Matches the contract + src/utils/bls.util.ts.
const _fp = x => {
  const s = x.toString(16).padStart(96, "0");
  const b = new Uint8Array(48);
  for (let i = 0; i < 48; i++) b[i] = parseInt(s.substr(i * 2, 2), 16);
  return b;
};
function eip2537G1(point) {
  const a = point.toAffine();
  const r = new Uint8Array(128);
  r.set(_fp(a.x), 16);
  r.set(_fp(a.y), 80);
  return "0x" + Buffer.from(r).toString("hex");
}
function eip2537G2(point) {
  const a = point.toAffine();
  const r = new Uint8Array(256);
  r.set(_fp(a.x.c0), 16);
  r.set(_fp(a.x.c1), 80);
  r.set(_fp(a.y.c0), 144);
  r.set(_fp(a.y.c1), 208);
  return "0x" + Buffer.from(r).toString("hex");
}
// nodeId = keccak256(EIP-2537 G1 pubkey) — matches AAStarValidator.registerWithProof.
const derivedNodeId = eip2537PubHex => ethers.keccak256(eip2537PubHex);

// --- step 1: generate the node's own BLS key ---------------------------------
function keygen() {
  if (existsSync(STATE)) {
    const s = loadState();
    ok(`key already exists (${STATE})`);
    info(`nodeId=${s.nodeId}`);
    return s;
  }
  mkdirSync(STATE.substring(0, STATE.lastIndexOf("/")), { recursive: true });
  let sk;
  do {
    sk = randomBytes(32);
    try {
      sigs.getPublicKey(sk);
      break;
    } catch {}
  } while (true);
  const pubPoint = sigs.getPublicKey(sk);
  const publicKey = pubPoint.toHex();
  const publicKeyEip2537 = eip2537G1(pubPoint);
  // Staked path: nodeId is DERIVED from the pubkey (matches registerWithProof on-chain).
  const nodeId = derivedNodeId(publicKeyEip2537);
  writeFileSync(
    STATE,
    JSON.stringify(
      {
        nodeId,
        nodeName: "dvt-community",
        privateKey: "0x" + Buffer.from(sk).toString("hex"),
        publicKey,
        publicKeyEip2537,
        createdAt: new Date().toISOString(),
        description: "community DVT node",
      },
      null,
      2
    )
  );
  ok(`generated ${STATE}`);
  info(`nodeId=${nodeId}  (= keccak256(EIP-2537 pubkey) — the staked-path nodeId)`);
  warn("this file holds your SECRET key — never commit/share it. Encrypt it: docs/KEYSTORE.md");
  return { nodeId, publicKey, publicKeyEip2537 };
}

// --- staked path: produce the BLS proof-of-possession + registerWithProof params.
// Usage: onboard.mjs pop <operatorAddress>   (the EOA/Safe that stakes + registers)
async function pop() {
  const s = loadState() || die("no key yet — run `keygen` first");
  const operator =
    arg && ethers.isAddress(arg) ? ethers.getAddress(arg) : die("usage: pop <operatorAddress>");
  const sk = Uint8Array.from(Buffer.from(s.privateKey.replace(/^0x/, ""), "hex"));
  const pubHex = s.publicKeyEip2537 || eip2537G1(sigs.getPublicKey(sk));

  // popPoint = hash_to_G2(operatorAddress, POP_DST); popSig = sk * popPoint.
  const msg = ethers.getBytes(operator); // 20-byte address
  const popPoint = await bls.G2.hashToCurve(msg, { DST: POP_DST });
  const popSig = await sigs.sign(popPoint, sk);

  console.log("\n── registerWithProof params (call from your operator EOA/Safe) ──");
  console.log(
    JSON.stringify(
      {
        nodeId: derivedNodeId(pubHex),
        operator,
        publicKey: pubHex,
        popPoint: eip2537G2(popPoint),
        popSig: eip2537G2(popSig),
      },
      null,
      2
    )
  );
  console.log(
    "\nThen (from the operator EOA/Safe): (1) stake GToken + Registry.registerRole(ROLE_DVT)\n" +
      "on SuperPaymaster, (2) AAStarValidator.registerWithProof(publicKey, popPoint, popSig)."
  );
}

// --- step 2: the registration request to hand to AAStar ----------------------
function registerRequest() {
  const s = loadState() || die("no key yet — run `keygen` first");
  console.log("\n── Send this to AAStar (open an issue) to register your node ──");
  console.log(JSON.stringify({ nodeId: s.nodeId, publicKey: s.publicKey }, null, 2));
  console.log("\nOr, once the permissionless PNT-staking path is live: stake, then self-register.");
}

// --- poll the validator until your nodeId is registered on-chain -------------
async function waitRegister() {
  const s = loadState() || die("no key yet — run `keygen` first");
  const rpc = process.env.ETH_RPC_URL || die("set ETH_RPC_URL");
  const addr = process.env.VALIDATOR_CONTRACT_ADDRESS || die("set VALIDATOR_CONTRACT_ADDRESS");
  const c = new ethers.Contract(
    addr,
    ["function isRegistered(bytes32 nodeId) view returns (bool)"],
    new ethers.JsonRpcProvider(rpc)
  );
  info(`polling isRegistered(${s.nodeId}) on ${addr} …`);
  for (;;) {
    let reg = false;
    try {
      reg = await c.isRegistered(s.nodeId);
    } catch (e) {
      warn(`read failed (${e.shortMessage ?? e.message}); retrying`);
    }
    if (reg) return ok("registered on-chain ✅");
    await new Promise(r => setTimeout(r, 15000));
  }
}

// --- verify (steps 4/5): is the node up + on the gossip mesh + fail-closed? ---
async function verify(url) {
  url = (url || die("usage: verify <your node https url>")).replace(/\/+$/, "");
  let pass = true;
  const check = async (name, fn) => {
    try {
      await fn();
      ok(name);
    } catch (e) {
      warn(`${name} — ${e.message}`);
      pass = false;
    }
  };
  const j = async p => {
    const r = await fetch(url + p, { signal: AbortSignal.timeout(8000) });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return r.json();
  };

  await check("health + version", async () => {
    const h = await j("/health");
    info(`version=${h.version} status=${h.status}`);
  });
  await check("node identity", async () => info(`nodeId=${(await j("/node/info")).nodeId}`));
  await check("on the gossip mesh (sees peers)", async () => {
    const g = await j("/gossip/peers");
    const n = g.peers?.length ?? 0;
    info(`${n} peer(s) in roster`);
    if (n < 2) throw new Error("only sees itself — set GOSSIP_BOOTSTRAP_PEERS to a live seed");
  });
  await check("owner-auth gate is fail-closed (403)", async () => {
    const r = await fetch(url + "/signature/sign", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ userOp: {} }),
      signal: AbortSignal.timeout(8000),
    });
    if (r.status !== 403) throw new Error(`expected 403, got ${r.status}`);
  });

  console.log(
    pass
      ? "\n✅ path is clear — your node is up, on the mesh, and fail-closed. Next: a full\n" +
          "   co-sign E2E with the other operators (scripts/e2e/realnode-e2e.mjs)."
      : "\n⚠️  some checks failed — fix the above, then re-run `verify`."
  );
  if (!pass) process.exit(1);
}

const main = {
  keygen,
  "register-request": registerRequest,
  "wait-register": waitRegister,
  pop, // staked path: emit registerWithProof(pubkey, popPoint, popSig) params
  verify: () => verify(arg),
  all: async () => {
    keygen();
    registerRequest();
    console.log("\n(after AAStar registers you and you've deployed + set GOSSIP_* envs:)");
    await verify(arg);
  },
};

(main[cmd] || (() => die(`unknown command '${cmd ?? ""}'. See the header for usage.`)))();
