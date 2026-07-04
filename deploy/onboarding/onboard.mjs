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
  const nodeId = "0x" + randomBytes(32).toString("hex");
  const publicKey = sigs.getPublicKey(sk).toHex();
  writeFileSync(
    STATE,
    JSON.stringify(
      {
        nodeId,
        nodeName: "dvt-community",
        privateKey: "0x" + Buffer.from(sk).toString("hex"),
        publicKey,
        createdAt: new Date().toISOString(),
        description: "community DVT node",
      },
      null,
      2
    )
  );
  ok(`generated ${STATE}`);
  info(`nodeId=${nodeId}`);
  warn("this file holds your SECRET key — never commit/share it. Encrypt it: docs/KEYSTORE.md");
  return { nodeId, publicKey };
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
  verify: () => verify(arg),
  all: async () => {
    keygen();
    registerRequest();
    console.log("\n(after AAStar registers you and you've deployed + set GOSSIP_* envs:)");
    await verify(arg);
  },
};

(main[cmd] || (() => die(`unknown command '${cmd ?? ""}'. See the header for usage.`)))();
