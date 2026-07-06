// Generate a fresh INDEPENDENT DVT node identity into ./node_state.json (cwd).
//
// Every deployment must run its own node on its OWN BLS12-381 key — a shared/committed
// key lets anyone impersonate the node. This is the headless (systemd / imx93 board)
// path; the /admin dashboard is the equivalent for a browser deploy.
//
// Usage:
//   node scripts/gen-node-state.mjs [nodeName]
//   NODE_NAME=dvt-community node scripts/gen-node-state.mjs
//
// nodeId derivation matches AAStarValidator.registerWithProof + deploy/onboarding/onboard.mjs:
//   nodeId = keccak256(EIP-2537 G1 pubkey).
// For at-rest encryption, run scripts/encrypt-node-key.mjs afterwards (EIP-2335, KDF=pbkdf2
// recommended on embedded A55 boards) and provide NODE_KEY_PASSPHRASE at runtime.

import { bls12_381 as bls } from "@noble/curves/bls12-381.js";
import { ethers } from "ethers";
import { existsSync, writeFileSync } from "fs";
import { randomBytes } from "crypto";
import { join } from "path";

const sigs = bls.longSignatures;
const STATE = join(process.cwd(), "node_state.json");

if (existsSync(STATE)) {
  console.error(`‼ ${STATE} already exists — refusing to overwrite an existing key.`);
  console.error("  Remove it first if you really mean to mint a new identity.");
  process.exit(1);
}

// EIP-2537 G1 wire encoding (128 bytes: each Fp padded to 64 = 16 zero + 48). Matches the
// contract, src/utils/bls.util.ts, and deploy/onboarding/onboard.mjs.
const _fp = x => {
  const s = x.toString(16).padStart(96, "0");
  const b = new Uint8Array(48);
  for (let i = 0; i < 48; i++) b[i] = parseInt(s.substr(i * 2, 2), 16);
  return b;
};
const eip2537G1 = point => {
  const a = point.toAffine();
  const r = new Uint8Array(128);
  r.set(_fp(a.x), 16);
  r.set(_fp(a.y), 80);
  return "0x" + Buffer.from(r).toString("hex");
};

// Fresh scalar (retry until it is a valid, non-zero BLS private key).
let sk;
do {
  sk = randomBytes(32);
  try {
    sigs.getPublicKey(sk);
    break;
  } catch {}
} while (true);

const pubPoint = sigs.getPublicKey(sk);
const publicKey = pubPoint.toHex(); // 48-byte compressed G1
const nodeId = ethers.keccak256(eip2537G1(pubPoint)); // = registerWithProof's nodeId
const nodeName = process.env.NODE_NAME || process.argv[2] || "dvt-community";

writeFileSync(
  STATE,
  JSON.stringify(
    {
      nodeId,
      nodeName,
      privateKey: "0x" + Buffer.from(sk).toString("hex"),
      publicKey,
      createdAt: new Date().toISOString(),
      description: "Independent DVT signing node",
    },
    null,
    2
  ),
  "utf8"
);

console.log(`✔ wrote ${STATE}`);
console.log(`  nodeId   = ${nodeId}`);
console.log(`  nodeName = ${nodeName}`);
console.log(
  "  next: (optional) scripts/encrypt-node-key.mjs to encrypt at rest, then start the node."
);
