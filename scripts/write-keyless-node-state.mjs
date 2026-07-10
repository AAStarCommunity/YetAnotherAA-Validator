// Write a KEY-LESS DVT node_state.json (KMS-TEE custody, CC-22/CC-24).
//
// For the co-located KMS-TEE deployment the BLS private key is sealed in the KMS OP-TEE and
// NEVER touches disk. The node boots key-less: node_state.json holds only { nodeId, publicKey }
// and the node signs via RUST_SIGNER_URL (KMS :3100). This script is the DVT-owned handoff so
// the KMS node-setup does NOT have to re-implement DVT's nodeId derivation — feed it the 48-byte
// compressed G1 pubkey that KMS `gen-key` returns, and it writes the exact node_state DVT expects.
//
// Usage (run in the node's working dir, e.g. /opt/dvt-build):
//   node scripts/write-keyless-node-state.mjs 0x<48B-compressed-G1-pubkey> [nodeName]
//
// nodeId derivation is IDENTICAL to gen-node-state.mjs / AAStarValidator.registerWithProof:
//   nodeId = keccak256(EIP-2537 G1 pubkey).   node.service.ts boots this ONLY when
//   RUST_SIGNER_URL is set AND RUST_SIGNER_REQUIRED=true (never a local-key fallback).

import { bls12_381 as bls } from "@noble/curves/bls12-381.js";
import { ethers } from "ethers";
import { existsSync, writeFileSync } from "fs";
import { join } from "path";

const STATE = join(process.cwd(), "node_state.json");

const raw = process.argv[2];
if (!raw) {
  console.error("usage: node scripts/write-keyless-node-state.mjs 0x<48B-compressed-G1-pubkey> [nodeName]");
  process.exit(1);
}
const hex = raw.startsWith("0x") ? raw.slice(2) : raw;
if (!/^[0-9a-fA-F]{96}$/.test(hex)) {
  console.error(`‼ pubkey must be a 48-byte (96 hex char) compressed G1 point, got ${hex.length} hex chars`);
  process.exit(1);
}
if (existsSync(STATE)) {
  console.error(`‼ ${STATE} already exists — refusing to overwrite. Remove it first if you mean to re-provision.`);
  process.exit(1);
}

// Parse + validate the compressed point (throws on a bad/off-curve pubkey → fail-closed).
let point;
try {
  point = bls.G1.Point.fromHex(hex);
} catch (e) {
  console.error(`‼ invalid G1 pubkey: ${e.message}`);
  process.exit(1);
}
const publicKey = point.toHex(); // compressed 48B, NO 0x prefix — matches gen-node-state.mjs exactly

// EIP-2537 G1 wire encoding (128 bytes: each Fp padded to 64 = 16 zero + 48). Matches the
// contract, src/utils/bls.util.ts, gen-node-state.mjs, and deploy/onboarding/onboard.mjs.
const _fp = x => {
  const s = x.toString(16).padStart(96, "0");
  const b = new Uint8Array(48);
  for (let i = 0; i < 48; i++) b[i] = parseInt(s.substr(i * 2, 2), 16);
  return b;
};
const a = point.toAffine();
const eip2537 = new Uint8Array(128);
eip2537.set(_fp(a.x), 16);
eip2537.set(_fp(a.y), 80);
const nodeId = ethers.keccak256("0x" + Buffer.from(eip2537).toString("hex"));

const nodeName = process.env.NODE_NAME || process.argv[3] || "dvt-kms-tee";
writeFileSync(
  STATE,
  JSON.stringify(
    {
      nodeId,
      nodeName,
      // NO privateKey — sealed in the KMS TEE. Signing goes via RUST_SIGNER_URL.
      publicKey,
      createdAt: new Date().toISOString(),
      description: "Key-less DVT node (KMS-TEE custody) — private key sealed in KMS OP-TEE",
    },
    null,
    2
  ),
  "utf8"
);

console.log(`✔ wrote key-less ${STATE}`);
console.log(`  nodeId    = ${nodeId}`);
console.log(`  publicKey = ${publicKey}`);
console.log("  boot needs: RUST_SIGNER_URL=http://127.0.0.1:3100 + RUST_SIGNER_REQUIRED=true (+ RUST_SIGNER_TOKEN)");
