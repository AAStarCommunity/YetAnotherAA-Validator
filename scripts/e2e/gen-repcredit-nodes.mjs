#!/usr/bin/env node
// Generate deterministic LOCAL-ONLY RepCredit BLS node states without reading .env.
// The output contains private keys and must stay in a gitignored or temporary directory.
// Usage: node scripts/e2e/gen-repcredit-nodes.mjs <output-dir> [count]

import { bls12_381 as bls } from "@noble/curves/bls12-381.js";
import { ethers } from "ethers";
import { existsSync, mkdirSync, writeFileSync } from "fs";
import { resolve } from "path";

const outputDir = resolve(process.argv[2] || ".e2e/repcredit");
const count = Number(process.argv[3] || "3");
if (!Number.isInteger(count) || count < 1 || count > 13) {
  throw new Error("node count must be an integer in [1, 13]");
}

const sigs = bls.longSignatures;
function eip2537G1(point) {
  const affine = point.toAffine();
  const out = new Uint8Array(128);
  out.set(Buffer.from(affine.x.toString(16).padStart(96, "0"), "hex"), 16);
  out.set(Buffer.from(affine.y.toString(16).padStart(96, "0"), "hex"), 80);
  return ethers.hexlify(out);
}

for (let index = 0; index < count; index++) {
  const nodeDir = resolve(outputDir, `node${index + 1}`);
  const statePath = resolve(nodeDir, "node_state.json");
  if (existsSync(statePath)) {
    throw new Error(`${statePath} already exists; refusing to overwrite key material`);
  }
  mkdirSync(nodeDir, { recursive: true });
  const privateKey = ethers.getBytes(ethers.zeroPadValue(ethers.toBeHex(BigInt(index + 1)), 32));
  const publicKey = sigs.getPublicKey(privateKey);
  const nodeId = ethers.keccak256(eip2537G1(publicKey));
  writeFileSync(
    statePath,
    JSON.stringify(
      {
        nodeId,
        nodeName: `repcredit-local-${index + 1}`,
        privateKey: ethers.hexlify(privateKey),
        publicKey: publicKey.toHex(),
        createdAt: "deterministic-local-evidence-v1",
        description: "Local-only deterministic RepCredit evidence signer",
      },
      null,
      2
    )
  );
  console.log(`node${index + 1}: slot=${index + 1} nodeId=${nodeId}`);
}
