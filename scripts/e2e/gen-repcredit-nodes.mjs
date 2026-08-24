#!/usr/bin/env node
// Generate LOCAL-ONLY RepCredit BLS node states without reading .env.
// The output contains private keys and must stay in a gitignored or temporary directory.
// Usage: node scripts/e2e/gen-repcredit-nodes.mjs <output-dir> [count]
//
// CC-49 HIGH-2: keys are drawn from the OS CSPRNG, never derived from the node index.
// The previous version used the literal scalars 1, 2, 3, so anyone could reproduce the
// whole "three-node quorum" and forge signatures for any slot those keys occupied. Any
// evidence produced with those keys is cryptographically worthless and, if the keys were
// ever registered on a live aggregator, that aggregator's quorum was publicly forgeable.
// Private key material is written to disk with 0600 and is NEVER printed.

import { bls12_381 as bls } from "@noble/curves/bls12-381.js";
import { randomBytes } from "crypto";
import { ethers } from "ethers";
import { existsSync, mkdirSync, writeFileSync } from "fs";
import { resolve } from "path";

const outputDir = resolve(process.argv[2] || ".e2e/repcredit");
const count = Number(process.argv[3] || "3");
if (!Number.isInteger(count) || count < 1 || count > 13) {
  throw new Error("node count must be an integer in [1, 13]");
}

const sigs = bls.longSignatures;
/** BLS12-381 scalar field order r — a secret key must be in [1, r-1]. */
const CURVE_ORDER = bls.fields.Fr.ORDER;

/** Rejection-sample a uniform secret key from the OS CSPRNG. */
function randomSecretKey() {
  for (let attempt = 0; attempt < 64; attempt++) {
    const candidate = BigInt("0x" + Buffer.from(randomBytes(32)).toString("hex"));
    if (candidate > 0n && candidate < CURVE_ORDER) {
      return ethers.getBytes(ethers.zeroPadValue(ethers.toBeHex(candidate), 32));
    }
  }
  throw new Error("failed to sample a BLS secret key from the CSPRNG");
}

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
  mkdirSync(nodeDir, { recursive: true, mode: 0o700 });
  const privateKey = randomSecretKey();
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
        createdAt: new Date().toISOString(),
        description: "Local-only RepCredit experiment signer (ephemeral random key)",
      },
      null,
      2
    ),
    // `wx` makes create-if-absent ATOMIC (CC-49 round-2 LOW-G): the existsSync check above
    // is advisory only, and `mode` is IGNORED for a file that already exists — a local
    // attacker who won that race would have had the key written into their own 0644 file.
    { mode: 0o600, flag: "wx" }
  );
  // nodeId and the public key are safe to print; the private key never is.
  console.log(`node${index + 1}: slot=${index + 1} nodeId=${nodeId}`);
}
