#!/usr/bin/env node
// CC-89 joint-testnet co-sign CLI — produce the 3-of-3 BLS aggregate `proof` SuperPaymaster's
// BLSAggregator.verifyAndExecute needs for a (disputed, over-issue) slash proposal.
//
// This is a thin ENTRYPOINT over the SAME primitives the DVT signer service uses in production
// (src/modules/bls + src/modules/audit/gossip-quorum-cosigner): @noble longSignatures over the
// SP-matching DST, EIP-2537 G2 encoding, proof = abi.encode(uint256 signerMask, bytes sigG2).
// It just signs with the 3 LOCAL guardian keys (node_dev_00{1,2,3}.json) instead of over gossip —
// which is correct for the testnet E2E where all 3 keys are on this machine (CLAUDE.md dev nodes).
//
// The messageHash is SP's slash-only expectedMessageHash:
//   keccak256(abi.encode(proposalId, operator, slashLevel, [], [], epoch, chainId, evidenceHash))
// and each key signs hashToCurve(messageHash, DST) — byte-identical to BLSAggregator._checkSignatures.
//
// Usage (real run — fields from SP):
//   PROPOSAL_ID=42 OPERATOR=0x.. SLASH_LEVEL=1 EPOCH=100 \
//     TOKEN=0x..            (over-issue evidenceHash = keccak(TAG,token,operator,epoch))  \
//     AGGREGATOR=0xf44E7E51..  SEPOLIA_RPC_URL=..  node scripts/cc89-cosign.mjs
//   (or pass EVIDENCE_HASH=0x.. directly instead of TOKEN)
// Self-test (no SP fields — proves the 3-key aggregate passes on-chain verify):
//   AGGREGATOR=0xf44E7E51..  SEPOLIA_RPC_URL=..  node scripts/cc89-cosign.mjs --selftest
//
// Output: the `proof` bytes to hand SP, after a staticcall to aggregator.verify(...) returns true.
import { bls12_381 as bls } from "@noble/curves/bls12-381.js";
import { ethers } from "ethers";
import { readFileSync, existsSync } from "fs";

const sigs = bls.longSignatures;
// MUST equal SP BLSAggregator BLS.sol hashToG2 DST + src/utils/bls.util.ts BLS_DST.
const BLS_DST = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
const OVERISSUE_EVIDENCE_TAG = "DVT_OVERISSUE_EVIDENCE_V1"; // cross-repo, must match verifier
const coder = ethers.AbiCoder.defaultAbiCoder();
const die = m => {
  console.error("✗ " + m);
  process.exit(1);
};

// EIP-2537 G2 (256B) — identical layout to src/utils/bls.util.ts encodeG2Point.
const _fp = x => {
  const b = new Uint8Array(48);
  const s = x.toString(16).padStart(96, "0");
  for (let i = 0; i < 48; i++) b[i] = parseInt(s.substr(i * 2, 2), 16);
  return b;
};
const eip2537G2 = point => {
  const a = point.toAffine();
  const r = new Uint8Array(256);
  r.set(_fp(a.x.c0), 16);
  r.set(_fp(a.x.c1), 80);
  r.set(_fp(a.y.c0), 144);
  r.set(_fp(a.y.c1), 208);
  return "0x" + Buffer.from(r).toString("hex");
};

function loadKey(slot) {
  const f = `node_dev_00${slot}.json`;
  if (!existsSync(f)) die(`${f} not found — generate the 3 guardian keys first`);
  const s = JSON.parse(readFileSync(f, "utf8"));
  if (!s.privateKey) die(`${f} has no privateKey`);
  return Buffer.from(s.privateKey.replace(/^0x/, ""), "hex");
}

const selftest = process.argv.includes("--selftest");
const chainId = BigInt(process.env.CHAIN_ID || "11155111");
const aggregator = process.env.AGGREGATOR || die("AGGREGATOR required");
const rpc =
  process.env.SEPOLIA_RPC_URL || process.env.ETH_RPC_URL || die("SEPOLIA_RPC_URL required");

// ---- 1. messageHash ---------------------------------------------------------
let messageHash;
if (selftest) {
  messageHash = ethers.keccak256(ethers.toUtf8Bytes("cc89-cosign-selftest"));
  console.log("SELF-TEST mode: signing a dummy messageHash to prove the 3-key aggregate verifies.");
} else {
  const proposalId = BigInt(process.env.PROPOSAL_ID || die("PROPOSAL_ID required"));
  const operator = ethers.getAddress(process.env.OPERATOR || die("OPERATOR required"));
  const slashLevel = parseInt(process.env.SLASH_LEVEL || die("SLASH_LEVEL required"), 10);
  const epoch = BigInt(process.env.EPOCH || die("EPOCH required"));
  let evidenceHash = process.env.EVIDENCE_HASH;
  if (!evidenceHash) {
    const token = ethers.getAddress(process.env.TOKEN || die("TOKEN or EVIDENCE_HASH required"));
    evidenceHash = ethers.keccak256(
      coder.encode(
        ["string", "address", "address", "uint256"],
        [OVERISSUE_EVIDENCE_TAG, token, operator, epoch]
      )
    );
    console.log(`over-issue evidenceHash(${token}, ${operator}, ${epoch}) = ${evidenceHash}`);
  }
  // SP slash-only expectedMessageHash (repUsers/newScores empty).
  messageHash = ethers.keccak256(
    coder.encode(
      ["uint256", "address", "uint8", "address[]", "uint256[]", "uint256", "uint256", "bytes32"],
      [proposalId, operator, slashLevel, [], [], epoch, chainId, evidenceHash]
    )
  );
}
console.log("messageHash:", messageHash);

// ---- 2. sign with the 3 local guardian keys + aggregate ---------------------
const msgG2 = bls.G2.hashToCurve(ethers.getBytes(messageHash), { DST: BLS_DST });
const perSig = [1, 2, 3].map(slot => sigs.sign(msgG2, loadKey(slot)));
const aggregate = sigs.aggregateSignatures(perSig);
const sigG2 = eip2537G2(aggregate);
const signerMask = 0x7n; // slots 1,2,3
const proof = coder.encode(["uint256", "bytes"], [signerMask, sigG2]);

// ---- 3. on-chain self-verify (definitive: passes ⇒ verifyAndExecute will accept) -----
const provider = new ethers.JsonRpcProvider(rpc);
const agg = new ethers.Contract(
  aggregator,
  ["function verify(bytes32,uint256,uint256,bytes) view returns (bool)"],
  provider
);
const ok = await agg.verify(messageHash, signerMask, 3n, sigG2);
console.log("\n=== aggregator.verify(messageHash, mask=0x7, threshold=3, sigG2) =", ok, "===");
if (!ok) die("on-chain verify returned FALSE — aggregate/encoding/keys mismatch, DO NOT submit");

console.log("\n✓ 3-of-3 aggregate VALID on-chain. Hand SP this proof for verifyAndExecute:");
console.log("signerMask:", "0x" + signerMask.toString(16));
console.log("sigG2 (EIP-2537 256B):", sigG2);
console.log("proof (abi.encode(uint256,bytes)):", proof);
