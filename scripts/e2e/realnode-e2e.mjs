// Real-node DVT E2E: drive 3 running v1.1.0 node instances through a real co-sign,
// aggregate, verify off-chain, and verify on-chain via the deployed AAStarBLSAlgorithm.
//
// Prereq: gen-nodes.mjs run, then 3 instances started (see scripts/e2e/README.md), and
// a .env.sepolia with SEPOLIA_RPC_URL[,2,3], ENTRY_POINT_ADDRESS, AIRACCOUNT_V018_BLS_ALGORITHM,
// BLS_TEST_NODE_ID_1/2, PRIVATE_KEY_SUPPLIER (= the test account's ECDSA owner).
// Usage: node scripts/e2e/realnode-e2e.mjs
import { ethers } from "ethers";
import { bls12_381 as bls } from "@noble/curves/bls12-381.js";
import { readFileSync } from "fs";
const sigs = bls.longSignatures;
const DST = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
const strip = s => s.replace(/^["']|["']$/g, "");
const env = Object.fromEntries(
  readFileSync(".env.sepolia", "utf8")
    .split("\n")
    .filter(l => l.includes("="))
    .map(l => {
      const i = l.indexOf("=");
      return [l.slice(0, i).trim(), strip(l.slice(i + 1).trim())];
    })
);
const RPCS = [env.SEPOLIA_RPC_URL].filter(Boolean); // others rotated/dead
const ENTRY = env.ENTRY_POINT_ADDRESS || env.ENTRYPOINT_ADDRESS;
// Pinned current AAStarBLSAlgorithm (airaccount-contract v0.19.0-beta.2). The pinned
// constant is authoritative; only an EXPLICIT, version-matched override is honored.
// NB: we deliberately do NOT fall back to the generic `AIRACCOUNT_BLS_ALGORITHM` — that
// var in older .env files points at a stale contract (a pre-v0.18 deploy) where these
// test nodes are not registered, which silently makes validate() return 1 (reject).
const BLS_ALG = env.AIRACCOUNT_V019_BLS_ALGORITHM || "0x68c381Ad3A2e3380F22840008027E9Ec2783F43A";
const ACCOUNT = process.env.E2E_ACCOUNT || "0x45Dfe3D5938fDf5a8D30641C3FDA9c9fb1F31ba9";
const owner = new ethers.Wallet(env.PRIVATE_KEY_SUPPLIER);
const PORTS = [3001, 3002, 3003];

const b48 = n => ethers.getBytes("0x" + n.toString(16).padStart(96, "0"));
const encG2 = pt => {
  const a = pt.toAffine();
  const r = new Uint8Array(256);
  r.set(b48(a.x.c0), 16);
  r.set(b48(a.x.c1), 80);
  r.set(b48(a.y.c0), 144);
  r.set(b48(a.y.c1), 208);
  return ethers.hexlify(r);
};
async function withRpc(fn) {
  for (const u of RPCS) {
    try {
      return await fn(new ethers.JsonRpcProvider(u));
    } catch (e) {
      console.log("  rpc retry:", e.shortMessage || e.code);
    }
  }
  throw new Error("all RPCs failed");
}

const userOp = {
  sender: ACCOUNT,
  nonce: "0",
  initCode: "0x",
  callData: "0x",
  accountGasLimits: "0x" + "00".repeat(32),
  preVerificationGas: "0",
  gasFees: "0x" + "00".repeat(32),
  paymasterAndData: "0x",
  signature: "0x",
};
const EP_ABI = [
  "function getUserOpHash((address sender,uint256 nonce,bytes initCode,bytes callData,bytes32 accountGasLimits,uint256 preVerificationGas,bytes32 gasFees,bytes paymasterAndData,bytes signature) userOp) view returns (bytes32)",
];
const userOpHash = await withRpc(p => new ethers.Contract(ENTRY, EP_ABI, p).getUserOpHash(userOp));
const ownerAuth = await owner.signMessage(ethers.getBytes(userOpHash));
console.log("account:", ACCOUNT, "owner:", owner.address);
console.log("userOpHash:", userOpHash);

// 3 real running nodes co-sign (each enforces Stage 1 owner-auth against on-chain owner())
const signed = [];
for (const port of PORTS) {
  const r = await fetch(`http://localhost:${port}/signature/sign`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ userOp, ownerAuth }),
  });
  if (!r.ok) throw new Error(`node :${port} -> ${r.status} ${await r.text()}`);
  const j = await r.json();
  console.log(`node :${port} signed (msg==userOpHash: ${j.message === userOpHash})`);
  signed.push(j);
}
// off-chain aggregate verify (all 3)
const aggAll = sigs.aggregateSignatures(
  signed.map(s => sigs.Signature.fromHex(s.signatureCompact.replace(/^0x/, "")))
);
const aggPk = signed
  .map(s => bls.G1.Point.fromHex(s.publicKey.replace(/^0x/, "")))
  .reduce((a, b) => a.add(b));
const mp = bls.G2.hashToCurve(ethers.getBytes(userOpHash), { DST });
console.log(
  "\n[1] 3-node aggregate off-chain verify:",
  sigs.verify(aggAll, mp, aggPk) ? "✅ VALID" : "❌ INVALID"
);

// on-chain verify via deployed AAStarBLSAlgorithm using the 2 registered nodes
const agg2 = sigs.aggregateSignatures(
  signed.slice(0, 2).map(s => sigs.Signature.fromHex(s.signatureCompact.replace(/^0x/, "")))
);
const payload = ethers.concat([env.BLS_TEST_NODE_ID_1, env.BLS_TEST_NODE_ID_2, encG2(agg2)]);
const ret = await withRpc(p =>
  new ethers.Contract(
    BLS_ALG,
    ["function validate(bytes32 hash, bytes signature) view returns (uint256)"],
    p
  ).validate(userOpHash, payload)
);
console.log(
  "[2] on-chain AAStarBLSAlgorithm.validate:",
  ret.toString(),
  ret === 0n ? "✅ VALID" : "❌ reject"
);
