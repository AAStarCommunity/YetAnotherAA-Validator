// Verify the 3 PRODUCTION DVT nodes (independent keys, ports 4001/2/3) end-to-end:
// real co-sign → 3-node aggregate → off-chain verify → on-chain AAStarBLSAlgorithm.validate === 0.
// Usage: node deploy/verify-prod-e2e.mjs
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
const RPC = env.SEPOLIA_RPC_URL;
const ENTRY = env.ENTRY_POINT_ADDRESS || "0x0000000071727De22E5E9d8BAf0edAc6f37da032";
const BLS_ALG = "0xAF525A161CB17e0A1b6254ef0B8d8473bdA05174";
const ACCOUNT = process.env.E2E_ACCOUNT || "0x45Dfe3D5938fDf5a8D30641C3FDA9c9fb1F31ba9";
const owner = new ethers.Wallet(env.PRIVATE_KEY_SUPPLIER);
const PORTS = [4001, 4002, 4003];
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
const call = async fn => {
  for (let i = 0; i < 6; i++) {
    try {
      return await fn(new ethers.JsonRpcProvider(RPC));
    } catch (e) {
      console.log("  rpc retry", i, e.shortMessage || e.code);
      await new Promise(r => setTimeout(r, 2500));
    }
  }
  throw new Error("all RPC retries failed");
};
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
const userOpHash = await call(p => new ethers.Contract(ENTRY, EP_ABI, p).getUserOpHash(userOp));
const ownerAuth = await owner.signMessage(ethers.getBytes(userOpHash));
console.log("account:", ACCOUNT, "owner:", owner.address, "\nuserOpHash:", userOpHash);

const signed = [];
for (const port of PORTS) {
  const r = await fetch(`http://localhost:${port}/signature/sign`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ userOp, ownerAuth }),
  });
  if (!r.ok) throw new Error(`node :${port} -> ${r.status} ${await r.text()}`);
  const j = await r.json();
  console.log(`node :${port} signed  nodeId=${j.nodeId.slice(0, 20)}…  (msg==hash: ${j.message === userOpHash})`);
  signed.push(j);
}

const aggAll = sigs.aggregateSignatures(
  signed.map(s => sigs.Signature.fromHex(s.signatureCompact.replace(/^0x/, "")))
);
const aggPk = signed
  .map(s => bls.G1.Point.fromHex(s.publicKey.replace(/^0x/, "")))
  .reduce((a, b) => a.add(b));
const mp = bls.G2.hashToCurve(ethers.getBytes(userOpHash), { DST });
console.log("\n[1] 3-node aggregate off-chain verify:", sigs.verify(aggAll, mp, aggPk) ? "✅ VALID" : "❌ INVALID");

const payload = ethers.concat([...signed.map(s => s.nodeId), encG2(aggAll)]);
const ret = await call(p =>
  new ethers.Contract(
    BLS_ALG,
    ["function validate(bytes32 hash, bytes signature) view returns (uint256)"],
    p
  ).validate(userOpHash, payload)
);
console.log("[2] on-chain AAStarBLSAlgorithm.validate:", ret.toString(), ret === 0n ? "✅ VALID" : "❌ reject");
