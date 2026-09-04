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
// E2E_ACCOUNT is REQUIRED — no default. The old hardcoded 0x45Dfe3D5… does not implement the
// owner-gate's isValidOwnerAuth(bytes32,bytes) at all (verified on Sepolia: the call REVERTS, while
// the same call on an AAStarAirAccountV7 returns a bytes4), so every bare run of this script 403s
// with a message naming the NODE — sending the reader to debug three healthy nodes instead of their
// own configuration. scripts/e2e/realnode-e2e.mjs removed this same default for this same reason on
// CC-22; this copy never got the fix.
const ACCOUNT_RAW = process.env.E2E_ACCOUNT;
if (!ACCOUNT_RAW) {
  console.error(
    "\u203c E2E_ACCOUNT is required (an account implementing isValidOwnerAuth\u21920xa0cf00cf, e.g. an " +
      "AAStarAirAccountV7 such as community.toml's e2e_account). Set E2E_ACCOUNT=0x... and re-run."
  );
  process.exit(1);
}
// Normalised through `ethers.getAddress` rather than used as the raw string: it rejects a malformed
// address at the point it enters the run, with a message naming THIS variable, instead of surfacing
// later as an opaque ENS or ABI-encoding error from three frames down. It also checksums, so the
// address printed in the log is the one a block explorer will show.
// Describes the SHAPE of the bad value rather than echoing it. Two reasons, and the second is the
// real one: (a) after `ethers.getAddress` the accepted value is no longer flagged by CodeQL — the
// remaining sink was this line handing a raw `process.env` string straight to a log; (b) echoing back
// what the operator typed adds little they do not already have, whereas "44 chars, no 0x prefix"
// names the mistake directly. Length and prefix are derived facts about the input, not the input.
const shapeOf = v => `${v.length} char(s), ${v.startsWith("0x") ? "0x-prefixed" : "no 0x prefix"}`;
let ACCOUNT;
try {
  ACCOUNT = ethers.getAddress(ACCOUNT_RAW);
} catch {
  console.error(
    `\u203c E2E_ACCOUNT is not a valid address (${shapeOf(ACCOUNT_RAW)}); ` +
      `it must be a 0x-prefixed 20-byte hex address`
  );
  process.exit(1);
}
const owner = new ethers.Wallet(env.PRIVATE_KEY_SUPPLIER);
const PORTS = [4001, 4002, 4003];
// 127.0.0.1, NOT localhost. `localhost` can resolve to ::1 first, and anything else listening on
// IPv6 at that port answers instead of the node — on this machine an unrelated Next.js dev server
// holds *:3001 while the DVT containers bind 127.0.0.1 only, so the run failed with "Internal Server
// Error" and read as a broken node. Override with DVT_NODE_HOST.
const NODE_HOST = process.env.DVT_NODE_HOST || "127.0.0.1";

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
// ownerAuth = 1-byte tag ‖ payload (docs/INTERFACES.md §1). tag 0x01 = owner ECDSA (k1) over
// personal_sign(userOpHash). isValidOwnerAuth requires EXACTLY 66 bytes and returns 0xffffffff for
// anything else, so the bare 65-byte signature this used to send was rejected by every account.
// Verified on Sepolia against e2e_account 0x92EA8b02…, same owner key, same hash:
//   0x01 ‖ sig (66 bytes) -> 0xa0cf00cf accepted
//   bare sig  (65 bytes)  -> 0xffffffff rejected
const ownerAuth = "0x01" + (await owner.signMessage(ethers.getBytes(userOpHash))).slice(2);
console.log("account:", ACCOUNT, "owner:", owner.address, "\nuserOpHash:", userOpHash);

const signed = [];
for (const port of PORTS) {
  const r = await fetch(`http://${NODE_HOST}:${port}/signature/sign`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ userOp, ownerAuth }),
  });
  if (!r.ok) throw new Error(`node :${port} -> ${r.status} ${await r.text()}`);
  const j = await r.json();
  console.log(
    `node :${port} signed  nodeId=${j.nodeId.slice(0, 20)}…  (msg==hash: ${j.message === userOpHash})`
  );
  signed.push(j);
}

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

const payload = ethers.concat([...signed.map(s => s.nodeId), encG2(aggAll)]);
const ret = await call(p =>
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
