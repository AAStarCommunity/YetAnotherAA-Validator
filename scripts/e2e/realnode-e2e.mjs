// Real-node DVT E2E: drive 3 running v1.1.0 node instances through a real co-sign,
// aggregate, verify off-chain, and verify on-chain via the deployed AAStarBLSAlgorithm.
//
// Prereq: gen-nodes.mjs run, then 3 instances started (see scripts/e2e/README.md), and
// a .env.sepolia with SEPOLIA_RPC_URL[,2,3], ENTRY_POINT_ADDRESS, AIRACCOUNT_V020_BLS_ALGORITHM,
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
// Pinned current AAStarBLSAlgorithm (airaccount-contract v0.20.0). The pinned
// constant is authoritative; only an EXPLICIT, version-matched override is honored.
// NB: we deliberately do NOT fall back to the generic `AIRACCOUNT_BLS_ALGORITHM` — that
// var in older .env files points at a stale contract (an earlier deploy) where these
// test nodes are not registered, which silently makes validate() return 1 (reject).
const BLS_ALG = env.AIRACCOUNT_V020_BLS_ALGORITHM || "0xAF525A161CB17e0A1b6254ef0B8d8473bdA05174";
// E2E_ACCOUNT is REQUIRED — no default. The old hardcoded 0x45Dfe3… only implements standard
// ERC-1271 (0x1626ba7e), NOT the owner-gate's isValidOwnerAuth(bytes32,bytes)→0xa0cf00cf, so it
// silently fails the owner-auth gate (CC-22). Pass an account that implements 0xa0cf00cf (an
// AAStarAirAccountV7), e.g. from community.toml's e2e_account.
const ACCOUNT = process.env.E2E_ACCOUNT;
if (!ACCOUNT) {
  console.error(
    "‼ E2E_ACCOUNT is required (an account implementing isValidOwnerAuth→0xa0cf00cf, e.g. AAStarAirAccountV7). " +
      "Set E2E_ACCOUNT=0x... and re-run."
  );
  process.exit(1);
}
const owner = new ethers.Wallet(env.PRIVATE_KEY_SUPPLIER);
// Configurable for the same reason dvt-nodes.sh's are: the always-on testnet stack holds 3001-3003,
// so the .e2e/ stack this driver targets is normally booted elsewhere (E2E_PORTS="3011 3012 3013").
const PORTS = (process.env.DVT_NODE_PORTS || "3001,3002,3003").split(",").map(s => s.trim());
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
// ownerAuth = 1-byte tag ‖ payload (airaccount AAStarAirAccountV7 isValidOwnerAuth contract,
// see docs/INTERFACES.md §1). tag 0x01 = owner ECDSA (k1): personal_sign(userOpHash) EIP-191.
// A bare signature (no tag) returns 0xffffffff → the gate 403s (the bug KMS hit on CC-22).
const ownerSig = await owner.signMessage(ethers.getBytes(userOpHash));
const ownerAuth = "0x01" + ownerSig.slice(2);
// Do not echo raw process.env values (ACCOUNT / owner.address) — CodeQL's clear-text-logging
// query flags any process.env value reaching console.log (js/clear-text-logging), and the
// operator already knows what they passed. Log a non-tainted confirmation instead.
console.log("account: set via E2E_ACCOUNT env");
console.log("userOpHash:", userOpHash);

// 3 real running nodes co-sign (each enforces Stage 1 owner-auth against on-chain owner())
const signed = [];
for (const port of PORTS) {
  const r = await fetch(`http://${NODE_HOST}:${port}/signature/sign`, {
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

// On-chain verify via the deployed AAStarBLSAlgorithm.
//
// The signer set is taken from what the NODES REPORTED and from what the verifier says it knows --
// never from env constants. Until this change the payload named BLS_TEST_NODE_ID_1/2 while the
// aggregate was built from whichever two processes happened to answer on those ports. Those agree
// only when the running stack is the one gen-nodes.mjs produced; point the same script at the
// always-on testnet stack (docker, dvt1/2/3) and it claims two identities that did not sign, so
// validate() returns a bare `1` and the reader has no way to see why. Measured: exactly that, on
// 2026-09-01.
// A factory, not an instance: withRpc() hands each attempt a FRESH provider so it can fail over
// between the RPCs in RPCS, and a contract bound to one dead provider would defeat that.
const validatorAt = p =>
  new ethers.Contract(
    BLS_ALG,
    [
      "function validate(bytes32 hash, bytes signature) view returns (uint256)",
      "function isRegistered(bytes32) view returns (bool)",
    ],
    p
  );
// Canonical 32-byte ids, then STRICTLY ASCENDING -- the contract rejects `nid <= prevId`
// (AAStarValidator.sol:251), and BigInt compare because Array.sort's Number coercion loses
// precision above 2^53.
const withIds = signed.map(s => ({ ...s, id: ethers.zeroPadValue(s.nodeId, 32) }));
const eligible = [];
for (const n of withIds) {
  const reg = await withRpc(p => validatorAt(p).isRegistered(n.id));
  if (reg) eligible.push(n);
  else console.log(`  note: ${n.id.slice(0, 18)}… is NOT registered on ${BLS_ALG} — excluded`);
}
if (eligible.length < 2) {
  console.error(
    `\n‼ only ${eligible.length} of ${withIds.length} signing nodes are registered on ${BLS_ALG}, ` +
      `so no aggregate can verify there.\n` +
      `  This normally means the running stack is not the one this verifier knows: ` +
      `scripts/e2e/dvt-nodes.sh boots the .e2e/ nodes (BLS_TEST keys, registered here), while the\n` +
      `  always-on testnet stack (docker-compose.testnet.yml, dvt1/2/3) is registered on the\n` +
      `  router-mounted committee validator instead — use scripts/e2e/committee-e2e.mjs for that one.`
  );
  process.exit(1);
}
eligible.sort((a, b) => (BigInt(a.id) < BigInt(b.id) ? -1 : BigInt(a.id) > BigInt(b.id) ? 1 : 0));
const agg2 = sigs.aggregateSignatures(
  eligible.map(s => sigs.Signature.fromHex(s.signatureCompact.replace(/^0x/, "")))
);
const payload = ethers.concat([...eligible.map(n => n.id), encG2(agg2)]);
const ret = await withRpc(p => validatorAt(p).validate(userOpHash, payload));
console.log(
  "[2] on-chain AAStarBLSAlgorithm.validate:",
  ret.toString(),
  ret === 0n ? "✅ VALID" : "❌ reject"
);
