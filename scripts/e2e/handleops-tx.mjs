// Full DVT combined-signature handleOps tx (Tier2 = P256 main + real-node BLS aggregate).
// Reconfigures the test account's P256 to a freshly generated key (owner=SUPPLIER), funds it,
// then submits a real EntryPoint.handleOps tx whose BLS factor comes from the 3 RUNNING nodes.
// Usage: node scripts/e2e/handleops-tx.mjs   (consumes a little Sepolia test ETH for gas/transfer)
import { ethers } from "ethers";
import { bls12_381 as bls } from "@noble/curves/bls12-381.js";
import { p256 } from "@noble/curves/nist.js";
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
const RPCS = [env.SEPOLIA_RPC_URL, env.SEPOLIA_RPC_URL2, env.SEPOLIA_RPC_URL3].filter(Boolean);
const ENTRY = env.ENTRY_POINT_ADDRESS || env.ENTRYPOINT_ADDRESS;
const ACCOUNT = "0x45Dfe3D5938fDf5a8D30641C3FDA9c9fb1F31ba9";
// Pick a healthy RPC (public Sepolia endpoints are flaky under heavy eth_call/pairing).
async function pickRpc() {
  for (const u of RPCS) {
    try {
      const p = new ethers.JsonRpcProvider(u);
      await p.getBlockNumber();
      console.log("using RPC:", u.slice(0, 30) + "...");
      return p;
    } catch {
      console.log("rpc down:", u.slice(0, 30));
    }
  }
  throw new Error("no healthy RPC");
}
const provider = await pickRpc();
const owner = new ethers.Wallet(env.PRIVATE_KEY_SUPPLIER, provider);
const RECIPIENT = owner.address; // transfer back to owner to recover funds

const ACCOUNT_ABI = [
  "function execute(address dest, uint256 value, bytes func)",
  "function setP256Key(bytes32 _x, bytes32 _y)",
  "function setTierLimits(uint256 _tier1, uint256 _tier2)",
  "function p256KeyX() view returns (bytes32)",
  "function tier1Limit() view returns (uint256)",
  "function tier2Limit() view returns (uint256)",
];
const EP_ABI = [
  "function getUserOpHash((address sender,uint256 nonce,bytes initCode,bytes callData,bytes32 accountGasLimits,uint256 preVerificationGas,bytes32 gasFees,bytes paymasterAndData,bytes signature) userOp) view returns (bytes32)",
  "function getNonce(address sender, uint192 key) view returns (uint256)",
  "function depositTo(address account) payable",
  "function balanceOf(address account) view returns (uint256)",
  "function handleOps((address sender,uint256 nonce,bytes initCode,bytes callData,bytes32 accountGasLimits,uint256 preVerificationGas,bytes32 gasFees,bytes paymasterAndData,bytes signature)[] ops, address beneficiary)",
  "error FailedOp(uint256 opIndex, string reason)",
  "error FailedOpWithRevert(uint256 opIndex, string reason, bytes inner)",
];
const acct = new ethers.Contract(ACCOUNT, ACCOUNT_ABI, owner);
const ep = new ethers.Contract(ENTRY, EP_ABI, owner);
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
const pack = (hi, lo) => ethers.concat([ethers.toBeHex(hi, 16), ethers.toBeHex(lo, 16)]);

// 0. generate P256 keypair (mine)
const p256Priv = ethers.randomBytes(32);
const p256Pub = p256.getPublicKey(p256Priv, false); // 65 bytes 0x04|x|y
const p256X = ethers.hexlify(p256Pub.slice(1, 33)),
  p256Y = ethers.hexlify(p256Pub.slice(33, 65));
console.log("generated P256 x:", p256X.slice(0, 18) + "...");

// 1. setP256Key + ensure tier limits
console.log("[setP256Key]...");
await (await acct.setP256Key(p256X, p256Y)).wait();
const [t1, t2] = [await acct.tier1Limit(), await acct.tier2Limit()];
if (t1 === 0n || t2 === 0n) {
  console.log("[setTierLimits]...");
  await (await acct.setTierLimits(ethers.parseEther("0.01"), ethers.parseEther("0.1"))).wait();
}
console.log(
  "  tier1:",
  ethers.formatEther(await acct.tier1Limit()),
  "tier2:",
  ethers.formatEther(await acct.tier2Limit())
);

// 2. fund account + EntryPoint deposit (for the transfer + gas)
const AMOUNT = ethers.parseEther("0.03"); // Tier2: > tier1, <= tier2 (read live below)
const acctBal = await provider.getBalance(ACCOUNT);
if (acctBal < AMOUNT) {
  console.log("[fund account]...");
  await (await owner.sendTransaction({ to: ACCOUNT, value: AMOUNT })).wait();
}
const dep = await ep.balanceOf(ACCOUNT);
if (dep < ethers.parseEther("0.01")) {
  console.log("[EntryPoint deposit]...");
  await (await ep.depositTo(ACCOUNT, { value: ethers.parseEther("0.01") })).wait();
}

// 3. build Tier2 userOp
const iface = new ethers.Interface(ACCOUNT_ABI);
const callData = iface.encodeFunctionData("execute", [RECIPIENT, AMOUNT, "0x"]);
const nonce = await ep.getNonce(ACCOUNT, 0n);
const fee = await provider.getFeeData();
const userOp = {
  sender: ACCOUNT,
  nonce,
  initCode: "0x",
  callData,
  accountGasLimits: pack(800000n, 200000n),
  preVerificationGas: 80000n,
  gasFees: pack(fee.maxPriorityFeePerGas ?? 2000000000n, fee.maxFeePerGas ?? 20000000000n),
  paymasterAndData: "0x",
  signature: "0x",
};
const userOpHash = await ep.getUserOpHash(userOp);
console.log("userOpHash:", userOpHash);

// 4. P256 main sig (raw hash, lowS) — noble v2 returns 64-byte compact r||s
const p256Sig = ethers.hexlify(p256.sign(ethers.getBytes(userOpHash), p256Priv, { lowS: true }));

// 5. real-node BLS aggregate (node1+node2, registered) via running instances
const ownerAuth = await owner.signMessage(ethers.getBytes(userOpHash));
// JSON-safe userOp for the node (BigInt nonce/preVerificationGas -> string).
const userOpJson = {
  ...userOp,
  nonce: userOp.nonce.toString(),
  preVerificationGas: userOp.preVerificationGas.toString(),
};
const got = [];
for (const port of [3001, 3002]) {
  const r = await fetch(`http://localhost:${port}/signature/sign`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ userOp: userOpJson, ownerAuth }),
  });
  if (!r.ok) throw new Error(`node :${port} ${r.status} ${await r.text()}`);
  got.push(await r.json());
}
const aggSig = encG2(
  sigs.aggregateSignatures(
    got.map(g => sigs.Signature.fromHex(g.signatureCompact.replace(/^0x/, "")))
  )
);

// 6. assemble Tier2 combined signature: [0x04][p256 r/s(64)][nodeIdsLength(32)=2][nodeId1][nodeId2][blsSig(256)]
userOp.signature = ethers.concat([
  "0x04",
  p256Sig,
  ethers.toBeHex(2n, 32),
  env.BLS_TEST_NODE_ID_1,
  env.BLS_TEST_NODE_ID_2,
  aggSig,
]);
console.log(
  "combined sig len:",
  ethers.dataLength(userOp.signature),
  "bytes (expect 1+64+32+64+256=417)"
);

// 7. simulate first (decode FailedOp reason), only send if it passes
try {
  await ep.handleOps.staticCall([userOp], owner.address);
  console.log("[simulation] ✅ passes — sending real tx");
} catch (e) {
  const data = e.data || e.info?.error?.data || e.error?.data;
  console.log("[simulation] ❌ revert:", e.shortMessage || e.message);
  console.log("  raw data:", typeof data === "string" ? data.slice(0, 200) : data);
  if (typeof data === "string" && data.length >= 10) {
    try { const p = ep.interface.parseError(data); console.log("  decoded:", p?.name, JSON.stringify(p?.args, (k,v)=>typeof v==="bigint"?v.toString():v)); } catch (err) { console.log("  (undecodable selector", data.slice(0,10) + ")"); }
  }
  process.exit(1);
}
console.log("[handleOps] submitting...");
const tx = await ep.handleOps([userOp], owner.address, { gasLimit: 2000000n });
console.log("tx:", tx.hash);
const rc = await tx.wait();
console.log(
  `\n=== handleOps ${rc.status === 1 ? "✅ MINED" : "❌ failed"} block ${rc.blockNumber} gas ${rc.gasUsed} ===`
);
console.log("https://sepolia.etherscan.io/tx/" + tx.hash);
