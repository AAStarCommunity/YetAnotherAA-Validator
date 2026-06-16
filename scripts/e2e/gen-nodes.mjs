// Generate 3 DVT node identities (BLS12-381) into ./.e2e/node{1,2,3}/node_state.json
// node1/node2 reuse the on-chain-registered BLS_TEST keys from .env.sepolia; node3 is fresh.
// Usage: node scripts/e2e/gen-nodes.mjs
import { bls12_381 as bls } from "@noble/curves/bls12-381.js";
import { readFileSync, writeFileSync, mkdirSync } from "fs";
import { randomBytes } from "crypto";
const sigs = bls.longSignatures;
const strip = s => s.replace(/^["']|["']$/g, "");
const env = Object.fromEntries(
  readFileSync(".env.sepolia", "utf8").split("\n").filter(l => l.includes("="))
    .map(l => { const i = l.indexOf("="); return [l.slice(0, i).trim(), strip(l.slice(i + 1).trim())]; })
);
const skFresh = () => { let s; while (true) { s = randomBytes(32); try { sigs.getPublicKey(s); break; } catch {} } return s; };
const state = (id, sk, name) => ({
  nodeId: id, nodeName: name,
  privateKey: "0x" + Buffer.from(sk).toString("hex"),
  publicKey: sigs.getPublicKey(sk).toHex(),
  createdAt: "2026-06-16T00:00:00.000Z", description: "DVT real-node E2E",
});
const sk1 = Buffer.from(env.BLS_TEST_PRIVATE_KEY_1.replace(/^0x/, ""), "hex");
const sk2 = Buffer.from(env.BLS_TEST_PRIVATE_KEY_2.replace(/^0x/, ""), "hex");
const nodes = [
  state(env.BLS_TEST_NODE_ID_1, sk1, "dvt-node-1"),
  state(env.BLS_TEST_NODE_ID_2, sk2, "dvt-node-2"),
  state("0x" + randomBytes(32).toString("hex"), skFresh(), "dvt-node-3"),
];
nodes.forEach((n, i) => {
  mkdirSync(`.e2e/node${i + 1}`, { recursive: true });
  writeFileSync(`.e2e/node${i + 1}/node_state.json`, JSON.stringify(n, null, 2));
  console.log(`node${i + 1}: ${n.nodeId.slice(0, 18)}... (${n.nodeName})`);
});
console.log("→ .e2e/node{1,2,3}/node_state.json written");
