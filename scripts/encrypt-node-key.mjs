#!/usr/bin/env node
// Migrate a plaintext node_state.json to an EIP-2335 encrypted keystore (#5).
// The plaintext privateKey is replaced by an encrypted `keystore` field; nothing else
// changes. The passphrase is read from NODE_KEY_PASSPHRASE (never passed on argv, so it
// doesn't land in shell history / process listings).
//
//   NODE_KEY_PASSPHRASE='…' node scripts/encrypt-node-key.mjs deploy/node1/node_state.json
//   # optional: KDF=pbkdf2 (lighter on tiny boards) | KDF=scrypt (default, stronger)
//
// A .bak of the original is written next to the file. Verify the node boots with the
// passphrase, then SECURELY DELETE the .bak (it still holds the plaintext key).
import { readFileSync, writeFileSync } from "fs";
import { encryptKeystore, isKeystore } from "../dist/utils/keystore.util.js";

const file = process.argv[2];
if (!file) {
  console.error("usage: NODE_KEY_PASSPHRASE=… node scripts/encrypt-node-key.mjs <node_state.json>");
  process.exit(1);
}
const passphrase = process.env.NODE_KEY_PASSPHRASE;
if (!passphrase) {
  console.error("‼ set NODE_KEY_PASSPHRASE (not passed on argv)");
  process.exit(1);
}
const kdf = process.env.KDF === "pbkdf2" ? "pbkdf2" : "scrypt";

const state = JSON.parse(readFileSync(file, "utf8"));
if (isKeystore(state.keystore)) {
  console.error("‼ already encrypted (keystore present) — nothing to do");
  process.exit(1);
}
if (typeof state.privateKey !== "string" || !/^0x[0-9a-fA-F]{64}$/.test(state.privateKey)) {
  console.error("‼ node_state.json has no valid plaintext privateKey (0x + 64 hex)");
  process.exit(1);
}

const secret = Uint8Array.from(Buffer.from(state.privateKey.slice(2), "hex"));
const keystore = encryptKeystore(secret, passphrase, {
  kdf,
  pubkey: state.publicKey?.replace(/^0x/, ""),
  description: `aastar-dvt ${state.nodeId ?? ""}`.trim(),
});

// Back up the plaintext original, then replace privateKey with the keystore.
writeFileSync(`${file}.bak`, readFileSync(file));
const { privateKey: _omit, ...rest } = state;
writeFileSync(file, JSON.stringify({ ...rest, keystore }, null, 2) + "\n");

console.log(`✅ encrypted ${file} (kdf=${kdf})`);
console.log(`   backup (STILL PLAINTEXT): ${file}.bak — verify boot, then securely delete it`);
console.log(`   run the node with NODE_KEY_PASSPHRASE set to decrypt at boot.`);
