#!/usr/bin/env node
// Generate the pause job's signer ON THE MINI: a fresh random key, never imported (DSR 0578c49a: a
// key with any history, or whose past copies nobody can list, is refused; DSR 4019916a: never
// 0xB747 or any privileged identity, nonce 0). It is written as an encrypted Web3 v3 keystore
// (`cast wallet address --keystore <file>` reads it) at the path the job loads. Its password is the
// secret file aoa-dvt-pause-keystore-pw in the secrets directory: created here from 32 random
// bytes when absent (nobody types it), read with the job's own checks when present. The key is
// never in plaintext on disk, never in .env, never exported, never printed: only the address is.
// (Taken from the retired watcher's new-sender-keystore.mjs, feat/no-keychain-secrets 6901343f.)
//
//   node deploy/pause-job/new-signer.mjs \
//     [--secrets ~/.aoa-pause-job/secrets] [--out ~/.aoa-pause-job/keystore/pause-signer]
//
// Refuses to overwrite an existing keystore (a second run would orphan the first signer).
import { randomBytes } from "node:crypto";
import { existsSync, lstatSync, mkdirSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { ethers } from "ethers";
import { readSecretFile, secretsDirProblems, okDir, SECRET_NAMES } from "./lib/secrets.mjs";

const args = process.argv.slice(2);
const opt = (k, d) => {
  const i = args.indexOf(k);
  return (i >= 0 ? args[i + 1] : d)?.replace(/^~\//, `${homedir()}/`);
};
const fail = m => {
  console.error(`new-signer: ${m}`);
  process.exit(1);
};
const secrets = opt("--secrets", "~/.aoa-pause-job/secrets");
const out = opt("--out", "~/.aoa-pause-job/keystore/pause-signer");
if (!okDir(secrets) || !okDir(out)) fail("--secrets and --out must be absolute plain paths");
if (existsSync(out)) fail("a keystore already exists there; refusing to overwrite it");

if (!existsSync(secrets)) mkdirSync(secrets, { recursive: true, mode: 0o700 });
const dp = secretsDirProblems(lstatSync(secrets), process.getuid());
if (dp.length) fail(dp.join("; "));
const pwFile = join(secrets, SECRET_NAMES.keystorePassword);
if (!existsSync(pwFile))
  writeFileSync(pwFile, randomBytes(32).toString("base64url"), { mode: 0o600, flag: "wx" });
let password;
try {
  password = readSecretFile(SECRET_NAMES.keystorePassword, secrets);
} catch (e) {
  fail(`the keystore unlock file: ${e?.name === "SafeError" ? e.message : "unreadable"}`);
}
if (password.length < 16) fail("the keystore password is shorter than 16 characters");

const w = ethers.Wallet.createRandom();
const json = await w.encrypt(password);
mkdirSync(dirname(out), { recursive: true, mode: 0o700 });
writeFileSync(out, json, { mode: 0o600, flag: "wx" });
console.log(`pause signer address: ${w.address}`);
console.log(`keystore: ${out} (mode 600)`);
console.log("next: fund it from a source SP has checked and DSR has approved (README, Funding)");
