#!/usr/bin/env node
// Create the guardian watcher's sender (DisclosureRegistry writer) as an encrypted JSON keystore,
// its password taken from the macOS Keychain (account aoa-watcher, service
// aoa-dvt-watcher-keystore-pw, DSR 0829236d; M0 §5.5). The key never exists in plaintext on disk,
// never in .env, and is never printed: only the new address is.
//
//   node deploy/guardian-watcher/new-sender-keystore.mjs [--out ~/.aoa-watcher/sender.keystore.json]
//
// Refuses to overwrite an existing keystore (a second run would orphan the first sender).
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { ethers } from "ethers";

const args = process.argv.slice(2);
const i = args.indexOf("--out");
const out =
  i >= 0
    ? args[i + 1].replace(/^~\//, `${homedir()}/`)
    : join(homedir(), ".aoa-watcher/sender.keystore.json");
const fail = m => {
  console.error(`new-sender-keystore: ${m}`);
  process.exit(1);
};
if (existsSync(out)) fail("a keystore already exists there; refusing to overwrite it");
const r = spawnSync(
  "security",
  ["find-generic-password", "-a", "aoa-watcher", "-s", "aoa-dvt-watcher-keystore-pw", "-w"],
  { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }
);
if (r.status !== 0)
  fail("no password in the Keychain (service aoa-dvt-watcher-keystore-pw, account aoa-watcher)");
const password = r.stdout.replace(/\n$/, "");
if (password.length < 16) fail("the Keychain password is shorter than 16 characters");
const w = ethers.Wallet.createRandom();
const json = await w.encrypt(password);
mkdirSync(dirname(out), { recursive: true, mode: 0o700 });
writeFileSync(out, json, { mode: 0o600, flag: "wx" });
console.log(`sender address: ${w.address}`);
console.log(`keystore: ${out} (mode 600)`);
