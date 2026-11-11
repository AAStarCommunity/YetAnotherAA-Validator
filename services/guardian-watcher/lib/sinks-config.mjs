// Sink construction from the watcher config (W2c). Secrets are read once at startup from the
// macOS Keychain (lib/keychain.mjs), never from config, env or files. The writer key is an
// encrypted keystore JSON whose password is a Keychain item (M0 §5.5). The registry sink is
// rebuilt on every run with the roles read from chain at that moment (lib/publisher.mjs).
//
// Keychain layout (DSR 0829236d): ONE account, "aoa-watcher", and one service per secret:
//   aoa-dvt-pinata-jwt, aoa-dvt-filebase-token, aoa-dvt-alert-bot-token,
//   aoa-dvt-watcher-keystore-pw (the writer = the watcher sender keystore's password).
// Each item's service defaults to that name; config may name another.
//
// config.publish:
//   { "enabled": true, "keychainAccount": "aoa-watcher",
//     "pinners": [ { "type": "pinata", "gateway": "https://<name>.mypinata.cloud" },
//                  { "type": "filebase" } ],
//     "telegram": { "chatId": "-100…" },
//     "mirror": { "clone": "/path/to/bare/clone.git", "branch": "disclosure-records",
//                 "repoUrl": "https://github.com/AAStarCommunity/YetAnotherAA-Validator" },
//     "registry": { "address": "0x…", "fromBlock": N, "deployer": "0x…",
//                   "keystore": "~/.aoa-watcher/sender.keystore.json" },
//     "lockPort": 47331, "maxPendingMs": 1800000, "reverifyEveryMs": 604800000, "alertRepeatMs": 3600000 }
import { readFileSync } from "node:fs";
import { ethers } from "ethers";
import { readSecret as keychainRead } from "./keychain.mjs";
import { SafeError } from "./safe-error.mjs";
import { pinataPinner } from "../sinks/pinata.mjs";
import { filebasePinner } from "../sinks/filebase.mjs";
import { telegramSink } from "../sinks/telegram.mjs";
import { gitMirror } from "../sinks/git-mirror.mjs";
import { registrySink } from "../sinks/registry.mjs";

const DEFAULTS = {
  lockPort: 47331,
  maxPendingMs: 30 * 60_000,
  reverifyEveryMs: 7 * 24 * 3_600_000,
  alertRepeatMs: 3_600_000,
  keychainAccount: "aoa-watcher",
};
/** The Keychain service of each secret, unless the config names another (DSR 0829236d). */
export const SERVICE_DEFAULTS = {
  pinata: "aoa-dvt-pinata-jwt",
  filebase: "aoa-dvt-filebase-token",
  telegram: "aoa-dvt-alert-bot-token",
  registry: "aoa-dvt-watcher-keystore-pw",
};
const okService = s => typeof s === "string" && /^[A-Za-z0-9._-]{1,128}$/.test(s);

/** Validate config.publish; throws SafeError naming the first problem. */
export function publishConfig(c) {
  const p = { ...DEFAULTS, ...(c ?? {}) };
  const need = (ok, what) => {
    if (!ok) throw new SafeError(`config.publish: ${what}`);
  };
  need(Array.isArray(p.pinners) && p.pinners.length > 0, "pinners required (at least one)");
  for (const [i, x] of p.pinners.entries()) {
    need(
      x.type === "pinata" || x.type === "filebase",
      `pinners[${i}].type must be pinata or filebase`
    );
    if (x.service === undefined) x.service = SERVICE_DEFAULTS[x.type];
    need(okService(x.service), `pinners[${i}].service must be a Keychain service name`);
    if (x.type === "pinata")
      need(/^https:\/\//.test(x.gateway ?? ""), `pinners[${i}].gateway https URL required`);
  }
  need(p.telegram?.chatId, "telegram.chatId required");
  p.telegram = { ...p.telegram, service: p.telegram.service ?? SERVICE_DEFAULTS.telegram };
  need(okService(p.telegram.service), "telegram.service must be a Keychain service name");
  need(p.mirror?.clone, "mirror.clone required");
  const r = p.registry ?? {};
  need(ethers.isAddress(r.address ?? ""), "registry.address required");
  need(Number.isSafeInteger(r.fromBlock) && r.fromBlock >= 0, "registry.fromBlock required");
  need(ethers.isAddress(r.deployer ?? ""), "registry.deployer (release manifest) required");
  need(r.keystore, "registry.keystore required");
  p.registry = { ...r, service: r.service ?? SERVICE_DEFAULTS.registry };
  need(okService(p.registry.service), "registry.service must be a Keychain service name");
  need(okService(p.keychainAccount), "keychainAccount must be a Keychain account name");
  for (const k of ["lockPort", "maxPendingMs", "reverifyEveryMs", "alertRepeatMs"])
    need(Number.isSafeInteger(p[k]) && p[k] > 0, `${k} must be a positive integer`);
  return p;
}

/**
 * Read every secret and decrypt the writer keystore. `readSecret(service, account)` is injectable
 * for tests. Returns { pinners, telegram, mirror, wallet, registryFor(roles) }.
 */
export async function buildSinks(p, provider, { readSecret = keychainRead } = {}) {
  const acct = p.keychainAccount;
  const pinners = [];
  for (const x of p.pinners) {
    const token = await readSecret(x.service, acct);
    pinners.push(
      x.type === "pinata"
        ? pinataPinner({
            token,
            gateway: x.gateway,
            ...(x.uploadUrl ? { uploadUrl: x.uploadUrl } : {}),
          })
        : filebasePinner({
            token,
            ...(x.gateway ? { gateway: x.gateway } : {}),
            ...(x.rpcUrl ? { rpcUrl: x.rpcUrl } : {}),
          })
    );
  }
  const telegram = telegramSink({
    token: await readSecret(p.telegram.service, acct),
    chatId: String(p.telegram.chatId),
    ...(p.telegram.apiBase ? { apiBase: p.telegram.apiBase } : {}),
  });
  const mirror = gitMirror({
    clone: p.mirror.clone,
    branch: p.mirror.branch,
    repoUrl: p.mirror.repoUrl,
  });
  let json;
  try {
    json = readFileSync(p.registry.keystore, "utf8");
  } catch {
    throw new SafeError("registry keystore unreadable");
  }
  let wallet;
  try {
    wallet = (
      await ethers.Wallet.fromEncryptedJson(json, await readSecret(p.registry.service, acct))
    ).connect(provider);
  } catch (e) {
    if (e instanceof SafeError) throw e;
    throw new SafeError("registry keystore could not be decrypted");
  }
  const registryFor = (roles, currentRoles) =>
    registrySink({
      provider,
      wallet,
      registry: p.registry.address,
      fromBlock: p.registry.fromBlock,
      roles,
      currentRoles,
    });
  return { pinners, telegram, mirror, wallet, registryFor };
}
