// Secrets as files (DSR 0578c49a, 3e89cecd: no macOS Keychain), taken from the retired guardian
// watcher (feat/no-keychain-secrets 6901343f) for the pause job (DSR 4019916a). One directory, mode
// exactly 0700, owned by the job's account, holding one file per secret, each a regular file of mode
// exactly 0600 owned by that account, one link, one plain line. The file names are fixed
// (SECRET_NAMES); the config names only the directory. Write each one without argv or history:
//   read -rs "v?value: "; install -m 600 /dev/null "$DIR/<name>"; printf '%s' "$v" > "$DIR/<name>"
//
// What this protects against, and what not: another account without sudo cannot read the files.
// An admin with sudo, or anything running as the job's account, reads them. A leak of this
// directory is a leak of the pause signer (keystore + password), which holds no role and only ever
// calls the permissionless pauseUnderstakedOperator, capped in spend (README).
//
// A value is the file's bytes with ONE trailing newline removed; empty, oversized or containing any
// other control character is refused. Errors name the item, never its value.
import { readSecretFile as readNamed } from "./secret-file.mjs";

export {
  SAFE_DIR,
  okDir,
  dirProblems,
  secretsDirProblems,
  secretFileProblems,
  secretValue,
} from "./secret-file.mjs";

/** The fixed file name of each secret. */
export const SECRET_NAMES = Object.freeze({
  keystorePassword: "aoa-dvt-pause-keystore-pw",
  rpcPrimary: "aoa-dvt-pause-rpc-primary",
  rpcFallback: "aoa-dvt-pause-rpc-fallback",
  // the existing aastar-monitor bot the keeper already uses on the Mini (DSR bd595f0f)
  telegram: "aoa-dvt-alert-bot-token",
});

/** readSecretFile over the pause job's own name table (lib/secret-file.mjs). */
export const readSecretFile = (name, dir, opts = {}) =>
  readNamed(name, dir, { ...opts, names: SECRET_NAMES });
