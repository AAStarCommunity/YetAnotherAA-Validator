// Secrets from the macOS Keychain (M0 §5.5): provider tokens, the Telegram bot token, the keystore
// password, the mirror deploy key. Read through `security find-generic-password -w`, by argv (no
// shell), never logged, never written to disk or env. A missing item is an error naming the item,
// never its value.
import { execFile } from "node:child_process";

/** Read the generic password for (service, account). `run` is injectable for tests. */
export function readSecret(service, account, run = execFile) {
  return new Promise((resolve, reject) => {
    run(
      "/usr/bin/security",
      ["find-generic-password", "-s", service, "-a", account, "-w"],
      { timeout: 10_000, maxBuffer: 64 * 1024 },
      (err, stdout) => {
        if (err)
          return reject(
            new Error(`Keychain item ${service}/${account} unavailable (${err.code ?? "error"})`)
          );
        const v = String(stdout).replace(/\n$/, "");
        if (!v) return reject(new Error(`Keychain item ${service}/${account} is empty`));
        resolve(v);
      }
    );
  });
}
