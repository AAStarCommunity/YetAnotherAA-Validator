// Single-instance lock for the watcher's publication loop (Codex W2a R2): two processes must not
// publish the same records (and must not share the writer's nonces). O_EXCL lockfile holding the
// owner's pid and start time; a lock whose pid is no longer alive is reclaimed. The holder reloads
// state after acquiring, so it never acts on a snapshot taken before another holder's writes.
import { openSync, writeSync, closeSync, readFileSync, unlinkSync } from "node:fs";

function alive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return e.code === "EPERM"; // exists but not ours: treat as alive
  }
}

/** Acquire `path` or throw. Returns release(). */
export function acquireLock(path) {
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const fd = openSync(path, "wx", 0o600);
      writeSync(
        fd,
        JSON.stringify({ pid: process.pid, startedAt: new Date().toISOString() }) + "\n"
      );
      closeSync(fd);
      return () => {
        try {
          const cur = JSON.parse(readFileSync(path, "utf8"));
          if (cur.pid === process.pid) unlinkSync(path);
        } catch {
          /* already gone */
        }
      };
    } catch (e) {
      if (e.code !== "EEXIST") throw e;
      let holder = null;
      try {
        holder = JSON.parse(readFileSync(path, "utf8"));
      } catch {
        holder = null;
      }
      if (holder && Number.isSafeInteger(holder.pid) && alive(holder.pid)) {
        throw new Error(
          `another watcher holds ${path} (pid ${holder.pid}, since ${holder.startedAt})`
        );
      }
      unlinkSync(path); // stale: its owner is gone
    }
  }
  throw new Error(`could not acquire ${path}`);
}
