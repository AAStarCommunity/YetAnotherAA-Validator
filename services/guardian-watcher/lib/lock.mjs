// Single-instance lock for the watcher's publication loop (Codex W2a R2/R3): two processes must not
// publish the same records, share journals, or compete for the writer's nonces.
//
// The lock is an OS-held resource, not a file: a listening TCP socket on 127.0.0.1:<port>. Binding is
// atomic (EADDRINUSE for every second holder), and the kernel releases it when the process exits,
// however it exits, so there is no stale state to reclaim and no pid-reuse or unlink race. This is
// a single-host mechanism by construction (the watcher runs only on the Mac Mini, M0 §5.1); a
// multi-host deployment would need a distributed lock with fencing instead.
import { createServer } from "node:net";

export const DEFAULT_LOCK_PORT = 47331;

/** Acquire the lock or throw. Resolves to release(). */
export function acquireLock(port = DEFAULT_LOCK_PORT) {
  return new Promise((resolve, reject) => {
    const srv = createServer(sock => sock.destroy());
    srv.once("error", e =>
      reject(
        e.code === "EADDRINUSE"
          ? new Error(`another watcher holds the lock (127.0.0.1:${port} in use)`)
          : e
      )
    );
    srv.listen({ host: "127.0.0.1", port, exclusive: true }, () => {
      srv.unref(); // never keeps the process alive on its own
      resolve(() => new Promise(r => srv.close(() => r())));
    });
  });
}
