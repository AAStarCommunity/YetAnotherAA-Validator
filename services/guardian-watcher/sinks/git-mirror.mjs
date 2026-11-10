// GitHub mirror sink: append record files to the `disclosure-records` branch of a dedicated clone
// on the Mini, pushed with a repo-scoped deploy key held in the ssh-agent (loaded from the
// Keychain, never a key file). Idempotent: a path that already holds identical bytes returns the
// commit that added it. The branch is protected by a ruleset (no force-push, no delete), so a
// non-fast-forward is an error, never a rewrite. All git calls are argv-only (no shell).
import { execFile } from "node:child_process";
import { mkdirSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { dirname, resolve, sep } from "node:path";

const git = (cwd, args) =>
  new Promise((res, rej) =>
    execFile(
      "git",
      ["-C", cwd, ...args],
      { timeout: 120_000, maxBuffer: 1 << 20 },
      (err, stdout, stderr) =>
        err
          ? rej(new Error(`git ${args[0]}: ${String(stderr).trim().slice(0, 300)}`))
          : res(String(stdout).trim())
    )
  );

export function gitMirror({ clone, branch = "disclosure-records", remote = "origin", repoUrl }) {
  if (!clone) throw new Error("mirror: clone directory required");
  const sameBytes = (p, bytes) =>
    existsSync(p) && Buffer.compare(readFileSync(p), Buffer.from(bytes)) === 0;
  return {
    async commit(path, bytes, message) {
      const abs = resolve(clone, path);
      if (!abs.startsWith(resolve(clone) + sep))
        throw new Error(`mirror: path escapes the clone: ${path}`);
      await git(clone, ["fetch", "--quiet", remote, branch]);
      await git(clone, ["checkout", "--quiet", "-B", branch, `${remote}/${branch}`]);
      if (sameBytes(abs, bytes)) {
        const c = await git(clone, ["log", "-1", "--format=%H", "--", path]);
        return { commit: c, url: repoUrl ? `${repoUrl}/blob/${c}/${path}` : null, existing: true };
      }
      if (existsSync(abs))
        throw new Error(`mirror: ${path} exists with different bytes; refusing to overwrite`);
      mkdirSync(dirname(abs), { recursive: true });
      writeFileSync(abs, bytes);
      await git(clone, ["add", "--", path]);
      await git(clone, [
        "-c",
        "user.name=dvt-guardian-watcher",
        "-c",
        "user.email=watcher@invalid",
        "commit",
        "--quiet",
        "-m",
        message,
        "--",
        path,
      ]);
      await git(clone, ["push", "--quiet", remote, `HEAD:refs/heads/${branch}`]);
      const c = await git(clone, ["rev-parse", "HEAD"]);
      return { commit: c, url: repoUrl ? `${repoUrl}/blob/${c}/${path}` : null };
    },
  };
}
