// GitHub mirror sink: append record files to the `disclosure-records` branch, pushed with a
// repo-scoped deploy key held in the ssh-agent (loaded from the Keychain, never a key file).
//
// Plumbing only, no working tree (Codex W2b R1 H5/H6): every read is of the FETCHED remote tree
// and every write goes through hash-object / a private temporary index / commit-tree, so nothing
// on the filesystem (a symlink, a locally modified or untracked file) can redirect a write or
// stand in for committed bytes. `clone` may be a bare repository.
// - Idempotent: a path whose blob in the fetched branch tip has identical bytes returns the commit
//   that last touched it, without writing.
// - Never rewrites: a path that exists with other bytes, or as anything but a regular file, is
//   refused. The push is a plain fast-forward of the fetched tip; the branch is also protected by
//   a ruleset (no force-push, no delete). A non-fast-forward (a concurrent writer) is an error;
//   the next run fetches again and either finds the record or appends on the new tip.
// - Read-back: after the push, the remote branch is fetched again and must contain the commit,
//   and the commit's blob at the path must equal the bytes, before success is returned.
// All git calls are argv-only (no shell).
import { spawn } from "node:child_process";
import { ethers } from "ethers";
import { mkdtempSync, rmSync } from "node:fs";
import { SinkError, guarded } from "./errors.mjs";
import { join, posix } from "node:path";

function git(cwd, args, { input, env } = {}) {
  return new Promise((res, rej) => {
    const p = spawn("git", ["-C", cwd, ...args], {
      env: { ...process.env, GIT_TERMINAL_PROMPT: "0", ...env },
      stdio: ["pipe", "pipe", "pipe"],
    });
    const out = [];
    const err = [];
    let n = 0;
    const t = setTimeout(() => p.kill("SIGKILL"), 120_000);
    p.stdout.on("data", d => {
      n += d.length;
      if (n <= 4 << 20) out.push(d);
    });
    p.stderr.on("data", d => err.length < 64 && err.push(d));
    p.on("error", e => {
      clearTimeout(t);
      rej(new SinkError(`git ${args[0]}: spawn failed`));
    });
    p.on("close", code => {
      clearTimeout(t);
      if (code === 0) return res(Buffer.concat(out));
      // stderr is untrusted (it can carry a remote URL with credentials): it only selects one of
      // these fixed categories and is then dropped (Codex W2b R2 H2).
      // with --porcelain git reports a push's per-ref status ("[rejected] (stale info)") on stdout
      // (#411 review F3), so both streams select the category; neither is ever kept
      const se = Buffer.concat([...out, ...err]).toString();
      const cat = /non-fast-forward|fetch first|stale info/i.test(se)
        ? "rejected (the branch moved)"
        : /could not read from remote|permission denied|authentication|could not resolve|connection|timed out/i.test(
              se
            )
          ? "remote unreachable or not authorized"
          : /couldn't find remote ref|not a valid object|unknown revision|bad revision/i.test(se)
            ? "ref or object not found"
            : /\[remote rejected\]|\[rejected\]|failed to push|pre-receive hook declined/i.test(se)
              ? "push rejected by the remote"
              : `exit ${Number.isInteger(code) ? code : "signal"}`;
      rej(new SinkError(`git ${args[0]}: ${cat}`));
    });
    p.stdin.end(input ?? undefined);
  });
}
const text = async (...a) => (await git(...a)).toString().trim();

/** A record path: under records/, forward slashes, no empty/dot/.git/-leading segments, safe charset. */
export function checkMirrorPath(path) {
  const p = String(path);
  const segs = p.split("/");
  const ok =
    /^[A-Za-z0-9._/-]+$/.test(p) &&
    !p.startsWith("/") &&
    posix.normalize(p) === p &&
    p.startsWith("records/") &&
    segs.every(
      s => s !== "" && s !== "." && s !== ".." && !s.startsWith("-") && s.toLowerCase() !== ".git"
    );
  // Fixed text: the rejected value is not ours to echo (Codex W2b R5); its digest tells cases apart.
  if (!ok)
    throw new SinkError(
      `mirror: path escapes or is not a plain record path (keccak ${ethers.keccak256(ethers.toUtf8Bytes(p)).slice(0, 18)})`
    );
  return p;
}

/** `beforePush` is a test seam: awaited after the commit is built, before it is pushed. */
export function gitMirror({
  clone,
  branch = "disclosure-records",
  remote = "origin",
  repoUrl,
  beforePush,
}) {
  if (!clone) throw new SinkError("mirror: clone directory required");
  if (!/^[A-Za-z0-9._/-]+$/.test(branch) || branch.startsWith("-"))
    throw new SinkError("mirror: bad branch name");
  const tracking = `refs/watcher/${branch}`; // our own ref: nothing else updates it
  const fetchTip = async () => {
    await git(clone, [
      "fetch",
      "--quiet",
      "--no-tags",
      remote,
      `+refs/heads/${branch}:${tracking}`,
    ]);
    return text(clone, ["rev-parse", "--verify", `${tracking}^{commit}`]);
  };
  // { mode, blob } of `path` in commit `c`, or null if absent.
  const entry = async (c, path) => {
    const ls = await text(clone, ["ls-tree", "-z", "--full-tree", c, "--", path]);
    if (!ls) return null;
    const [meta, name] = ls.replace(/\0$/, "").split("\t");
    if (name !== path) return null;
    const [mode, type, blob] = meta.split(" ");
    return { mode, type, blob };
  };
  const blobBytes = blob => git(clone, ["cat-file", "blob", blob]);
  const url = (c, path) => (repoUrl ? `${repoUrl}/blob/${c}/${path}` : null);

  return {
    commit: (path, bytes, message) =>
      guarded("mirror commit", () => commitOnce(path, bytes, message)),
  };

  async function commitOnce(path, bytes, message) {
    path = checkMirrorPath(path);
    const want = Buffer.from(bytes);
    const tip = await fetchTip();
    const cur = await entry(tip, path);
    if (cur) {
      if (cur.mode !== "100644" || cur.type !== "blob")
        throw new SinkError(`mirror: ${path} exists as ${cur.mode} ${cur.type}; refusing`);
      if (Buffer.compare(await blobBytes(cur.blob), want) !== 0)
        throw new SinkError(`mirror: ${path} exists with different bytes; refusing to overwrite`);
      const c = await text(clone, ["log", "-1", "--format=%H", tip, "--", path]);
      return { commit: c, url: url(c, path), existing: true };
    }
    // Any prefix of the path that is a file or symlink in the tree would make the new entry
    // ambiguous; refuse rather than let update-index replace it.
    const segs = path.split("/");
    for (let i = 1; i < segs.length; i++) {
      const e = await entry(tip, segs.slice(0, i).join("/"));
      if (e && e.type !== "tree")
        throw new SinkError(`mirror: ${segs.slice(0, i).join("/")} is not a directory; refusing`);
    }
    const blob = await text(clone, ["hash-object", "-w", "--stdin"], { input: want });
    const gitDir = await text(clone, ["rev-parse", "--absolute-git-dir"]);
    // A private directory per call (Codex W2b R2 M4): concurrent calls never share an index.
    const tmp = mkdtempSync(join(gitDir, "watcher-index-"));
    const env = { GIT_INDEX_FILE: join(tmp, "index") };
    let commit;
    try {
      await git(clone, ["read-tree", tip], { env });
      await git(clone, ["update-index", "--add", "--cacheinfo", `100644,${blob},${path}`], {
        env,
      });
      const tree = await text(clone, ["write-tree"], { env });
      commit = await text(clone, ["commit-tree", tree, "-p", tip, "-F", "-"], {
        input: Buffer.from(String(message)),
        env: {
          GIT_AUTHOR_NAME: "dvt-guardian-watcher",
          GIT_AUTHOR_EMAIL: "watcher@invalid",
          GIT_COMMITTER_NAME: "dvt-guardian-watcher",
          GIT_COMMITTER_EMAIL: "watcher@invalid",
        },
      });
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
    if (beforePush) await beforePush();
    // Fast-forward only, and only from the tip we built on (lease), never forced.
    await git(clone, [
      "push",
      "--quiet",
      "--porcelain",
      `--force-with-lease=refs/heads/${branch}:${tip}`,
      remote,
      `${commit}:refs/heads/${branch}`,
    ]);
    // Read-back from the remote: the branch contains our commit and it holds exactly the bytes.
    const after = await fetchTip();
    try {
      await git(clone, ["merge-base", "--is-ancestor", commit, after]);
    } catch {
      throw new SinkError("mirror: pushed commit is not on the remote branch after push");
    }
    const got = await entry(commit, path);
    if (!got || Buffer.compare(await blobBytes(got.blob), want) !== 0)
      throw new SinkError("mirror: read-back of the pushed record does not match");
    return { commit, url: url(commit, path) };
  }
}
