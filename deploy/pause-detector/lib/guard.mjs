// The detector's startup guards (README "The guarantee"). Node builtins only, so they run before
// any dependency, and before the bundle's other files have been read: detector.mjs calls them
// first and imports run.mjs only when every one passes.
//
// What they guard against is an ACCIDENTAL signing path or an accidental exposure of key material,
// not a malicious dependency: Node's permission model is not a security boundary against malicious
// code, and the trust boundary is the price keeper's uid (DSR).
import { createHash } from "node:crypto";
import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  openSync,
  readSync,
  readdirSync,
} from "node:fs";
import { join, relative, sep } from "node:path";

/** A guard failure: fixed text we wrote, never a path's contents. */
export class GuardError extends Error {
  constructor(message) {
    super(message);
    this.name = "GuardError";
  }
}

/** The bundle's manifest file name, at the bundle root. */
export const MANIFEST = "MANIFEST.json";
/** The detector's directory, under the home directory: config, secrets, state and the bundle. */
export const DIR = ".aoa-pause-detector";

/**
 * Node's permission model, with no child processes, workers, native addons or WASI, and reads
 * that reach none of the usual key locations. `perm` is process.permission. Returns the problems.
 * Pure.
 */
export function permissionProblems(perm, home) {
  if (!perm || typeof perm.has !== "function")
    return ["not running under Node's permission model (node --permission, see the plist)"];
  const p = [];
  for (const [scope, what] of [
    ["child", "child processes"],
    ["worker", "worker threads"],
    ["addon", "native addons"],
    ["wasi", "WASI"],
  ])
    if (perm.has(scope)) p.push(`${what} are allowed`);
  for (const path of [
    "/",
    home,
    `${home}/.config`,
    `${home}/.foundry`,
    `${home}/.ssh`,
    `${home}/Dev`,
  ])
    if (perm.has("fs.read", path)) p.push(`${path} is readable`);
  if (perm.has("fs.write", "/") || perm.has("fs.write", home)) p.push("writes are not confined");
  return p;
}

// variables through which node or the loader take options or code before the script runs: a
// NODE_OPTIONS=--allow-fs-read=<key> widens the grants without touching argv (Codex R4 P1-1)
export const INJECTION_ENV = /^(NODE_.*|DYLD_.*|BASH_ENV|ENV|BASH_FUNC_.*|SHELLOPTS|PS4)$/;
/**
 * The only environment variables the detector runs with: what macOS and launchd give an agent,
 * and SSH_AUTH_SOCK (inherited on the Mini; an agent socket, which never hands out key material).
 * Anything else, a *_KEY among them, refuses the start.
 */
export const ENV_OK = new Set([
  "PATH",
  "HOME",
  "USER",
  "LOGNAME",
  "SHELL",
  "TMPDIR",
  "LANG",
  "__CF_USER_TEXT_ENCODING",
  "__CFBundleIdentifier",
  "XPC_FLAGS",
  "XPC_SERVICE_NAME",
  "OSLogRateLimit",
  "SSH_AUTH_SOCK",
]);

/**
 * The launch, exactly as the plist has it: node's own flags are
 *   [--permission, --allow-fs-read=<home>/.aoa-pause-detector,
 *    --allow-fs-write=<home>/.aoa-pause-detector/state]
 * (Node 20: --experimental-permission), the script is the bundle's entry
 * <home>/.aoa-pause-detector/app/deploy/pause-detector/detector.mjs, and no option-injecting
 * variable is set. Reads reach ONLY the detector's own directory: never a repository checkout,
 * which may hold node_state.json, .env.sepolia or .keys/ (Codex R7 P1-1). Pure.
 */
export function launchProblems({ execArgv, script, envNames, home }) {
  const p = [];
  const d = `${home}/${DIR}`;
  const flag = execArgv?.[0];
  const want = [flag, `--allow-fs-read=${d}`, `--allow-fs-write=${d}/state`];
  if (
    !Array.isArray(execArgv) ||
    !["--permission", "--experimental-permission"].includes(flag) ||
    execArgv.join("\n") !== want.join("\n")
  )
    p.push(
      "node was not started with exactly the plist's flags (--permission, reads of ~/.aoa-pause-detector, writes of its state)"
    );
  if (script !== `${d}/app/deploy/pause-detector/detector.mjs`)
    p.push("the detector is not run from its bundle, ~/.aoa-pause-detector/app");
  const bad = (envNames ?? []).filter(n => INJECTION_ENV.test(n));
  if (bad.length) p.push(`option-injecting variables are set: ${bad.join(", ")}`);
  // an allowlist, not a denylist: a stale KEEPER_PRIVATE_KEY (or any other variable) inherited
  // from launchd would be key material inside the process (Codex R8 P1-2)
  const extra = (envNames ?? []).filter(n => !ENV_OK.has(n) && !INJECTION_ENV.test(n));
  if (extra.length) p.push(`variables outside the allowlist are set: ${extra.join(", ")}`);
  return p;
}

/**
 * The bytes of a file of ours, opened without following a symlink and checked on its descriptor:
 * a regular file, owned by this uid, writable by nobody else, at most `max` bytes. Node's
 * permission model follows a symlink inside a granted directory (Codex R5 P1-1), so nothing is
 * ever read through one. Throws a GuardError naming `what` only.
 */
export function readOwn(path, what, max = 1 << 20) {
  let fd;
  try {
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  } catch (e) {
    throw new GuardError(
      `${what}: ${e?.code === "ELOOP" ? "is a symlink" : "missing or unreadable"}`
    );
  }
  try {
    const st = fstatSync(fd);
    if (!st.isFile()) throw new GuardError(`${what}: not a regular file`);
    if (st.uid !== process.getuid()) throw new GuardError(`${what}: not owned by this account`);
    if ((st.mode & 0o022) !== 0) throw new GuardError(`${what}: writable by group or others`);
    if (st.size > max) throw new GuardError(`${what}: too large`);
    const buf = Buffer.alloc(st.size);
    let off = 0;
    while (off < st.size) {
      const n = readSync(fd, buf, off, st.size - off, off);
      if (n <= 0) break;
      off += n;
    }
    if (off !== st.size) throw new GuardError(`${what}: short read`);
    return buf;
  } finally {
    closeSync(fd);
  }
}

/** readOwn, parsed as JSON; a parse failure never echoes the bytes. */
export function readOwnJson(path, what) {
  const buf = readOwn(path, what);
  try {
    return JSON.parse(buf.toString("utf8"));
  } catch {
    throw new GuardError(`${what}: not JSON`);
  }
}

/**
 * Every entry under `dir`, by lstat, never following a link: { files: [relative path], problems }.
 * Any symlink, and anything that is neither a regular file nor a directory, is a problem (the
 * permission model would follow a link out of the granted tree). At most `limit` entries.
 */
export function walk(dir, limit = 50_000) {
  const files = [];
  const problems = [];
  const stack = [dir];
  let seen = 0;
  while (stack.length) {
    const d = stack.pop();
    let st;
    try {
      st = lstatSync(d);
    } catch {
      problems.push(`${d} cannot be checked`);
      continue;
    }
    if (++seen > limit)
      return { files, problems: [...problems, `more than ${limit} entries under ${dir}`] };
    if (st.isSymbolicLink()) problems.push(`${d} is a symlink`);
    else if (st.isDirectory()) {
      let names = [];
      try {
        names = readdirSync(d);
      } catch {
        problems.push(`${d} cannot be listed`);
      }
      for (const n of names) stack.push(join(d, n));
    } else if (st.isFile()) files.push(relative(dir, d).split(sep).join("/"));
    else problems.push(`${d} is not a regular file or directory`);
  }
  return { files, problems };
}

/** The symlink (and odd-entry) problems under `dir`. */
export const symlinkProblems = (dir, limit) => walk(dir, limit).problems;

/**
 * The bundle at `app` is exactly its manifest: no symlink, no file the manifest does not list, no
 * listed file missing, every file's sha256 as listed. So the process reads nothing in its granted
 * tree that the bundler did not put there (Codex R7 P1-1), and run.mjs is imported only after this
 * passes (Codex R7 P1-2: sp-pin.json is read at import). Returns the problems.
 */
export function bundleProblems(app) {
  let man;
  try {
    man = readOwnJson(join(app, MANIFEST), "the bundle manifest");
  } catch (e) {
    return [e instanceof GuardError ? e.message : "the bundle manifest cannot be read"];
  }
  if (man?.schema !== "aoa-pause-detector-bundle/1" || !man.files || typeof man.files !== "object")
    return ["the bundle manifest is not a detector bundle manifest"];
  const { files, problems } = walk(app);
  const p = [...problems];
  const listed = new Set(Object.keys(man.files));
  for (const f of files) {
    if (f === MANIFEST) continue;
    if (!listed.has(f)) {
      p.push(`${f} is in the bundle but not in its manifest`);
      continue;
    }
    let h;
    try {
      h = createHash("sha256")
        .update(readOwn(join(app, f), f, 64 << 20))
        .digest("hex");
    } catch (e) {
      p.push(e instanceof GuardError ? e.message : `${f}: unreadable`);
      continue;
    }
    if (h !== man.files[f]) p.push(`${f} does not hash to its manifest entry`);
    listed.delete(f);
  }
  for (const f of listed) p.push(`${f} is in the manifest but missing`);
  return p.slice(0, 20);
}
