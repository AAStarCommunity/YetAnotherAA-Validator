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
  renameSync,
  writeSync,
} from "node:fs";
import { join, relative, sep } from "node:path";

/** A guard failure: fixed text we wrote, never a path's contents. */
export class GuardError extends Error {
  constructor(message) {
    super(message);
    this.name = "GuardError";
  }
}

/**
 * Best effort: record a run that stopped before its round, so silence never reads as healthy
 * (clestons #434 F1). A minimal status.json in ~/.aoa-pause-detector/state, `clear: false`, the
 * reason in `startup` (fixed text from our own checks); preflight FAILs on it. Written as a temp
 * file (O_EXCL, O_NOFOLLOW) and renamed; any error is swallowed: the exit code and log still say it.
 */
/** A stop record carries the schema of the job whose directory it is in (clestons #435 L4). */
const STOP_SCHEMA = Object.freeze({
  state: "aoa-pause-detector-status/1",
  deadman: "aoa-pause-detector-deadman/1",
});
export function recordStop(home, text, sub = "state") {
  const dir = join(home, DIR, sub);
  const tmp = join(dir, `status.json.${process.pid}.stop`);
  // only into our own real directories: a symlinked ~/.aoa-pause-detector or state would carry the
  // write elsewhere (Codex R16 P1-1); then nothing is recorded (the exit code still says it)
  for (const d of [join(home, DIR), dir]) {
    let st;
    try {
      st = lstatSync(d);
    } catch {
      return;
    }
    if (!st.isDirectory() || st.isSymbolicLink() || st.uid !== process.getuid()) return;
  }
  try {
    const fd = openSync(
      tmp,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
      0o600
    );
    try {
      const body = Buffer.from(
        `${JSON.stringify({ schema: STOP_SCHEMA[sub] ?? STOP_SCHEMA.state, at: new Date().toISOString(), clear: false, startup: text })}\n`
      );
      writeSync(fd, body);
    } finally {
      closeSync(fd);
    }
    renameSync(tmp, join(dir, "status.json"));
  } catch {
    /* best effort */
  }
}

/**
 * The bundle's two entries, each with the one directory it may write: the detector writes its
 * state, the dead-man check (DSR: "no successful round in 2 h" alerts) writes only its own.
 */
export const ENTRIES = Object.freeze({
  detector: { script: "detector.mjs", write: "state" },
  deadman: { script: "deadman.mjs", write: "deadman" },
});

/**
 * A fixed label for an uncaught error (DSR: logged; Codex dm-R1 P1-3: never its text). Only an
 * allowlisted code shape (ERR_* / E*) or a known error class name passes; anything else, and any
 * getter that throws, is "error". Never throws.
 */
export function crashLabel(e) {
  try {
    const c = e?.code;
    if (typeof c === "string" && /^(ERR_[A-Z0-9_]{1,60}|E[A-Z0-9]{2,20})$/.test(c)) return c;
  } catch {
    /* a throwing getter */
  }
  try {
    const n = e?.name;
    if (typeof n === "string" && CRASH_NAMES.has(n)) return n;
  } catch {
    /* a throwing getter */
  }
  return "error";
}
const CRASH_NAMES = new Set([
  "Error",
  "TypeError",
  "RangeError",
  "ReferenceError",
  "SyntaxError",
  "SafeError",
  "GuardError",
  "AbortError",
  "TimeoutError",
]);

/** No completed detector round for this long is an outage (DSR: 2 h); shared by both entries. */
export const MAX_SILENCE_MS = 2 * 3600_000;

/**
 * The heartbeat's list of outages the dead-man has not acknowledged yet (Codex dm-R5): the old
 * heartbeat's gaps minus those `acked` (the dead-man's reportedGaps), plus a new gap when the
 * previous completed round is more than MAX_SILENCE_MS before `nowIso`. At most 20 kept: the
 * first and the latest. Pure.
 */
export function carryGaps(old, acked, nowIso) {
  const valid = g => typeof g?.from === "string" && typeof g?.to === "string";
  const ack = new Set(Array.isArray(acked) ? acked : []);
  let gaps = (Array.isArray(old?.gaps) ? old.gaps.filter(valid) : []).filter(g => !ack.has(g.from));
  const prev = Date.parse(old?.at);
  if (Number.isFinite(prev) && Date.parse(nowIso) - prev > MAX_SILENCE_MS && !ack.has(old.at))
    gaps.push({ from: old.at, to: nowIso });
  if (gaps.length > 20) gaps = [gaps[0], ...gaps.slice(-19)];
  return gaps;
}

/** The bundle's manifest file name, at the bundle root. */
export const MANIFEST = "MANIFEST.json";

/**
 * The bundled packages that CI's npm audit lets through by an exception (DSR 2026-11-18): none may
 * be bundled. An exception in scripts/ci/audit-exceptions.json is granted because the package is
 * dev tooling only; this is the check that the detector bundle, the thing deployed on the Mini,
 * really does not carry it. Pure: `names` are the bundled package names, `exceptions` the parsed
 * file. A file that is not a list of entries with a package is a problem too (fail closed).
 */
export function auditExceptedInBundle(names, exceptions) {
  if (!Array.isArray(exceptions) || exceptions.some(e => typeof e?.package !== "string"))
    return ["scripts/ci/audit-exceptions.json is not a list of exceptions with a package"];
  const excepted = new Map(exceptions.map(e => [e.package, e.id]));
  return [...new Set(names)]
    .filter(n => excepted.has(n))
    .sort()
    .map(n => `${n} is bundled, but CI's audit lets ${excepted.get(n)} in it through as dev-only`);
}
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
export function launchProblems({ execArgv, script, args, envNames, home, entry = "detector" }) {
  const p = [];
  const d = `${home}/${DIR}`;
  const e = ENTRIES[entry];
  if (!e) return [`unknown entry ${entry}`];
  const flag = execArgv?.[0];
  const want = [flag, `--allow-fs-read=${d}`, `--allow-fs-write=${d}/${e.write}`];
  if (
    !Array.isArray(execArgv) ||
    !["--permission", "--experimental-permission"].includes(flag) ||
    execArgv.join("\n") !== want.join("\n")
  )
    p.push(
      `node was not started with exactly the plist's flags (--permission, reads of ~/.aoa-pause-detector, writes of its ${e.write})`
    );
  if (script !== `${d}/app/deploy/pause-detector/${e.script}`)
    p.push(`the ${entry} is not run from its bundle, ~/.aoa-pause-detector/app`);
  // and nothing after the script but the plist's own arguments (clestons #434 F3)
  if (!Array.isArray(args) || args.join("\n") !== ["--config", `${d}/config.json`].join("\n"))
    p.push(
      "the arguments after the script are not exactly --config ~/.aoa-pause-detector/config.json"
    );
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
  // Daybreak H4 (DSR 2026-11-17): a bundle of files that differ from its recorded commit
  if (man.dirty !== undefined)
    p.push(
      "the bundle was built from files that differ from its recorded commit (--allow-dirty): a test bundle, never a deployed one"
    );
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

/**
 * The bundle at `app` is the one the deploy log recorded (Daybreak H4, DSR 2026-11-17): its
 * MANIFEST.json's `commit` is `expect.commit` (40 hex) and the file's sha256 is
 * `expect.manifestSha256` (64 hex), the two values bundle.mjs printed and SP's step-13 manifest
 * holds. So a stale bundle, or one from another commit, fails preflight. Returns the problems.
 */
export function bundleIdentityProblems(app, expect) {
  const commit = String(expect?.commit ?? "");
  const sha = String(expect?.manifestSha256 ?? "");
  const p = [];
  if (!/^[0-9a-f]{40}$/.test(commit))
    p.push("no expected detector commit (--detector-commit <40 hex>, from the deploy log)");
  if (!/^[0-9a-f]{64}$/.test(sha))
    p.push(
      "no expected manifest sha256 (--detector-manifest-sha256 <64 hex>, from the deploy log)"
    );
  let bytes;
  try {
    bytes = readOwn(join(app, MANIFEST), "the bundle manifest");
  } catch (e) {
    return [...p, e instanceof GuardError ? e.message : "the bundle manifest cannot be read"];
  }
  if (p.length) return p;
  let man;
  try {
    man = JSON.parse(bytes.toString("utf8"));
  } catch {
    return ["the bundle manifest is not JSON"];
  }
  if (man?.commit !== commit)
    p.push(
      `the bundle was built from ${String(man?.commit).slice(0, 12)}, not ${commit.slice(0, 12)}`
    );
  const got = createHash("sha256").update(bytes).digest("hex");
  if (got !== sha)
    p.push(`MANIFEST.json's sha256 is ${got.slice(0, 12)}…, not the recorded ${sha.slice(0, 12)}…`);
  return p;
}

/**
 * The dead-man check's own module graph, as bundle paths (clestons #435 B1, #436). The dead-man
 * verifies only these against the manifest, so a detector file that drifted, or a stray file
 * elsewhere in the bundle, stops the detector but not the job that alerts about it. A cell keeps
 * this list equal to deadman.mjs's static import closure.
 */
export const DEADMAN_GRAPH = Object.freeze([
  "deploy/pause-detector/deadman.mjs",
  "deploy/pause-detector/deadman-run.mjs",
  "deploy/pause-detector/lib/guard.mjs",
  "deploy/pause-detector/lib/notify.mjs",
  "deploy/pause-job/lib/safe-error.mjs",
  "deploy/pause-job/lib/secret-file.mjs",
]);

/**
 * `files` (bundle paths) are in the bundle at `app` exactly as its manifest lists them: every
 * directory on the way a real directory (lstat, so the loader cannot be led through a symlinked
 * directory), every file read without following a link (readOwn) and hashing to its entry.
 * Nothing else in the bundle is looked at. Returns the problems.
 */
export function graphProblems(app, files) {
  let man;
  try {
    man = readOwnJson(join(app, MANIFEST), "the bundle manifest");
  } catch (e) {
    return [e instanceof GuardError ? e.message : "the bundle manifest cannot be read"];
  }
  if (man?.schema !== "aoa-pause-detector-bundle/1" || !man.files || typeof man.files !== "object")
    return ["the bundle manifest is not a detector bundle manifest"];
  const p = [];
  const dirs = new Set([app]);
  for (const f of files) {
    const parts = f.split("/");
    for (let k = 1; k < parts.length; k++) dirs.add(join(app, ...parts.slice(0, k)));
  }
  for (const d of dirs) {
    let st;
    try {
      st = lstatSync(d);
    } catch {
      p.push(`${d} cannot be checked`);
      continue;
    }
    if (st.isSymbolicLink() || !st.isDirectory()) p.push(`${d} is not a real directory`);
  }
  for (const f of files) {
    if (typeof man.files[f] !== "string") {
      p.push(`${f} is not in the manifest`);
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
  }
  return p.slice(0, 20);
}

/** `d` is a real directory owned by this account (lstat). Returns the problems. */
export function realDirProblems(d, what) {
  let st;
  try {
    st = lstatSync(d);
  } catch {
    return [`${what} is not present`];
  }
  if (st.isSymbolicLink() || !st.isDirectory()) return [`${what} is not a real directory`];
  if (st.uid !== process.getuid()) return [`${what} is not owned by this account`];
  return [];
}

/** How often launchd runs the dead-man check, and how stale its status may be (three runs). */
export const DEADMAN_INTERVAL_MS = 15 * 60_000;
export const DEADMAN_STALE_MS = 3 * DEADMAN_INTERVAL_MS;

/**
 * Is the dead-man check itself running and delivering? `text` is its status.json (null when
 * missing). Not about the detector's heartbeat: the detector asks this every round (clestons #435
 * M1, #436: a dead-man that stopped is otherwise seen only on a manual preflight), and preflight
 * asks it before its own heartbeat checks. Returns the problems, fixed wording. Pure.
 */
export function deadmanRunProblems(text, now, maxAgeMs = DEADMAN_STALE_MS) {
  if (text === null) return ["the dead-man check has written no status.json"];
  let j;
  try {
    j = JSON.parse(text);
  } catch {
    return ["the dead-man's status.json is not JSON"];
  }
  if (j?.schema !== "aoa-pause-detector-deadman/1")
    return ["the dead-man's status.json is not the dead-man's"];
  const at = Date.parse(j.at);
  if (!Number.isFinite(at)) return ["the dead-man's status.json has no time"];
  if (at > now) return ["the dead-man's status.json is dated in the future"];
  if (now - at > maxAgeMs)
    return [`the dead-man's last run is ${Math.round((now - at) / 60_000)} min old`];
  if (typeof j.startup === "string") return [`the dead-man's last run stopped: ${j.startup}`];
  if (j.delivery?.ok === false || (Number.isSafeInteger(j.undelivered) && j.undelivered > 0))
    return ["the dead-man has undelivered alerts"];
  return [];
}
