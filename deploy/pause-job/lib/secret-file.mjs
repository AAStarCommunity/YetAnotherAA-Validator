// Secret files, the generic part (no names): one directory, mode exactly 0700, owned by the job's
// account, holding one file per secret, each a regular file of mode exactly 0600 owned by that
// account, one link, one plain line. Each job keeps its own fixed table of file names and passes
// it to readSecretFile (the pause job: secrets.mjs; the pause detector: its own table). Taken from
// the retired guardian watcher (feat/no-keychain-secrets 6901343f). Errors name the item, never
// its value.
import { closeSync, constants, fstatSync, lstatSync, openSync, readSync } from "node:fs";
import { join } from "node:path";
import { SafeError } from "./safe-error.mjs";

const MAX_BYTES = 64 * 1024;
/** An absolute plain path: no space, quote, `$`, `~` or `..` segment (it is placed in a wrapper). */
export const SAFE_DIR = /^\/[A-Za-z0-9._/-]+$/;
export const okDir = d =>
  typeof d === "string" && SAFE_DIR.test(d) && !/(^|\/)\.\.(\/|$)/.test(d) && d.length <= 512;

const modeOf = st => (st.mode & 0o777).toString(8).padStart(3, "0");

/** Problems of a private directory (lstat-like `st`): `what` names it in the fixed wording. Pure. */
export function dirProblems(st, uid, what) {
  if (!st) return [`the ${what} is not present`];
  const p = [];
  if (st.isSymbolicLink?.()) p.push(`the ${what} is a symlink`);
  else if (!st.isDirectory?.()) p.push(`the ${what} is not a directory`);
  if ((st.mode & 0o777) !== 0o700) p.push(`${what} mode ${modeOf(st)}, required 700`);
  if (st.uid !== uid) p.push(`the ${what} is not owned by the job's account`);
  return p;
}

/** Problems of the secrets directory itself (lstat-like `st`), fixed wording. Pure. */
export function secretsDirProblems(st, uid) {
  if (!st) return ["the secrets directory is not present"];
  const p = [];
  if (st.isSymbolicLink?.()) p.push("the secrets directory is a symlink");
  else if (!st.isDirectory?.()) p.push("the secrets directory is not a directory");
  if ((st.mode & 0o777) !== 0o700) p.push(`secrets directory mode ${modeOf(st)}, required 700`);
  if (st.uid !== uid) p.push("the secrets directory is not owned by the job's account");
  return p;
}

/** Problems of one opened secret file (fstat of the descriptor), fixed wording. Pure. */
export function secretFileProblems(st, uid) {
  const p = [];
  if (!st.isFile?.()) p.push("not a regular file");
  if ((st.mode & 0o777) !== 0o600) p.push(`mode ${modeOf(st)}, required 600`);
  if (st.uid !== uid) p.push("not owned by the job's account");
  if (st.nlink !== 1) p.push("has another hard link");
  if (st.size === 0) p.push("empty");
  if (st.size > MAX_BYTES) p.push("too large");
  return p;
}

/** The value of a secret file's bytes, or null when it is not one plain line. Pure. */
export function secretValue(buf) {
  const s = buf.toString("utf8").replace(/\n$/, "");
  if (!s || /[\x00-\x1f\x7f]/.test(s)) return null;
  return s;
}

const defaultFs = { lstatSync, openSync, fstatSync, readSync, closeSync };

/**
 * Read one secret from `dir`, where `names` is the caller's fixed name table: the directory checked, the file opened without following a symlink
 * and checked on its descriptor (so the checked file is the one read), then its value. `fs` and
 * `uid` are injectable for tests. Throws a SafeError with the reason only: the caller names the
 * item with its own fixed label (no secret's file name or value reaches a log; CodeQL
 * js/clear-text-logging on #432).
 */
export function readSecretFile(name, dir, { names, fs = defaultFs, uid = process.getuid() } = {}) {
  const fail = why => {
    throw new SafeError(why);
  };
  if (!names || !Object.values(names).includes(name)) fail("not a known secret name");
  if (!okDir(dir)) fail("the secrets directory is not an absolute plain path");
  let dst = null;
  try {
    dst = fs.lstatSync(dir);
  } catch {
    dst = null;
  }
  const dp = secretsDirProblems(dst, uid);
  if (dp.length) fail(dp.join("; "));
  let fd;
  try {
    fd = fs.openSync(join(dir, name), constants.O_RDONLY | constants.O_NOFOLLOW);
  } catch (e) {
    fail(e?.code === "ELOOP" ? "is a symlink" : "not present or unreadable");
  }
  try {
    const st = fs.fstatSync(fd);
    const fp = secretFileProblems(st, uid);
    if (fp.length) fail(fp.join("; "));
    const buf = Buffer.alloc(st.size);
    let off = 0;
    while (off < st.size) {
      const n = fs.readSync(fd, buf, off, st.size - off, off);
      if (n <= 0) break;
      off += n;
    }
    const v = off === st.size ? secretValue(buf) : null;
    if (v === null) fail("not one plain line");
    return v;
  } finally {
    fs.closeSync(fd);
  }
}
