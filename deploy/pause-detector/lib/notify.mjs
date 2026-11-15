// The detector's notification half, shared with the dead-man check (clestons #435 B1, #436): the
// secret names, durable JSON writes, message batching and the Telegram send. Node builtins and
// safe-error only, so the dead-man's module graph does not include run.mjs, ethers or the round.
import { closeSync, constants, fsyncSync, openSync, renameSync, writeSync } from "node:fs";
import { dirname } from "node:path";
import { SafeError, safeText } from "../../pause-job/lib/safe-error.mjs";

/** The detector's secret files: two RPC URLs and the aastar-monitor bot token. Nothing else. */
export const DETECTOR_SECRETS = Object.freeze({
  rpcPrimary: "aoa-dvt-detector-rpc-primary",
  rpcFallback: "aoa-dvt-detector-rpc-fallback",
  telegram: "aoa-dvt-alert-bot-token",
});

/**
 * fsync, except where Node's permission model disables it (ERR_ACCESS_DENIED, Node 24): there the
 * write is still atomic (temp file + rename); a crash can lose the last write, which costs a
 * rescan and a repeated alert, never a missed one.
 */
const syncFd = fd => {
  try {
    fsyncSync(fd);
  } catch (e) {
    if (e?.code !== "ERR_ACCESS_DENIED") throw e;
  }
};

/** Write `obj` to `path`: 0600 temp file, fsync (see syncFd), rename, fsync the directory. */
export function writeDurable(path, obj) {
  const tmp = `${path}.${process.pid}.tmp`;
  const fd = openSync(
    tmp,
    constants.O_WRONLY | constants.O_CREAT | constants.O_TRUNC | constants.O_NOFOLLOW,
    0o600
  );
  try {
    const buf = Buffer.from(`${JSON.stringify(obj, null, 2)}\n`);
    let off = 0;
    while (off < buf.length) {
      const n = writeSync(fd, buf, off, buf.length - off);
      if (!(n > 0)) throw new SafeError("state write made no progress");
      off += n;
    }
    syncFd(fd);
  } finally {
    closeSync(fd);
  }
  renameSync(tmp, path);
  const d = openSync(dirname(path), constants.O_RDONLY);
  try {
    syncFd(d);
  } finally {
    closeSync(d);
  }
}

/** Telegram's message limit, with room for the header line. */
export const MESSAGE_CHARS = 3800;

/**
 * Split alert lines into messages of at most MESSAGE_CHARS, each line whole. A line longer than
 * the limit (not produced by this detector) is cut, and says so. Returns [{ text, items }], where
 * items are the caller's entries carried in that message. Pure.
 */
export function batches(header, entries) {
  const out = [];
  let cur = null;
  for (const e of entries) {
    let line = e.line;
    if (header.length + 1 + line.length > MESSAGE_CHARS)
      line = `${line.slice(0, MESSAGE_CHARS - header.length - 20)} …(cut)`;
    if (!cur || cur.text.length + 1 + line.length > MESSAGE_CHARS) {
      cur = { text: header, items: [] };
      out.push(cur);
    }
    cur.text += `\n${line}`;
    cur.items.push(e);
  }
  return out;
}

/**
 * Send one message. Delivered only when Telegram answers HTTP 2xx with a JSON body `ok: true`.
 * `post` is injectable (tests).
 */
export async function telegram(cfg, token, text, post = null) {
  if (!cfg.telegram) {
    console.error(`ALERT ${text}`);
    return { ok: false, why: "no Telegram configured" };
  }
  try {
    const r = post
      ? await post(text)
      : await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ chat_id: cfg.telegram.chatId, text }),
          signal: AbortSignal.timeout(15_000),
        });
    if (!r.ok) return { ok: false, why: `telegram HTTP ${r.status}` };
    let j;
    try {
      j = await r.json();
    } catch {
      return { ok: false, why: "telegram: not JSON" };
    }
    return j?.ok === true ? { ok: true } : { ok: false, why: "telegram: ok is not true" };
  } catch (e) {
    return { ok: false, why: safeText("telegram", e) };
  }
}
