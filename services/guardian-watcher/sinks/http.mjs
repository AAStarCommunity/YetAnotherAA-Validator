// HTTP for the sinks (Codex W2b R1 H1-H3): one deadline covering headers AND body, every body read
// bounded while streaming, and errors that are fixed text: operation + status only. A response
// body, an exception message or its cause can echo a URL with a token in it (Telegram puts the bot
// token in the path) or an Authorization value, so none of them is ever copied into an error.
import { MAX_RECORD_BYTES } from "../lib/cid.mjs";
import { SinkError } from "./errors.mjs";

export const MAX_API_BYTES = 64 * 1024; // provider JSON answers are a few hundred bytes

export class SinkHttpError extends SinkError {
  constructor(what, detail) {
    super(`${what}: ${detail}`);
    this.name = "SinkHttpError";
  }
}

/**
 * Perform one request and read at most `maxBytes` of its body, all within `ms`.
 * Returns { status, ok, bytes } where bytes is null if the body exceeded maxBytes.
 * Throws SinkHttpError("<what>: timeout" | "<what>: request failed") with no cause attached.
 */
export async function request(
  what,
  url,
  init = {},
  { ms = 30_000, maxBytes = MAX_API_BYTES } = {}
) {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), ms);
  let reader = null;
  try {
    let res;
    try {
      res = await fetch(url, { redirect: "error", ...init, signal: ctl.signal });
    } catch {
      throw new SinkHttpError(what, ctl.signal.aborted ? "timeout" : "request failed");
    }
    const chunks = [];
    let n = 0;
    if (res.body) {
      reader = res.body.getReader();
      try {
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          n += value.length;
          if (n > maxBytes) return { status: res.status, ok: res.ok, bytes: null };
          chunks.push(value);
        }
      } catch (e) {
        if (e instanceof SinkHttpError) throw e;
        throw new SinkHttpError(what, ctl.signal.aborted ? "timeout" : "body read failed");
      }
      reader = null; // fully consumed
    }
    const bytes = new Uint8Array(n);
    let o = 0;
    for (const c of chunks) {
      bytes.set(c, o);
      o += c.length;
    }
    return { status: res.status, ok: res.ok, bytes };
  } finally {
    clearTimeout(t);
    if (reader) reader.cancel().catch(() => {}); // early exit: release the connection
  }
}

/** Parse a bounded JSON answer; any failure is a fixed error. */
export function jsonOf(what, r) {
  if (!r.ok) throw new SinkHttpError(what, `HTTP ${r.status}`);
  if (r.bytes === null) throw new SinkHttpError(what, "response too large");
  try {
    return JSON.parse(new TextDecoder().decode(r.bytes));
  } catch {
    throw new SinkHttpError(what, "response is not JSON");
  }
}

/** GET a record from a public gateway: null if not served, not OK, or larger than one record. */
export async function fetchBounded(url, ms = 30_000) {
  const r = await request(
    "gateway fetch",
    url,
    { redirect: "follow" }, // gateways redirect to subdomain form; no credential is sent
    { ms, maxBytes: MAX_RECORD_BYTES + 1 }
  );
  if (!r.ok || r.bytes === null || r.bytes.length > MAX_RECORD_BYTES) return null;
  return r.bytes;
}
