// Small fetch helpers shared by the sinks: timeouts, bounded bodies, no secret in errors.
import { MAX_RECORD_BYTES } from "../lib/cid.mjs";

export async function fetchWithTimeout(url, init = {}, ms = 30_000) {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), ms);
  try {
    return await fetch(url, { ...init, signal: ctl.signal });
  } finally {
    clearTimeout(t);
  }
}

/** GET `url` and return at most MAX_RECORD_BYTES + 1 bytes (more means "not our record"). */
export async function fetchBounded(url, ms = 30_000) {
  const res = await fetchWithTimeout(url, { redirect: "follow" }, ms);
  if (!res.ok) return null;
  const reader = res.body.getReader();
  const chunks = [];
  let n = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    n += value.length;
    if (n > MAX_RECORD_BYTES + 1) {
      await reader.cancel();
      return null;
    }
    chunks.push(value);
  }
  const out = new Uint8Array(n);
  let o = 0;
  for (const c of chunks) {
    out.set(c, o);
    o += c.length;
  }
  return out;
}

/** An error that names the endpoint and status, never a header or token. */
export async function httpError(what, res) {
  let body = "";
  try {
    body = (await res.text()).slice(0, 200);
  } catch {
    /* ignore */
  }
  return new Error(`${what}: HTTP ${res.status} ${body}`);
}
