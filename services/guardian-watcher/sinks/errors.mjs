// Error boundary for every sink (Codex W2b R1 H1, R2 H1-H3): what leaves a sink is a SinkError
// carrying fixed text: the operation, plus a category chosen by this code. Never an upstream
// message, stderr, response body, URL, cause or provider object, because any of them can carry
// a token (an RPC URL with a key, a git remote with credentials, an echoed Authorization).
// Our own refusals (role checks, path checks) are SinkErrors with text we wrote, and pass as is.
export class SinkError extends Error {
  constructor(message) {
    super(message);
    this.name = "SinkError";
  }
}

/** A machine code is passed through only if it looks like one (ethers' CALL_EXCEPTION etc.). */
export const safeCode = e =>
  typeof e?.code === "string" && /^[A-Z][A-Z0-9_]{1,40}$/.test(e.code) ? e.code : "error";

/** Run `fn`; rethrow our own SinkErrors, replace anything else with `<op>: <code>`. */
export async function guarded(op, fn) {
  try {
    return await fn();
  } catch (e) {
    if (e instanceof SinkError) throw e;
    throw new SinkError(`${op}: ${safeCode(e)}`);
  }
}
