// The watcher's one rule for error text (Codex W2b R1-R3): an error raised by something outside
// this code (RPC provider, HTTP upstream, git, the OS) can carry a credential: an RPC URL with a
// key, a remote with a token, an echoed Authorization header. Even its `code` is untrusted text.
// So nothing outside is ever copied into an error, alert, record, dead letter, status or log:
// - our own errors are SafeErrors (fixed text we wrote) and pass as is;
// - anything else becomes a category: an ALLOWLISTED code (below) or "error".
export class SafeError extends Error {
  constructor(message, code) {
    super(message);
    this.name = "SafeError";
    if (code) this.code = code;
  }
}

// ethers v6 ErrorCode values and the Node network/system codes we may meet. Only these names are
// ever reported; any other `code`, however it is spelled, reports as "error".
export const KNOWN_CODES = new Set([
  "UNKNOWN_ERROR",
  "NOT_IMPLEMENTED",
  "UNSUPPORTED_OPERATION",
  "NETWORK_ERROR",
  "SERVER_ERROR",
  "TIMEOUT",
  "BAD_DATA",
  "CANCELLED",
  "BUFFER_OVERRUN",
  "NUMERIC_FAULT",
  "INVALID_ARGUMENT",
  "MISSING_ARGUMENT",
  "UNEXPECTED_ARGUMENT",
  "VALUE_MISMATCH",
  "CALL_EXCEPTION",
  "INSUFFICIENT_FUNDS",
  "NONCE_EXPIRED",
  "REPLACEMENT_UNDERPRICED",
  "TRANSACTION_REPLACED",
  "UNCONFIGURED_NAME",
  "OFFCHAIN_FAULT",
  "ACTION_REJECTED",
  "ECONNREFUSED",
  "ECONNRESET",
  "ETIMEDOUT",
  "ENOTFOUND",
  "EAI_AGAIN",
  "EPIPE",
  "ENOENT",
  "EACCES",
  "ENOSPC",
  "EEXIST",
  "EADDRINUSE",
]);

export const safeCode = e =>
  typeof e?.code === "string" && KNOWN_CODES.has(e.code) ? e.code : "error";

/** Text for any caught error: our own message, or `<op>: <allowlisted code | "error">`. */
export function safeText(op, e) {
  if (e instanceof SafeError) return e.message;
  return `${op}: ${safeCode(e)}`;
}

/** Run `fn`; rethrow our own SafeErrors; replace anything else with a SafeError category. */
export async function guarded(op, fn) {
  try {
    return await fn();
  } catch (e) {
    if (e instanceof SafeError) throw e;
    const code = safeCode(e);
    throw new SafeError(`${op}: ${code}`, code === "error" ? undefined : code);
  }
}
