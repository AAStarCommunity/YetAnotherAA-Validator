// One rule for error text, taken from the retired guardian watcher (Codex W2b R1-R3): an error raised by something outside
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

// classification never throws (#411 review F4): a `code` getter or a Proxy trap that throws, or
// anything else odd about the value, falls back to the fixed "error"
const isOurs = e => {
  try {
    return e instanceof SafeError;
  } catch {
    return false;
  }
};
export { isOurs };
export const safeCode = e => {
  try {
    const c = e?.code;
    return typeof c === "string" && KNOWN_CODES.has(c) ? c : "error";
  } catch {
    return "error";
  }
};

/** Text for any caught error: our own message, or `<op>: <allowlisted code | "error">`. */
export function safeText(op, e) {
  if (isOurs(e)) return e.message;
  return `${op}: ${safeCode(e)}`;
}

/** Run `fn`; rethrow our own SafeErrors; replace anything else with a SafeError category. */
export async function guarded(op, fn) {
  try {
    return await fn();
  } catch (e) {
    if (isOurs(e)) throw e;
    const code = safeCode(e);
    throw new SafeError(`${op}: ${code}`, code === "error" ? undefined : code);
  }
}
