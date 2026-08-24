import { ArgumentsHost, Catch } from "@nestjs/common";
import { BaseExceptionFilter } from "@nestjs/core";
import { redactRpcUrl, scrubSecrets } from "../config/redact.js";

/**
 * Global exception filter that scrubs credentials out of anything Nest logs (CC-49 round-3
 * HIGH).
 *
 * Scrubbing every `logger.*(error.message)` call site is necessary but NOT sufficient: an
 * unhandled provider error propagating out of a controller is logged by Nest's own
 * `ExceptionsHandler`, which prints `exception.message` and `exception.stack` verbatim. For an
 * ethers error both carry `info.requestUrl` — i.e. the full RPC URL, i.e. the provider API
 * key. A real-process smoke test of the RepCredit endpoints reproduced exactly that: an
 * upstream 401 produced a clean `500 Internal server error` to the caller and six copies of
 * the live credential in the node log.
 *
 * This filter changes ONLY what is logged. Status codes and response bodies are unchanged —
 * `BaseExceptionFilter` still does the responding, so an `HttpException` keeps its own status
 * and payload and anything else stays a generic 500.
 */
@Catch()
export class ScrubbingExceptionFilter extends BaseExceptionFilter {
  catch(exception: unknown, host: ArgumentsHost): void {
    super.catch(scrubExceptionForLogging(exception), host);
  }
}

/**
 * Exported for direct testing. Replaces an error's text with a scrubbed copy, keeping the class name, the (scrubbed) stack
 * and the HTTP semantics Nest depends on. Non-`Error` values pass through unchanged: they are
 * never provider errors, and rewriting them would change the response body.
 */
export function scrubExceptionForLogging(exception: unknown): unknown {
  if (!(exception instanceof Error)) return exception;
  // ethers keeps the request URL on `info.requestUrl` as well as inside the message. Node's
  // inspector appends an Error's own enumerable properties when a logger passes the object
  // through, so this one has to be redacted in place too — scrubbing `message` alone left the
  // credential in the log.
  const info = (exception as { info?: { requestUrl?: unknown } }).info;
  if (info && typeof info === "object" && typeof info.requestUrl === "string") {
    info.requestUrl = redactRpcUrl(info.requestUrl);
  }
  const scrubbedMessage = scrubSecrets(exception.message);
  const scrubbedStack = exception.stack ? scrubSecrets(exception.stack) : exception.stack;
  if (scrubbedMessage === exception.message && scrubbedStack === exception.stack) {
    return exception;
  }
  // Mutate in place rather than re-wrapping: `BaseExceptionFilter` branches on
  // `instanceof HttpException` and reads `getStatus()`/`getResponse()`, so a copy would have
  // to reproduce that surface exactly.
  Object.defineProperty(exception, "message", {
    value: scrubbedMessage,
    configurable: true,
    writable: true,
  });
  if (scrubbedStack !== undefined) {
    Object.defineProperty(exception, "stack", {
      value: scrubbedStack,
      configurable: true,
      writable: true,
    });
  }
  return exception;
}
