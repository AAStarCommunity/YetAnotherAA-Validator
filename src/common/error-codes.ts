import { HttpException } from "@nestjs/common";
import { scrubSecrets } from "../config/redact.js";

/**
 * Stable, versioned machine-readable error codes (CC-49 round-4).
 *
 * WHY. repo:sdk was matching on free text to decide whether a co-sign refusal was "the node
 * is not armed", "your proposal is malformed" or "the RPC is down" — three outcomes with
 * completely different retry semantics. Free text is not an interface: every wording fix
 * (including the scrubbing work in this very issue) silently reclassified an SDK branch.
 *
 * The contract is:
 *   - `errorCode` is a STABLE identifier. Codes are added, never renamed or re-purposed.
 *   - `errorCodeVersion` is bumped only if the ENVELOPE shape changes; adding a code does not
 *     bump it. A client that does not recognise a code must fall back to `category`.
 *   - `category` is the coarse, exhaustive classification a client can always switch on:
 *       auth           — the caller is not admitted (credentials/replay/rate/source).
 *       prerequisite   — the node refuses by policy or configuration; retrying is pointless
 *                        until an operator changes something.
 *       validation     — the request itself is wrong; fix the request.
 *       infrastructure — a dependency (RPC/chain) failed; the same request may succeed later.
 *   - HTTP status stays the primary signal and never contradicts the category.
 *   - `message` is HUMAN-ONLY and always scrubbed. Clients must not branch on it.
 */
export const ERROR_CODE_SCHEMA_VERSION = 1;

export type ErrorCategory = "auth" | "prerequisite" | "validation" | "infrastructure";

export interface StructuredErrorBody {
  statusCode: number;
  errorCodeVersion: number;
  errorCode: string;
  category: ErrorCategory;
  message: string;
}

/**
 * Build the exception carrying the versioned envelope.
 *
 * The message is scrubbed HERE, at the single funnel, rather than at each call site: an
 * ethers error text can reach an error body through any number of intermediate `${}`
 * interpolations, and a scrub that has to be remembered is a scrub that is eventually
 * forgotten (that is exactly how `/node/register` echoed a live provider credential).
 */
export function structuredError(
  status: number,
  errorCode: string,
  category: ErrorCategory,
  message: string
): HttpException {
  const body: StructuredErrorBody = {
    statusCode: status,
    errorCodeVersion: ERROR_CODE_SCHEMA_VERSION,
    errorCode,
    category,
    message: scrubSecrets(message),
  };
  return new HttpException(body, status);
}
