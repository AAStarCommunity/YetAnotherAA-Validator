import { HttpStatus } from "@nestjs/common";
import { ErrorCategory, structuredError } from "../../common/error-codes.js";

/**
 * Stable machine-readable codes for the node lifecycle endpoints (CC-49 round-4 HIGH-1).
 * See `common/error-codes.ts` for the versioning contract.
 *
 * `NODE_REGISTER_UPSTREAM_FAILED` is 502, not 500: the node itself is healthy and the request
 * was well-formed — an upstream (RPC / chain) refused. It is also the code under which the
 * provider's own text is deliberately DROPPED rather than forwarded, because that text carries
 * the RPC credential.
 */
export const NODE_ERRORS: Record<string, { status: number; category: ErrorCategory }> = {
  NODE_REGISTER_STATE_MISSING: {
    status: HttpStatus.SERVICE_UNAVAILABLE,
    category: "prerequisite",
  },
  NODE_REGISTER_BLOCKCHAIN_UNCONFIGURED: {
    status: HttpStatus.SERVICE_UNAVAILABLE,
    category: "prerequisite",
  },
  NODE_REGISTER_UPSTREAM_FAILED: {
    status: HttpStatus.BAD_GATEWAY,
    category: "infrastructure",
  },
};

export type NodeErrorCode = keyof typeof NODE_ERRORS;

export function nodeError(code: NodeErrorCode, message: string) {
  const spec = NODE_ERRORS[code];
  return structuredError(spec.status, code, spec.category, message);
}
