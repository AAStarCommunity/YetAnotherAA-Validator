import { HttpStatus } from "@nestjs/common";
import { ErrorCategory, structuredError } from "../../common/error-codes.js";

/**
 * The stable RepCredit error-code table handed to repo:sdk (CC-49 round-4).
 *
 * The SDK orchestrates a three-node quorum and has to decide, per node, whether to retry the
 * same call, retry with a fixed request, or drop the node from the round. Before this table
 * the only signal was English prose, so the SDK matched on substrings — and every wording
 * change (there were several in this issue alone) silently reclassified a branch.
 *
 * Read `category` first; it is exhaustive and never changes meaning:
 *   auth           — not admitted. A fresh token may help (`AUTH_TIMESTAMP_OUTSIDE_WINDOW`,
 *                    `AUTH_TOKEN_REPLAYED`); the same token never will.
 *   prerequisite   — the node refuses by policy/configuration. Do NOT retry; this node is out
 *                    of the round until an operator changes something.
 *   validation     — the request is wrong. Fix it; retrying it verbatim on another node fails
 *                    the same way.
 *   infrastructure — a dependency failed. The same request may succeed on a retry/another node.
 *
 * Codes are append-only. `errorCodeVersion` (see common/error-codes.ts) covers the envelope,
 * not the membership of this table, so a new code does not bump it — an unknown code MUST fall
 * back to `category`. Never branch on `message`.
 *
 * The full table is mirrored in docs/REPCREDIT_EXPERIMENT.md; keep the two in step.
 */
export const REPCREDIT_ERRORS = {
  // ── guard: admission ────────────────────────────────────────────────────────────────
  /** REPCREDIT_EXPERIMENT_SIGNING is not true. */
  REPCREDIT_NOT_ARMED: { status: HttpStatus.FORBIDDEN, category: "auth" },
  /** Armed but REPCREDIT_EXPERIMENT_AUTH_SECRET is empty — never degrades to "no auth". */
  REPCREDIT_AUTH_SECRET_UNSET: { status: HttpStatus.SERVICE_UNAVAILABLE, category: "auth" },
  /** Body above REPCREDIT_MAX_BODY_BYTES, rejected before any HMAC/parse work. */
  REPCREDIT_BODY_TOO_LARGE: { status: HttpStatus.PAYLOAD_TOO_LARGE, category: "auth" },
  /** Non-loopback caller while REPCREDIT_ALLOW_REMOTE is off. */
  REPCREDIT_REMOTE_FORBIDDEN: { status: HttpStatus.FORBIDDEN, category: "auth" },
  /** X-RepCredit-Timestamp and/or X-RepCredit-Auth absent. */
  REPCREDIT_AUTH_HEADERS_MISSING: { status: HttpStatus.UNAUTHORIZED, category: "auth" },
  /** X-RepCredit-Scheme is not the supported version (currently "v2"). No v1 fallback. */
  REPCREDIT_AUTH_SCHEME_UNSUPPORTED: { status: HttpStatus.UNAUTHORIZED, category: "auth" },
  /** Timestamp too old (> TTL) or too far in the future (> max skew). Re-sign with a fresh ts. */
  REPCREDIT_AUTH_TIMESTAMP_OUTSIDE_WINDOW: { status: HttpStatus.UNAUTHORIZED, category: "auth" },
  /** X-RepCredit-Auth is not exactly 64 lowercase hex characters (the canonical encoding). */
  REPCREDIT_AUTH_TOKEN_MALFORMED: { status: HttpStatus.UNAUTHORIZED, category: "auth" },
  /** Server-side misconfiguration: raw request bytes unavailable, so nothing can be verified. */
  REPCREDIT_AUTH_RAW_BODY_UNAVAILABLE: { status: HttpStatus.UNAUTHORIZED, category: "auth" },
  /** The HMAC does not match the v2 preimage over METHOD, REQUEST-TARGET, timestamp, raw body. */
  REPCREDIT_AUTH_HMAC_MISMATCH: { status: HttpStatus.FORBIDDEN, category: "auth" },
  /** Single-use violated: this token (in ANY equivalent encoding) was already consumed. */
  REPCREDIT_AUTH_TOKEN_REPLAYED: { status: HttpStatus.FORBIDDEN, category: "auth" },
  /** Replay cache full. Fail-closed by design — evicting would re-open the replay window. */
  REPCREDIT_REPLAY_CACHE_FULL: { status: HttpStatus.SERVICE_UNAVAILABLE, category: "auth" },

  // ── service: prerequisites (operator/config state; do not retry) ────────────────────
  /** The service-level arm check failed (mirrors REPCREDIT_NOT_ARMED behind the guard). */
  REPCREDIT_EXPERIMENT_DISABLED: { status: HttpStatus.FORBIDDEN, category: "prerequisite" },
  /** Experiment/audit aggregator configuration violates the isolation policy. */
  REPCREDIT_AGGREGATOR_POLICY_VIOLATION: { status: HttpStatus.FORBIDDEN, category: "prerequisite" },
  /** REPCREDIT_VALIDATOR_SLOT is unset or outside [1, MAX_VALIDATORS]. */
  REPCREDIT_VALIDATOR_SLOT_INVALID: { status: HttpStatus.FORBIDDEN, category: "prerequisite" },
  /** The node's own BLS public key cannot be encoded. */
  REPCREDIT_LOCAL_KEY_MALFORMED: { status: HttpStatus.FORBIDDEN, category: "prerequisite" },
  /** The configured slot holds no active key on the experiment aggregator. */
  REPCREDIT_SLOT_NOT_ACTIVE: { status: HttpStatus.FORBIDDEN, category: "prerequisite" },
  /** The configured slot holds a DIFFERENT key than this node's. */
  REPCREDIT_SLOT_KEY_MISMATCH: { status: HttpStatus.FORBIDDEN, category: "prerequisite" },
  /** The signing key is also active on an aggregator that guards real stake (HIGH-A). */
  REPCREDIT_KEY_NOT_ISOLATED: { status: HttpStatus.FORBIDDEN, category: "prerequisite" },
  /** A deny-listed aggregator could not be verified, so isolation is indeterminate. */
  REPCREDIT_ISOLATION_INDETERMINATE: { status: HttpStatus.FORBIDDEN, category: "prerequisite" },
  /** The BLS signer returned incomplete material. */
  REPCREDIT_SIGNER_OUTPUT_INVALID: { status: HttpStatus.FORBIDDEN, category: "prerequisite" },

  // ── service: request validation (fix the request) ───────────────────────────────────
  /** The proposal failed structured validation / local hash recomputation. */
  REPCREDIT_PROPOSAL_INVALID: { status: HttpStatus.BAD_REQUEST, category: "validation" },
  /** slashLevel is not an integer in [0, 2]. */
  REPCREDIT_SLASH_LEVEL_INVALID: { status: HttpStatus.BAD_REQUEST, category: "validation" },
  /** The requested threshold is below what the aggregator enforces on-chain. */
  REPCREDIT_THRESHOLD_BELOW_ONCHAIN: { status: HttpStatus.BAD_REQUEST, category: "validation" },
  /** The submitted co-signature set failed validation/aggregation. */
  REPCREDIT_AGGREGATION_INVALID: { status: HttpStatus.BAD_REQUEST, category: "validation" },

  // ── infrastructure (retryable) ──────────────────────────────────────────────────────
  /** The configured RPC could not be read; the node refuses to sign or aggregate blind. */
  REPCREDIT_RPC_UNAVAILABLE: { status: HttpStatus.SERVICE_UNAVAILABLE, category: "infrastructure" },
} as const satisfies Record<string, { status: number; category: ErrorCategory }>;

export type RepCreditErrorCode = keyof typeof REPCREDIT_ERRORS;

/** Build the HttpException for a RepCredit error code. The message is scrubbed downstream. */
export function repCreditError(code: RepCreditErrorCode, message: string) {
  const spec = REPCREDIT_ERRORS[code];
  return structuredError(spec.status, code, spec.category, message);
}
