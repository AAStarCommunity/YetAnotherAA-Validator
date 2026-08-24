/**
 * Secret-safe rendering of RPC endpoints and provider errors for logs (CC-49).
 *
 * Provider RPC URLs routinely carry the API key in the path (Alchemy/Infura
 * `/v2/<KEY>`), in the query string, or in userinfo (`https://user:pass@host`).
 * Printing the raw `ETH_RPC_URL` at boot therefore leaks a live credential into
 * stdout, journald, container logs, and any log shipper downstream (MEDIUM-3).
 *
 * The same credential comes back a second way (CC-49 round-3 HIGH): ethers wraps a
 * non-2xx or transport-level provider failure into an Error whose `message` embeds the
 * full request URL — e.g. `server response 401 Unauthorized (url="https://host/v2/KEY",
 * ...)`. Any `logger.*(error.message)` on an RPC path is therefore a credential leak on
 * exactly the failure modes (401/429/transport) an operator is most likely to hit and
 * most likely to paste into a ticket. `scrubProviderError` is the single funnel every
 * such log line must go through.
 *
 * Two layers, because a key can appear with or without its scheme:
 *   1. any `scheme://…` run collapses to `protocol//hostname[:port]` — enough to tell
 *      WHICH endpoint failed, which is the operational reason the line exists;
 *   2. any fragment registered from the configured RPC URL (userinfo, path, query
 *      values) is replaced literally, catching a key echoed back on its own.
 */
import { URL } from "url";

export const REDACTED_RPC_URL = "[REDACTED_RPC_URL]";
export const REDACTED_SECRET = "[REDACTED]";

/**
 * A `scheme://…` run. The terminator class deliberately includes quotes, brackets and
 * commas so a URL embedded in ethers' `(url="…", body=…)` formatting is matched without
 * swallowing the rest of the message.
 */
const URL_LIKE = /[a-zA-Z][a-zA-Z0-9+.-]*:\/\/[^\s"'`<>()[\]{}\\,;]+/g;

/**
 * Credential fragments harvested from configured URLs. Short fragments are never
 * registered — replacing a 3-character path segment would shred unrelated log text
 * without protecting anything.
 */
const MIN_FRAGMENT_LENGTH = 8;
const registeredSecrets = new Set<string>();

export function redactRpcUrl(raw?: string | null): string {
  if (!raw) return REDACTED_RPC_URL;
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    // Not a parseable URL — never echo the original, it may still be a secret.
    return REDACTED_RPC_URL;
  }
  if (!url.hostname) return REDACTED_RPC_URL;
  return `${url.protocol}//${url.hostname}${url.port ? `:${url.port}` : ""}`;
}

/**
 * Register the credential-bearing parts of a URL so they are scrubbed even when they
 * surface without their scheme. Call once per secret-bearing endpoint at boot.
 */
export function registerSensitiveUrl(raw?: string | null): void {
  if (!raw) return;
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    // Unparseable but non-empty: treat the whole value as opaque and sensitive.
    if (raw.length >= MIN_FRAGMENT_LENGTH) registeredSecrets.add(raw);
    return;
  }
  const candidates: string[] = [
    url.username,
    url.password,
    url.hash.replace(/^#/, ""),
    // The whole tail in one piece, so a message echoing "/v2/KEY?x=y" is caught even
    // when no individual component clears the length floor.
    `${url.pathname}${url.search}${url.hash}`,
    ...url.pathname.split("/"),
    ...Array.from(url.searchParams.values()),
  ];
  for (const candidate of candidates) {
    const value = candidate?.trim();
    if (value && value.length >= MIN_FRAGMENT_LENGTH && value !== "/") {
      registeredSecrets.add(value);
    }
  }
}

/** Test seam. Production never un-registers a secret. */
export function clearRegisteredSecrets(): void {
  registeredSecrets.clear();
}

/** Collapse every URL and every registered credential fragment in arbitrary text. */
export function scrubSecrets(text: string): string {
  if (!text) return text;
  let out = text.replace(URL_LIKE, match => redactRpcUrl(match));
  for (const secret of registeredSecrets) {
    if (out.includes(secret)) out = out.split(secret).join(REDACTED_SECRET);
  }
  return out;
}

/**
 * The ONLY safe way to render a provider/RPC error into a log line or an exception
 * message. Reads the error's own text — never its `info`/`request`/`stack`, which carry
 * the request URL verbatim — and scrubs what is left.
 */
export function scrubProviderError(error: unknown): string {
  if (error === null || error === undefined) return "unknown error";
  const anyError = error as { shortMessage?: unknown; message?: unknown };
  const raw =
    typeof anyError.shortMessage === "string" && anyError.shortMessage
      ? anyError.shortMessage
      : typeof anyError.message === "string" && anyError.message
        ? anyError.message
        : String(error);
  return scrubSecrets(raw);
}
