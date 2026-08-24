/**
 * Secret-safe rendering of RPC endpoints for logs (CC-49 MEDIUM-3).
 *
 * Provider RPC URLs routinely carry the API key in the path (Alchemy/Infura
 * `/v2/<KEY>`), in the query string, or in userinfo (`https://user:pass@host`).
 * Printing the raw `ETH_RPC_URL` at boot therefore leaks a live credential into
 * stdout, journald, container logs, and any log shipper downstream.
 *
 * Only `protocol//hostname[:port]` survives — enough to tell WHICH network the
 * node is pointed at, which is the operational reason the line exists at all.
 * Anything unparseable collapses to a fixed sentinel rather than being echoed.
 */
import { URL } from "url";

export const REDACTED_RPC_URL = "[REDACTED_RPC_URL]";

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
