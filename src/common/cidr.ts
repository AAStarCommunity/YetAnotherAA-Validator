/**
 * Minimal, fail-closed CIDR membership for the node-admin trusted-proxy allow-list
 * (CC-49 round-5 MEDIUM-1).
 *
 * WHY IT IS HERE AND NOT A DEPENDENCY. The only thing this is allowed to decide is
 * "is the socket peer one of the reverse proxies the operator named" — a decision that
 * gates whether an `X-Forwarded-For` header may be read AT ALL, and only ever for
 * rate-limit bucketing. Everything unparseable is a NON-match, and callers turn a
 * non-match into a rejection, so a malformed entry can never widen access.
 *
 * Supported: IPv4 (`a.b.c.d`, `a.b.c.d/n`), IPv6 (`::1`, `2001:db8::/32`) and
 * IPv4-mapped IPv6 (`::ffff:127.0.0.1`), which is what Node hands back on a
 * dual-stack listener. A zone id (`%eth0`) is stripped before parsing.
 */

export interface CidrRange {
  /** Network address bytes, already masked. 4 bytes for IPv4, 16 for IPv6. */
  readonly bytes: Uint8Array;
  readonly prefixBits: number;
}

/** Parse an IP literal into its bytes, or null. IPv4-mapped IPv6 collapses to 4 bytes. */
export function parseIp(value: string): Uint8Array | null {
  const raw = value.trim().replace(/%.*$/, "");
  if (!raw) return null;
  if (!raw.includes(":")) return parseIpv4(raw);

  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(raw);
  if (mapped) return parseIpv4(mapped[1]);
  return parseIpv6(raw);
}

function parseIpv4(value: string): Uint8Array | null {
  const parts = value.split(".");
  if (parts.length !== 4) return null;
  const bytes = new Uint8Array(4);
  for (let i = 0; i < 4; i++) {
    // Reject "01", "+1", "0x7f" and anything non-numeric: one address, one spelling.
    if (!/^(0|[1-9][0-9]{0,2})$/.test(parts[i])) return null;
    const octet = Number(parts[i]);
    if (octet > 255) return null;
    bytes[i] = octet;
  }
  return bytes;
}

function parseIpv6(value: string): Uint8Array | null {
  const halves = value.split("::");
  if (halves.length > 2) return null;

  const expand = (part: string): string[] | null => {
    if (part === "") return [];
    const groups = part.split(":");
    return groups.some(g => !/^[0-9a-fA-F]{1,4}$/.test(g)) ? null : groups;
  };

  const head = expand(halves[0]);
  const tail = halves.length === 2 ? expand(halves[1]) : [];
  if (!head || !tail) return null;

  const missing = 8 - head.length - tail.length;
  if (halves.length === 2 ? missing < 1 : missing !== 0) return null;

  const groups = [...head, ...Array<string>(halves.length === 2 ? missing : 0).fill("0"), ...tail];
  const bytes = new Uint8Array(16);
  for (let i = 0; i < 8; i++) {
    const word = parseInt(groups[i], 16);
    bytes[i * 2] = word >> 8;
    bytes[i * 2 + 1] = word & 0xff;
  }
  return bytes;
}

/**
 * Parse `a.b.c.d/n` / `2001:db8::/32` / a bare literal (implicit full-length prefix).
 * Returns null for anything it cannot parse EXACTLY — the caller must treat that as a
 * configuration error and refuse to boot, never as "allow".
 */
export function parseCidr(value: string): CidrRange | null {
  const [address, prefix, ...rest] = value.trim().split("/");
  if (rest.length > 0) return null;

  const bytes = parseIp(address);
  if (!bytes) return null;

  const fullBits = bytes.length * 8;
  let prefixBits = fullBits;
  if (prefix !== undefined) {
    if (!/^(0|[1-9][0-9]?|1[0-9]{2})$/.test(prefix)) return null;
    prefixBits = Number(prefix);
    if (prefixBits > fullBits) return null;
  }
  return { bytes: maskTo(bytes, prefixBits), prefixBits };
}

/** True when `ip` falls inside `range`. Unparseable or cross-family inputs are NOT members. */
export function ipInCidr(ip: string, range: CidrRange): boolean {
  const bytes = parseIp(ip);
  if (!bytes || bytes.length !== range.bytes.length) return false;
  const masked = maskTo(bytes, range.prefixBits);
  for (let i = 0; i < masked.length; i++) {
    if (masked[i] !== range.bytes[i]) return false;
  }
  return true;
}

/** True when `ip` is inside ANY of the ranges. An empty list matches nothing. */
export function ipInAnyCidr(ip: string, ranges: readonly CidrRange[]): boolean {
  return ranges.some(range => ipInCidr(ip, range));
}

function maskTo(bytes: Uint8Array, prefixBits: number): Uint8Array {
  const out = new Uint8Array(bytes);
  for (let i = 0; i < out.length; i++) {
    const bitsBefore = i * 8;
    if (prefixBits >= bitsBefore + 8) continue;
    out[i] = prefixBits <= bitsBefore ? 0 : out[i] & (0xff << (bitsBefore + 8 - prefixBits));
  }
  return out;
}
