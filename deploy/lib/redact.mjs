// What deploy/reregister-guardians.mjs may print of a node-file value (clestons #444 Low 2, #460 Lows
// 1-2). A BLS secret pasted into the wrong field of a node file must not reach the terminal, so a
// field is printed only in one of these shapes. Extracted so CI can pin them
// (deploy/check-reregister-guardians.mjs).

/// The first and last 8 bytes of a 128-byte key: enough to tell two public keys apart, not the whole
/// value (DSR 2026-11-18).
export const keyEnds = hex => `${hex.slice(0, 18)}…${hex.slice(-16)}`;

/// Any node-file field: a small integer as is, anything else only by its type and length. No part
/// of the value is shown (clestons #460 Low 1: first/last characters of a pasted secret are still
/// part of it).
export const fieldShape = v => {
  if (typeof v === "number" && Number.isSafeInteger(v) && Math.abs(v) < 1000) return String(v);
  if (typeof v === "string" && /^\d{1,3}$/.test(v)) return JSON.stringify(v);
  if (typeof v !== "string") return `<${typeof v}, value withheld>`;
  return `<${v.length} chars, value withheld>`;
};

/// publicKeyEip2537: its ends only when it has the exact shape of one (0x + 256 hex digits, 128
/// bytes), so the operator can compare it with the derived key. A 32-byte secret never has it.
export const pubKeyShape = v =>
  typeof v === "string" && /^0x[0-9a-fA-F]{256}$/.test(v) ? keyEnds(v) : fieldShape(v);

/// nodeName goes into every label: shown only when it looks like a name (up to 40 letters, digits,
/// '.', '_' or '-'), otherwise only its shape.
export const nodeNameShape = v =>
  v === undefined
    ? "?"
    : typeof v === "string" && /^[A-Za-z0-9._-]{1,40}$/.test(v)
      ? v
      : fieldShape(v);
