// Values read from SP's BLSAggregator.sol source (--sp-aggregator-source) in --plan mode, where the
// contract does not exist yet and version() cannot be read. Extracted so CI can test it
// (deploy/check-reregister-guardians.mjs).

/// The source with every comment replaced by spaces (same length, so offsets hold), and a copy in
/// which string-literal contents are blanked too, for brace matching. Quotes inside comments and
/// comment markers inside strings are both handled. An unterminated block comment or string makes
/// `ok` false (Codex).
const lex = src => {
  const code = src.split("");
  const bare = src.split("");
  let ok = true;
  let i = 0;
  while (i < src.length) {
    const c = src[i];
    const d = src[i + 1];
    if (c === "/" && d === "/") {
      while (i < src.length && src[i] !== "\n") code[i] = bare[i++] = " ";
    } else if (c === "/" && d === "*") {
      const end = src.indexOf("*/", i + 2);
      if (end < 0) ok = false;
      const stop = end < 0 ? src.length : end + 2;
      for (; i < stop; i++) if (src[i] !== "\n") code[i] = bare[i] = " ";
    } else if (c === '"' || c === "'") {
      i++;
      while (i < src.length && src[i] !== c) {
        if (src[i] === "\\") bare[i++] = " ";
        if (i < src.length) bare[i++] = " ";
      }
      if (i >= src.length) ok = false;
      i++;
    } else i++;
  }
  return { ok, code: code.join(""), bare: bare.join("") };
};

/// The end (exclusive) of the brace block opening at `open` in `bare`, or -1.
const blockEnd = (bare, open) => {
  let depth = 0;
  for (let i = open; i < bare.length; i++) {
    if (bare[i] === "{") depth++;
    else if (bare[i] === "}" && --depth === 0) return i + 1;
  }
  return -1;
};

/// The release string BLSAggregator's version() returns, e.g. "BLSAggregator-4.14.2" (DSR
/// 2026-11-18, Codex). Comments are ignored. The file must define exactly one `contract
/// BLSAggregator`, it must have exactly one `function version(`, with no parameter and no modifier,
/// and that function's body must be exactly `return "<BLSAggregator-x.y.z[-tag]>";`. Anything else (a concatenation, a constant, a
/// second definition) returns null, and the caller stops.
export const aggregatorSourceVersion = source => {
  if (typeof source !== "string") return null;
  const { ok, code, bare } = lex(source);
  if (!ok) return null;
  // Whole Solidity identifiers: `$` is an identifier character there, which JavaScript's \b ignores.
  const contracts = [
    ...bare.matchAll(/(?<![A-Za-z0-9_$])contract\s+BLSAggregator(?![A-Za-z0-9_$])/g),
  ];
  if (contracts.length !== 1) return null;
  const open = bare.indexOf("{", contracts[0].index);
  const end = open < 0 ? -1 : blockEnd(bare, open);
  if (end < 0) return null;
  const body = bare.slice(open, end);
  const fns = [...body.matchAll(/(?<![A-Za-z0-9_$])function\s+version\s*\(/g)];
  if (fns.length !== 1) return null;
  // The body must be version()'s own: a `;` before the first `{` is a body-less declaration, and
  // the next `{` would be another member's (Codex).
  const after = open + fns[0].index;
  const fOpen = bare.indexOf("{", after);
  const semi = bare.indexOf(";", after);
  if (semi >= 0 && (fOpen < 0 || semi < fOpen)) return null;
  // The header must be exactly `version()` with only these keywords and `returns (string memory)`:
  // a parameter makes it another overload, and a modifier could change what it returns (Codex).
  const header = bare.slice(after + fns[0][0].length - 1, fOpen);
  if (
    !/^\(\s*\)\s*(?:(?:external|public|pure|view|override|virtual)\s+)*returns\s*\(\s*string\s+memory\s*\)\s*$/.test(
      header
    )
  )
    return null;
  const fEnd = fOpen < 0 ? -1 : blockEnd(bare, fOpen);
  if (fEnd < 0 || fEnd > end) return null;
  const m = code.slice(fOpen + 1, fEnd - 1).match(/^\s*return\s+(["'])([^"'\\]*)\1\s*;\s*$/);
  if (!m) return null;
  return /^BLSAggregator-\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?$/.test(m[2]) ? m[2] : null;
};
