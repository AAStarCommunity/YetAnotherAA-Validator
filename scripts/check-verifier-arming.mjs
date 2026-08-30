#!/usr/bin/env node
/**
 * CC-115 B3 / PR-D1 static gate: keep the fraud-proof verifier arming instructions honest.
 *
 * SuperPaymaster removed the direct `setFraudProofVerifier(address)` setter — and introduced the
 * four-parameter, domain-bound fraud-proof ABI — in the same change (the release reporting
 * `version() == "BLSAggregator-4.10.0"`). The only arming path is now `proposeFraudProofVerifier(v)`
 * -> wait the full on-chain `VERIFIER_ROTATION_DELAY` (4 days) -> permissionless
 * `applyFraudProofVerifier()`. Deploy scripts and runbooks that still instruct an operator to call the
 * removed setter are not merely stale: they describe an *undelayed* arming of an unbounded,
 * 100%-of-lock slash authority, which is exactly what the two-step rotation exists to prevent. That
 * drift is invisible to `forge build` (we never compile against SP), so it is asserted here.
 *
 * Fail-closed: any violation exits non-zero.
 *
 * STATED LIMITS (so the next reader does not mistake absence of a check for a guarantee):
 *  - Threat model is ACCIDENTAL drift and stale copy-paste. An author deliberately hiding an
 *    instruction from their own repo's lint is out of scope, and several checks below say where.
 *  - There is NO Markdown parser here any more, and that is the design. Six review rounds each found
 *    a defect in the hand-rolled one — several of them SILENT PASSES, where a mis-parsed fence or
 *    code span hid a live instruction. A lint has no business reimplementing CommonMark, so the
 *    document declares its own boundaries with four whole-line HTML-comment markers instead. Marker
 *    matching needs no grammar and cannot be mis-parsed; any deviation is a hard error naming the
 *    marker.
 *  - Content inside the marked section is checked whether or not it sits in a fenced example, since
 *    there is no fence handling. A balanced fence AFTER the pinned block is allowed, but its contents
 *    are still scanned — so a fenced snippet naming an arming call is still rejected (fixtured). A
 *    fence before or through the pinned block is rejected outright: it could render the procedure
 *    inert. Put illustrative examples outside the markers.
 *  - Known residues, each fixtured: a shortcut naming no arming object; one written with an article
 *    ("after a day") or hidden behind an abbreviation ("e.g. after two days"); one whose object sits
 *    on a lead-in line rather than in the same segment; and a `<template>`-style hidden container
 *    (deliberate concealment, out of scope per the threat model). Four attempts to close the first
 *    three each introduced a false positive on correct prose — see the note above `checkRunbook`.
 *  - Prose semantics are only partly decidable. Two heuristics were removed after review demonstrated
 *    both failure directions on each; what survives is a CONJUNCTIVE rule (a duration below the
 *    window AND an arming object in the same segment), which review supplied after I had wrongly
 *    concluded no bounded rule existed. Its residue — a shortcut naming no arming object — is a
 *    fixtured, documented limit.
 *  - `.mjs` is outside this repo's Prettier glob, so this file's formatting is not CI-enforced.
 *  - This checker does NOT verify that ci.yml keeps its `timeout-minutes` bounds. They are what makes
 *    a hanging regression fail in minutes rather than after GitHub's 360-minute default, but a job
 *    added without one passes here. Enforcing it would mean this gate policing unrelated CI config;
 *    it belongs in a separate check, and until one exists the bound is a convention, not a guarantee.
 *  - A bare function name passed in a JS/TS TEMPLATE literal is NOT detected:
 *    `encodeFunctionData(\`setFraudProofVerifier\`, [v])` passes, while the same line with double
 *    quotes is caught. Backticks are excluded on purpose — this repo's own prose and NatSpec quote
 *    the removed setter's name with backticks, and matching them produced false positives on the
 *    deploy script's own documentation. The trade buys legal prose at the cost of template literals,
 *    which are a legitimate way to pass the name. Closing it properly means stripping comments from
 *    JS/TS first (as `splitSolidity` does for Solidity) and then allowing all three quote styles;
 *    that is not done here because it has not been verified false-positive-free on this repository.
 *
 * Run: npm run check:arming      (also runs the detector's own adversarial self-tests)
 *      node scripts/check-verifier-arming.mjs --self-test-only
 */
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
// Directories scanned recursively. `deploy/` was the gap pr-daemon found: it holds 21 files matching
// SCAN_EXTS — dvt-testnet.sh, COMMUNITY_OPERATORS.md, TESTNET-TO-MAINNET.md and friends — i.e. exactly
// the material an operator follows, and a real `cast send "$AGG" "setFraudProofVerifier(address)"`
// placed there passed silently. `conformance/` and `signer/` are included for the same reason.
const SCAN_DIRS = [
  "contracts/script",
  "contracts/src",
  "docs",
  "scripts",
  "deploy",
  "conformance",
  "signer",
  "src", // the signer service: a bare-name encodeFunctionData("setFraudProofVerifier", …) lives here
];
const SCAN_EXTS = [".sol", ".md", ".mjs", ".js", ".ts", ".sh", ".json"];
const SELF = "scripts/check-verifier-arming.mjs";

const DEPLOY_SCRIPT = "contracts/script/DeployOverIssueVerifier.s.sol";
const RUNBOOK = "docs/design/cc89-e2e-runbook.md";

/// @dev The authoritative arming procedure, pinned. Compared to the runbook after whitespace
///      normalisation (Prettier rewraps prose), so line breaks are free but every word is load-bearing.
///      Changing the procedure means changing this constant and the runbook in the same commit — that
///      friction is the point: it puts a quietly weakened wait, a reordering, or a stale duplicate in
///      front of a human reviewer instead of letting it pass as ordinary prose.
const ARMING_BLOCK = `
This block is asserted VERBATIM by \`scripts/check-verifier-arming.mjs\`, and the
operational arming calls must appear nowhere else in this section. Changing the
procedure therefore means changing the checker's pinned copy in the same commit
— deliberate friction on a security-critical sequence, and the reason a stale
duplicate or a quietly weakened wait cannot survive review.

1. The aggregator owner (a Safe M-of-N) calls
   \`proposeFraudProofVerifier(verifier)\`. Record the transaction hash and the
   emitted \`pendingFraudProofVerifierReadyAt\`.
2. Wait the FULL on-chain \`VERIFIER_ROTATION_DELAY\` — **4 days**.
   \`applyFraudProofVerifier()\` reverts \`VerifierRotationNotReady(readyAt)\`
   before then. Those four days of public visibility ARE the security property
   (CC-48 MEDIUM-1); they are not a formality and must not be shortened.
3. Anyone may then call the permissionless \`applyFraudProofVerifier()\` — the
   decision was already taken by the owner and has served its full delay, so
   keeping it owner-only would hand the owner a second veto. Record that receipt
   too.

There is no direct setter and no deployment-time bypass in this release.
Disarming is the only immediate direction (\`emergencyDisarmFraudProofVerifier\`,
owner-only).
`;

// ---------------------------------------------------------------------------------------------
//                                        DETECTOR
// ---------------------------------------------------------------------------------------------
//
// Comments ARE scanned, deliberately: the defect this gate exists to catch was a COMMENT — the deploy
// script's handoff text told the operator to call the removed setter. Stripping comments would have
// missed it. But that policy only holds if the declaration exemption below cannot be used to hide
// prose, so code and comments are separated first and the exemption is applied to CODE ONLY.
//
// The cost is that prose must name the setter WITHOUT a call form: write `setFraudProofVerifier`
// (a bare name), never `setFraudProofVerifier(...)`.

/// @dev Split a Solidity source into FOUR offset-preserving views: `code` (syntax outside strings and
///      comments), `strings` (string-literal payloads), `comments`, and `codeAndStrings`. Every view is
///      the same length as the input (unselected characters become spaces, newlines preserved), so a
///      match offset in any view maps back to the original text and to the correct line.
///
///      Strings are their OWN view rather than part of `code` for two reasons the reviewer found the
///      hard way: (1) the declaration exemption must never reach string prose, or
///      `console.log("Operator calls function setFraudProofVerifier(v) now")` slips through; (2) the
///      structural positive checks must not be satisfiable by a string literal that merely quotes the
///      require they are supposed to prove exists.
function splitSolidity(text) {
  const code = [];
  const strings = [];
  const comments = [];
  const both = [];
  const push = (ch, bucket) => {
    if (ch === "\n") {
      code.push("\n");
      strings.push("\n");
      comments.push("\n");
      both.push("\n");
      return;
    }
    code.push(bucket === "code" ? ch : " ");
    strings.push(bucket === "string" ? ch : " ");
    comments.push(bucket === "comment" ? ch : " ");
    both.push(bucket === "comment" ? " " : ch);
  };

  const literals = []; // {start, end, content} of each string literal, in source order
  let litStart = -1;
  let litBody = [];

  let state = "code"; // code | line | block | strD | strS
  let blockStart = -1;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    const next = text[i + 1];
    let bucket =
      state === "line" || state === "block" ? "comment" : state === "code" ? "code" : "string";

    if (state === "code") {
      if (c === "/" && next === "/") {
        state = "line";
        bucket = "comment";
      } else if (c === "/" && next === "*") {
        state = "block";
        blockStart = i;
        bucket = "comment";
      } else if (c === '"') {
        state = "strD";
        bucket = "string";
        litStart = i;
        litBody = [];
      } else if (c === "'") {
        state = "strS";
        bucket = "string";
        litStart = i;
        litBody = [];
      }
    } else if (state === "line") {
      if (c === "\n") state = "code";
    } else if (state === "block") {
      // `i - blockStart >= 3` stops the closer from reusing the opener's own `*`: in Solidity `/*/`
      // does NOT terminate a comment, so treating it as a close would spill genuine comment text into
      // the code view — silently re-admitting commented-out code to the structural checks below.
      if (text[i - 1] === "*" && c === "/" && i - blockStart >= 3) state = "code";
    } else if (state === "strD" || state === "strS") {
      if (c === "\\") {
        // The backslash AND the character it escapes belong to the string, so a `\"` cannot close it.
        push(c, "string");
        litBody.push(c);
        i++;
        if (i < text.length) {
          push(text[i], "string");
          litBody.push(text[i]);
        }
        continue;
      }
      if ((state === "strD" && c === '"') || (state === "strS" && c === "'")) {
        state = "code";
        literals.push({ start: litStart, end: i + 1, content: litBody.join("") });
      } else {
        litBody.push(c);
      }
    }

    push(c, bucket);
  }
  return {
    code: code.join(""),
    strings: strings.join(""),
    comments: comments.join(""),
    codeAndStrings: both.join(""),
    literals,
  };
}

/// @dev Solidity CONCATENATES adjacent string literals: `"setFraudProof" "Verifier(address)"` is one
///      string and compiles to the forbidden selector. Scanning literals individually misses that, so
///      group runs separated by nothing but whitespace or comments and scan each run's joined content.
///      A lone literal is simply a run of one, so this subsumes the single-literal scan.
/// @dev Whether `gap` contains ONLY whitespace, comments, and literal-kind prefixes — i.e. whether the
///      literals on either side are one concatenated Solidity string.
///
///      Written as a scan rather than a regex on purpose. The obvious pattern
///      `^(?:\s|unicode|hex|//[^\n]*\n|/\*[\s\S]*?\*/)*$` nests a lazy quantifier inside a
///      quantified alternation, which backtracks exponentially on input like `/*` followed by many
///      `*//*` repetitions — CodeQL flagged it as a high-severity ReDoS. This consumes each construct
///      once, in linear time, with no backtracking at all.
function isLiteralGap(gap) {
  let i = 0;
  while (i < gap.length) {
    const c = gap[i];
    if (c === " " || c === "\t" || c === "\n" || c === "\r" || c === "\f" || c === "\v") {
      i++;
    } else if (gap.startsWith("unicode", i)) {
      i += 7;
    } else if (gap.startsWith("hex", i)) {
      i += 3;
    } else if (gap.startsWith("//", i)) {
      const nl = gap.indexOf("\n", i);
      if (nl === -1) return false; // an unterminated line comment cannot be followed by a literal
      i = nl + 1;
    } else if (gap.startsWith("/*", i)) {
      const end = gap.indexOf("*/", i + 2);
      if (end === -1) return false;
      i = end + 2;
    } else {
      return false; // any other syntax (comma, operator, semicolon) separates the expressions
    }
  }
  return true;
}

export function stringRuns(text, literals) {
  const runs = [];
  let cur = null;
  for (const lit of literals) {
    // Only whitespace and comments may sit between two literals of the same expression.
    // `unicode"a" unicode"b"` and `hex"aa" hex"bb"` also concatenate, so the literal-kind prefix is
    // part of a legal gap — without it the run splits and each fragment scans clean.
    const gap = cur ? text.slice(cur.end, lit.start) : null;
    const adjacent = cur !== null && isLiteralGap(gap);
    if (adjacent) {
      cur.content += lit.content;
      cur.end = lit.end;
    } else {
      if (cur) runs.push(cur);
      cur = { start: lit.start, end: lit.end, content: lit.content };
    }
  }
  if (cur) runs.push(cur);
  return runs;
}

// A DECLARATION of the setter is legal in CODE — a mock that faithfully re-creates a pre-rotation
// aggregator has to declare it. Blanked in place (length-preserving) so offsets stay valid. Applied
// ONLY to the code view, so neither prose nor a string literal can borrow the exemption.
const DECLARATION_RE = /function\s+setFraudProofVerifier\s*\(/g;

// Call sites. `\s*` spans newlines, so `foo.setFraudProofVerifier\n  (v)` is caught. The lookbehind
// stops `unsetFraudProofVerifier(` from matching.
const CALL_RE = /(?<![A-Za-z0-9_$])setFraudProofVerifier\s*\(/g;

// Reflective invocation by signature string or member selector.
const ENCODED_RE =
  /setFraudProofVerifier\s*\(\s*address\s*\)|setFraudProofVerifier\s*\.\s*selector/g;

/// @dev viem/ethers take the function NAME as a bare string: `encodeFunctionData("setFraudProofVerifier", [v])`.
///      Matched only inside single/double-quoted literals and only in JS/TS sources — NatSpec and
///      Markdown quote the name with BACKTICKS, which is how this repo's own prose refers to the
///      removed setter, so restricting the quote characters keeps that prose legal.
const BARE_NAME_RE = /(['"])setFraudProofVerifier\1/g;
const JS_EXTS = [".mjs", ".js", ".ts"];

const NAME_PATTERNS = [
  [CALL_RE, "direct call"],
  [ENCODED_RE, "encoded signature / selector"],
];

// --- Raw selector literals -----------------------------------------------------------------------
// keccak256("setFraudProofVerifier(address)")[0:4] == 0xb93b1a6e == 3107658350. A call can name the
// selector instead of the function, and Solidity offers several spellings of the SAME constant, so
// numerals are matched generically and then NORMALISED before comparison — a regex pinned to the
// contiguous form misses `0xb93b_1a6e`, `hex"b93b1a6e"`, and the decimal.
const SELECTOR = 0xb93b1a6en; // == 3107658350
const SELECTOR_HEX = "b93b1a6e";

// Numerals are matched generically and then EVALUATED, not string-compared: solc accepts leading
// zeros (`0x0b93b1a6e`), underscore separators (`0xb93b_1a6e`), decimal (`3107658350`), and scientific
// notation (`310765835e1`) as spellings of the SAME constant. The exponent is part of the match so
// that an unrelated `3107658350e18` is evaluated (and rejected) rather than truncated into a hit.
const NUMERIC_RE =
  /(?<![A-Za-z0-9_$.])(?:0[xX][0-9a-fA-F_]+|[0-9][0-9_]*(?:\.[0-9_]+)?(?:[eE][+-]?[0-9_]+)?)/g;

const HEX_STRING_RE = /hex"[0-9a-fA-F_]*"|hex'[0-9a-fA-F_]*'/g;

/// @dev `hex"b93b1a6e..."` — a calldata blob whose first four bytes ARE the removed setter's selector.
function isSelectorHexString(raw) {
  const body = raw.slice(4, -1).replace(/_/g, "").toLowerCase();
  return body.startsWith(SELECTOR_HEX);
}

/// @dev Solidity denomination suffixes MULTIPLY the literal. Skipping such literals outright (the
///      earlier fix) both missed `3107658350 wei` — multiplier 1, still the selector — and
///      `3.10765835 gwei`, which scales exactly to it. So the factor is applied instead of ignored.
const DENOMINATIONS = {
  wei: 1n,
  gwei: 10n ** 9n,
  szabo: 10n ** 12n,
  finney: 10n ** 15n,
  ether: 10n ** 18n,
  seconds: 1n,
  minutes: 60n,
  hours: 3600n,
  days: 86400n,
  weeks: 604800n,
  years: 31536000n,
};
const DENOMINATION_RE = new RegExp("^\\s*(" + Object.keys(DENOMINATIONS).join("|") + ")\\b");

/// @dev A Solidity numeric literal as an exact rational `num / den`, or null if unparseable. Kept
///      rational rather than integral because a fractional literal only becomes an integer AFTER its
///      denomination is applied (`3.10765835 gwei`).
function numeralRational(raw) {
  const t = raw.replace(/_/g, "").toLowerCase();
  try {
    if (t.startsWith("0x")) return { num: BigInt(t), den: 1n };
    const e = t.indexOf("e");
    const mantissa = e === -1 ? t : t.slice(0, e);
    const exp = e === -1 ? 0 : Number(t.slice(e + 1));
    if (!Number.isInteger(exp) || Math.abs(exp) > 100) return null;
    const dot = mantissa.indexOf(".");
    const digits = dot === -1 ? mantissa : mantissa.slice(0, dot) + mantissa.slice(dot + 1);
    const fracLen = dot === -1 ? 0 : mantissa.length - dot - 1;
    const shift = exp - fracLen;
    return shift >= 0
      ? { num: BigInt(digits) * 10n ** BigInt(shift), den: 1n }
      : { num: BigInt(digits), den: 10n ** BigInt(-shift) };
  } catch {
    return null;
  }
}

/// @dev True when `raw`, scaled by its denomination, is exactly the removed setter's selector.
function isSelectorNumeral(raw, factor = 1n) {
  const r = numeralRational(raw);
  if (!r) return false;
  const num = r.num * factor;
  return num % r.den === 0n && num / r.den === SELECTOR;
}

function lineOf(text, index) {
  let line = 1;
  for (let i = 0; i < index; i++) if (text.charCodeAt(i) === 10) line++;
  return line;
}

/** Scan one view, reporting line numbers against `original` (all views are offset-preserving). */
function scanView(view, original, kindSuffix, hits) {
  for (const [re, kind] of NAME_PATTERNS) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(view)) !== null)
      hits.push({ line: lineOf(original, m.index), kind: kind + kindSuffix });
  }
  NUMERIC_RE.lastIndex = 0;
  let n;
  while ((n = NUMERIC_RE.exec(view)) !== null) {
    // A denomination scales the literal, so apply it rather than ignore the literal.
    //
    // BOTH lookups here are BOUNDED, and that is load-bearing rather than tidiness. They used to be
    // `view.slice(n.index + len)` and `view.slice(0, n.index)`, which copy the entire suffix and
    // prefix once PER NUMERAL — quadratic on its own — and the prefix was then matched against
    // `(?:\s*-)*\s*$`, a nested quantifier anchored at the end. The code view is mostly runs of
    // spaces (comments and string bodies are blanked), so that pattern backtracked catastrophically:
    // one 39KB Solidity file took 12.4 of the checker's 23 seconds.
    const LOOKAHEAD = 16; // longest denomination is "seconds" plus separating whitespace
    const after = view.substr(n.index + n[0].length, LOOKAHEAD);
    const suffix = DENOMINATION_RE.exec(after);
    const factor = suffix ? DENOMINATIONS[suffix[1]] : 1n;
    // An ODD number of leading minus signs makes the operand negative — never the selector. An even
    // number (`- -x`) leaves it positive. Scanned backwards over a bounded window, stopping at the
    // first character that is neither a sign nor whitespace.
    const LOOKBEHIND = 64;
    let minuses = 0;
    for (let k = n.index - 1; k >= 0 && k >= n.index - LOOKBEHIND; k--) {
      const ch = view[k];
      if (ch === "-") {
        minuses++;
      } else if (ch === " " || ch === "\t" || ch === "\n" || ch === "\r") {
        continue;
      } else {
        break;
      }
    }
    if (minuses % 2 === 1) continue;
    if (isSelectorNumeral(n[0], factor)) {
      hits.push({
        line: lineOf(original, n.index),
        kind: `raw selector literal \`${n[0]}\`` + kindSuffix,
      });
    }
  }
}

/// @dev `hex"b93b1a6e"` STRADDLES the code/string boundary — the `hex` keyword is code, the payload is
///      a string literal — so it matches in neither per-view scan. Run it once over the raw text.
function scanHexLiterals(text, hits) {
  HEX_STRING_RE.lastIndex = 0;
  let h;
  while ((h = HEX_STRING_RE.exec(text)) !== null) {
    if (isSelectorHexString(h[0])) {
      hits.push({ line: lineOf(text, h.index), kind: "selector as a hex byte literal" });
    }
  }
}

/**
 * @returns {{line:number, kind:string}[]} every place that INVOKES the removed setter.
 * @param isSolidity when true, `function setFraudProofVerifier(` declarations in CODE are exempt.
 */
export function findSetterCalls(text, isSolidity = false, isJs = false) {
  const hits = [];
  if (isSolidity) {
    const { code, comments, literals } = splitSolidity(text);
    scanView(blankDeclarations(code), text, "", hits);
    // No declaration exemption outside code: an operator-facing string and instructive prose are both
    // ways the original defect shipped. Literals are scanned as CONCATENATION RUNS, because solc joins
    // adjacent literals — `"setFraudProof" "Verifier(address)"` is one signature, not two fragments.
    for (const run of stringRuns(text, literals)) {
      const line = lineOf(text, run.start);
      const runHits = [];
      scanView(run.content, run.content, " in a string literal", runHits);
      for (const h of runHits) hits.push({ line, kind: h.kind });
      // A run of `hex"..."` literals concatenates into ONE byte string, so the selector can be split
      // across fragments that each look innocent — `scanHexLiterals` only sees them individually.
      if (text.slice(Math.max(0, run.start - 3), run.start) === "hex") {
        const joined = run.content.replace(/_/g, "").toLowerCase();
        if (joined.startsWith(SELECTOR_HEX)) {
          hits.push({ line, kind: "selector across concatenated hex literals" });
        }
      }
    }
    scanView(comments, text, " in a comment", hits);
  } else {
    scanView(text, text, "", hits);
  }
  scanHexLiterals(text, hits);
  if (isJs) {
    BARE_NAME_RE.lastIndex = 0;
    let b;
    while ((b = BARE_NAME_RE.exec(text)) !== null) {
      hits.push({ line: lineOf(text, b.index), kind: "bare function name in a JS/TS string" });
    }
  }
  return hits.sort((a, b) => a.line - b.line);
}

function blankDeclarations(text) {
  return text.replace(DECLARATION_RE, m => m.replace(/[^\n]/g, " "));
}

/// @dev The `[start, end)` offsets of the body of `function <name>(` in a Solidity CODE view (strings
///      and comments already blanked, so no brace inside either can throw off the count). Returns null
///      if the function is absent or unbalanced. Offsets are valid in EVERY view of the same source.
export function functionBodyRange(codeView, name) {
  const sig = new RegExp(`function\\s+${name}\\s*\\(`, "g");
  let m;
  while ((m = sig.exec(codeView)) !== null) {
    const open = codeView.indexOf("{", m.index);
    if (open === -1) return null;
    // An INTERFACE declaration (`function deploy() external;`) has no body. Without this check the
    // locator walks past its semicolon and swallows a later, unrelated block as "deploy's body".
    const semi = codeView.indexOf(";", m.index);
    if (semi !== -1 && semi < open) continue; // declaration only — keep looking for the definition
    let depth = 0;
    for (let i = open; i < codeView.length; i++) {
      if (codeView[i] === "{") depth++;
      else if (codeView[i] === "}") {
        depth--;
        if (depth === 0) return [open, i + 1];
      }
    }
    return null; // unbalanced
  }
  return null;
}

/// @dev Comment- AND string-free view: for structural checks that must prove LIVE ENFORCEMENT, so
///      neither a commented-out relic nor a string literal quoting the check can satisfy them.
export function solidityCodeOnly(text) {
  return splitSolidity(text).code;
}

export { splitSolidity };

// ---------------------------------------------------------------------------------------------
//                              RUNBOOK GATE (pure, so it is testable)
// ---------------------------------------------------------------------------------------------

// Explicit machine-readable markers, NOT Markdown structure.
//
// Earlier revisions located the section and the block by parsing Markdown — ATX headings, fenced code
// blocks, HTML comments, inline code spans. Review found a defect in that parser every round for six
// rounds, including several SILENT PASSES (an indented fence delimiter swallowing live prose, a
// column-0 opener with an indented closer, `<!--` inside a single- and then double-backtick code
// span). The lesson is not that the parser needed one more fix: a lint has no business reimplementing
// CommonMark, and every approximation of it is a place where a wrong answer is invisible.
//
// So the document declares its own boundaries. These markers are HTML comments, invisible when
// rendered, and matched as WHOLE LINES — which needs no grammar at all and cannot be mis-parsed.
const SECTION_BEGIN = "<!-- arming-section:begin -->";
const SECTION_END = "<!-- arming-section:end -->";
const BLOCK_BEGIN = "<!-- arming-block:begin -->";
const BLOCK_END = "<!-- arming-block:end -->";
const SECTION = "the marked arming section";

/// @dev Offsets of the single line exactly equal to `marker`, or an error describing the count.
function findMarker(lines, marker) {
  const hits = [];
  let off = 0;
  for (const line of lines) {
    // Column 0, exactly. An indented marker still "matches" visually but renders the whole marked
    // region as a Markdown code block, so the gate would be validating an inert copy.
    if (line.replace(/\r$/, "") === marker) hits.push({ start: off, end: off + line.length });
    off += line.length + 1;
  }
  return hits;
}

const norm = t => t.replace(/\s+/g, " ").trim();

/// @dev THE ONE PROSE RULE, AND WHY NOTHING IS LAYERED ON TOP OF IT.
///
///      The rule: flag a duration BELOW the arming window only when the SAME segment also names an
///      arming-specific OBJECT. Conjunctive, no verb, no polarity. It has survived every review round
///      since it was adopted without a demonstrated false positive.
///
///      Four narrower heuristics were tried around it and ALL FOUR failed in BOTH directions within a
///      single review round of being added:
///        1. A polarity blacklist ("do not wait", "skip the delay") — missed "apply early", rejected
///           "operators should not skip the delay".
///        2. A duration rule keyed on a nearby waiting VERB — missed "After one day, execute the
///           pending rotation", rejected a descriptive duration sharing a clause with an unrelated wait.
///        3. An article shortcut ("after a day, execute ...") — missed "finalize" because the verb was
///           not on the list, and rejected "After a week, complete the pending rotation audit" because
///           a week is ABOVE the window.
///        4. A colon-header bridge from a lead-in line to the item beneath it — rejected "Verifier
///           rotation evidence:" followed by a descriptive 2-day bullet, and still missed the shortcut
///           when the item began with another sentence.
///      An abbreviation guard for sentence splitting died the same way: it mis-split on Markdown
///      emphasis and was case-sensitive.
///
///      Three of those were suggested by the reviewer and failed on first contact. That consistency is
///      the actual finding: this class of rule cannot be made correct by another revision, and each
///      attempt traded a documented miss for an undocumented false positive — the worse failure, since
///      a lint that rejects correct writing gets disabled. So the core rule stands alone, and its
///      residues are fixtured KNOWN LIMITs rather than the next heuristic.
const ARMING_OBJECT =
  /pending rotation|verifier rotation|verifier arming|arming procedure|pendingFraudProofVerifier|VERIFIER_ROTATION_DELAY|proposeFraudProofVerifier|applyFraudProofVerifier/i;
const NUMBER_WORDS = {
  one: 1,
  two: 2,
  three: 3,
  four: 4,
  five: 5,
  six: 6,
  seven: 7,
  eight: 8,
  nine: 9,
  ten: 10,
};
const UNIT_DAYS = {
  second: 1 / 86400,
  seconds: 1 / 86400,
  minute: 1 / 1440,
  minutes: 1 / 1440,
  hour: 1 / 24,
  hours: 1 / 24,
  day: 1,
  days: 1,
  week: 7,
  weeks: 7,
};
// `\\d+(?:\\.\\d+)?` covers decimals — "3.5 days" previously matched at "5 days" and evaluated as five,
// which read as longer than the window and passed. Articles ("a day", "an hour") carry a value of one
// and are how a shortcut is most naturally written with no numeral at all.
// Articles ("a day", "an hour") are NOT durations here — see the heuristic note above `checkRunbook`. Supporting them rejected
// "A day after the verifier rotation, verify that both receipts are archived" — ordinary
// post-rotation prose — and a lint that blocks legitimate writing is worse than one that misses an
// article-only shortcut. That miss is recorded as a KNOWN LIMIT fixture below.
const HALF_SUFFIX = "(?:\\s+and\\s+a\\s+half)?";
const DURATION_RE = new RegExp(
  "(?<![\\d])(\\d+(?:\\.\\d+)?|\\.\\d+|" +
    Object.keys(NUMBER_WORDS).join("|") +
    ")(" +
    HALF_SUFFIX +
    ")[- ]?(" +
    Object.keys(UNIT_DAYS).join("|") +
    ")\\b",
  "gi"
);
const ARMING_WINDOW_DAYS = 4;

/// @dev Segment boundaries: a sentence terminator, a blank line, or a new list item. A single newline
///      is NOT a boundary, because prose wraps mid-sentence.
// The lookbehind excludes common abbreviations: "e.g." split "The pending rotation can be applied
// early, e.g. after two days." into two segments, stranding the duration away from the arming object
// and letting the shortcut through.
// Plain sentence/paragraph/list-item boundaries. There is deliberately NO abbreviation handling: a
// guard for "e.g." mis-split "etc. **After two days**, ..." on the Markdown emphasis and was
// case-sensitive besides. Without it the only cost is a MISS (a shortcut written after "e.g." lands
// in a segment with no arming object) — and a miss is the safe direction for a lint.
const SEGMENT_BOUNDARY = /(?<=[.!?])\s|\n\s*\n|\n\s*(?:[-*+]|\d+\.)\s/;

function durationInDays(match) {
  const raw = match[1].toLowerCase();
  let n = /^(?:\d+(?:\.\d+)?|\.\d+)$/.test(raw) ? Number(raw) : NUMBER_WORDS[raw];
  // The HALF_SUFFIX group in DURATION_RE is what makes "three and a half days" match at all; this
  // adjustment keeps the VALUE honest even though, at a 4-day threshold, +0.5 cannot flip a verdict.
  if (n !== undefined && /and\s+a\s+half/i.test(match[2] || "")) n += 0.5;
  const unit = UNIT_DAYS[match[3].toLowerCase()];
  return n === undefined || unit === undefined ? null : n * unit;
}

/// @notice Validate the runbook's arming section. Pure: takes the text, returns error strings — so
///         every mutation below is a committed regression test instead of a claim in a review reply.
export function checkRunbook(runbook) {
  const errors = [];
  const lines = runbook.split("\n");

  // Each marker must appear exactly once, as its own line, in the right order. Any deviation is a
  // hard error naming the marker — the author is told exactly what to fix, and nothing is guessed.
  const found = {};
  for (const [name, marker] of [
    ["SECTION_BEGIN", SECTION_BEGIN],
    ["SECTION_END", SECTION_END],
    ["BLOCK_BEGIN", BLOCK_BEGIN],
    ["BLOCK_END", BLOCK_END],
  ]) {
    const hits = findMarker(lines, marker);
    if (hits.length !== 1) {
      errors.push(`expected exactly one \`${marker}\` line, found ${hits.length}.`);
    } else {
      found[name] = hits[0];
    }
  }
  if (errors.length) return errors;

  const secStart = found.SECTION_BEGIN.end;
  const secEnd = found.SECTION_END.start;
  const blkStart = found.BLOCK_BEGIN.end;
  const blkEnd = found.BLOCK_END.start;
  if (!(secStart < blkStart && blkStart < blkEnd && blkEnd < secEnd)) {
    errors.push(
      `the arming markers are out of order: the block must sit inside the section ` +
        `(${SECTION_BEGIN} < ${BLOCK_BEGIN} < ${BLOCK_END} < ${SECTION_END}).`
    );
    return errors;
  }

  // The markers prove WHERE the procedure is; these three checks prove the marked region is the LIVE
  // one and still spans the operational content. Without them the region can be made inert (fenced or
  // indented into a code block) or shrunk (moving the end marker up) while every marker check passes.
  // Whether ${SECTION_BEGIN} sits inside an open fence. Parity-counting delimiter lines was wrong: a
  // four-backtick opener followed by a three-backtick line counts two but leaves the fence OPEN,
  // because a shorter run cannot close a longer one. This is a ten-line state check whose only output
  // is that boolean — not a return to parsing Markdown.
  const FENCE_LINE = /^\s*(?:```|~~~)/;
  const FENCE_OPEN = /^\s*(`{3,}|~{3,})/;
  const FENCE_CLOSE = /^\s*(`{3,}|~{3,})\s*$/;
  let openFence = null;
  for (const line of runbook.slice(0, found.SECTION_BEGIN.start).split("\n")) {
    const bare = line.replace(/\r$/, "");
    if (openFence) {
      const c = FENCE_CLOSE.exec(bare);
      if (c && c[1][0] === openFence.char && c[1].length >= openFence.len) openFence = null;
      continue;
    }
    const o = FENCE_OPEN.exec(bare);
    if (o) openFence = { char: o[1][0], len: o[1].length };
  }
  if (openFence) {
    errors.push(
      `${SECTION_BEGIN} sits inside an unclosed code fence, so the whole marked region renders as an ` +
        `example rather than as instructions. Close the fence before the marker.`
    );
  }
  // No fence anywhere in the marked region. I briefly relaxed this to allow a balanced fence AFTER
  // the pinned block, on the theory that its contents were still scanned — but a fence opened before
  // ${SECTION_END} can swallow the end marker AND the next "##" heading and close beyond them,
  // moving the section boundary. The relaxation bought a nicety and cost a boundary bypass.
  const sectionLines = runbook.slice(found.SECTION_BEGIN.start, found.SECTION_END.end).split("\n");
  if (sectionLines.some(l => FENCE_LINE.test(l))) {
    errors.push(
      `the marked arming section contains a code fence. There is no fence handling in this checker by ` +
        `design (see STATED LIMITS); move fenced examples outside ${SECTION_BEGIN}/${SECTION_END}.`
    );
  }
  // The region must span a WHOLE document section, checked at both ends. A substring test for the
  // anchors was not enough: moving ${SECTION_END} to just after the "### Run steps" HEADING kept the
  // substring present while excluding every run step, and the gate passed.
  const firstNonBlankAfter = idx => {
    const rest = runbook.slice(idx).split("\n").slice(1);
    return rest.find(l => l.trim() !== "") ?? "";
  };
  const afterBegin = firstNonBlankAfter(found.SECTION_BEGIN.end);
  if (!afterBegin.startsWith("## Joint successor-Sepolia run")) {
    errors.push(
      `${SECTION_BEGIN} must sit immediately before the "## Joint successor-Sepolia run" heading; ` +
        `found ${JSON.stringify(afterBegin.slice(0, 60))}.`
    );
  }
  // "" means end of file, which is a legitimate place for the last section to end.
  const afterEnd = firstNonBlankAfter(found.SECTION_END.end);
  if (afterEnd !== "" && !afterEnd.startsWith("## ")) {
    errors.push(
      `${SECTION_END} must sit at the end of that section, immediately before the next "## " heading; ` +
        `found ${JSON.stringify(afterEnd.slice(0, 60))}. Moving it up silently shrinks the checked region.`
    );
  }
  if (errors.length) return errors;

  const block = runbook.slice(blkStart, blkEnd);
  if (norm(block) !== norm(ARMING_BLOCK)) {
    errors.push(
      `the authoritative arming block no longer matches the pinned copy in ${SELF}. ` +
        `If the procedure genuinely changed, update BOTH in the same commit.`
    );
  }

  // Everything in the marked section that is NOT the pinned block.
  const outside = runbook.slice(secStart, blkStart) + runbook.slice(blkEnd, secEnd);

  // The operational calls must live ONLY in the block: a second procedure in this section would give
  // operators two conflicting security-critical instructions.
  for (const call of ["proposeFraudProofVerifier", "applyFraudProofVerifier"]) {
    if (outside.includes(call)) {
      errors.push(
        `\`${call}\` appears in ${SECTION} outside the authoritative arming block. ` +
          `Operational arming instructions must exist in exactly one place; reference the block instead.`
      );
    }
  }

  // A contradicting instruction need not name the calls — but a shortcut that means anything to an
  // operator has to name WHAT is being shortened. Conjunctive: below the window AND an arming object
  // in the same segment.
  // KNOWN LIMIT, measured not assumed: the object and the duration must be in the SAME segment. I
  // tried widening this to the immediately preceding segment so a lead-in line would count
  // ("Pending rotation:" / "- After two days, execute it."). It promptly rejected a descriptive
  // 2-day sentence written after any bullet that mentions the arming procedure — a false positive on
  // ordinary prose, which is the worse failure for a lint. Reverted and fixtured both ways.
  for (const segment of outside.split(SEGMENT_BOUNDARY)) {
    if (!segment || !ARMING_OBJECT.test(segment)) continue;
    DURATION_RE.lastIndex = 0;
    let m;
    while ((m = DURATION_RE.exec(segment)) !== null) {
      const d = durationInDays(m);
      if (d === null || d >= ARMING_WINDOW_DAYS) continue;
      errors.push(
        `"${SECTION}" states ${JSON.stringify(m[0])} alongside an arming instruction, outside the ` +
          `authoritative block. The arming window is ${ARMING_WINDOW_DAYS} days; a shorter one here ` +
          `contradicts the pinned procedure.`
      );
    }
  }
  return errors;
}

// ---------------------------------------------------------------------------------------------
//                                      SELF-TESTS
// ---------------------------------------------------------------------------------------------
// The detector's own failure mode is silent under-matching, so it is tested against the evasions a
// reviewer would actually try. Runs on every invocation; a broken detector fails the build.

function selfTest() {
  /** @type {[string, string, boolean][]} name, source, isSolidity */
  const must = [
    ["plain call", `aggregator.setFraudProofVerifier(verifier);`, true],
    ["multiline call", `aggregator.setFraudProofVerifier\n    (verifier);`, true],
    ["bare call", `setFraudProofVerifier(v);`, true],
    ["encoded signature", `abi.encodeWithSignature("setFraudProofVerifier(address)", v)`, true],
    [
      "cast invocation in markdown",
      `cast send $AGG "setFraudProofVerifier(address)" $VERIFIER`,
      false,
    ],
    ["selector reference", `bytes4 s = IAgg.setFraudProofVerifier.selector;`, true],
    ["raw selector literal", `abi.encodeWithSelector(0xb93b1a6e, verifier)`, true],
    ["raw selector, uppercase hex", `abi.encodeWithSelector(0xB93B1A6E, verifier)`, true],
    ["raw selector in a shell snippet", `cast send "$AGG" 0xb93b1a6e "$V"`, false],
    [
      "declaration plus call on one line",
      `function setFraudProofVerifier(address v) external { o.setFraudProofVerifier(v); }`,
      true,
    ],
    // THE regression this gate was written for: instructive prose in a comment.
    ["instruction in a line comment", `// Next: SP calls setFraudProofVerifier(verifier)`, true],
    [
      "instruction in a block comment",
      `/**\n * 3. SP calls setFraudProofVerifier(verifier).\n */`,
      true,
    ],
    // The declaration exemption must not be borrowable by prose.
    [
      "declaration-shaped prose in a comment",
      `// Operator must call function setFraudProofVerifier(verifier) now`,
      true,
    ],
    [
      "declaration-shaped prose in markdown",
      `Operator must call function setFraudProofVerifier(verifier) now`,
      false,
    ],
    // The declaration exemption must not be borrowable by a STRING either (round-3 Medium 1): this is
    // an operator-facing handoff, the exact shape of the original defect.
    [
      "declaration-shaped prose in a string literal",
      `console.log("Operator calls function setFraudProofVerifier(verifier) now");`,
      true,
    ],
    [
      "plain instruction in a string literal",
      `console.log("Next: SP calls setFraudProofVerifier(", v, ")");`,
      true,
    ],
    // Static spellings of the SAME selector (round-3 Medium 3).
    [
      "selector with underscore separators",
      `abi.encodeWithSelector(bytes4(uint32(0xb93b_1a6e)), verifier);`,
      true,
    ],
    [
      "selector as a hex byte literal",
      `bytes.concat(hex"b93b1a6e", bytes32(uint256(uint160(v))));`,
      true,
    ],
    [
      "selector as a hex byte literal with a payload",
      `bytes memory cd = hex"b93b1a6e0000000000000000";`,
      true,
    ],
    ["selector in decimal", `bytes4 s = bytes4(uint32(3107658350));`, true],
    ["selector in decimal with separators", `bytes4 s = bytes4(uint32(3_107_658_350));`, true],
    // Round-4 Medium 2: solc accepts several more spellings of the SAME constant.
    ["selector with a leading zero", `bytes4 s = bytes4(uint32(0x0b93b1a6e));`, true],
    ["selector in scientific notation", `bytes4 s = bytes4(uint32(310765835e1));`, true],
    // Round-4 Medium 3: solc concatenates ADJACENT string literals.
    [
      "signature split across adjacent literals",
      `abi.encodeWithSignature("setFraudProof" "Verifier(address)", v)`,
      true,
    ],
    [
      "signature split across three adjacent literals",
      `abi.encodeWithSignature("setFraud" "ProofVerifier" "(address)", v)`,
      true,
    ],
    [
      "adjacent literals separated by a newline",
      `abi.encodeWithSignature(\n  "setFraudProof"\n  "Verifier(address)", v)`,
      true,
    ],
    [
      "adjacent literals separated by a comment",
      `abi.encodeWithSignature("setFraudProof" /* x */ "Verifier(address)", v)`,
      true,
    ],
    // Round-5: prefixed literal kinds also concatenate.
    [
      "adjacent unicode-prefixed literals",
      `abi.encodeWithSignature(unicode"setFraudProof" unicode"Verifier(address)", v)`,
      true,
    ],
    ["adjacent hex literals forming the selector", `bytes memory cd = hex"b93b" hex"1a6e";`, true],
    // Round-5: rational spellings of the same integer constant.
    ["selector with a trailing fraction", `bytes4 s = bytes4(uint32(310765835.0e1));`, true],
    ["selector with a leading fraction", `bytes4 s = bytes4(uint32(3.10765835e9));`, true],
    ["selector with a negative exponent", `bytes4 s = bytes4(uint32(31076583500e-1));`, true],
    // Round-6: a denomination MULTIPLIES the literal, so the factor must be applied, not the literal
    // skipped — `wei` has multiplier 1, and a fraction only becomes the selector after scaling.
    ["selector with a wei suffix (multiplier 1)", `uint x = 3107658350 wei;`, true],
    ["fraction that scales to the selector", `uint x = 3.10765835 gwei;`, true],
    ["double unary minus leaves it positive", `int x = - -3107658350;`, true],
  ];
  const mustNot = [
    [
      "prose naming the removed setter without a call form",
      `// There is NO setFraudProofVerifier in this release.`,
      true,
    ],
    [
      "declaration only (faithful mock)",
      `function setFraudProofVerifier(address) external {}`,
      true,
    ],
    [
      "multiline declaration only",
      `function setFraudProofVerifier(\n    address v\n) external {}`,
      true,
    ],
    ["different function sharing a suffix", `agg.unsetFraudProofVerifier(v);`, true],
    [
      "the replacement calls",
      `agg.proposeFraudProofVerifier(v); agg.applyFraudProofVerifier();`,
      true,
    ],
    ["an unrelated 4-byte literal", `bytes4 other = 0xb93b1a6f;`, true],
    ["the selector as part of a longer word", `uint x = 0xb93b1a6eff;`, true],
    ["a hex literal that merely starts similarly", `bytes memory b = hex"b93b1a6f00";`, true],
    ["a decimal that merely contains the digits", `uint x = 13107658350;`, true],
    [
      "an address literal, not a selector",
      `address a = 0xb93b1a6e00000000000000000000000000000000;`,
      true,
    ],
    // Round-4 Medium 2: the exponent must be EVALUATED, not truncated away into a false hit.
    ["an unrelated value with a large exponent", `uint x = 3107658350e18;`, true],
    ["an unrelated scientific literal", `uint x = 310765835e2;`, true],
    // Non-adjacent literals are separate strings; solc does not join them across a comma.
    [
      "literals separated by a comma are not concatenated",
      `f("setFraudProof", "Verifier(address)")`,
      true,
    ],
    // Round-5: unary minus and denomination suffixes change the value — reporting them is noise.
    ["the digits scaled past the selector by gwei", `uint x = 3107658350 gwei;`, true],
    ["the digits negated", `int x = -3107658350;`, true],
    ["negated across a line break", `int x =\n    -3107658350;`, true],
    ["the digits scaled past the selector by days", `uint x = 3107658350 days;`, true],
    ["a fraction that is not an integer", `uint x = 3107658351e-1;`, true],
  ];
  const failures = [];
  for (const [name, src, sol] of must) {
    if (findSetterCalls(src, sol).length === 0)
      failures.push(`detector MISSED: ${name} -> ${JSON.stringify(src)}`);
  }
  for (const [name, src, sol] of mustNot) {
    if (findSetterCalls(src, sol).length !== 0)
      failures.push(`detector FALSE-POSITIVE: ${name} -> ${JSON.stringify(src)}`);
  }

  // Performance regression. The numeral scan used to slice the whole prefix and suffix per numeral and
  // match the prefix against a nested quantifier, which made a single 39KB Solidity file take 12.4s.
  // A real source file is the fixture, because the pathological input is ordinary blanked-out code.
  //
  // HOW THIS ACTUALLY FAILS, measured rather than assumed: pr-daemon restored the old implementation
  // verbatim and ran `--self-test-only` — it did not return within TEN MINUTES. So on a regression the
  // symptom is a CI TIMEOUT, not this assertion firing: `elapsed > 1000` is evaluated only after
  // `findSetterCalls` returns, and on this input the old code never does. The message below is
  // therefore a diagnostic for a MILD regression; a severe one hangs.
  //
  // "A hang is still a failure" is only true because CI bounds it. AS OF THIS COMMIT every job in
  // ci.yml carries an explicit `timeout-minutes`; without one GitHub's default is 360, so the same
  // regression would burn a runner for six hours and fail with nothing in the log explaining why.
  //
  // That is a STATEMENT ABOUT TODAY, not an invariant — nothing here enforces it, and a ninth job
  // added without a bound passes this checker. Deliberately not enforced HERE: this file is the
  // arming gate, and having it police unrelated CI configuration is the kind of scope drift that
  // makes a checker nobody can reason about. Pinning it properly belongs in its own check.
  {
    const solidityLike =
      "// a comment line that gets blanked to spaces\n".repeat(400) +
      "contract C { uint256 a = 1; uint256 b = 2; uint256 c = 0x1234; }\n".repeat(200);
    const started = Date.now();
    findSetterCalls(solidityLike, true);
    const elapsed = Date.now() - started;
    if (elapsed > 1000) {
      failures.push(
        `numeral scanning is superlinear: ${elapsed}ms on a ${solidityLike.length}-char source`
      );
    }
  }

  // ReDoS regression (CodeQL high-severity finding on the first push). The literal-gap test used to
  // be a regex nesting a lazy quantifier inside a quantified alternation, which backtracks
  // exponentially on `/*` followed by many `*//*` repetitions. Assert it stays linear.
  {
    const evil = 'f("a" ' + "/*" + "*//*".repeat(2000) + ' "b")';
    const started = Date.now();
    findSetterCalls(evil, true);
    const elapsed = Date.now() - started;
    if (elapsed > 1000) {
      failures.push(
        `literal-gap scanning is superlinear: ${elapsed}ms on a ${evil.length}-char input`
      );
    }
  }

  // Line numbers must survive the code/comment split and the length-preserving blanking.
  const multi = `contract C {\n    function setFraudProofVerifier(\n        address v\n    ) external {}\n    function f() external { o.setFraudProofVerifier(v); }\n}`;
  const hits = findSetterCalls(multi, true);
  if (hits.length !== 1 || hits[0].line !== 5) {
    failures.push(
      `detector line number wrong for a call after a multiline declaration: ${JSON.stringify(hits)}`
    );
  }

  // The comment-free view must not leak commented-out code into the structural positive checks.
  const leaks = [
    ["line comment", `// require(x >= y);\nuint a;`],
    ["block comment", `/* require(x >= y); */ uint a;`],
    // `/*/` is NOT a comment terminator in Solidity; a lexer that thinks it is spills the rest of the
    // comment into the code view, which is exactly how a commented-out require sneaks back in.
    ["slash-star-slash opener", `/*/ require(x >= y); */ uint a;`],
    ["doc comment", `/// require(x >= y);\nuint a;`],
  ];
  for (const [name, src] of leaks) {
    if (solidityCodeOnly(src).includes("require")) {
      failures.push(`solidityCodeOnly leaked a commented-out require into the code view (${name})`);
    }
  }
  // ...and a string literal must not open a line comment: `"http://x"` is a URL, not a comment.
  if (!solidityCodeOnly(`string u = "http://x"; require(a >= b);`).includes("require")) {
    failures.push("solidityCodeOnly treated a // inside a string literal as a comment opener");
  }
  // A string that merely QUOTES an enforcement shape must not satisfy a check meant to prove the
  // enforcement exists (round-3 Medium 2).
  if (
    solidityCodeOnly(
      `string x = "require(rotationDelay >= MIN_VERIFIER_ROTATION_DELAY,";`
    ).includes("require(")
  ) {
    failures.push("solidityCodeOnly leaked a string-literal decoy into the enforcement view");
  }
  // ...while the string-bearing view still carries console payloads.
  if (
    !splitSolidity(`console.log("proposeFraudProofVerifier(", v);`).codeAndStrings.includes(
      "proposeFraudProofVerifier("
    )
  ) {
    failures.push("codeAndStrings dropped a console.log payload the handoff checks depend on");
  }
  // Scoping: the checks must follow `deploy()`, not any same-named decoy elsewhere in the file.
  const scoped = `contract S {\n  function decoy() public { require(a >= b, "x"); }\n  function deploy() public { uint z; }\n}`;
  const codeView = solidityCodeOnly(scoped);
  const range = functionBodyRange(codeView, "deploy");
  if (!range || codeView.slice(range[0], range[1]).includes("require")) {
    failures.push("functionBodyRange did not isolate deploy() from a same-file decoy function");
  }
  // Round-4 Medium 1: a bodiless INTERFACE declaration must not make the locator swallow a later,
  // unrelated block as if it were deploy()'s body.
  const withIface =
    `interface IDecoy { function deploy() external; }\n` +
    `contract Other { function f() public { require(a >= b, "decoy"); } }\n` +
    `contract S { function deploy() public { uint z; } }`;
  const ifaceView = solidityCodeOnly(withIface);
  const ifaceRange = functionBodyRange(ifaceView, "deploy");
  if (!ifaceRange || ifaceView.slice(ifaceRange[0], ifaceRange[1]).includes("require")) {
    failures.push("functionBodyRange was fooled by a bodiless interface declaration of deploy()");
  }
  // ...and the `;`-before-`{` skip must not overshoot the REAL definition. Solidity return clauses and
  // modifiers carry no `;`, but multi-line signatures and `abstract` declarations are easy to get wrong.
  const LOCATOR_CASES = [
    [
      "a multi-line signature with virtual/override/returns",
      `contract C {\n  function deploy(\n    Cfg memory cfg\n  ) public virtual override returns (X memory v) {\n    REAL;\n  }\n}`,
    ],
    [
      "an abstract declaration before the definition",
      `abstract contract A { function deploy(Cfg memory) public virtual returns (X memory); }\n` +
        `contract B { function f() public { DECOY; } }\n` +
        `contract C { function deploy(Cfg memory cfg) public returns (X memory) { REAL; } }`,
    ],
    [
      "a declaration AFTER the definition",
      `contract C { function deploy() public { REAL; } }\ninterface I { function deploy() external; }`,
    ],
  ];
  for (const [name, src] of LOCATOR_CASES) {
    const view = solidityCodeOnly(src);
    const r = functionBodyRange(view, "deploy");
    const body = r ? view.slice(r[0], r[1]) : "";
    if (!body.includes("REAL") || body.includes("DECOY")) {
      failures.push(`functionBodyRange picked the wrong body for ${name}`);
    }
  }
  failures.push(...runbookSelfTest());
  return failures;
}

// ---------------------------------------------------------------------------------------------
//                            RUNBOOK GATE REGRESSION FIXTURES
// ---------------------------------------------------------------------------------------------
// Every mutation an earlier review round found — and every legitimate edit the gate must NOT reject —
// is asserted here against `checkRunbook`. Two blocking defects survived to round 7 precisely because
// these existed only as ad-hoc shell commands in a session transcript: uncommitted checks protect
// nothing after merge.

/// @dev A minimal runbook whose arming section is exactly what the gate requires.
function validRunbook() {
  return [
    "# Runbook",
    "",
    "## Something before",
    "",
    "Prose.",
    "",
    SECTION_BEGIN,
    "",
    "## Joint successor-Sepolia run (CC-115 B0/B3)",
    "",
    "### Arming procedure (authoritative)",
    "",
    BLOCK_BEGIN,
    ARMING_BLOCK,
    BLOCK_END,
    "",
    "### Run steps",
    "",
    "1. **SP**: deploy the aggregator dormant.",
    "   - **DVT**: deploy the verifier; the script requires a delay of at least **4 days**.",
    "   - **SP + anyone**: run the authoritative arming procedure above.",
    "2. **SP**: craft the slash.",
    "",
    SECTION_END,
    "",
    "## After",
    "",
    "More prose.",
  ].join("\n");
}

function runbookSelfTest() {
  const failures = [];
  // `expect` pins WHICH rule must fire, not merely that something did.
  const check = (name, text, shouldPass, expect) => {
    const errs = checkRunbook(text);
    if ((errs.length === 0) !== shouldPass) {
      failures.push(
        `checkRunbook wrong for "${name}": expected ${shouldPass ? "pass" : "fail"}, got ` +
          (errs.length ? JSON.stringify(errs) : "pass")
      );
      return;
    }
    if (expect && !errs.some(e => e.includes(expect))) {
      failures.push(
        `checkRunbook failed "${name}" for the wrong reason: expected an error mentioning ` +
          `${JSON.stringify(expect)}, got ${JSON.stringify(errs)}`
      );
    }
  };
  const base = validRunbook();
  const sub = (from, to) => base.replace(from, to);

  check("the valid runbook", base, true);

  // --- markers: presence, uniqueness, order ------------------------------------------------------
  for (const [name, marker] of [
    ["section begin", SECTION_BEGIN],
    ["section end", SECTION_END],
    ["block begin", BLOCK_BEGIN],
    ["block end", BLOCK_END],
  ]) {
    check(`a missing ${name} marker`, base.replace(marker, ""), false, "expected exactly one");
    check(
      `a duplicated ${name} marker`,
      base.replace(marker, marker + "\n" + marker),
      false,
      "expected exactly one"
    );
  }
  check(
    "the block markers outside the section",
    base
      .replace(BLOCK_BEGIN, "")
      .replace(BLOCK_END, "")
      .replace("## After", BLOCK_BEGIN + "\n" + BLOCK_END + "\n\n## After"),
    false,
    "out of order"
  );

  // --- the marked region must be LIVE and must still span the procedure -------------------------
  check(
    "the whole marked region indented into a code block",
    base
      .split("\n")
      .map(l => (l.includes("arming-") || l.trim() ? "    " + l : l))
      .join("\n"),
    false,
    "expected exactly one"
  );
  check(
    "a marker indented so the region renders as code",
    base.replace(SECTION_BEGIN, "    " + SECTION_BEGIN),
    false,
    "expected exactly one"
  );
  check(
    "a code fence anywhere inside the marked section",
    sub("2. **SP**: craft the slash.", "```\nexample output\n```\n\n2. **SP**: craft the slash."),
    false,
    "contains a code fence"
  );
  check(
    "a fence that swallows the end marker and the next heading",
    base
      .replace(SECTION_END, "```\n" + SECTION_END)
      .replace("## After", "## After\n\n```\n\nAfter one day, execute the pending rotation."),
    false,
    "contains a code fence"
  );
  check(
    "a code fence BEFORE the pinned block",
    base.replace(
      "### Arming procedure (authoritative)",
      "```\nexample\n```\n\n### Arming procedure (authoritative)"
    ),
    false,
    "contains a code fence"
  );
  check(
    "the section end marker moved up to shrink the checked region",
    base
      .replace(SECTION_END, "")
      .replace(BLOCK_END, BLOCK_END + "\n\n" + SECTION_END)
      .replace("2. **SP**: craft the slash.", "After one day, execute the pending rotation."),
    false,
    "must sit at the end of that section"
  );

  check(
    "the section begin marker moved away from its heading",
    base
      .replace(SECTION_BEGIN, "")
      .replace(
        "### Arming procedure (authoritative)",
        SECTION_BEGIN + "\n\n### Arming procedure (authoritative)"
      ),
    false,
    "must sit immediately before"
  );
  check(
    "the section end marker moved to just after the Run steps HEADING",
    base
      .replace(SECTION_END, "")
      .replace("### Run steps", "### Run steps\n\n" + SECTION_END)
      .replace("2. **SP**: craft the slash.", "After one day, execute the pending rotation."),
    false,
    "must sit at the end of that section"
  );
  check(
    "an unclosed four-backtick fence before the section marker",
    base.replace(SECTION_BEGIN, "````\n```\n\n" + SECTION_BEGIN),
    false,
    "unclosed code fence"
  );
  check(
    "a balanced fence before the section marker is fine",
    base.replace(SECTION_BEGIN, "````\n```\nexample\n````\n\n" + SECTION_BEGIN),
    true
  );

  // --- the block is pinned verbatim --------------------------------------------------------------
  check(
    "weakened wait inside the block",
    sub(
      "Wait the FULL on-chain `VERIFIER_ROTATION_DELAY` — **4 days**.",
      "Wait only 1 day, then apply early."
    ),
    false,
    "no longer matches the pinned copy"
  );
  check(
    "the block reworded without changing any duration",
    sub("The aggregator owner (a Safe M-of-N) calls", "The owner calls"),
    false,
    "no longer matches the pinned copy"
  );
  check(
    "contradiction appended inside the block",
    sub(
      "There is no direct setter",
      "Operators may instead wait only one day.\n\nThere is no direct setter"
    ),
    false,
    "no longer matches the pinned copy"
  );
  check(
    "the block rewrapped (whitespace only)",
    base.replace(ARMING_BLOCK, ARMING_BLOCK.replace(/\n   /g, " ")),
    true
  );

  // --- the arming calls are exclusive to the block -----------------------------------------------
  check(
    "a second stale procedure elsewhere in the section",
    sub(
      "2. **SP**: craft the slash.",
      "Call `proposeFraudProofVerifier`, then `applyFraudProofVerifier`.\n\n2. **SP**: craft the slash."
    ),
    false,
    "outside the authoritative arming block"
  );
  check(
    "the arming calls named OUTSIDE the marked section",
    sub("More prose.", "Historically SP called `applyFraudProofVerifier` here."),
    true
  );

  // --- the conjunctive duration rule -------------------------------------------------------------
  check(
    "a contradicting paraphrase under Run steps",
    sub(
      "2. **SP**: craft the slash.",
      "After the owner queues the new verifier, wait one day and execute the pending rotation.\n\n2. **SP**: craft the slash."
    ),
    false,
    "contradicts the pinned procedure"
  );
  check(
    "a shortcut with no waiting verb at all",
    sub(
      "2. **SP**: craft the slash.",
      "After one day, execute the pending rotation.\n\n2. **SP**: craft the slash."
    ),
    false,
    "contradicts the pinned procedure"
  );
  // KNOWN LIMIT — see the heuristic note above `checkRunbook`.
  check(
    "a shortcut written with an article instead of a numeral (KNOWN LIMIT: passes)",
    sub(
      "2. **SP**: craft the slash.",
      "After a day, execute the pending rotation.\n\n2. **SP**: craft the slash."
    ),
    true
  );
  check(
    "ordinary post-rotation prose beginning with an article",
    sub(
      "2. **SP**: craft the slash.",
      "A day after the verifier rotation, verify that both receipts are archived.\n\n2. **SP**: craft the slash."
    ),
    true
  );
  check(
    "a shortcut written with a leading-dot decimal",
    sub(
      "2. **SP**: craft the slash.",
      "After .5 days, execute the pending rotation.\n\n2. **SP**: craft the slash."
    ),
    false,
    "contradicts the pinned procedure"
  );
  check(
    "a shortcut written with a decimal duration",
    sub(
      "2. **SP**: craft the slash.",
      "After 3.5 days, execute the pending rotation.\n\n2. **SP**: craft the slash."
    ),
    false,
    "contradicts the pinned procedure"
  );
  check(
    "an hour-scale shortcut naming the call",
    sub(
      "2. **SP**: craft the slash.",
      "Wait 6 hours, then run the verifier rotation.\n\n2. **SP**: craft the slash."
    ),
    false,
    "contradicts the pinned procedure"
  );
  check(
    "a legitimate 4-day statement that names an arming object",
    sub(
      "2. **SP**: craft the slash.",
      "The `VERIFIER_ROTATION_DELAY` is 4 days.\n\n2. **SP**: craft the slash."
    ),
    true
  );
  check(
    "a descriptive mention of SP's 2-day exit notice",
    sub(
      "2. **SP**: craft the slash.",
      "SP must honor the 2-day ROLE_DVT exit notice.\n\n2. **SP**: craft the slash."
    ),
    true
  );
  check(
    "an unrelated wait and a descriptive duration in one sentence",
    sub(
      "2. **SP**: craft the slash.",
      "While waiting for the deployment receipt, remember that the ROLE_DVT exit notice is 2 days.\n\n2. **SP**: craft the slash."
    ),
    true
  );
  check(
    "a compound half-day shortcut",
    sub(
      "2. **SP**: craft the slash.",
      "After three and a half days, execute the pending rotation.\n\n2. **SP**: craft the slash."
    ),
    false,
    "contradicts the pinned procedure"
  );
  check(
    "an abbreviation that genuinely ENDS a sentence must still split",
    sub(
      "2. **SP**: craft the slash.",
      "The pending rotation record includes receipts, hashes, etc. After two days, archive the ROLE_DVT exit-notice receipt.\n\n2. **SP**: craft the slash."
    ),
    true
  );
  check(
    "a shortcut behind an abbreviation in the same sentence (KNOWN LIMIT: passes)",
    sub(
      "2. **SP**: craft the slash.",
      "The pending rotation can be applied early, e.g. after two days.\n\n2. **SP**: craft the slash."
    ),
    true
  );

  check(
    "an abbreviation that genuinely ends a sentence before a duration",
    sub(
      "2. **SP**: craft the slash.",
      "The pending rotation record includes receipts, hashes, etc. **After two days**, archive the ROLE_DVT receipt.\n\n2. **SP**: craft the slash."
    ),
    true
  );
  check(
    "a colon header followed by a descriptive duration bullet",
    sub(
      "2. **SP**: craft the slash.",
      "Verifier rotation evidence:\n\n- Archive the 2-day ROLE_DVT exit-notice receipt.\n\n2. **SP**: craft the slash."
    ),
    true
  );
  check(
    "a week-scale duration is above the window and must not be flagged",
    sub(
      "2. **SP**: craft the slash.",
      "After a week, complete the pending rotation audit.\n\n2. **SP**: craft the slash."
    ),
    true
  );
  check("the section being last in the file", base.replace("\n## After\n\nMore prose.", ""), true);

  // KNOWN, DOCUMENTED LIMITS — recorded rather than hidden.
  check(
    "a lead-in header with the duration in the list item beneath it (KNOWN LIMIT: passes)",
    sub(
      "2. **SP**: craft the slash.",
      "Pending rotation:\n\n- After two days, execute it.\n\n2. **SP**: craft the slash."
    ),
    true
  );
  check(
    "a shortcut naming no arming object (KNOWN LIMIT: passes)",
    sub(
      "2. **SP**: craft the slash.",
      "After one day, finish the rest.\n\n2. **SP**: craft the slash."
    ),
    true
  );
  check(
    "two durations in one sentence, one of them an arming object (KNOWN LIMIT: rejected)",
    sub(
      "2. **SP**: craft the slash.",
      "The verifier rotation takes 4 days, while the exit notice takes 2 days.\n\n2. **SP**: craft the slash."
    ),
    false,
    "contradicts the pinned procedure"
  );
  // Examples inside the section are checked too — there is no fence exemption by design.
  check(
    "a fenced example naming an arming call",
    sub(
      "2. **SP**: craft the slash.",
      "```\napplyFraudProofVerifier()\n```\n\n2. **SP**: craft the slash."
    ),
    false,
    "contains a code fence"
  );

  return failures;
}

// ---------------------------------------------------------------------------------------------
//                                        SCAN
// ---------------------------------------------------------------------------------------------

// Generated / vendored trees only. Deliberately does NOT skip directories named `lib`: `scripts/lib`
// is first-party code that must be scanned, and the forge submodule tree `contracts/lib` is already
// out of reach because SCAN_DIRS names `contracts/script` and `contracts/src` rather than `contracts`.
const SKIP_DIRS = new Set([
  "node_modules",
  "out",
  "cache",
  "broadcast",
  "artifacts",
  "target", // Rust build output under signer/ — 171 matching files, and 36s of scan time
  "dist",
  "coverage",
  ".git",
]);

function walk(dir, out = []) {
  let entries;
  try {
    entries = readdirSync(dir);
  } catch {
    return out; // directory absent in this checkout — nothing to assert
  }
  for (const name of entries) {
    if (SKIP_DIRS.has(name)) continue;
    const full = join(dir, name);
    let st;
    try {
      st = statSync(full);
    } catch {
      continue; // dangling symlink — nothing to read
    }
    if (st.isDirectory()) walk(full, out);
    else if (SCAN_EXTS.some(e => name.endsWith(e))) out.push(full);
  }
  return out;
}

const errors = [];

// --- Gate 0: the detector itself works -----------------------------------------------------------
errors.push(...selfTest());

if (!process.argv.includes("--self-test-only")) {
  // --- Gate 1: nothing may INVOKE the removed setter ---------------------------------------------
  // Repository-root files are scanned NON-recursively: adding "." to SCAN_DIRS walks the whole tree
  // (node_modules, contracts/lib, out/) and times out, so the root is handled as a flat list. README.md
  // and the other top-level operator-facing docs live here.
  const rootFiles = readdirSync(ROOT)
    .map(n => join(ROOT, n))
    .filter(f => {
      try {
        return statSync(f).isFile() && SCAN_EXTS.some(e => f.endsWith(e));
      } catch {
        return false;
      }
    });
  for (const file of [...SCAN_DIRS.flatMap(d => walk(join(ROOT, d))), ...rootFiles]) {
    const rel = relative(ROOT, file);
    if (rel === SELF) continue;
    const isJs = JS_EXTS.some(e => rel.endsWith(e));
    for (const hit of findSetterCalls(readFileSync(file, "utf8"), rel.endsWith(".sol"), isJs)) {
      errors.push(
        `${rel}:${hit.line}: invokes the removed setter \`setFraudProofVerifier\` (${hit.kind}). ` +
          `Use proposeFraudProofVerifier -> full VERIFIER_ROTATION_DELAY (4 days) -> applyFraudProofVerifier.`
      );
    }
  }

  // --- Gate 2: the deploy script must STRUCTURALLY hand off the whole rotation -------------------
  // Scoped to the BODY of `deploy(...)` and matched as real code shapes. Three failure modes this
  // closes, all found in review: (a) `includes` word tests keep passing after the console handoff is
  // deleted, because the header comment still mentions every term; (b) a commented-out require reads
  // as live code; (c) a string literal that merely QUOTES the require satisfies a check meant to
  // prove the require exists — so enforcement shapes are matched with strings blanked, and only the
  // console shapes (whose payload legitimately lives in a string) see string content.
  const deploySrc = readFileSync(join(ROOT, DEPLOY_SCRIPT), "utf8");
  const deployViews = splitSolidity(deploySrc);
  const bodyRange = functionBodyRange(deployViews.code, "deploy");
  if (!bodyRange) {
    errors.push(
      `${DEPLOY_SCRIPT}: cannot locate the body of \`deploy(...)\` — the guards have no home.`
    );
  } else {
    const [bs, be] = bodyRange;
    // Enforcement must be LIVE CODE inside deploy(): no comments, no string decoys.
    const deployBodyCode = deployViews.code.slice(bs, be);
    // Console handoff legitimately carries its payload in string literals, so this view keeps them.
    const deployBodyText = deployViews.codeAndStrings.slice(bs, be);

    const CODE_SHAPES = [
      [
        /require\(\s*\n?\s*rotationDelay\s*>=\s*MIN_VERIFIER_ROTATION_DELAY\s*,/,
        "a live require() inside deploy() enforcing the 4-day arming floor",
      ],
      [
        /require\(\s*\n?\s*keccak256\(bytes\(reportedVersion\)\)\s*==\s*keccak256\(bytes\(expectedVersion\)\)\s*,/,
        "a live require() inside deploy() rejecting an AGGREGATOR.version() that differs from the pin",
      ],
    ];
    const TEXT_SHAPES = [
      [
        /console\.log\([^;]*proposeFraudProofVerifier\s*\(/,
        "a console.log in deploy() telling the operator to call proposeFraudProofVerifier(verifier)",
      ],
      [
        /console\.log\([^;]*applyFraudProofVerifier\s*\(\s*\)/,
        "a console.log in deploy() telling the operator to call the permissionless applyFraudProofVerifier()",
      ],
      [
        /console\.log\([^;]*rotationDelay\s*\)/,
        "a console.log in deploy() printing the actual on-chain rotation delay",
      ],
    ];
    for (const [re, what] of CODE_SHAPES)
      if (!re.test(deployBodyCode)) errors.push(`${DEPLOY_SCRIPT}: missing ${what}.`);
    for (const [re, what] of TEXT_SHAPES)
      if (!re.test(deployBodyText)) errors.push(`${DEPLOY_SCRIPT}: missing ${what}.`);
  }

  // The pinned constant lives at contract scope, not inside deploy(). The DECLARATION must be live
  // code (so a string decoy quoting the whole line cannot stand in for it) while its VALUE is
  // legitimately a string — so the declaration is located in the code view and the literal is then
  // read from the same offsets in the string-bearing view. Pinned to the EXACT reviewed release:
  // accepting any "BLSAggregator-*" would let a regression to a pre-rotation release through the very
  // gate meant to catch it.
  const pinDecl = /string\s+internal\s+constant\s+SUPPORTED_AGGREGATOR_VERSION\s*=/.exec(
    deployViews.code
  );
  if (!pinDecl) {
    errors.push(`${DEPLOY_SCRIPT}: no live declaration of SUPPORTED_AGGREGATOR_VERSION.`);
  } else {
    const tail = deployViews.codeAndStrings.slice(pinDecl.index, pinDecl.index + 200);
    if (!/=\s*"BLSAggregator-4\.11\.0"\s*;/.test(tail)) {
      errors.push(
        `${DEPLOY_SCRIPT}: SUPPORTED_AGGREGATOR_VERSION must stay pinned to the exact reviewed release ` +
          `"BLSAggregator-4.11.0".`
      );
    }
  }

  // The floor must not become a knob.
  if (/vm\.env\w*\(\s*"[A-Z_]*ROTATION[A-Z_]*"/.test(deployViews.codeAndStrings)) {
    errors.push(
      `${DEPLOY_SCRIPT}: the arming-delay floor must not become env-overridable — a shortened window ` +
        `is a security regression the operator has to see, not a knob.`
    );
  }

  // --- Gate 3: the runbook's arming procedure is a pinned, exclusive block (no polarity checks) ---
  // The logic lives in `checkRunbook`, a pure function, so the mutations that must fail are committed
  // regression tests in selfTest() rather than assertions in a review reply.
  for (const e of checkRunbook(readFileSync(join(ROOT, RUNBOOK), "utf8"))) {
    errors.push(`${RUNBOOK}: ${e}`);
  }
}

if (errors.length > 0) {
  console.error("verifier-arming check FAILED:\n");
  for (const e of errors) console.error(`  - ${e}`);
  console.error(
    "\nArming is: proposeFraudProofVerifier(v) -> wait the FULL VERIFIER_ROTATION_DELAY (4 days) -> permissionless applyFraudProofVerifier()."
  );
  process.exit(1);
}

console.log(
  "verifier-arming check OK — detector self-tests pass; no setter invocation; propose -> 4 days -> apply intact."
);
