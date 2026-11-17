#!/usr/bin/env node
// The decision half of CI's npm audit gate: reads `npm audit --json` output and says pass or fail.
// The fetching half (retries, the registry-outage warning) stays in .github/workflows/ci.yml.
//
//   node scripts/ci/audit-decide.mjs --mode prod  < audit.json   # npm audit --omit=dev: STRICT
//   node scripts/ci/audit-decide.mjs --mode full  < audit.json   # all deps: listed exceptions apply
//   node scripts/ci/audit-decide.mjs --mode expiry               # the exceptions file and its dates only
//
// - prod: any high or critical advisory fails. No exception ever applies (DSR 2026-11-18): this run
//   is what proves, mechanically, that an excepted advisory is not in a runtime dependency.
// - full: a high or critical advisory fails unless its GHSA id is listed in audit-exceptions.json
//   and that entry has not expired. An expired entry fails by itself, whether or not the advisory is
//   still reported: the exception must be re-checked (removed or renewed with a new reason).
//
// Advisory DATA never fails open (the workflow's rule): output this script cannot read as an audit
// report fails. Exit 0 = pass, 1 = fail; the reason is printed as a GitHub annotation.
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HIGH = new Set(["high", "critical"]);
const GHSA = /^GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}$/;

/** The GHSA id an advisory object names (from its url), or null. */
const ghsaOf = a => {
  const id = String(a?.url ?? "")
    .split("/")
    .pop();
  return GHSA.test(id) ? id : null;
};

/** Problems with the exceptions file itself (it is reviewed code; a malformed entry fails). Pure. */
export function exceptionProblems(list) {
  if (!Array.isArray(list)) return ["the exceptions file is not a list"];
  const p = [];
  const seen = new Set();
  for (const e of list) {
    if (!GHSA.test(e?.id ?? "")) p.push(`an exception has no GHSA id: ${JSON.stringify(e)}`);
    else if (seen.has(e.id)) p.push(`${e.id} is listed twice`);
    else seen.add(e.id);
    if (!/^\d{4}-\d{2}-\d{2}$/.test(e?.expires ?? "") || Number.isNaN(Date.parse(e.expires)))
      p.push(`${e?.id}: expires is not a YYYY-MM-DD date`);
    for (const k of ["package", "reason", "approvedBy"])
      if (typeof e?.[k] !== "string" || !e[k].trim()) p.push(`${e?.id}: no ${k}`);
  }
  return p;
}

const SEVERITIES = new Set(["info", "low", "moderate", "high", "critical"]);
const count = n => Number.isSafeInteger(n) && n >= 0;

/**
 * Problems with the exceptions themselves at `today` (YYYY-MM-DD, UTC): malformed entries, and any
 * entry past its date. Checked BEFORE the audit is fetched (scripts/ci/npm-audit.sh), so a registry
 * outage cannot outlive an expiry (Codex pre-PR review). Pure.
 */
export function expiryProblems(exceptions, today) {
  const p = exceptionProblems(exceptions);
  if (p.length) return p;
  return exceptions
    .filter(e => today > e.expires)
    .map(
      e =>
        `the exception for ${e.id} (${e.package}) expired on ${e.expires}: re-check it. If a fixed version exists, update the lockfile and remove the exception; otherwise renew it in scripts/ci/audit-exceptions.json with a new date and reason, reviewed`
    );
}

/**
 * Decide from one `npm audit --json` report. `today` is a YYYY-MM-DD string (UTC). Pure.
 * Returns { ok, errors: [string], notes: [string] }.
 *
 * Every high or critical ENTRY must be explained: its `via` chain (string links resolved through
 * the map) must reach at least one high or critical advisory object, and in full mode every such
 * advisory it reaches must be excepted for that GHSA id IN THAT PACKAGE. Any high or critical
 * advisory object anywhere is judged the same way. The counts must be integers and agree with the
 * entries. Anything else is not a report this gate can read, and fails (Codex pre-PR review).
 */
export function decide(report, { mode, exceptions = [], today }) {
  const errors = [];
  const notes = [];
  const fail = e => ({ ok: false, errors: [e], notes });
  if (mode !== "prod" && mode !== "full") return fail(`unknown mode ${mode}`);
  // only the keys npm's report has (Codex pre-PR r5): a report that ALSO carries `error`, or
  // anything else, may be incomplete, and fails. A future npm that adds a key fails here too, and
  // this list is then updated by review: never by passing
  const REPORT_KEYS = ["auditReportVersion", "vulnerabilities", "metadata"];
  if (!(report && typeof report === "object" && !Array.isArray(report)))
    return fail("the output is not an npm audit report");
  const extra = Object.keys(report).filter(k => !REPORT_KEYS.includes(k));
  if (extra.length)
    return fail(`the report carries keys an audit report does not have: ${extra.join(", ")}`);
  const v = report?.metadata?.vulnerabilities;
  if (!(v && typeof v === "object" && count(v.high) && count(v.critical)))
    return fail("the output is not an npm audit report (no high/critical counts)");
  for (const k of [...SEVERITIES, "total"])
    if (!count(v[k])) return fail(`the report's ${k} count is missing or not a count`);
  const map = report.vulnerabilities;
  if (!(map && typeof map === "object" && !Array.isArray(map)))
    return fail("the npm audit report has no vulnerabilities map");
  for (const [pkg, e] of Object.entries(map)) {
    if (!(e && typeof e === "object" && SEVERITIES.has(e.severity) && Array.isArray(e.via)))
      return fail(`the report's entry ${pkg} is not an audit entry`);
    // every advisory object is read before anything is filtered by severity (Codex pre-PR r2): an
    // unreadable one, or one naming another package than the entry it sits in, fails
    for (const x of e.via) {
      if (typeof x === "string") continue;
      if (!(x && typeof x === "object" && SEVERITIES.has(x.severity)))
        return fail(`${pkg}: an advisory with no readable severity`);
      if (typeof x.url !== "string" && typeof x.title !== "string")
        return fail(`${pkg}: an advisory with neither a url nor a title`);
      for (const k of ["name", "dependency"])
        if (x[k] !== undefined && x[k] !== pkg)
          return fail(`${pkg}: an advisory whose ${k} is ${JSON.stringify(x[k])}, not ${pkg}`);
    }
  }
  const entries = Object.entries(map);
  const bySev = sev => entries.filter(([, e]) => e.severity === sev).length;
  // every severity's count, and the total, must be the entries' (Codex pre-PR r2)
  for (const sev of SEVERITIES)
    if (bySev(sev) !== v[sev])
      return fail(`the report's ${sev} count ${v[sev]} disagrees with its entries (${bySev(sev)})`);
  if (v.total !== entries.length)
    return fail(`the report's total ${v.total} disagrees with its entries (${entries.length})`);
  notes.push(
    `advisories: critical=${v.critical} high=${v.high} moderate=${v.moderate} low=${v.low}`
  );

  let active = new Map(); // "GHSA|package" -> exception
  if (mode === "full") {
    const ep = expiryProblems(exceptions, today);
    if (ep.length) return { ok: false, errors: ep, notes };
    active = new Map(exceptions.map(e => [`${e.id}|${e.package}`, e]));
  }
  const seen = new Set();
  // one advisory object, judged: prod never excepts; full needs its GHSA id in its own package
  const judge = (a, where) => {
    const id = ghsaOf(a);
    const pkg = where; // the entry it sits in; name and dependency were checked to agree above
    const key = `${id ?? `?${a.title ?? pkg}`}|${pkg}`;
    if (seen.has(key)) return;
    seen.add(key);
    const e = id && active.get(`${id}|${pkg}`);
    if (mode === "prod")
      errors.push(
        `${a.severity} ${id ?? "(no GHSA id)"} in ${pkg} (a production dependency; no exception applies): ${a.title}`
      );
    else if (!e) errors.push(`${a.severity} ${id ?? "(no GHSA id)"} in ${pkg}: ${a.title}`);
    else notes.push(`EXCEPTED until ${e.expires}: ${a.severity} ${id} in ${pkg} (${e.reason})`);
  };
  // the advisory objects an entry's via chain reaches (string links resolved, cycles cut)
  const reach = pkg => {
    const out = [];
    const stack = [pkg];
    const visited = new Set();
    while (stack.length) {
      const p = stack.pop();
      if (visited.has(p)) continue;
      visited.add(p);
      if (!(p in map)) {
        errors.push(`${pkg}: its via chain names ${p}, which the report does not have`);
        continue;
      }
      for (const x of map[p].via)
        if (typeof x === "string") stack.push(x);
        else if (x && typeof x === "object") out.push([x, p]);
        else errors.push(`${p}: a via item that is neither a name nor an advisory`);
    }
    return out;
  };
  for (const [pkg, e] of entries) {
    for (const x of e.via) if (x && typeof x === "object" && HIGH.has(x.severity)) judge(x, pkg);
    if (!HIGH.has(e.severity)) continue;
    const high = reach(pkg).filter(([a]) => HIGH.has(a.severity));
    if (!high.length)
      errors.push(`${pkg} is ${e.severity}, but no high or critical advisory explains it`);
    for (const [a, where] of high) judge(a, where);
  }
  for (const e of active.values())
    if (!seen.has(`${e.id}|${e.package}`))
      notes.push(`the exception for ${e.id} matched nothing this run: remove it if the fix is in`);
  return { ok: errors.length === 0, errors, notes };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const mode = process.argv[process.argv.indexOf("--mode") + 1];
  const here = dirname(fileURLToPath(import.meta.url));
  let report = null;
  if (mode !== "expiry")
    try {
      report = JSON.parse(readFileSync(0, "utf8"));
    } catch {
      report = null;
    }
  const exceptions = JSON.parse(readFileSync(join(here, "audit-exceptions.json"), "utf8"));
  const today = new Date().toISOString().slice(0, 10);
  const r =
    mode === "expiry"
      ? (p => ({ ok: !p.length, errors: p, notes: [] }))(expiryProblems(exceptions, today))
      : decide(report, { mode, exceptions, today });
  for (const n of r.notes)
    console.log(n.startsWith("EXCEPTED") ? `::warning title=npm audit exception::${n}` : n);
  for (const e of r.errors) console.log(`::error title=npm audit (${mode})::${e}`);
  console.log(r.ok ? `npm audit (${mode}): pass` : `npm audit (${mode}): FAIL`);
  process.exit(r.ok ? 0 : 1);
}
