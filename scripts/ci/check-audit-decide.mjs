#!/usr/bin/env node
// Cells for audit-decide.mjs (the npm audit gate's decision). `npm run check:audit-gate`.
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { decide, exceptionProblems, expiryProblems } from "./audit-decide.mjs";

let pass = 0;
let fail = 0;
const cell = (name, fn) => {
  try {
    fn();
    pass++;
    console.log(`ok   ${name}`);
  } catch (e) {
    fail++;
    console.log(`FAIL ${name}: ${e.message}`);
  }
};
const assert = (c, m) => {
  if (!c) throw new Error(m);
};

const PICO = "GHSA-fc5q-39xc-vjpf";
const adv = (name, id, severity = "high") => ({
  name,
  severity,
  title: `${name} advisory`,
  url: `https://github.com/advisories/${id}`,
  range: "<=4.0.7",
});
// the shape npm audit --json gives: a root advisory object, and dependents pointing at it by name
const report = (entries, counts) => ({
  auditReportVersion: 2,
  vulnerabilities: entries,
  metadata: {
    vulnerabilities: (c => ({ ...c, total: c.total ?? Object.keys(entries).length }))({
      info: 0,
      low: 0,
      moderate: 0,
      high: 0,
      critical: 0,
      ...counts,
    }),
  },
});
const picoOnly = report(
  {
    picomatch: { name: "picomatch", severity: "high", via: [adv("picomatch", PICO)] },
    jest: { name: "jest", severity: "high", via: ["picomatch"] },
  },
  { high: 2 }
);
const EXC = [
  { id: PICO, package: "picomatch", expires: "2026-12-17", reason: "r", approvedBy: "DSR" },
];
const today = "2026-11-18";

cell("full: the excepted advisory alone passes, and says so", () => {
  const r = decide(picoOnly, { mode: "full", exceptions: EXC, today });
  assert(r.ok, r.errors.join("; "));
  assert(
    r.notes.some(n => n.startsWith("EXCEPTED") && n.includes(PICO)),
    r.notes.join("; ")
  );
});
cell("full CONTROL: without the exception the same report fails", () => {
  assert(!decide(picoOnly, { mode: "full", exceptions: [], today }).ok, "passed");
});
cell("full: any other high advisory still fails beside the excepted one", () => {
  const r = report(
    {
      picomatch: { name: "picomatch", severity: "high", via: [adv("picomatch", PICO)] },
      lodash: {
        name: "lodash",
        severity: "critical",
        via: [adv("lodash", "GHSA-aaaa-bbbb-cccc", "critical")],
      },
    },
    { high: 1, critical: 1 }
  );
  const d = decide(r, { mode: "full", exceptions: EXC, today });
  assert(!d.ok && d.errors.some(e => e.includes("GHSA-aaaa-bbbb-cccc")), d.errors.join("; "));
});
cell("full: the excepted id in ANOTHER package is not excepted", () => {
  const r = report(
    { other: { name: "other", severity: "high", via: [adv("other", PICO)] } },
    { high: 1 }
  );
  assert(!decide(r, { mode: "full", exceptions: EXC, today }).ok, "passed");
});
cell("full: an expired exception fails by itself (2026-12-18), even with nothing reported", () => {
  const clean = report({}, {});
  assert(
    decide(clean, { mode: "full", exceptions: EXC, today: "2026-12-17" }).ok,
    "failed on its last day"
  );
  const d = decide(clean, { mode: "full", exceptions: EXC, today: "2026-12-18" });
  assert(!d.ok && /expired on 2026-12-17: re-check/.test(d.errors.join()), d.errors.join("; "));
  assert(
    !decide(picoOnly, { mode: "full", exceptions: EXC, today: "2026-12-18" }).ok,
    "expired passed"
  );
});
cell("prod: no exception ever applies", () => {
  const d = decide(picoOnly, { mode: "prod", exceptions: EXC, today });
  assert(!d.ok && d.errors.some(e => e.includes(PICO)), d.errors.join("; "));
  assert(decide(report({}, {}), { mode: "prod", today }).ok, "a clean production report failed");
});
cell("never fail-open: output that is not an audit report fails, both modes", () => {
  for (const mode of ["prod", "full"])
    for (const bad of [
      null,
      {},
      { metadata: { vulnerabilities: {} } },
      { metadata: { vulnerabilities: { high: 0, critical: 0 } } },
      { vulnerabilities: {}, metadata: { vulnerabilities: {} } },
      { vulnerabilities: {}, metadata: { vulnerabilities: { high: "0", critical: 0 } } },
    ])
      assert(
        !decide(bad, { mode, exceptions: EXC, today }).ok,
        `${mode} passed ${JSON.stringify(bad)}`
      );
});
cell("high counts with no advisory object to explain them fail", () => {
  const r = report({ jest: { name: "jest", severity: "high", via: ["picomatch"] } }, { high: 1 });
  assert(!decide(r, { mode: "full", exceptions: EXC, today }).ok, "passed");
});
cell("an unknown mode fails", () => {
  assert(!decide(report({}, {}), { mode: "dev", today }).ok, "passed");
});
cell(
  "the exceptions file: each entry names a GHSA id, package, date, reason and approver, once",
  () => {
    assert(
      exceptionProblems([
        { id: "CVE-1", package: "x", expires: "2026-12-17", reason: "r", approvedBy: "a" },
      ]).length,
      "a non-GHSA id"
    );
    assert(exceptionProblems([{ ...EXC[0], expires: "soon" }]).length, "a bad date");
    assert(exceptionProblems([{ ...EXC[0], reason: "" }]).length, "no reason");
    assert(exceptionProblems([EXC[0], EXC[0]]).length, "a duplicate");
    assert(exceptionProblems("x").length, "not a list");
    const real = JSON.parse(
      readFileSync(join(dirname(fileURLToPath(import.meta.url)), "audit-exceptions.json"), "utf8")
    );
    assert(exceptionProblems(real).length === 0, exceptionProblems(real).join("; "));
    assert(
      real.length === 1 && real[0].id === PICO && real[0].expires === "2026-12-17",
      "the committed exceptions changed"
    );
  }
);

// ---- Codex pre-PR review: inputs that passed before --------------------------------------------
cell(
  "full: an excepted advisory does not mask another high entry (unresolved via, or a moderate-only chain)",
  () => {
    const base = {
      picomatch: { name: "picomatch", severity: "high", via: [adv("picomatch", PICO)] },
    };
    const a = report(
      { ...base, other: { name: "other", severity: "high", via: ["missing"] } },
      { high: 2 }
    );
    assert(!decide(a, { mode: "full", exceptions: EXC, today }).ok, "an unresolved via passed");
    const b = report(
      {
        ...base,
        other: {
          name: "other",
          severity: "high",
          via: [adv("other", "GHSA-dddd-eeee-ffff", "moderate")],
        },
      },
      { high: 2 }
    );
    assert(
      !decide(b, { mode: "full", exceptions: EXC, today }).ok,
      "a high entry explained by a moderate advisory passed"
    );
  }
);
cell(
  "prod and full: high evidence fails even when the counts say zero (the counts must agree)",
  () => {
    const r = report(
      { other: { name: "other", severity: "high", via: [adv("other", "GHSA-aaaa-bbbb-cccc")] } },
      { high: 0 }
    );
    for (const mode of ["prod", "full"])
      assert(!decide(r, { mode, exceptions: EXC, today }).ok, `${mode} passed`);
    const hidden = report(
      {
        other: { name: "other", severity: "moderate", via: [adv("other", "GHSA-aaaa-bbbb-cccc")] },
      },
      { moderate: 1 }
    );
    assert(
      !decide(hidden, { mode: "prod", today }).ok,
      "a high advisory object in a moderate entry passed"
    );
    assert(
      !decide(report({}, { high: -1 }), { mode: "prod", today }).ok,
      "a negative count passed"
    );
    assert(
      !decide(report({}, { high: 0.5 }), { mode: "prod", today }).ok,
      "a fractional count passed"
    );
    for (const mode of ["prod", "full"])
      assert(
        !decide(report({}, { high: 1 }), { mode, exceptions: EXC, today }).ok,
        `${mode}: counts with no entry behind them passed`
      );
  }
);
cell(
  "full: the excepted GHSA id reported again in another package fails (keyed by id AND package)",
  () => {
    const r = report(
      {
        picomatch: { name: "picomatch", severity: "high", via: [adv("picomatch", PICO)] },
        other: { name: "other", severity: "high", via: [adv("other", PICO)] },
      },
      { high: 2 }
    );
    const d = decide(r, { mode: "full", exceptions: EXC, today });
    assert(!d.ok && d.errors.some(e => e.includes("in other")), d.errors.join("; "));
  }
);
cell("the real report: picomatch's chain through jest etc. passes full, fails prod", () => {
  // the shape npm printed on 2026-11-18 for this repo, trimmed to one chain
  const r = report(
    {
      picomatch: { name: "picomatch", severity: "high", via: [adv("picomatch", PICO)] },
      micromatch: { name: "micromatch", severity: "high", via: ["picomatch"] },
      jest: { name: "jest", severity: "high", via: ["micromatch", "jest"] },
    },
    { high: 3 }
  );
  assert(decide(r, { mode: "full", exceptions: EXC, today }).ok, "full failed");
  assert(!decide(r, { mode: "prod", today }).ok, "prod passed");
});
cell("expiry: checked on its own (before any fetch); expired or malformed exceptions fail", () => {
  assert(expiryProblems(EXC, "2026-12-17").length === 0, "failed on its last day");
  assert(expiryProblems(EXC, "2026-12-18").length === 1, "an expired exception passed");
  assert(expiryProblems([{ id: "x" }], today).length > 0, "a malformed exception passed");
  const sh = readFileSync(join(dirname(fileURLToPath(import.meta.url)), "npm-audit.sh"), "utf8");
  const e = sh.indexOf("--mode expiry || exit 1");
  assert(
    e > 0 && e < sh.indexOf("for attempt in"),
    "npm-audit.sh does not check expiry before fetching"
  );
});

// the wrapper itself, with npm/timeout/sleep stubbed: what is retried as an outage and what is data
const SH = join(dirname(fileURLToPath(import.meta.url)), "npm-audit.sh");
const wrapper = (mode, stdout, code = 124) => {
  const bin = mkdtempSync(join(tmpdir(), "audit-stub-"));
  const fixture = join(bin, "out.json");
  writeFileSync(fixture, stdout);
  // npm exits 1 when it prints a report with findings; an empty fixture stands for a hang (124)
  writeFileSync(
    join(bin, "npm"),
    `#!/bin/sh\ncat "${fixture}"\n[ -s "${fixture}" ] && exit 1\nexit ${code}\n`,
    {
      mode: 0o755,
    }
  );
  writeFileSync(join(bin, "timeout"), '#!/bin/sh\nshift\nexec "$@"\n', { mode: 0o755 });
  writeFileSync(join(bin, "sleep"), "#!/bin/sh\nexit 0\n", { mode: 0o755 });
  const r = spawnSync("bash", [SH, mode], {
    encoding: "utf8",
    env: { ...process.env, PATH: `${bin}:${process.env.PATH}` },
  });
  rmSync(bin, { recursive: true, force: true });
  return r;
};
cell("wrapper: a malformed report is data, not an outage: it FAILS (prod and full)", () => {
  const bad = JSON.stringify({
    vulnerabilities: { other: { severity: "critical" } },
    metadata: { vulnerabilities: { high: "0", critical: 1 } },
  });
  for (const mode of ["prod", "full"]) {
    const r = wrapper(mode, bad);
    assert(
      r.status === 1 && !/PASSED WITHOUT CHECKING/.test(r.stdout),
      `${mode}: ${r.status} ${r.stdout}`
    );
  }
  assert(wrapper("prod", "not json at all").status === 1, "non-JSON output passed");
});
cell(
  "wrapper: empty output or npm's error envelope is an outage: retried 3 times, then a loud pass",
  () => {
    for (const out of ["", JSON.stringify({ error: { code: "ENOAUDIT", summary: "503" } })]) {
      const r = wrapper("prod", out);
      assert(
        r.status === 0 &&
          /attempt 3 did not return advisory data/.test(r.stdout) &&
          /PASSED WITHOUT CHECKING/.test(r.stdout),
        `${JSON.stringify(out)}: ${r.status} ${r.stdout}`
      );
    }
  }
);
cell("wrapper CONTROL: a real clean report passes; a real high one fails prod", () => {
  assert(wrapper("prod", JSON.stringify(report({}, {}))).status === 0, "clean failed");
  assert(wrapper("prod", JSON.stringify(picoOnly)).status === 1, "high passed prod");
  assert(wrapper("full", JSON.stringify(picoOnly)).status === 0, "excepted failed full");
});

// ---- Codex pre-PR review, round 2 ----------------------------------------------------------------
cell(
  "wrapper: an `error` key does not make data an outage: error:null on a high report, {error:{}}, ENOLOCK all FAIL",
  () => {
    const withNull = JSON.stringify({ ...picoOnly, error: null });
    for (const [out, why] of [
      [withNull, "a high report with error:null"],
      [JSON.stringify({ error: {} }), "an empty error envelope"],
      [
        JSON.stringify({ ...picoOnly, error: { code: "E503", summary: "503" } }),
        "a high report carrying an outage-looking error",
      ],
      [
        JSON.stringify({
          error: { code: "ENOLOCK", summary: "This command requires an existing lockfile." },
        }),
        "ENOLOCK",
      ],
    ]) {
      const r = wrapper("prod", out);
      assert(r.status === 1 && !/PASSED WITHOUT CHECKING/.test(r.stdout), `${why}: ${r.status}`);
    }
    const r = wrapper(
      "prod",
      JSON.stringify({ message: "x", error: { code: "E503", summary: "503" } })
    );
    assert(
      r.status === 0 && /PASSED WITHOUT CHECKING/.test(r.stdout),
      "CONTROL: E503 is an outage"
    );
  }
);
cell("an advisory's name or dependency must be the entry it sits in", () => {
  for (const extra of [
    { dependency: "other" },
    { name: "other" },
    { name: "picomatch", dependency: "other" },
  ]) {
    const r = report(
      {
        picomatch: {
          name: "picomatch",
          severity: "high",
          via: [{ ...adv("picomatch", PICO), ...extra }],
        },
      },
      { high: 1 }
    );
    assert(
      !decide(r, { mode: "full", exceptions: EXC, today }).ok,
      `passed with ${JSON.stringify(extra)}`
    );
  }
  const ok = report(
    {
      picomatch: {
        name: "picomatch",
        severity: "high",
        via: [{ ...adv("picomatch", PICO), dependency: "picomatch", source: 1 }],
      },
    },
    { high: 1 }
  );
  assert(
    decide(ok, { mode: "full", exceptions: EXC, today }).ok,
    "CONTROL: a consistent advisory failed"
  );
});
cell("an advisory with no readable severity fails, even beside the excepted one", () => {
  const r = report(
    {
      picomatch: {
        name: "picomatch",
        severity: "high",
        via: [
          adv("picomatch", PICO),
          { source: 999, url: "https://github.com/advisories/GHSA-aaaa-bbbb-cccc" },
        ],
      },
    },
    { high: 1 }
  );
  assert(!decide(r, { mode: "full", exceptions: EXC, today }).ok, "passed");
});
cell("every severity count and the total must agree with the entries", () => {
  const mod = {
    x: { name: "x", severity: "moderate", via: [adv("x", "GHSA-aaaa-bbbb-cccc", "moderate")] },
  };
  assert(
    decide(report(mod, { moderate: 1 }), { mode: "prod", today }).ok,
    "CONTROL: a consistent moderate report failed"
  );
  assert(
    !decide(report(mod, { moderate: 0 }), { mode: "prod", today }).ok,
    "a wrong moderate count passed"
  );
  assert(
    !decide(report(mod, { moderate: 1, total: 2 }), { mode: "prod", today }).ok,
    "a wrong total passed"
  );
  const missing = report(mod, { moderate: 1 });
  delete missing.metadata.vulnerabilities.low;
  assert(!decide(missing, { mode: "prod", today }).ok, "a missing count passed");
});
cell("wrapper: npm that cannot be run fails, it is not an outage", () => {
  const bin = mkdtempSync(join(tmpdir(), "audit-stub-"));
  writeFileSync(join(bin, "timeout"), '#!/bin/sh\nshift\nexec "$@"\n', { mode: 0o755 });
  writeFileSync(join(bin, "npm"), "#!/bin/sh\nexit 127\n", { mode: 0o755 });
  const r = spawnSync("bash", [SH, "prod"], {
    encoding: "utf8",
    env: { ...process.env, PATH: `${bin}:${process.env.PATH}` },
  });
  rmSync(bin, { recursive: true, force: true });
  assert(r.status === 1 && /not a registry outage/.test(r.stdout), `${r.status} ${r.stdout}`);
});

cell(
  "wrapper: a report followed by an outage envelope is data, not an outage: FAILS (Codex pre-PR r3)",
  () => {
    const crit = JSON.stringify(
      report(
        {
          x: {
            name: "x",
            severity: "critical",
            via: [adv("x", "GHSA-aaaa-bbbb-cccc", "critical")],
          },
        },
        { critical: 1 }
      )
    );
    const stream = `${crit}\n${JSON.stringify({ error: { code: "E503" } })}\n`;
    for (const mode of ["prod", "full"]) {
      const r = wrapper(mode, stream);
      assert(r.status === 1 && !/PASSED WITHOUT CHECKING/.test(r.stdout), `${mode}: ${r.status}`);
    }
    const twoOutages = `${JSON.stringify({ error: { code: "E503" } })}\n${JSON.stringify({ error: { code: "E503" } })}`;
    assert(wrapper("prod", twoOutages).status === 1, "two envelopes passed as an outage");
  }
);

cell(
  "wrapper: empty output is an outage only after a timeout (124); any other exit FAILS (Codex pre-PR r4)",
  () => {
    for (const mode of ["prod", "full"]) {
      for (const code of [0, 1, 125, 126, 127, 134, 137]) {
        const r = wrapper(mode, "", code);
        assert(
          r.status === 1 && !/PASSED WITHOUT CHECKING/.test(r.stdout),
          `${mode} exit ${code}: ${r.status}`
        );
      }
      const t = wrapper(mode, "", 124);
      assert(
        t.status === 0 && /PASSED WITHOUT CHECKING/.test(t.stdout),
        `CONTROL ${mode}: a timeout is an outage`
      );
    }
  }
);

cell(
  "a report that also carries `error` (or any key a report does not have) FAILS, both modes, clean or excepted (Codex pre-PR r5)",
  () => {
    const err = { code: "ENOLOCK", summary: "This command requires an existing lockfile." };
    for (const mode of ["prod", "full"]) {
      assert(
        !decide({ ...report({}, {}), error: err }, { mode, exceptions: EXC, today }).ok,
        `${mode}: a clean report with error passed`
      );
      assert(
        !decide({ ...report({}, {}), extra: 1 }, { mode, exceptions: EXC, today }).ok,
        `${mode}: an unknown key passed`
      );
      const r = wrapper(mode, JSON.stringify({ ...report({}, {}), error: err }));
      assert(r.status === 1, `${mode}: the wrapper passed a clean report with error`);
    }
    assert(
      !decide({ ...picoOnly, error: err }, { mode: "full", exceptions: EXC, today }).ok,
      "the excepted report with error passed"
    );
  }
);

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
