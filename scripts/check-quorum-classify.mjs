#!/usr/bin/env node
// Regression guard for the sentinel exemption in deploy/lib/quorum-classify.mjs.
//
// This exists because the exemption has already been wrong once in each direction's neighbourhood:
// it EXCLUDED `beforeWindow`, so the first block of every epoch paged CRITICAL on a healthy stack
// (~1 block in 64, a false page every few hours at a 15-minute sampling interval). Widening it fixed
// that -- and widening a "do not alert" predicate is exactly the change that can silently swallow a
// real outage, so the boundary needs a test that does not depend on the chain being in a particular
// state.
//
// It cannot be an integration test. The decisive case -- the epoch's first block with e-1 ALSO
// unusable -- needs archive state to reproduce and cannot be provoked on demand, which is why it had
// no coverage at all until pr-daemon pointed at the gap on #274.
//
// CELL 2 IS THE POINT. Cells 1 and 3 only show the function says "benign" sometimes; only a cell
// that must NOT be exempt can show the exemption is not vacuously true.
import { isBenignPendingPin } from "../deploy/lib/quorum-classify.mjs";

const HEALTHY_D2 = { isD2: true, usableE: false, usablePrev: true, floorOk: true, pinnedE: false, pastWindow: false };

const CELLS = [
  {
    name: "1. epoch e unpinned, still inside its window, e-1 serves",
    why: "the keeper's ordinary pin latency (~4-5 blocks in 64). Paging here is the alert fatigue this exemption exists to prevent.",
    state: HEALTHY_D2,
    expect: true,
  },
  {
    name: "2. epoch e unpinned at its FIRST block, and e-1 is ALSO unusable",
    why: "THE SAFETY BOUNDARY. bn == start means nobody could have pinned e yet, which is why the exemption was widened to cover it -- but if e-1 does not serve either, NOTHING serves and tier-2/3 is failing closed. This must page. If this cell ever returns true, the widening became a hole.",
    state: { ...HEALTHY_D2, usablePrev: false },
    expect: false,
  },
  {
    name: "3. epoch e unpinned and its window has CLOSED",
    why: "the keeper missed the window outright; e can never be pinned now. Not latency.",
    state: { ...HEALTHY_D2, pastWindow: true },
    expect: false,
  },
  {
    name: "4. same state on a PRE-D2 contract",
    why: "pre-D2's requiredQuorum consults e-1 alone, so an unpinned current epoch never produces the sentinel there; a sentinel on pre-D2 is never benign.",
    state: { ...HEALTHY_D2, isD2: false },
    expect: false,
  },
  {
    name: "5. CC-97 floor unmet",
    why: "a frozen pool below minCommittee can never carry committee security, whatever the pin state.",
    state: { ...HEALTHY_D2, floorOk: false },
    expect: false,
  },
  {
    name: "6. epoch e IS pinned yet the sentinel is on",
    why: "then the sentinel has some other cause and naming it 'pending pin' would misattribute it.",
    state: { ...HEALTHY_D2, pinnedE: true, usableE: true },
    expect: false,
  },
];

let failed = 0;
for (const c of CELLS) {
  const got = isBenignPendingPin(c.state);
  const ok = got === c.expect;
  if (!ok) failed++;
  console.log(`${ok ? "  ok  " : "  FAIL"} ${c.name}`);
  console.log(`       expected benign=${c.expect}, got ${got}`);
  if (!ok) console.log(`       WHY THIS CELL EXISTS: ${c.why}`);
}

// A predicate that returns the same thing for every input would pass any set of same-expectation
// cells. Assert both answers actually occur.
const answers = new Set(CELLS.map(c => isBenignPendingPin(c.state)));
if (answers.size < 2) {
  console.log("  FAIL the predicate returned one answer for every cell -- it is constant, not a classifier");
  failed++;
}

if (failed) {
  console.error(`\nquorum-classify check FAILED (${failed})`);
  process.exit(1);
}
console.log(`\nquorum-classify check OK — ${CELLS.length} cells, both answers observed.`);
