// How often does the committee keeper MISS an epoch, and how much availability does that cost?
//
// WHY THIS EXISTS
//
// `deploy/committee-health.mjs` answers "is it broken right now". It reads `epochPinned(e)` and
// `epochPinned(e-1)` and nothing else — by design, and correctly, because that is what an alert
// needs. But it means nothing in this repo can answer "how often does this happen", and the two
// questions have different answers:
//
//   * a single missed epoch and an eight-hour outage produce the SAME reading from the health check
//     — `e` pinned, `e-1` not — because the visible shape only appears once the keeper resumes;
//   * a downstream consumer sees only `e-1`, so a RUN of missed epochs looks to them like one miss.
//
// Both of those actually happened, two days apart, and each time the real number was recovered by
// someone hand-writing a one-off log scan and then deleting it. On 2026-09-02 a consumer repo
// reasoned from an 8.0-hour gap between two alerts to "~34 epochs missed"; the measured answer was
// ONE. The interval between two events and the duration of one event are indistinguishable from a
// point-in-time monitor, and an estimate built on that confusion is off by an order of magnitude.
//
// So this reconstructs the record from chain events, which is the only place the history actually
// lives, and prints the quantities that were previously produced by hand.
//
// WHAT IT REPORTS
//
//   missed epochs, grouped into RUNS  — a run of k consecutive misses fail-closes k+1 epochs,
//                                       because validate()/requiredQuorum() need BOTH e and e-1
//                                       usable. Verified against three real runs (k=1,2,1).
//   pin latency distribution          — offset in blocks from each epoch's start
//   steady-state unavailability       — mean pin latency / epochLength. Committee ops fail closed
//                                       between an epoch starting and its pin landing, EVERY epoch.
//                                       This is structural, not a defect: a pin cannot precede the
//                                       epoch it snapshots, so 1/epochLength is the hard floor.
//   total unavailability              — the two combined.
//
// Usage:
//   node scripts/check-pin-rate.mjs                  (last ~5000 blocks)
//   node scripts/check-pin-rate.mjs --blocks 20000
//   node scripts/check-pin-rate.mjs --max-missed 0   (exit 1 if ANY epoch was missed — for a gate)
//   node scripts/check-pin-rate.mjs --json           (machine-readable, for appending to a record)
//
// A NOTE ON RETENTION. This reads `eth_getLogs`, so it can only see as far back as the endpoint
// keeps logs. Every run therefore appends its findings to deploy/.run/pin-rate-history.jsonl, so the
// record outlives the endpoint's retention. Running it occasionally is what makes the long-run
// frequency knowable at all; a single run tells you about one window and should be read that way.
import { ethers } from "ethers";
import { readFileSync, appendFileSync, mkdirSync } from "fs";
import { dirname, resolve } from "path";
import { fileURLToPath } from "url";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, "..");
const argv = process.argv.slice(2);
const flag = n => {
  const i = argv.indexOf(n);
  return i === -1 ? undefined : argv[i + 1];
};
const JSON_OUT = argv.includes("--json");
const BLOCKS = Number(flag("--blocks") || 5000);
const MAX_MISSED = flag("--max-missed") === undefined ? null : Number(flag("--max-missed"));

const strip = s => s.replace(/^["']|["']$/g, "");
let env = {};
try {
  env = Object.fromEntries(
    readFileSync(resolve(REPO, ".env.sepolia"), "utf8")
      .split("\n")
      .filter(l => l.includes("=") && !l.trim().startsWith("#"))
      .map(l => {
        const i = l.indexOf("=");
        return [l.slice(0, i).trim(), strip(l.slice(i + 1).trim())];
      })
  );
} catch {
  /* the environment may supply everything */
}
const pick = (...n) => n.map(k => process.env[k] || env[k]).find(Boolean);
const RPC = pick("SEPOLIA_RPC_URL", "ETH_RPC_URL", "RPC_URL");
const die = m => {
  console.error(`\n✗ ${m}`);
  process.exit(1);
};
if (!RPC) die("no RPC url (SEPOLIA_RPC_URL / ETH_RPC_URL / RPC_URL)");

const provider = new ethers.JsonRpcProvider(RPC);

// Same resolution rule as the keeper, proofgen and health check: EXPLICIT > router algId 0x01 >
// fail. Never a hard-coded validator — see scripts/check-validator-precedence.mjs.
const ROUTER = pick("COMMITTEE_ROUTER") || "0xA97A752779ebfDA58612F6727Ec7C8366c39f897";
let VALIDATOR = pick("COMMITTEE_VALIDATOR") || flag("--validator");
if (!VALIDATOR) {
  const r = new ethers.Contract(
    ROUTER,
    ["function getAlgorithm(uint8) view returns (address)"],
    provider
  );
  VALIDATOR = await r.getAlgorithm(1);
  if (VALIDATOR === ethers.ZeroAddress) die(`router ${ROUTER} mounts nothing at algId 0x01`);
}

const V = new ethers.Contract(
  VALIDATOR,
  [
    "function epochLength() view returns (uint256)",
    "event EpochSnapshotted(uint256 indexed epoch, bytes32 seed, bytes32 setRoot, uint256 setCount)",
  ],
  provider
);

const head = await provider.getBlockNumber();
const L = Number(await V.epochLength());
if (L === 0) die("epochLength == 0 — committee mode is off on this validator, nothing to measure");

// Never judge epochs from before the contract EXISTED. Without this the window silently extends past
// the deployment and every pre-deploy epoch counts as "missed", because there is no pin event for a
// contract that is not there yet. Caught the hour this tool shipped: `--blocks 30000` reported a run
// of k=273 and "63.4% unavailable", which is not a measurement of anything — most of that range
// predates the validator. An availability tool that inflates its own headline number on a wider
// window is worse than no tool.
let deployBlock = 0;
{
  let lo = 0,
    hi = head;
  if ((await provider.getCode(VALIDATOR, hi)) === "0x") die(`${VALIDATOR} has no code at head`);
  while (lo < hi) {
    const mid = Math.floor((lo + hi) / 2);
    if ((await provider.getCode(VALIDATOR, mid)) === "0x") lo = mid + 1;
    else hi = mid;
  }
  deployBlock = lo;
}
const requested = Math.max(0, head - BLOCKS);
const from = Math.max(requested, deployBlock);
const clampedToDeploy = from > requested;

// Chunked, because endpoints cap eth_getLogs by result count or block span. A chunk that FAILS is
// recorded rather than swallowed: a scan with holes would under-report misses, which is the one
// direction this tool must never fail in — it would report a healthier keeper than reality.
const CHUNK = 2000;
const events = [];
const chunkFailures = [];
for (let f = from; f <= head; f += CHUNK + 1) {
  const t = Math.min(f + CHUNK, head);
  try {
    events.push(...(await V.queryFilter(V.filters.EpochSnapshotted(), f, t)));
  } catch (e) {
    chunkFailures.push({ from: f, to: t, error: (e.shortMessage || e.code || "").slice(0, 80) });
  }
}
if (chunkFailures.length) {
  console.error(`\n✗ ${chunkFailures.length} log chunk(s) failed — the scan has HOLES, so any`);
  console.error(`  "missed epochs" count below would be an undercount. Refusing to report.`);
  for (const c of chunkFailures) console.error(`    blocks ${c.from}-${c.to}: ${c.error}`);
  process.exit(1);
}

const pinBlock = new Map();
for (const ev of events) {
  const e = Number(ev.args.epoch);
  // First pin wins: a re-pin after a reconfiguration is a different event, and the FIRST is the one
  // that decides how long the epoch was unusable.
  if (!pinBlock.has(e)) pinBlock.set(e, ev.blockNumber);
}

// Only whole epochs inside the scanned range can be judged. The partial epoch at each end would
// otherwise read as "missed" purely because the window cut it — an artifact that would inflate
// exactly the number this tool exists to measure.
const eFirst = Math.ceil(from / L);
const eLast = Math.floor(head / L) - 1; // the current epoch may legitimately not be pinned YET
let span = eLast - eFirst + 1;
if (span < 2) die(`window too small: only ${span} whole epoch(s). Use --blocks to widen it.`);

// A scan that found nothing is far more likely to be a broken scan than a keeper that never ran.
// Without this, a silently empty result reads as "every epoch missed" — maximum alarm from zero
// evidence.
if (pinBlock.size === 0) {
  die(
    `no EpochSnapshotted events at all in ${BLOCKS} blocks. That is not a measurement of a stopped ` +
      `keeper — it is far more likely this endpoint does not retain logs that far back, or the ` +
      `validator is wrong (${VALIDATOR}). Narrow --blocks and retry before believing it.`
  );
}

const missedAll = [];
for (let e = eFirst; e <= eLast; e++) if (!pinBlock.has(e)) missedAll.push(e);

// A run of misses that starts at the very FIRST epoch of the window is not attributable. It is
// indistinguishable from "committee mode was not enabled yet" or "no keeper had been started yet" —
// both of which mean there was nothing to be unavailable. Cut it out of the arithmetic and say so,
// rather than charging the keeper for a period in which it did not yet exist.
let leadingUnattributable = null;
const missed = [...missedAll];
if (missed.length && missed[0] === eFirst) {
  let end = eFirst;
  while (missed.includes(end + 1)) end++;
  leadingUnattributable = { from: eFirst, to: end, k: end - eFirst + 1 };
  missed.splice(0, leadingUnattributable.k);
}
// Everything after the leading run is judged against the epochs that were actually measurable.
const measuredFirst = leadingUnattributable ? leadingUnattributable.to + 1 : eFirst;
// Everything below is computed over the MEASURABLE span only.
span = eLast - measuredFirst + 1;
if (span < 2)
  die(
    `after excluding the unattributable leading run (epochs ${leadingUnattributable?.from}-${leadingUnattributable?.to}), ` +
      `only ${span} whole epoch(s) remain. Widen --blocks, or the keeper simply has no measurable history here.`
  );

// Group into runs: k consecutive misses fail-close k+1 epochs (the run, plus the epoch after it,
// which still needs its e-1).
const runs = [];
for (const m of missed) {
  const last = runs[runs.length - 1];
  if (last && m === last.to + 1) last.to = m;
  else runs.push({ from: m, to: m });
}
const failClosedEpochs = runs.reduce((a, r) => a + (r.to - r.from + 1) + 1, 0);

// Pin latency over every epoch that WAS pinned — INCLUDING the late recovery pin after a run of
// misses. An earlier version excluded those as outliers, which is right for "what is the typical
// delay" and wrong for the headline number: a pin landing 60 blocks into a 64-block epoch means that
// epoch really was fail-closed for 60/64 of its length. Excluding it biases the availability figure
// optimistically, and in the one direction this tool must not be wrong. The MEDIAN below is the
// outlier-robust "typical" reading; the MEAN is what a fraction-of-wall-clock number requires.
const offsets = [];
for (const [e, blk] of pinBlock) {
  if (e < measuredFirst || e > eLast) continue;
  offsets.push(blk - e * L);
}
offsets.sort((a, b) => a - b);
const mean = offsets.reduce((a, b) => a + b, 0) / (offsets.length || 1);
const median = offsets.length ? offsets[Math.floor(offsets.length / 2)] : 0;

const missPct = (failClosedEpochs / span) * 100;
const steadyPct = (mean / L) * 100;
const floorPct = (1 / L) * 100;
// The two are disjoint: an epoch that is fail-closed outright contributes no steady-state window.
const totalPct = missPct + ((100 - missPct) / 100) * steadyPct;

const blockOf = async n => (await provider.getBlock(n)).timestamp;
const t0 = await blockOf(measuredFirst * L);
const t1 = await blockOf(Math.min((eLast + 1) * L, head));
const hours = (t1 - t0) / 3600;

const record = {
  at: new Date().toISOString(),
  validator: VALIDATOR,
  epochLength: L,
  blocks: { from, to: head },
  epochs: { first: measuredFirst, last: eLast, span },
  deployBlock,
  clampedToDeploy,
  leadingUnattributable,
  hours: Number(hours.toFixed(2)),
  missedEpochs: missed,
  runs: runs.map(r => ({ from: r.from, to: r.to, k: r.to - r.from + 1 })),
  failClosedEpochs,
  pinLatency: {
    n: offsets.length,
    min: offsets[0] ?? null,
    median,
    mean: Number(mean.toFixed(2)),
    max: offsets[offsets.length - 1] ?? null,
  },
  pct: {
    missed: Number(missPct.toFixed(2)),
    steadyState: Number(steadyPct.toFixed(2)),
    total: Number(totalPct.toFixed(2)),
    structuralFloor: Number(floorPct.toFixed(2)),
  },
};

try {
  mkdirSync(resolve(REPO, "deploy/.run"), { recursive: true });
  appendFileSync(
    resolve(REPO, "deploy/.run/pin-rate-history.jsonl"),
    JSON.stringify(record) + "\n"
  );
} catch (e) {
  console.error(`(could not append to the history file: ${e.message})`);
}

if (JSON_OUT) {
  console.log(JSON.stringify(record, null, 2));
} else {
  const loc = ts => new Date((ts + 7 * 3600) * 1000).toISOString().slice(0, 19).replace("T", " ");
  console.log(`validator ${VALIDATOR}  epochLength ${L}`);
  console.log(
    `window    epoch ${measuredFirst}–${eLast} (${span} whole epochs, ${hours.toFixed(1)}h)  ` +
      `blocks ${from}–${head}`
  );
  if (clampedToDeploy)
    console.log(
      `          (clamped to the validator's deploy block ${deployBlock} — earlier epochs did not exist)`
    );
  if (leadingUnattributable)
    console.log(
      `          (EXCLUDED epochs ${leadingUnattributable.from}–${leadingUnattributable.to}, k=${leadingUnattributable.k}: ` +
        `a miss run starting at the window edge cannot be told apart from "committee not enabled yet")`
    );
  console.log(`          ${loc(t0)} → ${loc(t1)} +07\n`);

  if (!runs.length) {
    console.log("missed    none — every whole epoch in this window was pinned");
  } else {
    console.log(`missed    ${missed.length} epoch(s) in ${runs.length} run(s):`);
    for (const r of runs) {
      const k = r.to - r.from + 1;
      const label = r.from === r.to ? `${r.from}` : `${r.from}–${r.to}`;
      console.log(`            ${label}  k=${k}  ⇒ ${k + 1} epochs fail-closed`);
    }
  }

  const hist = {};
  for (const o of offsets) hist[o] = (hist[o] || 0) + 1;
  console.log(
    `\npin delay  min ${offsets[0]}  median ${median}  mean ${mean.toFixed(2)}  max ${offsets[offsets.length - 1]}  (blocks after epoch start)`
  );
  console.log(
    `           ${Object.entries(hist)
      .sort((a, b) => a[0] - b[0])
      .map(([k, v]) => `${k}:${v}`)
      .join("  ")}`
  );

  console.log(`\nunavailability of committee validate() in this window`);
  console.log(`  missed epochs      ${missPct.toFixed(1)}%   (${failClosedEpochs}/${span})`);
  console.log(
    `  steady state       ${steadyPct.toFixed(1)}%   (mean pin delay ${mean.toFixed(2)}/${L} blocks)`
  );
  console.log(`  TOTAL              ${totalPct.toFixed(1)}%`);
  console.log(
    `  structural floor   ${floorPct.toFixed(1)}%   (a pin cannot precede the epoch it snapshots)`
  );
  console.log(
    `\nOne window is not a rate. This appended to deploy/.run/pin-rate-history.jsonl (${record.at});` +
      `\nthe long-run frequency comes from accumulating those, not from any single run.`
  );
}

if (MAX_MISSED !== null && missed.length > MAX_MISSED) {
  console.error(`\n✗ ${missed.length} missed epoch(s) exceeds --max-missed ${MAX_MISSED}`);
  process.exit(1);
}
