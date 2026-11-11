// Self-test of the external heartbeat (heartbeat.mjs): every rule, with the clock, the status file
// and the sender injected. Run: node deploy/guardian-watcher/check-heartbeat.mjs
import { check } from "./heartbeat.mjs";

const results = [];
const cell = (name, ok, got) =>
  results.push({ name, ok: !!ok, got: ok ? "" : JSON.stringify(got) });
const cfg = {
  dataDir: "/data",
  intervalMs: 60_000,
  maxLagBlocks: 300,
  heartbeat: { label: "mini" },
};

/** A run of checks over a scripted status file and clock; returns the messages and states. */
async function run(steps, { failSend = false, failState = false } = {}) {
  let state = null;
  const sent = [];
  const out = [];
  for (const s of steps) {
    const r = await check({
      cfg,
      now: s.now,
      readStatus: () => {
        if (s.status === undefined) throw new Error("ENOENT");
        return JSON.stringify(s.status);
      },
      statMtime: () => s.mtime ?? s.now,
      send: async t => {
        sent.push(t);
        return !failSend;
      },
      readState: () => state,
      writeState: x => {
        if (failState) return false;
        state = x;
        return true;
      },
    });
    out.push(r);
  }
  return { sent, out, state };
}
const ok = (at, extra = {}) => ({
  at: new Date(at).toISOString(),
  healthy: true,
  lagBlocks: 2,
  ...extra,
});
const T = 10_000_000;

{
  // the kill drill: fresh, then the watcher dies (status stops changing), then it comes back
  const r = await run([
    { now: T, status: ok(T) },
    { now: T + 300_000, status: ok(T), mtime: T }, // 5 min old > 3 x 60 s: stale
    { now: T + 600_000, status: ok(T), mtime: T }, // still stale: no repeat within realert
    { now: T + 900_000, status: ok(T + 890_000) }, // fresh again
  ]);
  cell(
    "kill drill: a status that stops changing alerts once (watcher not running or stuck), no repeat within the hour, then one RECOVERED",
    r.sent.length === 2 &&
      /not running or stuck: status\.json is 5 min old/.test(r.sent[0]) &&
      /RECOVERED/.test(r.sent[1]) &&
      r.out[2].sent === null &&
      r.state.alerting === null,
    r
  );
}
{
  const r = await run([{ now: T, status: undefined }]);
  cell(
    "no readable status.json at all: alerted as not running",
    r.sent.length === 1 && /no readable status\.json/.test(r.sent[0]),
    r
  );
}
{
  const r = await run([
    { now: T, status: ok(T, { lagBlocks: 400 }) },
    { now: T + 3_700_000, status: ok(T + 3_700_000, { lagBlocks: 500 }) }, // past the hour: repeated
  ]);
  cell(
    "lag past maxLagBlocks alerts, and repeats after the realert interval",
    r.sent.length === 2 &&
      /cursor 400 blocks behind finalized \(> 300\)/.test(r.sent[0]) &&
      /cursor 500/.test(r.sent[1]),
    r
  );
}
{
  const bad = at =>
    ok(at, {
      healthy: false,
      degraded: ["isolation budget reached this tick (the rest is read next tick)"],
    });
  const r = await run([
    { now: T, status: bad(T) },
    { now: T + 60_000, status: bad(T + 60_000) },
  ]);
  cell(
    "healthy:false alerts only after two checks in a row, with the watcher's own reasons",
    r.out[0].sent === null &&
      r.sent.length === 1 &&
      /degraded for 2 checks: isolation budget reached/.test(r.sent[0]),
    r
  );
}
{
  const r = await run([{ now: T, status: ok(T, { lagBlocks: 400 }) }], { failSend: true });
  cell(
    "a failed send is not recorded as sent: the next check tries again",
    r.state.alerting === null && r.state.lastSentAt === 0,
    r
  );
}
{
  const r = await run([{ now: T, status: ok(T) }], { failState: true });
  cell(
    "state that cannot be written is itself alerted (it would otherwise mute the rules)",
    r.out[0].stateWritten === false && r.sent.some(t => /cannot write its state/.test(t)),
    r
  );
}
{
  const r = await run([
    {
      now: T,
      status: ok(T, { lagBlocks: 400, rpcUrl: "https://x/SECRETKEY", lastError: "SECRETKEY" }),
    },
  ]);
  cell(
    "only fixed wording is sent: nothing else from status.json",
    r.sent.length === 1 && !r.sent[0].includes("SECRETKEY"),
    r
  );
}

let failed = 0;
for (const r of results) {
  console.log(
    `${r.ok ? "ok  " : "FAIL"} ${r.name}${r.ok ? "" : `\n     got ${r.got.slice(0, 800)}`}`
  );
  if (!r.ok) failed++;
}
console.log(`\n${results.length - failed}/${results.length} cells`);
process.exit(failed ? 1 : 0);
