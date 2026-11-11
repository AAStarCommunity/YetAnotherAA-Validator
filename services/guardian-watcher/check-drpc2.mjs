// D-RPC2 self-test (DSR c8a0e5ef, 437b8937): cases C1-C4, each with its negative (the primary answers
// consistently but wrongly; the honest second provider disagrees, so the accusatory record is held)
// and its positive control (both honest: the record is confirmed and may be published). A negative
// first asserts that the crafted primary really produced the wrong accusatory record, so a pass is
// never vacuous.
import { mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ethers } from "ethers";
import {
  AGG,
  SAFE,
  SP,
  FORWARDERS,
  addr,
  makeChain,
  slashF,
} from "../../scripts/disclosure/stub-chain.mjs";
import { Kind, aggIface } from "../../scripts/disclosure/recheck-lib.mjs";
import { spIface } from "./lib/sp-abi.mjs";
import { validateRuleset } from "./lib/rules.mjs";
import { Store } from "./lib/store.mjs";
import { runOnce } from "./watcher.mjs";
import {
  isAccusatory,
  mayPublish,
  confirmPending,
  getHold,
  accusationView,
  CONFIRM_MAX_ATTEMPTS,
  viewDigest,
} from "./lib/confirm.mjs";

const rs = validateRuleset(
  JSON.parse(readFileSync(new URL("./ruleset.json", import.meta.url), "utf8"))
);
const ident = { commit: "0".repeat(40), hash: ethers.id("ruleset"), verified: true };
const results = [];
const j = v => JSON.stringify(v, (k, x) => (typeof x === "bigint" ? x.toString() : x));
const cell = (name, ok, got) => results.push({ name, ok: !!ok, got: ok ? "" : j(got) });
const sel = s => ethers.id(s).slice(0, 10);
const recsOf = d =>
  readdirSync(join(d, "records"))
    .filter(f => f.endsWith(".json"))
    .map(f => JSON.parse(readFileSync(join(d, "records", f), "utf8")));

/** A provider wrapper: `over` replaces chosen methods; everything else is the honest stub. */
const wrap = (chain, over) =>
  new Proxy(chain, {
    get(t, p) {
      if (over[p]) return over[p];
      const v = t[p];
      return typeof v === "function" ? v.bind(t) : v;
    },
  });

/** Scan with the primary, then confirm with the second. Returns what each produced. */
async function scenario(build) {
  const d = mkdtempSync(join(tmpdir(), "drpc2-"));
  try {
    const c = makeChain();
    const cfg = {
      aggregator: AGG,
      roles: { superPaymaster: SP },
      forwarders: FORWARDERS,
      startBlock: c.head() + 1,
      maxBlocksPerTick: 1000,
      page: 5000,
    };
    const { primary, second, target } = await build(c, cfg);
    const store = new Store(d);
    const st = (await runOnce(primary, cfg, store, rs, ident)).status;
    const acc = recsOf(d).filter(isAccusatory);
    const counts = await confirmPending(store, second, "second.example", cfg, rs, ident, {
      runOnce,
    });
    const holds = acc.map(r => getHold(store, Store.recordId(r)));
    return { st, acc, counts, holds, publish: acc.map(r => mayPublish(store, r)), target };
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
}

// ---- positive control (shared shape): an honest owner action, both providers honest -> confirmed
{
  const r = await scenario(async c => {
    const t = c.ownerTx([{ name: "GuardianSet", args: [addr("pc-a"), addr("pc-b")] }]);
    for (let i = 0; i < 4; i++) c.mine();
    return { primary: c.chain, second: c.chain, target: t.hash };
  });
  cell(
    "positive control: an honest owner GuardianSet, both providers honest: one accusatory record, confirmed, may be published",
    r.st.ok &&
      r.acc.length === 1 &&
      r.holds[0]?.state === "confirmed" &&
      r.publish[0] === true &&
      r.holds[0].secondProvider === "second.example" &&
      !JSON.stringify(r.holds[0]).includes("http"),
    r
  );
}

// ---- C2: crafted tx + trace move a keeper's public pauseUnderstakedOperator onto the owner route
{
  const KEEP = addr("c2-keeper");
  const pub = sel("pauseUnderstakedOperator(address)");
  const priv = sel("pauseOperator(address)");
  const build = crafted => async c => {
    const t = c.ownerTx([{ name: "OperatorPaused", args: [addr("c2-op")] }], {
      from: KEEP,
      data: pub,
    });
    for (let i = 0; i < 4; i++) c.mine();
    if (!crafted) return { primary: c.chain, second: c.chain, target: t.hash };
    // a single provider, internally consistent: tx and trace root both say the Safe called a
    // privileged function
    const primary = wrap(c.chain, {
      getTransaction: async h => {
        const tx = await c.chain.getTransaction(h);
        return h === t.hash ? { ...tx, from: SAFE, data: priv } : tx;
      },
      send: async (m, p) => {
        const r = await c.chain.send(m, p);
        return m === "debug_traceTransaction" &&
          p?.[0] === t.hash &&
          !p?.[1]?.tracer?.startsWith?.("prestate")
          ? { ...r, from: SAFE, input: priv }
          : r;
      },
    });
    return { primary, second: c.chain, target: t.hash };
  };
  const neg = await scenario(build(true));
  const pos = await scenario(build(false));
  cell(
    "C2 negative: a crafted primary attributes a keeper's public pause to the owner route (an accusation); the honest second disagrees: held unconfirmed, not publishable",
    neg.acc.length === 1 &&
      neg.acc[0].route === "owner" &&
      neg.holds[0]?.state === "unconfirmed" &&
      neg.holds[0].fields?.length > 0 &&
      neg.publish[0] === false,
    {
      acc: neg.acc.map(r => [r.route, r.caller, r.selector]),
      holds: neg.holds,
      publish: neg.publish,
    }
  );
  cell(
    "C2 positive control: both honest: the pause is public (no accusation), nothing held",
    pos.st.ok && pos.acc.length === 0 && pos.counts.checked === 0,
    { acc: pos.acc.length, counts: pos.counts }
  );
}

// ---- C4: a crafted NESTED frame (root unchanged) names the owner's privileged call
{
  const KEEP = addr("c4-keeper");
  const FWD = addr("c4-forwarder");
  const pub = sel("pauseUnderstakedOperator(address)");
  const priv = sel("pauseOperator(address)");
  const build = crafted => async c => {
    const t = c.ownerTx([{ name: "OperatorPaused", args: [addr("c4-op")] }], {
      from: KEEP,
      to: FWD,
      data: sel("go()"),
      trace: false,
    });
    const rc = await c.chain.getTransactionReceipt(t.hash);
    const inner = (from, input) => ({
      type: "CALL",
      from,
      to: SP,
      input,
      logs: rc.logs.map(l => ({ address: l.address, topics: l.topics, data: l.data, position: 0 })),
    });
    c.setTrace(t.hash, { type: "CALL", calls: [inner(FWD, pub)] });
    for (let i = 0; i < 4; i++) c.mine();
    if (!crafted) return { primary: c.chain, second: c.chain, target: t.hash };
    const primary = wrap(c.chain, {
      send: async (m, p) => {
        const r = await c.chain.send(m, p);
        return m === "debug_traceTransaction" &&
          p?.[0] === t.hash &&
          !p?.[1]?.tracer?.startsWith?.("prestate")
          ? { ...r, calls: [inner(FWD, priv)] }
          : r;
      },
    });
    return { primary, second: c.chain, target: t.hash };
  };
  const neg = await scenario(build(true));
  const pos = await scenario(build(false));
  cell(
    "C4 negative: a crafted nested frame names a privileged selector (root unchanged): an owner-route accusation, held by the honest second",
    neg.acc.length === 1 &&
      neg.acc[0].route === "owner" &&
      neg.holds[0]?.state === "unconfirmed" &&
      neg.publish[0] === false,
    {
      acc: neg.acc.map(r => [r.route, r.caller, r.selector]),
      holds: neg.holds,
      st: neg.st.lastError,
    }
  );
  cell(
    "C4 positive control: both honest: the nested public pause accuses nobody",
    pos.st.ok && pos.acc.length === 0,
    { acc: pos.acc.map(r => [r.route, r.selector]), st: pos.st.lastError }
  );
}

// ---- C3: a log the canonical chain does not have, returned live by the primary with removed: "true"
{
  const build = crafted => async c => {
    const t = c.ownerTx([{ name: "SlashCancelled", args: [addr("c3-op")] }]);
    for (let i = 0; i < 4; i++) c.mine();
    if (!crafted) return { primary: c.chain, second: c.chain, target: t.hash };
    // the primary still serves the tx (a stale backend) and marks its log removed:"true" (a string,
    // not the boolean): treated as live. The honest second knows nothing of it.
    const primary = wrap(c.chain, {
      send: async (m, p) => {
        const r = await c.chain.send(m, p);
        if (m === "eth_getLogs" && Array.isArray(r))
          return r.map(l => (l.transactionHash === t.hash ? { ...l, removed: "true" } : l));
        return r;
      },
    });
    const second = wrap(c.chain, {
      send: async (m, p) => {
        const r = await c.chain.send(m, p);
        return m === "eth_getLogs" && Array.isArray(r)
          ? r.filter(l => l.transactionHash !== t.hash)
          : r;
      },
      getTransactionReceipt: async h => (h === t.hash ? null : c.chain.getTransactionReceipt(h)),
      getTransaction: async h => (h === t.hash ? null : c.chain.getTransaction(h)),
    });
    return { primary, second, target: t.hash };
  };
  const neg = await scenario(build(true));
  const pos = await scenario(build(false));
  cell(
    'C3 negative: a log served live with removed:"true" that the honest second does not have: the accusation is held',
    neg.acc.length === 1 && neg.holds[0]?.state === "unconfirmed" && neg.publish[0] === false,
    { acc: neg.acc.map(r => [r.route, r.event]), holds: neg.holds }
  );
  cell(
    "C3 positive control: the log is live on both: confirmed",
    pos.acc.length === 1 && pos.holds[0]?.state === "confirmed" && pos.publish[0] === true,
    { holds: pos.holds }
  );
}

// ---- C1: within one BLS reconstruction the primary's answers about the signer mask change
{
  const build = crafted => async c => {
    const t = c.execute(Kind.SLASH, 9191n, slashF, 0b011n);
    for (let i = 0; i < 4; i++) c.mine();
    if (!crafted) return { primary: c.chain, second: c.chain, target: t.hash };
    // getLogs (and the first receipt read) report signerMask 0b111; later reads are honest (0b011)
    let receipts = 0;
    const bump = l => {
      if (String(l.address).toLowerCase() !== AGG.toLowerCase()) return l;
      try {
        const dlog = aggIface.parseLog(l);
        if (dlog?.name !== "SignersCommitted") return l;
        return {
          ...l,
          data: aggIface.encodeEventLog("SignersCommitted", [dlog.args[0], 0b111n]).data,
        };
      } catch {
        return l;
      }
    };
    const primary = wrap(c.chain, {
      send: async (m, p) => {
        const r = await c.chain.send(m, p);
        return m === "eth_getLogs" && Array.isArray(r) ? r.map(bump) : r;
      },
      getTransactionReceipt: async h => {
        const rc = await c.chain.getTransactionReceipt(h);
        if (h !== t.hash || !rc) return rc;
        return receipts++ === 0 ? { ...rc, logs: rc.logs.map(bump) } : rc;
      },
    });
    return { primary, second: c.chain, target: t.hash };
  };
  const neg = await scenario(build(true));
  const pos = await scenario(build(false));
  // the scan may refuse the inconsistent answers outright (no accusatory record at all): that is
  // also safe, and is reported as "closed upstream"; when it does produce one, it must be held
  const negOk =
    neg.acc.length === 0 ||
    (neg.holds.every(h => h?.state === "unconfirmed") && neg.publish.every(p => p === false));
  cell(
    `C1 negative: a signer mask that changes within one reconstruction is either refused by the scan or held (${neg.acc.length === 0 ? "closed upstream: no accusatory record" : "held"})`,
    negOk,
    {
      acc: neg.acc.map(r => [r.route, r.kind, r.signerMask]),
      holds: neg.holds,
      st: neg.st.lastError,
    }
  );
  cell(
    "C1 positive control: an honest BLS slash, both providers honest: confirmed",
    pos.acc.length >= 1 &&
      pos.holds.every(h => h?.state === "confirmed") &&
      pos.publish.every(Boolean),
    { acc: pos.acc.map(r => [r.route, r.kind, r.signerMask]), holds: pos.holds }
  );
}

// ---- the cap: a record the second provider can never reproduce ends unconfirmed-final, still unpublishable
{
  const d = mkdtempSync(join(tmpdir(), "drpc2-cap-"));
  try {
    const c = makeChain();
    const cfg = {
      aggregator: AGG,
      roles: { superPaymaster: SP },
      forwarders: FORWARDERS,
      startBlock: c.head() + 1,
      maxBlocksPerTick: 1000,
      page: 5000,
    };
    const t = c.ownerTx([{ name: "SlashCancelled", args: [addr("cap-op")] }]);
    for (let i = 0; i < 4; i++) c.mine();
    const store = new Store(d);
    await runOnce(c.chain, cfg, store, rs, ident);
    const down = wrap(c.chain, {
      getBlock: async () => {
        throw new Error("second provider down");
      },
      send: async () => {
        throw new Error("down");
      },
    });
    let last;
    for (let i = 0; i < CONFIRM_MAX_ATTEMPTS + 2; i++)
      last = await confirmPending(store, down, "second.example", cfg, rs, ident, { runOnce });
    const rec = recsOf(d).find(r => r.txHash === t.hash);
    const h = getHold(store, Store.recordId(rec));
    cell(
      "cap: a second provider that never answers leaves the accusation unconfirmed-final after the cap, never publishable, no further attempts",
      h?.state === "unconfirmed-final" &&
        h.attempts === CONFIRM_MAX_ATTEMPTS &&
        !mayPublish(store, rec) &&
        last.final === 1 &&
        last.checked === 0,
      { h, last }
    );
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
}

// ---- unit: when-fields are ignored, everything else is compared
{
  const a = {
    route: "owner",
    caller: addr("u1"),
    seenAt: "t1",
    lastReasons: ["x"],
    verdict: { flagged: true },
  };
  const b = { ...a, seenAt: "t2", lastReasons: ["y"] };
  const c = { ...a, caller: addr("u2") };
  cell(
    "unit: accusationView ignores when-fields (seenAt, lastReasons…) and keeps everything else",
    accusationView(a) === accusationView(b) && accusationView(a) !== accusationView(c),
    { a: accusationView(a), c: accusationView(c) }
  );
}

// ---- wiring: runOnce with a second provider confirms in the same tick and reports it; without one,
// a production config (requireSecondProvider) is degraded
{
  const d1 = mkdtempSync(join(tmpdir(), "drpc2-wire-"));
  const d2 = mkdtempSync(join(tmpdir(), "drpc2-wire2-"));
  try {
    const c = makeChain();
    const cfg = {
      aggregator: AGG,
      roles: { superPaymaster: SP },
      forwarders: FORWARDERS,
      startBlock: c.head() + 1,
      maxBlocksPerTick: 1000,
      page: 5000,
    };
    const t = c.ownerTx([{ name: "GuardianSet", args: [addr("w-a"), addr("w-b")] }]);
    for (let i = 0; i < 4; i++) c.mine();
    const s1 = new Store(d1);
    const st = (
      await runOnce(c.chain, cfg, s1, rs, ident, {
        second: { chain: c.chain, host: "second.example" },
      })
    ).status;
    const rec = recsOf(d1).find(r => r.txHash === t.hash);
    const st2 = (
      await runOnce(c.chain, { ...cfg, requireSecondProvider: true }, new Store(d2), rs, ident)
    ).status;
    cell(
      "wiring: runOnce confirms the accusatory record in the same tick (status.confirm, holds, mayPublish); a production config without a second provider is degraded",
      st.ok &&
        st.confirm?.confirmed === 1 &&
        st.confirm.secondProvider === "second.example" &&
        mayPublish(s1, rec) &&
        st2.ok &&
        st2.healthy === false &&
        (st2.degraded ?? []).some(x => /no second provider/.test(x)),
      { confirm: st.confirm, degraded2: st2.degraded }
    );
  } finally {
    rmSync(d1, { recursive: true, force: true });
    rmSync(d2, { recursive: true, force: true });
  }
}

// ---- the publisher's gate (lib/publisher.mjs publishPending): held records are never published
{
  const { publishPending } = await import("./lib/publisher.mjs");
  const { bls, owner, sinks } = await import("./mock-sinks.mjs");
  const { atomicWriteJson } = await import("./lib/store.mjs");
  const { mkdirSync } = await import("node:fs");
  const hold = (store, rec, state) => {
    mkdirSync(join(store.dir, "holds"), { recursive: true });
    const id = Store.recordId(rec);
    atomicWriteJson(join(store.dir, "holds", `${id}.json`), {
      id,
      state,
      attempts: 1,
      digest: viewDigest(
        JSON.parse(readFileSync(join(store.dir, "records", `${id}.json`), "utf8"))
      ),
    });
  };
  const run = async (state, rec) => {
    const d = mkdtempSync(join(tmpdir(), "drpc2-pub-"));
    try {
      const store = new Store(d);
      store.putRecord(rec);
      if (state) hold(store, rec, state);
      const s = sinks();
      const sk = { pinners: s.pinners, mirror: s.mirror, telegram: s.telegram, registry: null };
      const r = await publishPending(store, sk);
      return {
        counts: r.counts,
        published: store.getPublication(Store.recordId(rec)),
        uploads: Object.values(s.calls.uploads).reduce((a, b) => a + b, 0),
        telegram: s.calls.telegram,
      };
    } finally {
      rmSync(d, { recursive: true, force: true });
    }
  };
  for (const [label, state] of [
    ["no hold yet", null],
    ["unconfirmed", "unconfirmed"],
    ["unconfirmed-final", "unconfirmed-final"],
  ]) {
    const r = await run(state, bls);
    cell(
      `publisher: an accusatory record with ${label} is held: not pinned, not mirrored, no Telegram, counted`,
      r.counts.held === 1 &&
        r.counts.ran === 0 &&
        !r.published &&
        r.uploads === 0 &&
        r.telegram === 0,
      r
    );
  }
  const ok = await run("confirmed", owner);
  cell(
    "publisher: a confirmed accusatory record is published",
    ok.counts.held === 0 && ok.published?.published === true && ok.uploads > 0,
    ok
  );
  // an unreadable hold file is not a confirmation
  const d = mkdtempSync(join(tmpdir(), "drpc2-pub-"));
  try {
    const store = new Store(d);
    store.putRecord(bls);
    const { writeFileSync } = await import("node:fs");
    mkdirSync(join(d, "holds"), { recursive: true });
    writeFileSync(join(d, "holds", `${Store.recordId(bls)}.json`), "{not json");
    const s = sinks();
    const r = await publishPending(store, {
      pinners: s.pinners,
      mirror: s.mirror,
      telegram: s.telegram,
      registry: null,
    });
    cell(
      "publisher: an unreadable hold is not a confirmation (held)",
      r.counts.held === 1 && r.counts.ran === 0,
      r.counts
    );
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
}

// ---- D-RPC2 Codex R1: digest binding, alias files, malformed records, exhaustion replays
{
  const { bls, owner } = await import("./mock-sinks.mjs");
  const { writeFileSync, mkdirSync } = await import("node:fs");
  const stored = (store, rec) =>
    JSON.parse(readFileSync(join(store.dir, "records", `${Store.recordId(rec)}.json`), "utf8"));
  // a fake second-provider tick: `script(i, temp)` decides what the i-th tick leaves in the temp store
  const fakeRun = script => {
    let i = 0;
    const f = async (second, c, temp) => {
      script(i++, temp);
      return { status: { ok: true, cursor: c.startBlock } };
    };
    f.calls = () => i;
    return f;
  };
  // #1: a confirmation is bound to the content it was made on
  {
    const d = mkdtempSync(join(tmpdir(), "drpc2-r1-"));
    try {
      const store = new Store(d);
      store.putRecord(bls);
      const honest = stored(store, bls);
      mkdirSync(join(d, "holds"), { recursive: true });
      const id = Store.recordId(bls);
      const { atomicWriteJson } = await import("./lib/store.mjs");
      atomicWriteJson(join(d, "holds", `${id}.json`), {
        id,
        state: "confirmed",
        digest: viewDigest(honest),
      });
      const fabricated = { ...honest, caller: "0x000000000000000000000000000000000000bad1" };
      writeFileSync(join(d, "records", `${id}.json`), JSON.stringify(fabricated));
      cell(
        "R1#1: a confirmed hold for other content under the same id does not authorize this record",
        mayPublish(store, honest) === true && mayPublish(store, fabricated) === false,
        { honest: mayPublish(store, honest), fabricated: mayPublish(store, fabricated) }
      );
      // an alias file (same identity, another name) is never confirmed
      writeFileSync(join(d, "records", "alias.json"), JSON.stringify(honest));
      const run = fakeRun((i, temp) => temp.putRecord(bls));
      const c = await confirmPending(store, {}, "second.example", { startBlock: 0 }, null, null, {
        runOnce: run,
      });
      cell(
        "R1#1: an alias record file is skipped (malformed), never confirmed",
        (c.malformed ?? 0) >= 1,
        c
      );
    } finally {
      rmSync(d, { recursive: true, force: true });
    }
  }
  // #2: one malformed record does not stop the pass
  {
    const d = mkdtempSync(join(tmpdir(), "drpc2-r1-"));
    try {
      const store = new Store(d);
      mkdirSync(join(d, "records"), { recursive: true });
      writeFileSync(
        join(d, "records", "aaa-broken.json"),
        JSON.stringify({ ...bls, key: "invalid" })
      );
      store.putRecord(owner);
      const run = fakeRun((i, temp) => temp.putRecord(owner));
      const c = await confirmPending(store, {}, "second.example", { startBlock: 0 }, null, null, {
        runOnce: run,
      });
      cell(
        "R1#2: a malformed accusatory record is isolated; the honest one after it is confirmed",
        (c.malformed ?? 0) >= 1 && getHold(store, Store.recordId(owner))?.state === "confirmed",
        { counts: c, hold: getHold(store, Store.recordId(owner)) }
      );
    } finally {
      rmSync(d, { recursive: true, force: true });
    }
  }
  // #3: a record produced by exhaustion is reproduced by replaying the attempt budget
  {
    const d = mkdtempSync(join(tmpdir(), "drpc2-r1-"));
    try {
      const store = new Store(d);
      store.putRecord(owner);
      const { MAX_DEADLETTER_ATTEMPTS } = await import("./lib/scan.mjs");
      const run = fakeRun((i, temp) => {
        if (i < MAX_DEADLETTER_ATTEMPTS)
          temp.putDeadLetter({
            route: "tx",
            txHash: owner.txHash,
            blockNumber: owner.blockNumber,
            attempts: i + 1,
            reasons: ["price"],
          });
        else temp.putRecord(owner);
      });
      const c = await confirmPending(store, {}, "second.example", { startBlock: 0 }, null, null, {
        runOnce: run,
      });
      cell(
        "R1#3: a dead letter on the second provider is retried up to the attempt budget, then the record confirms",
        getHold(store, Store.recordId(owner))?.state === "confirmed" &&
          run.calls() === MAX_DEADLETTER_ATTEMPTS + 1,
        { counts: c, calls: run.calls(), hold: getHold(store, Store.recordId(owner)) }
      );
    } finally {
      rmSync(d, { recursive: true, force: true });
    }
  }
}

let failed = 0;
for (const r of results) {
  console.log(
    `${r.ok ? "ok  " : "FAIL"} ${r.name}${r.ok ? "" : `\n     got ${r.got.slice(0, 1500)}`}`
  );
  if (!r.ok) failed++;
}
console.log(`\n${results.length - failed}/${results.length} cells`);
process.exit(failed ? 1 : 0);
