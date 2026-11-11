// CI self-test for W2c: the publication loop (lib/publisher.mjs), sink construction from config
// (lib/sinks-config.mjs) and the store's publication journal, against the shared mock sinks.
import { execFileSync } from "node:child_process";
import {
  chmodSync,
  mkdtempSync,
  mkdirSync,
  renameSync,
  rmSync,
  writeFileSync,
  readdirSync,
  readFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { ethers } from "ethers";
import { Store as BaseStore, atomicWriteJson } from "./lib/store.mjs";
import { viewDigest } from "./lib/confirm.mjs";
// These cells test publication itself, not D-RPC2 (check-drpc2.mjs does): every record stored here
// is also marked confirmed by the second provider, as a confirmed hold, so publishPending's D-RPC2
// gate (lib/confirm.mjs mayPublish) lets it through.
class Store extends BaseStore {
  putRecord(rec) {
    const r = super.putRecord(rec);
    const id = BaseStore.recordId(rec);
    mkdirSync(join(this.dir, "holds"), { recursive: true });
    atomicWriteJson(join(this.dir, "holds", `${id}.json`), {
      id,
      state: "confirmed",
      attempts: 1,
      // the digest of the content as stored (the file), as confirmPending computes it
      digest: viewDigest(JSON.parse(readFileSync(join(this.dir, "records", `${id}.json`), "utf8"))),
    });
    return r;
  }
}
import {
  publishPending,
  publishPhase,
  deliverAlerts,
  readRoles,
  currentRoles,
  isDone,
} from "./lib/publisher.mjs";
import { publishConfig, buildSinks } from "./lib/sinks-config.mjs";
import { runOnce, onceExitCode } from "./watcher.mjs";
import { bls, owner, sinks } from "./mock-sinks.mjs";
import { createServer } from "node:http";
import { pinataPinner } from "./sinks/pinata.mjs";
import { filebasePinner } from "./sinks/filebase.mjs";
import { telegramSink } from "./sinks/telegram.mjs";
import { gitMirror } from "./sinks/git-mirror.mjs";
import { cidV1Raw } from "./lib/cid.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const results = [];
const j = v => JSON.stringify(v, (_, x) => (typeof x === "bigint" ? x.toString() : x));
const cell = (name, ok, got) => results.push({ name, ok: !!ok, got: ok ? "" : j(got) });
const tmp = () => mkdtempSync(join(tmpdir(), "loop-"));

// A chain runner answering the aggregator's role views (owner, MAX_VALIDATORS, validatorAtSlot).
const roleIface = new ethers.Interface([
  "function owner() view returns (address)",
  "function MAX_VALIDATORS() view returns (uint256)",
  "function validatorAtSlot(uint8) view returns (address)",
]);
function roleChain(state) {
  return {
    async call(tx) {
      state.calls = (state.calls ?? 0) + 1;
      state.tags = [...(state.tags ?? []), tx.blockTag];
      if (state.fail || state.failTags?.includes(tx.blockTag))
        throw Object.assign(new Error("https://rpc/ROLESECRET"), { code: "SERVER_ERROR" });
      const d = roleIface.parseTransaction({ data: tx.data });
      const st = state.byTag?.[tx.blockTag] ?? state;
      if (d.name === "owner") return roleIface.encodeFunctionResult("owner", [st.owner]);
      if (d.name === "MAX_VALIDATORS")
        return roleIface.encodeFunctionResult("MAX_VALIDATORS", [st.max]);
      const slot = Number(d.args[0]);
      return roleIface.encodeFunctionResult("validatorAtSlot", [
        st.slots[slot] ?? ethers.ZeroAddress,
      ]);
    },
  };
}

const AGG = ethers.getAddress("0x" + "a9".repeat(20));
const DEPLOYER = ethers.getAddress("0x" + "de".repeat(20));
const writer = ethers.Wallet.createRandom();
const G1 = ethers.getAddress("0x" + "61".repeat(20));
const G2 = ethers.getAddress("0x" + "62".repeat(20));
const P = {
  registry: { deployer: DEPLOYER },
  maxPendingMs: 30 * 60_000,
  reverifyEveryMs: 7 * 24 * 3_600_000,
  alertRepeatMs: 3_600_000,
};
const cfg = { aggregator: AGG };

// ---- readRoles: on-chain, at the finalized block, fail closed
{
  const st = {
    owner: ethers.getAddress("0x" + "5a".repeat(20)),
    max: 13,
    slots: { 1: G1, 13: G2 },
  };
  const r = await readRoles(roleChain(st), AGG, DEPLOYER);
  cell(
    "readRoles: owner and every non-empty slot 1..MAX (incl. the last), read at 'finalized'",
    r.aggregatorOwner === st.owner &&
      j(r.guardians) === j([G1, G2]) &&
      r.deployer === DEPLOYER &&
      st.calls === 15 &&
      st.tags.every(t => t === "finalized"),
    { r, calls: st.calls, tags: st.tags?.slice(0, 3) }
  );
  let e = null;
  try {
    await readRoles(roleChain({ ...st, fail: true }), AGG, DEPLOYER);
  } catch (x) {
    e = x.message;
  }
  cell(
    "readRoles: an unreadable set is an error (category only, no RPC text)",
    e === "role read: SERVER_ERROR",
    e
  );
  let e2 = null;
  try {
    await readRoles(roleChain({ ...st, max: 0 }), AGG, DEPLOYER);
  } catch (x) {
    e2 = x.message;
  }
  cell("readRoles: MAX_VALIDATORS out of range is refused", /out of range/.test(e2 ?? ""), e2);
}

// ---- currentRoles (Codex W2c R1 H2): latest required, pending added when served, union refused
{
  const O = ethers.getAddress("0x" + "5a".repeat(20));
  const O2 = ethers.getAddress("0x" + "5b".repeat(20));
  const base = { owner: O, max: 3, slots: { 1: G1 } };
  const both = {
    ...base,
    byTag: { pending: { owner: O2, max: 3, slots: { 1: G1, 2: writer.address } } },
  };
  const u = await currentRoles(roleChain(both), AGG, DEPLOYER);
  const noPend = await currentRoles(roleChain({ ...base, failTags: ["pending"] }), AGG, DEPLOYER);
  let latestFail = null;
  try {
    await currentRoles(roleChain({ ...base, failTags: ["latest"] }), AGG, DEPLOYER);
  } catch (e) {
    latestFail = e.message;
  }
  cell(
    "currentRoles: a guardian or owner at pending is refused with latest's; no pending = latest; no latest = refusal",
    u.guardians.includes(writer.address) &&
      u.guardians.includes(O2) &&
      u.aggregatorOwner === O &&
      j(noPend.guardians) === j([G1]) &&
      typeof latestFail === "string" &&
      !/ROLESECRET/.test(latestFail),
    { u, noPend, latestFail }
  );
}

// ---- publishPhase end to end: two flagged records and one unflagged, through to done
{
  const d = tmp();
  try {
    const store = new Store(d);
    store.putRecord(bls);
    store.putRecord(owner);
    store.putRecord({
      ...owner,
      txHash: ethers.id("quiet"),
      verdict: { flagged: false, reasons: [] },
    });
    const s = sinks();
    const roles = {
      owner: ethers.getAddress("0x" + "5a".repeat(20)),
      max: 3,
      slots: { 1: G1, 2: G2 },
    };
    const built = {
      pinners: s.pinners,
      mirror: s.mirror,
      telegram: s.telegram,
      wallet: writer,
      registryFor: (r, cur) => {
        gotCurrent = cur;
        return s.registry;
      },
    };
    let gotCurrent = null;
    let now = 1_000_000;
    const runs = [];
    for (let i = 0; i < 4; i++)
      runs.push(
        await publishPhase(store, roleChain(roles), cfg, P, built, { now: (now += 60_000) })
      );
    const ids = store.listRecords().map(r => r.id);
    const quietId = ids.find(x => x.includes(ethers.id("quiet").slice(2, 10)));
    const blsSt = store.getPublication(Store.recordId(bls));
    const ownSt = store.getPublication(Store.recordId(owner));
    cell(
      "publishPhase: flagged records reach done across passes (BLS confirmed, owner route published), journalled",
      isDone(bls, blsSt) &&
        isDone(owner, ownSt) &&
        blsSt.registry.phase === "confirmed" &&
        runs.at(-1).done === 2 &&
        runs.at(-1).ok === true,
      { last: runs.at(-1), bls: blsSt?.registry?.phase }
    );
    const cur = typeof gotCurrent === "function" ? await gotCurrent() : null;
    cell(
      "publishPhase hands the registry sink a sign-time role reader (latest state)",
      cur?.guardians.includes(G1) && cur.guardians.includes(G2) && roles.tags.includes("latest"),
      { cur, tags: roles.tags }
    );
    cell(
      "publishPhase: an unflagged record is never published (no journal)",
      quietId && store.getPublication(quietId) === null && runs.every(r => r.flagged === 2),
      { quietId, runs: runs.map(r => r.flagged) }
    );
    const before = { ...s.calls };
    const again = await publishPhase(store, roleChain(roles), cfg, P, built, {
      now: (now += 60_000),
    });
    cell(
      "publishPhase: done records are skipped (no upload, sign or message) until the weekly reverify",
      again.ran === 0 &&
        again.reverified === false &&
        s.calls.sign === before.sign &&
        s.calls.telegram === before.telegram,
      { again, before, after: s.calls }
    );
    // A degraded watcher (here: lag past maxLagBlocks) is alerted through the same channel (W2c)
    const tgBefore = s.calls.telegram;
    const deg = await publishPhase(store, roleChain(roles), cfg, P, built, {
      now: (now += 60_000),
      degraded: ["cursor 400 blocks behind finalized (> 300)"],
    });
    const latest = JSON.parse(readFileSync(join(store.dir, "alerts-latest.json"), "utf8"));
    cell(
      "publishPhase: a degraded watcher (lag) is alerted: 'watcher degraded: …' in the alert list, delivered to Telegram",
      deg.alerts >= 1 &&
        latest.alerts.some(
          x => x === "watcher degraded: cursor 400 blocks behind finalized (> 300)"
        ) &&
        s.calls.telegram > tgBefore,
      { alerts: latest.alerts, tg: [tgBefore, s.calls.telegram], delivery: deg.delivery }
    );
    // A pin that was valid is gone by the weekly pass: the reverify must read it and repair it.
    s.pinOpts.pinata.gone = true;
    const fetchesBefore = s.calls.fetches ?? 0;
    const pinataBefore = s.calls.uploads.pinata ?? 0;
    const week = await publishPhase(store, roleChain(roles), cfg, P, built, {
      now: now + P.reverifyEveryMs + 1,
    });
    cell(
      "publishPhase: after reverifyEveryMs the pins are read again and a lost pin is detected (nothing re-signed)",
      week.reverified === true &&
        week.ran === 2 &&
        s.calls.sign === before.sign &&
        (s.calls.fetches ?? 0) > fetchesBefore &&
        ((s.calls.uploads.pinata ?? 0) > pinataBefore || week.alerts > 0),
      {
        week,
        sign: s.calls.sign,
        fetches: [fetchesBefore, s.calls.fetches],
        pinata: [pinataBefore, s.calls.uploads.pinata],
      }
    );
    // R2: with one record per pass, the weekly generation closes only after both are re-checked
    s.pinOpts.pinata.gone = false;
    const P1 = { ...P, limits: { maxRecords: 1 } };
    const tW = now + 3 * P.reverifyEveryMs;
    const w1 = await publishPhase(store, roleChain(roles), cfg, P1, built, { now: tW });
    const w2 = await publishPhase(store, roleChain(roles), cfg, P1, built, { now: tW + 1 });
    const w3 = await publishPhase(store, roleChain(roles), cfg, P1, built, { now: tW + 2 });
    cell(
      "publishPhase: the weekly reverify generation stays open across bounded passes and closes when all were re-checked",
      w1.reverified === false &&
        w1.reverifying?.remaining === 1 &&
        w2.reverified === true &&
        (store.getAlertState()?.lastReverifyAt ?? 0) === tW &&
        w3.ran === 0 &&
        w3.reverifying === null,
      { w1: [w1.ran, w1.reverifying, w1.reverified], w2: [w2.ran, w2.reverified], w3: w3.ran }
    );
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
}

// ---- the writer holds a role, or roles are unreadable: registry stage skipped, alerted once
{
  const d = tmp();
  try {
    const store = new Store(d);
    store.putRecord(bls);
    const s = sinks();
    const built = {
      pinners: s.pinners,
      mirror: s.mirror,
      telegram: s.telegram,
      wallet: writer,
      registryFor: () => s.registry,
    };
    const asGuardian = {
      owner: ethers.getAddress("0x" + "5a".repeat(20)),
      max: 3,
      slots: { 3: writer.address },
    };
    const t0 = 10 * P.reverifyEveryMs; // past the first reverify window
    const r1 = await publishPhase(store, roleChain(asGuardian), cfg, P, built, { now: t0 });
    const st = store.getPublication(Store.recordId(bls));
    const texts1 = s.calls.texts.filter(t => /alert\(s\)/.test(t)).length;
    cell(
      "writer that is a guardian: registry stage skipped (nothing signed), pins/mirror/Telegram still run, alerted",
      /also the guardian/.test(r1.registrySkipped ?? "") &&
        s.calls.sign === 0 &&
        st.published === true &&
        !isDone(bls, st) &&
        texts1 === 1,
      { r1, sign: s.calls.sign, texts1 }
    );
    const r2 = await publishPhase(store, roleChain(asGuardian), cfg, P, built, {
      now: t0 + 60_000,
    });
    cell(
      "alert delivery keeps the reverify clock: the pass after a reverify + alert does not reverify",
      r1.reverified === true && r2.reverified === false,
      { r1: r1.reverified, r2: r2.reverified }
    );
    const texts2 = s.calls.texts.filter(t => /alert\(s\)/.test(t)).length;
    await publishPhase(store, roleChain(asGuardian), cfg, P, built, {
      now: t0 + P.alertRepeatMs + 1,
    });
    const texts3 = s.calls.texts.filter(t => /alert\(s\)/.test(t)).length;
    cell(
      "alerts: an unchanged set is not re-sent within alertRepeatMs, and is re-sent after it",
      texts2 === 1 && texts3 === 2,
      { texts2, texts3 }
    );
    const r4 = await publishPhase(store, roleChain({ ...asGuardian, fail: true }), cfg, P, built, {
      now: t0 + 2 * P.alertRepeatMs,
    });
    cell(
      "roles unreadable: registry skipped with a category, never the RPC's text",
      r4.registrySkipped === "role read: SERVER_ERROR" &&
        !j(store.getAlertState()).includes("ROLESECRET"),
      r4
    );
    const ok = { owner: ethers.getAddress("0x" + "5a".repeat(20)), max: 3, slots: { 1: G1 } };
    let r5;
    for (let i = 0; i < 4; i++)
      r5 = await publishPhase(store, roleChain(ok), cfg, P, built, {
        now: t0 + 3 * P.alertRepeatMs + i,
      });
    cell(
      "once the roles are clean, the skipped registry stage completes",
      isDone(bls, store.getPublication(Store.recordId(bls))) &&
        s.calls.sign === 1 &&
        !r5.registrySkipped,
      { r5, sign: s.calls.sign }
    );
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
}

// ---- a persist failure stops the pass; nothing is reported as done
{
  const d = tmp();
  try {
    const store = new Store(d);
    store.putRecord(bls);
    store.putRecord(owner);
    store.putPublication = () => {
      throw Object.assign(new Error("disk full /secret"), { code: "ENOSPC" });
    };
    const s = sinks();
    const r = await publishPending(store, {
      pinners: s.pinners,
      mirror: s.mirror,
      telegram: s.telegram,
      registry: s.registry,
    });
    cell(
      "a persist failure stops the pass at the first record, with a category",
      r.stopped === true &&
        r.counts.ran === 1 &&
        r.alerts.length === 1 &&
        /persist failed: ENOSPC; publication pass stopped/.test(r.alerts[0]),
      r
    );
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
}

// ---- M4 / M5 / H3: done means every pin current and the same bytes; bounded, rotating passes
{
  const d = tmp();
  try {
    const store = new Store(d);
    store.putRecord(owner);
    const s = sinks({ filebase: { fail: true } });
    const sk = { pinners: s.pinners, mirror: s.mirror, telegram: s.telegram, registry: null };
    const p1 = await publishPending(store, sk);
    const p2 = await publishPending(store, sk);
    const fbTried = s.calls.uploads.filebase;
    s.pinOpts.filebase.fail = false;
    const p3 = await publishPending(store, sk);
    const p4 = await publishPending(store, sk);
    const st = store.getPublication(Store.recordId(owner));
    cell(
      "M5: a published record with a failed configured pin is not done; the pin is retried each pass until it lands",
      p1.counts.done === 0 &&
        p2.counts.ran === 1 &&
        p2.alerts.some(a => /1\/2 current pins/.test(a)) &&
        fbTried >= 2 &&
        p3.counts.done === 1 &&
        p4.counts.ran === 0 &&
        st.pins.filebase?.current === true,
      { p1: p1.counts, p2: p2.counts, p3: p3.counts, p4: p4.counts, fbTried }
    );
    // M4: the record's bytes change on disk after publication
    const id = Store.recordId(owner);
    const original = readFileSync(join(d, "records", `${id}.json`), "utf8");
    writeFileSync(
      join(d, "records", `${id}.json`),
      JSON.stringify({ ...JSON.parse(original), tampered: true })
    );
    const p5 = await publishPending(store, sk);
    const p6 = await publishPending(store, sk);
    const st5 = store.getPublication(id);
    writeFileSync(join(d, "records", `${id}.json`), original); // changed back: still an incident
    const p7 = await publishPending(store, sk);
    cell(
      "M4: changed bytes are never done: a durable INCIDENT, alerted every pass, never republished",
      p5.counts.done === 0 &&
        p5.alerts.some(a => /bytes changed.*INCIDENT/.test(a)) &&
        p6.counts.incidents === 1 &&
        p6.alerts.some(a => /bytes changed/.test(a)) &&
        st5.bytesChanged?.to &&
        st5.cid !== st5.bytesChanged.to &&
        p7.counts.done === 0 &&
        p7.counts.incidents === 1,
      { p5: p5.counts, p6: p6.counts, bc: st5.bytesChanged }
    );
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
}
{
  const d = tmp();
  try {
    const store = new Store(d);
    const ids = [];
    for (let i = 0; i < 5; i++) {
      const r = { ...owner, txHash: ethers.id(`backlog-${i}`) };
      store.putRecord(r);
      ids.push(Store.recordId(r));
    }
    const s = sinks({ pinata: { fail: true }, filebase: { fail: true } });
    const sk = { pinners: s.pinners, mirror: s.mirror, telegram: s.telegram, registry: null };
    let t = 1000;
    const clock = () => t++;
    const a = await publishPending(store, sk, { maxRecords: 2, now: clock });
    const b = await publishPending(store, sk, { maxRecords: 2, now: clock });
    const c = await publishPending(store, sk, { maxRecords: 2, now: clock });
    const sch = store.getSchedule().entries ?? {};
    const ran = ids.filter(x => sch[x]?.lastRunAt).length;
    let slow = 0;
    const tick = () => (slow += 200_000);
    const timed = await publishPending(store, sk, { now: tick });
    cell(
      "H3: a pass runs at most maxRecords (and stops starting new ones after maxMs); passes rotate through the backlog",
      a.counts.ran === 2 &&
        a.counts.deferred === 3 &&
        b.counts.ran === 2 &&
        c.counts.ran === 2 &&
        ran === 5 &&
        // the budget covers preparation too: past it, no further file is even read (R4)
        timed.counts.ran === 1 &&
        timed.counts.flagged === 1,
      { a: a.counts, b: b.counts, c: c.counts, ran, timed: timed.counts }
    );
    // an acknowledged registry incident is parked: not run every pass
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
}
// ---- R2: an acknowledged registry incident parks only the registry stage
{
  const d = tmp();
  try {
    const store = new Store(d);
    store.putRecord(bls);
    const id = Store.recordId(bls);
    const s = sinks();
    const sk = { pinners: s.pinners, mirror: s.mirror, telegram: s.telegram, registry: s.registry };
    await publishPending(store, sk);
    await publishPending(store, sk);
    const st = store.getPublication(id);
    // written by this code, the stage names its registry (W2d)
    store.putPublication(id, {
      ...st,
      registry: { phase: "conflict", ack: true, at: st.registry.at },
    });
    const signBefore = s.calls.sign;
    const pk = await publishPending(store, sk);
    // a pin is lost: it is repaired, and the registry is still not touched
    const st2 = store.getPublication(id);
    store.putPublication(id, {
      ...st2,
      pins: { ...st2.pins, filebase: { ...st2.pins.filebase, current: false } },
    });
    const upBefore = s.calls.uploads.filebase ?? 0;
    const pk2 = await publishPending(store, sk);
    cell(
      "an acknowledged registry incident parks only the registry stage: done otherwise = parked; a lost pin is still repaired; nothing signed",
      pk.counts.parked === 1 &&
        pk.counts.ran === 0 &&
        pk2.counts.ran === 1 &&
        (s.calls.uploads.filebase ?? 0) > upBefore &&
        store.getPublication(id).pins.filebase.current === true &&
        s.calls.sign === signBefore,
      { pk: pk.counts, pk2: pk2.counts, sign: [signBefore, s.calls.sign] }
    );
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
}

// ---- W2c R2: bounded parsing, failing records rotate, bad identities isolated, reverify
// generation, restored bytes still an incident
{
  const d = tmp();
  try {
    const store = new Store(d);
    const s = sinks();
    const sk = { pinners: s.pinners, mirror: s.mirror, telegram: s.telegram, registry: null };
    // three records that always throw (over the CID cap), one healthy, one with an unusable id
    for (let i = 0; i < 3; i++)
      store.putRecord({ ...owner, txHash: ethers.id(`huge-${i}`), pad: "x".repeat(300_000) });
    const healthy = { ...owner, txHash: ethers.id("healthy") };
    store.putRecord(healthy);
    writeFileSync(
      join(d, "records", "bls-SLASH-zz.json"),
      JSON.stringify({ route: "bls", kind: "SLASH", key: "bad", verdict: { flagged: true } })
    );
    writeFileSync(
      join(d, "records", "owner-zz-evil.json"),
      JSON.stringify({
        route: "owner",
        id: "../evil",
        txHash: "0x01",
        logIndex: 0,
        verdict: { flagged: true },
      })
    );
    let t = 10;
    const clock = () => t++;
    const p1 = await publishPending(store, sk, { maxRecords: 3, now: clock });
    const p2 = await publishPending(store, sk, { maxRecords: 3, now: clock });
    const hid = Store.recordId(healthy);
    cell(
      "R2: records that always fail still rotate (healthy one runs by the second pass); a parseable record with an unusable id is isolated",
      p1.counts.ran === 3 &&
        p1.counts.failed >= 3 &&
        p1.alerts.some(a =>
          /2 record file\(s\) unreadable, oversized, duplicated or without a matching id/.test(a)
        ) &&
        store.getPublication(hid)?.published === true,
      { p1: p1.counts, p2: p2.counts, healthy: !!store.getPublication(hid) }
    );
    // bounded parsing: only maxParse files are read per pass, the cursor rotates through all
    const reads = [];
    const orig = store.readRecordFile.bind(store);
    store.readRecordFile = n => {
      reads.push(n);
      return orig(n);
    };
    const total = store.recordFiles().length;
    for (let i = 0; i < 3; i++) await publishPending(store, sk, { maxParse: 2, now: clock });
    const passes = [reads.slice(0, 2), reads.slice(2, 4), reads.slice(4, 6)];
    store.readRecordFile = orig;
    cell(
      "R2: at most maxParse record files are read per pass, and successive passes rotate through the directory",
      reads.length === 6 &&
        passes.every(p => p.length === 2) &&
        new Set(reads).size === Math.min(6, total),
      { reads, total }
    );
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
}
{
  const d = tmp();
  try {
    const store = new Store(d);
    const s = sinks();
    const sk = { pinners: s.pinners, mirror: s.mirror, telegram: s.telegram, registry: null };
    const ids = [];
    for (let i = 0; i < 3; i++) {
      const r = { ...owner, txHash: ethers.id(`rv-${i}`) };
      store.putRecord(r);
      ids.push(Store.recordId(r));
    }
    let t = 100;
    const clock = () => t++;
    await publishPending(store, sk, { now: clock });
    const f0 = s.calls.fetches ?? 0;
    const g1 = await publishPending(store, sk, { reverifyGen: 7, maxRecords: 2, now: clock });
    const g2 = await publishPending(store, sk, { reverifyGen: 7, maxRecords: 2, now: clock });
    const g3 = await publishPending(store, sk, { reverifyGen: 7, maxRecords: 2, now: clock });
    cell(
      "R2: a reverify generation stays open until every done record was re-checked in it, across bounded passes",
      g1.counts.ran === 2 &&
        g1.reverifyRemaining === 1 &&
        g2.counts.ran === 1 &&
        g2.reverifyRemaining === 0 &&
        g3.counts.ran === 0 &&
        (s.calls.fetches ?? 0) > f0,
      {
        g1: [g1.counts, g1.reverifyRemaining],
        g2: [g2.counts, g2.reverifyRemaining],
        g3: g3.counts,
      }
    );
    // restored bytes: the recorded incident still stands and is alerted, nothing else runs
    const id = ids[0];
    const file = join(d, "records", `${id}.json`);
    const original = readFileSync(file, "utf8");
    writeFileSync(file, JSON.stringify({ ...JSON.parse(original), tampered: true }));
    await publishPending(store, sk, { now: clock });
    writeFileSync(file, original);
    const before = { ...s.calls };
    const back = await publishPending(store, sk, { now: clock });
    cell(
      "R2: a recorded bytes change stands after the bytes change back: alerted, not done, no further publication effects",
      back.alerts.some(a => a.startsWith(id) && /bytes changed.*INCIDENT/.test(a)) &&
        back.counts.incidents >= 1 &&
        s.calls.mirror === before.mirror &&
        s.calls.telegram === before.telegram,
      { back: back.counts, alerts: back.alerts }
    );
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
}
{
  const d = tmp();
  try {
    const store = new Store(d);
    const texts = [];
    const tg = { send: async x => texts.push(x) };
    const alerts = Array.from({ length: 40 }, (_, i) => `a-${i}: ${"y".repeat(900)}`);
    const r = await deliverAlerts(store, tg, alerts, { now: 1, maxParts: 3 });
    cell(
      "R2: at most maxParts messages per pass; the last says how many lines are not shown",
      r.sent === true &&
        texts.length === 3 &&
        /and \d+ more alert line\(s\) not shown/.test(texts[2]),
      { n: texts.length, last: texts.at(-1)?.slice(0, 120) }
    );
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
}

// ---- W2c R3: generation needs a full sweep; schedule failure; real sink failures; orphans;
// duplicates; alert details; oversized files
{
  const d = tmp();
  try {
    const store = new Store(d);
    const s = sinks();
    const sk = { pinners: s.pinners, mirror: s.mirror, telegram: s.telegram, registry: null };
    for (let i = 0; i < 3; i++) store.putRecord({ ...owner, txHash: ethers.id(`sw-${i}`) });
    let t = 1;
    const clock = () => t++;
    // a generation opened on a fresh schedule, with one file read and one record run per pass
    const passes = [];
    for (let i = 0; i < 6; i++)
      passes.push(
        await publishPending(store, sk, { reverifyGen: 9, maxParse: 1, maxRecords: 1, now: clock })
      );
    const firstClosable = passes.findIndex(p => p.reverifyRemaining === 0 && p.sweeps > 0);
    cell(
      "R3: a generation cannot close before a full sweep has registered every record (fresh schedule, bounded batches)",
      firstClosable >= 2 &&
        passes.slice(0, firstClosable).every(p => p.reverifyRemaining > 0 || p.sweeps === 0),
      passes.map(p => [p.counts.ran, p.reverifyRemaining, p.sweeps])
    );
    // an orphan entry (its record removed) is retired by the next completed sweep
    // a fresh Store (a restarted process): its schedule comes from disk, with an orphan in it
    const st2 = new Store(d);
    const sch = st2.getSchedule();
    st2.putSchedule({ ...sch, entries: { ...sch.entries, "owner-0xgone-0": { done: true } } });
    const st3 = new Store(d);
    const hadIt = "owner-0xgone-0" in (st3.getSchedule().entries ?? {});
    for (let i = 0; i < 4; i++) await publishPending(st3, sk, { maxParse: 1, now: clock });
    cell(
      "R3: an entry whose record is gone is retired when a sweep completes",
      hadIt && !("owner-0xgone-0" in (st3.getSchedule().entries ?? {})),
      { hadIt, entries: Object.keys(st3.getSchedule().entries ?? {}) }
    );
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
}
{
  const d = tmp();
  try {
    const store = new Store(d);
    const s = sinks();
    const sk = { pinners: s.pinners, mirror: s.mirror, telegram: s.telegram, registry: null };
    for (let i = 0; i < 3; i++)
      store.putRecord({ ...owner, txHash: ethers.id(`sf-huge-${i}`), pad: "x".repeat(300_000) });
    const healthy = { ...owner, txHash: ethers.id("sf-healthy") };
    store.putRecord(healthy);
    const realPut = store.putSchedule.bind(store);
    store.putSchedule = () => {
      throw new Error("disk full");
    };
    let t = 1;
    const clock = () => t++;
    const q1 = await publishPending(store, sk, { maxRecords: 3, now: clock });
    const q2 = await publishPending(store, sk, { maxRecords: 3, now: clock });
    store.putSchedule = realPut;
    cell(
      "R3: a failing schedule write fails the pass (alerted) and rotation stays fair in memory (healthy record runs by pass 2)",
      q1.counts.failed >= 1 &&
        q1.alerts.some(a => /schedule not saved/.test(a)) &&
        store.getPublication(Store.recordId(healthy))?.published === true,
      { q1: q1.counts, q2: q2.counts }
    );
    // duplicate identity: a copy of the healthy record under another file name is isolated
    const name = `${Store.recordId(healthy)}.json`;
    writeFileSync(
      join(d, "records", `zz-copy.json`),
      readFileSync(join(d, "records", name), "utf8")
    );
    const tg0 = s.calls.telegram;
    const q3 = await publishPending(store, sk, { maxRecords: 10, now: clock });
    cell(
      "R3: a second file with the same record identity is isolated (no duplicate publication)",
      q3.counts.unreadable === 1 &&
        q3.alerts.some(a => /^1 record file\(s\) unreadable, oversized, duplicated/.test(a)) &&
        !q3.alerts.some(a => /zz-copy/.test(a)) &&
        s.calls.telegram === tg0,
      { q3: q3.counts, alerts: q3.alerts }
    );
    // an oversized file is refused before it is parsed
    writeFileSync(
      join(d, "records", "owner-0xbig-0.json"),
      JSON.stringify({ route: "owner", pad: "x".repeat(600_000) }) // valid JSON, unflagged, huge
    );
    const q4 = await publishPending(store, sk, { maxRecords: 10, now: clock });
    cell(
      "R3: a record file over the read bound is refused (unreadable), not parsed",
      q4.counts.unreadable === q3.counts.unreadable + 1 &&
        !q4.alerts.some(a => /owner-0xbig-0/.test(a)),
      { q3: q3.counts.unreadable, q4: q4.counts.unreadable, alerts: q4.alerts }
    );
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
}
{
  // publishPhase on a fresh store: with one record per pass, the generation closes only after
  // every record was registered (by a full sweep) and re-checked
  for (const [label, limits] of [
    ["one file read per pass", { maxParse: 1, maxRecords: 1 }],
    ["all files read, one record run per pass", { maxRecords: 1 }],
  ]) {
    const d = tmp();
    try {
      const store = new Store(d);
      for (let i = 0; i < 3; i++)
        store.putRecord({ ...owner, txHash: ethers.id(`gp-${label}-${i}`) });
      const s = sinks();
      const built = {
        pinners: s.pinners,
        mirror: s.mirror,
        telegram: s.telegram,
        wallet: writer,
        registryFor: () => s.registry,
      };
      const roles = { owner: ethers.getAddress("0x" + "5a".repeat(20)), max: 3, slots: { 1: G1 } };
      const PL = { ...P, limits };
      const out = [];
      for (let i = 0; i < 6; i++)
        out.push(
          await publishPhase(store, roleChain(roles), cfg, PL, built, {
            now: P.reverifyEveryMs + 10 + i,
          })
        );
      const closedAt = out.findIndex(r => r.reverified);
      cell(
        `R3 publishPhase (${label}): the generation closes no earlier than the third pass (three records, one run per pass)`,
        closedAt >= 2,
        out.map(r => [r.ran, r.reverifying?.remaining ?? null, r.reverified])
      );
    } finally {
      rmSync(d, { recursive: true, force: true });
    }
  }
}
{
  // real sink failures (both pinners down) make the pass not ok and --once exit 1
  const d = tmp();
  try {
    const store = new Store(d);
    store.putRecord(owner);
    const s = sinks({ pinata: { fail: true }, filebase: { fail: true } });
    const built = {
      pinners: s.pinners,
      mirror: s.mirror,
      telegram: s.telegram,
      wallet: writer,
      registryFor: () => s.registry,
    };
    const roles = { owner: ethers.getAddress("0x" + "5a".repeat(20)), max: 3, slots: { 1: G1 } };
    const r = await publishPhase(store, roleChain(roles), cfg, P, built, { now: 7_000_000 });
    cell(
      "R3: sink failures caught inside publishRecord make the pass not ok, so --once exits 1",
      r.ok === false && r.failed >= 1 && onceExitCode({ healthy: true, publication: r }) === 1,
      r
    );
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
}
{
  // a shortened digest is not acknowledged when its full list could not be stored
  const d = tmp();
  try {
    const store = new Store(d);
    const texts = [];
    const tg = { send: async x => texts.push(x) };
    const alerts = Array.from({ length: 40 }, (_, i) => `b-${i}: ${"y".repeat(900)}`);
    const r1 = await deliverAlerts(store, tg, alerts, { now: 1, maxParts: 3, detailsSaved: false });
    const r2 = await deliverAlerts(store, tg, alerts, { now: 2, maxParts: 3, detailsSaved: true });
    cell(
      "R3: a truncated digest is acknowledged only when the full alert list is stored",
      r1.sent === false && /details not stored/.test(r1.reason) && r2.sent === true,
      { r1, r2 }
    );
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
}

// ---- W2c R4 counterexamples
{
  // 1. an alias (a copy under another name with a rewritten id) is isolated, published once
  const d = tmp();
  try {
    const store = new Store(d);
    store.putRecord(owner);
    const id = Store.recordId(owner);
    writeFileSync(
      join(d, "records", "alias.json"),
      JSON.stringify({
        ...JSON.parse(readFileSync(join(d, "records", `${id}.json`), "utf8")),
        id: "alias",
      })
    );
    const s = sinks();
    const sk = { pinners: s.pinners, mirror: s.mirror, telegram: s.telegram, registry: null };
    const r = await publishPending(store, sk);
    cell(
      "R4: an alias with a rewritten id is refused (the id is derived, never taken from the file); one publication",
      r.counts.ran === 1 && r.counts.unreadable === 1 && s.calls.telegram === 1,
      { r: r.counts, tg: s.calls.telegram }
    );
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
}
{
  // 2. the directory changes during a generation: a record added before the cursor is visited
  //    (and published) before the generation closes
  const d = tmp();
  try {
    const store = new Store(d);
    const rec = (hx, flagged = true) => ({
      ...owner,
      txHash: "0x" + hx.repeat(32),
      verdict: flagged ? owner.verdict : { flagged: false, reasons: [] },
    });
    store.putRecord(rec("bb", false));
    store.putRecord(rec("cc"));
    store.putRecord(rec("dd"));
    const s = sinks();
    const built = {
      pinners: s.pinners,
      mirror: s.mirror,
      telegram: s.telegram,
      wallet: writer,
      registryFor: () => s.registry,
    };
    const roles = { owner: ethers.getAddress("0x" + "5a".repeat(20)), max: 3, slots: { 1: G1 } };
    const PL = { ...P, limits: { maxParse: 1, maxRecords: 1 } };
    await publishPhase(store, roleChain(roles), cfg, PL, built, { now: 5 }); // reads b, no generation
    rmSync(join(d, "records", `${Store.recordId(rec("bb", false))}.json`));
    store.putRecord(rec("aa"));
    const aId = Store.recordId(rec("aa"));
    let closedWithA = null;
    for (let i = 0; i < 12; i++) {
      const r = await publishPhase(store, roleChain(roles), cfg, PL, built, {
        now: P.reverifyEveryMs + 10 + i,
      });
      if (r.reverified) {
        closedWithA = !!store.getPublication(aId)?.published;
        break;
      }
    }
    cell(
      "R4: a generation closes only after a traversal that began after it opened (a record present at its opening is published first)",
      closedWithA === true,
      { closedWithA }
    );
    // 3. orphan cleanup on established absence only: removing files read earlier never retires a
    //    live record's entry
    const before = Object.keys(store.getSchedule().entries ?? {});
    rmSync(join(d, "records", `${aId}.json`));
    await publishPending(
      new Store(d),
      { pinners: s.pinners, mirror: s.mirror, telegram: s.telegram, registry: null },
      { maxParse: 1 }
    );
    const after = Object.keys(new Store(d).getSchedule().entries ?? {});
    const dId = Store.recordId(rec("dd"));
    cell(
      "R4: only entries whose file is gone are retired; a live record keeps its entry",
      before.includes(dId) && after.includes(dId) && !after.includes(aId),
      { before, after }
    );
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
}
{
  // 3b. mid-traversal: entries of files already gone are retired at once, live ones kept
  const d = tmp();
  try {
    const store = new Store(d);
    const ids = ["aa", "bb", "cc", "dd"].map(hx => {
      const r = { ...owner, txHash: "0x" + hx.repeat(32) };
      store.putRecord(r);
      return Store.recordId(r);
    });
    store.putSchedule({
      cursor: `${ids[1]}.json`,
      entries: Object.fromEntries(ids.map(i => [i, { done: true }])),
    });
    for (const i of ids.slice(0, 2)) rmSync(join(d, "records", `${i}.json`));
    const s = sinks();
    await publishPending(
      store,
      { pinners: s.pinners, mirror: s.mirror, telegram: s.telegram, registry: null },
      { maxParse: 1 }
    );
    const e = Object.keys(store.getSchedule().entries ?? {});
    cell(
      "R4: mid-traversal, entries whose file is gone are retired and live ones kept",
      !e.includes(ids[0]) && !e.includes(ids[1]) && e.includes(ids[2]) && e.includes(ids[3]),
      e
    );
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
}
{
  // 4. a resumed broadcast that fails again is a stage failure (the pass is not ok)
  const d = tmp();
  try {
    const store = new Store(d);
    store.putRecord(bls);
    const s = sinks({ mine: "pending" });
    const realB = s.registry.broadcast.bind(s.registry);
    let n = 0;
    s.registry.broadcast = async raw => {
      n++;
      if (n >= 1) throw Object.assign(new Error("rpc"), { code: "SERVER_ERROR" });
      return realB(raw);
    };
    const sk = { pinners: s.pinners, mirror: s.mirror, telegram: s.telegram, registry: s.registry };
    const r1 = await publishPending(store, sk);
    const r2 = await publishPending(store, sk);
    const r3 = await publishPending(store, sk);
    cell(
      "R4: a rebroadcast that fails with no receipt yet counts as a failed stage on every pass",
      r2.counts.failed >= 1 && r3.counts.failed >= 1,
      { r1: r1.counts, r2: r2.counts, r3: r3.counts, n }
    );
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
}
{
  // 5. a failed schedule write at the generation's close is reported (not ok)
  const d = tmp();
  try {
    const store = new Store(d);
    store.putRecord(owner);
    const s = sinks();
    const built = {
      pinners: s.pinners,
      mirror: s.mirror,
      telegram: s.telegram,
      wallet: writer,
      registryFor: () => s.registry,
    };
    const roles = { owner: ethers.getAddress("0x" + "5a".repeat(20)), max: 3, slots: { 1: G1 } };
    await publishPhase(store, roleChain(roles), cfg, P, built, { now: 1 });
    const realPut = store.putSchedule.bind(store);
    // open and close in the same pass; fail only the close write
    const origSave = realPut;
    let sawOpen = false;
    store.putSchedule = x => {
      if (x.reverifyGen !== undefined) sawOpen = true;
      else if (sawOpen) throw new Error("disk");
      return origSave(x);
    };
    const r = await publishPhase(store, roleChain(roles), cfg, P, built, {
      now: P.reverifyEveryMs + 5,
    });
    store.putSchedule = realPut;
    cell(
      "R4: a schedule write that fails when a generation closes is reported: not ok, alerted",
      r.ok === false && r.failed >= 1,
      r
    );
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
}

// ---- W2c R5: snapshot contract for generations; legacy open generation migrates
{
  const d = tmp();
  try {
    const store = new Store(d);
    const rec = hx => ({ ...owner, txHash: "0x" + hx.repeat(32) });
    store.putRecord(rec("bb"));
    store.putRecord(rec("cc"));
    const s = sinks();
    const built = {
      pinners: s.pinners,
      mirror: s.mirror,
      telegram: s.telegram,
      wallet: writer,
      registryFor: () => s.registry,
    };
    const roles = { owner: ethers.getAddress("0x" + "5a".repeat(20)), max: 3, slots: { 1: G1 } };
    const PL = { ...P, limits: { maxParse: 1, maxRecords: 1 } };
    const T = P.reverifyEveryMs + 10;
    await publishPhase(store, roleChain(roles), cfg, PL, built, { now: T }); // opens, reads b
    store.putRecord(rec("aa")); // added behind the cursor after the generation opened
    const aId = Store.recordId(rec("aa"));
    for (let i = 1; i < 12; i++)
      await publishPhase(store, roleChain(roles), cfg, PL, built, { now: T + i });
    cell(
      "R5: a record added behind the cursor after a generation opened is outside it, and is still published by the normal path",
      store.getPublication(aId)?.published === true &&
        (store.getAlertState()?.lastReverifyAt ?? 0) === T,
      { a: !!store.getPublication(aId)?.published, last: store.getAlertState()?.lastReverifyAt }
    );
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
}
{
  const d = tmp();
  try {
    const store = new Store(d);
    store.putRecord(owner);
    // a schedule written before reverifyGenNeed existed, with a generation open
    store.putSchedule({ reverifyGen: 42, reverifyGenSweeps: 0, sweeps: 3, cursor: null });
    const s = sinks();
    const built = {
      pinners: s.pinners,
      mirror: s.mirror,
      telegram: s.telegram,
      wallet: writer,
      registryFor: () => s.registry,
    };
    const roles = { owner: ethers.getAddress("0x" + "5a".repeat(20)), max: 3, slots: { 1: G1 } };
    const out = [];
    for (let i = 0; i < 4; i++)
      out.push(await publishPhase(store, roleChain(roles), cfg, P, built, { now: 1000 + i }));
    cell(
      "R5: a legacy open generation (no reverifyGenNeed) gets a finite threshold and closes",
      out.some(r => r.reverified) && (store.getAlertState()?.lastReverifyAt ?? 0) === 42,
      out.map(r => [r.reverified, r.reverifying])
    );
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
}

// ---- DSR: no sink secret in anything the publication layer writes or sends. One sentinel per
// secret (Pinata JWT, Filebase token, GitHub token in the remote URL, Telegram bot token in the URL
// path). Pass 1: every sink fails, echoing its secret in the message / URL / body (Telegram by a
// closed port, so the URL itself is in the failing request). Pass 2: Telegram 401 echoing its URL,
// pins 4xx/5xx with the secret in the body. Pass 3: everything works. Then the data dir, statuses,
// the uploaded IPFS bytes, the mirror's commits (contents and messages) and every Telegram text are
// searched for every sentinel.
{
  const S = {
    pin: "SENTPINATAjwt7a1",
    fb: "SENTFILEBASEtok2b",
    gh: "SENTGITHUBtok3c",
    tg: "SENTTELEGRAMbot4d",
  };
  const all = Object.values(S);
  const got = { uploads: [], texts: [] };
  let pass = 1;
  let tgMode = "ok"; // ok | 401 | 200false
  const blobs = new Map();
  const fileBytes = body => {
    const t = body.toString("latin1");
    const i = t.indexOf("\r\n\r\n", t.indexOf('filename="record.json"'));
    const k = t.indexOf("\r\n--", i + 4);
    return Buffer.from(t.slice(i + 4, k), "latin1");
  };
  const srv = createServer(async (req, res) => {
    // a token-leak probe on 127.0.0.1: it echoes the URL and Authorization on purpose (the cells
    // check that nothing of it reaches our output). Never rendered as HTML (#413 review B2).
    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    res.setHeader("X-Content-Type-Options", "nosniff");
    const chunks = [];
    for await (const c of req) chunks.push(c);
    const body = Buffer.concat(chunks);
    const echo = `${req.url} ${req.headers.authorization ?? ""}`;
    if (req.url.startsWith("/pin")) {
      if (pass === 1)
        return res.end(JSON.stringify({ data: { cid: `Bearer ${req.headers.authorization}` } }));
      if (pass === 2) {
        res.statusCode = 401;
        return res.end(JSON.stringify({ error: `invalid token ${echo}` }));
      }
      const b = fileBytes(body);
      got.uploads.push(b);
      const cid = cidV1Raw(b);
      blobs.set(cid, b);
      return res.end(JSON.stringify({ data: { cid } }));
    }
    if (req.url.startsWith("/fb")) {
      if (pass === 1) return res.end(JSON.stringify({ Hash: String(req.headers.authorization) }));
      if (pass === 2) {
        res.statusCode = 500;
        return res.end(`internal error ${echo}`);
      }
      const b = fileBytes(body);
      got.uploads.push(b);
      const cid = cidV1Raw(b);
      blobs.set(cid, b);
      return res.end(JSON.stringify({ Hash: cid }));
    }
    if (req.url.startsWith("/gw/ipfs/")) {
      const b = blobs.get(req.url.split("/").pop());
      if (!b) {
        res.statusCode = 404;
        return res.end(`not found ${echo}`);
      }
      return res.end(b);
    }
    if (req.url.startsWith("/tg/bot")) {
      const m = JSON.parse(body.toString() || "{}");
      if (tgMode === "200false")
        return res.end(
          JSON.stringify({ ok: false, error_code: 400, description: `Bad Request: ${req.url}` })
        );
      if (tgMode === "401") {
        res.statusCode = 401;
        return res.end(
          JSON.stringify({ ok: false, error_code: 401, description: `Unauthorized ${req.url}` })
        );
      }
      got.texts.push(String(m.text));
      return res.end(JSON.stringify({ ok: true }));
    }
    res.statusCode = 404;
    res.end(echo);
  });
  await new Promise(r => srv.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${srv.address().port}`;
  const d = tmp();
  try {
    const g = (cwd, ...a) =>
      execFileSync("git", ["-C", cwd, ...a], { stdio: "pipe" })
        .toString()
        .trim();
    const bare = join(d, "mirror.git");
    const seed = join(d, "seed");
    const clone = join(d, "clone.git");
    const bad = join(d, "bad.git");
    execFileSync("git", ["init", "--quiet", "--bare", bare]);
    execFileSync("git", ["clone", "--quiet", bare, seed], { stdio: "pipe" });
    g(
      seed,
      "-c",
      "user.name=t",
      "-c",
      "user.email=t@invalid",
      "commit",
      "--quiet",
      "--allow-empty",
      "-m",
      "init"
    );
    g(seed, "push", "--quiet", "origin", "HEAD:refs/heads/disclosure-records");
    execFileSync("git", ["clone", "--quiet", "--bare", bare, clone], { stdio: "pipe" });
    execFileSync("git", ["init", "--quiet", "--bare", bad]);
    g(bad, "remote", "add", "origin", `http://user:${S.gh}@127.0.0.1:1/${S.gh}/r.git`);
    const store = new Store(join(d, "data"));
    store.putRecord(owner);
    const pinners = () => [
      pinataPinner({ token: S.pin, gateway: `${base}/gw`, uploadUrl: `${base}/pin` }),
      filebasePinner({ token: S.fb, gateway: `${base}/gw`, rpcUrl: `${base}/fb` }),
    ];
    const tgUp = telegramSink({ token: S.tg, chatId: "1", apiBase: `${base}/tg` });
    const tgDown = telegramSink({ token: S.tg, chatId: "1", apiBase: "http://127.0.0.1:1/tg" });
    const builtFor = (telegram, mirrorClone) => ({
      pinners: pinners(),
      mirror: gitMirror({ clone: mirrorClone, repoUrl: `https://github.com/o/r` }),
      telegram,
      wallet: writer,
      registryFor: () => null,
    });
    const roles = { owner: ethers.getAddress("0x" + "5a".repeat(20)), max: 3, slots: { 1: G1 } };
    const statuses = [];
    // every file of the data dir after every pass (later passes overwrite journals and alerts)
    const snaps = [];
    const snap = () => {
      const w = p => {
        for (const n of readdirSync(p, { withFileTypes: true })) {
          const q = join(p, n.name);
          if (n.isDirectory()) w(q);
          else snaps.push(readFileSync(q, "latin1"));
        }
      };
      w(join(d, "data"));
    };
    pass = 1;
    statuses.push(
      await publishPhase(store, roleChain(roles), cfg, P, builtFor(tgDown, bad), { now: 10_000 })
    );
    snap();
    pass = 2;
    tgMode = "401";
    statuses.push(
      await publishPhase(store, roleChain(roles), cfg, P, builtFor(tgUp, bad), { now: 20_000 })
    );
    snap();
    tgMode = "200false";
    statuses.push(
      await publishPhase(store, roleChain(roles), cfg, P, builtFor(tgUp, bad), { now: 25_000 })
    );
    snap();
    // pins and mirror still failing, Telegram back: the digest of the sink-failure alerts goes out
    tgMode = "ok";
    statuses.push(
      await publishPhase(store, roleChain(roles), cfg, P, builtFor(tgUp, bad), { now: 30_000 })
    );
    pass = 3;
    statuses.push(
      await publishPhase(store, roleChain(roles), cfg, P, builtFor(tgUp, clone), {
        now: 30_000 + P.alertRepeatMs + 1,
      })
    );
    // everything the publication layer wrote or sent
    const files = [];
    const walk = p => {
      for (const n of readdirSync(p, { withFileTypes: true })) {
        const q = join(p, n.name);
        if (n.isDirectory()) walk(q);
        else files.push(q);
      }
    };
    walk(join(d, "data"));
    const mirrorText = g(bare, "log", "-p", "--all", "--format=%H%n%B");
    const hay = [
      ...files.map(f => readFileSync(f, "latin1")),
      ...snaps,
      ...statuses.map(x => JSON.stringify(x)),
      ...got.uploads.map(b => b.toString("latin1")),
      mirrorText,
      ...got.texts,
    ].join("\n");
    const leaked = all.filter(x => hay.includes(x));
    const published = !!store.getPublication(Store.recordId(owner))?.published;
    cell(
      "DSR: no Pinata / Filebase / GitHub / Telegram secret in records, IPFS bytes, mirror commits, status, alerts or any written file (every sink fails once with its secret in message, URL and body)",
      leaked.length === 0 &&
        statuses[0].ok === false &&
        statuses[1].ok === false &&
        statuses[2].ok === false &&
        statuses[3].ok === false &&
        published &&
        got.uploads.length >= 2 &&
        /disclosure/.test(mirrorText) &&
        got.texts.length >= 1 &&
        got.texts.some(t => /alert/.test(t) && /pinata|filebase|mirror/.test(t)),
      {
        leaked,
        ok: statuses.map(x => x.ok),
        published,
        uploads: got.uploads.length,
        texts: got.texts.length,
      }
    );
  } finally {
    srv.close();
    rmSync(d, { recursive: true, force: true });
  }
}

// ---- --once exit code: healthy scan AND an ok publication pass
cell(
  "onceExitCode: 0 only when the scan is healthy and publication (if it ran) reported ok",
  onceExitCode({ healthy: true }) === 0 &&
    onceExitCode({ healthy: true, publication: { ok: true } }) === 0 &&
    onceExitCode({ healthy: true, publication: { ok: false, failed: 1 } }) === 1 &&
    onceExitCode({ healthy: true, publication: { error: "x" } }) === 1 &&
    onceExitCode({ healthy: false, publication: { ok: true } }) === 1 &&
    onceExitCode({ ok: true }) === 1,
  null
);

// ---- M6: a large alert set is delivered whole, in chunks, and acknowledged only when all land
{
  const d = tmp();
  try {
    const store = new Store(d);
    const texts = [];
    let failAt = 2;
    const tg = {
      async send(t) {
        if (texts.length + 1 === failAt) {
          failAt = 0;
          throw Object.assign(new Error("x"), { code: "ECONNRESET" });
        }
        texts.push(t);
      },
    };
    const alerts = Array.from({ length: 40 }, (_, i) => `rec-${i}: ${"z".repeat(200)} END${i}`);
    alerts.push(`huge: ${"q".repeat(9000)} TAIL`);
    const r1 = await deliverAlerts(store, tg, alerts, { now: 1, maxParts: 100 });
    const after1 = texts.length;
    const r2 = await deliverAlerts(store, tg, alerts, { now: 2, maxParts: 100 });
    const all = texts.slice(after1).join("\n");
    cell(
      "alerts: every chunk is under the sink's cut; a failure part-way is not acked; the retry delivers every alert",
      r1.sent === false &&
        r1.partsSent === 1 &&
        r2.sent === true &&
        r2.parts > 2 &&
        texts.every(t => t.length <= 4000) &&
        alerts.slice(0, 40).every((_, i) => all.includes(`END${i}`)) &&
        all.includes("TAIL") &&
        (all.match(/q/g) ?? []).length === 9000,
      { r1, r2, lens: texts.map(t => t.length) }
    );
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
}

// ---- M7: one corrupt record or journal does not block the others, and a journal is never reset
{
  const d = tmp();
  try {
    const store = new Store(d);
    store.putRecord(bls);
    store.putRecord(owner);
    writeFileSync(join(d, "records", "owner-0xbad-0.json"), "{not json");
    const s = sinks();
    const built = {
      pinners: s.pinners,
      mirror: s.mirror,
      telegram: s.telegram,
      wallet: writer,
      registryFor: () => s.registry,
    };
    const roles = { owner: ethers.getAddress("0x" + "5a".repeat(20)), max: 3, slots: { 1: G1 } };
    const blsId = Store.recordId(bls);
    writeFileSync(join(d, "publications", `${Store.safeId(blsId)}.json`), "{broken");
    const r = await publishPhase(store, roleChain(roles), cfg, P, built, { now: 5_000_000 });
    const ownSt = store.getPublication(Store.recordId(owner));
    let journalKept = false;
    try {
      store.getPublication(blsId);
    } catch {
      journalKept = true;
    }
    cell(
      "a corrupt record and a corrupt journal are alerted and skipped; healthy records still publish; nothing signed for the broken one",
      ownSt?.published &&
        r.failed === 2 &&
        r.ok === false &&
        journalKept &&
        s.calls.sign === 0 &&
        s.calls.texts.some(
          t =>
            /unreadable, oversized, duplicated or without a matching id/.test(t) &&
            /journal unreadable/.test(t)
        ),
      { r, ownSt: !!ownSt, sign: s.calls.sign, texts: s.calls.texts.length }
    );
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
}

// ---- M8: the scan's status keeps the last publication result, marked in progress
{
  const d = tmp();
  try {
    const store = new Store(d);
    const broken = {
      async getBlock() {
        throw Object.assign(new Error("down"), { code: "SERVER_ERROR" });
      },
      async send() {
        throw Object.assign(new Error("down"), { code: "SERVER_ERROR" });
      },
    };
    const last = { at: "t0", failed: 1, alerts: 3 };
    const { status } = await runOnce(
      broken,
      { aggregator: AGG, roles: { superPaymaster: AGG }, startBlock: 0, forwarders: {} },
      store,
      {},
      { verified: true },
      { carry: { publication: { ...last, inProgress: true, since: "t1" } } }
    );
    const onDisk = store.readStatus();
    cell(
      "status written by the scan keeps the previous publication result (in progress) until the pass replaces it",
      status.ok === false &&
        onDisk?.publication?.failed === 1 &&
        onDisk.publication.inProgress === true &&
        onDisk.publication.since === "t1",
      onDisk
    );
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
}

// ---- deliverAlerts without a Telegram failure loop
{
  const d = tmp();
  try {
    const store = new Store(d);
    let sends = 0;
    const tg = {
      async send() {
        sends++;
        throw Object.assign(new Error("bot TOKSECRET"), { code: "ECONNRESET" });
      },
    };
    const r = await deliverAlerts(store, tg, ["x"], { now: 1 });
    const r2 = await deliverAlerts(store, tg, ["x"], { now: 2 });
    cell(
      "a failed alert delivery is reported (category), not marked sent, retried next pass, never self-alerted",
      r.sent === false && r.reason === "telegram: ECONNRESET" && r2.sent === false && sends === 2,
      { r, r2, sends }
    );
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
}

// ---- publishConfig + buildSinks
const good = {
  enabled: true,
  pinners: [{ type: "pinata", gateway: "https://x.mypinata.cloud" }, { type: "filebase" }],
  telegram: { chatId: "-100" },
  mirror: { clone: "/tmp/none.git" },
  registry: {
    address: ethers.getAddress("0x" + "ab".repeat(20)),
    fromBlock: 1,
    deployer: DEPLOYER,
    keystore: "/nonexistent",
    maxFeePerGas: "200000000000",
  },
};
{
  cell(
    "publishConfig: a complete config is accepted with defaults",
    publishConfig(good).lockPort === 47331,
    null
  );
  const bad = {};
  for (const [name, c] of [
    ["no pinners", { ...good, pinners: [] }],
    ["unknown pinner", { ...good, pinners: [{ type: "web3" }] }],
    [
      "pinata without https gateway",
      { ...good, pinners: [{ type: "pinata", gateway: "http://x" }] },
    ],
    ["no telegram", { ...good, telegram: undefined }],
    ["no mirror", { ...good, mirror: {} }],
    ["bad registry", { ...good, registry: { ...good.registry, address: "0x12" } }],
    ["no deployer", { ...good, registry: { ...good.registry, deployer: undefined } }],
    ["no keystore", { ...good, registry: { ...good.registry, keystore: "" } }],
    // the absolute fee ceiling is required, a decimal wei string (DSR, #411 F1)
    ["no fee cap", { ...good, registry: { ...good.registry, maxFeePerGas: undefined } }],
    ["fee cap not decimal", { ...good, registry: { ...good.registry, maxFeePerGas: "200 gwei" } }],
    ["bad interval", { ...good, alertRepeatMs: -1 }],
  ]) {
    try {
      publishConfig(c);
      bad[name] = "accepted";
    } catch (e) {
      bad[name] = /^config\.publish: /.test(e.message) ? true : e.message;
    }
  }
  cell(
    "publishConfig: every incomplete config is refused with a named reason",
    Object.values(bad).every(v => v === true),
    bad
  );

  const d = tmp();
  try {
    const ks = join(d, "writer.json");
    writeFileSync(
      ks,
      await ethers.encryptKeystoreJson(
        { address: writer.address, privateKey: writer.privateKey },
        "PASSWORDSECRET",
        { scrypt: { N: 1 << 10 } }
      )
    );
    const asked = [];
    const secrets = {
      "aoa-dvt-pinata-jwt": "pj",
      "aoa-dvt-filebase-token": "fb",
      "aoa-dvt-alert-bot-token": "tg",
      "aoa-dvt-watcher-keystore-pw": "PASSWORDSECRET",
    };
    const readSecret = async (svc, acct) => {
      asked.push(`${svc}/${acct}`);
      return acct === "aoa-watcher" ? secrets[svc] : undefined;
    };
    const p = publishConfig({ ...good, registry: { ...good.registry, keystore: ks } });
    const b = await buildSinks(
      p,
      new ethers.JsonRpcProvider("http://127.0.0.1:1", 1, { staticNetwork: true }),
      { readSecret }
    );
    cell(
      "buildSinks: every secret from its own Keychain service under the aoa-watcher account (DSR 0829236d), the keystore decrypted to the writer",
      b.wallet.address === writer.address &&
        b.pinners.map(x => x.name).join() === "pinata,filebase" &&
        j(asked) ===
          j([
            "aoa-dvt-pinata-jwt/aoa-watcher",
            "aoa-dvt-filebase-token/aoa-watcher",
            "aoa-dvt-alert-bot-token/aoa-watcher",
            "aoa-dvt-watcher-keystore-pw/aoa-watcher",
          ]),
      { asked, addr: b.wallet.address }
    );
    let e = null;
    try {
      await buildSinks(p, null, {
        readSecret: async (s2, a) => (s2 === "aoa-dvt-watcher-keystore-pw" ? "wrong" : secrets[s2]),
      });
    } catch (x) {
      e = x.message;
    }
    cell(
      "buildSinks: a wrong keystore password is a fixed error",
      e === "registry keystore could not be decrypted",
      e
    );
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
}

// ---- the process: a bad publish config refuses to start (one category line, exit 1)
{
  const d = tmp();
  try {
    writeFileSync(
      join(d, "c.json"),
      JSON.stringify({
        aggregator: AGG,
        dataDir: join(d, "data"),
        startBlock: 1,
        roles: { superPaymaster: AGG },
        lockPort: 47399,
        publish: { enabled: true, pinners: [] },
      })
    );
    let out = { status: 0, err: "" };
    try {
      execFileSync(
        process.execPath,
        [join(HERE, "watcher.mjs"), "--config", join(d, "c.json"), "--once"],
        {
          env: { ...process.env, RPC_URL: "http://127.0.0.1:1" },
          stdio: "pipe",
        }
      );
    } catch (e) {
      out = { status: e.status, err: String(e.stderr).trim() };
    }
    cell(
      "watcher: publish enabled with a bad config refuses to start, names the problem, exit 1",
      out.status === 1 &&
        out.err === "config.publish: pinners required (at least one)" &&
        readdirSync(d).length === 1,
      out
    );
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
}

// ---- #411 F1 / DSR: fee-capped or unfunded discloses are a store-wide, persistent degraded state
{
  const { stallReasons } = await import("./watcher.mjs");
  const { stallCounts } = await import("./lib/publisher.mjs");
  const { check: heartbeat } = await import("../../deploy/guardian-watcher/heartbeat.mjs");
  const d = tmp();
  try {
    const store = new Store(d);
    store.putRecord(bls);
    const s = sinks({ mine: "pending", rejectBroadcast: true });
    const sk = { pinners: s.pinners, mirror: s.mirror, telegram: s.telegram, registry: s.registry };
    await publishPending(store, sk, { maxPendingMs: 0 });
    const p2 = await publishPending(store, sk, { maxPendingMs: 0 });
    cell(
      "F1: an unfunded disclose is recorded store-wide and becomes a fixed-wording degraded reason",
      p2.stalls.insufficientFunds === 1 &&
        /insufficient funds/.test(stallReasons({ stalls: p2.stalls })[0] ?? ""),
      { stalls: p2.stalls }
    );
    // later passes whose batch does NOT contain the record: the stall persists, degraded stays true
    const statuses = [];
    let hb = null;
    const sent = [];
    for (let i = 0; i < 3; i++) {
      const pi = await publishPending(store, sk, { maxPendingMs: 0, maxParse: 0 });
      const reasons = stallReasons({ stalls: pi.stalls });
      statuses.push(reasons.length > 0);
      const at = new Date(1_000_000 + i * 60_000).toISOString();
      const r = await heartbeat({
        cfg: { dataDir: d, intervalMs: 60_000, heartbeat: { label: "t" } },
        now: Date.parse(at),
        readStatus: () =>
          JSON.stringify({ at, healthy: reasons.length === 0, degraded: reasons, lagBlocks: 0 }),
        statMtime: () => Date.parse(at),
        send: async t => (sent.push(t), true),
        readState: () => hb,
        writeState: x => ((hb = x), true),
      });
      void r;
    }
    cell(
      "DSR: a fee-capped/unfunded record outside the batch keeps degraded true pass after pass; the heartbeat's two-in-a-row fires",
      statuses.every(Boolean) &&
        stallCounts(store).insufficientFunds === 1 &&
        sent.some(t => /degraded for 2 checks/.test(t)),
      { statuses, sent }
    );
    // the writer is funded again: the next pass that processes the record clears the stall
    s.chain.known.clear();
    const s2 = sinks({ mine: "pending" });
    Object.assign(sk, { registry: s2.registry });
    const after = await publishPending(store, sk, { maxPendingMs: 60 * 60_000 });
    cell(
      "F1: once broadcasts go through again, the record's stall is cleared store-wide",
      after.stalls.insufficientFunds === 0 && stallReasons({ stalls: after.stalls }).length === 0,
      { stalls: after.stalls }
    );
    cell(
      "F1: no stall, no degraded reason",
      stallReasons({ stalls: { feeCapped: 0, insufficientFunds: 0 } }).length === 0 &&
        stallReasons({ stalls: { feeCapped: 2 } })[0] ===
          "2 disclose tx(s) need a fee above registry.maxFeePerGas",
      null
    );
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
}

// ---- Codex W2c R12–R14: per-record stalls in the publication schedule
{
  const { stallReasons } = await import("./watcher.mjs");
  const { stallCounts, stallKind } = await import("./lib/publisher.mjs");
  const schedPath = d => join(d, "publish-schedule.json");
  const readSched = d => JSON.parse(readFileSync(schedPath(d), "utf8"));
  const unfunded = () => {
    const s = sinks({ mine: "pending", rejectBroadcast: true });
    return {
      s,
      sk: { pinners: s.pinners, mirror: s.mirror, telegram: s.telegram, registry: s.registry },
    };
  };
  const recs = n =>
    Array.from({ length: n }, (_, i) => ({
      ...bls,
      key: String(9000 + i),
      proposalId: String(9000 + i),
      txHash: ethers.id(`stall-${i}`),
    }));
  // R12 #2: the FIRST broadcast failing for funds is journalled and counted from that pass
  {
    const d = tmp();
    try {
      const store = new Store(d);
      store.putRecord(bls);
      const { sk } = unfunded();
      const p1 = await publishPending(store, sk, { maxPendingMs: 0 });
      const pub = store.getPublication(Store.recordId(bls));
      cell(
        "R12#2: an initial broadcast refused for funds is journalled, alerted and counted in the same pass",
        p1.stalls.insufficientFunds === 1 &&
          !p1.stalls.unknown &&
          /INSUFFICIENT_FUNDS|insufficient/i.test(
            String(pub?.registry?.lastBroadcastError ?? "")
          ) &&
          p1.alerts.some(a => /insufficient funds/.test(a)),
        { stalls: p1.stalls, reg: pub?.registry, alerts: p1.alerts }
      );
    } finally {
      rmSync(d, { recursive: true, force: true });
    }
  }
  cell(
    "R12#1/R13#2: confirmed, reverted and conflict are never stalls, whatever markers remain",
    stallKind({
      registry: { phase: "confirmed", feeCapped: "t", lastBroadcastError: "INSUFFICIENT_FUNDS" },
    }) === null &&
      stallKind({ registry: { phase: "reverted", feeCapped: "t" } }) === null &&
      stallKind({ registry: { phase: "conflict", lastBroadcastError: "INSUFFICIENT_FUNDS" } }) ===
        null &&
      stallKind({ registry: { phase: "sent", feeCapped: "t" } }) === "feeCapped" &&
      stallKind({ registry: { phase: "unsigned", feeCapped: "t" } }) === "feeCapped",
    null
  );
  // R12 #1: a done (confirmed) record clears a stale stall in its entry
  {
    const d = tmp();
    try {
      const store = new Store(d);
      store.putRecord(bls);
      const s = sinks({});
      const sk = {
        pinners: s.pinners,
        mirror: s.mirror,
        telegram: s.telegram,
        registry: s.registry,
      };
      for (let i = 0; i < 4; i++) await publishPending(store, sk, { maxPendingMs: 0 });
      const id = Store.recordId(bls);
      const pub = store.getPublication(id);
      store.putPublication(id, {
        ...pub,
        registry: { ...pub.registry, feeCapped: "2026-01-01T00:00:00Z" },
      });
      const sc = readSched(d);
      sc.entries[id] = { ...sc.entries[id], stall: "feeCapped" };
      writeFileSync(schedPath(d), JSON.stringify(sc));
      const fresh = new Store(d); // a new process: nothing in memory
      const before = stallCounts(fresh);
      const p = await publishPending(fresh, sk, { maxPendingMs: 0 });
      cell(
        "R12#1: a done (confirmed) record clears its stale stall store-wide",
        pub?.registry?.phase === "confirmed" &&
          before.feeCapped === 1 &&
          p.stalls.feeCapped === 0 &&
          readSched(d).entries[id].stall === undefined,
        { phase: pub?.registry?.phase, before, stalls: p.stalls }
      );
    } finally {
      rmSync(d, { recursive: true, force: true });
    }
  }
  // R12 #3 / R14 #2: an unreadable schedule is "unknown" until a complete sweep, each pass within
  // its budget (no full rebuild)
  {
    const d = tmp();
    try {
      const store0 = new Store(d);
      for (const r of recs(3)) store0.putRecord(r);
      const { sk } = unfunded();
      await publishPending(store0, sk, { maxPendingMs: 0 });
      writeFileSync(schedPath(d), "{not json");
      class Counting extends Store {
        reads = 0;
        getPublication(id) {
          this.reads++;
          return super.getPublication(id);
        }
      }
      const store = new Counting(d);
      const u0 = stallCounts(store);
      const seen = [];
      for (let i = 0; i < 3; i++) {
        store.reads = 0;
        const p = await publishPending(store, sk, { maxPendingMs: 0, maxParse: 1 });
        seen.push({
          unknown: !!p.stalls.unknown,
          n: p.stalls.insufficientFunds,
          reads: store.reads,
          alerts: p.alerts.filter(a => /schedule/.test(a)),
        });
      }
      cell(
        "R12#3: an unreadable schedule counts as unknown, never as zero stalls",
        u0.unknown === true &&
          stallReasons({ stalls: u0 })[0] ===
            "stall state unknown: records not all re-read yet, or a record or journal unreadable" &&
          seen[0].alerts.some(a =>
            /schedule unreadable; stall state unknown until a full sweep/.test(a)
          ),
        { u0, seen }
      );
      cell(
        "R14#2: unknown until the sweep completes (3 records, 1 per pass), then the true count; every pass reads at most its budget of journals",
        seen[0].unknown &&
          seen[1].unknown &&
          !seen[2].unknown &&
          seen[2].n === 3 &&
          seen.every(x => x.reads <= 2),
        seen
      );
    } finally {
      rmSync(d, { recursive: true, force: true });
    }
  }
  // a schedule written before stalls were tracked, part-way through a traversal: one more sweep
  {
    const d = tmp();
    try {
      const store0 = new Store(d);
      for (const r of recs(3)) store0.putRecord(r);
      const names = store0.recordFiles();
      writeFileSync(schedPath(d), JSON.stringify({ cursor: names[0], entries: {}, sweeps: 0 }));
      const store = new Store(d);
      const { sk } = unfunded();
      const a = await publishPending(store, sk, { maxPendingMs: 0 });
      const b = await publishPending(store, sk, { maxPendingMs: 0 });
      cell(
        "R14: a legacy schedule mid-traversal stays unknown after the partial sweep and is known after a full one",
        a.stalls.unknown === true && !b.stalls.unknown && b.stalls.insufficientFunds === 3,
        { a: a.stalls, b: b.stalls }
      );
    } finally {
      rmSync(d, { recursive: true, force: true });
    }
  }
  // R13 #1 / R14 #1: the stall travels with the rotation. An unwritable schedule is reported, the
  // pass reports what it computed, and a restart reads "unknown", never an old zero.
  {
    const d = tmp();
    try {
      const store = new Store(d);
      store.putRecord(bls);
      const { sk } = unfunded();
      mkdirSync(join(schedPath(d), "x"), { recursive: true });
      const p1 = await publishPending(store, sk, { maxPendingMs: 0 });
      const p2 = await publishPending(store, sk, { maxPendingMs: 0, maxParse: 0 });
      const restarted = stallCounts(new Store(d));
      cell(
        "R14#1: an unwritable schedule: alerted, the pass and the next (in memory) report the stall, a restart reports unknown",
        p1.stalls.insufficientFunds === 1 &&
          p1.alerts.some(a => /publication schedule not saved/.test(a)) &&
          p2.stalls.insufficientFunds === 1 &&
          restarted.unknown === true,
        { p1: [p1.stalls, p1.alerts], p2: p2.stalls, restarted }
      );
    } finally {
      rmSync(d, { recursive: true, force: true });
    }
  }
  // the schedule write fails while the old one stays readable (store root read-only): after a
  // restart the rotation resumes at the last saved cursor, so the first pass re-reads the record
  {
    const d = tmp();
    try {
      const store = new Store(d);
      store.putRecord(bls);
      const { sk } = unfunded();
      await publishPending(store, sk, { maxPendingMs: 0 });
      chmodSync(d, 0o500);
      let funded;
      const s2 = sinks({ mine: "pending" });
      const sk2 = { ...sk, registry: s2.registry };
      try {
        funded = await publishPending(store, sk2, { maxPendingMs: 60 * 60_000 });
      } finally {
        chmodSync(d, 0o700);
      }
      const fresh = new Store(d);
      const first = await publishPending(fresh, sk2, { maxPendingMs: 60 * 60_000 });
      cell(
        "R14#1: an unsaved stall change is redone by the first pass after a restart (the rotation restarts at the saved cursor)",
        funded.stalls.insufficientFunds === 0 &&
          funded.alerts.some(a => /publication schedule not saved/.test(a)) &&
          first.stalls.insufficientFunds === 0 &&
          !first.stalls.unknown,
        { funded: [funded.stalls, funded.alerts], first: [first.stalls, first.alerts] }
      );
    } finally {
      rmSync(d, { recursive: true, force: true });
    }
  }
}

// ---- Codex W2c R15: deferred records, lost saves across a restart, unreadable record files
{
  const { stallCounts } = await import("./lib/publisher.mjs");
  const schedPath = d => join(d, "publish-schedule.json");
  const recs = (n, tag) =>
    Array.from({ length: n }, (_, i) => ({
      ...bls,
      key: String(7000 + i),
      proposalId: String(7000 + i),
      txHash: ethers.id(`${tag}-${i}`),
    }));
  const skOf = s => ({
    pinners: s.pinners,
    mirror: s.mirror,
    telegram: s.telegram,
    registry: s.registry,
  });
  // #1: reconstruction with deferred records (one run per pass) still counts every journal read
  {
    const d = tmp();
    try {
      const st0 = new Store(d);
      for (const r of recs(3, "r15a")) st0.putRecord(r);
      const sk = skOf(sinks({ mine: "pending", rejectBroadcast: true }));
      await publishPending(st0, sk, { maxPendingMs: 0 });
      writeFileSync(schedPath(d), "{bad");
      const p = await publishPending(new Store(d), sk, { maxPendingMs: 0, maxRecords: 1 });
      cell(
        "R15#1: records deferred by the run budget are refreshed from their journals (3 stalls, not 1)",
        p.counts.deferred === 2 && p.stalls.insufficientFunds === 3 && !p.stalls.unknown,
        { counts: p.counts, stalls: p.stalls }
      );
    } finally {
      rmSync(d, { recursive: true, force: true });
    }
  }
  // #2: saves lost over several passes, then a restart: unknown until a sweep, never a false clean
  {
    const d = tmp();
    try {
      const st = new Store(d);
      for (const r of recs(2, "r15b")) st.putRecord(r);
      const funded = sinks({ mine: "pending" });
      const p0 = await publishPending(st, skOf(funded), { maxPendingMs: 60 * 60_000 });
      const savedClean = !p0.stalls.unknown && p0.stalls.insufficientFunds === 0;
      st.putSchedule = () => {
        throw new Error("disk full");
      };
      const broke = skOf(sinks({ mine: "pending", rejectBroadcast: true }));
      await publishPending(st, broke, { maxPendingMs: 60 * 60_000, maxParse: 1 });
      const pm = await publishPending(st, broke, { maxPendingMs: 60 * 60_000, maxParse: 1 });
      const restarted = new Store(d); // the saved schedule is the clean one of p0
      const r1 = await publishPending(restarted, broke, { maxPendingMs: 60 * 60_000, maxParse: 1 });
      const r2 = await publishPending(restarted, broke, { maxPendingMs: 60 * 60_000, maxParse: 1 });
      cell(
        "R15#2: after a restart over lost saves the first bounded pass reports unknown, then the sweep gives the true count",
        savedClean &&
          pm.stalls.insufficientFunds === 2 &&
          r1.stalls.unknown === true &&
          !r2.stalls.unknown &&
          r2.stalls.insufficientFunds === 2,
        { savedClean, pm: pm.stalls, r1: r1.stalls, r2: r2.stalls }
      );
    } finally {
      rmSync(d, { recursive: true, force: true });
    }
  }
  // the same reconciliation is invisible for a store one pass can sweep: a restart reports known
  {
    const d = tmp();
    try {
      const st = new Store(d);
      st.putRecord(bls);
      const sk = skOf(sinks({ mine: "pending", rejectBroadcast: true }));
      await publishPending(st, sk, { maxPendingMs: 0 });
      const p = await publishPending(new Store(d), sk, { maxPendingMs: 0 });
      cell(
        "R15#2: a restart on a store swept in one pass reports the count at once (no spurious unknown)",
        !p.stalls.unknown && p.stalls.insufficientFunds === 1,
        p.stalls
      );
    } finally {
      rmSync(d, { recursive: true, force: true });
    }
  }
  // a run that fails after its journal advanced: the entry takes the journal's stall, not the
  // listing's. Pass 1 journals an unfunded stall; in pass 2 the writer is funded, the rebroadcast
  // goes through and the cleared state is journalled, then the next journal write fails.
  {
    const d = tmp();
    try {
      class FailAfterClear extends Store {
        mode = "off";
        putPublication(id, st) {
          if (this.mode === "fire") throw new Error("disk full");
          super.putPublication(id, st);
          const r = st?.registry;
          if (this.mode === "armed" && r?.phase === "sent" && r.lastBroadcastError === undefined)
            this.mode = "fire";
        }
      }
      const st = new FailAfterClear(d);
      st.putRecord(bls);
      const sk = skOf(sinks({ mine: "pending", rejectBroadcast: true }));
      const p1 = await publishPending(st, sk, { maxPendingMs: 0 });
      st.mode = "armed";
      const sk2 = { ...sk, registry: sinks({ mine: "pending" }).registry };
      const p2 = await publishPending(st, sk2, { maxPendingMs: 0 });
      const disk = st.getPublication(Store.recordId(bls))?.registry;
      cell(
        "R15: a run that fails after journalling a cleared stall takes the journal's state (0), not the listing's (1)",
        p1.stalls.insufficientFunds === 1 &&
          st.mode === "fire" &&
          p2.counts.failed >= 1 &&
          disk?.lastBroadcastError === undefined &&
          p2.stalls.insufficientFunds === 0,
        { p1: p1.stalls, mode: st.mode, p2: [p2.counts, p2.stalls], disk }
      );
    } finally {
      rmSync(d, { recursive: true, force: true });
    }
  }
  // R16: a bad file repaired into a valid UNflagged record no longer holds stalls or reverify open
  {
    const d = tmp();
    try {
      const st = new Store(d);
      st.putRecord(bls);
      const sk = skOf(sinks({ mine: "pending" }));
      const plain = {
        ...owner,
        txHash: ethers.id("r16-plain"),
        verdict: { flagged: false, reasons: [] },
      };
      const name = `${Store.recordId(plain)}.json`;
      writeFileSync(join(d, "records", name), "{corrupt");
      const bad = await publishPending(st, sk, { maxPendingMs: 60 * 60_000, reverifyGen: 1 });
      st.putRecord(plain); // repaired
      const after = await publishPending(st, sk, { maxPendingMs: 60 * 60_000, reverifyGen: 1 });
      cell(
        "R16: a repaired unflagged record file clears its unknown entry and leaves no reverify obligation",
        bad.stalls.unknown === true &&
          !after.stalls.unknown &&
          after.reverifyRemaining === 0 &&
          !(Store.recordId(plain) in (st.getSchedule().entries ?? {})),
        { bad: bad.stalls, after: [after.stalls, after.reverifyRemaining] }
      );
    } finally {
      rmSync(d, { recursive: true, force: true });
    }
  }
  // #3: a record file that cannot be read keeps the state unknown, whatever its journal says
  {
    const d = tmp();
    try {
      const st = new Store(d);
      st.putRecord(bls);
      const sk = skOf(sinks({ mine: "pending", rejectBroadcast: true }));
      await publishPending(st, sk, { maxPendingMs: 0 });
      writeFileSync(join(d, "records", `${Store.recordId(bls)}.json`), "{corrupt");
      const fresh = new Store(d);
      const a = await publishPending(fresh, sk, { maxPendingMs: 0 });
      const b = await publishPending(fresh, sk, { maxPendingMs: 0 });
      cell(
        "R15#3: an unreadable record file whose journal was never examined keeps stalls unknown after full sweeps",
        a.stalls.unknown === true &&
          b.stalls.unknown === true &&
          stallCounts(fresh).unknown === true,
        { a: a.stalls, b: b.stalls }
      );
    } finally {
      rmSync(d, { recursive: true, force: true });
    }
  }
}

// ---- DSR (#413): publication is at least once and every sink is idempotent. A crash between a
// sink's effect and its journal write repeats that stage after a restart; the repeat must not
// create a second registry entry or a second mirror commit (Telegram may repeat: accepted).
{
  class CrashOnce extends Store {
    constructor(d, when) {
      super(d);
      this.when = when;
      this.crashed = false;
    }
    putPublication(id, st) {
      if (!this.crashed && this.when(st)) {
        this.crashed = true;
        throw new Error("killed"); // the process dies here: the effect happened, the journal did not
      }
      super.putPublication(id, st);
    }
  }
  // `repeated` proves the stage really ran again after the restart (the cell is not vacuous)
  const points = [
    [
      "after the mirror commit, before it is journalled",
      st => !!st?.mirror?.commit,
      c => c.mirror >= 2,
    ],
    [
      "after the disclose broadcast, before 'sent' is journalled",
      st => st?.registry?.phase === "sent",
      c => c.broadcast >= 2,
    ],
  ];
  for (const [label, when, repeated] of points) {
    const d = tmp();
    try {
      const s = sinks({}); // the outside world (chain, mirror, pins) survives the restart
      const sk = {
        pinners: s.pinners,
        mirror: s.mirror,
        telegram: s.telegram,
        registry: s.registry,
      };
      const crashing = new CrashOnce(d, when);
      crashing.putRecord(bls);
      const first = await publishPending(crashing, sk, { maxPendingMs: 60 * 60_000 });
      const restarted = new Store(d); // a new process on the same data directory
      for (let i = 0; i < 6; i++)
        await publishPending(restarted, sk, { maxPendingMs: 60 * 60_000 });
      const pub = restarted.getPublication(Store.recordId(bls));
      cell(
        `DSR #413: a crash ${label}: after restart one registry entry, one mirror commit, confirmed`,
        crashing.crashed &&
          first.stopped &&
          repeated(s.calls) &&
          s.chain.entries.size === 1 &&
          s.calls.mirrorCommits === 1 &&
          pub?.registry?.phase === "confirmed" &&
          pub?.published === true,
        {
          crashed: crashing.crashed,
          stopped: first.stopped,
          entries: s.chain.entries.size,
          mirrorCommits: s.calls.mirrorCommits,
          mirrorCalls: s.calls.mirror,
          broadcasts: s.calls.broadcast,
          phase: pub?.registry?.phase,
          telegram: s.calls.telegram,
        }
      );
    } finally {
      rmSync(d, { recursive: true, force: true });
    }
  }
}

// ---- #413 review (clestons): B1, F2, F3, N1
{
  const { publicationStep } = await import("./watcher.mjs");
  const step = async run => {
    const status = { ok: true, healthy: true, degraded: undefined }; // a scan that succeeded
    await publicationStep({
      status,
      run,
      slowNote: null,
      iterStart: 0,
      cfg: { intervalMs: 60_000 },
      now: () => 1,
    });
    return status;
  };
  // B1: a thrown pass, a pass that is not ok, and a pass without counts are all degraded
  const thrown = await step(async () => {
    throw new Error("alerts.json: Unexpected token");
  });
  const notOk = await step(async () => ({
    ok: false,
    stalls: { feeCapped: 0, insufficientFunds: 0 },
  }));
  const noCounts = await step(async () => ({ ok: true }));
  const fine = await step(async () => ({
    ok: true,
    stalls: { feeCapped: 0, insufficientFunds: 0 },
  }));
  cell(
    "B1: a publication pass that throws is degraded (healthy false, fixed wording, no foreign text) and its stalls are unknown",
    thrown.healthy === false &&
      thrown.degraded.includes("publication pass failed (see the alerts)") &&
      thrown.degraded.includes("stall state unknown: no publication result") &&
      !JSON.stringify(thrown.degraded).includes("Unexpected token"),
    thrown
  );
  cell(
    "B1: a pass that is not ok, or reports no stall counts, is degraded; an ok pass with counts is not",
    notOk.healthy === false &&
      notOk.degraded.includes("publication pass not ok (a stage failed, stopped or was skipped)") &&
      noCounts.healthy === false &&
      noCounts.degraded.includes("stall state unknown: no publication result") &&
      fine.healthy === true &&
      !fine.degraded,
    { notOk, noCounts, fine }
  );
  // B1 (the trigger): an unreadable alerts.json is reset and alerted; it no longer aborts every pass
  {
    const d = tmp();
    try {
      const store = new Store(d);
      store.putRecord({ ...owner, txHash: ethers.id("b1-alerts") });
      const s = sinks();
      const built = {
        pinners: s.pinners,
        mirror: s.mirror,
        telegram: s.telegram,
        wallet: writer,
        registryFor: () => s.registry,
      };
      const roles = { owner: ethers.getAddress("0x" + "5a".repeat(20)), max: 3, slots: { 1: G1 } };
      writeFileSync(join(d, "alerts.json"), "{corrupt");
      const a = await publishPhase(store, roleChain(roles), cfg, P, built, { now: 5 });
      const b = await publishPhase(store, roleChain(roles), cfg, P, built, { now: 6 });
      cell(
        "B1: a corrupt alerts.json does not abort the pass: reset, alerted, that pass not ok; the next pass is ok",
        a.ok === false &&
          a.ran >= 1 &&
          b.ok === true &&
          JSON.parse(readFileSync(join(d, "alerts.json"), "utf8")) !== null,
        { a: [a.ok, a.ran, a.alerts], b: [b.ok, b.alerts] }
      );
    } finally {
      rmSync(d, { recursive: true, force: true });
    }
  }
  // F2: an "unknown" entry (unreadable journal) does not hold the reverify generation open
  {
    const d = tmp();
    try {
      const store = new Store(d);
      store.putRecord(bls);
      const sk = { pinners: [], mirror: null, telegram: null, registry: null };
      writeFileSync(join(d, "publications", `${Store.recordId(bls)}.json`), "{corrupt");
      const p = await publishPending(store, sk, { reverifyGen: 1 });
      cell(
        "F2: an unreadable journal is unknown AND failing, so reverifyRemaining does not count it",
        p.stalls.unknown === true &&
          p.reverifyRemaining === 0 &&
          store.getSchedule().entries[Store.recordId(bls)]?.failing === true,
        {
          stalls: p.stalls,
          remaining: p.reverifyRemaining,
          entry: store.getSchedule().entries?.[Store.recordId(bls)],
        }
      );
    } finally {
      rmSync(d, { recursive: true, force: true });
    }
  }
  // F3: a successful replacement clears the old tx's broadcast error (no false funding stall)
  {
    const d = tmp();
    try {
      const store = new Store(d);
      store.putRecord(bls);
      const o = { mine: "pending", rejectBroadcast: true };
      const s = sinks(o);
      const sk = {
        pinners: s.pinners,
        mirror: s.mirror,
        telegram: s.telegram,
        registry: s.registry,
      };
      const p1 = await publishPending(store, sk, { maxPendingMs: 0 });
      const firstRaw = store.getPublication(Store.recordId(bls)).registry.raw;
      o.rejectBroadcast = false;
      o.rejectRaw = raw => raw === firstRaw; // the old tx still refused, its replacement accepted
      const p2 = await publishPending(store, sk, { maxPendingMs: 0 });
      const reg = store.getPublication(Store.recordId(bls)).registry;
      cell(
        "F3: after a successful replacement the old broadcast error is gone: no false insufficient-funds stall",
        p1.stalls.insufficientFunds === 1 &&
          reg.raw !== firstRaw &&
          (reg.replacements ?? 0) >= 1 &&
          reg.lastBroadcastError === undefined &&
          p2.stalls.insufficientFunds === 0,
        {
          p1: p1.stalls,
          p2: p2.stalls,
          reg: { raw: reg.raw, rep: reg.replacements, err: reg.lastBroadcastError },
        }
      );
    } finally {
      rmSync(d, { recursive: true, force: true });
    }
  }
  // N1: after an alert, a fresh but unhealthy status (below the unhealthy threshold) is not RECOVERED
  {
    const { check: heartbeat } = await import("../../deploy/guardian-watcher/heartbeat.mjs");
    const d = tmp();
    try {
      let st = {
        alerting: "stale",
        unhealthyRuns: 0,
        lastAt: "x",
        lastAtSeenSince: 0,
        lastSentAt: 0,
      };
      const sent = [];
      const tick = async (at, healthy) =>
        heartbeat({
          cfg: { dataDir: d, intervalMs: 60_000, heartbeat: { label: "t" } },
          now: Date.parse(at),
          readStatus: () =>
            JSON.stringify({ at, healthy, degraded: healthy ? [] : ["x"], lagBlocks: 0 }),
          statMtime: () => Date.parse(at),
          send: async t => (sent.push(t), true),
          readState: () => st,
          writeState: x => ((st = x), true),
        });
      await tick("2026-11-11T00:00:00.000Z", false);
      const afterUnhealthy = sent.some(t => /RECOVERED/.test(t));
      // healthy, but written while the publication is still in progress: not a recovery (R18)
      const inProgress = await heartbeat({
        cfg: { dataDir: d, intervalMs: 60_000, heartbeat: { label: "t" } },
        now: Date.parse("2026-11-11T00:00:30.000Z"),
        readStatus: () =>
          JSON.stringify({
            at: "2026-11-11T00:00:30.000Z",
            healthy: true,
            degraded: [],
            lagBlocks: 0,
            publication: { inProgress: true },
          }),
        statMtime: () => Date.parse("2026-11-11T00:00:30.000Z"),
        send: async t => (sent.push(t), true),
        readState: () => st,
        writeState: x => ((st = x), true),
      });
      void inProgress;
      const afterInProgress = sent.some(t => /RECOVERED/.test(t));
      await tick("2026-11-11T00:01:00.000Z", true);
      cell(
        "N1/R18: no RECOVERED while the status is unhealthy or publication is in progress; RECOVERED once a completed iteration is healthy",
        !afterUnhealthy && !afterInProgress && sent.some(t => /RECOVERED/.test(t)),
        sent
      );
    } finally {
      rmSync(d, { recursive: true, force: true });
    }
  }
}

// ---- Codex W2c R19
{
  const { publicationStep, stallReasons } = await import("./watcher.mjs");
  // #1: an unresolved stage failure stays store-wide while the record is outside later batches
  {
    const d = tmp();
    try {
      const store = new Store(d);
      store.putRecord({ ...owner, txHash: ethers.id("r19-mirror") });
      const o = { mirrorFail: true };
      const s = sinks(o);
      const sk = { pinners: s.pinners, mirror: s.mirror, telegram: s.telegram, registry: null };
      const a = await publishPending(store, sk, {});
      const b = await publishPending(store, sk, { maxParse: 0 });
      const c = await publishPending(store, sk, { maxParse: 0 });
      o.mirrorFail = false;
      const fixed = await publishPending(store, sk, {});
      cell(
        "R19#1: a failing stage keeps the record failing store-wide in later batches without it; a successful retry clears it",
        a.stalls.failing === 1 &&
          b.stalls.failing === 1 &&
          c.stalls.failing === 1 &&
          stallReasons({ stalls: c.stalls }).some(r =>
            /1 record\(s\) failing publication/.test(r)
          ) &&
          fixed.stalls.failing === 0,
        { a: a.stalls, b: b.stalls, c: c.stalls, fixed: fixed.stalls }
      );
    } finally {
      rmSync(d, { recursive: true, force: true });
    }
  }
  // a done record skipped by the listing clears an old failure (its journal restored after being
  // unreadable): the store is not left "failing" by a record that is complete
  {
    const d = tmp();
    try {
      const store = new Store(d);
      const r = { ...owner, txHash: ethers.id("r19-done") };
      store.putRecord(r);
      const s = sinks();
      const sk = { pinners: s.pinners, mirror: s.mirror, telegram: s.telegram, registry: null };
      for (let i = 0; i < 3; i++) await publishPending(store, sk, {});
      const jp = join(d, "publications", `${Store.recordId(r)}.json`);
      const good = readFileSync(jp, "utf8");
      writeFileSync(jp, "{corrupt");
      const broken = await publishPending(store, sk, {});
      writeFileSync(jp, good);
      const back = await publishPending(store, sk, {});
      cell(
        "R19: a complete record skipped as done clears the failure its unreadable journal left",
        broken.stalls.failing === 1 &&
          back.counts.done === 1 &&
          back.counts.ran === 0 &&
          back.stalls.failing === 0,
        { broken: broken.stalls, back: [back.counts, back.stalls] }
      );
    } finally {
      rmSync(d, { recursive: true, force: true });
    }
  }
  // #2: the reasons carried into the interim status are replaced by this pass's result
  {
    const carriedReason = "publication pass not ok (a stage failed, stopped or was skipped)";
    const scanReason = "cursor 999 blocks behind finalized (> 300)";
    const mk = () => ({ ok: true, healthy: false, degraded: [carriedReason] });
    const ok = mk();
    await publicationStep({
      status: ok,
      carried: [carriedReason],
      run: async () => ({ ok: true, stalls: { feeCapped: 0, insufficientFunds: 0, failing: 0 } }),
      slowNote: null,
      iterStart: 0,
      cfg: { intervalMs: 60_000 },
      now: () => 1,
    });
    const withScan = { ok: true, healthy: false, degraded: [scanReason, carriedReason] };
    await publicationStep({
      status: withScan,
      carried: [carriedReason],
      run: async () => ({ ok: true, stalls: { feeCapped: 0, insufficientFunds: 0, failing: 0 } }),
      slowNote: null,
      iterStart: 0,
      cfg: { intervalMs: 60_000 },
      now: () => 1,
    });
    cell(
      "R19#2: a successful pass replaces the carried reasons (healthy); a scan reason stays",
      ok.healthy === true &&
        !ok.degraded &&
        withScan.healthy === false &&
        JSON.stringify(withScan.degraded) === JSON.stringify([scanReason]),
      { ok, withScan }
    );
  }
}

// ---- Codex W2c R20: what still needs attention counts store-wide until the journal says it is over
{
  const { stallReasons } = await import("./watcher.mjs");
  const skOf = s => ({
    pinners: s.pinners,
    mirror: s.mirror,
    telegram: s.telegram,
    registry: s.registry,
  });
  // #1: an unacknowledged revert is an incident (degraded) until acknowledged
  {
    const d = tmp();
    try {
      const store = new Store(d);
      store.putRecord(bls);
      const s = sinks({ mine: "revert" });
      const sk = skOf(s);
      let p;
      for (let i = 0; i < 4; i++)
        p = await publishPending(store, sk, { maxPendingMs: 60 * 60_000 });
      const id = Store.recordId(bls);
      const j = store.getPublication(id);
      const later = await publishPending(store, sk, { maxPendingMs: 60 * 60_000, maxParse: 0 });
      store.putPublication(id, { ...j, registry: { ...j.registry, ack: { by: "test", at: "t" } } });
      const acked = await publishPending(store, sk, { maxPendingMs: 60 * 60_000 });
      cell(
        "R20#1: an unacknowledged reverted disclose is an incident store-wide (also outside the batch) until acknowledged",
        j.registry.phase === "reverted" &&
          p.stalls.incidents === 1 &&
          later.stalls.incidents === 1 &&
          stallReasons({ stalls: later.stalls }).some(r =>
            /1 unresolved registry or bytes incident/.test(r)
          ) &&
          acked.stalls.incidents === 0,
        { phase: j.registry.phase, p: p.stalls, later: later.stalls, acked: acked.stalls }
      );
    } finally {
      rmSync(d, { recursive: true, force: true });
    }
  }
  // #2: a final receipt whose entry is not visible is degraded until a later check finds the entry
  {
    const d = tmp();
    try {
      const store = new Store(d);
      store.putRecord(bls);
      const s = sinks({});
      const sk = skOf(s);
      await publishPending(store, sk, { maxPendingMs: 60 * 60_000 });
      const saved = new Map(s.chain.byAction);
      s.chain.byAction.clear(); // the RPC does not show the entry at the finalized block
      const odd = await publishPending(store, sk, { maxPendingMs: 60 * 60_000 });
      const oddReg = store.getPublication(Store.recordId(bls)).registry;
      for (const [k, v] of saved) s.chain.byAction.set(k, v);
      let ok;
      for (let i = 0; i < 3; i++)
        ok = await publishPending(store, sk, { maxPendingMs: 60 * 60_000 });
      cell(
        "R20#2: a final receipt without a visible entry is 'inconsistent' (degraded) until the entry is confirmed",
        oddReg.phase === "landed" &&
          !!oddReg.inconsistentAt &&
          odd.stalls.inconsistent === 1 &&
          store.getPublication(Store.recordId(bls)).registry.phase === "confirmed" &&
          ok.stalls.inconsistent === 0,
        { odd: odd.stalls, oddReg, ok: ok.stalls }
      );
    } finally {
      rmSync(d, { recursive: true, force: true });
    }
  }
  // #3: a re-verification that cannot reach the gateway is retried every pass until it succeeds
  {
    const d = tmp();
    try {
      const store = new Store(d);
      const r = { ...owner, txHash: ethers.id("r20-gw") };
      store.putRecord(r);
      const s = sinks();
      const sk = { ...skOf(s), registry: null };
      for (let i = 0; i < 3; i++) await publishPending(store, sk, {});
      s.pinOpts.pinata.fetchThrows = true;
      const rv = await publishPending(store, sk, { reverifyGen: 1 });
      const next = await publishPending(store, sk, {}); // an ordinary pass, gateway still down
      s.pinOpts.pinata.fetchThrows = false;
      const fetches0 = s.calls.fetches;
      const healed = await publishPending(store, sk, {});
      cell(
        "R20#3: a failed gateway re-verification is 'unverified' (degraded, not done) and retried each pass until verified",
        rv.stalls.unverified === 1 &&
          next.stalls.unverified === 1 &&
          next.counts.done === 0 &&
          healed.stalls.unverified === 0 &&
          s.calls.fetches > fetches0 &&
          !store.getPublication(Store.recordId(r)).pins.pinata.checkError,
        { rv: rv.stalls, next: [next.stalls, next.counts.done], healed: healed.stalls }
      );
    } finally {
      rmSync(d, { recursive: true, force: true });
    }
  }
}

// ---- Codex W2c R21 (exhaustive enumeration: items 1-3)
{
  const skOf = s => ({
    pinners: s.pinners,
    mirror: s.mirror,
    telegram: s.telegram,
    registry: s.registry,
  });
  // #1: a successful receipt without the Disclosed event is "inconsistent" until resolved
  {
    const d = tmp();
    try {
      const store = new Store(d);
      store.putRecord(bls);
      const s = sinks({});
      const sk = skOf(s);
      await publishPending(store, sk, { maxPendingMs: 60 * 60_000 });
      const kept = new Map();
      for (const [h, rc] of s.chain.receipts) {
        kept.set(h, rc.entryId);
        s.chain.receipts.set(h, { ...rc, entryId: null });
      }
      const odd = await publishPending(store, sk, { maxPendingMs: 60 * 60_000 });
      const outside = await publishPending(store, sk, { maxPendingMs: 60 * 60_000, maxParse: 0 });
      for (const [h, id] of kept)
        s.chain.receipts.set(h, { ...s.chain.receipts.get(h), entryId: id });
      let ok;
      for (let i = 0; i < 3; i++)
        ok = await publishPending(store, sk, { maxPendingMs: 60 * 60_000 });
      cell(
        "R21#1: a receipt without the Disclosed event is 'inconsistent' (also outside the batch) until the entry confirms",
        odd.stalls.inconsistent === 1 &&
          outside.stalls.inconsistent === 1 &&
          store.getPublication(Store.recordId(bls)).registry.phase === "confirmed" &&
          ok.stalls.inconsistent === 0,
        { odd: odd.stalls, outside: outside.stalls, ok: ok.stalls }
      );
    } finally {
      rmSync(d, { recursive: true, force: true });
    }
  }
  // #2: a flagged file whose name cannot be an id stays failing after the sweep, until removed
  {
    const d = tmp();
    try {
      const store = new Store(d);
      const r = { ...owner, txHash: ethers.id("r21-good") };
      store.putRecord(r);
      const rBad = { ...owner, txHash: ethers.id("r21-bad") };
      store.putRecord(rBad);
      renameSync(
        join(d, "records", `${Store.recordId(rBad)}.json`),
        join(d, "records", "a.bad.json")
      );
      const s = sinks();
      const sk = { ...skOf(s), registry: null };
      const passes = [];
      for (let i = 0; i < 4; i++) passes.push(await publishPending(store, sk, { maxParse: 1 }));
      rmSync(join(d, "records", "a.bad.json"));
      const after = [];
      for (let i = 0; i < 3; i++) after.push(await publishPending(store, sk, { maxParse: 1 }));
      cell(
        "R21#2: a bad file name stays counted as failing in every later batch; gone, it clears",
        passes.every(p => p.stalls.failing >= 1) && after.at(-1).stalls.failing === 0,
        { passes: passes.map(p => p.stalls.failing), after: after.map(p => p.stalls.failing) }
      );
    } finally {
      rmSync(d, { recursive: true, force: true });
    }
  }
  // #3: a failed check on a provider that is no longer configured does not hold the record
  {
    const d = tmp();
    try {
      const store = new Store(d);
      const r = { ...owner, txHash: ethers.id("r21-pin") };
      store.putRecord(r);
      const s = sinks();
      const sk = { ...skOf(s), registry: null };
      for (let i = 0; i < 3; i++) await publishPending(store, sk, {});
      s.pinOpts.pinata.fetchThrows = true;
      const rv = await publishPending(store, sk, { reverifyGen: 1 });
      const onlyFilebase = { ...sk, pinners: s.pinners.filter(p => p.name === "filebase") };
      const later = await publishPending(store, onlyFilebase, {});
      cell(
        "R21#3: an unconfigured provider's failed check is not 'unverified' and does not keep the record from done",
        rv.stalls.unverified === 1 && later.stalls.unverified === 0 && later.counts.done === 1,
        { rv: rv.stalls, later: [later.stalls, later.counts.done] }
      );
    } finally {
      rmSync(d, { recursive: true, force: true });
    }
  }
}

// ---- Codex W2c R22: a record file's name never reaches an alert, the saved details or Telegram
{
  const d = tmp();
  try {
    const store = new Store(d);
    store.putRecord({ ...owner, txHash: ethers.id("r22-good") });
    const SENT = "private-TOKEN9z7q";
    writeFileSync(join(d, "records", `${SENT}.json`), "{not a record");
    writeFileSync(join(d, "records", `x.${SENT}.json`), "{not a record");
    const s = sinks();
    const built = {
      pinners: s.pinners,
      mirror: s.mirror,
      telegram: s.telegram,
      wallet: writer,
      registryFor: () => s.registry,
    };
    const roles = { owner: ethers.getAddress("0x" + "5a".repeat(20)), max: 3, slots: { 1: G1 } };
    const out = await publishPhase(store, roleChain(roles), cfg, P, built, { now: 5 });
    const saved = readFileSync(join(d, "alerts-latest.json"), "utf8");
    cell(
      "R22: a file name (a sentinel token) is in no returned alert, not in alerts-latest.json, not in any Telegram text",
      out.unreadable === 2 &&
        !JSON.stringify(out).includes(SENT) &&
        !saved.includes(SENT) &&
        s.calls.texts.length > 0 &&
        !s.calls.texts.some(t => t.includes(SENT)),
      { unreadable: out.unreadable, saved: saved.slice(0, 300), texts: s.calls.texts.length }
    );
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
}

// ---- Codex W2c R23 #1: the publish config refuses a credentialed mirror.repoUrl
{
  const SENT = "private-TOKEN9z7q";
  const msgs = [];
  for (const u of [`https://user:${SENT}@github.com/o/r`, `https://github.com/o/r?t=${SENT}`]) {
    try {
      publishConfig({ ...good, mirror: { ...good.mirror, repoUrl: u } });
      msgs.push(null);
    } catch (e) {
      msgs.push(e.message);
    }
  }
  const ok = publishConfig({
    ...good,
    mirror: { ...good.mirror, repoUrl: "https://github.com/o/r" },
  });
  cell(
    "R23#1: publishConfig refuses a mirror.repoUrl with credentials or a query, names the rule, never echoes it",
    msgs.every(
      m => m === "config.publish: mirror.repoUrl must be https://github.com/<owner>/<repo>"
    ) && !!ok,
    msgs
  );
}

// ---- W2d (DSR): the registry stage is bound to its registry (address and chain)
{
  const skOf = s => ({
    pinners: s.pinners,
    mirror: s.mirror,
    telegram: s.telegram,
    registry: s.registry,
  });
  const OLD = "0x" + "aa".repeat(20);
  const NEW = "0x" + "bb".repeat(20);
  // (a) a record confirmed on the old registry is disclosed again on the new one; degraded until
  // it is confirmed there
  {
    const d = tmp();
    try {
      const store = new Store(d);
      store.putRecord(bls);
      const a = sinks({ registryAddress: OLD });
      for (let i = 0; i < 4; i++)
        await publishPending(store, skOf(a), { maxPendingMs: 60 * 60_000 });
      const before = store.getPublication(Store.recordId(bls)).registry;
      const b = sinks({ registryAddress: NEW });
      const passes = [];
      for (let i = 0; i < 5; i++)
        passes.push(await publishPending(store, skOf(b), { maxPendingMs: 60 * 60_000 }));
      const after = store.getPublication(Store.recordId(bls));
      cell(
        "W2d(a): a record confirmed on the old registry is disclosed again on the new one, degraded (migrating) until confirmed there",
        before.phase === "confirmed" &&
          before.at?.address === OLD &&
          b.chain.entries.size === 1 &&
          after.registry.phase === "confirmed" &&
          after.registry.at?.address === NEW &&
          after.registryHistory?.[0]?.at?.address === OLD &&
          passes[0].stalls.migrating === 1 &&
          passes.at(-1).stalls.migrating === 0 &&
          !passes.at(-1).stalls.unknown,
        {
          before: [before.phase, before.at],
          entries: b.chain.entries.size,
          after: [after.registry.phase, after.registry.at],
          stalls: passes.map(p => p.stalls),
        }
      );
    } finally {
      rmSync(d, { recursive: true, force: true });
    }
  }
  // (b) a disclose signed for the old registry and not confirmed is never broadcast again; the new
  // registry's writer signs a new one
  {
    const d = tmp();
    try {
      const store = new Store(d);
      store.putRecord(bls);
      const a = sinks({ registryAddress: OLD, mine: "pending" });
      await publishPending(store, skOf(a), { maxPendingMs: 60 * 60_000 });
      const oldReg = store.getPublication(Store.recordId(bls)).registry;
      const oldRaws = oldReg.raws ?? [oldReg.raw];
      const aBroadcasts = a.calls.broadcast;
      const b = sinks({ registryAddress: NEW, rawTag: "b" });
      b.chain.nonce = oldReg.nonce + 1; // its nonce consumed (else the switch waits: B2-A)
      for (let i = 0; i < 4; i++) await publishPending(store, skOf(b), { maxPendingMs: 0 });
      const after = store.getPublication(Store.recordId(bls)).registry;
      cell(
        "W2d(b): an old registry's unconfirmed disclose is never broadcast again (not through the new sink, not to the old one); a new one is signed and confirmed",
        oldReg.phase === "sent" &&
          a.calls.broadcast === aBroadcasts &&
          !(b.calls.raws ?? []).some(r => oldRaws.includes(r)) &&
          b.calls.sign >= 1 &&
          after.phase === "confirmed" &&
          after.at?.address === NEW,
        {
          oldPhase: oldReg.phase,
          aB: [aBroadcasts, a.calls.broadcast],
          bRaws: b.calls.raws,
          oldRaws,
          after: [after.phase, after.at],
        }
      );
    } finally {
      rmSync(d, { recursive: true, force: true });
    }
  }
  // (d) after a switch the store-wide counts are unknown until a sweep has re-read every record
  // (3 records, one read per pass)
  {
    const d = tmp();
    try {
      const store = new Store(d);
      const recs = [0, 1, 2].map(i => ({
        ...bls,
        key: String(8100 + i),
        proposalId: String(8100 + i),
        txHash: ethers.id(`w2d-d-${i}`),
      }));
      for (const r of recs) store.putRecord(r);
      const a = sinks({ registryAddress: OLD });
      for (let i = 0; i < 4; i++)
        await publishPending(store, skOf(a), { maxPendingMs: 60 * 60_000 });
      const b = sinks({ registryAddress: NEW, rawTag: "d" });
      const p1 = await publishPending(store, skOf(b), { maxPendingMs: 60 * 60_000, maxParse: 1 });
      cell(
        "W2d(d): right after a registry switch the counts are unknown (degraded) until a sweep re-read every record",
        p1.stalls.unknown === true && p1.alerts.some(x => /configured registry changed/.test(x)),
        { stalls: p1.stalls }
      );
      // records read but deferred by the run budget are counted as migrating from their journal
      const p2 = await publishPending(store, skOf(b), { maxPendingMs: 60 * 60_000, maxRecords: 0 });
      const { stallReasons } = await import("./watcher.mjs");
      cell(
        "W2d(d): deferred records whose stage is for another registry count as migrating (a fixed degraded reason)",
        p2.counts.ran === 0 &&
          p2.stalls.migrating === 3 &&
          stallReasons({ stalls: p2.stalls }).includes(
            "3 record(s) not yet confirmed on the configured registry (registry switched)"
          ),
        { counts: p2.counts, stalls: p2.stalls }
      );
    } finally {
      rmSync(d, { recursive: true, force: true });
    }
  }
  // (e) an incident acknowledged on the old registry does not park the record on the new one
  {
    const d = tmp();
    try {
      const store = new Store(d);
      store.putRecord(bls);
      const a = sinks({ registryAddress: OLD, mine: "revert" });
      for (let i = 0; i < 4; i++)
        await publishPending(store, skOf(a), { maxPendingMs: 60 * 60_000 });
      const id = Store.recordId(bls);
      const j = store.getPublication(id);
      store.putPublication(id, { ...j, registry: { ...j.registry, ack: { by: "t", at: "t" } } });
      const b = sinks({ registryAddress: NEW, rawTag: "e" });
      for (let i = 0; i < 4; i++)
        await publishPending(store, skOf(b), { maxPendingMs: 60 * 60_000 });
      const after = store.getPublication(id).registry;
      cell(
        "W2d(e): an incident acknowledged on the old registry is not parked on the new one: disclosed and confirmed there",
        j.registry.phase === "reverted" && after.phase === "confirmed" && after.at?.address === NEW,
        { old: j.registry.phase, after: [after.phase, after.at] }
      );
    } finally {
      rmSync(d, { recursive: true, force: true });
    }
  }
  // (f) a stage journalled before W2d (no `at`) is bound by its signed transaction's to/chainId;
  // without a transaction it is taken as the configured registry (no deployment predates W2d)
  {
    const { registryAt, sameRegistry } = await import("./lib/publish.mjs");
    const w = ethers.Wallet.createRandom();
    const raw = await w.signTransaction({
      type: 2,
      to: ethers.getAddress(OLD),
      chainId: 10,
      nonce: 0,
      gasLimit: 100000n,
      maxFeePerGas: 1000n,
      maxPriorityFeePerGas: 1n,
      data: "0x",
    });
    const fromRaw = registryAt({ phase: "sent", raw });
    const none = registryAt({ phase: "confirmed" });
    const here = { address: OLD, chainId: "10" };
    cell(
      "W2d(f): a pre-W2d journal is bound by its signed tx (to, chainId); one without a tx matches no registry (checked on chain)",
      fromRaw?.address === OLD &&
        fromRaw.chainId === "10" &&
        sameRegistry(fromRaw, here) &&
        !sameRegistry(fromRaw, { address: NEW, chainId: "10" }) &&
        !sameRegistry(fromRaw, { address: OLD, chainId: "11155111" }) &&
        none === null &&
        !sameRegistry(none, here),
      { fromRaw, none }
    );
  }
  // (g) DSR: a legacy stage without `at` or a tx is checked ON CHAIN against the configured
  // registry before it counts: (i) a matching entry there -> confirmed without signing;
  // (ii) no entry -> disclosed again; (iii) the query fails -> not done, degraded
  {
    const { expectedBinding } = await import("./lib/publish.mjs");
    const { recordFile } = await import("./lib/record-file.mjs");
    const legacy = (store, phase = "confirmed") => {
      const id = Store.recordId(bls);
      const j = store.getPublication(id);
      const { at: _a, raw: _r, raws: _rs, ...rest } = j.registry;
      (void _a, _r, _rs);
      store.putPublication(id, { ...j, registry: { ...rest, phase } });
    };
    const publishAll = async (store, s) => {
      for (let i = 0; i < 4; i++)
        await publishPending(store, skOf(s), { maxPendingMs: 60 * 60_000 });
    };
    // (i)
    {
      const d = tmp();
      try {
        const store = new Store(d);
        store.putRecord(bls);
        const f = recordFile(
          JSON.parse(readFileSync(join(d, "records", `${Store.recordId(bls)}.json`), "utf8"))
        );
        const s = sinks({
          registryAddress: OLD,
          existing: {
            binding: expectedBinding(bls),
            recordURI: `ipfs://${f.cid}`,
            recordHash: f.recordHash,
          },
        });
        await publishAll(store, s);
        legacy(store);
        const signs = s.calls.sign;
        await publishAll(store, s);
        const r = store.getPublication(Store.recordId(bls)).registry;
        cell(
          "W2d(g-i): a legacy confirmed stage with a matching entry on the current registry is confirmed by that entry, without signing",
          r.phase === "confirmed" &&
            r.entryId === "9" &&
            r.at?.address === OLD &&
            s.calls.sign === signs,
          { r, signs: [signs, s.calls.sign] }
        );
      } finally {
        rmSync(d, { recursive: true, force: true });
      }
    }
    // (ii)
    {
      const d = tmp();
      try {
        const store = new Store(d);
        store.putRecord(bls);
        const a = sinks({ registryAddress: OLD });
        await publishAll(store, a);
        legacy(store);
        const fresh = sinks({ registryAddress: OLD, rawTag: "g" }); // the same address, no entry on it
        await publishAll(store, fresh);
        const r = store.getPublication(Store.recordId(bls)).registry;
        cell(
          "W2d(g-ii): a legacy confirmed stage with no entry on the current registry is disclosed again there",
          fresh.calls.sign >= 1 &&
            fresh.chain.entries.size === 1 &&
            r.phase === "confirmed" &&
            r.at?.address === OLD,
          { r, sign: fresh.calls.sign, entries: fresh.chain.entries.size }
        );
      } finally {
        rmSync(d, { recursive: true, force: true });
      }
    }
    // (iii)
    {
      const d = tmp();
      try {
        const store = new Store(d);
        store.putRecord(bls);
        const a = sinks({ registryAddress: OLD });
        await publishAll(store, a);
        legacy(store);
        const down = sinks({ registryAddress: OLD });
        const reg = {
          ...down.registry,
          entryOf: async () => {
            throw new Error("rpc down");
          },
        };
        const p = await publishPending(
          store,
          { ...skOf(down), registry: reg },
          { maxPendingMs: 60 * 60_000 }
        );
        const r = store.getPublication(Store.recordId(bls)).registry;
        cell(
          "W2d(g-iii): a legacy stage whose check on the current registry fails is not done and the watcher is degraded",
          p.counts.done === 0 &&
            p.counts.failed >= 1 &&
            (p.stalls.failing >= 1 || p.stalls.migrating >= 1) &&
            r?.phase !== "confirmed",
          { counts: p.counts, stalls: p.stalls, r }
        );
      } finally {
        rmSync(d, { recursive: true, force: true });
      }
    }
  }
  // (h) Codex W2d R2: a pass without a registry sink (writer-role check failed) still judges
  // records against the CONFIGURED registry: migration does not clear before they are reconciled
  {
    const d = tmp();
    try {
      const store = new Store(d);
      const recs = [0, 1, 2].map(i => ({
        ...bls,
        key: String(8200 + i),
        proposalId: String(8200 + i),
        txHash: ethers.id(`w2d-h-${i}`),
      }));
      for (const r of recs) store.putRecord(r);
      const a = sinks({ registryAddress: OLD });
      for (let i = 0; i < 4; i++)
        await publishPending(store, skOf(a), { maxPendingMs: 60 * 60_000 });
      const b = sinks({ registryAddress: NEW, rawTag: "h" });
      const whereB = { address: NEW, chainId: "11155111" };
      await publishPending(store, skOf(b), { maxPendingMs: 60 * 60_000, maxParse: 1 });
      // the role check fails: no registry sink this pass, the configured registry is still B
      const noSink = await publishPending(
        store,
        { ...skOf(b), registry: null },
        { maxPendingMs: 60 * 60_000, configuredRegistry: whereB }
      );
      // publishPhase passes the configured registry itself when the role read fails
      const { publishPhase } = await import("./lib/publisher.mjs");
      const broken = {
        async call() {
          throw new Error("down");
        },
      };
      const built = {
        pinners: b.pinners,
        mirror: b.mirror,
        telegram: b.telegram,
        wallet: writer,
        registryFor: () => b.registry,
      };
      const ph = await publishPhase(
        store,
        broken,
        { ...cfg, chainId: 11155111 },
        { ...P, registry: { ...P.registry, address: NEW } },
        built,
        { now: 7 }
      );
      cell(
        "W2d(h): without a registry sink (role check failed) records still on A count as migrating and not done; publishPhase passes the configured registry",
        noSink.stalls.migrating >= 2 &&
          noSink.counts.done <= 1 &&
          !!ph.registrySkipped &&
          ph.stalls.migrating >= 2,
        { noSink: [noSink.counts, noSink.stalls], ph: [ph.registrySkipped, ph.stalls] }
      );
    } finally {
      rmSync(d, { recursive: true, force: true });
    }
  }
  // (i) #425 review B1: the chain switched at the same address while the RPC still serves the old
  // chain: nothing is adopted or stamped on the new chain; the stage fails (degraded)
  {
    const d = tmp();
    try {
      const store = new Store(d);
      store.putRecord(bls);
      const a = sinks({ registryAddress: OLD, chainId: 10 });
      for (let i = 0; i < 4; i++)
        await publishPending(store, skOf(a), { maxPendingMs: 60 * 60_000 });
      // the same node (chain 10, the entry is there), the config now says chain 8453
      const regB = { ...a.registry, chainId: 8453n };
      const signs = a.calls.sign;
      let p;
      for (let i = 0; i < 3; i++)
        p = await publishPending(
          store,
          { ...skOf(a), registry: regB },
          { maxPendingMs: 60 * 60_000 }
        );
      const r = store.getPublication(Store.recordId(bls)).registry;
      cell(
        "W2d(i) B1: an RPC serving another chain than the configured one adopts and stamps nothing there; the stage fails, the watcher is degraded",
        r?.phase !== "confirmed" &&
          a.calls.sign === signs &&
          p.counts.failed >= 1 &&
          (p.stalls.migrating ?? 0) >= 1,
        { r, signs: [signs, a.calls.sign], counts: p.counts, stalls: p.stalls }
      );
    } finally {
      rmSync(d, { recursive: true, force: true });
    }
  }
  // ---- #425 review B2, DSR option A: a same-writer, same-chain switch waits for the old nonce
  {
    const { stallReasons } = await import("./watcher.mjs");
    const { nonceGaps } = await import("./lib/publisher.mjs");
    const { planFill, runFill } = await import("../../deploy/guardian-watcher/fill-nonce.mjs");
    const CC = "0x" + "cc".repeat(20);
    const W2 = "0x" + "88".repeat(20);
    const whereOf = (address, chainId = "11155111") => ({ address, chainId });
    const id = Store.recordId(bls);
    // the record's disclose on A by the default writer, sent at nonce 5 and still pending
    const onA = async () => {
      const d = tmp();
      const store = new Store(d);
      store.putRecord(bls);
      const a = sinks({ registryAddress: OLD, mine: "pending" });
      a.chain.nonce = 5;
      await publishPending(store, skOf(a), { maxPendingMs: 60 * 60_000 });
      return { d, store, old: store.getPublication(id).registry };
    };
    const pass = (store, s, o = {}) =>
      publishPending(store, skOf(s), { maxPendingMs: 60 * 60_000, ...o });
    // (a) waits until the old nonce is consumed at the FINALIZED block, then archives and discloses
    // again; an entry already on the new registry is not adopted while waiting (Codex W2d R7 #3)
    {
      const x = await onA();
      const b = sinks({ registryAddress: NEW, rawTag: "a" });
      b.chain.nonce = 5;
      b.chain.known.add(x.old.hash);
      const p1 = await pass(x.store, b);
      const j1 = x.store.getPublication(id);
      b.chain.latestNonce = 6; // mined, not yet finalized
      const p2 = await pass(x.store, b);
      const j2 = x.store.getPublication(id);
      const signsWaiting = b.calls.sign;
      b.chain.nonce = 6; // consumed at the finalized block
      b.chain.latestNonce = undefined;
      const after = [];
      for (let i = 0; i < 4; i++) after.push(await pass(x.store, b));
      const jf = x.store.getPublication(id);
      // R7 #3: the same record's entry is already on B (published from another store)
      const y = await onA();
      const b2 = sinks({ registryAddress: NEW, rawTag: "a2" });
      {
        const d2 = tmp();
        const other = new Store(d2);
        other.putRecord(bls);
        for (let i = 0; i < 4; i++) await pass(other, b2);
        rmSync(d2, { recursive: true, force: true });
      }
      b2.chain.nonce = 5;
      b2.chain.known.add(y.old.hash);
      const signs0 = b2.calls.sign;
      await pass(y.store, b2);
      await pass(y.store, b2);
      const yw = y.store.getPublication(id);
      b2.chain.nonce = 6;
      for (let i = 0; i < 3; i++) await pass(y.store, b2);
      const yf = y.store.getPublication(id);
      cell(
        "B2-A(a): a same-writer same-chain switch waits (degraded, nonce named) until the old nonce is consumed at the finalized block, then archives and is confirmed on the new registry; an existing entry there is adopted only after the wait",
        x.old.phase === "sent" &&
          x.old.nonce === 5 &&
          j1.registry.at?.address === OLD &&
          j1.registryWait?.nonce === 5 &&
          !j1.registryHistory &&
          p1.stalls.nonceWait === 1 &&
          p1.stalls.waitNonces?.[0] === 5 &&
          stallReasons({ stalls: p1.stalls }).some(r => /nonce\(s\) 5 to be consumed/.test(r)) &&
          j2.registryWait?.nonce === 5 &&
          p2.stalls.nonceWait === 1 &&
          signsWaiting === 0 &&
          b.calls.sign >= 1 &&
          b.calls.lastSignOpts?.nonce === undefined &&
          jf.registry.phase === "confirmed" &&
          jf.registry.at?.address === NEW &&
          jf.registryHistory?.[0]?.nonce === 5 &&
          !jf.registryWait &&
          after.at(-1).stalls.nonceWait === 0 &&
          yw.registryWait?.nonce === 5 &&
          yw.registry.at?.address === OLD &&
          yf.registry.phase === "confirmed" &&
          yf.registry.at?.address === NEW &&
          b2.calls.sign === signs0,
        {
          j1: [j1.registry.at, j1.registryWait, p1.stalls],
          j2: [j2.registryWait, p2.stalls],
          signs: [signsWaiting, b.calls.sign, b.calls.lastSignOpts],
          jf: [jf.registry.phase, jf.registry.at, jf.registryWait],
          y: [yw.registryWait, yw.registry.at, yf.registry.phase, b2.calls.sign, signs0],
        }
      );
      for (const z of [x, y]) rmSync(z.d, { recursive: true, force: true });
    }
    // (b) while waiting nothing is broadcast or re-priced, past maxPendingMs and through a second
    // switch (A -> B -> C, Codex W2d R6): still waiting for A's nonce
    {
      const x = await onA();
      const b = sinks({ registryAddress: NEW, rawTag: "b", mine: "pending" });
      b.chain.nonce = 5;
      b.chain.known.add(x.old.hash);
      for (let i = 0; i < 4; i++) await pass(x.store, b, { maxPendingMs: 0 });
      const jb = x.store.getPublication(id);
      const c = sinks({ registryAddress: CC, rawTag: "c", mine: "pending" });
      c.chain.nonce = 5;
      c.chain.known.add(x.old.hash);
      const pc = await pass(x.store, c, { maxPendingMs: 0 });
      const jc = x.store.getPublication(id);
      cell(
        "B2-A(b): waiting, nothing is signed, broadcast or replaced (past maxPendingMs too), the old tx's journal is unchanged; a further switch (A -> B -> C) still waits for A's nonce",
        b.calls.sign === 0 &&
          b.calls.broadcast === 0 &&
          c.calls.sign === 0 &&
          c.calls.broadcast === 0 &&
          JSON.stringify(jb.registry.hashes) === JSON.stringify(x.old.hashes) &&
          jb.registry.replacements === undefined &&
          jc.registryWait?.nonce === 5 &&
          jc.registry.at?.address === OLD &&
          pc.stalls.nonceWait === 1,
        {
          b: [b.calls.sign, b.calls.broadcast],
          c: [c.calls.sign, c.calls.broadcast],
          jb: [jb.registry.hashes, jb.registry.replacements],
          jc: [jc.registryWait, jc.registry.at, pc.stalls],
        }
      );
      rmSync(x.d, { recursive: true, force: true });
    }
    // (c) the old tx evicted: degraded for good; fill-nonce consumes the nonce and the record then
    // completes on the new registry
    {
      const x = await onA();
      const b = sinks({ registryAddress: NEW, rawTag: "c", fillMines: true });
      b.chain.nonce = 5; // evicted: A's hash is not known
      const waiting = [];
      for (let i = 0; i < 5; i++) waiting.push(await pass(x.store, b));
      const signsWaiting = b.calls.sign;
      const r = await runFill(
        x.store,
        b.registry,
        whereOf(NEW),
        5,
        "old disclose evicted",
        () => "T"
      );
      let fills = [];
      try {
        fills = JSON.parse(readFileSync(join(x.d, "nonce-fills.json"), "utf8")).fills;
      } catch {
        fills = []; // no fill journalled
      }
      const after = [];
      for (let i = 0; i < 4; i++) after.push(await pass(x.store, b));
      const jf = x.store.getPublication(id);
      cell(
        "B2-A(c): the old tx evicted, the record stays waiting and degraded on every pass; fill-nonce fills nonce 5 (journalled pending -> applied), then the record is archived and confirmed on the new registry",
        waiting.every(p => p.stalls.nonceWait === 1) &&
          signsWaiting === 0 &&
          r.code === 0 &&
          JSON.stringify(b.calls.fills) === "[5]" &&
          fills.length === 1 &&
          fills[0].applied === true &&
          fills[0].basis === "wait" &&
          fills[0].ids?.[0] === id &&
          typeof fills[0].hash === "string" &&
          jf.registry.phase === "confirmed" &&
          jf.registry.at?.address === NEW &&
          !jf.registryWait &&
          after.at(-1).stalls.nonceWait === 0,
        {
          waiting: waiting.map(p => p.stalls.nonceWait),
          r,
          fills,
          jf: [jf.registry.phase, jf.registry.at, jf.registryWait],
        }
      );
      rmSync(x.d, { recursive: true, force: true });
    }
    // (d) the store-wide nonce gap: W1 -> W2 -> W1 (Codex W2d R7 #2), through publishPhase
    {
      const x = await onA(); // W1 (default writer), nonce 5, pending
      const b = sinks({ registryAddress: NEW, rawTag: "d", writer: W2, mine: "pending" });
      await pass(x.store, b); // another writer: archived at once, disclosed by W2 on B
      const c = sinks({ registryAddress: CC, rawTag: "d2", mine: "pending" });
      c.chain.nonce = 5;
      c.chain.latestNonce = 5;
      c.chain.pendingNonce = 6; // A's tx at 5 still in a mempool, held by no active stage
      c.chain.known.add(x.old.hash);
      const built = {
        pinners: c.pinners,
        mirror: c.mirror,
        telegram: c.telegram,
        wallet: writer,
        registryFor: () => c.registry,
      };
      const healthy = {
        owner: ethers.getAddress("0x" + "5a".repeat(20)),
        max: 3,
        slots: { 1: G1 },
      };
      const phP = { ...P, registry: { ...P.registry, address: CC } };
      const phCfg = { ...cfg, chainId: 11155111 };
      let ph;
      for (let i = 0; i < 3; i++)
        ph = await publishPhase(x.store, roleChain(healthy), phCfg, phP, built, { now: 7 + i });
      const failing = sinks({ registryAddress: CC, rawTag: "d3", nonceRangeFail: true });
      const phF = await publishPhase(
        x.store,
        roleChain(healthy),
        phCfg,
        phP,
        { ...built, registryFor: () => failing.registry },
        { now: 20 }
      );
      const w = "0x" + "ab".repeat(20);
      const held = n => ({ nonceUse: { from: w, chainId: "1", nonce: n } });
      const inPool = nonceGaps({}, w, "1", { latest: 5, pending: 6 });
      const below = nonceGaps({ r: held(6) }, w, "1", { latest: 5, pending: 5 });
      const none = nonceGaps({ r: held(5), s: held(6) }, w, "1", { latest: 5, pending: 7 });
      cell(
        "B2-A(d): a writer nonce pending or skipped that no active stage holds is degraded (W1 -> W2 -> W1 through publishPhase; an eviction below a held nonce); a failed check is degraded too; a fully held range is not",
        ph.stalls.nonceGaps?.includes(5) &&
          stallReasons(ph).some(r => /nonce\(s\) 5\b.*held by no journal/.test(r)) &&
          phF.stalls.nonceGapUnknown === true &&
          stallReasons(phF).includes("writer nonce gap check failed") &&
          JSON.stringify(inPool) === "[5]" &&
          JSON.stringify(below) === "[5]" &&
          JSON.stringify(none) === "[]",
        { ph: [ph.registrySkipped, ph.stalls], phF: phF.stalls, inPool, below, none }
      );
      rmSync(x.d, { recursive: true, force: true });
    }
    // (e) fill-nonce refuses: a nonce held on the current registry, a nonce that is no gap, a
    // consumed one, an old tx still known, a reason with a URL; a real gap is accepted
    {
      const x = await onA();
      const b = sinks({ registryAddress: NEW, rawTag: "e", writer: W2, mine: "pending" });
      b.chain.nonce = 7;
      await pass(x.store, b); // W2 holds nonce 7 on the current registry B
      b.chain.known.clear(); // not even known: only the current-registry rule refuses it
      const held = await planFill(x.store, b.registry, whereOf(NEW), 7);
      const noGap = await planFill(x.store, b.registry, whereOf(NEW), 9);
      const consumed = await planFill(x.store, b.registry, whereOf(NEW), 3);
      b.chain.pendingNonce = 9; // 8 pending in a mempool, held by no journal
      const gap = await planFill(x.store, b.registry, whereOf(NEW), 8);
      const url = await runFill(x.store, b.registry, whereOf(NEW), 8, "see https://x/y");
      // a waiting record whose old tx a node still knows
      const y = await onA();
      const c = sinks({ registryAddress: NEW, rawTag: "e2" });
      c.chain.nonce = 5;
      c.chain.known.add(y.old.hash);
      await pass(y.store, c);
      const known = await planFill(y.store, c.registry, whereOf(NEW), 5);
      cell(
        "B2-A(e): fill-nonce refuses a nonce held by a current-registry stage, one that is no gap, a consumed one, an old tx still known, a reason with a URL; a real gap is accepted",
        /held by .* on the current registry/.test(held.refuse ?? "") &&
          /neither waited for/.test(noGap.refuse ?? "") &&
          /already consumed/.test(consumed.refuse ?? "") &&
          gap.basis === "gap" &&
          url.code === 1 &&
          !(b.calls.fills ?? []).length &&
          /still known/.test(known.refuse ?? "") &&
          !(c.calls.fills ?? []).length,
        { held, noGap, consumed, gap, url, known }
      );
      for (const z of [x, y]) rmSync(z.d, { recursive: true, force: true });
    }
    // (f) another writer (the M0 §5.5a recovery) or another chain has its own nonce space: no wait;
    // a stage already waiting is archived at once when the chain changes (Codex W2d R7 #1)
    {
      const x = await onA();
      const b = sinks({ registryAddress: NEW, rawTag: "f", writer: W2 });
      b.chain.nonce = 5;
      b.chain.known.add(x.old.hash);
      for (let i = 0; i < 4; i++) await pass(x.store, b);
      const jw = x.store.getPublication(id);
      const y = await onA();
      const c = sinks({ registryAddress: NEW, rawTag: "f2" });
      c.chain.nonce = 5;
      c.chain.known.add(y.old.hash);
      await pass(y.store, c); // waiting on the same chain
      const yw = y.store.getPublication(id);
      const c10 = sinks({ registryAddress: NEW, rawTag: "f3", chainId: 10 });
      c10.chain.nonce = 0;
      for (let i = 0; i < 4; i++) await pass(y.store, c10);
      const yc = y.store.getPublication(id);
      cell(
        "B2-A(f): a new writer (M0 §5.5a) or a new chain does not wait: archived at once, disclosed and confirmed without a forced nonce; a waiting stage is released at once by a chain change",
        !jw.registryWait &&
          jw.registryHistory?.[0]?.nonce === 5 &&
          jw.registry.phase === "confirmed" &&
          jw.registry.at?.address === NEW &&
          b.calls.lastSignOpts?.nonce === undefined &&
          yw.registryWait?.nonce === 5 &&
          !yc.registryWait &&
          yc.registry.phase === "confirmed" &&
          yc.registry.at?.chainId === "10" &&
          c10.calls.lastSignOpts?.nonce === undefined,
        {
          jw: [jw.registryWait, jw.registry.phase, jw.registry.at, b.calls.lastSignOpts],
          yw: yw.registryWait,
          yc: [yc.registryWait, yc.registry.phase, yc.registry.at],
        }
      );
      for (const z of [x, y]) rmSync(z.d, { recursive: true, force: true });
    }
  }
  // (c) the same address on another chain is another registry
  {
    const d = tmp();
    try {
      const store = new Store(d);
      store.putRecord(bls);
      const a = sinks({ registryAddress: OLD, chainId: 11155111 });
      for (let i = 0; i < 4; i++)
        await publishPending(store, skOf(a), { maxPendingMs: 60 * 60_000 });
      const b = sinks({ registryAddress: OLD, chainId: 10 });
      const first = await publishPending(store, skOf(b), { maxPendingMs: 60 * 60_000 });
      for (let i = 0; i < 4; i++)
        await publishPending(store, skOf(b), { maxPendingMs: 60 * 60_000 });
      const after = store.getPublication(Store.recordId(bls)).registry;
      cell(
        "W2d(c): the same address with another chainId triggers the switch: disclosed again on the configured chain",
        first.stalls.migrating === 1 &&
          b.chain.entries.size === 1 &&
          after.phase === "confirmed" &&
          after.at?.chainId === "10",
        { first: first.stalls, entries: b.chain.entries.size, after: [after.phase, after.at] }
      );
    } finally {
      rmSync(d, { recursive: true, force: true });
    }
  }
}

// ---- Codex D-RPC2 R6: a permanent hold does not keep the store's reverify generation open
{
  const d = tmp();
  try {
    const store = new Store(d);
    const a = { ...owner, txHash: ethers.id("r6-published") };
    const b = { ...owner, txHash: ethers.id("r6-held") };
    store.putRecord(a);
    store.putRecord(b);
    // b's confirmation never came: held for good (unconfirmed-final), never publishable
    const bid = Store.recordId(b);
    atomicWriteJson(join(d, "holds", `${bid}.json`), {
      id: bid,
      state: "unconfirmed-final",
      attempts: 10,
    });
    const s = sinks();
    const sk = { pinners: s.pinners, mirror: s.mirror, telegram: s.telegram, registry: null };
    for (let i = 0; i < 3; i++) await publishPending(store, sk, {});
    const f0 = s.calls.fetches ?? 0;
    const r1 = await publishPending(store, sk, { reverifyGen: 1 });
    const r2 = await publishPending(store, sk, { reverifyGen: 2 });
    cell(
      "R6: with one record held for good, a reverify generation still completes (remaining 0) and the next one re-checks the published record's pins again",
      r1.counts.held === 1 &&
        r1.reverifyRemaining === 0 &&
        r2.reverifyRemaining === 0 &&
        (s.calls.fetches ?? 0) > f0 &&
        store.getPublication(bid) === null,
      {
        r1: [r1.counts.held, r1.reverifyRemaining],
        r2: r2.reverifyRemaining,
        fetches: [f0, s.calls.fetches],
      }
    );
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
}

let failed = 0;
for (const r of results) {
  console.log(`${r.ok ? "ok  " : "FAIL"} ${r.name}${r.ok ? "" : `\n     got ${r.got}`}`);
  if (!r.ok) failed++;
}
console.log(`\n${results.length - failed}/${results.length} cells`);
process.exit(failed ? 1 : 0);
