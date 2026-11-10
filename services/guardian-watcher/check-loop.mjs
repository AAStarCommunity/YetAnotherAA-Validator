// CI self-test for W2c: the publication loop (lib/publisher.mjs), sink construction from config
// (lib/sinks-config.mjs) and the store's publication journal, against the shared mock sinks.
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { ethers } from "ethers";
import { Store } from "./lib/store.mjs";
import {
  publishPending,
  publishPhase,
  deliverAlerts,
  readRoles,
  isDone,
} from "./lib/publisher.mjs";
import { publishConfig, buildSinks } from "./lib/sinks-config.mjs";
import { runOnce } from "./watcher.mjs";
import { bls, owner, sinks } from "./mock-sinks.mjs";

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
      if (state.fail)
        throw Object.assign(new Error("https://rpc/ROLESECRET"), { code: "SERVER_ERROR" });
      const d = roleIface.parseTransaction({ data: tx.data });
      if (d.name === "owner") return roleIface.encodeFunctionResult("owner", [state.owner]);
      if (d.name === "MAX_VALIDATORS")
        return roleIface.encodeFunctionResult("MAX_VALIDATORS", [state.max]);
      const slot = Number(d.args[0]);
      return roleIface.encodeFunctionResult("validatorAtSlot", [
        state.slots[slot] ?? ethers.ZeroAddress,
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
      registryFor: () => s.registry,
    };
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
        runs.at(-1).done === 2,
      { last: runs.at(-1), bls: blsSt?.registry?.phase }
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
    const r1 = await deliverAlerts(store, tg, alerts, { now: 1 });
    const after1 = texts.length;
    const r2 = await deliverAlerts(store, tg, alerts, { now: 2 });
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
        journalKept &&
        s.calls.sign === 0 &&
        s.calls.texts.some(t => /record file unreadable/.test(t) && /journal unreadable/.test(t)),
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
  pinners: [
    { type: "pinata", gateway: "https://x.mypinata.cloud", account: "pinata-jwt" },
    { type: "filebase", account: "filebase-token" },
  ],
  telegram: { chatId: "-100", account: "tg-token" },
  mirror: { clone: "/tmp/none.git" },
  registry: {
    address: ethers.getAddress("0x" + "ab".repeat(20)),
    fromBlock: 1,
    deployer: DEPLOYER,
    keystore: "/nonexistent",
    account: "writer-pass",
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
    ["unknown pinner", { ...good, pinners: [{ type: "web3", account: "a" }] }],
    [
      "pinata without https gateway",
      { ...good, pinners: [{ type: "pinata", gateway: "http://x", account: "a" }] },
    ],
    ["no telegram", { ...good, telegram: undefined }],
    ["no mirror", { ...good, mirror: {} }],
    ["bad registry", { ...good, registry: { ...good.registry, address: "0x12" } }],
    ["no deployer", { ...good, registry: { ...good.registry, deployer: undefined } }],
    ["no keystore", { ...good, registry: { ...good.registry, keystore: "" } }],
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
      "pinata-jwt": "pj",
      "filebase-token": "fb",
      "tg-token": "tg",
      "writer-pass": "PASSWORDSECRET",
    };
    const readSecret = async (svc, acct) => {
      asked.push(`${svc}/${acct}`);
      return secrets[acct];
    };
    const p = publishConfig({ ...good, registry: { ...good.registry, keystore: ks } });
    const b = await buildSinks(
      p,
      new ethers.JsonRpcProvider("http://127.0.0.1:1", 1, { staticNetwork: true }),
      { readSecret }
    );
    cell(
      "buildSinks: every secret from the Keychain service, the keystore decrypted to the writer",
      b.wallet.address === writer.address &&
        b.pinners.map(x => x.name).join() === "pinata,filebase" &&
        j(asked) ===
          j([
            "dvt-guardian-watcher/pinata-jwt",
            "dvt-guardian-watcher/filebase-token",
            "dvt-guardian-watcher/tg-token",
            "dvt-guardian-watcher/writer-pass",
          ]),
      { asked, addr: b.wallet.address }
    );
    let e = null;
    try {
      await buildSinks(p, null, {
        readSecret: async (s2, a) => (a === "writer-pass" ? "wrong" : secrets[a]),
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

let failed = 0;
for (const r of results) {
  console.log(`${r.ok ? "ok  " : "FAIL"} ${r.name}${r.ok ? "" : `\n     got ${r.got}`}`);
  if (!r.ok) failed++;
}
console.log(`\n${results.length - failed}/${results.length} cells`);
process.exit(failed ? 1 : 0);
