// CI self-test for the guardian watcher core (W1) against the shared stub chain. Each cell asserts a
// specific outcome; must-pass and must-fail cells are both present (a self-test of only one kind
// proves nothing).
import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync, writeSync } from "node:fs";
import { tmpdir } from "node:os";
import { createHash } from "node:crypto";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { ethers } from "ethers";
import {
  Kind,
  aggIface,
  traceDepthOk as recheckDepthOk,
  findEntryLogs,
} from "../../scripts/disclosure/recheck-lib.mjs";
import {
  AGG,
  SAFE,
  WRAPPER,
  SP,
  FORWARDERS,
  addr,
  makeChain,
  slashF,
  repF,
} from "../../scripts/disclosure/stub-chain.mjs";
import { spIface } from "./lib/sp-abi.mjs";
import { validateRuleset, evaluate, matchGeneric } from "./lib/rules.mjs";
import {
  MAX_DEADLETTER_ATTEMPTS,
  traceUnsupported,
  verifyTrace,
  sameLog,
  envelopeProblem,
  txOfEvidence,
  typedEvidence,
  nativeEvidence,
} from "./lib/scan.mjs";
import { bloomOf, mayHaveLog } from "./lib/bloom.mjs";
import {
  Store,
  writeAll,
  validAmendment,
  atomicWriteJson,
  boundReasons,
  renameDurable,
} from "./lib/store.mjs";
import { runOnce, rulesetIdentity, traceHealth, loadConfig } from "./watcher.mjs";
import {
  attributeLogs,
  flattenTraceLogs,
  validLog,
  receiptPos,
  traceDepthOk,
} from "./lib/attribute.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const rs = validateRuleset(JSON.parse(readFileSync(join(HERE, "ruleset.json"), "utf8")));
const results = [];
const j = v => JSON.stringify(v, (_, x) => (typeof x === "bigint" ? x.toString() : x));
/** Open dead letters plus quarantine records in dead-letter shape: since follow-up #2 R4 a
 * quarantine is a final record at once (DSR log 2892c30f), not a dead letter waiting for its cap. */
const withQ = store => [
  ...store.listDeadLetters(),
  ...readdirSync(join(store.dir, "records"))
    .filter(f => f.endsWith(".json"))
    .map(f => JSON.parse(readFileSync(join(store.dir, "records", f), "utf8")))
    .filter(r => r.quarantine === true)
    .map(r => ({ ...r, watched: r.evidence, reasons: r.lastReasons, finalRecord: true })),
];
const cell = (name, ok, got) => results.push({ name, ok: !!ok, got: ok ? "" : j(got) });

const dir = mkdtempSync(join(tmpdir(), "guardian-watcher-"));
const readRecs = () =>
  readdirSync(join(dir, "records"))
    .filter(f => f.endsWith(".json"))
    .map(f => JSON.parse(readFileSync(join(dir, "records", f), "utf8")));
try {
  const c = makeChain();
  const start = c.head() + 1;
  const cfg = {
    aggregator: AGG,
    roles: { superPaymaster: SP },
    forwarders: FORWARDERS,
    startBlock: start,
    maxBlocksPerTick: 1000,
    page: 5000,
  };
  const store = new Store(dir);
  const ident = { commit: "0".repeat(40), hash: ethers.id("ruleset"), verified: true };
  const priceF = {
    target: SP,
    callData: spIface.encodeFunctionData("updatePriceDVT", [300000000000n, 1n, "0x", 0]),
    requiredThreshold: 2n,
  };

  c.setPrice(start - 1, 250000000000n);
  // 1. direct BLS slash (owner route through the aggregator)
  const a1 = c.execute(Kind.SLASH, 101n, slashF, 0b011n);
  // 2. BLS price update via the owner Safe; the trace places its PriceUpdated inside the aggregator
  const a2 = c.execute(Kind.GENERIC, 70n, priceF, 0b111n, {
    via: { route: "safe" },
    spLogs: [{ name: "PriceUpdated", args: [300000000000n, 1n] }],
    price: 300000000000n,
  });
  {
    const pu = spIface.encodeEventLog("PriceUpdated", [300000000000n, 1n]);
    c.setTrace(a2.hash, {
      type: "CALL",
      to: SAFE,
      calls: [
        {
          type: "CALL",
          to: AGG,
          logs: [
            {
              address: AGG,
              ...aggIface.encodeEventLog("SignersCommitted", [a2.key, a2.mask]),
              position: 0,
            },
          ],
          calls: [
            { type: "CALL", to: SP, logs: [{ address: SP, topics: pu.topics, data: pu.data }] },
          ],
        },
      ],
    });
  }
  // 3. reputation batch through DVTValidator
  const a3 = c.execute(Kind.REPUTATION, 102n, repF, 0b111n, { via: { route: "dvt" } });
  // 4. owner price update straight to SP (no BLS): the owner calls updatePriceDVT itself, a
  // privileged selector, so the owner route (#400 M1: classified by the emitting call)
  const o1 = c.ownerTx([{ name: "PriceUpdated", args: [310000000000n, 2n] }], {
    price: 310000000000n,
    data: spIface.encodeFunctionData("updatePriceDVT", [310000000000n, 2n, "0x", 0]),
  });
  // 5. owner slash: queue + slash, no BLS (two events in one tx: both must survive)
  const opr = addr("operator-x");
  const o2 = c.ownerTx([
    { name: "SlashQueued", args: [opr] },
    { name: "OperatorSlashed", args: [opr, 5n, 1] },
  ]);
  // 6. a BLS action wrapped by an unpinned contract with no trace: not authenticable
  const a6 = c.execute(Kind.SLASH, 103n, slashF, 0b011n, { to: WRAPPER });
  // 8. mixed tx without a trace: a BLS action plus an independent owner slash in one Safe batch
  const mixOp = addr("mixed-op");
  const a8 = c.execute(Kind.GENERIC, 71n, priceF, 0b111n, {
    via: { route: "safe" },
    spLogs: [{ name: "OperatorSlashed", args: [mixOp, 9n, 2] }],
  });
  // 9. a direct BLS action whose slot table changed inside the block: proven, signers unverified
  const a9 = c.execute(Kind.SLASH, 105n, slashF, 0b011n, {
    midSlots: { 1: addr("t1"), 2: addr("t2") },
  });
  // 10. an owner pause in the same tx as a BLS action; the trace shows an identical-looking event
  // only inside a REVERTED subcall of the aggregator, and the real one outside it
  const pauseOp = addr("paused-op");
  const a10 = c.execute(Kind.GENERIC, 72n, priceF, 0b111n, {
    via: { route: "safe" },
    spLogs: [{ name: "OperatorPaused", args: [pauseOp] }],
  });
  {
    const pz = spIface.encodeEventLog("OperatorPaused", [pauseOp]);
    const lg = { address: SP, topics: pz.topics, data: pz.data };
    c.setTrace(a10.hash, {
      type: "CALL",
      to: SAFE,
      calls: [
        {
          type: "CALL",
          to: AGG,
          logs: [
            {
              address: AGG,
              ...aggIface.encodeEventLog("SignersCommitted", [a10.key, a10.mask]),
              position: 0,
            },
          ],
          calls: [{ type: "CALL", to: SP, error: "execution reverted", logs: [lg] }],
        },
        {
          type: "CALL",
          from: SAFE,
          to: SP,
          input: ethers.id("setOperatorPaused(address,bool)").slice(0, 10),
          logs: [lg],
        },
      ],
    });
  }
  // 7. an action beyond finality must not be scanned yet
  c.setFinalityLag(2);
  const a7 = c.execute(
    Kind.QUEUE,
    0n,
    { operator: addr("late-op"), slashLevel: 1, epoch: 9n },
    0b110n
  );
  c.mineEmpty();

  const r1 = await runOnce(c.chain, cfg, store, rs, ident);
  cell("tick 1 succeeds", r1.status.ok, r1.status);
  const recs = readRecs();
  const find = pred => recs.find(pred);

  const s1 = find(r => r.route === "bls" && r.txHash === a1.hash);
  cell(
    "BLS slash recorded, flagged, with its verified signer set",
    s1 && s1.kind === "SLASH" && s1.verdict.flagged && s1.signers?.length === 2,
    s1
  );

  const s2 = find(r => r.route === "bls" && r.txHash === a2.hash);
  cell(
    "BLS price update via Safe: GENERIC, flagged by the price rule, price before/after read",
    s2 &&
      s2.kind === "GENERIC" &&
      s2.verdict.rule.startsWith("bls.GENERIC.expected:superPaymaster") &&
      s2.price?.before?.price === "250000000000" &&
      s2.price?.after?.price === "300000000000",
    s2
  );
  cell(
    "a PriceUpdated the trace places inside the aggregator call is the BLS record's effect",
    s2?.spEvents?.[0]?.event === "PriceUpdated" &&
      !find(r => r.route === "owner" && r.txHash === a2.hash),
    s2?.spEvents
  );

  const s3 = find(r => r.route === "bls" && r.txHash === a3.hash);
  cell(
    "reputation batch via DVTValidator recorded and flagged",
    s3 && s3.kind === "REPUTATION" && s3.verdict.flagged && s3.signers?.length === 3,
    s3
  );

  const ow1 = find(r => r.route === "owner" && r.txHash === o1.hash);
  cell(
    "owner price update: owner-route record, labelled, price read",
    ow1 &&
      ow1.event === "PriceUpdated" &&
      ow1.label === rs.ownerRoute.label &&
      ow1.verdict.flagged &&
      ow1.price?.after?.price === "310000000000",
    ow1
  );
  const ow2 = recs
    .filter(r => r.route === "owner" && r.txHash === o2.hash)
    .map(r => r.event)
    .sort();
  cell(
    "owner slash: SlashQueued and OperatorSlashed each recorded (log index from ethers `index`)",
    j(ow2) === j(["OperatorSlashed", "SlashQueued"]),
    ow2
  );

  const m8 = find(r => r.route === "owner" && r.txHash === a8.hash);
  cell(
    "mixed tx, no trace: the owner slash is its own record, marked route-uncertain, never swallowed",
    m8 &&
      m8.event === "OperatorSlashed" &&
      /no trace/.test(m8.routeUncertain ?? "") &&
      m8.verdict.flagged,
    m8
  );
  const s8 = find(r => r.route === "bls" && r.txHash === a8.hash);
  cell(
    "…and the BLS record of that tx carries no unproven effects",
    s8 && s8.spEvents.length === 0,
    s8
  );

  const p10 = find(r => r.route === "owner" && r.txHash === a10.hash);
  cell(
    "an event seen only in a reverted subcall of the aggregator is not attributed to it",
    p10 &&
      p10.event === "OperatorPaused" &&
      /outside that action's aggregator call/.test(p10.routeUncertain ?? ""),
    p10
  );
  cell(
    "unauthenticable BLS action is NOT a record",
    !find(r => r.txHash === a6.hash),
    "record exists"
  );
  const dls = store.listDeadLetters();
  const d6 = dls.find(d => d.txHash === a6.hash);
  cell(
    "…it is a dead letter, flagged UNRECOVERED, with a reason",
    d6 && d6.verdict.rule === "bls.UNRECOVERED" && d6.reasons.some(x => x.includes("wrapped")),
    d6
  );
  cell(
    "signers not verified (intra-block slot change): dead letter SIGNERS_UNVERIFIED, not a record",
    !find(r => r.txHash === a9.hash) &&
      dls.some(d => d.txHash === a9.hash && d.status === "SIGNERS_UNVERIFIED"),
    dls.map(d => [d.txHash === a9.hash, d.status])
  );

  cell("action past finality not scanned yet", !find(r => r.txHash === a7.hash), "scanned early");
  cell("cursor stops at finalized", store.getCursor().block === c.head() - 2, store.getCursor());
  cell(
    "status.json reports lag 0 at finalized and counts",
    r1.status.lagBlocks === 0 && r1.status.records === recs.length && r1.status.deadLetters === 2,
    r1.status
  );
  cell(
    "every record carries the ruleset identity it was judged by",
    recs.every(r => r.ruleset?.hash === ident.hash && r.ruleset?.commit === ident.commit),
    recs.map(r => r.ruleset)
  );

  // second tick after finality catches up: the late action appears, nothing is duplicated
  c.setFinalityLag(0);
  const before = recs.length;
  const r2 = await runOnce(c.chain, cfg, store, rs, ident);
  const after = readRecs().length;
  cell(
    "tick 2 picks up the newly finalized action only",
    r2.status.ok && after === before + 1 && r2.summary.newRecords === 1,
    { before, after, s: r2.summary }
  );
  const r3 = await runOnce(c.chain, cfg, store, rs, ident);
  cell(
    "tick 3 is idempotent (no new records, nothing re-flagged)",
    r3.status.ok && r3.summary.newRecords === 0 && r3.summary.flagged.length === 0,
    r3.summary
  );
  cell(
    "dead letter retried, attempts counted",
    store.listDeadLetters().find(d => d.txHash === a6.hash)?.attempts >= 3,
    store.listDeadLetters()
  );

  // Re-scanning an already scanned range rewrites nothing (first write wins).
  {
    const snap = readRecs().map(j).join("|");
    const keep = store.getCursor();
    const hdr = await c.chain.send("eth_getBlockByNumber", [ethers.toQuantity(start - 1), false]);
    store.setCursor({ block: start - 1, hash: hdr.hash });
    const rr = await runOnce(c.chain, cfg, store, rs, {
      ...ident,
      commit: "1".repeat(40),
      hash: ethers.id("other"),
    });
    const snap2 = readRecs().map(j).join("|");
    cell(
      "re-scan of a scanned range: no new records, files byte-identical",
      rr.status.ok && rr.summary.newRecords === 0 && snap === snap2,
      rr.summary
    );
    store.setCursor(keep);
  }

  // Codex W2c R18: the status runOnce writes before this iteration's publication keeps the last
  // publication's degradation (a scan-only "healthy" is not a recovery)
  {
    const keep = store.getCursor();
    const bad = await runOnce(c.chain, cfg, store, rs, ident, {
      carry: {
        publication: {
          ok: false,
          stalls: { feeCapped: 0, insufficientFunds: 0 },
          inProgress: true,
        },
      },
    });
    const onDisk = store.readStatus();
    store.setCursor(keep);
    const good = await runOnce(c.chain, cfg, store, rs, ident, {
      carry: {
        publication: { ok: true, stalls: { feeCapped: 0, insufficientFunds: 0 }, inProgress: true },
      },
    });
    store.setCursor(keep);
    const reason = "publication pass not ok (a stage failed, stopped or was skipped)";
    cell(
      "R18: the scan's status write carries the last publication's degradation (healthy false), not a scan-only healthy",
      bad.status.ok === true &&
        bad.status.healthy === false &&
        onDisk?.healthy === false &&
        (onDisk.degraded ?? []).includes(reason) &&
        !(good.status.degraded ?? []).includes(reason),
      {
        bad: [bad.status.healthy, bad.status.degraded],
        good: [good.status.healthy, good.status.degraded],
      }
    );
  }

  // #413 review Low 2 + Codex info R1: the interim status carries whether the last completed
  // iteration (scan, publication, slowness) was healthy: degraded unless it was known healthy (a
  // restart without a saved status included); never a status field; the completed status drops
  // the carried reason
  {
    const { interimCarry, publicationStep, LAST_ITERATION_DEGRADED, restoredCarry } =
      await import("./watcher.mjs");
    // a restart restores the saved status's health: a slow (degraded) last iteration stays degraded
    const rSlow = restoredCarry({ healthy: false, publication: { at: "t0", ok: true } });
    const rNone = restoredCarry(null);
    const rGood = restoredCarry({ healthy: true, publication: { at: "t0", ok: true } });
    const keep = store.getCursor();
    const done = { at: "t0", ok: true, stalls: { feeCapped: 0, insufficientFunds: 0 } };
    const run = async lastHealthy => {
      const r = await runOnce(c.chain, cfg, store, rs, ident, {
        carry: interimCarry(done, lastHealthy, "t1"),
      });
      store.setCursor(keep);
      return r;
    };
    const afterBad = await run(false);
    const afterUnknown = await run(undefined);
    const afterGood = await run(true);
    let t = 0;
    const finalSt = { ...afterBad.status };
    await publicationStep({
      status: finalSt,
      run: async () => ({ ok: true, stalls: { feeCapped: 0, insufficientFunds: 0 } }),
      slowNote: null,
      iterStart: 0,
      cfg: { intervalMs: 60_000, maxTickFraction: 0.5 },
      carried: afterBad.carried,
      now: () => (t += 1),
    });
    cell(
      "#413 Low 2 / Codex info R1: an interim status after a degraded (or unknown) completed iteration is degraded with a fixed reason; after a healthy one it is healthy; no carry field leaks; the completed status drops the carried reason",
      afterBad.status.healthy === false &&
        (afterBad.status.degraded ?? []).includes(LAST_ITERATION_DEGRADED) &&
        afterUnknown.status.healthy === false &&
        afterGood.status.healthy === true &&
        !("lastCompletedHealthy" in afterBad.status) &&
        afterBad.status.publication?.inProgress === true &&
        !(finalSt.degraded ?? []).includes(LAST_ITERATION_DEGRADED) &&
        finalSt.healthy === true &&
        rSlow.lastHealthy === false &&
        rSlow.lastPub?.at === "t0" &&
        rNone.lastHealthy === false &&
        rNone.lastPub === null &&
        rGood.lastHealthy === true,
      {
        restored: [rSlow, rNone, rGood],
        bad: [afterBad.status.healthy, afterBad.status.degraded],
        unknown: afterUnknown.status.healthy,
        good: [afterGood.status.healthy, afterGood.status.degraded],
        final: [finalSt.healthy, finalSt.degraded],
      }
    );
  }

  // #427 review Low: the loop step carries the health of the iteration it just completed, so after
  // a degraded iteration the next interim status is degraded, and after a healthy one it is healthy
  {
    const { watchStep, LAST_ITERATION_DEGRADED } = await import("./watcher.mjs");
    const keep = store.getCursor();
    const interims = [];
    const written = [];
    let loop = {
      carryState: {
        lastPub: { at: "t0", ok: true, stalls: { feeCapped: 0, insufficientFunds: 0 } },
        lastHealthy: true,
      },
      slowNote: null,
    };
    const step = async publishOk => {
      const r = await watchStep(loop, {
        publishing: true,
        scan: async carry => {
          const x = await runOnce(c.chain, cfg, store, rs, ident, { carry });
          store.setCursor(keep);
          interims.push({ healthy: x.status.healthy, degraded: [...(x.status.degraded ?? [])] });
          return x;
        },
        publish: async () =>
          publishOk
            ? { at: "t", ok: true, stalls: { feeCapped: 0, insufficientFunds: 0 } }
            : { at: "t", ok: false, stalls: { feeCapped: 0, insufficientFunds: 0 } },
        writeStatus: st => written.push(st.healthy),
        cfg: { intervalMs: 60_000, maxTickFraction: 0.5 },
      });
      loop = r.next;
      return r.status;
    };
    const s1 = await step(false); // healthy interim, degraded completed
    const s2 = await step(true); // degraded interim (carried), healthy completed
    const s3 = await step(true); // healthy interim
    cell(
      "#427 Low: each loop step carries the iteration it just completed: after a degraded one the next interim is degraded (fixed reason), after a healthy one healthy; every completed status is written",
      interims[0].healthy === true &&
        s1.healthy === false &&
        interims[1].healthy === false &&
        interims[1].degraded.includes(LAST_ITERATION_DEGRADED) &&
        s2.healthy === true &&
        interims[2].healthy === true &&
        s3.healthy === true &&
        JSON.stringify(written) === "[false,true,true]",
      { interims, completed: [s1.healthy, s2.healthy, s3.healthy], written }
    );
  }

  // A cursor whose block no longer has the stored hash: stop, do not advance.
  {
    const keep = store.getCursor();
    store.setCursor({ block: keep.block, hash: ethers.id("not-this-block") });
    const rr = await runOnce(c.chain, cfg, store, rs, ident);
    cell(
      "cursor block hash changed: tick fails with a finality error",
      !rr.status.ok && /finality violated/.test(rr.status.lastError),
      rr.status
    );
    cell(
      "…and the cursor is left where it was",
      store.getCursor().block === keep.block,
      store.getCursor()
    );
    store.setCursor(keep);
  }

  // One action whose rebuild throws: dead letter with the error, the rest of the range proceeds.
  {
    const bad = c.execute(Kind.SLASH, 106n, slashF, 0b011n);
    const good = c.execute(Kind.SLASH, 107n, slashF, 0b011n);
    const flaky = {
      ...c.chain,
      async getTransaction(h) {
        if (h === bad.hash) throw new Error("node lost this tx");
        return c.chain.getTransaction(h);
      },
    };
    const rr = await runOnce(flaky, cfg, store, rs, ident);
    const dl = store.listDeadLetters().find(d => d.txHash === bad.hash);
    cell(
      "an action that throws becomes an ERROR dead letter",
      rr.status.ok &&
        dl?.status === "ERROR" &&
        dl.reasons[0] === "rebuild failed: rebuild: error" && // the RPC's own text never kept
        !JSON.stringify(dl).includes("node lost this tx"),
      { s: rr.status, dl }
    );
    cell(
      "…and the scan still records the next action and advances",
      readRecs().some(r => r.txHash === good.hash) && store.getCursor().block >= good.block,
      store.getCursor()
    );
    const rr2 = await runOnce(c.chain, cfg, store, rs, ident);
    cell(
      "…and resolves into a record on retry, counted once as upgraded",
      rr2.status.ok &&
        !store.listDeadLetters().some(d => d.txHash === bad.hash) &&
        readRecs().some(r => r.txHash === bad.hash) &&
        rr2.summary.upgraded === 1,
      { dls: store.listDeadLetters().map(d => d.txHash), s: rr2.summary }
    );
  }

  // Crash between writing a record and retiring its dead letter: the next put reconciles it.
  {
    const k = 999n;
    const dl = {
      route: "bls",
      key: k.toString(),
      signerMask: "3",
      txHash: ethers.id("x"),
      blockNumber: 1,
      logIndex: 0,
      seenAt: "t",
    };
    const rec = {
      route: "bls",
      kind: "SLASH",
      key: k.toString(),
      txHash: ethers.id("x"),
      verdict: { flagged: true },
    };
    store.putRecord(rec); // record written…
    store.putDeadLetter(dl); // …but the dead letter is still there (as after a crash)
    const res = store.putRecord(rec);
    cell(
      "crash recovery: an existing record retires a leftover dead letter",
      res === "same" && !store.listDeadLetters().some(d => d.key === k.toString()),
      { res, dls: store.listDeadLetters().map(d => d.key) }
    );
  }

  // Ruleset identity: the committed bytes verify; edited bytes do not, and name no commit.
  {
    const real = readFileSync(join(HERE, "ruleset.json"));
    const okId = rulesetIdentity(real);
    cell(
      "ruleset identity: committed bytes verify against their git commit",
      okId.verified && /^[0-9a-f]{40}$/.test(okId.commit),
      okId
    );
    const edited = rulesetIdentity(Buffer.concat([real, Buffer.from(" ")]));
    cell(
      "ruleset identity: edited bytes are unverified and name no commit",
      !edited.verified && edited.commit === null && edited.hash !== okId.hash,
      edited
    );
  }

  // RPC failure: status records the error, cursor does not move
  const curBefore = store.getCursor();
  const broken = {
    ...c.chain,
    getLogs: async () => {
      throw new Error("rpc down");
    },
    // range reads go through raw eth_getLogs (#403 review M-1): the RPC is down there too
    send: async (m, p) => {
      if (m === "eth_getLogs") throw new Error("rpc down");
      return c.chain.send(m, p);
    },
  };
  c.execute(Kind.SLASH, 104n, slashF, 0b011n);
  const r4 = await runOnce(broken, cfg, store, rs, ident);
  cell(
    "RPC failure: status not ok, error recorded",
    !r4.status.ok &&
      r4.status.lastError === "aggregator log read: error" && // the stage is named, the text dropped
      !JSON.stringify(r4.status).includes("rpc down"),
    r4.status
  );
  cell(
    "RPC failure: cursor did not advance",
    store.getCursor().block === curBefore.block,
    store.getCursor()
  );

  // Attribution is per aggregator call and per log occurrence (Codex W1 R2 H1, M2).
  {
    const L = (address, tag, position) => ({
      address,
      topics: [ethers.id(tag)],
      data: "0x",
      position,
    });
    const rl = list =>
      list.map((l, i) => ({ address: l.address, topics: l.topics, data: l.data, index: i }));
    // H1: two identical SP logs, one inside the aggregator call, one outside
    const t1 = {
      type: "CALL",
      to: SAFE,
      calls: [
        {
          type: "CALL",
          to: AGG,
          logs: [L(AGG, "commit", 0)],
          calls: [{ type: "CALL", to: SP, logs: [L(SP, "paused")] }],
        },
        { type: "CALL", to: SP, logs: [L(SP, "paused")] },
      ],
    };
    const a1x = attributeLogs(t1, rl([L(AGG, "commit"), L(SP, "paused"), L(SP, "paused")]), AGG);
    cell(
      "identical SP logs: only the occurrence inside the aggregator call is attributed",
      a1x.aligned && a1x.owner.get(1) === 0 && a1x.owner.get(2) === null,
      [...a1x.owner]
    );
    // M2: two aggregator calls in one tx, each with its own effect
    const t2 = {
      type: "CALL",
      to: SAFE,
      calls: [
        {
          type: "CALL",
          to: AGG,
          logs: [L(AGG, "commitA", 0)],
          calls: [{ type: "CALL", to: SP, logs: [L(SP, "effA")] }],
        },
        {
          type: "CALL",
          to: AGG,
          logs: [L(AGG, "commitB", 0)],
          calls: [{ type: "CALL", to: SP, logs: [L(SP, "effB")] }],
        },
      ],
    };
    const a2x = attributeLogs(
      t2,
      rl([L(AGG, "commitA"), L(SP, "effA"), L(AGG, "commitB"), L(SP, "effB")]),
      AGG
    );
    cell(
      "two BLS actions in one tx: each effect belongs to its own aggregator call",
      a2x.aligned &&
        a2x.owner.get(0) === a2x.owner.get(1) &&
        a2x.owner.get(2) === a2x.owner.get(3) &&
        a2x.owner.get(0) !== a2x.owner.get(2),
      [...a2x.owner]
    );
    // misalignment and missing positions attribute nothing
    const a3x = attributeLogs(
      t2,
      rl([L(AGG, "commitA"), L(SP, "effB"), L(AGG, "commitB"), L(SP, "effA")]),
      AGG
    );
    cell(
      "trace and receipt disagree: nothing attributed",
      !a3x.aligned && a3x.owner.size === 0,
      a3x
    );
    const t4 = {
      type: "CALL",
      to: AGG,
      logs: [L(AGG, "commit")],
      calls: [{ type: "CALL", to: SP, logs: [L(SP, "e")] }],
    };
    const a4x = attributeLogs(t4, rl([L(AGG, "commit"), L(SP, "e")]), AGG);
    cell(
      "a log without position in a frame with subcalls: nothing attributed",
      !a4x.aligned && /positions/.test(a4x.why),
      a4x
    );
    const t5 = {
      type: "CALL",
      to: SAFE,
      calls: [
        { type: "CALL", to: AGG, error: "reverted", logs: [L(AGG, "commit", 0)] },
        { type: "CALL", to: SP, logs: [L(SP, "e")] },
      ],
    };
    const a6x = attributeLogs(t2, rl([L(AGG, "commitA"), L(SP, "effA"), L(AGG, "commitB")]), AGG);
    cell(
      "trace with more logs than the receipt: nothing attributed",
      !a6x.aligned && a6x.owner.size === 0,
      a6x
    );
    const a5x = attributeLogs(t5, rl([L(SP, "e")]), AGG);
    cell(
      "logs of a reverted call are dropped before alignment",
      a5x.aligned && a5x.owner.get(0) === null,
      [...a5x.owner]
    );
  }

  // rules: unexpected generic and unlisted owner event are flagged
  cell(
    "rule: generic call outside the expected set is flagged as unexpected",
    evaluate(rs, cfg.roles, {
      route: "bls",
      kind: "GENERIC",
      fields: { target: addr("x"), callData: "0x12345678" },
    }).rule === "bls.GENERIC.unexpected",
    null
  );
  cell(
    "rule: an SP event missing from the ruleset is still flagged",
    evaluate(rs, cfg.roles, { route: "owner", event: "SomethingNew" }).flagged,
    null
  );
  let threw = false;
  try {
    validateRuleset({ ...rs, bls: { ...rs.bls, QUEUE: undefined } });
  } catch {
    threw = true;
  }
  cell("ruleset validation rejects a missing rule", threw, null);
} finally {
  rmSync(dir, { recursive: true, force: true });
}

// ---- #400 M1: classify SuperPaymaster events by the call that emitted them; dead letters;
// exhaustion; logsBloom cross-check; the branches the review found untested.
{
  const d2 = mkdtempSync(join(tmpdir(), "guardian-watcher-m1-"));
  try {
    const c = makeChain();
    const start = c.head() + 1;
    const cfg = {
      aggregator: AGG,
      roles: { superPaymaster: SP },
      forwarders: FORWARDERS,
      startBlock: start,
      maxBlocksPerTick: 1000,
      page: 5000,
    };
    const store = new Store(d2);
    const ident = { commit: "0".repeat(40), hash: ethers.id("ruleset"), verified: true };
    const KEEPER = addr("keeper-eoa");
    const KCONTRACT = addr("keeper-contract");
    const sel = sig => ethers.id(sig).slice(0, 10);
    c.setPrice(start - 1, 250000000000n);
    // K1 keeper: direct updatePrice(), only PriceUpdated
    const k1 = c.ownerTx([{ name: "PriceUpdated", args: [251000000000n, 3n] }], {
      from: KEEPER,
      data: sel("updatePrice()"),
      price: 251000000000n,
    });
    // K2 keeper: updatePrice() that also switches the price mode
    const k2 = c.ownerTx(
      [
        { name: "PriceModeChanged", args: [1, 0] },
        { name: "PriceUpdated", args: [252000000000n, 4n] },
      ],
      { from: KEEPER, data: sel("updatePrice()"), price: 252000000000n }
    );
    // K3 anyone: executeEmergencyPrice() after the owner queued it
    const k3 = c.ownerTx(
      [
        { name: "EmergencyPriceExecuted", args: [200000000000n] },
        { name: "PriceUpdated", args: [200000000000n, 5n] },
      ],
      { from: KEEPER, data: sel("executeEmergencyPrice()"), price: 200000000000n }
    );
    // K4 anyone: pauseUnderstakedOperator(address)
    const weakOp = addr("weak-op");
    const k4 = c.ownerTx([{ name: "OperatorPaused", args: [weakOp] }], {
      from: KEEPER,
      data: sel("pauseUnderstakedOperator(address)") + "00".repeat(32),
    });
    // K5 keeper through a contract, no trace yet: the caller of PriceUpdated is undeterminable
    const k5 = c.ownerTx([{ name: "PriceUpdated", args: [253000000000n, 6n] }], {
      from: KEEPER,
      to: KCONTRACT,
      data: "0xdeadbeef",
      price: 253000000000n,
    });
    // K6 owner through its Safe: the trace shows the Safe calling updatePriceDVT on SP
    const k6 = c.ownerTx([{ name: "PriceUpdated", args: [254000000000n, 7n] }], {
      from: addr("safe-signer"),
      to: SAFE,
      data: "0x6a761202",
      price: 254000000000n,
    });
    {
      const pu = spIface.encodeEventLog("PriceUpdated", [254000000000n, 7n]);
      c.setTrace(k6.hash, {
        type: "CALL",
        from: addr("safe-signer"),
        to: SAFE,
        calls: [
          {
            type: "CALL",
            from: SAFE,
            to: SP,
            input: spIface.encodeFunctionData("updatePriceDVT", [254000000000n, 7n, "0x", 0]),
            logs: [{ address: SP, topics: pu.topics, data: pu.data }],
          },
        ],
      });
    }
    // K7 a transient getTransaction failure
    const k7 = c.ownerTx([{ name: "SlashCancelled", args: [weakOp] }]);
    c.failTx(k7.hash, 1);
    const r1 = await runOnce(c.chain, cfg, store, rs, ident);
    const recs = () =>
      readdirSync(join(d2, "records"))
        .filter(f => f.endsWith(".json"))
        .map(f => JSON.parse(readFileSync(join(d2, "records", f), "utf8")));
    const byTx = h => recs().filter(r => r.txHash === h);
    const dls = () =>
      readdirSync(join(d2, "deadletters"))
        .filter(f => f.endsWith(".json"))
        .flatMap(f => {
          try {
            return [JSON.parse(readFileSync(join(d2, "deadletters", f), "utf8"))];
          } catch {
            return []; // K14 plants a corrupt one on purpose
          }
        });
    const [p1] = byTx(k1.hash);
    cell(
      "keeper updatePrice() emitting only PriceUpdated: public route, NOT flagged, caller and selector kept",
      r1.status.ok &&
        p1?.route === "public" &&
        p1.verdict.flagged === false &&
        p1.caller === KEEPER &&
        p1.selector === sel("updatePrice()") &&
        p1.function === "updatePrice()" &&
        p1.callerSource === "trace",
      p1
    );
    const p2 = byTx(k2.hash);
    cell(
      "keeper updatePrice() that also changes the price mode: flagged as informational, caller not accused",
      p2.length === 2 &&
        p2.every(
          r =>
            r.route === "public" &&
            r.verdict.flagged &&
            /caller not accused/.test(r.verdict.reasons[0])
        ) &&
        p2.every(r => j(r.callEvents.sort()) === j(["PriceModeChanged", "PriceUpdated"])),
      p2.map(r => ({ route: r.route, v: r.verdict, ce: r.callEvents }))
    );
    const p3 = byTx(k3.hash).find(r => r.event === "PriceUpdated");
    cell(
      "executeEmergencyPrice() by anyone: flagged, caller not accused, price before and after",
      p3?.route === "public" &&
        p3.verdict.flagged &&
        /not accused/.test(p3.verdict.reasons[0]) &&
        p3.price?.before?.price === "252000000000" &&
        p3.price?.after?.price === "200000000000",
      p3
    );
    const [p4] = byTx(k4.hash);
    cell(
      "pauseUnderstakedOperator() by anyone: public route, routine, not flagged, caller recorded",
      p4?.route === "public" && !p4.verdict.flagged && p4.caller === KEEPER,
      p4
    );
    const dl5 = dls().find(x => x.txHash === k5.hash);
    cell(
      "an ambiguous event whose call cannot be determined (no trace) is a dead letter, never a guess",
      byTx(k5.hash).length === 0 && dl5?.route === "tx" && /undeterminable/.test(dl5.reasons[0]),
      { recs: byTx(k5.hash), dl5 }
    );
    const [p6] = byTx(k6.hash);
    cell(
      "the owner through its Safe (trace): owner route, the Safe as caller, updatePriceDVT selector",
      p6?.route === "owner" &&
        p6.verdict.flagged &&
        p6.caller === SAFE &&
        p6.callerSource === "trace" &&
        p6.selector === sel("updatePriceDVT(int256,uint256,bytes,uint8)"),
      p6
    );
    cell(
      "a transient tx lookup failure is a dead letter (not a record with from:null)",
      byTx(k7.hash).length === 0 && dls().some(x => x.txHash === k7.hash),
      { recs: byTx(k7.hash) }
    );
    // Next tick: the tx answers and K5's trace appears; both dead letters resolve into records.
    {
      const pu = spIface.encodeEventLog("PriceUpdated", [253000000000n, 6n]);
      c.setTrace(k5.hash, {
        type: "CALL",
        from: KEEPER,
        to: KCONTRACT,
        calls: [
          {
            type: "CALL",
            from: KCONTRACT,
            to: SP,
            input: sel("updatePrice()"),
            logs: [{ address: SP, topics: pu.topics, data: pu.data }],
          },
        ],
      });
    }
    await runOnce(c.chain, cfg, store, rs, ident);
    const [p5] = byTx(k5.hash);
    const [p7] = byTx(k7.hash);
    cell(
      "retried dead letters resolve: the contract-routed keeper call is public (caller = the contract), the tx lookup has a sender",
      p5?.route === "public" &&
        p5.caller === KCONTRACT &&
        p5.from === KEEPER &&
        !p5.verdict.flagged &&
        p7?.route === "owner" &&
        p7.from === SAFE &&
        !dls().some(x => x.txHash === k5.hash || x.txHash === k7.hash),
      { p5, p7, open: dls().map(x => x.txHash) }
    );
    // K8 a failed price read is a dead letter, then a record with both prices
    const k8 = c.ownerTx([{ name: "PriceUpdated", args: [255000000000n, 8n] }], {
      from: KEEPER,
      data: sel("updatePrice()"),
      price: 255000000000n,
    });
    c.failPriceReads(1);
    await runOnce(c.chain, cfg, store, rs, ident);
    const before8 = byTx(k8.hash).length;
    await runOnce(c.chain, cfg, store, rs, ident);
    const [p8] = byTx(k8.hash);
    cell(
      "a failed price read is retried, not stored: the record lands next tick with both prices",
      before8 === 0 &&
        p8?.price?.before?.price === "254000000000" &&
        p8.price.after.price === "255000000000",
      { before8, p8: p8?.price }
    );
    // K9 a dead letter that never resolves: after every attempt, an unattributed record (nobody accused)
    const k9 = c.ownerTx([{ name: "PriceUpdated", args: [256000000000n, 9n] }], {
      from: KEEPER,
      to: KCONTRACT,
      data: "0xdeadbeef",
      price: 256000000000n,
    });
    let last;
    for (let i = 0; i <= MAX_DEADLETTER_ATTEMPTS + 1; i++)
      last = await runOnce(c.chain, cfg, store, rs, ident);
    const [p9] = byTx(k9.hash);
    cell(
      "an unresolvable SP dead letter becomes an 'unattributed' record after the attempt cap (flagged, nobody accused)",
      p9?.route === "unattributed" &&
        p9.verdict.flagged &&
        p9.caller === null &&
        p9.exhaustedAfter >= MAX_DEADLETTER_ATTEMPTS &&
        !dls().some(x => x.txHash === k9.hash) &&
        last.status.exhaustedTotal >= 1,
      { p9, status: last.status }
    );
    // K10 bloom: a lagging node omits a block's logs from the range read; the by-hash re-read has them
    const k10 = c.ownerTx([{ name: "SlashCancelled", args: [addr("lag-op")] }]);
    c.lagBlock(k10.block);
    const r10 = await runOnce(c.chain, cfg, store, rs, ident);
    c.clearLag();
    cell(
      "logsBloom says a watched log is in a block the range read omitted: re-read by hash, recovered",
      r10.status.ok && byTx(k10.hash).length === 1 && r10.status.bloom.recovered === 1,
      r10.status
    );
    // K11 ... and when the node does not have the block at all, the tick fails and is retried
    const k11 = c.ownerTx([{ name: "SlashCancelled", args: [addr("lag-op2")] }]);
    c.lagBlock(k11.block, { byHashFails: true });
    const r11 = await runOnce(c.chain, cfg, store, rs, ident);
    const cur11 = store.getCursor().block;
    c.clearLag();
    const r11b = await runOnce(c.chain, cfg, store, rs, ident);
    cell(
      "a block the node cannot serve by hash fails the tick (cursor stays), and the next tick records it",
      !r11.status.ok && cur11 < k11.block && r11b.status.ok && byTx(k11.hash).length === 1,
      { r11: r11.status.lastError, cur11, b: k11.block }
    );
    // K12 a bloom false positive (the header claims a watched log; by-hash says none): accepted
    const fpBlock = c.mine();
    c.forceBloom(fpBlock, [
      { address: SP, topics: [spIface.getEvent("OperatorSlashed").topicHash] },
    ]);
    const r12 = await runOnce(c.chain, cfg, store, rs, ident);
    cell(
      "a bloom false positive confirmed by a by-hash read is counted, and the scan advances",
      r12.status.ok && r12.status.bloom.falsePositives === 1 && store.getCursor().block >= fpBlock,
      r12.status
    );
    // K13 headers without a bloom: nothing can be cross-checked, counted, the scan advances
    c.setNoBloom(true);
    c.mine();
    const r13 = await runOnce(c.chain, cfg, store, rs, ident);
    c.setNoBloom(false);
    cell(
      "headers without logsBloom: unchecked is counted, never a stop",
      r13.status.ok && r13.status.bloom.unchecked >= 2,
      r13.status
    );
    // K14 a corrupt dead letter never stops the scan; a corrupt record file is rewritten
    writeFileSync(join(d2, "deadletters", "tx-0xbad.json"), "");
    const k14 = c.ownerTx([{ name: "SlashCancelled", args: [addr("corrupt-op")] }]);
    const id14 = Store.recordId({ route: "owner", txHash: k14.hash, logIndex: 0 });
    writeFileSync(join(d2, "records", `${id14}.json`), "");
    const r14 = await runOnce(c.chain, cfg, store, rs, ident);
    cell(
      "a corrupt dead letter is counted, not fatal; an empty record file is rewritten, not 'the same'",
      r14.status.ok &&
        r14.status.corruptDeadLetters === 1 &&
        JSON.parse(readFileSync(join(d2, "records", `${id14}.json`), "utf8")).txHash === k14.hash,
      r14.status
    );
    // C1 (Codex #400-fix H1) a direct updatePrice() whose tx also has an OperatorPaused that
    // updatePrice cannot emit: the root selector is not trusted for it; without a trace, retried
    const c1 = c.ownerTx(
      [
        { name: "PriceUpdated", args: [257000000000n, 10n] },
        { name: "OperatorPaused", args: [addr("nested-op")] },
      ],
      { from: KEEPER, data: sel("updatePrice()"), price: 257000000000n, trace: false }
    );
    // C2 (H2-adjacent) a direct call whose calldata has no selector: ambiguous events are retried
    const c2 = c.ownerTx([{ name: "OperatorPaused", args: [addr("noselector-op")] }], {
      from: KEEPER,
      data: "0x",
    });
    // C1b (R2 H1) a direct updatePrice() WITHOUT a trace whose events are all ones updatePrice can
    // emit: matching names do not prove the emitting call, so it is retried, not attributed
    const c1b = c.ownerTx([{ name: "PriceUpdated", args: [257500000000n, 10n] }], {
      from: KEEPER,
      data: sel("updatePrice()"),
      price: 257500000000n,
      trace: false,
    });
    await runOnce(c.chain, cfg, store, rs, ident);
    cell(
      "a root selector is not trusted for an event its function cannot emit; calldata '0x' proves no function",
      byTx(c1.hash).length === 0 &&
        dls().some(x => x.txHash === c1.hash) &&
        byTx(c2.hash).length === 0 &&
        dls().some(x => x.txHash === c2.hash) &&
        byTx(c1b.hash).length === 0 &&
        dls().some(x => x.txHash === c1b.hash),
      { c1: byTx(c1.hash), c2: byTx(c2.hash) }
    );
    {
      const pu = spIface.encodeEventLog("PriceUpdated", [257000000000n, 10n]);
      const pz = spIface.encodeEventLog("OperatorPaused", [addr("nested-op")]);
      c.setTrace(c1.hash, {
        type: "CALL",
        from: KEEPER,
        to: SP,
        input: sel("updatePrice()"),
        logs: [{ address: SP, topics: pu.topics, data: pu.data, position: 0 }],
        calls: [
          {
            type: "CALL",
            from: SP,
            to: SP,
            input: ethers.id("setOperatorPaused(address,bool)").slice(0, 10),
            logs: [{ address: SP, topics: pz.topics, data: pz.data }],
          },
        ],
      });
    }
    await runOnce(c.chain, cfg, store, rs, ident);
    const c1r = byTx(c1.hash);
    const c1p = c1r.find(r => r.event === "PriceUpdated");
    const c1z = c1r.find(r => r.event === "OperatorPaused");
    cell(
      "with the trace, each event takes its own emitting call: nested privileged call = owner, root = public",
      c1p?.route === "public" &&
        !c1p.verdict.flagged &&
        j(c1p.callEvents) === j(["PriceUpdated"]) &&
        c1z?.route === "owner" &&
        c1z.caller === SP &&
        c1z.callerSource === "trace",
      c1r
    );
    // C3 (M3) an SP record whose price never reads keeps its attribution at exhaustion
    const c3 = c.ownerTx([{ name: "PriceUpdated", args: [258000000000n, 11n] }], {
      from: KEEPER,
      data: sel("updatePrice()"),
      price: 258000000000n,
    });
    {
      const pu = spIface.encodeEventLog("PriceUpdated", [258000000000n, 11n]);
      c.setTrace(c3.hash, {
        type: "CALL",
        from: KEEPER,
        to: SP,
        input: sel("updatePrice()"),
        logs: [{ address: SP, topics: pu.topics, data: pu.data }],
      });
    }
    // C4 (M4) an authenticated BLS price action whose price read fails while its tx lookup also
    // fails: the verified evidence survives, and lands once the price reads
    const priceG = {
      target: SP,
      callData: spIface.encodeFunctionData("updatePriceDVT", [259000000000n, 12n, "0x", 0]),
      requiredThreshold: 2n,
    };
    const c4 = c.execute(Kind.GENERIC, 90n, priceG, 0b111n, { price: 259000000000n });
    c.failPriceReads(1_000_000);
    await runOnce(c.chain, cfg, store, rs, ident);
    const c4dl = dls().find(x => x.txHash === c4.hash);
    c.failTx(c4.hash, 1_000_000); // the lookup keeps failing until exhaustion
    for (let i = 0; i <= MAX_DEADLETTER_ATTEMPTS + 1; i++)
      await runOnce(c.chain, cfg, store, rs, ident);
    c.failPriceReads(0);
    c.failTx(c4.hash, 0);
    const [c3r] = byTx(c3.hash);
    cell(
      "an SP record whose price never reads is kept with its route, caller and verdict (price.unavailable)",
      c3r?.route === "public" &&
        c3r.caller === KEEPER &&
        !c3r.verdict.flagged &&
        c3r.price?.unavailable === true,
      c3r
    );
    const [c4r] = byTx(c4.hash);
    cell(
      "an authenticated BLS action whose price never reads keeps its verified evidence (not UNRECOVERED)",
      c4dl?.status === "PRICE_UNAVAILABLE" &&
        c4r?.kind === "GENERIC" &&
        c4r.price?.unavailable === true &&
        c4r.signers?.length === 3,
      { c4dl: c4dl?.status, c4r: c4r && { kind: c4r.kind, price: c4r.price } }
    );
    // C5 (M5) a tx dead letter whose SP events the trace later proves to be BLS effects resolves
    const c5 = c.execute(Kind.GENERIC, 91n, priceG, 0b111n, {
      via: { route: "safe" },
      spLogs: [{ name: "PriceUpdated", args: [260000000000n, 13n] }],
      price: 260000000000n,
    });
    await runOnce(c.chain, cfg, store, rs, ident);
    const c5open = dls().some(x => x.txHash === c5.hash && x.route === "tx");
    {
      const pu = spIface.encodeEventLog("PriceUpdated", [260000000000n, 13n]);
      c.setTrace(c5.hash, {
        type: "CALL",
        to: SAFE,
        calls: [
          {
            type: "CALL",
            to: AGG,
            logs: [
              {
                address: AGG,
                ...aggIface.encodeEventLog("SignersCommitted", [c5.key, c5.mask]),
                position: 0,
              },
            ],
            calls: [
              {
                type: "CALL",
                from: AGG,
                to: SP,
                input: priceG.callData.slice(0, 10),
                logs: [{ address: SP, topics: pu.topics, data: pu.data }],
              },
            ],
          },
        ],
      });
    }
    await runOnce(c.chain, cfg, store, rs, ident);
    cell(
      "a tx dead letter resolves once the trace proves its SP events are BLS effects (no stray record)",
      c5open &&
        !dls().some(x => x.txHash === c5.hash && x.route === "tx") &&
        !byTx(c5.hash).some(r => r.route !== "bls"),
      {
        c5open,
        open: dls()
          .filter(x => x.txHash === c5.hash)
          .map(x => x.route),
      }
    );
    // C6 (M6) one returned topic must not mask another missing topic in the same block
    const c6 = c.ownerTx([
      { name: "SlashCancelled", args: [addr("two-topics")] },
      { name: "OperatorUnpaused", args: [addr("two-topics")] },
    ]);
    c.lagTopic(c6.block, spIface.getEvent("OperatorUnpaused").topicHash);
    const r6 = await runOnce(c.chain, cfg, store, rs, ident);
    c.clearLag();
    cell(
      "bloom per (address, topic): a missing topic is re-read by hash even when another topic of the block came back",
      byTx(c6.hash).length === 2 && r6.status.bloom.recovered === 1,
      { n: byTx(c6.hash).map(r => r.event), bloom: r6.status.bloom }
    );
    // C7 (R2 M3) an SP record classified already and awaiting only its price lands once the price
    // reads, even while the tx lookup fails: the retry re-reads prices only, never re-attributes
    const c7 = c.ownerTx([{ name: "PriceUpdated", args: [261000000000n, 14n] }], {
      from: KEEPER,
      data: sel("updatePrice()"),
      price: 261000000000n,
    });
    c.failPriceReads(1_000_000);
    await runOnce(c.chain, cfg, store, rs, ident);
    const c7dl = dls().find(x => x.txHash === c7.hash);
    c.failPriceReads(0);
    c.failTx(c7.hash, 1_000_000);
    await runOnce(c.chain, cfg, store, rs, ident);
    c.failTx(c7.hash, 0);
    const [c7r] = byTx(c7.hash);
    cell(
      "a classified SP record awaiting its price lands when the price reads, without re-reading the tx",
      c7dl?.pendingRecords?.length === 1 &&
        c7r?.route === "public" &&
        c7r.callerSource === "trace" &&
        c7r.price &&
        !c7r.price.unavailable &&
        !c7r.price.error &&
        !("priceMissing" in c7r) &&
        !dls().some(x => x.txHash === c7.hash),
      { c7dl: c7dl && { reasons: c7dl.reasons, pending: !!c7dl.pendingRecords }, c7r }
    );
    // C8 (R2 M4) a mixed tx: an authenticated BLS action awaiting its price, and an SP event whose
    // caller is undeterminable (no trace). Retrying the tx must not rebuild the BLS action, so its
    // dead letter takes exactly one attempt per tick (the attempt cap counts ticks).
    const c8 = c.execute(Kind.GENERIC, 92n, priceG, 0b111n, {
      via: { route: "safe" },
      spLogs: [{ name: "OperatorPaused", args: [addr("c8-op")] }],
      price: 262000000000n,
    });
    c.failPriceReads(1_000_000);
    for (let i = 0; i < 3; i++) await runOnce(c.chain, cfg, store, rs, ident);
    const c8bls = dls().find(x => x.txHash === c8.hash && x.route === "bls");
    const c8tx = dls().find(x => x.txHash === c8.hash && x.route === "tx");
    c.failPriceReads(0);
    await runOnce(c.chain, cfg, store, rs, ident);
    const c8r = byTx(c8.hash).find(r => r.route === "bls");
    cell(
      "a tx retry never rebuilds a BLS action already awaiting its price (one attempt per tick)",
      c8bls?.pendingRecord?.kind === "GENERIC" &&
        c8bls.attempts === 3 &&
        c8tx?.attempts === 3 &&
        c8r?.kind === "GENERIC" &&
        c8r.price &&
        !c8r.price.unavailable,
      { bls: c8bls?.attempts, tx: c8tx?.attempts, c8r: c8r && { kind: c8r.kind, price: c8r.price } }
    );
    // C9 (R3 H1) an event no permissionless function emits stays the owner route even when the root
    // call's selector is a public one and no trace is available
    const c9 = c.ownerTx([{ name: "GuardianSet", args: [addr("c9-old"), addr("c9-new")] }], {
      from: KEEPER,
      data: sel("updatePrice()"),
      trace: false,
    });
    await runOnce(c.chain, cfg, store, rs, ident);
    const [c9r] = byTx(c9.hash);
    cell(
      "a privileged-only event under a public root selector is the owner route, flagged (never public)",
      c9r?.route === "owner" && c9r.verdict.flagged && c9r.function === undefined,
      c9r
    );
    // C10 (R3 M) a pending SP record persisted without the priceMissing marker still gets its price
    const legacyTx = ethers.id("legacy-pending");
    store.putDeadLetter({
      route: "tx",
      txHash: legacyTx,
      blockNumber: c3.block,
      status: "ERROR",
      reasons: ["price read failed"],
      events: [],
      pendingRecords: [
        {
          route: "public",
          label: rs.publicRoute.label,
          event: "PriceUpdated",
          args: ["258000000000", "11"],
          txHash: legacyTx,
          logIndex: 0,
          blockNumber: c3.block,
          caller: KEEPER,
          selector: sel("updatePrice()"),
          callerSource: "trace",
          function: "updatePrice()",
          callEvents: ["PriceUpdated"],
          verdict: { flagged: false, reasons: [] },
        },
      ],
      seenAt: "legacy",
    });
    await runOnce(c.chain, cfg, store, rs, ident);
    const [c10r] = byTx(legacyTx);
    cell(
      "a pending record without the priceMissing marker is still priced when the ruleset wants a price",
      c10r?.price?.before !== undefined && c10r.price.after !== undefined && !c10r.price.error,
      c10r
    );
    // K15 maxBlocksPerTick bounds each tick
    for (let i = 0; i < 5; i++) c.mine();
    const from15 = store.getCursor().block + 1;
    const r15 = await runOnce(c.chain, { ...cfg, maxBlocksPerTick: 2 }, store, rs, ident);
    cell(
      "maxBlocksPerTick bounds the scanned range",
      j(r15.status.scanned) === j([from15, from15 + 1]) && store.getCursor().block === from15 + 1,
      r15.status
    );
  } finally {
    rmSync(d2, { recursive: true, force: true });
  }
}

// ---- an unauthenticated BLS action that never resolves becomes an UNRECOVERED record
{
  const d3 = mkdtempSync(join(tmpdir(), "guardian-watcher-unrec-"));
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
    const store = new Store(d3);
    const ident = { commit: "0".repeat(40), hash: ethers.id("ruleset"), verified: true };
    const a = c.execute(Kind.SLASH, 777n, slashF, 0b011n, { to: WRAPPER });
    for (let i = 0; i <= MAX_DEADLETTER_ATTEMPTS + 1; i++)
      await runOnce(c.chain, cfg, store, rs, ident);
    const recs = readdirSync(join(d3, "records"))
      .filter(f => f.endsWith(".json"))
      .map(f => JSON.parse(readFileSync(join(d3, "records", f), "utf8")));
    const u = recs.find(r => r.txHash === a.hash);
    cell(
      "every BLS-executed action ends with a record: UNRECOVERED after the attempt cap (flagged per ruleset)",
      u?.route === "bls" &&
        u.kind === undefined &&
        u.verdict.rule === "bls.UNRECOVERED" &&
        u.verdict.flagged &&
        u.exhaustedAfter >= MAX_DEADLETTER_ATTEMPTS,
      u
    );
  } finally {
    rmSync(d3, { recursive: true, force: true });
  }
}

// ---- trace capability (DSR, #400; Codex #400-fix R4): known only by positive verification
{
  const dirs = [];
  const mk = () => {
    const d = mkdtempSync(join(tmpdir(), "guardian-watcher-trace-"));
    dirs.push(d);
    const c = makeChain();
    const cfg = {
      aggregator: AGG,
      roles: { superPaymaster: SP },
      forwarders: FORWARDERS,
      startBlock: c.head() + 1,
      maxBlocksPerTick: 1000,
      page: 5000,
    };
    return { c, cfg, store: new Store(d) };
  };
  const ident = { commit: "0".repeat(40), hash: ethers.id("ruleset"), verified: true };
  const H = 3_600_000;
  const T0 = 1_900_000_000_000;
  const keeper = {
    from: addr("keeper-eoa"),
    data: ethers.id("pauseUnderstakedOperator(address)").slice(0, 10),
  };
  const pause = n => [{ name: "OperatorPaused", args: [addr(n)] }];
  const guardianSet = n => [{ name: "GuardianSet", args: [addr(`${n}-a`), addr(`${n}-b`)] }];
  const settle = c => {
    for (let i = 0; i < 4; i++) c.mine();
  };
  try {
    // A: a real aligned trace during the scan verifies the capability
    const a = mk();
    a.c.ownerTx(pause("t-a"), keeper);
    settle(a.c);
    const sa = (await runOnce(a.c.chain, a.cfg, a.store, rs, ident, { now: T0 })).status;
    // B: quiet ticks keep a fresh proof; once stale, the node is re-verified and found unsupported
    const sb1 = (await runOnce(a.c.chain, a.cfg, a.store, rs, ident, { now: T0 + H / 2 })).status;
    a.c.setTraceMode("unsupported");
    const sb2 = (await runOnce(a.c.chain, a.cfg, a.store, rs, ident, { now: T0 + H + 1 })).status;
    a.c.setTraceMode("ok");
    // the unsupported verdict cleared the old proof: with no sample in reach, still unverified
    for (let i = 0; i < 6; i++) a.c.mine();
    const sb3 = (await runOnce(a.c.chain, a.cfg, a.store, rs, ident, { now: T0 + H + 2 })).status;
    cell(
      "trace: an aligned scan trace verifies; a quiet tick keeps a fresh proof; a stale proof is re-checked and a missing method is DEGRADED",
      sa.healthy === true &&
        sa.trace.capability === "verified" &&
        sa.trace.thisTick.verified >= 1 &&
        sa.trace.lastCheck === undefined &&
        typeof sa.trace.sampleTx === "string" &&
        sa.trace.sampleTx.length === 66 &&
        sb1.healthy === true &&
        sb1.trace.lastCheck === undefined &&
        sb2.ok === true &&
        sb2.healthy === false &&
        sb2.trace.capability === "unsupported" &&
        sb2.degraded.some(x => /method or tracer missing/.test(x)) &&
        sb3.healthy === false &&
        sb3.trace.capability === "unverified",
      { sa: sa.trace, sb1: sb1.trace, sb2: [sb2.trace, sb2.degraded], sb3: sb3.trace }
    );
    // C: a supporting node with no prior proof and no ambiguous traffic is verified by a sample tx
    const cc = mk();
    cc.c.ownerTx(guardianSet("t-c"));
    settle(cc.c);
    const sc = (await runOnce(cc.c.chain, cc.cfg, cc.store, rs, ident, { now: T0 })).status;
    // D: the same, on a node that ignores withLog: never healthy, even on a quiet tick
    const dd = mk();
    dd.c.ownerTx(guardianSet("t-d"));
    settle(dd.c);
    dd.c.setTraceMode("noLogs");
    const sd = (await runOnce(dd.c.chain, dd.cfg, dd.store, rs, ident, { now: T0 })).status;
    // D2: a sample whose trace carries logs that do not match its receipt proves nothing
    const d2 = mk();
    const mis = d2.c.ownerTx(guardianSet("t-d2"), { trace: false });
    {
      const other = spIface.encodeEventLog("OperatorPaused", [addr("not-this-tx")]);
      d2.c.setTrace(mis.hash, {
        type: "CALL",
        to: SP,
        logs: [{ address: SP, topics: other.topics, data: other.data }],
      });
    }
    settle(d2.c);
    const sd2 = (await runOnce(d2.c.chain, d2.cfg, d2.store, rs, ident, { now: T0 })).status;
    // E: no sample transaction anywhere: unverified, so degraded
    const ee = mk();
    settle(ee.c);
    const se = (await runOnce(ee.c.chain, ee.cfg, ee.store, rs, ident, { now: T0 })).status;
    cell(
      "trace: a supporting quiet node is verified by sampling a real tx; withLog ignored or no evidence is DEGRADED",
      sc.healthy === true &&
        sc.trace.capability === "verified" &&
        sc.trace.lastCheck === "verified" &&
        sd.healthy === false &&
        sd.trace.capability === "unsupported" &&
        sd.degraded.some(x => /withLog/.test(x)) &&
        se.healthy === false &&
        se.trace.capability === "unverified" &&
        sd2.healthy === false &&
        sd2.trace.capability === "unverified" &&
        /align/.test(sd2.trace.reason ?? ""),
      {
        sc: sc.trace,
        sd: [sd.trace, sd.degraded],
        sd2: sd2.trace,
        se: [se.trace, se.degraded],
      }
    );
    // F: a fresh proof, but every real trace this tick fails: degraded with the reason
    a.store.putTraceCapability({ verifiedAt: T0 + 2 * H, txHash: "0x", by: "test" });
    a.c.ownerTx(pause("t-f"), { ...keeper, trace: false });
    settle(a.c);
    const sf = (await runOnce(a.c.chain, a.cfg, a.store, rs, ident, { now: T0 + 2 * H + 1 }))
      .status;
    cell(
      "trace: when every real trace of the tick fails, the watcher is DEGRADED even with a fresh proof",
      sf.ok === true &&
        sf.healthy === false &&
        sf.trace.thisTick.failed >= 1 &&
        sf.degraded.some(x => /trace call\(s\) this tick failed/.test(x)),
      { sf: [sf.trace, sf.degraded] }
    );
    // G: a proof older than 2 x traceVerifyMs, and nothing to re-verify with: DEGRADED
    for (let i = 0; i < 6; i++) a.c.mine();
    const sg = (await runOnce(a.c.chain, a.cfg, a.store, rs, ident, { now: T0 + 5 * H })).status;
    cell(
      "trace: a proof older than twice the verify interval, with no fresh evidence, is DEGRADED",
      sg.ok === true &&
        sg.healthy === false &&
        sg.trace.lastCheck === "unverified" &&
        sg.trace.capability === "stale",
      sg.trace
    );
    // R5: a scan trace showing the method missing drops the proof; the next quiet tick, with no
    // sample in reach, is not healthy again
    const r1 = mk();
    r1.c.ownerTx(pause("r5-1a"), keeper);
    settle(r1.c);
    const r1a = (await runOnce(r1.c.chain, r1.cfg, r1.store, rs, ident, { now: T0 })).status;
    r1.c.setTraceMode("unsupported");
    r1.c.ownerTx(pause("r5-1b"), keeper);
    settle(r1.c);
    const r1b = (await runOnce(r1.c.chain, r1.cfg, r1.store, rs, ident, { now: T0 + 1 })).status;
    r1.c.setTraceMode("ok");
    for (let i = 0; i < 6; i++) r1.c.mine();
    // no trace call at all on the next tick: its dead letter is gone (as after exhaustion)
    {
      const dd = join(dirs.at(-1), "deadletters");
      for (const f of readdirSync(dd).filter(f => f.endsWith(".json"))) rmSync(join(dd, f));
    }
    const r1c = (await runOnce(r1.c.chain, r1.cfg, r1.store, rs, ident, { now: T0 + 2 })).status;
    // R5: on a quiet chain the stored sample, out of the discovery window, re-proves the capability
    const r2 = mk();
    const s2 = r2.c.ownerTx(guardianSet("r5-2"));
    for (let i = 0; i < 12; i++) r2.c.mine();
    r2.store.putTraceCapability({ verifiedAt: T0, txHash: s2.hash, by: "test" });
    const r2a = (await runOnce(r2.c.chain, r2.cfg, r2.store, rs, ident, { now: T0 + 2 * H + 1 }))
      .status;
    // R5: every verification trace fails while the proof is still within 2x: degraded
    const r3 = mk();
    const s3 = r3.c.ownerTx(guardianSet("r5-3"), { trace: false });
    settle(r3.c);
    r3.store.putTraceCapability({ verifiedAt: T0, txHash: s3.hash, by: "test" });
    const r3a = (await runOnce(r3.c.chain, r3.cfg, r3.store, rs, ident, { now: T0 + H + 1 }))
      .status;
    // R5: a receipt with no logs (disagreeing with getLogs) and a log-less trace prove nothing
    const r4 = mk();
    const s4 = r4.c.ownerTx(pause("r5-4"), keeper);
    r4.c.setReceiptLogs(s4.hash, []);
    r4.c.setTraceMode("noLogs");
    settle(r4.c);
    const r4a = (await runOnce(r4.c.chain, r4.cfg, r4.store, rs, ident, { now: T0 })).status;
    r4.c.setTraceMode("ok");
    // a receipt that disagrees with getLogs, but agrees with its trace, is no scan proof either
    const r5 = mk();
    const s5 = r5.c.ownerTx(pause("r5-5"), keeper);
    {
      const g = spIface.encodeEventLog("GuardianSet", [addr("r5-5a"), addr("r5-5b")]);
      const blk = s5.block;
      r5.c.setReceiptLogs(s5.hash, [
        { address: SP, topics: g.topics, data: g.data, index: 0, blockNumber: blk },
      ]);
      r5.c.setTrace(s5.hash, {
        type: "CALL",
        from: keeper.from,
        to: SP,
        input: keeper.data,
        logs: [{ address: SP, topics: g.topics, data: g.data }],
      });
    }
    settle(r5.c);
    const r5a = (await runOnce(r5.c.chain, r5.cfg, r5.store, rs, ident, { now: T0 })).status;
    // R6: a fresh proof exists; the node now ignores withLog and the receipt comes back empty
    const r6 = mk();
    const s6 = r6.c.ownerTx(pause("r6-1"), keeper);
    r6.c.setReceiptLogs(s6.hash, []);
    r6.c.setTraceMode("noLogs");
    settle(r6.c);
    r6.store.putTraceCapability({ verifiedAt: T0, txHash: null, by: "test" });
    const r6a = (await runOnce(r6.c.chain, r6.cfg, r6.store, rs, ident, { now: T0 + 1 })).status;
    r6.c.setTraceMode("ok");
    // R6: receipt and trace carry OperatorPaused(B) where getLogs saw OperatorPaused(A)
    const r7 = mk();
    const s7 = r7.c.ownerTx(pause("r6-A"), keeper);
    {
      const b = spIface.encodeEventLog("OperatorPaused", [addr("r6-B")]);
      r7.c.setReceiptLogs(s7.hash, [
        { address: SP, topics: b.topics, data: b.data, index: 0, blockNumber: s7.block },
      ]);
      r7.c.setTrace(s7.hash, {
        type: "CALL",
        from: keeper.from,
        to: SP,
        input: keeper.data,
        logs: [{ address: SP, topics: b.topics, data: b.data }],
      });
    }
    settle(r7.c);
    r7.store.putTraceCapability({ verifiedAt: T0, txHash: null, by: "test" });
    const r7a = (await runOnce(r7.c.chain, r7.cfg, r7.store, rs, ident, { now: T0 + 1 })).status;
    const r7dir = dirs.at(-1);
    const r7recs = readdirSync(join(r7dir, "records")).filter(f => f.endsWith(".json"));
    // R7: the retry is judged against the stored getLogs evidence, not the disputed receipt
    const r7b = (await runOnce(r7.c.chain, r7.cfg, r7.store, rs, ident, { now: T0 + 2 })).status;
    const r7recs2 = readdirSync(join(r7dir, "records")).filter(f => f.endsWith(".json"));
    const r7dl = r7.store.listDeadLetters().find(x => x.txHash === s7.hash);
    const r6b = (await runOnce(r6.c.chain, r6.cfg, r6.store, rs, ident, { now: T0 + 2 })).status;
    const r6dl = r6.store.listDeadLetters().find(x => x.txHash === s6.hash);
    // R7: a tx dead letter without stored evidence re-reads its watched logs by block hash
    const r8 = mk();
    const s8 = r8.c.ownerTx(pause("r7-legacy"), { ...keeper, trace: false });
    settle(r8.c);
    await runOnce(r8.c.chain, r8.cfg, r8.store, rs, ident, { now: T0 });
    {
      // strip the stored evidence, as in a dead letter written before it existed
      const dd = join(dirs.at(-1), "deadletters");
      const f8 = readdirSync(dd).find(f => f.startsWith("tx-") && f.endsWith(".json"));
      const v = JSON.parse(readFileSync(join(dd, f8), "utf8"));
      delete v.watched;
      writeFileSync(join(dd, f8), JSON.stringify(v));
    }
    {
      const pz = spIface.encodeEventLog("OperatorPaused", [addr("r7-legacy")]);
      r8.c.setTrace(s8.hash, {
        type: "CALL",
        from: keeper.from,
        to: SP,
        input: keeper.data,
        logs: [{ address: SP, topics: pz.topics, data: pz.data }],
      });
    }
    const r8a = (await runOnce(r8.c.chain, r8.cfg, r8.store, rs, ident, { now: T0 + 1 })).status;
    const r8recs = readdirSync(join(dirs.at(-1), "records"))
      .filter(f => f.endsWith(".json"))
      .map(f => JSON.parse(readFileSync(join(dirs.at(-1), "records", f), "utf8")))
      .filter(r => r.txHash === s8.hash);
    // R8: the receipt holds A and a different B at the same position; the trace matches both
    const r9 = mk();
    const s9 = r9.c.ownerTx(pause("r8-A"), keeper);
    {
      const a = spIface.encodeEventLog("OperatorPaused", [addr("r8-A")]);
      const b = spIface.encodeEventLog("OperatorPaused", [addr("r8-B")]);
      const kp = ethers.id("updatePrice()").slice(0, 10);
      r9.c.setReceiptLogs(s9.hash, [
        { address: SP, topics: a.topics, data: a.data, index: 0, blockNumber: s9.block },
        { address: SP, topics: b.topics, data: b.data, index: 0, blockNumber: s9.block },
      ]);
      r9.c.setTrace(s9.hash, {
        type: "CALL",
        from: keeper.from,
        to: SP,
        input: keeper.data,
        logs: [{ address: SP, topics: a.topics, data: a.data, position: 0 }],
        calls: [
          {
            type: "CALL",
            from: addr("r8-other"),
            to: SP,
            input: kp,
            logs: [{ address: SP, topics: b.topics, data: b.data }],
          },
        ],
      });
    }
    settle(r9.c);
    const r9dir = dirs.at(-1);
    r9.store.putTraceCapability({ verifiedAt: T0, txHash: null, by: "test" });
    const r9a = (await runOnce(r9.c.chain, r9.cfg, r9.store, rs, ident, { now: T0 + 1 })).status;
    const r9b = (await runOnce(r9.c.chain, r9.cfg, r9.store, rs, ident, { now: T0 + 2 })).status;
    const r9recs = readdirSync(join(r9dir, "records")).filter(f => f.endsWith(".json"));
    // R8: an extra watched log at a free position, and a duplicated position on an unwatched log
    const extraCase = async (mkLogs, tag) => {
      const r = mk();
      const sx = r.c.ownerTx(pause(`r8-${tag}`), keeper);
      const a = spIface.encodeEventLog("OperatorPaused", [addr(`r8-${tag}`)]);
      const rl = mkLogs(a, sx.block);
      r.c.setReceiptLogs(sx.hash, rl);
      r.c.setTrace(sx.hash, {
        type: "CALL",
        from: keeper.from,
        to: SP,
        input: keeper.data,
        logs: rl.map(l => ({ address: l.address, topics: l.topics, data: l.data })),
      });
      settle(r.c);
      r.store.putTraceCapability({ verifiedAt: T0, txHash: null, by: "test" });
      return (await runOnce(r.c.chain, r.cfg, r.store, rs, ident, { now: T0 + 1 })).status;
    };
    const extraW = await extraCase((a, blk) => {
      const b = spIface.encodeEventLog("OperatorPaused", [addr("r8-extra-B")]);
      return [
        { address: SP, topics: a.topics, data: a.data, index: 0, blockNumber: blk },
        { address: SP, topics: b.topics, data: b.data, index: 1, blockNumber: blk },
      ];
    }, "extra");
    const dupU = await extraCase(
      (a, blk) => [
        { address: SP, topics: a.topics, data: a.data, index: 0, blockNumber: blk },
        { address: AGG, topics: [ethers.ZeroHash], data: "0x", index: 0, blockNumber: blk },
      ],
      "dup"
    );
    const upper = x => "0x" + x.slice(2).toUpperCase();
    const caseR = await extraCase(
      (a, blk) => [
        {
          address: SP,
          topics: a.topics.map(upper),
          data: upper(a.data),
          index: 0,
          blockNumber: blk,
        },
      ],
      "case"
    );
    // R12: an invalid receipt position is handled per tx (inconsistent), never aborts the tick;
    // a consistent receipt whose trace cannot align (noncontiguous positions) is a health finding
    const badPos = await extraCase(
      (a, blk) => [{ address: SP, topics: a.topics, data: a.data, index: false, blockNumber: blk }],
      "badpos"
    );
    const gap = await extraCase(
      (a, blk) => [
        { address: SP, topics: a.topics, data: a.data, index: 0, blockNumber: blk },
        { address: AGG, topics: [ethers.ZeroHash], data: "0x", index: 2, blockNumber: blk },
      ],
      "gap"
    );
    cell(
      "trace R12: an invalid receipt position is a per-tx inconsistency (tick ok); a consistent receipt that cannot align degrades",
      badPos.ok === true &&
        badPos.trace.thisTick.inconsistent === 1 &&
        gap.ok === true &&
        gap.trace.thisTick.unaligned === 1 &&
        !gap.trace.thisTick.verified &&
        gap.healthy === false &&
        gap.degraded.some(x => /did not align/.test(x)),
      { badPos: [badPos.ok, badPos.lastError, badPos.trace], gap: [gap.trace, gap.degraded] }
    );
    // R13: a stale backend answers receipt + trace from an orphaned earlier inclusion
    const orphan = mk();
    const so = orphan.c.ownerTx(pause("r13-orphan"), keeper);
    orphan.c.patchReceipt(so.hash, { blockNumber: so.block - 1, blockHash: ethers.id("orphan") });
    settle(orphan.c);
    orphan.store.putTraceCapability({ verifiedAt: T0, txHash: null, by: "test" });
    const sOr = (
      await runOnce(orphan.c.chain, orphan.cfg, orphan.store, rs, ident, { now: T0 + 1 })
    ).status;
    const orRecs = readdirSync(join(dirs.at(-1), "records")).filter(f => f.endsWith(".json"));
    const orDl = orphan.store.listDeadLetters().find(x => x.txHash === so.hash);
    // R14: a legacy dead letter (evidence without blockHash) is anchored on the canonical header
    const leg = mk();
    const sl = leg.c.ownerTx(pause("r14-legacy"), { ...keeper, trace: false });
    settle(leg.c);
    await runOnce(leg.c.chain, leg.cfg, leg.store, rs, ident, { now: T0 });
    {
      const dd = join(dirs.at(-1), "deadletters");
      const fl = readdirSync(dd).find(f => f.startsWith("tx-") && f.endsWith(".json"));
      const v = JSON.parse(readFileSync(join(dd, fl), "utf8"));
      for (const w of v.watched) delete w.blockHash;
      writeFileSync(join(dd, fl), JSON.stringify(v));
    }
    {
      const pz = spIface.encodeEventLog("OperatorPaused", [addr("r14-legacy")]);
      leg.c.setTrace(sl.hash, {
        type: "CALL",
        logs: [{ address: SP, topics: pz.topics, data: pz.data }],
      });
    }
    // same height, orphaned inclusion: hash differs from the canonical header
    leg.c.patchReceipt(sl.hash, { blockHash: ethers.id("r14-orphan") });
    const sLeg = (await runOnce(leg.c.chain, leg.cfg, leg.store, rs, ident, { now: T0 + 1 }))
      .status;
    const legRecs = readdirSync(join(dirs.at(-1), "records")).filter(f => f.endsWith(".json"));
    leg.c.patchReceipt(sl.hash, {});
    const sLeg2 = (await runOnce(leg.c.chain, leg.cfg, leg.store, rs, ident, { now: T0 + 2 }))
      .status;
    const legRecs2 = readdirSync(join(dirs.at(-1), "records")).filter(f => f.endsWith(".json"));
    cell(
      "trace R14: a legacy dead letter is anchored on the canonical header: an orphaned same-height receipt is refused, the canonical one attributes",
      sLeg.trace.thisTick.inconsistent === 1 &&
        legRecs.length === 0 &&
        sLeg2.trace.thisTick.verified === 1 &&
        legRecs2.length === 1,
      { sLeg: sLeg.trace, legRecs, sLeg2: sLeg2.trace, legRecs2 }
    );
    cell(
      "trace R13: a receipt from another inclusion (block) is inconsistent: no record, no proof, degraded; the dead letter keeps the block hash",
      sOr.trace.thisTick.inconsistent === 1 &&
        !sOr.trace.thisTick.verified &&
        orRecs.length === 0 &&
        sOr.healthy === false &&
        typeof orDl?.watched?.[0]?.blockHash === "string",
      { trace: sOr.trace, orRecs, w: orDl?.watched }
    );
    cell(
      "trace R9: a receipt differing from getLogs only in hex case is consistent (supporting node stays healthy)",
      !caseR.trace.thisTick.inconsistent && caseR.trace.thisTick.verified === 1 && caseR.healthy,
      caseR.trace
    );
    // R11: a trace whose root is not the tx (input or sender differ) is inconsistent
    const rootCase = async (patch, tag) => {
      const r = mk();
      const sx = r.c.ownerTx(pause(`r11-${tag}`), keeper);
      const a = spIface.encodeEventLog("OperatorPaused", [addr(`r11-${tag}`)]);
      r.c.setTrace(sx.hash, {
        type: "CALL",
        from: keeper.from,
        to: SP,
        input: keeper.data,
        logs: [{ address: SP, topics: a.topics, data: a.data }],
        ...patch,
      });
      settle(r.c);
      r.store.putTraceCapability({ verifiedAt: T0, txHash: null, by: "test" });
      const st = (await runOnce(r.c.chain, r.cfg, r.store, rs, ident, { now: T0 + 1 })).status;
      const recs = readdirSync(join(dirs.at(-1), "records")).filter(f => f.endsWith(".json"));
      return { st, recs };
    };
    const rootIn = await rootCase({ input: "0xdeadbeef" }, "input");
    const rootFrom = await rootCase({ from: addr("r11-other") }, "from");
    const rootOk = await rootCase({}, "ok");
    cell(
      "trace R11: a trace root that is not the tx (input or sender differ) is inconsistent: no record, no proof, degraded",
      [rootIn, rootFrom].every(
        x =>
          x.st.trace.thisTick.inconsistent === 1 &&
          !x.st.trace.thisTick.verified &&
          x.recs.length === 0 &&
          x.st.healthy === false
      ) &&
        rootOk.st.healthy === true &&
        rootOk.st.trace.thisTick.verified === 1 &&
        rootOk.recs.length === 1,
      { rootIn: rootIn.st.trace, rootFrom: rootFrom.st.trace, rootOk: rootOk.st.trace }
    );
    cell(
      "trace R8: a receipt with an extra watched log, or a duplicated position on any log, is inconsistent",
      extraW.trace.thisTick.inconsistent === 1 &&
        !extraW.trace.thisTick.verified &&
        dupU.trace.thisTick.inconsistent === 1 &&
        !dupU.trace.thisTick.verified,
      { extraW: extraW.trace, dupU: dupU.trace }
    );
    const dupAttr = attributeLogs(
      { type: "CALL", to: SP, logs: [] },
      [
        { address: SP, topics: [], data: "0x", index: 0 },
        { address: SP, topics: [], data: "0x", index: 0 },
      ],
      AGG,
      SP
    );
    cell(
      "trace R8: duplicated receipt positions or extra watched logs are inconsistent (first tick and retry); attributeLogs refuses duplicate positions",
      r9a.trace.thisTick.inconsistent === 1 &&
        r9b.trace.thisTick.inconsistent === 1 &&
        !r9a.trace.thisTick.verified &&
        !r9b.trace.thisTick.verified &&
        r9recs.length === 0 &&
        r9b.healthy === false &&
        dupAttr.aligned === false &&
        /duplicated/.test(dupAttr.why),
      { r9a: r9a.trace, r9b: r9b.trace, r9recs, dupAttr: dupAttr.why }
    );
    cell(
      "trace R7: retries use the stored getLogs evidence (a disputed or empty receipt never closes the dead letter); a legacy dead letter re-reads by block hash",
      r7b.healthy === false &&
        r7recs2.length === 0 &&
        r7dl?.watched?.length === 1 &&
        r7b.trace.thisTick.inconsistent === 1 &&
        r6b.healthy === false &&
        r6dl?.watched?.length === 1 &&
        r8a.ok === true &&
        r8recs.length === 1 &&
        r8recs[0].route === "public",
      {
        r7b: [r7b.trace, r7b.degraded],
        r7recs2,
        r7dl: r7dl && { w: r7dl.watched?.length, a: r7dl.attempts },
        r6b: r6b.trace,
        r6dl: r6dl && { w: r6dl.watched?.length },
        r8: [r8a.ok, r8a.lastError, r8recs],
      }
    );
    cell(
      "trace R6: watched logs make a log-less trace unsupported even with an empty receipt; a receipt with other contents is inconsistent (no attribution, degraded, proof dropped)",
      r6a.healthy === false &&
        r6a.trace.thisTick.noLogs >= 1 &&
        r6a.trace.capability !== "verified" &&
        r7a.healthy === false &&
        r7a.trace.thisTick.inconsistent === 1 &&
        !r7a.trace.thisTick.verified &&
        r7a.degraded.some(x => /disagrees with getLogs/.test(x)) &&
        r7recs.length === 0,
      { r6: [r6a.trace, r6a.degraded], r7: [r7a.trace, r7a.degraded], r7recs }
    );
    cell(
      "trace R5: unsupported in the scan drops the proof; a stored sample re-proves a quiet chain; failed verification traces degrade; an empty receipt proves nothing",
      r1a.healthy === true &&
        r1b.healthy === false &&
        r1c.healthy === false &&
        r1c.trace.capability === "unverified" &&
        r2a.healthy === true &&
        r2a.trace.lastCheck === "verified" &&
        r2a.trace.sampleTx === s2.hash &&
        r3a.healthy === false &&
        r3a.degraded.some(x => /verification: 1 sample trace/.test(x)) &&
        r4a.healthy === false &&
        r4a.trace.capability !== "verified" &&
        !r4a.trace.thisTick.verified &&
        !r5a.trace.thisTick.verified,
      {
        r1: [r1a.trace, r1b.degraded, r1c.trace],
        r2: r2a.trace,
        r3: [r3a.trace, r3a.degraded],
        r4: [r4a.trace, r4a.degraded],
        r5: r5a.trace,
      }
    );
    const failed = (
      await runOnce(
        {
          ...a.c.chain,
          send: async (m, p) => {
            if (m === "eth_getBlockByNumber") throw new Error("down");
            return a.c.chain.send(m, p);
          },
        },
        a.cfg,
        a.store,
        rs,
        ident,
        { now: T0 + 5 * H + 1 }
      )
    ).status;
    cell(
      "a failed tick is never healthy, and still reports the trace capability",
      failed.ok === false && failed.healthy === false && failed.trace?.capability === "stale",
      failed
    );
  } finally {
    for (const d of dirs) rmSync(d, { recursive: true, force: true });
  }
  {
    // traceHealth alone, on a chain with no sample: a scan trace that shows the capability missing
    // drops the fresh proof, so the next quiet tick (no trace calls at all) is not healthy
    const d6 = mkdtempSync(join(tmpdir(), "guardian-watcher-th-"));
    try {
      const st = new Store(d6);
      const empty = {
        send: async m => (m === "eth_getBlockByNumber" ? { transactions: [] } : null),
        getTransactionReceipt: async () => null,
      };
      const thCfg = { aggregator: AGG, roles: { superPaymaster: SP } };
      st.putTraceCapability({ verifiedAt: 1000, txHash: null, by: "test" });
      const h0 = await traceHealth(empty, thCfg, st, {}, 50, 2000);
      const h1 = await traceHealth(empty, thCfg, st, { unsupported: 1 }, 50, 3000);
      const h2 = await traceHealth(empty, thCfg, st, {}, 50, 4000);
      const h3 = await traceHealth(empty, thCfg, st, { noLogs: 1 }, 50, 5000);
      cell(
        "traceHealth: unsupported or log-less scan traces drop the proof; a quiet tick after that is not healthy",
        h0.degraded === null &&
          h1.degraded !== null &&
          h2.degraded !== null &&
          h2.trace.capability === "unverified" &&
          h3.degraded !== null,
        { h0, h1: h1.degraded, h2: [h2.trace, h2.degraded] }
      );
      st.putTraceCapability({ verifiedAt: 1000, txHash: null, by: "test" });
      await traceHealth(empty, thCfg, st, { noLogs: 1 }, 50, 6000);
      const h4 = await traceHealth(empty, thCfg, st, {}, 50, 7000);
      cell("traceHealth: a log-less scan trace also drops the proof", h4.degraded !== null, h4);
      st.putTraceCapability({ verifiedAt: 1000, txHash: null, by: "test" });
      await traceHealth(empty, thCfg, st, { inconsistent: 1 }, 50, 8000);
      const h5 = await traceHealth(empty, thCfg, st, {}, 50, 9000);
      cell(
        "traceHealth: a receipt that disagrees with getLogs also drops the proof",
        h5.degraded !== null && h5.trace.capability === "unverified",
        h5
      );
    } finally {
      rmSync(d6, { recursive: true, force: true });
    }
  }
  const e = (code, message) => Object.assign(new Error(message), { error: { code, message } });
  cell(
    "traceUnsupported: method-missing answers are unsupported; lookup misses and transport errors are not",
    traceUnsupported(e(-32601, "x")) &&
      traceUnsupported(
        new Error("the method debug_traceTransaction does not exist/is not available")
      ) &&
      traceUnsupported(new Error("Method not found")) &&
      traceUnsupported(new Error("debug namespace is disabled")) &&
      traceUnsupported(new Error('unknown tracer "callTracer"')) &&
      !traceUnsupported(new Error("transaction not found")) &&
      !traceUnsupported(new Error("Cannot find block hash for transaction 0x01")) &&
      !traceUnsupported(new Error("execution timeout")) &&
      !traceUnsupported(Object.assign(new Error("x"), { code: "ECONNRESET" })),
    null
  );
  {
    const pu = spIface.encodeEventLog("PriceUpdated", [1n, 2n]);
    const l = { address: SP, topics: pu.topics, data: pu.data, index: 3 };
    const up = x => ({ ...x, address: x.address.toUpperCase().replace("0X", "0x") });
    cell(
      "sameLog: position, address, every topic and data must all match (hex case ignored)",
      sameLog(l, up(l)) &&
        !sameLog(l, { ...l, index: 4 }) &&
        !sameLog(l, { ...l, address: AGG }) &&
        !sameLog(l, {
          ...l,
          data: ethers.AbiCoder.defaultAbiCoder().encode(["int256", "uint256"], [1n, 3n]),
        }) &&
        !sameLog(l, { ...l, topics: [...l.topics, ethers.ZeroHash] }) &&
        !sameLog({ ...l, index: false }, l) &&
        !sameLog({ ...l, index: 3, logIndex: 4 }, l),
      null
    );
  }
  {
    // R9: a trace log whose explicit position is outside [0, calls.length] makes the trace unsure
    const pz = spIface.encodeEventLog("OperatorPaused", [addr("r9")]);
    const lg = { address: SP, topics: pz.topics, data: pz.data };
    const tr = pos => ({
      type: "CALL",
      from: addr("root"),
      to: SP,
      input: "0x11111111",
      logs: [{ ...lg, position: pos }],
      calls: [{ type: "CALL", from: addr("child"), to: SP, input: "0x22222222", logs: [lg] }],
    });
    const rc = [
      { ...lg, index: 0 },
      { ...lg, index: 1 },
    ];
    // a single-log receipt: a dropped root log would leave the child's identical log to align
    const bad = [2, -1, 0.5, "x", true, false, "", [0], {}, "0x"].map(
      p => attributeLogs(tr(p), [{ ...lg, index: 0 }], AGG, SP).aligned
    );
    const good = attributeLogs(tr("0x1"), rc, AGG, SP);
    // positions that decrease within a frame are contradictory, never reordered
    const dec = attributeLogs(
      {
        type: "CALL",
        from: addr("root"),
        to: SP,
        input: "0x11111111",
        logs: [
          { ...lg, position: 1 },
          { ...lg, position: 0 },
        ],
        calls: [{ type: "CALL", from: addr("child"), to: SP, input: "0x22222222", logs: [lg] }],
      },
      [0, 1, 2].map(i => ({ ...lg, index: i })),
      AGG,
      SP
    );
    cell(
      "attribution: a trace log position that is not an in-range integer (number or decimal/0x string), or that decreases within a frame, makes the trace unusable; a hex position is read",
      bad.every(a => a === false) &&
        [2, -1, 0.5, "x", true, false, "", [0], {}, "0x"].every(
          p => flattenTraceLogs(tr(p), AGG, SP) === null
        ) &&
        dec.aligned === false &&
        good.aligned === true &&
        good.spCall.get(0)?.from === addr("child"),
      { bad, good: [...good.spCall] }
    );
  }
  {
    const pz = spIface.encodeEventLog("OperatorPaused", [addr("r11u")]);
    const L = { address: SP, topics: pz.topics, data: pz.data };
    cell(
      "validLog: string 20-byte address, <=4 32-byte topics, even-length hex data; LOG0 ok",
      validLog(L) &&
        validLog({ ...L, topics: [] }) &&
        !validLog({ ...L, address: [SP] }) &&
        !validLog({ ...L, address: "0x1" }) &&
        !validLog({ ...L, topics: [[pz.topics[0]]] }) &&
        !validLog({ ...L, topics: ["0x1"] }) &&
        !validLog({ ...L, topics: Array(5).fill(pz.topics[0]) }) &&
        !validLog({ ...L, data: "0x1" }) &&
        !validLog({ ...L, data: ["0x"] }) &&
        !validLog({ ...L, data: undefined }) &&
        attributeLogs(
          { type: "CALL", to: SP, logs: [{ ...L, address: [SP] }] },
          [{ ...L, index: 0 }],
          AGG,
          SP
        ).aligned === false,
      null
    );
    const bads = [false, true, [], [0], "", " 1", "1e0", "0b1", -1, 1.5].map(v =>
      receiptPos({ index: v })
    );
    const t2 = n => ({ type: "CALL", to: SP, logs: Array(n).fill(L) });
    cell(
      "receiptPos strict (aliases must agree); receipt positions must be unique and contiguous (a nonzero offset is fine)",
      bads.every(x => x === null) &&
        receiptPos({ index: 0, logIndex: 99 }) === null &&
        receiptPos({ index: 3, logIndex: "0x3" }) === 3 &&
        receiptPos({ logIndex: "0x2" }) === 2 &&
        attributeLogs(
          t2(2),
          [
            { ...L, index: 0 },
            { ...L, index: 2 },
          ],
          AGG,
          SP
        ).aligned === false &&
        attributeLogs(
          t2(2),
          [
            { ...L, index: 5 },
            { ...L, index: 6 },
          ],
          AGG,
          SP
        ).aligned === true,
      { bads }
    );
    const H0 = ethers.id("tx-0");
    const ok = { from: addr("u"), to: SP, data: "0x12345678" };
    const tr = { type: "CALL", from: addr("u"), to: SP, input: "0x12345678" };
    const rc = (x = {}) => ({ transactionHash: H0, status: 1, logs: [{ ...L, index: 0 }], ...x });
    cell(
      "envelopeProblem: receipt for another tx, failed receipt with logs, removed / foreign logs, and a trace root that is not the tx are refused",
      envelopeProblem(H0, ok, rc(), tr) === null &&
        envelopeProblem(H0, { ...ok, to: null }, rc(), { ...tr, type: "CREATE", to: addr("c") }) ===
          null &&
        /another tx/.test(envelopeProblem(H0, ok, rc({ transactionHash: ethers.id("x") }), tr)) &&
        /explicit success/.test(envelopeProblem(H0, ok, rc({ status: 0 }), tr)) &&
        /explicit success/.test(envelopeProblem(H0, ok, rc({ status: undefined }), tr)) &&
        /does not name/.test(envelopeProblem(H0, ok, rc({ transactionHash: undefined }), tr)) &&
        envelopeProblem(H0, ok, rc({ transactionHash: undefined, hash: H0, status: "0x1" }), tr) ===
          null &&
        /another tx/.test(envelopeProblem(H0, ok, rc({ hash: ethers.id("z") }), tr)) &&
        /removed/.test(
          envelopeProblem(H0, ok, rc({ logs: [{ ...L, index: 0, removed: true }] }), tr)
        ) &&
        /another tx/.test(
          envelopeProblem(
            H0,
            ok,
            rc({ logs: [{ ...L, index: 0, transactionHash: ethers.id("y") }] }),
            tr
          )
        ) &&
        /sender/.test(envelopeProblem(H0, ok, rc(), { ...tr, from: addr("v") })) &&
        /destination/.test(envelopeProblem(H0, ok, rc(), { ...tr, to: addr("v") })) &&
        /destination/.test(envelopeProblem(H0, { ...ok, to: null }, rc(), tr)) &&
        /input/.test(envelopeProblem(H0, ok, rc(), { ...tr, input: "0x12345679" })),
      null
    );
    const B = { blockNumber: 7, blockHash: ethers.id("b7") };
    const rcB = (x = {}) => rc({ ...B, ...x });
    cell(
      "envelopeProblem: receipt, its logs and the tx must name the evidence's block",
      envelopeProblem(H0, ok, rcB(), tr, B) === null &&
        envelopeProblem(H0, { ...ok, ...B }, rcB(), tr, B) === null &&
        /another block/.test(
          envelopeProblem(H0, ok, rcB({ blockHash: ethers.id("b7x") }), tr, B)
        ) &&
        /another block/.test(envelopeProblem(H0, ok, rcB({ blockNumber: 6 }), tr, B)) &&
        /does not name its block/.test(
          envelopeProblem(H0, ok, rcB({ blockHash: undefined }), tr, B)
        ) &&
        /another block/.test(
          envelopeProblem(H0, { ...ok, blockHash: ethers.id("b7y") }, rcB(), tr, B)
        ) &&
        /another block/.test(
          envelopeProblem(H0, ok, rcB({ logs: [{ ...L, index: 0, blockNumber: 8 }] }), tr, B)
        ),
      null
    );
    const noPosParent = child =>
      attributeLogs(
        {
          type: "CALL",
          to: SP,
          logs: [L],
          calls: [{ type: "CALL", from: SP, to: AGG, logs: child }],
        },
        child.length
          ? [
              { ...L, index: 0 },
              { ...L, index: 1 },
            ]
          : [{ ...L, index: 0 }],
        AGG,
        SP
      ).aligned;
    cell(
      "positionless logs (geth before positions) are accepted when no child has a surviving log, refused when ambiguous",
      noPosParent([]) === true && noPosParent([L]) === false,
      null
    );
    const nullTrace = await verifyTrace(
      {
        send: async m =>
          m === "eth_getBlockByNumber" ? { transactions: [ethers.id("s1")] } : null,
        getTransactionReceipt: async () => ({ status: 1, logs: [{ ...L, index: 0 }] }),
        getTransaction: async () => ok,
      },
      { aggregator: AGG, roles: { superPaymaster: SP } },
      10,
      { blocks: 1 }
    );
    const vt = input =>
      verifyTrace(
        {
          send: async m =>
            m === "eth_getBlockByNumber"
              ? { transactions: [ethers.id("s2")] }
              : { type: "CALL", from: ok.from, to: SP, input, logs: [L] },
          getTransactionReceipt: async () => ({
            transactionHash: ethers.id("s2"),
            status: 1,
            logs: [{ ...L, index: 0 }],
          }),
          getTransaction: async () => ok,
        },
        { aggregator: AGG, roles: { superPaymaster: SP } },
        10,
        { blocks: 1 }
      );
    const vMis = await vt("0xdeadbeef");
    const vOk = await vt(ok.data);
    cell(
      "verifyTrace: a sample whose trace root is not its tx proves nothing; the matching root verifies",
      vMis.state === "unverified" && /input differs/.test(vMis.reason) && vOk.state === "verified",
      { vMis, vOk }
    );
    const vs = canon =>
      verifyTrace(
        {
          send: async (m, p) =>
            m === "eth_getBlockByNumber"
              ? p[0] === ethers.toQuantity(9)
                ? { number: "0x9", hash: canon, transactions: [] }
                : { transactions: [] }
              : { type: "CALL", from: ok.from, to: SP, input: ok.data, logs: [L] },
          getTransactionReceipt: async () => ({
            transactionHash: ethers.id("s3"),
            status: 1,
            blockNumber: 9,
            blockHash: ethers.id("b9"),
            logs: [{ ...L, index: 0 }],
          }),
          getTransaction: async () => ok,
        },
        { aggregator: AGG, roles: { superPaymaster: SP } },
        20,
        { blocks: 1, sampleTx: ethers.id("s3") }
      );
    const vCanon = await vs(ethers.id("b9"));
    const vStale = await vs(ethers.id("b9-reorged"));
    cell(
      "verifyTrace: the stored sample proves only while its receipt's block is still canonical",
      vCanon.state === "verified" &&
        vStale.state === "unverified" &&
        /another block/.test(vStale.reason),
      { vCanon, vStale }
    );
    cell(
      "verifyTrace: a null trace answer is inconclusive (unverified, counted failed), not 'unsupported'",
      nullTrace.state === "unverified" && nullTrace.failed === 1,
      nullTrace
    );
  }
  cell(
    "verifyTrace: a chain without send() is unsupported",
    (await verifyTrace({}, { roles: {} }, 10)).state === "unsupported",
    null
  );
}

// ---- #400 review L1–L5 and nits
{
  const dirs = [];
  const mk = () => {
    const d = mkdtempSync(join(tmpdir(), "guardian-watcher-rev-"));
    dirs.push(d);
    const c = makeChain();
    const cfg = {
      aggregator: AGG,
      roles: { superPaymaster: SP },
      forwarders: FORWARDERS,
      startBlock: c.head() + 1,
      maxBlocksPerTick: 1000,
      page: 5000,
    };
    const recs = () =>
      readdirSync(join(d, "records"))
        .filter(f => f.endsWith(".json"))
        .map(f => JSON.parse(readFileSync(join(d, "records", f), "utf8")));
    return { d, c, cfg, store: new Store(d), recs };
  };
  const ident = { commit: "0".repeat(40), hash: ethers.id("ruleset"), verified: true };
  const KEEPER = addr("rev-keeper");
  const pauseSel = ethers.id("pauseUnderstakedOperator(address)").slice(0, 10);
  const settle = c => {
    for (let i = 0; i < 4; i++) c.mine();
  };
  const priceG = {
    target: SP,
    callData: spIface.encodeFunctionData("updatePriceDVT", [261000000000n, 20n, "0x", 0]),
    requiredThreshold: 2n,
  };
  try {
    // L1: an inner frame with a malformed `from` makes the trace unusable (a retried dead letter),
    // never an exception that stops the scan; a malformed aggregator log (no key) is isolated as a
    // dead letter with its evidence, ends as an unattributed record, and the scan moves on
    const a = mk();
    const t1 = a.c.ownerTx([{ name: "OperatorPaused", args: [addr("rev-l1")] }], {
      from: KEEPER,
      data: pauseSel,
    });
    {
      const pz = spIface.encodeEventLog("OperatorPaused", [addr("rev-l1")]);
      a.c.setTrace(t1.hash, {
        type: "CALL",
        from: KEEPER,
        to: SP,
        input: pauseSel,
        calls: [
          {
            type: "CALL",
            from: "0x1234",
            to: SP,
            input: pauseSel,
            logs: [{ address: SP, topics: pz.topics, data: pz.data }],
          },
        ],
      });
    }
    const bad = a.c.mine();
    a.c.injectLog(bad, {
      address: AGG,
      topics: [aggIface.getEvent("SignersCommitted").topicHash],
      data: "0x",
      transactionHash: ethers.id("rev-malformed"),
    });
    settle(a.c);
    const s1 = (await runOnce(a.c.chain, a.cfg, a.store, rs, ident)).status;
    const dl1 = a.store.listDeadLetters();
    const later = a.c.ownerTx([{ name: "GuardianSet", args: [addr("rev-g1"), addr("rev-g2")] }]);
    settle(a.c);
    for (let i = 0; i <= MAX_DEADLETTER_ATTEMPTS + 1; i++)
      await runOnce(a.c.chain, a.cfg, a.store, rs, ident);
    const sEnd = (await runOnce(a.c.chain, a.cfg, a.store, rs, ident)).status;
    const unread = a.recs().find(r => r.txHash === ethers.id("rev-malformed"));
    cell(
      "L1: a malformed frame or aggregator log is isolated per tx (tick ok, dead letter with evidence), ends unattributed and counted; the scan moves on",
      s1.ok === true &&
        s1.isolatedThisTick === 1 &&
        // #403 review L-2: isolating a malformed answer makes the tick degraded, not healthy
        s1.healthy === false &&
        s1.degraded?.some(x => /1 malformed RPC answer\(s\) isolated/.test(x)) &&
        // L-4: the reason names the malformed frame address, not missing positions
        dl1.some(
          x =>
            x.txHash === t1.hash &&
            x.route === "tx" &&
            /trace frame address malformed/.test(x.reasons?.[0] ?? "")
        ) &&
        dl1.some(
          x =>
            x.txHash === ethers.id("rev-malformed") &&
            x.watched?.length === 1 &&
            /tx processing failed/.test(x.reasons[0])
        ) &&
        a.recs().some(r => r.txHash === later.hash && r.event === "GuardianSet") &&
        unread?.route === "unattributed" &&
        unread.event === "UNREADABLE" &&
        unread.evidence?.length === 1 &&
        unread.verdict?.rule === "watcher.UNREADABLE" &&
        !/SuperPaymaster|permissionless/.test(unread.verdict.reasons.join(" ")) &&
        sEnd.unreadableTotal === 1 &&
        sEnd.ok === true,
      { s1: [s1.ok, s1.isolatedThisTick, s1.lastError], dl1, unread, sEnd: sEnd.unreadableTotal }
    );
    const t1rec = a.recs().find(r => r.txHash === t1.hash);
    cell(
      "nit: an exhausted, undeterminable SP event keeps the tx's sender, target and root selector (never as the caller)",
      t1rec?.route === "unattributed" &&
        t1rec.from === KEEPER &&
        t1rec.to === SP &&
        t1rec.rootSelector === pauseSel &&
        t1rec.caller === null,
      t1rec
    );

    // Codex follow-up R1: malformed positions are isolated (not a halted scan), contradictory
    // positions stay contradictory in the evidence, and an SP log that does not decode is isolated
    const f1 = mk();
    const blk = f1.c.mine();
    const twoTx = ethers.id("fu-two");
    const gsTopic = spIface.getEvent("GuardianSet").topicHash;
    const pz = spIface.encodeEventLog("OperatorPaused", [addr("fu-two")]);
    f1.c.injectLog(blk, { address: SP, ...pz, transactionHash: twoTx, index: 0 });
    f1.c.injectLog(blk, { address: SP, ...pz, transactionHash: twoTx, index: "bad" });
    f1.c.injectLog(blk, {
      address: SP,
      topics: [gsTopic],
      data: "0x",
      transactionHash: ethers.id("fu-undecodable"),
    });
    const contra = f1.c.ownerTx([{ name: "OperatorPaused", args: [addr("fu-contra")] }], {
      from: KEEPER,
      data: pauseSel,
    });
    f1.c.patchLogs(contra.hash, { logIndex: 99 }); // getLogs says index 0 AND logIndex 99
    settle(f1.c);
    const fs1 = (await runOnce(f1.c.chain, f1.cfg, f1.store, rs, ident)).status;
    const fLater = f1.c.ownerTx([{ name: "GuardianSet", args: [addr("fu-g1"), addr("fu-g2")] }]);
    settle(f1.c);
    const fs2 = (await runOnce(f1.c.chain, f1.cfg, f1.store, rs, ident)).status;
    const fDls = f1.store.listDeadLetters();
    const contraDl = fDls.find(x => x.txHash === contra.hash);
    cell(
      "follow-up R1: a malformed position, a contradictory one and an undecodable SP log are each isolated (tick ok, cursor moves); evidence keeps the contradiction; no attribution on retry",
      fs1.ok === true &&
        fs1.isolatedThisTick === 3 &&
        fs2.ok === true &&
        f1.recs().some(r => r.txHash === fLater.hash) &&
        fDls.some(x => x.txHash === twoTx) &&
        fDls.some(x => x.txHash === ethers.id("fu-undecodable")) &&
        contraDl?.watched?.[0]?.index === 0 &&
        contraDl.watched[0].logIndex === 99 &&
        !f1.recs().some(r => r.txHash === contra.hash),
      {
        fs1: [fs1.ok, fs1.isolatedThisTick, fs1.lastError],
        fs2: fs2.ok,
        contraDl: contraDl?.watched,
      }
    );

    // a getLogs log marked removed stays removed in the evidence, so a retry still refuses it
    const f2 = mk();
    const rm1 = f2.c.ownerTx([{ name: "OperatorPaused", args: [addr("fu-removed")] }], {
      from: KEEPER,
      data: pauseSel,
    });
    f2.c.patchLogs(rm1.hash, { removed: true });
    settle(f2.c);
    for (let i = 0; i < 3; i++) await runOnce(f2.c.chain, f2.cfg, f2.store, rs, ident);
    const rmDl = f2.store.listDeadLetters().find(x => x.txHash === rm1.hash);
    cell(
      "follow-up R1: a removed log is kept as removed in the evidence and never attributed on retry",
      rmDl?.watched?.[0]?.removed === true && !f2.recs().some(r => r.txHash === rm1.hash),
      { rmDl: rmDl?.watched, n: f2.recs().length }
    );

    // Codex follow-up R2
    {
      const g = mk();
      const n = g.c.mine();
      const gs = spIface.encodeEventLog("GuardianSet", [addr("r2-a"), addr("r2-b")]);
      const op = spIface.encodeEventLog("OperatorPaused", [addr("r2-op")]);
      // (a) bloom recovery next to a malformed position; (c) conflicting copies at one position;
      // (e) a log without a tx hash
      g.c.injectLog(n, { address: SP, ...op, transactionHash: ethers.id("r2-badpos"), index: "x" });
      g.c.injectLog(n, { address: SP, ...gs, transactionHash: ethers.id("r2-lagged"), index: 1 });
      g.c.lagTopic(n, gs.topics[0]);
      const n2 = g.c.mine();
      g.c.injectLog(n2, {
        address: SP,
        ...gs,
        transactionHash: ethers.id("r2-conflict"),
        index: 0,
      });
      g.c.injectLog(n2, {
        address: SP,
        topics: [gs.topics[0]],
        data: "0x",
        transactionHash: ethers.id("r2-conflict"),
        index: 0,
      });
      const n3 = g.c.mine();
      g.c.injectLog(n3, { address: SP, ...op, index: 0 }); // no transactionHash
      // (d) a removed standalone privileged event
      const rmTx = g.c.ownerTx([{ name: "GuardianSet", args: [addr("r2-rm1"), addr("r2-rm2")] }]);
      g.c.patchLogs(rmTx.hash, { removed: true });
      settle(g.c);
      const gs1 = (await runOnce(g.c.chain, g.cfg, g.store, rs, ident)).status;
      g.c.clearLag();
      const gDls = withQ(g.store);
      cell(
        "follow-up R2: bloom recovery beside a malformed position, conflicting copies at one position, a log without a tx hash and a removed standalone event are each isolated; tick ok",
        gs1.ok === true &&
          gs1.bloom.recovered === 1 &&
          gDls.some(x => x.txHash === ethers.id("r2-badpos")) &&
          gDls.some(x => x.txHash === ethers.id("r2-conflict") && x.watched.length === 2) &&
          gDls.some(x => x.quarantine === true && x.watched.length === 1) &&
          gDls.some(x => x.txHash === rmTx.hash) &&
          !g.recs().some(r => [ethers.id("r2-conflict"), rmTx.hash].includes(r.txHash)),
        {
          ok: gs1.ok,
          err: gs1.lastError,
          bloom: gs1.bloom,
          dls: gDls.map(x => [x.txHash.slice(0, 10), x.quarantine, x.reasons]),
        }
      );
      for (let i = 0; i <= MAX_DEADLETTER_ATTEMPTS + 1; i++)
        await runOnce(g.c.chain, g.cfg, g.store, rs, ident);
      const q = g.recs().find(r => r.event === "UNREADABLE" && /quarantine/.test(r.label));
      cell(
        "follow-up R2: a quarantined item (no tx hash) ends as an UNREADABLE record that names no tx",
        q && q.evidence?.length === 1 && q.caller === null,
        q
      );
      // (b, end to end) a dead letter whose legacy evidence holds a log with a malformed address is
      // retried as malformed, never resolved because filtering emptied it
      const lg = g.c.ownerTx([{ name: "OperatorPaused", args: [addr("r2-legacy")] }], {
        from: KEEPER,
        data: pauseSel,
        trace: false,
      });
      settle(g.c);
      await runOnce(g.c.chain, g.cfg, g.store, rs, ident);
      {
        const ddir = join(g.d, "deadletters");
        const fl = readdirSync(ddir).find(f => f === `tx-${lg.hash.toLowerCase()}.json`);
        const v = JSON.parse(readFileSync(join(ddir, fl), "utf8"));
        v.watched = v.watched.map(({ source, ...w }) => ({ ...w, address: "0xBAD" }));
        writeFileSync(join(ddir, fl), JSON.stringify(v));
      }
      await runOnce(g.c.chain, g.cfg, g.store, rs, ident);
      const lgDl = g.store.listDeadLetters().find(x => x.txHash === lg.hash);
      cell(
        "follow-up R2: a retry whose stored evidence no longer classifies stays a dead letter (never resolved empty)",
        lgDl && /tx processing failed/.test(lgDl.reasons[0]),
        lgDl
      );
      // (b) stored evidence classifies by its source; legacy evidence that would fall out of the
      // address/topic split marks the tx malformed
      const ev = { address: "0xBAD", topics: [op.topics[0]], data: "0x", index: 0 };
      const sourced = txOfEvidence([{ ...ev, source: "sp" }], g.cfg, 1);
      const legacy = txOfEvidence([ev], g.cfg, 1);
      cell(
        "follow-up R2: retry evidence keeps its source classification; legacy evidence that does not classify is malformed",
        sourced.sp.length === 1 && !sourced.malformed && legacy.malformed === true,
        { sourced, legacy }
      );
    }
    {
      // (f) a stale snapshot must not undo a patch: retry the tx dead letter first; (g) a corrupt
      // amendment is repaired
      const h = mk();
      const sx = h.c.execute(Kind.GENERIC, 4646n, priceG, 0b111n, {
        via: { route: "safe" },
        spLogs: [{ name: "PriceUpdated", args: [261000000000n, 20n] }],
        price: 261000000000n,
      });
      settle(h.c);
      h.c.failPriceReads(1_000_000);
      await runOnce(h.c.chain, h.cfg, h.store, rs, ident);
      const pu = spIface.encodeEventLog("PriceUpdated", [261000000000n, 20n]);
      h.c.setTrace(sx.hash, {
        type: "CALL",
        to: SAFE,
        calls: [
          {
            type: "CALL",
            to: AGG,
            logs: [
              {
                address: AGG,
                ...aggIface.encodeEventLog("SignersCommitted", [sx.key, sx.mask]),
                position: 0,
              },
            ],
            calls: [
              {
                type: "CALL",
                from: AGG,
                to: SP,
                input: priceG.callData.slice(0, 10),
                logs: [{ address: SP, topics: pu.topics, data: pu.data }],
              },
            ],
          },
        ],
      });
      const realIds = h.store.listDeadLetterIds.bind(h.store);
      h.store.listDeadLetterIds = () => realIds().reverse(); // tx-… before bls-…
      await runOnce(h.c.chain, h.cfg, h.store, rs, ident);
      h.c.failPriceReads(0);
      await runOnce(h.c.chain, h.cfg, h.store, rs, ident);
      h.store.listDeadLetterIds = realIds;
      const rx = h.recs().find(r => r.txHash === sx.hash && r.route === "bls");
      // corrupt amendment repaired on the next proof
      const keyHex = BigInt(sx.key).toString(16).padStart(64, "0");
      writeFileSync(join(h.d, "amendments", `bls-${keyHex}.json`), "{trunc");
      const rep = h.store.putBlsAmendment(sx.key, {
        key: BigInt(sx.key).toString(),
        spEvents: [{ event: "PriceUpdated" }],
      });
      cell(
        "follow-up R2: a patched dead letter survives a tx-first retry order (effects reach the record); a corrupt amendment file is set aside and replaced, never trusted",
        rx?.spEvents?.[0]?.event === "PriceUpdated" &&
          rep === "repaired" &&
          h.store.getBlsAmendment(sx.key)?.spEvents?.length === 1,
        { rx: rx?.spEvents, rep }
      );
    }

    // Codex follow-up R3
    {
      const k = mk();
      const n = k.c.mine();
      const sc = spIface.encodeEventLog("SlashCancelled", [addr("r3-sc")]);
      // (1) two copies that disagree only on their block
      k.c.injectLog(n, { address: SP, ...sc, transactionHash: ethers.id("r3-blocks"), index: 0 });
      k.c.injectLog(n, {
        address: SP,
        ...sc,
        transactionHash: ethers.id("r3-blocks"),
        index: 0,
        blockHash: ethers.id("r3-other-block"),
      });
      // (4) an invalid block number
      k.c.injectRawResult(SP, {
        address: SP,
        ...sc,
        transactionHash: ethers.id("r3-height"),
        index: 2,
        blockNumber: "not-a-number",
      });
      // (3) a null entry next to a valid log
      k.c.injectRawResult(SP, null);
      const ok3 = k.c.ownerTx([{ name: "GuardianSet", args: [addr("r3-g1"), addr("r3-g2")] }]);
      settle(k.c);
      const ks = (await runOnce(k.c.chain, k.cfg, k.store, rs, ident)).status;
      const kd = withQ(k.store);
      const hDl = kd.find(x => x.txHash === ethers.id("r3-height"));
      cell(
        "follow-up R3: copies disagreeing on their block, an invalid height and a null entry are isolated (tick ok, valid log recorded, raw height kept)",
        ks.ok === true &&
          kd.some(x => x.txHash === ethers.id("r3-blocks") && x.watched.length === 2) &&
          hDl?.watched?.[0]?.blockNumber === "not-a-number" &&
          kd.some(x => x.quarantine === true && /null/.test(x.watched?.[0]?.raw ?? "")) &&
          k.recs().some(r => r.txHash === ok3.hash) &&
          !k.recs().some(r => [ethers.id("r3-blocks"), ethers.id("r3-height")].includes(r.txHash)),
        {
          ok: ks.ok,
          err: ks.lastError,
          dls: kd.map(x => [x.txHash.slice(0, 10), x.quarantine, x.watched?.length]),
        }
      );
      // (2) a parseable but invalid amendment is replaced by the valid proof, its bytes kept
      const key = 777n;
      const keyHex = key.toString(16).padStart(64, "0");
      writeFileSync(
        join(k.d, "amendments", `bls-${keyHex}.json`),
        JSON.stringify({ key: "777", spEvents: [null] })
      );
      const good = {
        key: "777",
        txHash: ethers.id("r3-am"),
        provenBy: "trace",
        spEvents: [{ event: "PriceUpdated", logIndex: 1 }],
      };
      const r2 = k.store.putBlsAmendment(key, good);
      cell(
        "follow-up R3: an existing amendment must be valid in identity, proof and events; an invalid one is kept aside and replaced",
        r2 === "repaired" &&
          k.store.getBlsAmendment(key)?.txHash === good.txHash &&
          readdirSync(join(k.d, "amendments")).some(f => f.endsWith(".invalid.1")) &&
          k.store.putBlsAmendment(key, good) === "same",
        { r2, files: readdirSync(join(k.d, "amendments")) }
      );
    }

    // Codex follow-up R4
    {
      const m = mk();
      const n = m.c.mine();
      const gs = spIface.encodeEventLog("GuardianSet", [addr("r4-a"), addr("r4-b")]);
      const blkHash = (await m.c.chain.send("eth_getBlockByNumber", [ethers.toQuantity(n), false]))
        .hash;
      const base = { blockNumber: n, blockHash: blkHash, index: 0 };
      // (b) a height that is an object
      m.c.injectRawResult(SP, {
        address: SP,
        ...gs,
        ...base,
        transactionHash: ethers.id("r4-objh"),
        blockNumber: { toString: null },
      });
      // (c) one tx in two casings, two different malformed copies
      const hx = ethers.id("r4-case");
      m.c.injectRawResult(SP, {
        address: SP,
        topics: [gs.topics[0]],
        data: "0x",
        ...base,
        transactionHash: hx,
      });
      m.c.injectRawResult(SP, {
        address: SP,
        topics: [gs.topics[0]],
        data: "0x00",
        ...base,
        transactionHash: "0x" + hx.slice(2).toUpperCase(),
      });
      // (d) the SP query returns another contract's decodable event, and an aggregator-shaped log,
      // both naming a REAL tx that emitted nothing watched
      const quiet = m.c.ownerTx([]);
      const quiet2 = m.c.ownerTx([]);
      const r1 = await m.c.chain.getTransactionReceipt(quiet.hash);
      const r2 = await m.c.chain.getTransactionReceipt(quiet2.hash);
      m.c.injectRawResult(SP, {
        address: addr("r4-other"),
        ...gs,
        blockNumber: r1.blockNumber,
        blockHash: r1.blockHash,
        index: 0,
        transactionHash: quiet.hash,
      });
      m.c.injectRawResult(SP, {
        address: AGG,
        ...aggIface.encodeEventLog("SignersCommitted", [123n, 3n]),
        blockNumber: r2.blockNumber,
        blockHash: r2.blockHash,
        index: 0,
        transactionHash: quiet2.hash,
      });
      settle(m.c);
      const ms = (await runOnce(m.c.chain, m.cfg, m.store, rs, ident)).status;
      const md = m.store.listDeadLetters();
      cell(
        "follow-up R4: an object height, one tx in two hash casings, and another emitter in the SP query are isolated; tick ok; nothing attributed",
        ms.ok === true &&
          md.some(x => x.txHash === ethers.id("r4-objh")) &&
          md.some(x => x.txHash === hx && x.watched.length === 2) &&
          md.some(x => x.txHash === quiet.hash && x.route === "tx") &&
          md.some(x => x.txHash === quiet2.hash && x.route === "tx") &&
          !md.some(x => x.txHash === quiet2.hash && x.route === "bls") &&
          !m
            .recs()
            .some(r => [ethers.id("r4-objh"), hx, quiet.hash, quiet2.hash].includes(r.txHash)),
        {
          ok: ms.ok,
          err: ms.lastError,
          dls: md.map(x => [x.txHash.slice(0, 10), x.watched?.length, x.reasons]),
        }
      );
      // (a) amendments: strict validity, and a different valid proof is a conflict, not "same"
      const okA = {
        key: "5",
        txHash: ethers.id("r4-am"),
        provenBy: "trace",
        spEvents: [{ event: "PriceUpdated", logIndex: 1 }],
      };
      const badOnes = [
        { ...okA, provenBy: "" },
        ...[null, false, "", -1].map(v => ({
          ...okA,
          spEvents: [{ event: "PriceUpdated", logIndex: v }],
        })),
      ];
      const k5 = 5n;
      m.store.putBlsAmendment(k5, okA);
      const other = { ...okA, txHash: ethers.id("r4-am-2") };
      const rc = m.store.putBlsAmendment(k5, other);
      const keyHex = k5.toString(16).padStart(64, "0");
      cell(
        "follow-up R4: amendment validity is strict, and a different valid proof is kept as a conflict, never reported as persisted",
        validAmendment(okA, k5) &&
          badOnes.every(b => !validAmendment(b, k5)) &&
          rc === "conflict" &&
          m.store.getBlsAmendment(k5)?.txHash === okA.txHash &&
          // addressed by the sha256 of the proof's signature (follow-up #2 R9)
          readdirSync(join(m.d, "amendments")).some(f =>
            new RegExp(`^bls-${keyHex}\\.json\\.conflict\\.[0-9a-f]{64}$`).test(f)
          ) &&
          m.store.putBlsAmendment(k5, okA) === "same",
        { rc, valid: badOnes.map(b => validAmendment(b, k5)) }
      );
    }

    // Codex follow-up R5: the tx response must be this tx; logs must be canonical and in range
    {
      const p = mk();
      const ga = p.c.ownerTx([{ name: "GuardianSet", args: [addr("r5-a1"), addr("r5-a2")] }], {
        from: KEEPER,
      });
      p.c.patchTx(ga.hash, { hash: ethers.id("r5-other-tx"), from: addr("r5-impostor") });
      const gf = p.c.ownerTx([{ name: "GuardianSet", args: [addr("r5-f1"), addr("r5-f2")] }]);
      p.c.patchLogs(gf.hash, { blockHash: ethers.id("r5-stale-fork") });
      settle(p.c);
      // a log past the finalized block, returned by the range query anyway
      const gs = spIface.encodeEventLog("GuardianSet", [addr("r5-b1"), addr("r5-b2")]);
      const beyond = p.c.ownerTx([]);
      p.c.injectRawResult(SP, {
        address: SP,
        ...gs,
        blockNumber: p.c.head() + 5,
        index: 0,
        transactionHash: beyond.hash,
      });
      const ps = (await runOnce(p.c.chain, p.cfg, p.store, rs, ident)).status;
      const pd = p.store.listDeadLetters();
      cell(
        "follow-up R5: a tx response for another tx, a log from a stale fork, and a log past the finalized block are isolated, never attributed",
        ps.ok === true &&
          [ga.hash, gf.hash, beyond.hash].every(h => pd.some(x => x.txHash === h)) &&
          !p.recs().some(r => [ga.hash, gf.hash, beyond.hash].includes(r.txHash)),
        { ok: ps.ok, err: ps.lastError, dls: pd.map(x => [x.txHash.slice(0, 10), x.reasons]) }
      );
    }

    // Codex follow-up R6
    {
      const q = mk();
      // (1) a log outside the requested range stays unattributed on retry
      const quiet = q.c.ownerTx([]);
      settle(q.c);
      await runOnce(q.c.chain, q.cfg, q.store, rs, ident); // scans past the quiet tx's block
      const rq = await q.c.chain.getTransactionReceipt(quiet.hash);
      const gs = spIface.encodeEventLog("GuardianSet", [addr("r6-a"), addr("r6-b")]);
      q.c.mine();
      settle(q.c);
      q.c.injectRawResult(SP, {
        address: SP,
        ...gs,
        blockNumber: rq.blockNumber,
        blockHash: rq.blockHash,
        index: 0,
        transactionHash: quiet.hash,
      });
      await runOnce(q.c.chain, q.cfg, q.store, rs, ident);
      const dlR = q.store.listDeadLetters().find(x => x.txHash === quiet.hash);
      await runOnce(q.c.chain, q.cfg, q.store, rs, ident);
      // (3) a tx response without a hash is not trusted
      const nh = q.c.ownerTx([{ name: "GuardianSet", args: [addr("r6-n1"), addr("r6-n2")] }], {
        from: KEEPER,
      });
      q.c.patchTx(nh.hash, { hash: undefined });
      // (2) BLS reconstruction's own tx fetch answered by another tx
      const sl = q.c.execute(Kind.SLASH, 6060n, slashF, 0b011n);
      q.c.patchTxFrom(sl.hash, 1, { hash: ethers.id("r6-other"), from: addr("r6-impostor") });
      settle(q.c);
      await runOnce(q.c.chain, q.cfg, q.store, rs, ident);
      const qd = q.store.listDeadLetters();
      cell(
        "follow-up R6: an out-of-range log stays a dead letter on retry; a hashless tx response and a reconstruction fetch answered by another tx are refused",
        Array.isArray(dlR?.range) &&
          qd.some(x => x.txHash === quiet.hash) &&
          !q.recs().some(r => r.txHash === quiet.hash) &&
          qd.some(x => x.txHash === nh.hash) &&
          !q.recs().some(r => r.txHash === nh.hash) &&
          qd.some(
            x =>
              x.txHash === sl.hash && x.route === "bls" && /another tx/.test(x.reasons?.[0] ?? "")
          ) &&
          !q.recs().some(r => r.txHash === sl.hash),
        { dlR: dlR?.range, dls: qd.map(x => [x.txHash.slice(0, 10), x.route, x.reasons]) }
      );
    }

    // Codex follow-up R7
    {
      const w = mk();
      // (1) getLogs says mask 4, the receipt (and the commitment) say mask 3
      const sl = w.c.execute(Kind.SLASH, 7070n, slashF, 0b011n);
      w.c.patchLogs(sl.hash, {
        data: ethers.AbiCoder.defaultAbiCoder().encode(["uint256"], [4n]),
      });
      // (2) two observations of one tx from two scan ranges, different and both malformed
      const quiet = w.c.ownerTx([]);
      settle(w.c);
      const rq = await w.c.chain.getTransactionReceipt(quiet.hash);
      const gs = spIface.encodeEventLog("GuardianSet", [addr("r7-a"), addr("r7-b")]);
      const obs = data => ({
        address: SP,
        topics: [gs.topics[0]],
        data,
        blockNumber: rq.blockNumber,
        blockHash: rq.blockHash,
        index: 0,
        transactionHash: quiet.hash,
      });
      w.c.injectRawResult(SP, obs("0x"));
      await runOnce(w.c.chain, w.cfg, w.store, rs, ident);
      w.c.mine();
      settle(w.c);
      w.c.injectRawResult(SP, obs("0x00"));
      await runOnce(w.c.chain, w.cfg, w.store, rs, ident);
      // a third, valid observation of the same tx (from outside its range, so isolated): merged too
      const op = spIface.encodeEventLog("OperatorPaused", [addr("r7-op")]);
      w.c.mine();
      settle(w.c);
      w.c.injectRawResult(SP, {
        address: SP,
        ...op,
        blockNumber: rq.blockNumber,
        blockHash: rq.blockHash,
        index: 1,
        transactionHash: quiet.hash,
      });
      await runOnce(w.c.chain, w.cfg, w.store, rs, ident);
      const wd = w.store.listDeadLetters();
      const q = wd.find(x => x.txHash === quiet.hash);
      const ranges = new Set((q?.watched ?? []).map(e => JSON.stringify(e.range)));
      cell(
        "follow-up R7: a commitment log that differs from the receipt is a dead letter (no record with mismatched signers); two observations of one tx from two ranges are both kept with their ranges",
        wd.some(
          x =>
            x.txHash === sl.hash &&
            x.route === "bls" &&
            /not found unchanged/.test(x.reasons?.[0] ?? "")
        ) &&
          !w.recs().some(r => r.txHash === sl.hash) &&
          q?.watched?.length >= 3 &&
          ranges.size === 3,
        { bls: wd.filter(x => x.txHash === sl.hash).map(x => x.reasons), q: q?.watched }
      );
    }

    // Codex follow-up R8: the same log returned by both queries is two observations, both kept
    {
      const v = mk();
      const quiet = v.c.ownerTx([]);
      settle(v.c);
      const rq = await v.c.chain.getTransactionReceipt(quiet.hash);
      const gs = spIface.encodeEventLog("GuardianSet", [addr("r8-a"), addr("r8-b")]);
      const lg = {
        address: SP,
        ...gs,
        blockNumber: rq.blockNumber,
        blockHash: rq.blockHash,
        index: 0,
        transactionHash: quiet.hash,
      };
      v.c.injectRawResult(AGG, lg);
      v.c.injectRawResult(SP, lg);
      await runOnce(v.c.chain, v.cfg, v.store, rs, ident);
      const vq = v.store.listDeadLetters().find(x => x.txHash === quiet.hash);
      cell(
        "follow-up R8: one log returned by both the aggregator and the SP query is kept as two observations (source is part of the evidence identity)",
        new Set((vq?.watched ?? []).map(e => e.source)).size === 2,
        vq?.watched
      );
    }

    // Codex follow-up R9: values whose toString is not callable never throw outside the isolation
    {
      const u = mk();
      const quiet = u.c.ownerTx([]);
      // a block whose bloom DOES show a watched topic, so the bloom check compares topics there
      const later = u.c.ownerTx([{ name: "GuardianSet", args: [addr("r9-g1"), addr("r9-g2")] }]);
      settle(u.c);
      const rq = await u.c.chain.getTransactionReceipt(quiet.hash);
      const rl = await u.c.chain.getTransactionReceipt(later.hash);
      const gs = spIface.encodeEventLog("GuardianSet", [addr("r9-a"), addr("r9-b")]);
      const evil = { toString: null };
      u.c.injectRawResult(SP, {
        address: SP,
        ...gs,
        blockNumber: rq.blockNumber,
        blockHash: rq.blockHash,
        index: 0,
        transactionHash: evil,
      });
      u.c.injectRawResult(SP, {
        address: SP,
        topics: [evil],
        data: "0x",
        blockNumber: rl.blockNumber,
        blockHash: rl.blockHash,
        index: 1,
        transactionHash: quiet.hash,
      });
      // the range answer lacks the real log, so the bloom check has only the malformed one to compare
      u.c.lagTopic(rl.blockNumber, gs.topics[0]);
      const us = (await runOnce(u.c.chain, u.cfg, u.store, rs, ident)).status;
      u.c.clearLag();
      const us2 = (await runOnce(u.c.chain, u.cfg, u.store, rs, ident)).status;
      cell(
        "follow-up R9: a tx hash or topic that cannot be stringified is isolated; the scan never throws and moves on",
        us.ok === true &&
          us2.ok === true &&
          withQ(u.store).some(x => x.quarantine === true) &&
          u.store.listDeadLetters().some(x => x.txHash === quiet.hash) &&
          u.recs().some(r => r.txHash === later.hash),
        { us: [us.ok, us.lastError], us2: [us2.ok, us2.lastError] }
      );
    }

    // Codex follow-up R10: BigInt fields, merged evidence, malformed headers
    {
      const b = mk();
      const quiet = b.c.ownerTx([]);
      settle(b.c);
      const rq = await b.c.chain.getTransactionReceipt(quiet.hash);
      const gs = spIface.encodeEventLog("GuardianSet", [addr("r10-a"), addr("r10-b")]);
      const at = {
        blockNumber: rq.blockNumber,
        blockHash: rq.blockHash,
        transactionHash: quiet.hash,
      };
      b.c.injectRawResult(SP, { address: SP, ...gs, ...at, index: 0 });
      b.c.injectRawResult(SP, { address: SP, ...gs, ...at, index: 1n }); // a BigInt position
      b.c.injectRawResult(AGG, { address: AGG, ...gs, ...at, index: 2n });
      b.c.injectRawResult(SP, {
        address: SP,
        ...gs,
        blockNumber: rq.blockNumber,
        blockHash: rq.blockHash,
        index: 0,
        transactionHash: 1n,
      });
      b.c.injectRawResult(SP, { address: SP, ...gs, ...at, index: "1" }); // same text, another type
      b.c.injectRawResult(SP, { address: SP, ...gs, ...at, index: { $bigint: "1" } }); // a literal tag
      const bs = (await runOnce(b.c.chain, b.cfg, b.store, rs, ident)).status;
      const bq = b.store.listDeadLetters().find(x => x.txHash === quiet.hash);
      // after persistence and a retry, 1n and "1" are still two observations (R11)
      // several retries: persistence is idempotent (no growth, one identity per observation)
      for (let i = 0; i < 3; i++) await runOnce(b.c.chain, b.cfg, b.store, rs, ident);
      const bq2 = b.store.listDeadLetters().find(x => x.txHash === quiet.hash);
      // a malformed hash in the final header read: the tick fails, the cursor is not poisoned
      b.c.mine();
      settle(b.c);
      const curBefore = b.store.getCursor();
      const fin = b.c.head() - 2;
      b.c.patchHeaderOnce(fin, { hash: { toString: null } });
      const bad = (await runOnce(b.c.chain, b.cfg, b.store, rs, ident)).status;
      const curAfterBad = b.store.getCursor();
      const good = (await runOnce(b.c.chain, b.cfg, b.store, rs, ident)).status;
      cell(
        "follow-up R10: BigInt fields never throw (isolated, every observation kept); a malformed header hash fails the tick without poisoning the cursor",
        bs.ok === true &&
          bq?.watched?.length === 5 &&
          bq2?.watched?.length === 5 &&
          j(bq2.watched) === j(bq.watched) && // stored bytes unchanged by retries (idempotent)
          withQ(b.store).some(x => x.quarantine === true) &&
          bad.ok === false &&
          j(curAfterBad) === j(curBefore) &&
          good.ok === true &&
          b.store.getCursor().block > curBefore.block,
        {
          bs: [bs.ok, bs.lastError],
          w: bq?.watched?.length,
          bad: [bad.ok, bad.lastError],
          good: [good.ok, good.lastError],
        }
      );
    }

    // L2: a BLS dead letter takes exactly one attempt per tick even when its tx also has a dead
    // letter; UNRECOVERED lands at the cap, not at half of it
    const b = mk();
    const ub = b.c.execute(Kind.SLASH, 4242n, slashF, 0b011n, {
      to: WRAPPER,
      spLogs: [{ name: "OperatorPaused", args: [addr("rev-l2")] }],
    });
    settle(b.c);
    for (let i = 0; i < 3; i++) await runOnce(b.c.chain, b.cfg, b.store, rs, ident);
    const bdl = b.store.listDeadLetters().find(x => x.txHash === ub.hash && x.route === "bls");
    let landedAt = null;
    for (let i = 4; i <= MAX_DEADLETTER_ATTEMPTS + 3 && landedAt === null; i++) {
      await runOnce(b.c.chain, b.cfg, b.store, rs, ident);
      if (b.recs().some(r => r.txHash === ub.hash && r.route === "bls")) landedAt = i;
    }
    const exh = readdirSync(join(b.d, "deadletters")).filter(f => /\.exhausted(\.\d+)?$/.test(f));
    cell(
      "L2: one attempt per tick for a BLS dead letter beside a tx dead letter; UNRECOVERED at the cap; retirements never overwritten",
      bdl?.attempts === 3 &&
        landedAt !== null &&
        landedAt >= MAX_DEADLETTER_ATTEMPTS &&
        new Set(exh).size === exh.length,
      { attempts: bdl?.attempts, landedAt, exh }
    );

    // L3: an aggregator call WITHOUT a commitment that emits SlashQueued, in the same Safe tx as a
    // BLS action: the event is not that action's effect, so it is its own record
    const cc = mk();
    const s3 = cc.c.execute(Kind.GENERIC, 4343n, priceG, 0b111n, {
      via: { route: "safe" },
      spLogs: [{ name: "SlashQueued", args: [addr("rev-l3")] }],
      price: 261000000000n,
    });
    {
      const sq = spIface.encodeEventLog("SlashQueued", [addr("rev-l3")]);
      cc.c.setTrace(s3.hash, {
        type: "CALL",
        to: SAFE,
        calls: [
          {
            type: "CALL",
            to: AGG,
            logs: [
              {
                address: AGG,
                ...aggIface.encodeEventLog("SignersCommitted", [s3.key, s3.mask]),
                position: 0,
              },
            ],
          },
          {
            type: "CALL",
            to: AGG,
            calls: [
              {
                type: "CALL",
                from: AGG,
                to: SP,
                input: "0x12345678",
                logs: [{ address: SP, topics: sq.topics, data: sq.data }],
              },
            ],
          },
        ],
      });
    }
    settle(cc.c);
    await runOnce(cc.c.chain, cc.cfg, cc.store, rs, ident);
    const sqRec = cc.recs().find(r => r.txHash === s3.hash && r.event === "SlashQueued");
    const blsRec = cc.recs().find(r => r.txHash === s3.hash && r.route === "bls");
    cell(
      "L3: an SP event inside an aggregator call with no commitment is its own record, not swallowed as the BLS action's effect",
      sqRec?.route === "owner" &&
        blsRec &&
        !(blsRec.spEvents ?? []).some(e => e.event === "SlashQueued"),
      { sqRec, blsSp: blsRec?.spEvents }
    );

    // L4: an effect the trace proves only after the BLS record exists is kept beside it; one proven
    // while the action's dead letter is open goes into that dead letter, then into the record
    const dd = mk();
    const s4 = dd.c.execute(Kind.GENERIC, 4444n, priceG, 0b111n, {
      via: { route: "safe" },
      spLogs: [{ name: "PriceUpdated", args: [261000000000n, 20n] }],
      price: 261000000000n,
    });
    const effTrace = (x, hash) => {
      const pu = spIface.encodeEventLog("PriceUpdated", [261000000000n, 20n]);
      dd.c.setTrace(hash, {
        type: "CALL",
        to: SAFE,
        calls: [
          {
            type: "CALL",
            to: AGG,
            logs: [
              {
                address: AGG,
                ...aggIface.encodeEventLog("SignersCommitted", [x.key, x.mask]),
                position: 0,
              },
            ],
            calls: [
              {
                type: "CALL",
                from: AGG,
                to: SP,
                input: priceG.callData.slice(0, 10),
                logs: [{ address: SP, topics: pu.topics, data: pu.data }],
              },
            ],
          },
        ],
      });
    };
    settle(dd.c);
    await runOnce(dd.c.chain, dd.cfg, dd.store, rs, ident);
    const before4 = dd.recs().find(r => r.txHash === s4.hash && r.route === "bls");
    effTrace(s4, s4.hash);
    await runOnce(dd.c.chain, dd.cfg, dd.store, rs, ident);
    const am = dd.store.getBlsAmendment(s4.key);
    // the open-dead-letter case
    const s4b = dd.c.execute(Kind.GENERIC, 4445n, priceG, 0b111n, {
      via: { route: "safe" },
      spLogs: [{ name: "PriceUpdated", args: [261000000000n, 20n] }],
      price: 261000000000n,
    });
    settle(dd.c);
    dd.c.failPriceReads(1_000_000);
    await runOnce(dd.c.chain, dd.cfg, dd.store, rs, ident);
    effTrace(s4b, s4b.hash);
    await runOnce(dd.c.chain, dd.cfg, dd.store, rs, ident);
    const pend = dd.store.listDeadLetters().find(x => x.txHash === s4b.hash && x.route === "bls");
    dd.c.failPriceReads(0);
    await runOnce(dd.c.chain, dd.cfg, dd.store, rs, ident);
    const rec4b = dd.recs().find(r => r.txHash === s4b.hash && r.route === "bls");
    cell(
      "L4: later-proven effects are kept: an amendment beside an existing BLS record, or carried by the open dead letter into the record",
      before4 &&
        !(before4.spEvents ?? []).length &&
        am?.spEvents?.[0]?.event === "PriceUpdated" &&
        pend?.spEvents?.[0]?.event === "PriceUpdated" &&
        rec4b?.spEvents?.[0]?.event === "PriceUpdated" &&
        !dd.store.listDeadLetters().some(x => x.txHash === s4.hash),
      { am, pend: pend?.spEvents, rec4b: rec4b?.spEvents }
    );

    // L5: a client answering topics in upper-case hex causes no bloom re-read or false positive
    const e5 = mk();
    e5.c.ownerTx([{ name: "GuardianSet", args: [addr("rev-l5a"), addr("rev-l5b")] }]);
    settle(e5.c);
    e5.c.setUpperTopics(true);
    const calls0 = e5.c.logCalls();
    const s5 = (await runOnce(e5.c.chain, e5.cfg, e5.store, rs, ident)).status;
    const callsUsed = e5.c.logCalls() - calls0; // aggregator + SP range reads, no by-hash re-read
    e5.c.setUpperTopics(false);
    cell(
      "L5: bloom topics compared case-insensitively (no false re-read for upper-case hex)",
      s5.ok === true &&
        s5.bloom.recovered === 0 &&
        s5.bloom.falsePositives === 0 &&
        e5.recs().length === 1 &&
        callsUsed === 2, // #403 review L-3: no by-hash re-read at all
      { bloom: s5.bloom, n: e5.recs().length, err: s5.lastError, callsUsed }
    );
  } finally {
    for (const d of dirs) rmSync(d, { recursive: true, force: true });
  }
}

// ---- L2: a second retirement of the same dead-letter id never overwrites the first
{
  const d7 = mkdtempSync(join(tmpdir(), "guardian-watcher-ret-"));
  try {
    const st = new Store(d7);
    const dl = {
      route: "tx",
      txHash: ethers.id("ret"),
      blockNumber: 1,
      status: "ERROR",
      reasons: ["x"],
      events: [],
      seenAt: "t",
    };
    st.putDeadLetter(dl);
    st.retireDeadLetter(`tx-${dl.txHash.toLowerCase()}`);
    st.putDeadLetter(dl);
    st.retireDeadLetter(`tx-${dl.txHash.toLowerCase()}`);
    cell(
      "L2: retirements of one id are numbered, never overwritten, and all counted",
      st.countExhausted() === 2,
      readdirSync(join(d7, "deadletters"))
    );
  } finally {
    rmSync(d7, { recursive: true, force: true });
  }
}

// ---- #403 review M-1: the production path. A real ethers JsonRpcProvider (only its transport
// replaced) answers eth_getLogs with raw JSON holding malformed entries; the range read must not go
// through ethers' log formatter (which throws on them), so the tick completes, the cursor moves and
// every malformed entry is isolated.
{
  const dP = mkdtempSync(join(tmpdir(), "guardian-watcher-realprov-"));
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
    const good = c.ownerTx([{ name: "GuardianSet", args: [addr("rp-g1"), addr("rp-g2")] }]);
    for (let i = 0; i < 4; i++) c.mine();
    const q = x => ethers.toQuantity(x);
    const asJson = l => ({
      address: l.address,
      topics: l.topics,
      data: l.data,
      blockNumber: q(l.blockNumber),
      blockHash: l.blockHash,
      transactionHash: l.transactionHash,
      transactionIndex: "0x0",
      logIndex: q(l.index),
      removed: false,
    });
    const gs = spIface.encodeEventLog("GuardianSet", [addr("rp-a"), addr("rp-b")]);
    const rq = await c.chain.getTransactionReceipt(good.hash);
    const base = {
      address: SP.toLowerCase(),
      topics: gs.topics,
      data: gs.data,
      blockNumber: q(rq.blockNumber),
      blockHash: rq.blockHash,
      transactionIndex: "0x0",
      removed: false,
    };
    const malformed = [
      null,
      { ...base, transactionHash: ethers.id("rp-badidx"), logIndex: "bad" },
      { ...base, transactionHash: ethers.id("rp-short"), logIndex: "0x5", address: "0x1234" },
      { ...base, logIndex: "0x6" }, // no transactionHash
      {
        ...base,
        transactionHash: ethers.id("rp-huge"),
        logIndex: "0x7",
        blockNumber: "0x" + "f".repeat(80),
      },
    ];
    let malformedServed = false;
    let byHashMalformed = false;
    let malformedByHash = [];
    class RawRpc extends ethers.JsonRpcProvider {
      constructor() {
        super("http://127.0.0.1:1", undefined, {
          staticNetwork: ethers.Network.from(1),
          batchMaxCount: 1,
          cacheTimeout: -1,
        });
      }
      async _send(payload) {
        const out = [];
        for (const p of Array.isArray(payload) ? payload : [payload]) {
          try {
            let result;
            if (p.method === "eth_chainId") result = "0x1";
            else if (p.method === "eth_getLogs") {
              const raw = (await c.chain.send("eth_getLogs", p.params)).map(asJson);
              const isSp = String(p.params[0].address).toLowerCase() === SP.toLowerCase();
              const byHash = p.params[0].blockHash !== undefined;
              if (isSp && byHash && byHashMalformed) {
                byHashMalformed = false;
                result = [...raw, ...malformedByHash];
              } else if (isSp && !byHash && !malformedServed) {
                malformedServed = true;
                result = [...raw, ...malformed];
              } else result = raw;
            } else if (p.method === "eth_getBlockByNumber")
              result = await c.chain.send(p.method, p.params);
            else if (["eth_getTransactionByHash", "eth_getTransactionReceipt"].includes(p.method))
              result = null;
            else throw new Error(`not served: ${p.method}`);
            out.push({ id: p.id, jsonrpc: "2.0", result });
          } catch (e) {
            out.push({
              id: p.id,
              jsonrpc: "2.0",
              error: { code: -32601, message: String(e.message) },
            });
          }
        }
        return out;
      }
    }
    const prov = new RawRpc();
    // control: the provider's own getLogs throws on this answer (the formatter boundary is real)
    malformedServed = false;
    let formatterThrew = false;
    try {
      await prov.getLogs({ address: SP, fromBlock: cfg.startBlock, toBlock: c.head() });
    } catch {
      formatterThrew = true;
    }
    malformedServed = false;
    const store = new Store(dP);
    const ident = { commit: "0".repeat(40), hash: ethers.id("ruleset"), verified: true };
    const head1 = c.head();
    const st = (await runOnce(prov, cfg, store, rs, ident)).status;
    // the bloom's by-hash re-read is the same raw path: a lagging range answer leaves a watched log
    // out, the by-hash answer brings it back together with a malformed entry
    const g2 = c.ownerTx([{ name: "GuardianSet", args: [addr("rp-h1"), addr("rp-h2")] }]);
    for (let i = 0; i < 4; i++) c.mine();
    const r2 = await c.chain.getTransactionReceipt(g2.hash);
    c.lagTopic(r2.blockNumber, gs.topics[0]);
    malformedByHash = [
      {
        ...base,
        blockNumber: q(r2.blockNumber),
        blockHash: r2.blockHash,
        transactionHash: ethers.id("rp-byhash"),
        logIndex: "bad",
      },
    ];
    byHashMalformed = true;
    const st2 = (await runOnce(prov, cfg, store, rs, ident)).status;
    c.clearLag();
    const dls = withQ(store);
    cell(
      "M-1: the bloom's by-hash re-read also takes the raw path: a malformed entry there is isolated, the tick completes",
      st2.ok === true &&
        st2.bloom.recovered >= 1 &&
        dls.some(x => x.txHash === ethers.id("rp-byhash")),
      { st2: [st2.ok, st2.lastError, st2.bloom], dls: dls.map(x => x.txHash.slice(0, 10)) }
    );
    cell(
      "M-1: through a real ethers JsonRpcProvider, malformed raw eth_getLogs entries are isolated and the tick completes (the provider's own getLogs throws on the same answer)",
      formatterThrew &&
        st.ok === true &&
        st.cursor === head1 &&
        st.isolatedThisTick >= 4 &&
        dls.some(x => x.quarantine === true) &&
        dls.some(x => x.txHash === ethers.id("rp-badidx")) &&
        dls.some(x => x.txHash === ethers.id("rp-short")) &&
        dls.some(x => x.txHash === ethers.id("rp-huge")),
      {
        formatterThrew,
        st: [st.ok, st.lastError, st.cursor, st.isolatedThisTick],
        dls: dls.map(x => [x.txHash.slice(0, 10), x.quarantine, x.reasons]),
      }
    );
  } finally {
    rmSync(dP, { recursive: true, force: true });
  }
}

// ---- #403 review L-1, L-3 (wiring, patch), L-5
{
  const dL = mkdtempSync(join(tmpdir(), "guardian-watcher-403l-"));
  try {
    // L-3: atomicWriteJson goes through writeAll (a short writer is driven to completion)
    let calls = 0;
    const short = (fd, b, off, len) => {
      calls++;
      return writeSync(fd, b, off, Math.min(5, len));
    };
    const p = join(dL, "w.json");
    atomicWriteJson(p, { a: "x".repeat(40) }, short);
    cell(
      "L-3: atomicWriteJson writes through writeAll (a short writer is looped to a complete file)",
      calls > 2 && JSON.parse(readFileSync(p, "utf8")).a.length === 40,
      { calls }
    );
    // L-3: patchDeadLetter spends no attempt
    const st = new Store(join(dL, "s"));
    const dl = {
      route: "tx",
      txHash: ethers.id("l3"),
      blockNumber: 1,
      status: "ERROR",
      reasons: ["x"],
      events: [],
      seenAt: "t",
    };
    st.putDeadLetter(dl);
    const id = `tx-${dl.txHash.toLowerCase()}`;
    st.patchDeadLetter(id, { spEvents: [{ event: "PriceUpdated", logIndex: 1 }] });
    const after = st.getDeadLetter(id);
    cell(
      "L-3: patchDeadLetter updates fields without spending an attempt",
      after.attempts === 1 && after.spEvents?.length === 1,
      after
    );
    // L-5: the same conflicting proof is stored once, and conflicts are counted in total
    const okA = {
      key: "9",
      txHash: ethers.id("l5-a"),
      provenBy: "trace",
      spEvents: [{ event: "PriceUpdated", logIndex: 1 }],
    };
    const okB = { ...okA, txHash: ethers.id("l5-b") };
    const seq = [okA, okA, okB, okB, okB, okA].map(x => st.putBlsAmendment(9n, x));
    cell(
      "L-5: an identical conflicting amendment is stored once; conflicts are counted in total",
      // a repeat of a stored conflict writes nothing ("conflict-same"; follow-up #2 R9)
      j(seq) === j(["new", "same", "conflict", "conflict-same", "conflict-same", "same"]) &&
        st.countAmendmentConflicts() === 1,
      { seq, conflicts: st.countAmendmentConflicts() }
    );
  } finally {
    rmSync(dL, { recursive: true, force: true });
  }
  // L-1: a later failed tx lookup keeps the sender / target / selector an earlier one established
  const dK = mkdtempSync(join(tmpdir(), "guardian-watcher-403l1-"));
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
    const store = new Store(dK);
    const ident = { commit: "0".repeat(40), hash: ethers.id("ruleset"), verified: true };
    const KEEP = addr("l1-keeper");
    const sel = ethers.id("pauseUnderstakedOperator(address)").slice(0, 10);
    const t = c.ownerTx([{ name: "OperatorPaused", args: [addr("l1-op")] }], {
      from: KEEP,
      data: sel,
      trace: false,
    });
    for (let i = 0; i < 4; i++) c.mine();
    await runOnce(c.chain, cfg, store, rs, ident); // the lookup works: sender etc. stored
    c.failTx(t.hash, 1_000_000); // every later lookup fails
    for (let i = 0; i <= MAX_DEADLETTER_ATTEMPTS + 1; i++)
      await runOnce(c.chain, cfg, store, rs, ident);
    c.failTx(t.hash, 0);
    const recs = readdirSync(join(dK, "records")).map(f =>
      JSON.parse(readFileSync(join(dK, "records", f), "utf8"))
    );
    const r = recs.find(x => x.txHash === t.hash);
    cell(
      "L-1: later failed tx lookups keep the sender, target and root selector of an earlier one, through exhaustion",
      r?.route === "unattributed" &&
        r.from === KEEP &&
        r.to === SP &&
        r.rootSelector === sel &&
        r.caller === null,
      r
    );
  } finally {
    rmSync(dK, { recursive: true, force: true });
  }
}

// ---- #404 review L3: a later lookup answering a DIFFERENT tx does not replace the facts the first
// lookup established (first write wins)
{
  const dL3 = mkdtempSync(join(tmpdir(), "guardian-watcher-l3-"));
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
    const store = new Store(dL3);
    const ident = { commit: "0".repeat(40), hash: ethers.id("ruleset"), verified: true };
    const KEEP = addr("l3-keeper");
    const sel = ethers.id("pauseUnderstakedOperator(address)").slice(0, 10);
    const t = c.ownerTx([{ name: "OperatorPaused", args: [addr("l3-op")] }], {
      from: KEEP,
      data: sel,
      trace: false,
    });
    for (let i = 0; i < 4; i++) c.mine();
    await runOnce(c.chain, cfg, store, rs, ident); // the first lookup names the tx
    // every later lookup answers another sender and calldata for the same hash
    c.patchTxFrom(t.hash, 1, { from: addr("l3-other"), data: "0xdeadbeef" });
    for (let i = 0; i <= MAX_DEADLETTER_ATTEMPTS + 1; i++)
      await runOnce(c.chain, cfg, store, rs, ident);
    const recs = readdirSync(join(dL3, "records")).map(f =>
      JSON.parse(readFileSync(join(dL3, "records", f), "utf8"))
    );
    const r = recs.find(x => x.txHash === t.hash);
    cell(
      "#404 L3: a later lookup naming a different sender and calldata does not replace the first lookup's facts (unattributed record keeps them, caller null)",
      r?.route === "unattributed" && r.from === KEEP && r.rootSelector === sel && r.caller === null,
      r && { route: r.route, from: r.from, sel: r.rootSelector, caller: r.caller }
    );
  } finally {
    rmSync(dL3, { recursive: true, force: true });
  }
}

// ---- Codex follow-up #2 R1: a huge raw answer (150 000 null entries) on the range read and on the
// by-hash re-read is quarantined, and the cursor moves (no call-stack overflow before intake)
{
  const dH = mkdtempSync(join(tmpdir(), "guardian-watcher-huge-"));
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
    const store = new Store(dH);
    const ident = { commit: "0".repeat(40), hash: ethers.id("ruleset"), verified: true };
    const g = c.ownerTx([{ name: "GuardianSet", args: [addr("huge-a"), addr("huge-b")] }]);
    for (let i = 0; i < 4; i++) c.mine();
    const huge = new Array(150_000).fill(null);
    let mode = "range";
    const chain = {
      ...c.chain,
      send: async (m, p) => {
        const r = await c.chain.send(m, p);
        if (m !== "eth_getLogs" || String(p[0].address).toLowerCase() !== SP.toLowerCase())
          return r;
        const byHash = p[0].blockHash !== undefined;
        if ((mode === "range" && !byHash) || (mode === "hash" && byHash)) {
          mode = "done";
          return [...r, ...huge];
        }
        return r;
      },
    };
    const s1 = (await runOnce(chain, cfg, store, rs, ident)).status;
    const g2 = c.ownerTx([{ name: "GuardianSet", args: [addr("huge-c"), addr("huge-d")] }]);
    for (let i = 0; i < 4; i++) c.mine();
    const r2 = await c.chain.getTransactionReceipt(g2.hash);
    c.lagTopic(r2.blockNumber, spIface.getEvent("GuardianSet").topicHash);
    mode = "hash";
    const s2 = (await runOnce(chain, cfg, store, rs, ident)).status;
    c.clearLag();
    cell(
      "huge raw answers (150 000 entries) on the range read and on the by-hash re-read are quarantined; the cursor moves",
      s1.ok === true &&
        s1.cursor !== null &&
        s1.isolatedThisTick >= 150_000 &&
        s2.ok === true &&
        s2.bloom.recovered >= 1 &&
        s2.isolatedThisTick >= 150_000 &&
        // bounded: one quarantine record per answer, not one per entry; each a final record
        // carrying the sha256 of its whole payload
        withQ(store).filter(x => x.quarantine === true).length === 2 &&
        withQ(store)
          .filter(x => x.quarantine)
          .every(
            x =>
              x.finalRecord &&
              /^0x[0-9a-f]{64}$/.test(x.payloadSha256) &&
              x.entries === 150_000 &&
              /150000 returned entries are not a log/.test(x.reasons[0])
          ),
      {
        s1: [s1.ok, s1.lastError, s1.cursor, s1.isolatedThisTick],
        s2: [s2.ok, s2.lastError, s2.isolatedThisTick, s2.bloom],
      }
    );
    void g;
  } finally {
    rmSync(dH, { recursive: true, force: true });
  }
}

// ---- quarantine samples are bounded: 30 distinct non-log entries -> one quarantine record, 10 samples
{
  const dQ = mkdtempSync(join(tmpdir(), "guardian-watcher-qsamples-"));
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
    const store = new Store(dQ);
    const ident = { commit: "0".repeat(40), hash: ethers.id("ruleset"), verified: true };
    for (let i = 0; i < 4; i++) c.mine();
    for (let i = 0; i < 30; i++) c.injectRawResult(SP, i % 2 ? `junk-${i}` : i);
    const st = (await runOnce(c.chain, cfg, store, rs, ident)).status;
    const q = withQ(store).filter(x => x.quarantine === true);
    cell(
      "quarantine is bounded: 30 distinct non-log entries make one quarantine record keeping 10 samples, the total in its reason",
      st.ok === true &&
        q.length === 1 &&
        q[0].watched.length === 10 &&
        /^30 returned entries are not a log \(30 distinct, first 10 kept\)/.test(q[0].reasons[0]),
      q.map(x => [x.watched.length, x.reasons])
    );
  } finally {
    rmSync(dQ, { recursive: true, force: true });
  }
}

// ---- follow-up #2 R2/R3: floods stay bounded per tick without losing evidence; deep JSON is stored
{
  const mkRun = () => {
    const d = mkdtempSync(join(tmpdir(), "guardian-watcher-flood-"));
    const c = makeChain();
    const cfg = {
      aggregator: AGG,
      roles: { superPaymaster: SP },
      forwarders: FORWARDERS,
      startBlock: c.head() + 1,
      maxBlocksPerTick: 1000,
      page: 5000,
    };
    const store = new Store(d);
    const ident = { commit: "0".repeat(40), hash: ethers.id("ruleset"), verified: true };
    for (let i = 0; i < 4; i++) c.mine();
    const tick = async () => {
      const t0 = Date.now();
      const st = (await runOnce(c.chain, cfg, store, rs, ident)).status;
      return { st, ms: Date.now() - t0 };
    };
    return { d, c, store, tick };
  };
  const gs = spIface.encodeEventLog("GuardianSet", [addr("fl-a"), addr("fl-b")]);
  const out = {};
  const runs = [];
  try {
    // 4000 object-shaped entries naming no tx: one bounded quarantine
    const a = mkRun();
    runs.push(a);
    for (let i = 0; i < 4000; i++) a.c.injectRawResult(SP, { logIndex: i });
    out.objFlood = await a.tick();
    out.objFloodQ = withQ(a.store).filter(x => x.quarantine).length;
    // 150 malformed logs of distinct txs in ONE block: isolated per tx (a block is never split)
    const b = mkRun();
    runs.push(b);
    for (let i = 0; i < 150; i++)
      b.c.injectRawResult(SP, {
        address: SP,
        ...gs,
        blockNumber: 101,
        index: "bad",
        transactionHash: ethers.id(`fl-one-${i}`),
      });
    out.oneBlock = await b.tick();
    out.oneBlockDls = b.store.listDeadLetters().filter(x => !x.quarantine).length;
    // 150 malformed logs spread over 150 blocks: the tick stops at a block boundary after the
    // budget; the next tick finishes them; none is dropped
    const m = mkRun();
    runs.push(m);
    const first = m.c.head() + 1;
    for (let i = 0; i < 150; i++) m.c.mine();
    for (let i = 0; i < 4; i++) m.c.mine();
    for (let i = 0; i < 150; i++)
      m.c.injectRawResult(SP, {
        address: SP,
        ...gs,
        blockNumber: first + i,
        index: "bad",
        transactionHash: ethers.id(`fl-many-${i}`),
      });
    out.many1 = await m.tick();
    out.many1Dls = m.store.listDeadLetters().filter(x => !x.quarantine).length;
    // the stub hands injected answers out once: re-inject the tail the second tick reads again
    for (let i = 0; i < 150; i++)
      if (first + i > out.many1.st.cursor)
        m.c.injectRawResult(SP, {
          address: SP,
          ...gs,
          blockNumber: first + i,
          index: "bad",
          transactionHash: ethers.id(`fl-many-${i}`),
        });
    out.many2 = await m.tick();
    out.manyDls = m.store.listDeadLetters().filter(x => !x.quarantine).length;
    // a log whose `data` is nested 10 000 deep, and one carrying a deeply nested `range` field
    const dd = mkRun();
    runs.push(dd);
    let deep = "x";
    for (let i = 0; i < 10_000; i++) deep = [deep];
    dd.c.injectRawResult(SP, {
      address: SP,
      ...gs,
      data: deep,
      blockNumber: 101,
      index: 0,
      transactionHash: ethers.id("fl-deep"),
    });
    dd.c.injectRawResult(SP, {
      address: SP,
      ...gs,
      data: "0x1",
      blockNumber: 101,
      index: 1,
      transactionHash: ethers.id("fl-range"),
      range: [deep, 1],
    });
    out.deep = await dd.tick();
    out.deepDls = dd.store.listDeadLetters();
  } finally {
    for (const r of runs) rmSync(r.d, { recursive: true, force: true });
  }
  cell(
    "floods are bounded per tick without dropping evidence: junk naming no tx is one quarantine; one block's 150 malformed txs are isolated per tx; 150 spread over blocks stop at a block boundary and finish next tick; deep data / a returned deep `range` never escape",
    out.objFlood.st.ok &&
      out.objFlood.ms < 10_000 &&
      out.objFloodQ === 1 &&
      out.oneBlock.st.ok &&
      out.oneBlockDls === 150 &&
      out.many1.st.ok &&
      out.many1.st.cursor < out.many2.st.cursor &&
      out.many1Dls >= 100 &&
      out.many1Dls < 150 &&
      out.many2.st.ok &&
      out.manyDls === 150 &&
      out.deep.st.ok &&
      out.deepDls.length === 2 &&
      /too deep or too large/.test(JSON.stringify(out.deepDls.map(x => x.watched))) &&
      // the placeholder keeps the full text's length and sha256 (follow-up #2 R5)
      out.deepDls.some(x =>
        (x.watched ?? []).some(
          w => /^0x[0-9a-f]{64}$/.test(w.rawSha256 ?? "") && w.rawLength > 20_000
        )
      ),
    {
      objFlood: [out.objFlood.st.ok, out.objFlood.ms, out.objFloodQ],
      oneBlock: [out.oneBlock.st.ok, out.oneBlockDls],
      many: [out.many1.st.cursor, out.many1Dls, out.many2.st.cursor, out.manyDls],
      deep: [out.deep.st.ok, out.deep.st.lastError, out.deepDls?.length],
    }
  );
}

// ---- follow-up #2 R3: one block past any real size joins a bounded quarantine; RPC fields that
// collide with the watcher's own evidence fields never reach the evidence
{
  const d = mkdtempSync(join(tmpdir(), "guardian-watcher-overflow-"));
  const c = makeChain();
  const cfg = {
    aggregator: AGG,
    roles: { superPaymaster: SP },
    forwarders: FORWARDERS,
    startBlock: c.head() + 1,
    maxBlocksPerTick: 1000,
    page: 5000,
  };
  const store = new Store(d);
  const ident = { commit: "0".repeat(40), hash: ethers.id("ruleset"), verified: true };
  for (let i = 0; i < 4; i++) c.mine();
  const gs = spIface.encodeEventLog("GuardianSet", [addr("ov-a"), addr("ov-b")]);
  for (let i = 0; i < 2100; i++)
    c.injectRawResult(SP, {
      address: SP,
      ...gs,
      blockNumber: 101,
      index: i,
      removed: true,
      transactionHash: ethers.id(`ov-${i}`),
    });
  const reserved = () =>
    c.injectRawResult(SP, {
      address: SP,
      ...gs,
      blockNumber: 102,
      index: 0,
      removed: true,
      transactionHash: ethers.id("ov-reserved"),
      source: "agg",
      quarantine: true,
      count: 7,
    });
  reserved();
  let st, st2, dls, ms;
  try {
    const t0 = Date.now();
    st = (await runOnce(c.chain, cfg, store, rs, ident)).status;
    ms = Date.now() - t0;
    // the tick stopped after block 101 (its budget); block 102 is read again on the next tick
    reserved();
    st2 = (await runOnce(c.chain, cfg, store, rs, ident)).status;
    dls = withQ(store);
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
  const perTx = dls.filter(x => !x.quarantine);
  const q = dls.filter(x => x.quarantine);
  const res = perTx.find(x => x.txHash === ethers.id("ov-reserved"));
  const resEv = JSON.stringify(res?.watched ?? null);
  cell(
    "a block past MAX_TXS_PER_BLOCK isolates 2000 txs and quarantines the rest in one bounded letter (query source kept); the tick stops at that block and the next one continues; reserved fields (source, quarantine, count) returned by the RPC are stripped from evidence",
    st?.ok &&
      st.cursor === 101 &&
      st2?.ok &&
      st2.cursor > 102 &&
      perTx.length === 2001 &&
      q.length === 1 &&
      /"source":"sp"/.test(JSON.stringify(q[0].watched)) &&
      /^100 returned entries are past 2000 isolating txs in one block/.test(
        q[0].reasons?.join(" ") ?? ""
      ) &&
      res &&
      !res.quarantine &&
      !/"count":7/.test(resEv) &&
      !/"source":"agg"/.test(resEv) &&
      /"source":"sp"/.test(resEv),
    {
      ok: st?.ok,
      err: st?.lastError,
      c1: st?.cursor,
      c2: st2?.cursor,
      ms,
      perTx: perTx.length,
      q: q.length,
      qReason: q[0]?.reasons,
      resEv: resEv.slice(0, 300),
    }
  );
}

// ---- follow-up #2 R3 (mutants): txs with no usable height are capped like a block; a `range`
// the RPC returns never becomes the stored query range
{
  const d = mkdtempSync(join(tmpdir(), "guardian-watcher-noheight-"));
  const c = makeChain();
  const cfg = {
    aggregator: AGG,
    roles: { superPaymaster: SP },
    forwarders: FORWARDERS,
    startBlock: c.head() + 1,
    maxBlocksPerTick: 1000,
    page: 5000,
  };
  const store = new Store(d);
  const ident = { commit: "0".repeat(40), hash: ethers.id("ruleset"), verified: true };
  for (let i = 0; i < 4; i++) c.mine();
  const from = cfg.startBlock;
  const gs = spIface.encodeEventLog("GuardianSet", [addr("nh-a"), addr("nh-b")]);
  for (let i = 0; i < 2100; i++)
    // half with no height, half claiming distinct heights past the range: one shared bucket
    c.injectRawResult(SP, {
      address: SP,
      ...gs,
      index: i,
      ...(i % 2 ? { blockNumber: 1_000_000 + i } : {}),
      transactionHash: ethers.id(`nh-${i}`),
    });
  c.injectRawResult(SP, {
    address: SP,
    ...gs,
    blockNumber: from,
    index: 0,
    removed: true,
    transactionHash: ethers.id("nh-range"),
    range: [1, 2],
  });
  let st, dls;
  try {
    st = (await runOnce(c.chain, cfg, store, rs, ident)).status;
    dls = withQ(store);
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
  const perTx = dls.filter(x => !x.quarantine);
  const q = dls.filter(x => x.quarantine);
  const fake = perTx.find(x => x.txHash === ethers.id("nh-range"));
  const ranges = (fake?.watched ?? []).map(w => w.range);
  cell(
    "2100 logs of distinct txs with no height: 2000 isolated, the rest one bounded quarantine (never one write each); a `range` field returned by the RPC is not stored as the query range",
    st?.ok &&
      perTx.length === 2001 &&
      q.length === 1 &&
      /no usable height/.test(q[0].reasons?.join(" ") ?? "") &&
      ranges.length > 0 &&
      ranges.every(r => Array.isArray(r) && r[0] === from && r[1] !== 2),
    {
      ok: st?.ok,
      err: st?.lastError,
      perTx: perTx.length,
      q: q.length,
      qr: q[0]?.reasons,
      ranges,
      from,
    }
  );
}

// ---- follow-up #2 R3: entries naming no usable tx hash share one bulk quarantine at intake
{
  const d = mkdtempSync(join(tmpdir(), "guardian-watcher-nohash-"));
  const c = makeChain();
  const cfg = {
    aggregator: AGG,
    roles: { superPaymaster: SP },
    forwarders: FORWARDERS,
    startBlock: c.head() + 1,
    maxBlocksPerTick: 1000,
    page: 5000,
  };
  const store = new Store(d);
  const ident = { commit: "0".repeat(40), hash: ethers.id("ruleset"), verified: true };
  for (let i = 0; i < 4; i++) c.mine();
  const gs = spIface.encodeEventLog("GuardianSet", [addr("nx-a"), addr("nx-b")]);
  for (const h of ["x1", "0x12", 7])
    c.injectRawResult(SP, {
      address: SP,
      ...gs,
      blockNumber: cfg.startBlock,
      index: 0,
      transactionHash: h,
    });
  let st, dls;
  try {
    st = (await runOnce(c.chain, cfg, store, rs, ident)).status;
    dls = withQ(store);
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
  cell(
    "three logs with distinct unusable tx hashes: one bulk quarantine at intake, no per-tx dead letter",
    st?.ok &&
      dls.length === 1 &&
      dls[0].quarantine &&
      /^3 returned entries are not a log/.test(dls[0].reasons?.join(" ") ?? ""),
    { ok: st?.ok, n: dls?.length, r: dls?.map(x => x.reasons) }
  );
}

// ---- follow-up #2 R4: only an in-range height can stop a tick (it always advances); txs with no
// height or outside the range are handled in the tick that read them, never deferred and lost
{
  const runs = [];
  const mk = () => {
    const d = mkdtempSync(join(tmpdir(), "guardian-watcher-r4-"));
    runs.push(d);
    const c = makeChain();
    const cfg = {
      aggregator: AGG,
      roles: { superPaymaster: SP },
      forwarders: FORWARDERS,
      startBlock: c.head() + 1,
      maxBlocksPerTick: 1000,
      page: 5000,
    };
    return { c, cfg, store: new Store(d) };
  };
  const ident = { commit: "0".repeat(40), hash: ethers.id("ruleset"), verified: true };
  const gs = spIface.encodeEventLog("GuardianSet", [addr("r4-a"), addr("r4-b")]);
  const out = {};
  try {
    // 150 isolating logs claiming the block before the range, beside one healthy owner tx
    const a = mk();
    const k = a.c.ownerTx([{ name: "SlashCancelled", args: [addr("r4-op")] }]);
    for (let i = 0; i < 4; i++) a.c.mine();
    for (let i = 0; i < 150; i++)
      a.c.injectRawResult(SP, {
        address: SP,
        ...gs,
        blockNumber: a.cfg.startBlock - 1,
        index: 0,
        transactionHash: ethers.id(`r4-prev-${i}`),
      });
    out.a = (await runOnce(a.c.chain, a.cfg, a.store, rs, ident)).status;
    out.aRec = readdirSync(join(a.store.dir, "records")).some(f =>
      f.includes(k.hash.toLowerCase().slice(2))
    );
    out.aDls = a.store.listDeadLetters().length;
    // 120 isolating logs on distinct in-range blocks, plus 5 with no height: the tick stops at a
    // block boundary, and the 5 are already dead letters (handled, not deferred)
    const b = mk();
    const first = b.cfg.startBlock;
    for (let i = 0; i < 124; i++) b.c.mine();
    for (let i = 0; i < 120; i++)
      b.c.injectRawResult(SP, {
        address: SP,
        ...gs,
        blockNumber: first + i,
        index: "bad",
        transactionHash: ethers.id(`r4-in-${i}`),
      });
    for (let i = 0; i < 5; i++)
      b.c.injectRawResult(SP, {
        address: SP,
        ...gs,
        index: 0,
        transactionHash: ethers.id(`r4-nh-${i}`),
      });
    out.b = (await runOnce(b.c.chain, b.cfg, b.store, rs, ident)).status;
    const bd = new Set(b.store.listDeadLetters().map(x => x.txHash));
    out.bNh = [0, 1, 2, 3, 4].filter(i => bd.has(ethers.id(`r4-nh-${i}`))).length;
  } finally {
    for (const d of runs) rmSync(d, { recursive: true, force: true });
  }
  cell(
    "follow-up R4: 150 isolating logs naming the block before the range cannot hold the cursor (the range completes, the healthy tx is recorded); after an early stop, txs with no height are already dead letters",
    out.a.ok &&
      out.a.cursor === out.a.finalized &&
      out.aRec &&
      out.aDls === 150 &&
      !out.a.budgetStopThisTick &&
      out.b.ok &&
      out.b.cursor < out.b.finalized &&
      out.b.budgetStopThisTick &&
      out.bNh === 5,
    {
      a: [out.a.ok, out.a.cursor, out.a.finalized, out.aRec, out.aDls],
      b: [out.b.ok, out.b.cursor, out.b.finalized, out.bNh],
    }
  );
}

// ---- DSR 2892c30f: quarantine is a final, unaccusing record with the payload's sha256; status counts
// budget stops and quarantines (totals survive ticks); a budget stop and a cursor too far behind are
// degraded
{
  const d = mkdtempSync(join(tmpdir(), "guardian-watcher-counters-"));
  const c = makeChain();
  const cfg = {
    aggregator: AGG,
    roles: { superPaymaster: SP },
    forwarders: FORWARDERS,
    startBlock: c.head() + 1,
    maxBlocksPerTick: 1000,
    page: 5000,
  };
  const store = new Store(d);
  const ident = { commit: "0".repeat(40), hash: ethers.id("ruleset"), verified: true };
  const gs = spIface.encodeEventLog("GuardianSet", [addr("ct-a"), addr("ct-b")]);
  const first = cfg.startBlock;
  for (let i = 0; i < 130; i++) c.mine();
  const junk = [7, "x", { logIndex: 1 }];
  const out = {};
  try {
    for (const x of junk) c.injectRawResult(SP, x);
    for (let i = 0; i < 110; i++)
      c.injectRawResult(SP, {
        address: SP,
        ...gs,
        blockNumber: first + i,
        index: "bad",
        transactionHash: ethers.id(`ct-${i}`),
      });
    out.t1 = (await runOnce(c.chain, cfg, store, rs, ident)).status;
    out.q = readdirSync(join(d, "records"))
      .map(f => JSON.parse(readFileSync(join(d, "records", f), "utf8")))
      .filter(r => r.quarantine);
    out.dlQ = store.listDeadLetters().filter(x => x.quarantine).length;
    // the next tick: more junk, a second budget stop
    for (const x of ["y", 8]) c.injectRawResult(SP, x);
    for (let i = 110; i < 125; i++)
      c.injectRawResult(SP, {
        address: SP,
        ...gs,
        blockNumber: first + i,
        index: "bad",
        transactionHash: ethers.id(`ct-${i}`),
      });
    out.t2 = (await runOnce(c.chain, cfg, store, rs, ident)).status;
    // lag: a tick limited to 2 blocks, with more than maxLagBlocks still to go
    const d2 = mkdtempSync(join(tmpdir(), "guardian-watcher-lag-"));
    try {
      const c2 = makeChain();
      const cfg2 = { ...cfg, startBlock: c2.head() + 1, maxBlocksPerTick: 2, maxLagBlocks: 5 };
      for (let i = 0; i < 20; i++) c2.mine();
      out.lag = (await runOnce(c2.chain, cfg2, new Store(d2), rs, ident)).status;
      const cfg3 = { ...cfg2, maxLagBlocks: 1000 };
      out.noLag = (await runOnce(c2.chain, cfg3, new Store(d2), rs, ident)).status;
    } finally {
      rmSync(d2, { recursive: true, force: true });
    }
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
  const want = createHash("sha256");
  for (const x of junk) want.update(JSON.stringify(x) + "\n");
  const q = out.q[0];
  cell(
    "quarantine is final at once (unattributed, UNREADABLE, caller null, never an accusation) with entries, samples and the sha256 of the whole payload; status counts budget stops and quarantines per tick and in total; budget stop and lag > maxLagBlocks are degraded",
    out.q.length === 1 &&
      out.dlQ === 0 &&
      q.route === "unattributed" &&
      q.event === "UNREADABLE" &&
      q.caller === null &&
      q.verdict.rule === "watcher.UNREADABLE" &&
      q.entries === 3 &&
      q.payloadSha256 === `0x${want.digest("hex")}` &&
      q.evidence.length === 3 &&
      out.t1.quarantinedThisTick === 1 &&
      out.t1.quarantinedTotal === 1 &&
      out.t1.budgetStopThisTick === true &&
      out.t1.budgetStopsTotal === 1 &&
      out.t1.healthy === false &&
      out.t1.degraded.some(r => /isolation budget reached/.test(r)) &&
      out.t2.quarantinedTotal === 2 &&
      out.t2.budgetStopsTotal >= 1 &&
      out.lag.ok &&
      out.lag.degraded?.some(r => /blocks behind finalized \(> 5\)/.test(r)) &&
      !(out.noLag.degraded ?? []).some(r => /behind finalized/.test(r)),
    {
      q: q && {
        route: q.route,
        event: q.event,
        entries: q.entries,
        sha: q.payloadSha256,
        ev: q.evidence?.length,
      },
      dlQ: out.dlQ,
      t1: out.t1 && [
        out.t1.quarantinedThisTick,
        out.t1.quarantinedTotal,
        out.t1.budgetStopThisTick,
        out.t1.budgetStopsTotal,
        out.t1.degraded,
      ],
      t2: out.t2 && [out.t2.quarantinedTotal, out.t2.budgetStopsTotal],
      lag: out.lag && [out.lag.lagBlocks, out.lag.degraded],
      noLag: out.noLag?.degraded,
    }
  );
}

// ---- a tick that fails after its quarantine and re-reads the same range does not count it twice
{
  const d = mkdtempSync(join(tmpdir(), "guardian-watcher-qsame-"));
  const c = makeChain();
  const cfg = {
    aggregator: AGG,
    roles: { superPaymaster: SP },
    forwarders: FORWARDERS,
    startBlock: c.head() + 1,
    maxBlocksPerTick: 1000,
    page: 5000,
  };
  const store = new Store(d);
  const ident = { commit: "0".repeat(40), hash: ethers.id("ruleset"), verified: true };
  for (let i = 0; i < 6; i++) c.mine();
  let t1, t2, recs, afterT1;
  try {
    // the tick fails at its last step (the cursor write), after the quarantine was written
    const setCursor = store.setCursor.bind(store);
    store.setCursor = () => {
      store.setCursor = setCursor;
      throw new Error("injected cursor write failure");
    };
    c.injectRawResult(SP, "junk");
    t1 = (await runOnce(c.chain, cfg, store, rs, ident)).status;
    afterT1 = readdirSync(join(d, "records")).length;
    c.injectRawResult(SP, "junk");
    t2 = (await runOnce(c.chain, cfg, store, rs, ident)).status;
    recs = readdirSync(join(d, "records")).filter(f => f.endsWith(".json")).length;
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
  cell(
    "a quarantine written by a tick that then failed is still counted in total; its re-read by the retried range is the same record (not new this tick)",
    t1.ok === false &&
      afterT1 === 1 &&
      t2.ok === true &&
      recs === 1 &&
      t2.quarantinedThisTick === 0 &&
      t2.quarantinedTotal === 1,
    {
      t1: [t1.ok, t1.lastError, afterT1],
      t2: [t2.ok, t2.quarantinedThisTick, t2.quarantinedTotal, t2.scanned],
      recs,
    }
  );
}

// ---- follow-up #2 R5: dead letters written without a throw (a tx lookup answering null) spend
// the budget and the per-block cap too
{
  const runs = [];
  const mk = () => {
    const d = mkdtempSync(join(tmpdir(), "guardian-watcher-r5-"));
    runs.push(d);
    const c = makeChain();
    const cfg = {
      aggregator: AGG,
      roles: { superPaymaster: SP },
      forwarders: FORWARDERS,
      startBlock: c.head() + 1,
      maxBlocksPerTick: 1000,
      page: 5000,
    };
    return { c, cfg, store: new Store(d) };
  };
  const ident = { commit: "0".repeat(40), hash: ethers.id("ruleset"), verified: true };
  const gs = spIface.encodeEventLog("SlashCancelled", [addr("r5-op")]);
  const out = {};
  try {
    const a = mk();
    for (let i = 0; i < 160; i++) a.c.mine();
    for (let i = 0; i < 150; i++)
      a.c.injectLog(a.cfg.startBlock + i, {
        address: SP,
        ...gs,
        transactionHash: ethers.id(`r5-many-${i}`),
      });
    for (let i = 0; i < 4; i++) a.c.mine();
    out.a = (await runOnce(a.c.chain, a.cfg, a.store, rs, ident)).status;
    out.aDls = a.store.listDeadLetters();
    const b = mk();
    for (let i = 0; i < 3; i++) b.c.mine();
    for (let i = 0; i < 2100; i++)
      b.c.injectLog(b.cfg.startBlock + 1, {
        address: SP,
        ...gs,
        index: i,
        transactionHash: ethers.id(`r5-one-${i}`),
      });
    for (let i = 0; i < 4; i++) b.c.mine();
    out.b = (await runOnce(b.c.chain, b.cfg, b.store, rs, ident)).status;
    out.bDls = b.store.listDeadLetters().length;
    out.bQ = withQ(b.store).filter(x => x.quarantine).length;
  } finally {
    for (const d of runs) rmSync(d, { recursive: true, force: true });
  }
  cell(
    "follow-up R5: null tx lookups (dead letters without a throw) spend the budget (150 over blocks: the tick stops at a block boundary) and the per-block cap (2100 in one block: 2000 dead letters + one quarantine)",
    out.a.ok &&
      out.a.budgetStopThisTick &&
      out.a.cursor < out.a.finalized &&
      out.aDls.length >= 100 &&
      out.aDls.length < 150 &&
      out.aDls.every(x => /transaction unavailable/.test(x.reasons.join(" "))) &&
      out.b.ok &&
      out.bDls === 2000 &&
      out.bQ === 1,
    {
      a: [out.a.ok, out.a.cursor, out.a.finalized, out.aDls.length, out.aDls[0]?.reasons],
      b: [out.b.ok, out.bDls, out.bQ],
    }
  );
}

// ---- follow-up #2 R5: deep JSON is hashed and sampled in full (no placeholder): distinct deep
// entries stay distinct, the payload digest is of the real text
{
  const d = mkdtempSync(join(tmpdir(), "guardian-watcher-deepq-"));
  const c = makeChain();
  const cfg = {
    aggregator: AGG,
    roles: { superPaymaster: SP },
    forwarders: FORWARDERS,
    startBlock: c.head() + 1,
    maxBlocksPerTick: 1000,
    page: 5000,
  };
  const store = new Store(d);
  const ident = { commit: "0".repeat(40), hash: ethers.id("ruleset"), verified: true };
  for (let i = 0; i < 4; i++) c.mine();
  const N = 10_000;
  const nest = leaf => {
    let v = leaf;
    for (let i = 0; i < N; i++) v = [v];
    return v;
  };
  const texts = ["a", "b"].map(l => "[".repeat(N) + JSON.stringify(l) + "]".repeat(N));
  let st, q;
  try {
    c.injectRawResult(SP, nest("a"));
    c.injectRawResult(SP, nest("b"));
    st = (await runOnce(c.chain, cfg, store, rs, ident)).status;
    q = withQ(store).find(x => x.quarantine);
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
  const want = createHash("sha256");
  for (const t of texts) want.update(t + "\n");
  const sh = t => `0x${createHash("sha256").update(t).digest("hex")}`;
  const ev = q?.evidence ?? [];
  cell(
    "two distinct 10 000-deep entries: one quarantine, two samples (prefix, full length, own sha256), payload sha256 of the full text",
    st?.ok &&
      q &&
      q.distinct === 2 &&
      ev.length === 2 &&
      q.payloadSha256 === `0x${want.digest("hex")}` &&
      ev.every(e => e.truncated && e.rawLength === texts[0].length && e.raw.length <= 2048) &&
      new Set(ev.map(e => e.rawSha256)).size === 2 &&
      ev.every(e => texts.map(sh).includes(e.rawSha256)) &&
      !JSON.stringify(ev).includes("unserialisable"),
    {
      ok: st?.ok,
      err: st?.lastError,
      distinct: q?.distinct,
      ev: ev.map(e => [e.truncated, e.rawLength, e.rawSha256?.slice(0, 10)]),
    }
  );
}

// ---- a busy, healthy range spends no budget: 150 healthy txs are recorded in one tick, not degraded
{
  const d = mkdtempSync(join(tmpdir(), "guardian-watcher-busy-"));
  const c = makeChain();
  const cfg = {
    aggregator: AGG,
    roles: { superPaymaster: SP },
    forwarders: FORWARDERS,
    startBlock: c.head() + 1,
    maxBlocksPerTick: 1000,
    page: 5000,
  };
  const store = new Store(d);
  const ident = { commit: "0".repeat(40), hash: ethers.id("ruleset"), verified: true };
  let st, recs;
  try {
    // one failing tx first (a null lookup), so a dead letter already exists in this tick
    c.mine();
    c.injectLog(cfg.startBlock, {
      address: SP,
      ...spIface.encodeEventLog("SlashCancelled", [addr("busy-bad")]),
      transactionHash: ethers.id("busy-bad"),
    });
    for (let i = 0; i < 150; i++)
      c.ownerTx([{ name: "SlashCancelled", args: [addr(`busy-${i}`)] }]);
    for (let i = 0; i < 4; i++) c.mine();
    st = (await runOnce(c.chain, cfg, store, rs, ident)).status;
    recs = store.countRecords();
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
  cell(
    "one failing tx then 150 healthy txs in one tick: all recorded, no budget stop (healthy txs spend nothing), the cursor reaches finalized",
    st.ok &&
      recs === 150 &&
      !st.budgetStopThisTick &&
      st.cursor === st.finalized &&
      st.deadLetters === 1,
    {
      ok: st.ok,
      recs,
      budget: st.budgetStopThisTick,
      cursor: st.cursor,
      fin: st.finalized,
      dls: st.deadLetters,
      deg: st.degraded,
    }
  );
}

// ---- follow-up #2 R6: a tx's commitments each spend the budget; an impossible number of them is
// one quarantine
{
  const runs = [];
  const mk = () => {
    const d = mkdtempSync(join(tmpdir(), "guardian-watcher-r6-"));
    runs.push(d);
    const c = makeChain();
    const cfg = {
      aggregator: AGG,
      roles: { superPaymaster: SP },
      forwarders: FORWARDERS,
      startBlock: c.head() + 1,
      maxBlocksPerTick: 1000,
      page: 5000,
    };
    return { c, cfg, store: new Store(d) };
  };
  const ident = { commit: "0".repeat(40), hash: ethers.id("ruleset"), verified: true };
  const sc = (k, m) => aggIface.encodeEventLog("SignersCommitted", [k, m]);
  const out = {};
  try {
    // 2100 commitments in one tx whose lookups answer null: one quarantine, no dead letter each
    const a = mk();
    for (let i = 0; i < 3; i++) a.c.mine();
    for (let i = 0; i < 2100; i++)
      a.c.injectLog(a.cfg.startBlock + 1, {
        address: AGG,
        ...sc(BigInt(i + 1), 3n),
        index: i,
        transactionHash: ethers.id("r6-big"),
      });
    for (let i = 0; i < 4; i++) a.c.mine();
    out.a = (await runOnce(a.c.chain, a.cfg, a.store, rs, ident)).status;
    out.aDls = a.store.listDeadLetters().length;
    out.aQ = withQ(a.store).filter(x => x.quarantine);
    // three txs of 60 commitments on three blocks: the writes of the first two reach the budget,
    // so the tick stops before the third block
    const b = mk();
    for (let i = 0; i < 4; i++) b.c.mine();
    for (let t = 0; t < 3; t++)
      for (let i = 0; i < 60; i++)
        b.c.injectLog(b.cfg.startBlock + t, {
          address: AGG,
          ...sc(BigInt(1000 * t + i + 1), 3n),
          index: i,
          transactionHash: ethers.id(`r6-tx-${t}`),
        });
    for (let i = 0; i < 4; i++) b.c.mine();
    out.b = (await runOnce(b.c.chain, b.cfg, b.store, rs, ident)).status;
    out.bDls = b.store.listDeadLetters();
  } finally {
    for (const d of runs) rmSync(d, { recursive: true, force: true });
  }
  const bTx = new Set(out.bDls.map(x => x.txHash));
  cell(
    "follow-up R6: 2100 commitments in one tx are one quarantine (no per-commitment writes); commitments spend the budget one write each, so three 60-commitment txs stop the tick before the third block",
    out.a.ok &&
      out.aDls === 0 &&
      out.aQ.length === 1 &&
      out.aQ[0].entries === 2100 &&
      /more than 300 commitments/.test(out.aQ[0].reasons.join(" ")) &&
      out.b.ok &&
      out.b.budgetStopThisTick &&
      out.b.cursor === out.b.scanned[0] + 1 &&
      !out.bDls.some(x => x.txHash === ethers.id("r6-tx-2")),
    {
      a: [out.a.ok, out.aDls, out.aQ.length, out.aQ[0]?.entries, out.aQ[0]?.reasons],
      b: [
        out.b.ok,
        out.b.cursor,
        out.b.scanned,
        out.b.budgetStopThisTick,
        out.bDls.length,
        bTx.size,
      ],
    }
  );
}

// ---- follow-up #2 R6: two distinct deep logs of one tx stay two observations, through retries
{
  const d = mkdtempSync(join(tmpdir(), "guardian-watcher-deeptx-"));
  const c = makeChain();
  const cfg = {
    aggregator: AGG,
    roles: { superPaymaster: SP },
    forwarders: FORWARDERS,
    startBlock: c.head() + 1,
    maxBlocksPerTick: 1000,
    page: 5000,
  };
  const store = new Store(d);
  const ident = { commit: "0".repeat(40), hash: ethers.id("ruleset"), verified: true };
  for (let i = 0; i < 4; i++) c.mine();
  const gs = spIface.encodeEventLog("GuardianSet", [addr("dt-a"), addr("dt-b")]);
  const nest = leaf => {
    let v = leaf;
    for (let i = 0; i < 10_000; i++) v = [v];
    return v;
  };
  const h = ethers.id("dt-tx");
  let w1, w3;
  try {
    c.injectRawResult(SP, {
      address: SP,
      ...gs,
      data: nest("a"),
      blockNumber: cfg.startBlock,
      index: 0,
      transactionHash: h,
    });
    c.injectRawResult(SP, {
      address: SP,
      ...gs,
      data: nest("b"),
      blockNumber: cfg.startBlock,
      index: 1,
      transactionHash: h,
    });
    // the first tick fails at its cursor write, so the same range is read again while the dead
    // letter is open: the fresh copies must match their stored placeholders, not add to them
    const setCursor = store.setCursor.bind(store);
    store.setCursor = () => {
      store.setCursor = setCursor;
      throw new Error("injected cursor write failure");
    };
    await runOnce(c.chain, cfg, store, rs, ident);
    c.injectRawResult(SP, {
      address: SP,
      ...gs,
      data: nest("a"),
      blockNumber: cfg.startBlock,
      index: 0,
      transactionHash: h,
    });
    c.injectRawResult(SP, {
      address: SP,
      ...gs,
      data: nest("b"),
      blockNumber: cfg.startBlock,
      index: 1,
      transactionHash: h,
    });
    await runOnce(c.chain, cfg, store, rs, ident);
    w1 = store.getDeadLetter(`tx-${h.toLowerCase()}`)?.watched ?? [];
    for (let i = 0; i < 2; i++) await runOnce(c.chain, cfg, store, rs, ident);
    w3 = store.getDeadLetter(`tx-${h.toLowerCase()}`)?.watched ?? [];
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
  const shas = w => new Set(w.map(x => x.rawSha256).filter(Boolean));
  cell(
    "follow-up R6: two distinct 10 000-deep logs of one tx are two stored observations with distinct digests, unchanged by a re-read of the same range and by retries",
    w1.length === 2 &&
      shas(w1).size === 2 &&
      w3.length === 2 &&
      JSON.stringify(w3) === JSON.stringify(w1),
    { n1: w1.length, s1: shas(w1).size, n3: w3.length }
  );
}
// ---- follow-up #2 R7: the same for logs 100 deep (storable as JSON, but past MAX_EVIDENCE_DEPTH)
{
  const d = mkdtempSync(join(tmpdir(), "guardian-watcher-deeptx100-"));
  const c = makeChain();
  const cfg = {
    aggregator: AGG,
    roles: { superPaymaster: SP },
    forwarders: FORWARDERS,
    startBlock: c.head() + 1,
    maxBlocksPerTick: 1000,
    page: 5000,
  };
  const store = new Store(d);
  const ident = { commit: "0".repeat(40), hash: ethers.id("ruleset"), verified: true };
  for (let i = 0; i < 4; i++) c.mine();
  const gs = spIface.encodeEventLog("GuardianSet", [addr("dt-a"), addr("dt-b")]);
  const nest = leaf => {
    let v = leaf;
    for (let i = 0; i < 100; i++) v = [v];
    return v;
  };
  const h = ethers.id("dt-tx-100");
  let w1, w3;
  try {
    c.injectRawResult(SP, {
      address: SP,
      ...gs,
      data: nest("a"),
      blockNumber: cfg.startBlock,
      index: 0,
      transactionHash: h,
    });
    c.injectRawResult(SP, {
      address: SP,
      ...gs,
      data: nest("b"),
      blockNumber: cfg.startBlock,
      index: 1,
      transactionHash: h,
    });
    // the first tick fails at its cursor write, so the same range is read again while the dead
    // letter is open: the fresh copies must match their stored placeholders, not add to them
    const setCursor = store.setCursor.bind(store);
    store.setCursor = () => {
      store.setCursor = setCursor;
      throw new Error("injected cursor write failure");
    };
    await runOnce(c.chain, cfg, store, rs, ident);
    c.injectRawResult(SP, {
      address: SP,
      ...gs,
      data: nest("a"),
      blockNumber: cfg.startBlock,
      index: 0,
      transactionHash: h,
    });
    c.injectRawResult(SP, {
      address: SP,
      ...gs,
      data: nest("b"),
      blockNumber: cfg.startBlock,
      index: 1,
      transactionHash: h,
    });
    await runOnce(c.chain, cfg, store, rs, ident);
    w1 = store.getDeadLetter(`tx-${h.toLowerCase()}`)?.watched ?? [];
    for (let i = 0; i < 2; i++) await runOnce(c.chain, cfg, store, rs, ident);
    w3 = store.getDeadLetter(`tx-${h.toLowerCase()}`)?.watched ?? [];
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
  const shas = w => new Set(w.map(x => x.rawSha256).filter(Boolean));
  cell(
    "follow-up R7: two distinct 100-deep logs of one tx are two stored observations with distinct digests, unchanged by a re-read of the same range and by retries",
    w1.length === 2 &&
      shas(w1).size === 2 &&
      w3.length === 2 &&
      JSON.stringify(w3) === JSON.stringify(w1),
    { n1: w1.length, s1: shas(w1).size, n3: w3.length }
  );
}

// ---- follow-up #2 R7: stored evidence thousands deep is decoded without recursion (retries run,
// attempts count); one tx's watched logs and one block's records are bounded
{
  const runs = [];
  const mk = () => {
    const d = mkdtempSync(join(tmpdir(), "guardian-watcher-r7-"));
    runs.push(d);
    const c = makeChain();
    const cfg = {
      aggregator: AGG,
      roles: { superPaymaster: SP },
      forwarders: FORWARDERS,
      startBlock: c.head() + 1,
      maxBlocksPerTick: 1000,
      page: 5000,
    };
    return { c, cfg, store: new Store(d) };
  };
  const ident = { commit: "0".repeat(40), hash: ethers.id("ruleset"), verified: true };
  const gs = spIface.encodeEventLog("GuardianSet", [addr("r7-a"), addr("r7-b")]);
  const out = {};
  try {
    // a log whose data is 6000 nested objects: a dead letter, retried on later ticks
    const a = mk();
    for (let i = 0; i < 4; i++) a.c.mine();
    let deep = "x";
    // 6000: still storable as JSON, but deeper than any recursive decoder survives
    for (let i = 0; i < 6000; i++) deep = { a: deep };
    const h = ethers.id("r7-deep");
    a.c.injectRawResult(SP, {
      address: SP,
      ...gs,
      data: deep,
      blockNumber: a.cfg.startBlock,
      index: 0,
      transactionHash: h,
    });
    out.a1 = (await runOnce(a.c.chain, a.cfg, a.store, rs, ident)).status;
    out.a2 = (await runOnce(a.c.chain, a.cfg, a.store, rs, ident)).status;
    out.a3 = (await runOnce(a.c.chain, a.cfg, a.store, rs, ident)).status;
    out.aAtt = a.store.getDeadLetter(`tx-${h.toLowerCase()}`)?.attempts;
    // stored as a placeholder (prefix, length, sha256), so the file stays small: indented JSON of a
    // 6000-deep value would be tens of MB, rewritten on every retry
    const dlFile = join(a.store.dir, "deadletters", `tx-${h.toLowerCase()}.json`);
    out.aBytes = readFileSync(dlFile).length;
    out.aW = a.store.getDeadLetter(`tx-${h.toLowerCase()}`)?.watched ?? [];
    // 2100 watched SP logs in one tx: one quarantine, no records or dead letters each
    const b = mk();
    for (let i = 0; i < 3; i++) b.c.mine();
    for (let i = 0; i < 2100; i++)
      b.c.injectLog(b.cfg.startBlock + 1, {
        address: SP,
        ...gs,
        index: i,
        transactionHash: ethers.id("r7-big"),
      });
    for (let i = 0; i < 4; i++) b.c.mine();
    out.b = (await runOnce(b.c.chain, b.cfg, b.store, rs, ident)).status;
    out.bRecs = b.store.countRecords();
    out.bQ = withQ(b.store).filter(x => x.quarantine);
    // healthy txs in one block, 2105 records: records never count towards the per-block cap, so all
    // three txs are recorded and nothing is quarantined (#404 review B1)
    const e = mk();
    const ev = (n, tag) =>
      Array.from({ length: n }, (_, i) => ({
        name: "SlashCancelled",
        args: [addr(`${tag}-${i}`)],
      }));
    const t1 = e.c.ownerTx(ev(1500, "r7-t1"));
    e.c.ownerTx(ev(600, "r7-t2"), { atBlock: t1.block });
    const t3 = e.c.ownerTx(ev(5, "r7-t3"), { atBlock: t1.block });
    for (let i = 0; i < 4; i++) e.c.mine();
    out.e = (await runOnce(e.c.chain, e.cfg, e.store, rs, ident)).status;
    out.eRecs = e.store.countRecords();
    out.eQ = withQ(e.store).filter(x => x.quarantine);
    out.eT3 = readdirSync(join(e.store.dir, "records")).some(f =>
      f.includes(t3.hash.toLowerCase().slice(2))
    );
  } finally {
    for (const d of runs) rmSync(d, { recursive: true, force: true });
  }
  cell(
    "follow-up R7: 6000-deep evidence is stored as a small placeholder and retried (ticks ok, attempts count); 2100 watched logs in one tx are one quarantine; 2105 healthy records in one block are all kept (records never fill the per-block cap)",
    out.a1.ok &&
      out.a2.ok &&
      out.a3.ok &&
      out.aAtt >= 3 &&
      out.aBytes < 100_000 &&
      out.aW.length === 1 &&
      /^0x[0-9a-f]{64}$/.test(out.aW[0].rawSha256 ?? "") &&
      out.b.ok &&
      out.bRecs === 1 &&
      out.bQ.length === 1 &&
      out.bQ[0].entries === 2100 &&
      out.e.ok &&
      out.eRecs === 2105 &&
      out.eT3 &&
      out.eQ.length === 0,
    {
      a: [out.a1.ok, out.a2.ok, out.a2.lastError, out.a3.ok, out.aAtt, out.aBytes, out.aW.length],
      b: [out.b.ok, out.bRecs, out.bQ.length, out.bQ[0]?.entries],
      e: [out.e.ok, out.e.lastError, out.eRecs, out.eT3, out.eQ.length, out.eQ[0]?.entries],
    }
  );
}

// ---- follow-up #2 R8: trace flattening is linear; traces past the EVM call-depth limit are
// refused; persisted reasons are bounded
{
  const A = AGG;
  const N = 30_000;
  const big = {
    type: "CALL",
    from: addr("r8-from"),
    to: SP,
    input: "0x12345678",
    calls: Array.from({ length: N }, () => ({
      type: "CALL",
      from: SP,
      to: addr("r8-to"),
      input: "0x",
    })),
    logs: Array.from({ length: N }, (_, i) => ({
      address: SP,
      topics: [ethers.id("t")],
      data: "0x",
      position: i,
    })),
  };
  const t0 = Date.now();
  const flat = flattenTraceLogs(big, A, SP);
  const ms = Date.now() - t0;
  const chain = n => {
    let f = { type: "CALL", from: addr("r8-x"), to: addr("r8-y"), input: "0x" };
    for (let i = 1; i < n; i++)
      f = { type: "CALL", from: addr("r8-x"), to: addr("r8-y"), input: "0x", calls: [f] };
    return f;
  };
  const many = Array.from({ length: 50 }, (_, i) => `step ${i}: ` + "p".repeat(10_000));
  const br = boundReasons({ reasons: many, lastReasons: ["short"] });
  const want = createHash("sha256");
  for (const x of many) want.update(x + "\n");
  // through the store: a dead letter keeps the bound
  const d = mkdtempSync(join(tmpdir(), "guardian-watcher-reasons-"));
  let stored;
  try {
    const st = new Store(d);
    st.putDeadLetter({
      route: "tx",
      txHash: ethers.id("r8-dl"),
      blockNumber: 1,
      reasons: many,
      seenAt: "x",
    });
    stored = readFileSync(
      join(d, "deadletters", `tx-${ethers.id("r8-dl").toLowerCase()}.json`)
    ).length;
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
  cell(
    "follow-up R8: 30 000 logs beside 30 000 calls flatten in linear time; a trace of 1025 frames passes and 1026 is refused; persisted reasons keep 10 of at most 512 characters with the total and the sha256 of the full list",
    flat?.length === N &&
      ms < 3000 &&
      traceDepthOk(chain(1025)) &&
      !traceDepthOk(chain(1026)) &&
      br.reasons.length === 10 &&
      br.reasons.every(x => x.length <= 513) &&
      br.reasonsTotal === 50 &&
      br.reasonsSha256 === `0x${want.digest("hex")}` &&
      br.lastReasons.length === 1 &&
      br.lastReasonsTotal === undefined &&
      stored < 20_000,
    {
      n: flat?.length,
      ms,
      d1025: traceDepthOk(chain(1025)),
      d1026: traceDepthOk(chain(1026)),
      r: br.reasons.length,
      tot: br.reasonsTotal,
      stored,
    }
  );
}

// ---- follow-up #2 R9: a trace whose calls or logs are not arrays is refused (both validators);
// a dead-letter retry obeys the same admission limits as fresh evidence
{
  const bad = [
    { type: "CALL", calls: { length: "Infinity" } },
    { type: "CALL", calls: [{ type: "CALL", calls: { length: 5 } }] },
    { type: "CALL", logs: { length: 3 } },
  ];
  const good = { type: "CALL", calls: [{ type: "CALL", logs: [] }], logs: [] };
  const units =
    bad.every(t => !traceDepthOk(t) && !recheckDepthOk(t)) &&
    traceDepthOk(good) &&
    recheckDepthOk(good);
  const d = mkdtempSync(join(tmpdir(), "guardian-watcher-r9-"));
  const c = makeChain();
  const cfg = {
    aggregator: AGG,
    roles: { superPaymaster: SP },
    forwarders: FORWARDERS,
    startBlock: c.head() + 1,
    maxBlocksPerTick: 1000,
    page: 5000,
  };
  const store = new Store(d);
  const ident = { commit: "0".repeat(40), hash: ethers.id("ruleset"), verified: true };
  const gs = spIface.encodeEventLog("GuardianSet", [addr("r9-a"), addr("r9-b")]);
  let st, recs, q, open;
  try {
    for (let i = 0; i < 4; i++) c.mine();
    const blk = cfg.startBlock + 1;
    const h = ethers.id("r9-legacy");
    // the tick scans from after the dead letter's block, so only the retry sees these logs
    cfg.startBlock = c.head() + 1;
    for (let i = 0; i < 2501; i++)
      c.injectLog(blk, { address: SP, ...gs, index: i, transactionHash: h });
    for (let i = 0; i < 4; i++) c.mine();
    // a dead letter written without stored evidence (legacy): its retry re-reads by hash
    store.putDeadLetter({
      route: "tx",
      txHash: h,
      blockNumber: blk,
      status: "ERROR",
      reasons: ["legacy"],
      events: [],
      seenAt: "x",
    });
    st = (await runOnce(c.chain, cfg, store, rs, ident)).status;
    recs = readdirSync(join(d, "records")).filter(f => !f.startsWith("quarantine-")).length;
    q = withQ(store).filter(x => x.quarantine);
    open = store.getDeadLetter(`tx-${h.toLowerCase()}`);
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
  cell(
    "follow-up R9: traces with non-array calls/logs are refused by both validators; a legacy dead letter whose re-read returns 2501 logs is one quarantine (no record each), and resolved",
    units && st.ok && recs === 0 && q.length === 1 && q[0].entries === 2501 && open === null,
    { units, ok: st.ok, err: st.lastError, recs, q: q.length, entries: q[0]?.entries, open: !!open }
  );
}

// ---- follow-up #2 R9: receipt logs given out of order are placed by their position (no sort)
{
  const l1 = { address: SP, topics: [ethers.id("o1")], data: "0x01" };
  const l2 = { address: SP, topics: [ethers.id("o2")], data: "0x02" };
  const l3 = { address: SP, topics: [ethers.id("o3")], data: "0x03" };
  const trace = {
    type: "CALL",
    from: addr("ord-from"),
    to: SP,
    input: "0x12345678",
    logs: [l1, l2, l3],
  };
  const receipt = [
    { ...l3, index: 12 },
    { ...l1, index: 10 },
    { ...l2, index: 11 },
  ];
  const r = attributeLogs(trace, receipt, AGG, SP);
  const swapped = attributeLogs(
    trace,
    [
      { ...l2, index: 10 },
      { ...l1, index: 11 },
      { ...l3, index: 12 },
    ],
    AGG,
    SP
  );
  cell(
    "follow-up R9: receipt logs out of order align by their positions; logs at swapped positions do not",
    r.aligned &&
      [10, 11, 12].every(p => r.spCall.get(p)?.from === addr("ord-from")) &&
      !swapped.aligned,
    { aligned: r.aligned, why: r.why, swapped: swapped.aligned }
  );
}

// ---- follow-up #2 R10: evidence carrying the encoder's own tag keys round-trips exactly;
// retirements are numbered by a durable counter; the rechecker appends without spreads
{
  const tag = v =>
    JSON.stringify(v, (k, x) => (typeof x === "bigint" ? { "#bigint": x.toString() } : x));
  const samples = [
    { data: { $obj: 0, nested: { $obj: { lost: "original wrapper" } } } },
    { data: { $obj: 1, inner: { $bigint: "5" } } },
    { $bigint: "7" },
    { $obj: { $obj: { $bigint: "9" } } },
    { n: 5n, m: { $bigint: "5" }, k: [{ $obj: 2 }, 3n] },
  ];
  // twice through storage: what a retry does
  const round = v => nativeEvidence(typedEvidence(nativeEvidence(typedEvidence([v]))))[0];
  const rt = samples.map(v => tag(round(v)) === tag(v));
  // retirements: five of one id are five files; a lost counter is rebuilt
  const d = mkdtempSync(join(tmpdir(), "guardian-watcher-retire-"));
  const id = `tx-${ethers.id("rt").toLowerCase()}`;
  let names;
  try {
    const st = new Store(d);
    const put = () =>
      st.putDeadLetter({
        route: "tx",
        txHash: ethers.id("rt"),
        blockNumber: 1,
        reasons: ["x"],
        seenAt: "x",
      });
    for (let i = 0; i < 3; i++) {
      put();
      st.retireDeadLetter(id);
    }
    rmSync(join(d, "deadletters", `${id}.json.exhausted-next`));
    for (let i = 0; i < 2; i++) {
      put();
      st.retireDeadLetter(id);
    }
    names = readdirSync(join(d, "deadletters"))
      .filter(f => /\.exhausted(\.\d+)?$/.test(f))
      .sort();
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
  const base = `${id}.json`;
  const want = [
    `${base}.exhausted`,
    `${base}.exhausted.2`,
    `${base}.exhausted.3`,
    `${base}.exhausted.4`,
    `${base}.exhausted.5`,
  ].sort();
  // the rechecker: 150 000 logs in one page
  const many = Array.from({ length: 150_000 }, (_, i) => ({ i }));
  let found, err;
  try {
    found = await findEntryLogs({ getLogs: async () => many }, addr("reg"), 1n, 1, 1);
  } catch (e) {
    err = e.message;
  }
  cell(
    "follow-up R10: evidence with nested $obj/$bigint keys round-trips exactly through storage twice; five retirements of one id are five numbered files (a lost counter is rebuilt); the rechecker takes 150 000 logs of one page without a spread",
    rt.every(Boolean) && j(names) === j(want) && found?.length === 150_000,
    { rt, names, err, n: found?.length }
  );
}

// ---- follow-up #2 R11: huge shallow evidence is a small placeholder; a __proto__ key never fakes
// log fields; malformed strings keep their case; falsy fields are kept; sampling is bounded
{
  const runs = [];
  const mk = () => {
    const d = mkdtempSync(join(tmpdir(), "guardian-watcher-r11-"));
    runs.push(d);
    const c = makeChain();
    const cfg = {
      aggregator: AGG,
      roles: { superPaymaster: SP },
      forwarders: FORWARDERS,
      startBlock: c.head() + 1,
      maxBlocksPerTick: 1000,
      page: 5000,
    };
    return { c, cfg, store: new Store(d), d };
  };
  const ident = { commit: "0".repeat(40), hash: ethers.id("ruleset"), verified: true };
  const gs = spIface.encodeEventLog("GuardianSet", [addr("r11-a"), addr("r11-b")]);
  const out = {};
  try {
    // (a) a 1 000 000-character data value
    const a = mk();
    for (let i = 0; i < 4; i++) a.c.mine();
    const ha = ethers.id("r11-big");
    a.c.injectRawResult(SP, {
      address: SP,
      ...gs,
      data: "z".repeat(1_000_000),
      blockNumber: a.cfg.startBlock,
      index: 0,
      transactionHash: ha,
    });
    await runOnce(a.c.chain, a.cfg, a.store, rs, ident);
    out.aBytes = readFileSync(join(a.d, "deadletters", `tx-${ha.toLowerCase()}.json`)).length;
    out.aW = a.store.getDeadLetter(`tx-${ha.toLowerCase()}`)?.watched ?? [];
    // (b) a log whose fields sit under an own __proto__ key, next to a reserved key
    const b = mk();
    for (let i = 0; i < 4; i++) b.c.mine();
    const hb = ethers.id("r11-proto");
    b.c.injectRawResult(
      SP,
      JSON.parse(
        JSON.stringify({
          source: "agg",
          transactionHash: hb,
          blockNumber: b.cfg.startBlock,
          index: 0,
        }).replace(/^\{/, `{"__proto__":${JSON.stringify({ address: SP, ...gs })},`)
      )
    );
    out.b = (await runOnce(b.c.chain, b.cfg, b.store, rs, ident)).status;
    out.bRecs = b.store.countRecords();
    out.bDl = !!b.store.getDeadLetter(`tx-${hb.toLowerCase()}`);
    // nothing inherited reaches the evidence: the stored observation has no address or topics
    out.bW = b.store.getDeadLetter(`tx-${hb.toLowerCase()}`)?.watched ?? [];
    // (c) two observations differing only in the case of a malformed string
    const c3 = mk();
    for (let i = 0; i < 4; i++) c3.c.mine();
    const hc = ethers.id("r11-case");
    // ...and an explicit null is kept as received
    c3.c.injectRawResult(SP, {
      address: SP,
      ...gs,
      data: "0x",
      logIndex: null,
      blockNumber: c3.cfg.startBlock,
      index: 1,
      transactionHash: hc,
    });
    for (const data of ["BAD", "bad"])
      c3.c.injectRawResult(SP, {
        address: SP,
        ...gs,
        data,
        blockNumber: c3.cfg.startBlock,
        index: 0,
        transactionHash: hc,
      });
    await runOnce(c3.c.chain, c3.cfg, c3.store, rs, ident);
    const cAll = c3.store.getDeadLetter(`tx-${hc.toLowerCase()}`)?.watched ?? [];
    out.cW = cAll.map(w => w.data).filter(x => x !== "0x");
    out.cNull = cAll.some(
      w => w.data === "0x" && Object.hasOwn(w, "logIndex") && w.logIndex === null
    );
    // (d) a real tx whose getLogs copy says blockHash: false: kept as received, never a record
    const e = mk();
    const k = e.c.ownerTx([{ name: "SlashCancelled", args: [addr("r11-op")] }]);
    for (let i = 0; i < 4; i++) e.c.mine();
    e.c.patchLogs(k.hash, { blockHash: false });
    for (let i = 0; i < 3; i++) await runOnce(e.c.chain, e.cfg, e.store, rs, ident);
    out.eW = e.store.getDeadLetter(`tx-${k.hash.toLowerCase()}`)?.watched ?? [];
    out.eRecs = e.store.countRecords();
  } finally {
    for (const d of runs) rmSync(d, { recursive: true, force: true });
  }
  // (e) trace sampling: a block listing 20 000 transactions whose receipts are null
  let lookups = 0;
  const fake = {
    send: async m =>
      m === "eth_getBlockByNumber"
        ? {
            hash: ethers.id("blk"),
            transactions: Array.from({ length: 20_000 }, (_, i) => ethers.id(`s-${i}`)),
          }
        : null,
    getTransactionReceipt: async () => {
      lookups++;
      return null;
    },
  };
  const v = await verifyTrace(fake, { aggregator: AGG, roles: { superPaymaster: SP } }, 100);
  cell(
    "follow-up R11: a 1 MB data value is a small placeholder; fields under a __proto__ key are not log fields (no record); 'BAD' and 'bad' stay two observations; blockHash: false is kept and never becomes a record; trace sampling looks at a bounded number of receipts",
    out.aBytes < 100_000 &&
      out.aW[0]?.rawLength > 1_000_000 &&
      /^0x[0-9a-f]{64}$/.test(out.aW[0]?.rawSha256 ?? "") &&
      out.b.ok &&
      out.bRecs === 0 &&
      out.bDl &&
      out.bW.length === 1 &&
      out.bW[0].address === undefined &&
      out.bW[0].topics === undefined &&
      out.cNull &&
      out.cW.length === 2 &&
      out.cW.includes("BAD") &&
      out.cW.includes("bad") &&
      out.eW.some(w => w.blockHash === false) &&
      out.eRecs === 0 &&
      v.state === "unverified" &&
      lookups <= 200,
    {
      aBytes: out.aBytes,
      aLen: out.aW[0]?.rawLength,
      b: [out.b.ok, out.bRecs, out.bDl, out.bW],
      cNull: out.cNull,
      c: out.cW,
      e: [out.eW.map(w => w.blockHash), out.eRecs],
      v: v.state,
      lookups,
    }
  );
}

// ---- DSR 97a9d55c: status reports the tick's duration and the archive size; a tick slower than
// maxTickFraction of the interval is degraded
{
  const d = mkdtempSync(join(tmpdir(), "guardian-watcher-timing-"));
  const c = makeChain();
  const base = {
    aggregator: AGG,
    roles: { superPaymaster: SP },
    forwarders: FORWARDERS,
    startBlock: c.head() + 1,
    maxBlocksPerTick: 1000,
    page: 5000,
  };
  const ident = { commit: "0".repeat(40), hash: ethers.id("ruleset"), verified: true };
  let fast, slow;
  try {
    c.ownerTx([{ name: "SlashCancelled", args: [addr("tm-op")] }]);
    for (let i = 0; i < 4; i++) c.mine();
    const store = new Store(d);
    fast = (await runOnce(c.chain, { ...base, intervalMs: 600_000 }, store, rs, ident)).status;
    // capability verification made slow (20 ms per receipt): the tick time must include it
    const slowChain = Object.create(c.chain);
    slowChain.getTransactionReceipt = async h => {
      await new Promise(r => setTimeout(r, 20));
      return c.chain.getTransactionReceipt(h);
    };
    // a fresh store, so capability verification runs (no stored proof yet)
    const d2 = mkdtempSync(join(tmpdir(), "guardian-watcher-timing2-"));
    try {
      // scanning starts after the owner tx: only the capability check (which samples recent
      // blocks) reads a receipt, so the slowness can come from finish() alone
      const cfgSlow = { ...base, startBlock: c.head() + 1, intervalMs: 20 };
      slow = (await runOnce(slowChain, cfgSlow, new Store(d2), rs, ident)).status;
    } finally {
      rmSync(d2, { recursive: true, force: true });
    }
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
  cell(
    "status reports tickMs and archiveFiles; a tick slower than maxTickFraction of the interval is degraded",
    Number.isFinite(fast.tickMs) &&
      fast.archiveFiles >= 1 &&
      !(fast.degraded ?? []).some(r => /tick took/.test(r)) &&
      (slow.degraded ?? []).some(r => /tick took \d+ ms, more than 10 ms/.test(r)) &&
      slow.tickMs >= 20 &&
      slow.healthy === false,
    { fast: [fast.tickMs, fast.archiveFiles, fast.degraded], slow: [slow.tickMs, slow.degraded] }
  );
}

// ---- follow-up #2 R12: a missing field and an explicit null are two observations, through
// retries; evidence size is measured as encoded bytes
{
  const d = mkdtempSync(join(tmpdir(), "guardian-watcher-r12-"));
  const c = makeChain();
  const cfg = {
    aggregator: AGG,
    roles: { superPaymaster: SP },
    forwarders: FORWARDERS,
    startBlock: c.head() + 1,
    maxBlocksPerTick: 1000,
    page: 5000,
  };
  const store = new Store(d);
  const ident = { commit: "0".repeat(40), hash: ethers.id("ruleset"), verified: true };
  const gs = spIface.encodeEventLog("GuardianSet", [addr("r12-a"), addr("r12-b")]);
  const h = ethers.id("r12-null");
  const hn = ethers.id("r12-nul");
  let w1, w3, nul;
  try {
    for (let i = 0; i < 4; i++) c.mine();
    const { data, ...noData } = {
      address: SP,
      ...gs,
      blockNumber: cfg.startBlock,
      index: 0,
      transactionHash: h,
    };
    void data;
    c.injectRawResult(SP, noData);
    c.injectRawResult(SP, { ...noData, data: null });
    // 20 000 NUL characters: 20 000 characters, but 120 000 bytes of JSON
    c.injectRawResult(SP, {
      address: SP,
      ...gs,
      data: "\u0000".repeat(20_000),
      blockNumber: cfg.startBlock,
      index: 1,
      transactionHash: hn,
    });
    await runOnce(c.chain, cfg, store, rs, ident);
    w1 = store.getDeadLetter(`tx-${h.toLowerCase()}`)?.watched ?? [];
    for (let i = 0; i < 2; i++) await runOnce(c.chain, cfg, store, rs, ident);
    w3 = store.getDeadLetter(`tx-${h.toLowerCase()}`)?.watched ?? [];
    nul = store.getDeadLetter(`tx-${hn.toLowerCase()}`)?.watched ?? [];
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
  cell(
    "follow-up R12: a log missing `data` and one with data: null are two stored observations, unchanged by retries; 20 000 NUL characters (120 KB of JSON) are a placeholder",
    w1.length === 2 &&
      w1.some(w => Object.hasOwn(w, "data") && w.data === null) &&
      w1.some(w => !Object.hasOwn(w, "data")) &&
      JSON.stringify(w3) === JSON.stringify(w1) &&
      nul.length === 1 &&
      /^0x[0-9a-f]{64}$/.test(nul[0].rawSha256 ?? ""),
    { n1: w1.length, w1, n3: w3.length, nul: nul.map(x => [x.raw?.slice?.(0, 20), x.rawLength]) }
  );
}

// ---- config: maxLagBlocks / maxTickFraction are validated; a non-array eth_getLogs answer fails
// the tick (cursor unchanged), never treated as an empty range
{
  const d = mkdtempSync(join(tmpdir(), "guardian-watcher-cfg-"));
  const p = join(d, "c.json");
  const baseCfg = { aggregator: AGG, dataDir: d, startBlock: 1, roles: { superPaymaster: SP } };
  const tryCfg = extra => {
    writeFileSync(p, JSON.stringify({ ...baseCfg, ...extra }));
    try {
      return loadConfig(p);
    } catch (e) {
      return { error: e.message };
    }
  };
  const ok = tryCfg({});
  const bads = [
    { maxLagBlocks: 0 },
    { maxLagBlocks: 1.5 },
    { maxTickFraction: 0 },
    { maxTickFraction: "0.5" },
    { maxTickFraction: 11 },
  ].map(tryCfg);
  const good = tryCfg({ maxLagBlocks: 10, maxTickFraction: 0.25 });
  // a node answering eth_getLogs with an object, not an array
  const c = makeChain();
  const cfg = {
    aggregator: AGG,
    roles: { superPaymaster: SP },
    forwarders: FORWARDERS,
    startBlock: c.head() + 1,
    maxBlocksPerTick: 1000,
    page: 5000,
  };
  for (let i = 0; i < 4; i++) c.mine();
  const odd = Object.create(c.chain);
  odd.send = async (m, params) => (m === "eth_getLogs" ? { length: 0 } : c.chain.send(m, params));
  const store = new Store(join(d, "s"));
  const ident = { commit: "0".repeat(40), hash: ethers.id("ruleset"), verified: true };
  const st = (await runOnce(odd, cfg, store, rs, ident)).status;
  const cur = store.getCursor();
  rmSync(d, { recursive: true, force: true });
  cell(
    "config: maxLagBlocks and maxTickFraction are validated (defaults 300 and 0.5); a non-array eth_getLogs answer fails the tick and leaves the cursor unset",
    !ok.error &&
      ok.maxLagBlocks === 300 &&
      ok.maxTickFraction === 0.5 &&
      bads.every(b => /config: (maxLagBlocks|maxTickFraction)/.test(b.error ?? "")) &&
      good.maxLagBlocks === 10 &&
      good.maxTickFraction === 0.25 &&
      st.ok === false &&
      /not an array/.test(st.lastError ?? "") &&
      cur === null,
    { ok, bads, good: [good.maxLagBlocks, good.maxTickFraction], st: [st.ok, st.lastError], cur }
  );
}

// ---- #404 review B1: healthy records never crowd a later owner action of the same block into
// quarantine (the per-block cap counts isolations, not records)
{
  const d = mkdtempSync(join(tmpdir(), "guardian-watcher-b1-"));
  const c = makeChain();
  const cfg = {
    aggregator: AGG,
    roles: { superPaymaster: SP },
    forwarders: FORWARDERS,
    startBlock: c.head() + 1,
    maxBlocksPerTick: 1000,
    page: 5000,
  };
  const store = new Store(d);
  const ident = { commit: "0".repeat(40), hash: ethers.id("ruleset"), verified: true };
  const s4 = x => ethers.id(x).slice(0, 10);
  let st,
    owner,
    q,
    pub,
    ownerAtCursor = false,
    cursorAt = null,
    ownerBlock = null;
  try {
    // tx A: anyone calls updatePrice() emitting 2000 PriceUpdated (2000 public records)
    const a = c.ownerTx(
      Array.from({ length: 2000 }, (_, i) => ({
        name: "PriceUpdated",
        args: [250000000000n + BigInt(i), BigInt(i)],
      })),
      { from: addr("b1-attacker"), data: s4("updatePrice()"), price: 250000000000n }
    );
    // tx B: the Safe's GuardianSet in the same block, after A
    const b = c.ownerTx([{ name: "GuardianSet", args: [addr("b1-g0"), addr("b1-g1")] }], {
      atBlock: a.block,
    });
    for (let i = 0; i < 4; i++) c.mine();
    // when the cursor is written, the owner record must already be on disk (DSR 41120e87)
    const setCursor = store.setCursor.bind(store);
    store.setCursor = cur => {
      ownerAtCursor = readdirSync(join(d, "records")).some(f => {
        const r = JSON.parse(readFileSync(join(d, "records", f), "utf8"));
        return r.txHash === b.hash && r.event === "GuardianSet";
      });
      cursorAt = cur.block;
      return setCursor(cur);
    };
    st = (await runOnce(c.chain, cfg, store, rs, ident)).status;
    const recs = readdirSync(join(d, "records")).map(f =>
      JSON.parse(readFileSync(join(d, "records", f), "utf8"))
    );
    owner = recs.find(r => r.txHash === b.hash && r.event === "GuardianSet");
    pub = recs.filter(r => r.txHash === a.hash).length;
    q = recs.filter(r => r.quarantine).length;
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
  cell(
    "#404 B1: 2000 public PriceUpdated records then an owner GuardianSet last in the same block: the owner action is a full owner-route record, already on disk when the cursor moves past its block; nothing quarantined",
    st.ok &&
      pub === 2000 &&
      owner?.route === "owner" &&
      q === 0 &&
      ownerAtCursor &&
      cursorAt >= ownerBlock,
    {
      ok: st.ok,
      err: st.lastError,
      pub,
      owner: owner && [owner.route, owner.event],
      q,
      ownerAtCursor,
      cursorAt,
      ownerBlock,
    }
  );
}

// ---- #404 review L2-L4: renames and writes fsync their directory; a corrupt conflict file is kept
// as .invalid; tx facts are first-write-wins
{
  const d = mkdtempSync(join(tmpdir(), "guardian-watcher-l2-"));
  const synced = [];
  const spy = dir => synced.push(dir);
  let l4, l4files;
  try {
    writeFileSync(join(d, "a"), "x");
    renameDurable(join(d, "a"), join(d, "b"), spy);
    atomicWriteJson(join(d, "c.json"), { v: 1 }, writeSync, spy);
    // L4: a conflict file with garbage at the address of a new conflicting proof
    const st = new Store(join(d, "s"));
    const k = 77n;
    const am = (tx, ev) => ({
      key: k.toString(),
      txHash: tx,
      provenBy: "trace",
      provenAt: "t",
      spEvents: [{ event: ev, logIndex: 1, args: [] }],
      ruleset: { commit: "0".repeat(40) },
    });
    st.putBlsAmendment(k, am(ethers.id("l4-a"), "SlashQueued"));
    const other = am(ethers.id("l4-b"), "SlashCancelled");
    const first = st.putBlsAmendment(k, other);
    const dir = join(d, "s", "amendments");
    const cfile = readdirSync(dir).find(f => /\.conflict\.[0-9a-f]{64}$/.test(f));
    writeFileSync(join(dir, cfile), "{ garbage");
    l4 = [first, st.putBlsAmendment(k, other)];
    l4files = readdirSync(dir).sort();
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
  cell(
    "#404 L2/L4: renameDurable and atomicWriteJson fsync the target directory; a corrupt conflict file is kept as .invalid.1 and the proof rewritten",
    synced.length === 2 &&
      synced.every(x => x === d) &&
      j(l4) === j(["conflict", "conflict"]) &&
      l4files.some(f => /\.conflict\.[0-9a-f]{64}\.invalid\.1$/.test(f)) &&
      l4files.some(f => /\.conflict\.[0-9a-f]{64}$/.test(f)),
    { synced, l4, l4files }
  );
}

// ---- #404 review Info: a log in the raw JSON-RPC shape a production node returns (hex logIndex and
// blockNumber, no `index`, lower-case address) goes all the way to a record
{
  const d = mkdtempSync(join(tmpdir(), "guardian-watcher-rawshape-"));
  const c = makeChain();
  const cfg = {
    aggregator: AGG,
    roles: { superPaymaster: SP },
    forwarders: FORWARDERS,
    startBlock: c.head() + 1,
    maxBlocksPerTick: 1000,
    page: 5000,
  };
  const ident = { commit: "0".repeat(40), hash: ethers.id("ruleset"), verified: true };
  const toRaw = l => ({
    address: String(l.address).toLowerCase(),
    topics: l.topics,
    data: l.data,
    blockNumber: ethers.toQuantity(l.blockNumber),
    blockHash: l.blockHash,
    transactionHash: l.transactionHash,
    transactionIndex: "0x0",
    logIndex: ethers.toQuantity(l.index ?? l.logIndex),
    removed: false,
  });
  const raw = Object.create(c.chain);
  let shaped = 0;
  raw.send = async (m, params) => {
    const r = await c.chain.send(m, params);
    if (m !== "eth_getLogs" || !Array.isArray(r)) return r;
    shaped += r.length;
    return r.map(toRaw);
  };
  let st, rec;
  try {
    const t = c.ownerTx([{ name: "GuardianSet", args: [addr("raw-g0"), addr("raw-g1")] }]);
    for (let i = 0; i < 4; i++) c.mine();
    st = (await runOnce(raw, cfg, new Store(d), rs, ident)).status;
    rec = readdirSync(join(d, "records"))
      .map(f => JSON.parse(readFileSync(join(d, "records", f), "utf8")))
      .find(r => r.txHash === t.hash);
  } finally {
    rmSync(d, { recursive: true, force: true });
  }
  cell(
    "#404 Info: a raw JSON-RPC-shaped log (hex logIndex/blockNumber, no index, lower-case address) is recorded on the owner route with no isolation",
    shaped > 0 &&
      st.ok &&
      rec?.route === "owner" &&
      rec.event === "GuardianSet" &&
      !st.isolatedThisTick,
    {
      shaped,
      ok: st.ok,
      err: st.lastError,
      iso: st.isolatedThisTick,
      rec: rec && [rec.route, rec.event],
    }
  );
}

// ---- DSR: no provider URL / key / foreign error text in anything the watcher writes. Every RPC
// method throws, at some point, an error whose message, shortMessage, info and url carry a
// sentinel key; malformed items trigger the isolation reasons; then every file under the data dir
// (dead letters, records, amendments, status.json, cursor) and every returned status is searched.
{
  const SENT = "SENTINELKEY9f3a";
  const URL = `https://eth-sepolia.example.io/v2/${SENT}`;
  const leakErr = () =>
    Object.assign(new Error(`request to ${URL} failed: ${SENT}`), {
      shortMessage: `bad response ${SENT}`,
      info: { error: { message: `upstream ${URL}` }, requestUrl: URL },
      url: URL,
      code: "SERVER_ERROR",
    });
  const dS = mkdtempSync(join(tmpdir(), "guardian-watcher-sentinel-"));
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
    const store = new Store(dS);
    const ident = { commit: "0".repeat(40), hash: ethers.id("ruleset"), verified: true };
    const KEEP = addr("sent-keeper");
    const pauseSel = ethers.id("pauseUnderstakedOperator(address)").slice(0, 10);
    // traffic: a traced public tx, a BLS action, a price-reading generic action, an owner event
    const tPub = c.ownerTx([{ name: "OperatorPaused", args: [addr("sent-op")] }], {
      from: KEEP,
      data: pauseSel,
    });
    const tBls = c.execute(Kind.SLASH, 9191n, slashF, 0b011n);
    const priceG = {
      target: SP,
      callData: spIface.encodeFunctionData("updatePriceDVT", [262000000000n, 21n, "0x", 0]),
      requiredThreshold: 2n,
    };
    const tGen = c.execute(Kind.GENERIC, 9292n, priceG, 0b111n, { price: 262000000000n });
    const tOwn = c.ownerTx([{ name: "GuardianSet", args: [addr("sent-g1"), addr("sent-g2")] }]);
    // malformed items for the isolation reasons
    const quiet = c.ownerTx([]);
    const quiet2 = c.ownerTx([]);
    for (let i = 0; i < 4; i++) c.mine();
    const rq = await c.chain.getTransactionReceipt(quiet.hash);
    const rq2 = await c.chain.getTransactionReceipt(quiet2.hash);
    const gs = spIface.encodeEventLog("GuardianSet", [addr("sent-a"), addr("sent-b")]);
    // a chain whose methods throw sentinel-carrying errors on chosen calls
    // log reads (raw eth_getLogs) have their own cell below; here the other methods fail, so the
    // malformed answers are read on a tick that is not itself failed
    const plan = {
      getTransaction: new Set([2, 3]),
      getTransactionReceipt: new Set([2, 5]),
      call: new Set([1, 2]),
      send: new Set([4, 9, 15]),
    };
    const counts = {};
    const leaky = new Proxy(c.chain, {
      get(t, p) {
        const v = t[p];
        if (typeof v !== "function") return v;
        return async (...a) => {
          if (p === "send" && a[0] === "eth_getLogs") {
            const r = await v.apply(t, a);
            // a node that keeps answering the malformed entries (not once): every range read of
            // the SP from tick 2 on carries them, so they are processed whatever tick succeeds
            const q = a[1]?.[0];
            if (
              junkOn &&
              Array.isArray(r) &&
              !q?.blockHash &&
              String(q?.address).toLowerCase() === SP.toLowerCase()
            )
              for (const x of malformed()) r.push(x);
            return r;
          }
          counts[p] = (counts[p] ?? 0) + 1;
          if (plan[p]?.has(counts[p])) throw leakErr();
          if (
            p === "send" &&
            a[0] === "debug_traceTransaction" &&
            (counts.trace = (counts.trace ?? 0) + 1) % 2
          )
            throw leakErr();
          return v.apply(t, a);
        };
      },
    });
    const statuses = [];
    // the malformed items are answered from the first tick past the planned failures (the stub
    // hands an injected answer out once; a real RPC would repeat it)
    let junkOn = false;
    const malformed = () => [
      null,
      {
        address: SP,
        ...gs,
        blockNumber: rq2.blockNumber,
        blockHash: rq2.blockHash,
        index: "bad",
        transactionHash: quiet2.hash,
      },
      {
        address: addr("sent-other"),
        ...gs,
        blockNumber: rq.blockNumber,
        blockHash: rq.blockHash,
        index: 0,
        transactionHash: quiet.hash,
      },
    ];
    // a foreign error thrown from inside the per-tx processing (here a store write) reaches the
    // isolation handler itself: its text must not be kept either
    const realPut = store.putRecord.bind(store);
    let putFails = 0;
    store.putRecord = r => {
      if (putFails-- > 0) throw leakErr();
      return realPut(r);
    };
    for (let i = 0; i < MAX_DEADLETTER_ATTEMPTS + 3; i++) {
      if (i === 2) junkOn = true;
      if (i === 2) putFails = 1;
      statuses.push((await runOnce(leaky, cfg, store, rs, ident)).status);
    }
    store.putRecord = realPut;
    const files = [];
    const walk = p => {
      for (const n of readdirSync(p, { withFileTypes: true })) {
        const q = join(p, n.name);
        if (n.isDirectory()) walk(q);
        else files.push(q);
      }
    };
    walk(dS);
    const leaks = files.filter(
      f =>
        readFileSync(f, "utf8").includes(SENT) ||
        readFileSync(f, "utf8").match(/eth-sepolia\.example\.io/) !== null
    );
    const statusLeak = statuses.some(st => JSON.stringify(st).includes(SENT));
    // isolation reasons and external-error categories, wherever they ended (open, exhausted, records)
    const all = files.map(f => readFileSync(f, "utf8")).join("\n");
    const reasons = new Set(all.match(/tx processing failed[^"]*/g) ?? []);
    cell(
      "DSR: no provider URL, key or foreign error text in dead letters, records, amendments, status or any written file (every RPC method throws a sentinel; isolation reasons triggered)",
      leaks.length === 0 &&
        !statusLeak &&
        statuses.some(st => st.ok === false) &&
        files.length > 5 &&
        reasons.size >= 2 &&
        /UNREADABLE/.test(all),
      {
        leaks,
        statusLeak,
        files: files.map(f => f.slice(dS.length)),
        dlReasons: files
          .filter(f => f.includes("deadletters"))
          .map(f => JSON.parse(readFileSync(f, "utf8")).reasons ?? null),
        counts,
        st: statuses.slice(0, 4).map(x => [x.ok, x.lastError, x.isolatedThisTick, x.scanned]),
        quiet: quiet.hash.slice(0, 10),
      }
    );
    void tPub;
    void tBls;
    void tGen;
    void tOwn;
  } finally {
    rmSync(dS, { recursive: true, force: true });
  }
}

// ---- DSR 6b775ed0: a log read that keeps failing (raw eth_getLogs, through the one-block retry)
// fails the tick with the stage named and the foreign text dropped, in the returned status AND in
// status.json on disk; the cursor does not move. Run for the aggregator and the SP read separately.
{
  const SENT = "SENTINELKEY7c1d";
  const URL = `https://eth-sepolia.example.io/v2/${SENT}`;
  const leakErr = () =>
    Object.assign(new Error(`request to ${URL} failed: ${SENT}`), {
      shortMessage: `bad response ${SENT}`,
      info: { error: { message: `upstream ${URL}` }, requestUrl: URL },
      url: URL,
      code: "SERVER_ERROR",
    });
  const out = {};
  for (const [label, target] of [
    ["aggregator log read", AGG],
    ["superpaymaster log read", SP],
  ]) {
    const d = mkdtempSync(join(tmpdir(), "guardian-watcher-logread-"));
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
      c.ownerTx([{ name: "GuardianSet", args: [addr("lr-a"), addr("lr-b")] }]);
      for (let i = 0; i < 6; i++) c.mine();
      let reads = 0;
      const leaky = Object.create(c.chain);
      leaky.send = async (m, params) => {
        if (
          m === "eth_getLogs" &&
          String(params?.[0]?.address).toLowerCase() === target.toLowerCase()
        ) {
          reads++;
          throw leakErr();
        }
        return c.chain.send(m, params);
      };
      const store = new Store(d);
      const st = (
        await runOnce(leaky, cfg, store, rs, {
          commit: "0".repeat(40),
          hash: ethers.id("r"),
          verified: true,
        })
      ).status;
      const disk = readFileSync(join(d, "status.json"), "utf8");
      out[label] = {
        ok: st.ok,
        lastError: st.lastError,
        disk: JSON.parse(disk).lastError,
        reads,
        cursor: store.getCursor(),
        leak:
          JSON.stringify(st).includes(SENT) ||
          disk.includes(SENT) ||
          disk.match(/eth-sepolia\.example\.io/) !== null,
      };
    } finally {
      rmSync(d, { recursive: true, force: true });
    }
  }
  const okFor = label => {
    const o = out[label];
    return (
      o.ok === false &&
      o.lastError === `${label}: SERVER_ERROR` &&
      o.disk === o.lastError &&
      o.reads > 1 && // the paged read halved down to one block before giving up
      o.cursor === null &&
      o.leak === false
    );
  };
  cell(
    "DSR: a persistently failing aggregator / SP log read fails the tick with only '<stage>: SERVER_ERROR', in the returned status and status.json, no sentinel text, cursor unmoved",
    okFor("aggregator log read") && okFor("superpaymaster log read"),
    out
  );
}

// ---- durable writes: a short write is completed, zero progress refused (Codex W2c R2)
{
  const got = [];
  const short = (fd, b, off, len) => {
    const n = Math.min(3, len);
    got.push(...b.subarray(off, off + n));
    return n;
  };
  const buf = Buffer.from("0123456789abcdef");
  writeAll(0, buf, short);
  let refused = null;
  try {
    writeAll(0, buf, () => 0);
  } catch (e) {
    refused = e.message;
  }
  cell(
    "writeAll: completes short writes byte for byte, refuses zero progress",
    Buffer.from(got).equals(buf) && /short write: 0 of 16/.test(refused ?? ""),
    { got: Buffer.from(got).toString(), refused }
  );
}

// ---- store: dead letters keep established evidence; only an authenticated record counts as done
{
  const d4 = mkdtempSync(join(tmpdir(), "guardian-watcher-store-"));
  try {
    const s = new Store(d4);
    const h = ethers.id("store-unit");
    const base = { txHash: h, blockNumber: 1, seenAt: "t0" };
    s.putDeadLetter({
      ...base,
      route: "tx",
      status: "ERROR",
      reasons: ["price read failed"],
      events: [],
      pendingRecords: [{ route: "public", txHash: h, logIndex: 0, priceMissing: true }],
    });
    s.putDeadLetter({
      ...base,
      route: "tx",
      status: "ERROR",
      reasons: ["transaction unavailable"],
      events: [],
    });
    const t = s.getDeadLetter(`tx-${h.toLowerCase()}`);
    s.putDeadLetter({
      ...base,
      route: "bls",
      key: "5",
      status: "PRICE_UNAVAILABLE",
      reasons: ["price read failed"],
      pendingRecord: { route: "bls", kind: "GENERIC", key: "5" },
    });
    s.putDeadLetter({
      ...base,
      route: "bls",
      key: "5",
      status: "ERROR",
      reasons: ["transaction unavailable"],
    });
    const b = s.getDeadLetter(Store.recordId({ route: "bls", key: "5" }));
    cell(
      "a dead letter keeps established evidence across a weaker later failure (pendingRecords; pendingRecord + status)",
      t?.pendingRecords?.length === 1 &&
        t.reasons[0] === "transaction unavailable" &&
        t.attempts === 2 &&
        b?.pendingRecord?.kind === "GENERIC" &&
        b.status === "PRICE_UNAVAILABLE" &&
        b.attempts === 2,
      { t, b }
    );
    s.putRecord({ ...base, route: "bls", key: "6", kind: undefined });
    const unrec = s.hasBlsRecord(6n);
    writeFileSync(
      join(d4, "records", `${Store.recordId({ route: "bls", kind: "SLASH", key: "7" })}.json`),
      "{not json"
    );
    const corrupt = s.hasBlsRecord(7n);
    s.putRecord({ ...base, route: "bls", key: "8", kind: "SLASH" });
    const real = s.hasBlsRecord(8n);
    cell(
      "hasBlsRecord: only a parseable authenticated record counts (not UNRECOVERED, not corrupt)",
      !unrec && !corrupt && real,
      { unrec, corrupt, real }
    );
  } finally {
    rmSync(d4, { recursive: true, force: true });
  }
}

// ---- matchGeneric needs target AND selector; callsWithCommit filters effect attribution; bloom unit
{
  const e = matchGeneric(rs, { superPaymaster: SP }, SP, ethers.id("updatePrice()").slice(0, 10));
  const ok = matchGeneric(
    rs,
    { superPaymaster: SP },
    SP,
    spIface.encodeFunctionData("updatePriceDVT", [1n, 1n, "0x", 0])
  );
  cell(
    "matchGeneric: right target, wrong selector is NOT the expected entry; right selector is",
    e === null && ok?.signature === "updatePriceDVT(int256,uint256,bytes,uint8)",
    { e, ok }
  );
  const pz = spIface.encodeEventLog("OperatorPaused", [addr("x")]);
  const sc = aggIface.encodeEventLog("SignersCommitted", [1n, 3n]);
  const trace = {
    type: "CALL",
    to: SAFE,
    calls: [
      { type: "CALL", to: AGG, logs: [{ address: AGG, ...sc, position: 0 }] },
      // a second aggregator call WITHOUT a commitment emits the SP event: not an action's effect
      {
        type: "CALL",
        to: AGG,
        calls: [
          { type: "CALL", from: AGG, to: SP, input: "0x12345678", logs: [{ address: SP, ...pz }] },
        ],
      },
    ],
  };
  const a = attributeLogs(
    trace,
    [
      { address: AGG, ...sc, index: 0 },
      { address: SP, ...pz, index: 1 },
    ],
    AGG,
    SP
  );
  cell(
    "attribution: an SP log inside an aggregator call that has no commitment belongs to that call, not the committed one",
    a.aligned && a.owner.get(0) === 0 && a.owner.get(1) === 1 && a.spCall.get(1)?.from === AGG,
    { owner: [...a.owner], sp: [...a.spCall] }
  );
  const bl = bloomOf([{ address: SP, topics: [pz.topics[0]] }]);
  cell(
    "bloom: present (address, topic) is 'may', absent topic is 'no', unreadable is null",
    mayHaveLog(bl, SP, [pz.topics[0]]) === true &&
      mayHaveLog(bl, SP, [spIface.getEvent("GuardianSet").topicHash]) === false &&
      mayHaveLog(undefined, SP, [pz.topics[0]]) === null,
    null
  );
}

let failed = 0;
for (const r of results) {
  console.log(`${r.ok ? "ok  " : "FAIL"} ${r.name}${r.ok ? "" : `\n     got ${r.got}`}`);
  if (!r.ok) failed++;
}
console.log(`\n${results.length - failed}/${results.length} cells`);
process.exit(failed ? 1 : 0);
