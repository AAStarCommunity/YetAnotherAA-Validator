// CI self-test for the guardian watcher core (W1) against the shared stub chain. Each cell asserts a
// specific outcome; must-pass and must-fail cells are both present (a self-test of only one kind
// proves nothing).
import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { ethers } from "ethers";
import { Kind, aggIface } from "../../scripts/disclosure/recheck-lib.mjs";
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
import { MAX_DEADLETTER_ATTEMPTS, traceUnsupported, verifyTrace } from "./lib/scan.mjs";
import { bloomOf, mayHaveLog } from "./lib/bloom.mjs";
import { Store } from "./lib/store.mjs";
import { runOnce, rulesetIdentity, traceHealth } from "./watcher.mjs";
import { attributeLogs } from "./lib/attribute.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const rs = validateRuleset(JSON.parse(readFileSync(join(HERE, "ruleset.json"), "utf8")));
const results = [];
const j = v => JSON.stringify(v, (_, x) => (typeof x === "bigint" ? x.toString() : x));
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
      rr.status.ok && dl?.status === "ERROR" && /node lost this tx/.test(dl.reasons[0]),
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
  };
  c.execute(Kind.SLASH, 104n, slashF, 0b011n);
  const r4 = await runOnce(broken, cfg, store, rs, ident);
  cell(
    "RPC failure: status not ok, error recorded",
    !r4.status.ok && r4.status.lastError === "rpc down",
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
  cell(
    "verifyTrace: a chain without send() is unsupported",
    (await verifyTrace({}, { roles: {} }, 10)).state === "unsupported",
    null
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
