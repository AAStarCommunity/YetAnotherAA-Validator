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
import { MAX_DEADLETTER_ATTEMPTS } from "./lib/scan.mjs";
import { bloomOf, mayHaveLog } from "./lib/bloom.mjs";
import { Store } from "./lib/store.mjs";
import { runOnce, rulesetIdentity } from "./watcher.mjs";
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
        .map(f => JSON.parse(readFileSync(join(d2, "deadletters", f), "utf8")));
    const [p1] = byTx(k1.hash);
    cell(
      "keeper updatePrice() emitting only PriceUpdated: public route, NOT flagged, caller and selector kept",
      r1.status.ok &&
        p1?.route === "public" &&
        p1.verdict.flagged === false &&
        p1.caller === KEEPER &&
        p1.selector === sel("updatePrice()") &&
        p1.function === "updatePrice()" &&
        p1.callerSource === "tx",
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
