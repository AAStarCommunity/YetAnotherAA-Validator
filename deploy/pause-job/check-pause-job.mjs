#!/usr/bin/env node
// Pure cells of the pause job: state invariants, ranges, config, the SP pin parser, revert
// decoding, and the host preflight rules. Everything that touches a chain (the pause path, the
// cap, crash recovery, nonce history, the identity check) runs against SP's REAL contracts on
// anvil in e2e-anvil.mjs (DSR 4019916a condition 3: no mocks on the pause path).
//   node deploy/pause-job/check-pause-job.mjs
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { ethers } from "ethers";
import {
  emptyState,
  stateProblems,
  ranges,
  revertData,
  costOf,
  provisionalCost,
  fundingGate,
  unknownCostAlert,
  receiptOf,
  runRound,
  committed,
  PIN,
  spIface,
  regIface,
  OPERATOR_CONFIGURED,
} from "./lib/core.mjs";
import { configProblems, CAP_CEILING } from "./pause-job.mjs";
import { parseRoles } from "./gen-sp-pin.mjs";
import {
  launchdOff,
  nodeSlashOff,
  runsSender,
  parseLaunchctlPrint,
  DETECTOR_LABEL,
  KEEPER_LABEL,
  detectorFresh,
  detectorArgsProblems,
} from "./preflight.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const results = [];
const cell = (name, ok, got) => results.push({ name, ok: !!ok, got: JSON.stringify(got ?? null) });
const A = "0x1111111111111111111111111111111111111111";
const B = "0x2222222222222222222222222222222222222222";

// ---- state invariants
const base = () =>
  emptyState({ chainId: 31337, signer: A, spProxy: A, registry: B, startBlock: 10, cap: "1000" });
cell("a fresh state has no problems", stateProblems(base()).length === 0, stateProblems(base()));
{
  const st = base();
  st.ledger.txs.push({ nonce: 0, reserve: "600", status: "sent" });
  cell(
    "an open reservation not counted in reserved is a problem",
    stateProblems(st).some(p => p.startsWith("reserved")),
    stateProblems(st)
  );
  st.ledger.reserved = "600";
  cell(
    "an open reservation counted in reserved is fine",
    stateProblems(st).length === 0,
    stateProblems(st)
  );
  st.ledger.txs.push({ nonce: 1, reserve: "500", status: "signed" });
  st.ledger.reserved = "1100";
  const p = stateProblems(st);
  cell(
    "spent + reserved > cap is a problem",
    p.some(x => x.includes("exceeds the cap")),
    p
  );
}
{
  const st = base();
  st.ledger.txs.push({ nonce: 0, reserve: "100", status: "sent" });
  st.ledger.txs.push({ nonce: 1, reserve: "100", status: "included" });
  st.ledger.reserved = "200";
  cell(
    "an included transaction after a pending one is a problem",
    stateProblems(st).some(x => x.includes("after a pending")),
    stateProblems(st)
  );
  st.ledger.txs[0].status = "included";
  st.ledger.txs[1].status = "sent";
  cell(
    "included then pending holds both reservations and is fine",
    stateProblems(st).length === 0,
    stateProblems(st)
  );
}
// ---- costs: L1 is execution only; OP adds the GasPriceOracle's L1 + operator fees, never less
{
  const r = { gasUsed: "100", effectiveGasPrice: "7", l1Fee: "50" };
  cell("costOf on Sepolia: gasUsed x effectiveGasPrice", costOf(r, 11155111) === 700n);
  const noL1 = { gasUsed: "100", effectiveGasPrice: "7" };
  cell(
    "costOf on OP, receipt without l1Fee: execution + the oracle's L1 fee + operator fee",
    costOf(noL1, 10, { l1Fee: 80n, operatorFee: 9n }) === 789n
  );
  cell(
    "costOf on OP: the receipt's l1Fee (what the chain charged) wins over the oracle, either way (clestons N2)",
    costOf(r, 10, { l1Fee: 80n, operatorFee: 9n }) === 759n &&
      costOf(r, 10, { l1Fee: 10n, operatorFee: 0n }) === 750n
  );
  let threw = false;
  try {
    costOf(r, 10, null);
  } catch {
    threw = true;
  }
  cell("costOf on OP without the oracle fees refuses (fail closed)", threw);
}
// ---- receipts are believed only for our own hashes with a plausible gasUsed (clestons L2)
{
  const t = { hashes: ["0xAA"], gasLimit: "1000" };
  const mk = r => ({ receipt: async () => r });
  const throws = async c => {
    try {
      await receiptOf(c, t);
      return false;
    } catch {
      return true;
    }
  };
  cell(
    "receiptOf: a receipt naming another transaction is refused",
    await throws(mk({ transactionHash: "0xbb", gasUsed: "10" }))
  );
  cell(
    "receiptOf: gasUsed 0 or above gasLimit is refused",
    (await throws(mk({ transactionHash: "0xaa", gasUsed: "0" }))) &&
      (await throws(mk({ transactionHash: "0xaa", gasUsed: "1001" })))
  );
  cell(
    "receiptOf: our hash (any case) with a plausible gasUsed is accepted",
    (await receiptOf(mk({ transactionHash: "0xaa", gasUsed: "10" }), t))?.gasUsed === "10"
  );
}
// ---- B3 in CI (clestons #432 test gap): a journalled pending nonce consumed with no receipt for
// any hash we signed stops the round; the same with our receipt present does not
{
  const signer = ethers.Wallet.createRandom();
  const mkState = () => {
    const st = emptyState({
      chainId: 31337,
      signer: signer.address,
      spProxy: A,
      registry: B,
      startBlock: 10,
      cap: "1000000",
    });
    st.ledger.txs.push({
      nonce: 0,
      operator: A,
      hash: "0xaa",
      hashes: ["0xaa"],
      raws: ["0x"],
      reserve: "100",
      gasLimit: "1000",
      status: "sent",
      pendingRounds: 0,
    });
    st.ledger.reserved = "100";
    return st;
  };
  const fake = receipt => ({
    chainId: async () => "0x7a69",
    blockNumber: async () => 5,
    blockByNumber: async () => ({ number: 5, hash: `0x${"ab".repeat(32)}` }),
    receipt: async () => receipt,
    nonce: async () => 1,
    getLogs: async () => [],
    call: async () => {
      throw new Error("not reached");
    },
  });
  const cfg = { logChunk: 10, pollMs: 1 };
  let msg = "";
  try {
    await runRound(mkState(), {
      chain: fake(null),
      signer: { address: signer.address },
      persist: () => {},
      cfg,
    });
  } catch (e) {
    msg = e.message;
  }
  cell(
    "B3 (unit): a pending journalled nonce consumed with no receipt of ours stops the round",
    /no receipt names a transaction the job journalled/.test(msg),
    msg
  );
  // control (Codex R14 P3): no receipt during reconcile, so tx0 stays pending and the B3 loop RUNS;
  // its re-read then finds our receipt, and the round goes on to the inventory (a getLogs call)
  const ours = {
    transactionHash: "0xAA",
    gasUsed: "10",
    blockNumber: "0x4",
    blockHash: `0x${"cd".repeat(32)}`,
    effectiveGasPrice: "1",
    status: "0x1",
  };
  let receiptCalls = 0;
  let reachedInventory = false;
  const late = {
    ...fake(null),
    blockNumber: async () => 50, // above the inventory cursor, so the inventory is read
    receipt: async () => (++receiptCalls >= 3 ? ours : null),
    getLogs: async () => ((reachedInventory = true), []),
  };
  let msg2 = "";
  try {
    await runRound(mkState(), {
      chain: late,
      signer: { address: signer.address },
      persist: () => {},
      cfg,
    });
  } catch (e) {
    msg2 = e.message;
  }
  cell(
    "B3 (unit, control): the loop runs, its re-read finds our receipt, and the round reaches the inventory",
    receiptCalls >= 3 && reachedInventory && !/no receipt names/.test(msg2),
    { receiptCalls, reachedInventory, msg2 }
  );
  {
    // committed(): a known OP overrun of an included transaction counts before finality (R14 P1)
    const st = emptyState({
      chainId: 10,
      signer: A,
      spProxy: A,
      registry: B,
      startBlock: 1,
      cap: "100",
    });
    st.ledger.txs.push({ nonce: 0, status: "included", reserve: "10", includedCost: "60" });
    st.ledger.reserved = "10";
    cell(
      "committed: cap 100, an included reservation 10 with a known cost 60 commits 60 (a new 90 cannot fit)",
      committed(st) === 60n && 100n - committed(st) < 90n
    );
    st.ledger.txs[0].includedCost = "5";
    cell(
      "committed: a known cost below its reservation still holds the reservation",
      committed(st) === 10n
    );
  }
}
// ---- a whole round on a scripted chain, so CI pins the send-path decisions (clestons #432 L2):
// the chain answers the job's own reads; SP's pause logic itself is covered by e2e-anvil.mjs
const OPR = "0x3333333333333333333333333333333333333333";
const OTHER = "0x4444444444444444444444444444444444444444";
const BH = `0x${"ab".repeat(32)}`;
function scripted({ signer, balance, finalized = 100, prior = null }) {
  const sent = [];
  const out = (iface, fn, v) => iface.encodeFunctionResult(fn, v);
  const roleCfg = {
    minStake: 0n,
    ticketPrice: 0n,
    slashThreshold: 0,
    slashBase: 0,
    slashInc: 0,
    slashMax: 0,
    exitFeePercent: 0,
    isActive: true,
    minExitFee: 0n,
    description: "",
    owner: OTHER,
    roleLockDuration: 0n,
  };
  const opsOut = {
    aPNTsBalance: 0n,
    isConfigured: true,
    isPaused: false,
    xPNTsToken: OTHER,
    reputation: 0,
    minTxInterval: 0,
    treasury: OTHER,
    totalSpent: 0n,
    totalTxSponsored: 0n,
  };
  const chain = {
    chainId: async () => "0x7a69",
    blockNumber: async () => finalized,
    blockByNumber: async () => ({ number: 101, hash: BH }),
    getLogs: async f =>
      f.topics[0] === OPERATOR_CONFIGURED && f.address.toLowerCase() === A.toLowerCase()
        ? [
            {
              address: A,
              topics: [OPERATOR_CONFIGURED, ethers.zeroPadValue(OPR, 32)],
              blockNumber: "0x1",
              removed: false,
            },
          ]
        : [],
    call: async ({ to, data }) => {
      const sp = to.toLowerCase() === A.toLowerCase();
      const iface = sp ? spIface : regIface;
      const f = iface.parseTransaction({ data });
      switch (f.name) {
        case "REGISTRY":
          return out(spIface, f.name, [B]);
        case "owner":
        case "pendingOwner":
        case "guardian":
        case "BLS_AGGREGATOR":
        case "blsAggregator":
          return out(iface, f.name, [OTHER]);
        case "hasRole":
        case "isReputationSource":
          return out(regIface, f.name, [false]);
        case "getRoleConfig":
          return out(regIface, f.name, [roleCfg]);
        case "pauseUnderstakedOperator":
          return "0x"; // understaked
        case "operators":
          return out(spIface, f.name, Object.values(opsOut));
        default:
          throw new Error(`unscripted ${f.name}`);
      }
    },
    nonce: async () => (prior ? 1 : 0) + sent.length,
    estimateGas: async () => 50000n,
    fees: async () => ({ baseFee: 1n }),
    balance: async () => balance,
    sendRaw: async raw => {
      sent.push(raw);
      return ethers.keccak256(raw);
    },
    receipt: async h => {
      if (prior && h === prior.hash)
        return {
          transactionHash: h,
          blockNumber: "0x63",
          blockHash: prior.blockHash,
          gasUsed: "10",
          effectiveGasPrice: "1",
          status: "0x1",
        };
      const i = sent.findIndex(r => ethers.keccak256(r) === h);
      return i < 0
        ? null
        : {
            transactionHash: h,
            blockNumber: "0x65",
            blockHash: BH,
            gasUsed: "40000",
            effectiveGasPrice: "3",
            status: "0x1",
          };
    },
  };
  return { chain, sent };
}
async function roundOn({ cap, balance, prior = null }) {
  const w = ethers.Wallet.createRandom();
  const st = emptyState({
    chainId: 31337,
    signer: w.address,
    spProxy: A,
    registry: B,
    startBlock: 1,
    cap,
  });
  if (prior) {
    st.ledger.txs.push({
      nonce: 0,
      operator: OTHER,
      hash: prior.hash,
      hashes: [prior.hash],
      raws: ["0x01"],
      reserve: prior.reserve,
      gasLimit: "100000",
      status: "included",
      includedHash: prior.hash,
      includedBlock: 99,
      includedBlockHash: prior.blockHash,
      includedCost: prior.includedCost,
      pendingRounds: 0,
    });
    st.ledger.reserved = prior.reserve;
  }
  const { chain, sent } = scripted({
    signer: w.address,
    balance,
    finalized: prior ? 50 : 100,
    prior,
  });
  const cfg = {
    logChunk: 1000,
    gasLimitMax: "1000000",
    maxFeePerGasCap: "1000",
    maxPriorityFeePerGas: "1",
    receiptWaitMs: 1000,
    pollMs: 1,
  };
  const r = await runRound(st, {
    chain,
    signer: { address: w.address, sign: tx => w.signTransaction(tx) },
    persist: () => {},
    cfg,
  });
  return { r, sent, st };
}
{
  const ok = await roundOn({ cap: "10000000", balance: 10000000n });
  cell(
    "scripted round (control): an understaked operator is paused, no inflow",
    ok.sent.length === 1 && !ok.r.alerts.some(x => x.key === "inflow"),
    { sent: ok.sent.length, a: ok.r.alerts.map(x => x.key) }
  );
  const inflow = await roundOn({ cap: "10000000", balance: 10000001n });
  cell(
    "scripted round: after an inflow of 1 wei the send STILL happens, and the inflow alert fires (L2)",
    inflow.sent.length === 1 && inflow.r.alerts.some(x => x.key === "inflow"),
    { sent: inflow.sent.length, a: inflow.r.alerts.map(x => x.key) }
  );
  const deficit = await roundOn({ cap: "10000000", balance: 9999999n });
  cell(
    "scripted round: a balance below what the ledger explains raises a deficit alert and still sends (L3)",
    deficit.sent.length === 1 && deficit.r.alerts.some(x => x.key === "deficit"),
    { sent: deficit.sent.length, a: deficit.r.alerts.map(x => x.key) }
  );
  {
    // a journalled PENDING tx mined between the reconcile and B: its fee is gone from the balance
    // but not in the ledger yet; that is no deficit (Codex follow-up P2)
    const w = ethers.Wallet.createRandom();
    const st = emptyState({
      chainId: 31337,
      signer: w.address,
      spProxy: A,
      registry: B,
      startBlock: 1,
      cap: "10000000",
    });
    st.ledger.txs.push({ nonce: 0, status: "sent", reserve: "300000" });
    st.ledger.reserved = "300000";
    const g = fundingGate(st, 10000000n - 120000n); // the fee it actually paid
    cell(
      "fundingGate: a pending tx already mined (fee gone from the balance, not yet in the ledger) is no deficit",
      g.deficit === null && g.inflow === null,
      g
    );
    cell(
      "fundingGate: a balance below even the pending allowance is a deficit",
      fundingGate(st, 10000000n - 300001n).deficit?.key === "deficit"
    );
    // an included tx recorded at 120000 whose block was reorged and re-included at 150000 before B
    const st2 = emptyState({
      chainId: 31337,
      signer: w.address,
      spProxy: A,
      registry: B,
      startBlock: 1,
      cap: "10000000",
    });
    st2.ledger.txs.push({
      nonce: 0,
      status: "included",
      reserve: "300000",
      includedCost: "120000",
    });
    st2.ledger.reserved = "300000";
    cell(
      "fundingGate: an included tx re-included at a higher cost (within its reservation) is no deficit (Codex follow-up R2)",
      fundingGate(st2, 10000000n - 150000n).deficit === null
    );
    cell(
      "fundingGate: below cap - committed it is a deficit",
      fundingGate(st2, 10000000n - 300001n).deficit?.key === "deficit"
    );
    cell(
      "fundingGate: a balance of EXACTLY cap - committed is no deficit (the boundary, clestons #433 L1)",
      fundingGate(st2, 10000000n - 300000n).deficit === null
    );
  }
  // an included tx with reservation 10 but a KNOWN cost far above it: a new send must not fit
  const H0 = `0x${"0c".repeat(32)}`;
  const big1 = await roundOn({
    cap: "10000000",
    balance: 0n,
    prior: { hash: H0, blockHash: `0x${"0d".repeat(32)}`, reserve: "10", includedCost: "9900000" },
  });
  cell(
    "scripted round: an included cost above its reservation is committed; the new send is refused (L2)",
    big1.sent.length === 0 && big1.r.alerts.some(x => x.key === "cap"),
    { sent: big1.sent.length, a: big1.r.alerts.map(x => x.key) }
  );
  const over = await roundOn({
    cap: "10000000",
    balance: 0n,
    prior: { hash: H0, blockHash: `0x${"0d".repeat(32)}`, reserve: "10", includedCost: "10000001" },
  });
  cell(
    "scripted round: an included cost above the cap trips overCap (committed), nothing sent (L2)",
    over.sent.length === 0 &&
      over.r.alerts.some(
        x =>
          x.key === "cap" &&
          /^remaining cap insufficient: committed 10000001 \(spent 0, held reservations or known included costs\) exceeds the cap 10000000;/.test(
            x.text
          )
      ),
    { sent: over.sent.length, a: over.r.alerts.map(x => x.text) }
  );
}

// ---- the provisional (included, not final) cost on OP includes the oracle's fees (Codex R9 P2)
{
  const w = ethers.Wallet.createRandom();
  const tx = {
    type: 2,
    chainId: 10,
    nonce: 0,
    to: A,
    data: "0x",
    value: 0n,
    gasLimit: 100000n,
    maxFeePerGas: 10n,
    maxPriorityFeePerGas: 1n,
  };
  const raw = await w.signTransaction(tx);
  const hash = ethers.keccak256(raw);
  const t = { hashes: [hash], raws: [raw], reserve: "999999" };
  const r = {
    transactionHash: hash,
    blockHash: `0x${"11".repeat(32)}`,
    gasUsed: "100",
    effectiveGasPrice: "7",
  };
  const gpo = new ethers.Interface([
    "function getL1Fee(bytes) view returns (uint256)",
    "function getOperatorFee(uint256) view returns (uint256)",
  ]);
  const seen = [];
  const unsignedOk = ethers.Transaction.from(raw).unsignedSerialized;
  const op = {
    call: async ({ data }, tag) => {
      seen.push({ data, tag });
      const f = gpo.parseTransaction({ data });
      // the oracle answers only for THIS transaction's unsigned bytes (a lookup that lost them
      // and priced something else must fail here)
      if (f.name === "getL1Fee" && f.args[0] !== unsignedOk) throw new Error("revert: other bytes");
      return ethers.AbiCoder.defaultAbiCoder().encode(
        ["uint256"],
        [f.name === "getL1Fee" ? 80n : 9n]
      );
    },
  };
  const st = { chainId: 10 };
  const c = await provisionalCost(st, op, t, r);
  const unsignedSent = seen.some(
    x =>
      gpo.parseTransaction({ data: x.data }).name === "getL1Fee" &&
      gpo.parseTransaction({ data: x.data }).args[0] ===
        ethers.Transaction.from(raw).unsignedSerialized
  );
  cell(
    "provisionalCost on OP = execution + oracle L1 + operator fee, read at the inclusion block",
    c === 789n && seen.every(x => x.tag?.blockHash === r.blockHash),
    { c: String(c), seen: seen.length }
  );
  cell("provisionalCost sends the oracle the UNSIGNED serialization (clestons L1)", unsignedSent);
  {
    // the receipt's hash in another case still finds the signed bytes (the lowercase lookup)
    const seen2 = [];
    const op2 = { call: async ({ data }, tag) => (seen2.push(tag), op.call({ data }, tag)) };
    const up = { ...r, transactionHash: r.transactionHash.toUpperCase().replace(/^0X/, "0x") };
    const c2 = await provisionalCost(st, op2, t, up);
    cell(
      "provisionalCost finds the signed bytes for a receipt hash in another case",
      c2 === 789n,
      String(c2)
    );
    // a REAL oracle prices any bytes it is given: with the signed bytes missing, the cost must be
    // unknown, not the price of an empty transaction (ethers' Transaction.from(undefined))
    const permissive = {
      call: async () => ethers.AbiCoder.defaultAbiCoder().encode(["uint256"], [1n]),
    };
    const lost = { ...t, raws: [] };
    cell(
      "provisionalCost with the signed bytes missing is unknown, even from an oracle that prices anything",
      (await provisionalCost(st, permissive, lost, r)) === null
    );
  }
  const down = {
    call: async () => {
      throw new Error("rpc down");
    },
  };
  cell(
    "provisionalCost on OP with the oracle unreadable is UNKNOWN (null), never a guess (Codex R10 P2)",
    (await provisionalCost(st, down, t, r)) === null
  );
  {
    const led = txs => ({ ledger: { cap: "100", spent: "0", reserved: "10", txs } });
    const inc = cost => ({ nonce: 0, status: "included", reserve: "10", includedCost: cost });
    cell(
      "fundingGate: an included cost still unknown refuses every broadcast",
      (() => {
        try {
          return fundingGate(led([inc(null)]), 0n).block?.key === "cost-unknown";
        } catch {
          return false;
        }
      })()
    );
    cell(
      "fundingGate: cap 100, included cost 15, an unexplained +3 (balance 88 > 85): an inflow ALERT, not a block (DSR N1 (c))",
      fundingGate(led([inc("15")]), 88n).inflow?.key === "inflow" &&
        fundingGate(led([inc("15")]), 88n).block === null
    );
    cell(
      "fundingGate: a balance of exactly cap - spent - included: neither block nor inflow",
      fundingGate(led([inc("15")]), 85n).block === null &&
        fundingGate(led([inc("15")]), 85n).inflow === null
    );
    cell(
      "unknownCostAlert: any included transaction with an unknown cost raises it; none, no alert",
      unknownCostAlert(led([inc(null)]))?.key === "cost-unknown" &&
        unknownCostAlert(led([inc("15")])) === null
    );
    // the control flow cannot be driven on anvil (an L1 chain never reads the OP oracle): this
    // structural cell pins that the gate runs at the top of the send loop, BEFORE send() (R11 P2)
    const src = readFileSync(join(here, "lib/core.mjs"), "utf8");
    const loop = src.slice(src.indexOf("for (const op of candidates) {"));
    cell(
      "the unknown-cost gate runs before every new send in the candidate loop (structural)",
      loop.indexOf("unknownCostAlert(st)") > 0 &&
        loop.indexOf("unknownCostAlert(st)") < loop.indexOf("await send(")
    );
  }
  cell(
    "provisionalCost on L1 is the execution cost",
    (await provisionalCost({ chainId: 11155111 }, down, t, r)) === 700n
  );
}
{
  const st = base();
  st.ledger.txs.push({ nonce: 1, cost: "5", status: "final" });
  st.ledger.spent = "5";
  cell(
    "a ledger whose nonces do not start at 0 is a problem",
    stateProblems(st).some(p => p.includes("nonces")),
    stateProblems(st)
  );
}
{
  const st = base();
  st.ledger.txs.push({ nonce: 0, cost: "5", status: "final" });
  cell(
    "spent that does not equal the mined costs is a problem",
    stateProblems(st).some(p => p.startsWith("spent does not")),
    stateProblems(st)
  );
}
cell(
  "the cursor starts one block before startBlock",
  base().cursor.operators === 9 && base().cursor.roles === 9,
  base().cursor
);

// ---- ranges
cell(
  "ranges cover [a,b] in chunks, inclusive",
  JSON.stringify(ranges(10, 25, 7)) === "[[10,16],[17,23],[24,25]]",
  ranges(10, 25, 7)
);
cell("an empty range has no chunks", ranges(11, 10, 5).length === 0, ranges(11, 10, 5));

// ---- revert data
const sel = n => spIface.getError(n).selector;
cell(
  "revertData reads a selector from error.data",
  revertData({ data: sel("OperatorMeetsMinimumStake") }) === sel("OperatorMeetsMinimumStake")
);
cell(
  "revertData reads a selector from info.error.data",
  revertData({ info: { error: { data: sel("OperatorNotConfigured") } } }) ===
    sel("OperatorNotConfigured")
);
cell(
  "revertData ignores longer data (an error with arguments is not one of ours)",
  revertData({ data: `${sel("OperatorNotConfigured")}00` }) === null
);
cell("revertData ignores a message", revertData({ message: "execution reverted" }) === null);

// ---- config
const good = {
  chainId: 11155111,
  spProxy: A,
  registry: B,
  startBlock: 100,
  registryStartBlock: 90,
  capWei: String(10n ** 17n),
  gasLimitMax: "200000",
  maxFeePerGasCap: "200000000000",
  maxPriorityFeePerGas: "1000000000",
  logChunk: 5000,
  stateDir: "/Users/x/.aoa-pause-job/state",
  secretsDir: "/Users/x/.aoa-pause-job/secrets",
  keystore: "/Users/x/.aoa-pause-job/keystore/pause-signer",
  telegram: { chatId: "-100123" },
  realertMinutes: 60,
  lockPort: 47219,
  rpc: { primary: "alchemy", fallback: "infura" },
};
cell("the example-shaped config passes", configProblems(good).length === 0, configProblems(good));
cell(
  "a cap above the Sepolia ceiling (0.1 ETH) is refused",
  configProblems({ ...good, capWei: String(10n ** 17n + 1n) }).some(p => p.includes("ceiling"))
);
cell(
  "a cap above the OP ceiling (0.02 ETH) is refused",
  configProblems({ ...good, chainId: 10, capWei: String(3n * 10n ** 16n) }).some(p =>
    p.includes("ceiling")
  )
);
cell(
  "the ceilings are 0.1 ETH Sepolia and 0.02 ETH OP",
  CAP_CEILING[11155111] === 10n ** 17n && CAP_CEILING[10] === 2n * 10n ** 16n
);
cell(
  "an unknown chain is refused",
  configProblems({ ...good, chainId: 1 }).some(p => p.startsWith("chainId"))
);
cell(
  "a relative state path is refused",
  configProblems({ ...good, stateDir: "state" }).some(p => p.startsWith("stateDir"))
);
cell(
  "the same provider twice is refused",
  configProblems({ ...good, rpc: { primary: "alchemy", fallback: "alchemy" } }).some(p =>
    p.includes("different providers")
  )
);
cell(
  "a provider URL in place of a name is refused",
  configProblems({ ...good, rpc: { primary: "https://x", fallback: "infura" } }).some(p =>
    p.startsWith("rpc")
  )
);
cell(
  "startBlock 0 is refused",
  configProblems({ ...good, startBlock: 0 }).some(p => p.startsWith("startBlock"))
);

// ---- the SP pin
cell(
  "sp-pin.json has a 40-hex spCommit and the seven Registry roles",
  /^[0-9a-f]{40}$/.test(PIN.spCommit) && Object.keys(PIN.roles).length === 7,
  Object.keys(PIN.roles)
);
cell(
  "each pinned role id is keccak256 of its name",
  Object.entries(PIN.roles).every(([n, id]) => id === ethers.id(n.slice(5)))
);
cell(
  "operators() in the pin has isPaused as its third output",
  PIN.abi.superPaymaster.find(f => f.name === "operators").outputs[2].name === "isPaused"
);
{
  const src =
    'bytes32 constant ROLE_A = keccak256("A");\nbytes32 constant ROLE_B = keccak256("B");\n';
  cell("parseRoles reads the constants", Object.keys(parseRoles(src)).join() === "ROLE_A,ROLE_B");
  let t1 = false;
  try {
    parseRoles('bytes32 constant ROLE_A = keccak256("B");');
  } catch {
    t1 = true;
  }
  cell("parseRoles refuses a constant that hashes another name", t1);
  cell(
    "parseRoles reads a declaration with a block comment inside it (Codex R2 P2-7)",
    Object.keys(
      parseRoles(
        'bytes32 constant ROLE_A = keccak256("A");\nbytes32 /* doc */ constant ROLE_X = keccak256("X");'
      )
    ).join() === "ROLE_A,ROLE_X"
  );
  cell(
    "parseRoles ignores a commented-out declaration",
    Object.keys(
      parseRoles(
        'bytes32 constant ROLE_A = keccak256("A");\n// bytes32 constant ROLE_Z = keccak256("Z");'
      )
    ).join() === "ROLE_A"
  );
  let t2 = false;
  try {
    parseRoles('bytes32 constant ROLE_A = keccak256("A");\nbytes32 constant ROLE_X = 0x01;');
  } catch {
    t2 = true;
  }
  cell("parseRoles refuses a ROLE_ constant in a form it does not read (fail closed)", t2);
}

// ---- preflight rules
{
  const ok = launchdOff(
    [DETECTOR_LABEL, KEEPER_LABEL, "com.apple.x"],
    l => (l === "com.apple.x" ? null : ["/bin/bash", `/x/${l}.sh`]),
    () => ({ kind: "text", text: "echo unrelated" })
  );
  cell("launchd-on passes with the detector, the keeper and unrelated jobs", ok.length === 0, ok);
  const d2 = launchdOff([DETECTOR_LABEL, KEEPER_LABEL, "io.aastar.dvt-pause-job"], () => []);
  cell(
    "launchd-on fails when the retired D2 pause job is loaded",
    d2.some(p => p.includes("io.aastar.dvt-pause-job is loaded")),
    d2
  );
  const nk = launchdOff([DETECTOR_LABEL], () => []);
  cell(
    "launchd-on fails when the price keeper is not loaded",
    nk.some(p => p.includes(`${KEEPER_LABEL} is not loaded`)),
    nk
  );
  const nd = launchdOff([KEEPER_LABEL], () => []);
  cell(
    "launchd-on fails when the pause detector is not loaded",
    nd.some(p => p.includes(`${DETECTOR_LABEL} is not loaded`)),
    nd
  );
  const ds = launchdOff([DETECTOR_LABEL, KEEPER_LABEL], l =>
    l === DETECTOR_LABEL ? ["/usr/bin/node", "/repo/deploy/pause-job/pause-job.mjs"] : null
  );
  cell(
    "launchd-on fails when the detector's label runs the D2 sender (the detector is scanned)",
    ds.some(p => p.includes("runs pause-job.mjs")),
    ds
  );
  {
    const H = "/Users/u";
    const good = [
      `${H}/.local/keeper-node/node-v24.21.0/bin/node`,
      "--permission",
      `--allow-fs-read=${H}/.aoa-pause-detector`,
      `--allow-fs-write=${H}/.aoa-pause-detector/state`,
      `${H}/.aoa-pause-detector/app/deploy/pause-detector/detector.mjs`,
      "--config",
      `${H}/.aoa-pause-detector/config.json`,
    ];
    cell("detector-args passes the exact plist form", detectorArgsProblems(good, H).length === 0);
    const bad = [
      ["no --permission", good.filter(a => a !== "--permission")],
      ["Homebrew node", ["/opt/homebrew/bin/node", ...good.slice(1)]],
      [
        "--allow-child-process added",
        [...good.slice(0, 2), "--allow-child-process", ...good.slice(2)],
      ],
      ["a wider read", good.map(a => (a.startsWith("--allow-fs-read") ? "--allow-fs-read=/" : a))],
      [
        "the repo granted (Codex R7)",
        [...good.slice(0, 2), "--allow-fs-read=/r", ...good.slice(2)],
      ],
      [
        "run from a checkout",
        good.map(a => (a.endsWith("detector.mjs") ? "/r/deploy/pause-detector/detector.mjs" : a)),
      ],
      [
        "a wider write",
        good.map(a => (a.startsWith("--allow-fs-write") ? `--allow-fs-write=${H}` : a)),
      ],
      ["unreadable", null],
    ];
    cell(
      "detector-args fails on NODE_OPTIONS set or inherited (Codex R4 P1-1)",
      detectorArgsProblems(good, H, ["NODE_OPTIONS"], []).length === 1 &&
        detectorArgsProblems(good, H, [], ["NODE_OPTIONS"]).length === 1 &&
        detectorArgsProblems(good, H, ["PATH"], ["SSH_AUTH_SOCK"]).length === 0
    );
    for (const [what, args] of bad)
      cell(`detector-args fails: ${what}`, detectorArgsProblems(args, H).length === 1);
  }
  const now = Date.parse("2026-11-14T12:00:00Z");
  const st = (at, clear = true) =>
    JSON.stringify({
      schema: "aoa-pause-detector-status/1",
      at,
      clear,
      alerts: clear ? [] : ["x"],
    });
  cell(
    "pause-detector passes on a fresh clear status",
    detectorFresh(st("2026-11-14T11:30:00Z"), now).problems.length === 0
  );
  cell(
    "pause-detector fails on a status older than two intervals",
    detectorFresh(st("2026-11-14T09:40:00Z"), now).problems.length === 1
  );
  cell(
    "pause-detector fails when there is no status",
    detectorFresh(null, now).problems.length === 1
  );
  cell(
    "pause-detector fails on a status dated even a minute in the future (Codex R1 P1-6)",
    detectorFresh(st("2026-11-14T12:01:00Z"), now).problems.some(x => x.includes("future")) &&
      detectorFresh(st("2026-11-14T12:00:00Z"), now).problems.length === 0
  );
  cell(
    "pause-detector fails on another job's status file",
    detectorFresh(
      JSON.stringify({ schema: "aoa-pause-job-status/1", at: "2026-11-14T11:59:00Z" }),
      now
    ).problems.length === 1
  );
  cell(
    "pause-detector reports NOT clear without failing (freshness is the trigger check)",
    detectorFresh(st("2026-11-14T11:30:00Z", false), now).note.includes("NOT clear")
  );
  const k = launchdOff([DETECTOR_LABEL, "io.aastar.dvt-committee-keeper"], () => []);
  cell(
    "launchd-on fails when the committee keeper is loaded",
    k.some(p => p.includes("committee-keeper")),
    k
  );
  const r = launchdOff([DETECTOR_LABEL, "io.aastar.dvt-apply-rotation"], () => []);
  cell(
    "launchd-on fails when apply-rotation is loaded",
    r.some(p => p.includes("apply-rotation")),
    r
  );
  const n = launchdOff([], () => []);
  cell(
    "launchd-on fails when the required jobs are not loaded",
    n.some(p => p.includes("not loaded")),
    n
  );
  const m = launchdOff([DETECTOR_LABEL, "io.aastar.harmless"], () => [
    "/usr/bin/node",
    "/repo/deploy/committee-keeper.mjs",
  ]);
  cell(
    "launchd-on fails when a job under another name runs the committee keeper",
    m.some(p => p.includes("runs committee-keeper.mjs")),
    m
  );
  const u = launchdOff([DETECTOR_LABEL, "io.aastar.unreadable"], () => null);
  cell(
    "launchd-on fails closed on a non-Apple job it cannot read",
    u.some(p => p.includes("cannot be read")),
    u
  );
}
{
  const env = { n1: ["AUDIT_ENABLED=false"], n2: [], n3: ["AUDIT_EXECUTE_SLASH=false", "X=1"] };
  cell(
    "node-slash-off passes with false or absent",
    nodeSlashOff(n => env[n] ?? null, ["n1", "n2", "n3"]).length === 0
  );
  for (const [name, e] of [
    ["true", ["AUDIT_ENABLED=true"]],
    ["TRUE (off in code, refused here)", ["AUDIT_EXECUTE_SLASH=TRUE"]],
    ["set twice", ["AUDIT_ENABLED=false", "AUDIT_ENABLED=false"]],
    ["empty", ["AUDIT_EXECUTE_SLASH="]],
  ])
    cell(
      `node-slash-off fails on ${name}`,
      nodeSlashOff(() => e, ["n"]).length > 0,
      nodeSlashOff(() => e, ["n"])
    );
  cell("node-slash-off fails on an empty inventory", nodeSlashOff(() => [], []).length > 0);
  cell(
    "node-slash-off fails when a running dvt-node-* is not in the inventory",
    nodeSlashOff(() => [], ["dvt-node-1"], ["dvt-node-1", "dvt-node-4"]).some(x =>
      x.includes("dvt-node-4")
    )
  );
  cell(
    "runsSender: a sending script inside sh -c is found",
    runsSender(["/bin/sh", "-c", "node /repo/deploy/committee-keeper.mjs --watch"]).includes(
      "committee-keeper.mjs"
    )
  );
  cell(
    "runsSender: a wrapper script that runs one is found by reading it",
    runsSender(["/bin/bash", "/x/run.sh"], () => ({
      kind: "text",
      text: "exec node deploy/apply-verifier-rotation.mjs",
    })).includes("apply-verifier-rotation.mjs")
  );
  cell(
    "runsSender: an unreadable wrapper is reported (fail closed)",
    runsSender(["/bin/bash", "/x/run.sh"], () => ({ kind: "unreadable" })).some(x =>
      x.includes("unreadable")
    )
  );
  cell(
    "runsSender: an extensionless wrapper is read too (Codex R2 P2-5)",
    runsSender(["/bin/bash", "/repo/run-keeper"], p =>
      p === "/repo/run-keeper"
        ? { kind: "text", text: "node deploy/committee-keeper.mjs" }
        : { kind: "binary" }
    ).includes("committee-keeper.mjs")
  );
  cell(
    "runsSender: a binary interpreter is not searched",
    runsSender(["/opt/homebrew/bin/node", "/x/y.mjs"], p =>
      p.endsWith("node") ? { kind: "binary" } : { kind: "text", text: "console.log(1)" }
    ).length === 0
  );
  {
    const fs = {
      "/repo/outer.sh": "#!/bin/bash\nexec /repo/inner.sh",
      "/repo/inner.sh": "node deploy/committee-keeper.mjs --watch",
      "/w/deploy/outer.sh": "bash ./deploy/inner2.sh",
      "/w/deploy/inner2.sh": "node deploy/apply-verifier-rotation.mjs --broadcast",
      "/c/quiet.sh": "# this script never runs committee-keeper.mjs\necho ok",
    };
    const rt = p => (fs[p] !== undefined ? { kind: "text", text: fs[p] } : { kind: "none" });
    cell(
      "runsSender: a nested wrapper chain outer.sh -> inner.sh -> keeper is followed (Codex R3 P2-3)",
      runsSender(["/bin/bash", "/repo/outer.sh"], rt).includes("committee-keeper.mjs")
    );
    cell(
      "runsSender: a relative wrapper is resolved against the working directory",
      runsSender(["/bin/bash", "deploy/outer.sh"], rt, "/w").includes("apply-verifier-rotation.mjs")
    );
    cell(
      "runsSender: a whole-line comment naming a sending script does not count",
      runsSender(["/bin/bash", "/c/quiet.sh"], rt).length === 0
    );
    const fs2 = {
      "/w/outer.sh": "bash inner.sh",
      "/w/inner.sh": "node /repo/deploy/committee-keeper.mjs",
      "/repo/inner.sh": "node /repo/deploy/committee-keeper.mjs",
      "/g/globs.sh": "ls /tmp/cache/*\nnode /repo/deploy/committee-keeper.mjs\nls /tmp/*/status",
    };
    const rt2 = p => (fs2[p] !== undefined ? { kind: "text", text: fs2[p] } : { kind: "none" });
    cell(
      "runsSender: a bare `bash inner.sh` reference is followed (Codex R4 P2-1)",
      runsSender(["/bin/bash", "/w/outer.sh"], rt2, "/w").includes("committee-keeper.mjs")
    );
    cell(
      'runsSender: a script inside `sh -c "exec /repo/inner.sh"` is followed (Codex R4 P2-1)',
      runsSender(["/bin/sh", "-c", "exec /repo/inner.sh"], rt2).includes("committee-keeper.mjs")
    );
    cell(
      "runsSender: shell globs `/tmp/*` ... `*/` are not taken for a comment (Codex R4 P2-2)",
      runsSender(["/bin/bash", "/g/globs.sh"], rt2).includes("committee-keeper.mjs")
    );
    const fs3 = {
      "/w/outer.sh": "exec /w/bin/run-keeper --watch",
      "/w/bin/run-keeper": "#!/bin/sh\nnode /repo/deploy/register-node.mjs",
    };
    cell(
      "runsSender: an extensionless absolute path inside a wrapper is followed (clestons L4)",
      runsSender(["/bin/bash", "/w/outer.sh"], p =>
        fs3[p] !== undefined ? { kind: "text", text: fs3[p] } : { kind: "none" }
      ).includes("register-node.mjs")
    );
    const fs4 = {
      "/w/outer.sh": "exec ./bin/run-keeper --watch",
      "/w/bin/run-keeper": "#!/bin/sh\nnode /repo/deploy/register-node.mjs",
    };
    const fs5 = {
      "/repo/outer.sh": "bash inner",
      "/repo/inner": "node /repo/deploy/committee-keeper.mjs",
    };
    cell(
      "runsSender: a bare script after an interpreter (`bash inner`) is followed (Codex R7 P2)",
      runsSender(
        ["/bin/bash", "/repo/outer.sh"],
        p => (fs5[p] !== undefined ? { kind: "text", text: fs5[p] } : { kind: "none" }),
        "/repo"
      ).includes("committee-keeper.mjs")
    );
    const fs6 = {
      "/repo/inner": "node /repo/deploy/committee-keeper.mjs",
      "/repo/a.sh": "/bin/bash inner",
      "/repo/b.sh": 'bash "inner"',
    };
    const rt6 = p => (fs6[p] !== undefined ? { kind: "text", text: fs6[p] } : { kind: "none" });
    cell(
      'runsSender: argv ["/bin/bash", "inner"], a wrapper with "/bin/bash inner", and bash "inner" are all followed (Codex R8 P2)',
      runsSender(["/bin/bash", "inner"], rt6, "/repo").includes("committee-keeper.mjs") &&
        runsSender(["/bin/bash", "/repo/a.sh"], rt6, "/repo").includes("committee-keeper.mjs") &&
        runsSender(["/bin/bash", "/repo/b.sh"], rt6, "/repo").includes("committee-keeper.mjs")
    );
    {
      const deep = {};
      for (let i = 0; i < 5; i++) deep[`/e/w${i}.sh`] = `exec /e/w${i + 1}.sh`;
      cell(
        "runsSender: an UNREADABLE file past the depth limit is reported too (Codex R8 P2)",
        runsSender(["/bin/bash", "/e/w0.sh"], p =>
          deep[p] !== undefined
            ? { kind: "text", text: deep[p] }
            : p === "/e/w5.sh"
              ? { kind: "unreadable" }
              : { kind: "none" }
        ).some(x => x.includes("not followed past depth"))
      );
    }
    const chain6 = {};
    for (let i = 0; i < 6; i++) chain6[`/d/w${i}.sh`] = `exec /d/w${i + 1}.sh`;
    chain6["/d/w6.sh"] = "node /repo/deploy/committee-keeper.mjs";
    cell(
      "runsSender: a wrapper chain deeper than followed is reported, not certified (Codex R7 P2)",
      runsSender(["/bin/bash", "/d/w0.sh"], p =>
        chain6[p] !== undefined ? { kind: "text", text: chain6[p] } : { kind: "none" }
      ).some(x => x.includes("not followed past depth"))
    );
    cell(
      "runsSender: a relative extensionless path inside a wrapper is followed (Codex R6 P2)",
      runsSender(
        ["/bin/bash", "/w/outer.sh"],
        p => (fs4[p] !== undefined ? { kind: "text", text: fs4[p] } : { kind: "none" }),
        "/w"
      ).includes("register-node.mjs")
    );
  }
  {
    // the real `launchctl print` shape (tabs, blocks), values abbreviated
    const out = [
      "gui/501/io.aastar.dvt-committee-health = {",
      "\tactive count = 0",
      "\tpath = /Users/u/Library/LaunchAgents/io.aastar.dvt-committee-health.plist",
      "\tstate = not running",
      "",
      "\tprogram = /bin/bash",
      "\targuments = {",
      "\t\t/bin/bash",
      "\t\t/Users/u/repo/deploy/local-heartbeat.sh",
      "\t\thealth",
      "\t}",
      "",
      "\tworking directory = /Users/u/repo",
      "",
      "\tinherited environment = {",
      "\t\tSSH_AUTH_SOCK => /private/tmp/x/Listeners",
      "\t}",
      "",
      "\tdefault environment = {",
      "\t\tPATH => /usr/bin:/bin:/usr/sbin:/sbin",
      "\t}",
      "",
      "\tenvironment = {",
      "\t\tOSLogRateLimit => 64",
      "\t\tPATH => /opt/homebrew/bin:/usr/bin:/bin",
      "\t\tHOME => /Users/u",
      "\t\tXPC_SERVICE_NAME => io.aastar.dvt-committee-health",
      "\t}",
      "}",
    ].join("\n");
    const L = parseLaunchctlPrint(out);
    cell(
      "parseLaunchctlPrint: args, environment names, inherited names and working directory",
      L.args.join() === "/bin/bash,/Users/u/repo/deploy/local-heartbeat.sh,health" &&
        L.env.join() === "OSLogRateLimit,PATH,HOME,XPC_SERVICE_NAME" &&
        L.inherited.join() === "SSH_AUTH_SOCK" &&
        L.cwd === "/Users/u/repo",
      L
    );
    const stale = parseLaunchctlPrint(
      out.replace("\t\tHOME => /Users/u", "\t\tHOME => /Users/u\n\t\tBASH_ENV => /tmp/x")
    );
    cell(
      "parseLaunchctlPrint: a stale loaded BASH_ENV is visible to the reviewed check",
      stale.env.includes("BASH_ENV")
    );
  }
  {
    // the reviewed exception (DSR bc3be95b): label, FULL args, loaded == plist, env names, file hashes
    const r = {
      label: "io.aastar.dvt-committee-health",
      interpreter: "/bin/bash",
      wrapper: "deploy/local-heartbeat.sh",
      args: ["health"],
      envKeys: ["HOME", "PATH"],
      files: {
        "deploy/local-heartbeat.sh": "a".repeat(64),
        "deploy/committee-health.mjs": "b".repeat(64),
      },
    };
    const args = ["/bin/bash", "/r/deploy/local-heartbeat.sh", "health"];
    const plist = {
      Label: r.label,
      ProgramArguments: args,
      EnvironmentVariables: { HOME: "/h", PATH: "/p" },
    };
    const sha = path =>
      ({
        "/r/deploy/local-heartbeat.sh": "a".repeat(64),
        "/r/deploy/committee-health.mjs": "b".repeat(64),
      })[path] ?? null;
    // the detector's own (harmless) files live under /d/; everything else reads as a wrapper that
    // could run apply-rotation
    const txt = path =>
      String(path).startsWith("/usr/")
        ? { kind: "binary" }
        : String(path).startsWith("/d/")
          ? { kind: "text", text: "read only" }
          : { kind: "text", text: "apply) node deploy/apply-verifier-rotation.mjs --broadcast" };
    const LOADED_ENV = ["OSLogRateLimit", "PATH", "HOME", "XPC_SERVICE_NAME"];
    const run = (
      pl,
      loaded = args,
      s = sha,
      labels = [KEEPER_LABEL, DETECTOR_LABEL, r.label],
      env = LOADED_ENV,
      inherited = ["SSH_AUTH_SOCK"]
    ) =>
      launchdOff(
        labels,
        l =>
          l === DETECTOR_LABEL
            ? { args: ["/usr/bin/node", "/d/detector.mjs"], env: [], inherited: [] }
            : { args: loaded, env, inherited },
        txt,
        [r],
        s,
        { [r.label]: pl }
      );
    cell(
      "reviewed: a stale LOADED BASH_ENV fails even when the plist on disk lacks it (Codex R3 P2-2)",
      run(plist, args, sha, undefined, [...LOADED_ENV, "BASH_ENV"]).some(x =>
        x.includes("LOADED environment")
      ) &&
        run(plist, args, sha, undefined, [...LOADED_ENV, "BASH_ENV"]).some(x =>
          x.includes("start-up variable")
        )
    );
    cell(
      "reviewed: an inherited BASH_ENV (launchctl setenv) fails",
      run(plist, args, sha, undefined, LOADED_ENV, ["BASH_ENV"]).some(x =>
        x.includes("start-up variable")
      )
    );
    cell(
      "reviewed: NODE_OPTIONS or DYLD_* in the loaded or inherited environment fails (clestons L4)",
      run(plist, args, sha, undefined, [...LOADED_ENV, "NODE_OPTIONS"]).some(x =>
        x.includes("start-up variable")
      ) &&
        run(plist, args, sha, undefined, LOADED_ENV, ["DYLD_INSERT_LIBRARIES"]).some(x =>
          x.includes("start-up variable")
        )
    );
    cell(
      "reviewed: an unreadable loaded environment fails closed",
      launchdOff([DETECTOR_LABEL, r.label], () => args, txt, [r], sha, { [r.label]: plist }).some(
        x => x.includes("loaded environment cannot be read")
      )
    );
    cell(
      "reviewed: the exact plist, loaded args, env names and both file hashes pass",
      run(plist).length === 0,
      run(plist)
    );
    cell(
      "reviewed: another mode fails",
      run({ ...plist, ProgramArguments: ["/bin/bash", "/r/deploy/local-heartbeat.sh", "apply"] }, [
        "/bin/bash",
        "/r/deploy/local-heartbeat.sh",
        "apply",
      ]).length > 0
    );
    {
      const bashC = [
        "/bin/bash",
        "-c",
        "node deploy/apply-verifier-rotation.mjs --broadcast",
        "/r/deploy/local-heartbeat.sh",
        "health",
      ];
      cell(
        "reviewed: bash -c with the wrapper as mere argument data fails (Codex R2 P2-5)",
        run({ ...plist, ProgramArguments: bashC }, bashC).length > 0
      );
    }
    cell(
      "reviewed: an extra argument fails",
      run({ ...plist, ProgramArguments: [...args, "--x"] }, [...args, "--x"]).length > 0
    );
    cell(
      "reviewed: another interpreter fails",
      run({ ...plist, ProgramArguments: ["/bin/zsh", ...args.slice(1)] }, [
        "/bin/zsh",
        ...args.slice(1),
      ]).length > 0
    );
    cell(
      "reviewed: loaded args that differ from the plist fail",
      run(plist, ["/bin/bash", "/other/deploy/local-heartbeat.sh", "health"]).length > 0
    );
    cell(
      "reviewed: an extra environment variable (e.g. BASH_ENV) fails",
      run({ ...plist, EnvironmentVariables: { ...plist.EnvironmentVariables, BASH_ENV: "/tmp/x" } })
        .length > 0
    );
    cell(
      "reviewed: a changed wrapper hash fails",
      run(plist, args, p => (p.endsWith("local-heartbeat.sh") ? "c".repeat(64) : sha(p))).length > 0
    );
    cell(
      "reviewed: a changed committee-health.mjs hash fails",
      run(plist, args, p => (p.endsWith("committee-health.mjs") ? "c".repeat(64) : sha(p))).length >
        0
    );
    cell(
      "reviewed: no plist for the job fails",
      launchdOff([DETECTOR_LABEL, r.label], () => args, txt, [r], sha, {}).length > 0
    );
    cell(
      "reviewed: apply-rotation loaded still fails (the exception covers health only)",
      run(plist, args, sha, [
        KEEPER_LABEL,
        DETECTOR_LABEL,
        r.label,
        "io.aastar.dvt-apply-rotation",
      ]).some(x => x.includes("apply-rotation is loaded"))
    );
    cell(
      "reviewed: a forbidden label cannot be made an exception",
      launchdOff(
        [DETECTOR_LABEL],
        () => [],
        txt,
        [{ ...r, label: "io.aastar.dvt-committee-keeper" }],
        sha,
        {}
      ).some(x => x.includes("cannot be a reviewed"))
    );
  }
  {
    // preflight-reviewed.json must hash what the repository holds (DSR bc3be95b: changes only by a
    // PR that states the new hashes; this cell turns CI red when a reviewed file changes alone)
    const rv = JSON.parse(readFileSync(join(here, "preflight-reviewed.json"), "utf8"));
    const repo = join(here, "../..");
    const bad = rv.jobs.flatMap(j =>
      Object.entries(j.files)
        .filter(
          ([rel, h]) =>
            createHash("sha256")
              .update(readFileSync(join(repo, rel)))
              .digest("hex") !== h
        )
        .map(([rel]) => rel)
    );
    cell(
      "preflight-reviewed.json hashes equal the repository's reviewed files",
      bad.length === 0,
      bad
    );
  }
  cell(
    "node-slash-off fails on a missing container",
    nodeSlashOff(() => null, ["gone"]).length === 1
  );
}

// ---- the README states the cap and the funding rule
{
  const readme = readFileSync(join(here, "README.md"), "utf8");
  cell(
    "README names the per-chain caps and the funding rule",
    /0\.1 ETH/.test(readme) && /0\.02 ETH/.test(readme) && /DSR/.test(readme)
  );
}

let nf = 0;
for (const r of results) {
  console.log(`${r.ok ? "ok  " : "FAIL"} ${r.name}${r.ok ? "" : `\n     got ${r.got}`}`);
  if (!r.ok) nf++;
}
console.log(`\n${results.length - nf}/${results.length} cells`);
process.exit(nf ? 1 : 0);
