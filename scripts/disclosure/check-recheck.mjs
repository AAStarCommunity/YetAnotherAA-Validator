// CI self-test for scripts/disclosure/recheck-lib.mjs against a stub chain (no RPC, no anvil).
//
// The stub aggregator derives its commitment the way SP's BLSAggregator does (mask bit i -> slot
// i+1 -> validatorAtSlot, insertion sort ascending), written out here with explicit abi types and NOT
// through recheck-lib's expectedCommitment, so a recheck that merely agrees with itself cannot pass.
//
// Each case is a control cell: correct entries must PASS and every forged entry must FAIL, and each
// failing case asserts WHICH check fired, so a recheck that fails for the wrong reason is caught too.
import { ethers } from "ethers";
import { Kind, aggIface, regIface, recheckEntry } from "./recheck-lib.mjs";

const ABI = ethers.AbiCoder.defaultAbiCoder();
const AGG = ethers.getAddress("0x00000000000000000000000000000000000a6600");
const REG = ethers.getAddress("0x00000000000000000000000000000000000d1500");
const WRAPPER = ethers.getAddress("0x00000000000000000000000000000000000bad00");
const WATCHER = ethers.getAddress("0x0000000000000000000000000000000000000777");
const SAFE = ethers.getAddress("0x0000000000000000000000000000000000005afe");
const DS = ethers.id("stub-domain-separator");

const addr = s => ethers.getAddress(ethers.dataSlice(ethers.id(s), 12));
const G = [addr("g1"), addr("g2"), addr("g3")]; // unsorted by construction of keccak
const G_NEW = addr("g2-replacement");

// ------------------------------------------------------------------ independent SP-side derivation
function spMessageHash(kind, id, f) {
  if (kind === Kind.SLASH)
    return ethers.keccak256(
      ABI.encode(
        ["bytes32", "bytes32", "uint256", "address", "uint8", "uint256", "bytes32"],
        [
          DS,
          ethers.id("SuperPaymaster.BLS.ExecuteSlash.v1"),
          id,
          f.operator,
          f.slashLevel,
          f.epoch,
          f.evidenceHash,
        ]
      )
    );
  if (kind === Kind.GENERIC)
    return ethers.keccak256(
      ABI.encode(
        ["bytes32", "bytes32", "uint256", "address", "bytes32", "uint256"],
        [
          DS,
          ethers.id("SuperPaymaster.BLS.Proposal.v1"),
          id,
          f.target,
          ethers.keccak256(f.callData),
          f.requiredThreshold,
        ]
      )
    );
  if (kind === Kind.QUEUE)
    return ethers.keccak256(
      ABI.encode(
        ["bytes32", "bytes32", "address", "uint8", "uint256"],
        [DS, ethers.id("SuperPaymaster.BLS.QueueSlash.v1"), f.operator, f.slashLevel, f.epoch]
      )
    );
  return ethers.keccak256(
    ABI.encode(
      ["bytes32", "bytes32", "uint256", "address[]", "uint256[]", "uint256"],
      [DS, ethers.id("SuperPaymaster.BLS.Reputation.v1"), id, f.users, f.newScores, f.epoch]
    )
  );
}
function spKey(kind, id, mh) {
  if (kind === Kind.GENERIC)
    return BigInt(
      ethers.keccak256(
        ABI.encode(["bytes32", "uint256"], [ethers.id("SuperPaymaster.BLS.Proposal.v1"), id])
      )
    );
  if (kind === Kind.QUEUE) return BigInt(mh);
  return BigInt(id);
}
function spSigners(slots, mask) {
  const s = [];
  for (let slot = 1; slot <= 255; slot++) if ((mask >> BigInt(slot - 1)) & 1n) s.push(slots[slot]);
  for (let i = 1; i < s.length; i++) {
    const k = s[i];
    let j = i;
    while (j > 0 && BigInt(s[j - 1]) > BigInt(k)) {
      s[j] = s[j - 1];
      j--;
    }
    s[j] = k;
  }
  return s;
}

// ------------------------------------------------------------------ stub chain
function makeChain() {
  const blocks = new Map(); // number -> { hash, slots }
  const txs = new Map(); // hash -> { tx, receipt }
  const commitments = new Map(); // key -> bytes32
  const logs = [];
  let head = 100;
  let slots = { 1: G[0], 2: G[1], 3: G[2] };
  const snapshot = () => ({ ...slots });
  for (let n = 0; n <= head; n++)
    blocks.set(n, { hash: ethers.id(`block-${n}`), slots: snapshot() });

  const mine = () => {
    head++;
    blocks.set(head, { hash: ethers.id(`block-${head}`), slots: snapshot() });
    return head;
  };
  const slotsAt = tag => blocks.get(tag === "latest" ? head : Number(tag)).slots;

  const chain = {
    async getTransaction(h) {
      return txs.get(h)?.tx ?? null;
    },
    async getTransactionReceipt(h) {
      return txs.get(h)?.receipt ?? null;
    },
    async getBlock(n) {
      return blocks.get(Number(n)) ?? null;
    },
    async getLogs({ address, topics }) {
      return logs.filter(
        l => l.address === address && topics.every((t, i) => t == null || l.topics[i] === t)
      );
    },
    async call({ to, data, blockTag }) {
      if (to !== AGG) throw new Error("call to unknown contract");
      const p = aggIface.parseTransaction({ data });
      if (p.name === "domainSeparator") return aggIface.encodeFunctionResult(p.name, [DS]);
      if (p.name === "validatorAtSlot")
        return aggIface.encodeFunctionResult(p.name, [
          slotsAt(blockTag)[Number(p.args[0])] ?? ethers.ZeroAddress,
        ]);
      if (p.name === "proposalSignersCommitment")
        return aggIface.encodeFunctionResult(p.name, [
          commitments.get(BigInt(p.args[0])) ?? ethers.ZeroHash,
        ]);
      throw new Error(`stub: ${p.name}`);
    },
  };

  /** Execute one action as SP would: commitment over pre-block slots, SignersCommitted log. */
  function execute(kind, id, f, mask, { to = AGG, from = SAFE } = {}) {
    const n = mine();
    const pre = blocks.get(n - 1).slots;
    const mh = spMessageHash(kind, id, f);
    const key = spKey(kind, id, mh);
    const signers = spSigners(pre, mask);
    const anchor = blocks.get(n - 1).hash;
    commitments.set(
      key,
      ethers.keccak256(
        ABI.encode(
          ["bytes32", "bytes32", "uint256", "bytes32", "uint256", "address[]", "bytes32"],
          [DS, ethers.id("SuperPaymaster.BLS.SignersCommitment.v1"), key, mh, mask, signers, anchor]
        )
      )
    );
    let data;
    if (kind === Kind.SLASH)
      data = aggIface.encodeFunctionData("verifyAndExecute", [
        id,
        f.operator,
        f.slashLevel,
        [],
        [],
        f.epoch,
        f.evidenceHash,
        "0x",
      ]);
    if (kind === Kind.REPUTATION)
      data = aggIface.encodeFunctionData("verifyAndExecute", [
        id,
        ethers.ZeroAddress,
        0,
        f.users,
        f.newScores,
        f.epoch,
        ethers.ZeroHash,
        "0x",
      ]);
    if (kind === Kind.GENERIC)
      data = aggIface.encodeFunctionData("executeProposal", [
        id,
        f.target,
        f.callData,
        f.requiredThreshold,
        "0x",
      ]);
    if (kind === Kind.QUEUE)
      data = aggIface.encodeFunctionData("queueSlashWithConsensus", [
        f.operator,
        f.slashLevel,
        f.epoch,
        "0x",
      ]);
    if (to !== AGG) data = ethers.concat(["0xdeadbeef", data]); // a wrapper contract's own calldata
    const hash = ethers.id(`action-${n}-${kind}-${id}`);
    const ev = aggIface.encodeEventLog("SignersCommitted", [key, mask]);
    txs.set(hash, {
      tx: { hash, to, from, data },
      receipt: {
        status: 1,
        blockNumber: n,
        logs: [{ address: AGG, topics: ev.topics, data: ev.data }],
      },
    });
    return { hash, key, mh, signers, anchor, block: n, mask };
  }

  /** Write an entry as the watcher would (honest unless `forge` overrides fields). */
  let entryCount = 0;
  function disclose(kind, id, inputs, act, forge = {}) {
    const n = mine();
    const entryId = BigInt(++entryCount);
    const e = {
      kind,
      key: act.key,
      proposalId: kind === Kind.QUEUE ? 0n : id,
      messageHash: act.mh,
      signers: act.signers,
      subjectToken: ethers.ZeroAddress,
      txHash: act.hash,
      blockNumber: act.block,
      blockVerified: true,
      rulesetCommit: "0x" + "ab".repeat(20),
      recordURI: "ipfs://record",
      recordHash: ethers.id("record"),
      ...forge,
    };
    const s = {
      kind,
      proposalId: e.proposalId,
      messageInputs: inputs,
      signerMask: forge.signerMask ?? act.mask,
      signers: e.signers,
      anchor: forge.anchor ?? act.anchor,
    };
    const ev = regIface.encodeEventLog("Disclosed", [
      entryId,
      e.kind,
      e.key,
      e.proposalId,
      e.messageHash,
      e.signers,
      e.subjectToken,
      e.txHash,
      e.blockNumber,
      e.blockVerified,
      e.rulesetCommit,
      e.recordURI,
      e.recordHash,
    ]);
    const hash = ethers.id(`disclose-${entryId}`);
    const data = regIface.encodeFunctionData("disclose", [
      s,
      e.subjectToken,
      e.txHash,
      e.blockNumber,
      e.rulesetCommit,
      e.recordURI,
      e.recordHash,
    ]);
    txs.set(hash, {
      tx: { hash, to: REG, from: WATCHER, data },
      receipt: { status: 1, blockNumber: n, logs: [] },
    });
    logs.push({ address: REG, topics: ev.topics, data: ev.data, transactionHash: hash });
    return entryId;
  }

  return { chain, execute, disclose, setSlot: (s, v) => (slots[s] = v) };
}

// ------------------------------------------------------------------ fixtures
const slashF = {
  operator: addr("op"),
  slashLevel: 1,
  epoch: 42n,
  evidenceHash: ethers.id("evidence"),
};
const slashIn = ABI.encode(
  ["address", "uint8", "uint256", "bytes32"],
  [slashF.operator, slashF.slashLevel, slashF.epoch, slashF.evidenceHash]
);
const genF = { target: addr("registry"), callData: "0x12345678", requiredThreshold: 3n };
const genIn = ABI.encode(
  ["address", "bytes32", "uint256"],
  [genF.target, ethers.keccak256(genF.callData), genF.requiredThreshold]
);
const qF = { operator: addr("op"), slashLevel: 2, epoch: 43n };
const qIn = ABI.encode(["address", "uint8", "uint256"], [qF.operator, qF.slashLevel, qF.epoch]);
const repF = { users: [addr("u1"), addr("u2")], newScores: [10n, 20n], epoch: 44n };
const repIn = ABI.encode(
  ["address[]", "uint256[]", "uint256"],
  [repF.users, repF.newScores, repF.epoch]
);

// ------------------------------------------------------------------ cases
const { chain, execute, disclose, setSlot } = makeChain();
const results = [];
async function expectCase(name, entryId, want) {
  const r = await recheckEntry(chain, { registry: REG, aggregator: AGG, entryId });
  let ok;
  if (want === "PASS") ok = r.ok;
  else if (want.diff) ok = !r.ok && r.diffs.some(d => d.field === want.diff);
  else ok = !r.ok && r.reasons.some(x => x.includes(want.reason));
  results.push({
    name,
    ok,
    want: JSON.stringify(want),
    got: JSON.stringify({ ok: r.ok, reasons: r.reasons, diffs: r.diffs.map(d => d.field) }),
  });
}

const aS = execute(Kind.SLASH, 7n, slashF, 0b011n);
const aG = execute(Kind.GENERIC, 5n, genF, 0b111n);
const aQ = execute(Kind.QUEUE, 0n, qF, 0b110n);
const aR = execute(Kind.REPUTATION, 9n, repF, 0b111n);
await expectCase("honest SLASH entry", disclose(Kind.SLASH, 7n, slashIn, aS), "PASS");
await expectCase("honest GENERIC entry", disclose(Kind.GENERIC, 5n, genIn, aG), "PASS");
await expectCase("honest QUEUE entry", disclose(Kind.QUEUE, 0n, qIn, aQ), "PASS");
await expectCase("honest REPUTATION entry", disclose(Kind.REPUTATION, 9n, repIn, aR), "PASS");

// Slots change after execution: the recheck must use historical slot state, not latest.
setSlot(2, G_NEW);
const aS2 = execute(Kind.SLASH, 8n, slashF, 0b011n); // mined after the change; G_NEW signs this one
await expectCase(
  "slot re-registered after execution (historical state used)",
  disclose(Kind.SLASH, 7n, slashIn, aS),
  "PASS"
);
await expectCase(
  "honest entry after the slot change",
  disclose(Kind.SLASH, 8n, slashIn, aS2),
  "PASS"
);

// Forged entries: each must be caught, by the check named.
await expectCase(
  "forged txHash (points at another action)",
  disclose(Kind.SLASH, 7n, slashIn, aS, { txHash: aG.hash }),
  { reason: "no SignersCommitted for key" }
);
await expectCase(
  "forged blockNumber",
  disclose(Kind.SLASH, 7n, slashIn, aS, { blockNumber: aS.block + 1 }),
  { diff: "blockNumber" }
);
await expectCase(
  "forged signer list",
  disclose(Kind.SLASH, 7n, slashIn, aS, { signers: [G[2], G[0]].sort() }),
  { diff: "signers" }
);
await expectCase(
  "forged messageHash",
  disclose(Kind.SLASH, 7n, slashIn, aS, { messageHash: ethers.id("x") }),
  { diff: "messageHash" }
);
await expectCase("forged proposalId", disclose(Kind.SLASH, 7n, slashIn, aS, { proposalId: 70n }), {
  diff: "proposalId",
});
await expectCase("forged kind", disclose(Kind.SLASH, 7n, slashIn, aS, { kind: Kind.REPUTATION }), {
  diff: "kind",
});
await expectCase("forged messageInputs in disclose calldata", disclose(Kind.SLASH, 7n, qIn, aS), {
  diff: "signed.messageInputs",
});
await expectCase(
  "forged anchor in disclose calldata",
  disclose(Kind.SLASH, 7n, slashIn, aS, { anchor: ethers.id("y") }),
  { diff: "signed.anchor" }
);
await expectCase("missing entry", 999n, { reason: "expected one Disclosed log" });

const aW = execute(Kind.SLASH, 11n, slashF, 0b011n, { to: WRAPPER });
await expectCase("wrapped action call fails closed", disclose(Kind.SLASH, 11n, slashIn, aW), {
  reason: "wrapped",
});

let failed = 0;
for (const r of results) {
  console.log(
    `${r.ok ? "ok  " : "FAIL"} ${r.name}${r.ok ? "" : `\n     want ${r.want}\n     got  ${r.got}`}`
  );
  if (!r.ok) failed++;
}
const honest = results.filter(r => r.want === '"PASS"').length;
console.log(
  `\n${results.length - failed}/${results.length} cells (${honest} must-pass, ${results.length - honest} must-fail)`
);
if (honest === 0 || honest === results.length) {
  console.log("FAIL: a recheck self-test needs both pass and fail cells");
  process.exit(1);
}
process.exit(failed ? 1 : 0);
