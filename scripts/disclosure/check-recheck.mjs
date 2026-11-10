// CI self-test for scripts/disclosure/recheck-lib.mjs against a stub chain (no RPC, no anvil).
//
// The stub aggregator derives its commitment the way SP's BLSAggregator does (mask bit i -> slot
// i+1 -> validatorAtSlot, insertion sort ascending), written out here with explicit abi types and NOT
// through recheck-lib's expectedCommitment, so a recheck that merely agrees with itself cannot pass.
//
// Each case is a control cell: correct entries must PASS and every forged entry must FAIL, and each
// failing case asserts WHICH check fired, so a recheck that fails for the wrong reason is caught too.
import { ethers } from "ethers";
import { Kind, aggIface, dvtIface, regIface, safeIface, recheckEntry } from "./recheck-lib.mjs";
import {
  ABI,
  AGG,
  REG,
  WRAPPER,
  SAFE,
  DVT,
  MULTISEND,
  FAKE_DVT,
  FORWARDERS,
  addr,
  G,
  G_NEW,
  spMessageHash,
  makeChain,
  slashF,
  slashIn,
  genF,
  genIn,
  qF,
  qIn,
  repF,
  repIn,
  withRequestCache,
} from "./stub-chain.mjs";

// ------------------------------------------------------------------ cases
const {
  chain,
  execute,
  disclose,
  setSlot,
  reorg,
  disclosureBlock,
  capRange,
  logCalls,
  overwrite,
  mineEmpty,
  reorgDuringNextCheck,
  head: headNow,
  dropParentHash,
  reorgDuringReceipt,
  revertedOnOrphan,
  reorgAfterSends,
  reorgHeadAfterCountRead,
  receiptWithoutStatus,
} = makeChain();
const results = [];
// want: "PASS" | { diff } (MISMATCH on that field) | { status, reason } | { unverified: {...} } (MATCH,
// with those claims reported back verbatim as unverified).
async function expectCase(name, entryId, want, opts = {}) {
  let r;
  try {
    r = await recheckEntry(opts.chain ?? chain, {
      registry: REG,
      aggregator: AGG,
      forwarders: opts.forwarders ?? FORWARDERS,
      entryId,
      page: opts.page,
      fromBlock: opts.fromBlock ?? 0,
      confirmations: opts.confirmations ?? 0,
    });
  } catch (e) {
    r = { status: "THREW", ok: false, reasons: [`${e.name}: ${e.message}`], diffs: [] };
  }
  let ok;
  if (want === "PASS") ok = r.status === "MATCH" && r.ok;
  else if (want.unverified)
    ok =
      r.status === "MATCH" &&
      Object.entries(want.unverified).every(
        ([k, v]) => r.unverified?.[k]?.toLowerCase() === v.toLowerCase()
      );
  else if (want.diff)
    ok = r.status === "MISMATCH" && !r.ok && r.diffs.some(d => d.field === want.diff);
  else ok = r.status === want.status && !r.ok && r.reasons.some(x => x.includes(want.reason));
  results.push({
    name,
    ok,
    want: JSON.stringify(want),
    got: JSON.stringify({ status: r.status, reasons: r.reasons, diffs: r.diffs.map(d => d.field) }),
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
  { status: "MISMATCH", reason: "no SignersCommitted for key" }
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
await expectCase("never-issued entry id is MISMATCH", 999n, {
  status: "MISMATCH",
  reason: "not issued as of block",
});

const aW = execute(Kind.SLASH, 11n, slashF, 0b011n, { to: WRAPPER });
await expectCase("wrapped action call is INCONCLUSIVE", disclose(Kind.SLASH, 11n, slashIn, aW), {
  status: "INCONCLUSIVE",
  reason: "wrapped",
});

// Codex M1: subjectToken is a claim. A MATCH must hand it back as unverified, never as verified.
const OTHER_TOKEN = addr("unrelated-community-token");
await expectCase(
  "unrelated subjectToken is reported unverified, not verified",
  disclose(Kind.SLASH, 7n, slashIn, aS, { subjectToken: OTHER_TOKEN }),
  { unverified: { subjectToken: OTHER_TOKEN } }
);

// Codex M3: a slot assignment that existed only inside the block (set by an earlier tx, undone by a
// later one) is in neither snapshot. Undecidable from snapshots: INCONCLUSIVE, not MISMATCH.
const aMid = execute(Kind.SLASH, 12n, slashF, 0b011n, {
  midSlots: { 1: G[0], 2: addr("transient") },
});
await expectCase(
  "intra-block slot change is INCONCLUSIVE",
  disclose(Kind.SLASH, 12n, slashIn, aMid),
  {
    status: "INCONCLUSIVE",
    reason: "inside the block",
  }
);

// Codex M2: reorgs. The action's block replaced by a sibling, and the disclosure's block replaced.
const aRe = execute(Kind.SLASH, 13n, slashF, 0b011n);
const eRe = disclose(Kind.SLASH, 13n, slashIn, aRe);
reorg(aRe.block);
await expectCase("action block reorged out is INCONCLUSIVE", eRe, {
  status: "INCONCLUSIVE",
  reason: "action receipt is not in the canonical chain",
});
const aRe2 = execute(Kind.SLASH, 14n, slashF, 0b011n);
const eRe2 = disclose(Kind.SLASH, 14n, slashIn, aRe2);
reorg(disclosureBlock(eRe2));
await expectCase("disclosure block reorged out is INCONCLUSIVE", eRe2, {
  status: "INCONCLUSIVE",
  reason: "Disclosed log is not in the canonical chain",
});

// Codex M2 (cont.): a reorg that happens WHILE the check runs is caught by the closing re-check.
const aRe3 = execute(Kind.SLASH, 15n, slashF, 0b011n);
const eRe3 = disclose(Kind.SLASH, 15n, slashIn, aRe3);
reorgDuringNextCheck(aRe3.block);
await expectCase("reorg during the check is INCONCLUSIVE", eRe3, {
  status: "INCONCLUSIVE",
  reason: "canonical chain changed during the check",
});

// All state is read at one snapshot (head - confirmations): a commitment overwritten after the
// snapshot does not change the verdict, and a pointer to an action newer than the snapshot is not
// judged on unconfirmed data.
const aSnap = execute(Kind.SLASH, 16n, slashF, 0b011n);
const eSnap = disclose(Kind.SLASH, 16n, slashIn, aSnap);
mineEmpty();
overwrite(aSnap.key);
await expectCase("reads pinned to the snapshot, not latest", eSnap, "PASS", { confirmations: 2 });
// Entry written at block D that points at an action executed later, at A = D + 1. With the snapshot
// at D (confirmations = 1) the action is not yet confirmed: INCONCLUSIVE, not judged on it.
{
  const D = headNow() + 1;
  const A = D + 1;
  const id = 18n;
  const mh = spMessageHash(Kind.SLASH, id, slashF);
  const placeholder = {
    hash: ethers.id(`action-${A}-${Kind.SLASH}-${id}`),
    key: id,
    mh,
    signers: [],
    anchor: ethers.ZeroHash,
    block: A,
    mask: 0b011n,
  };
  const eFwd = disclose(Kind.SLASH, id, slashIn, placeholder);
  const aFwd = execute(Kind.SLASH, id, slashF, 0b011n);
  if (aFwd.hash !== placeholder.hash)
    throw new Error("self-test setup: predicted action hash wrong");
  await expectCase(
    "entry pointing at an action newer than the snapshot is INCONCLUSIVE",
    eFwd,
    { status: "INCONCLUSIVE", reason: "newer than the confirmed snapshot" },
    { confirmations: 1 }
  );
}

// Codex round 2, M1: the closing canonical re-check must not be answered from a request cache.
const aC = execute(Kind.SLASH, 19n, slashF, 0b011n);
const eC = disclose(Kind.SLASH, 19n, slashIn, aC);
reorgDuringNextCheck(aC.block);
await expectCase(
  "mid-check reorg caught through a caching provider",
  eC,
  { status: "INCONCLUSIVE", reason: "canonical chain changed during the check" },
  { chain: withRequestCache(chain) }
);

// Codex round 2, M2: a provable contradiction must not hide behind INCONCLUSIVE.
const aW2 = execute(Kind.SLASH, 20n, slashF, 0b011n, { to: WRAPPER });
await expectCase(
  "wrapped action + wrong blockNumber is MISMATCH, not INCONCLUSIVE",
  disclose(Kind.SLASH, 20n, slashIn, aW2, { blockNumber: 0 }),
  { diff: "blockNumber" }
);
const aMid2 = execute(Kind.SLASH, 21n, slashF, 0b011n, {
  midSlots: { 1: G[0], 2: addr("transient2") },
});
await expectCase(
  "intra-block slots + wrong proposalId is MISMATCH, not INCONCLUSIVE",
  disclose(Kind.SLASH, 21n, slashIn, aMid2, { proposalId: 22n }),
  { diff: "proposalId" }
);

// Codex round 2, M3: an honest entry that is not yet confirmations-deep is pending, not wrong.
const aP = execute(Kind.SLASH, 23n, slashF, 0b011n);
await expectCase(
  "honest entry inside the unconfirmed tail is INCONCLUSIVE",
  disclose(Kind.SLASH, 23n, slashIn, aP),
  { status: "INCONCLUSIVE", reason: "not yet 3 confirmations deep" },
  { confirmations: 3 }
);

// Codex round 2, L4: invalid paging/range inputs are refused before any RPC, not looped on.
await expectCase(
  "page 0 is refused",
  1n,
  { status: "THREW", reason: "page must be a positive" },
  { page: 0 }
);
await expectCase(
  "negative confirmations refused",
  1n,
  { status: "THREW", reason: "confirmations must be" },
  { confirmations: -1 }
);

// Codex round 3, M1: absence and orphaned evidence are not accusations.
{
  const aX = execute(Kind.SLASH, 24n, slashF, 0b011n);
  const eX = disclose(Kind.SLASH, 24n, slashIn, aX, { txHash: ethers.id("no-such-tx") });
  await expectCase("entry naming a tx this RPC does not have is INCONCLUSIVE", eX, {
    status: "INCONCLUSIVE",
    reason: "not available from this RPC",
  });
  const aY = execute(Kind.SLASH, 25n, slashF, 0b011n);
  const eY = disclose(Kind.SLASH, 25n, slashIn, aY);
  reorgDuringReceipt([aY.block, disclosureBlock(eY)]);
  await expectCase("reorg while fetching the receipt (null) is INCONCLUSIVE", eY, {
    status: "INCONCLUSIVE",
    reason: "not available from this RPC",
  });
  const aZ = execute(Kind.SLASH, 26n, slashF, 0b011n);
  const eZ = disclose(Kind.SLASH, 26n, slashIn, aZ);
  revertedOnOrphan(aZ.hash, aZ.block);
  await expectCase("reverted receipt from an orphaned block is INCONCLUSIVE", eZ, {
    status: "INCONCLUSIVE",
    reason: "not in the canonical chain",
  });
  const aRv = execute(Kind.SLASH, 27n, slashF, 0b011n, { status: 0 });
  await expectCase(
    "canonical reverted action is MISMATCH",
    disclose(Kind.SLASH, 27n, slashIn, aRv),
    {
      status: "MISMATCH",
      reason: "action tx reverted",
    }
  );
  // An issued entry whose log the search window misses is not proof it is absent.
  await expectCase(
    "issued entry outside the searched range is INCONCLUSIVE",
    1n,
    { status: "INCONCLUSIVE", reason: "but no Disclosed log was found" },
    { fromBlock: headNow() }
  );
}

// A MISMATCH found on the action side is re-confirmed: reads 1 = disclosure log, 2 = action
// header; a reorg right after read 2 must turn the verdict INCONCLUSIVE, whichever block moved.
{
  const aM = execute(Kind.SLASH, 29n, slashF, 0b011n);
  const eM = disclose(Kind.SLASH, 29n, slashIn, aM, { txHash: aG.hash }); // provably wrong pointer
  reorgAfterSends(2, aG.block);
  await expectCase("action reorged after a MISMATCH was found is INCONCLUSIVE", eM, {
    status: "INCONCLUSIVE",
    reason: "canonical chain changed during the check",
  });
  const aOther = execute(Kind.GENERIC, 30n, genF, 0b111n); // fresh target: the cell above reorged aG
  const eM2 = disclose(Kind.SLASH, 29n, slashIn, aM, { txHash: aOther.hash });
  reorgAfterSends(2, disclosureBlock(eM2));
  await expectCase("disclosure reorged after a MISMATCH was found is INCONCLUSIVE", eM2, {
    status: "INCONCLUSIVE",
    reason: "canonical chain changed during the check",
  });
}

// Codex round 3, M2: a missing parent header is a missing fact, not an anchor contradiction.
{
  const aH = execute(Kind.SLASH, 28n, slashF, 0b011n, { to: WRAPPER });
  const eH = disclose(Kind.SLASH, 28n, slashIn, aH);
  dropParentHash(aH.block);
  await expectCase("wrapped action with no parent header is INCONCLUSIVE, not MISMATCH", eH, {
    status: "INCONCLUSIVE",
    reason: "no parentHash",
  });
}

// Codex round 4: the "not issued" verdict is reorg-safe; a missing receipt status or a missing
// parentHash on a TOP-LEVEL action is missing data, never an accusation or a crash.
reorgHeadAfterCountRead();
await expectCase("reorg during the entryCount read is INCONCLUSIVE", 998n, {
  status: "INCONCLUSIVE",
  reason: "canonical chain changed during the check",
});
{
  const aN = execute(Kind.SLASH, 31n, slashF, 0b011n);
  const eN = disclose(Kind.SLASH, 31n, slashIn, aN);
  receiptWithoutStatus();
  await expectCase("receipt without status is INCONCLUSIVE, not 'reverted'", eN, {
    status: "INCONCLUSIVE",
    reason: "no valid status",
  });
  const aT = execute(Kind.SLASH, 32n, slashF, 0b011n);
  const eT = disclose(Kind.SLASH, 32n, slashIn, aT);
  dropParentHash(aT.block);
  await expectCase("top-level action with no parent header is INCONCLUSIVE", eT, {
    status: "INCONCLUSIVE",
    reason: "no parentHash",
  });
  const aT2 = execute(Kind.SLASH, 33n, slashF, 0b011n);
  const eT2 = disclose(Kind.SLASH, 33n, slashIn, aT2, { proposalId: 34n });
  dropParentHash(aT2.block);
  await expectCase("…and a wrong proposalId there is still MISMATCH", eT2, { diff: "proposalId" });
}

// Codex round 5, L1: a provider without raw send cannot prove absence by counter.
{
  const noSend = { ...chain };
  delete noSend.send;
  await expectCase(
    "never-issued id through a provider without send is INCONCLUSIVE",
    997n,
    { status: "INCONCLUSIVE", reason: "cannot read state by block hash" },
    { chain: noSend }
  );
  await expectCase(
    "entry id 0 is MISMATCH on any provider",
    0n,
    { status: "MISMATCH", reason: "entry id 0" },
    { chain: noSend }
  );
}

// ---------------------------------------------------------------- forwarder routes (M0 §4.4, DSR)
// A real action is almost never a top-level aggregator call: slash/queue go through DVTValidator,
// the owner route through the Safe. Each route is followed only at its manifest-pinned address.
{
  const r = (route, extra = {}) => ({ via: { route, ...extra } });
  const aD = execute(Kind.SLASH, 40n, slashF, 0b011n, r("dvt"));
  await expectCase(
    "DVTValidator.executeWithProof route (fields from proposals@N-1)",
    disclose(Kind.SLASH, 40n, slashIn, aD),
    "PASS"
  );
  const aDq = execute(Kind.QUEUE, 0n, { ...qF, epoch: 50n }, 0b110n, r("dvt"));
  const qIn50 = ABI.encode(["address", "uint8", "uint256"], [qF.operator, qF.slashLevel, 50n]);
  await expectCase(
    "DVTValidator.queueSlashWithProof route",
    disclose(Kind.QUEUE, 0n, qIn50, aDq),
    "PASS"
  );
  const aDr = execute(Kind.REPUTATION, 41n, repF, 0b111n, r("dvt"));
  await expectCase(
    "DVTValidator route, reputation batch",
    disclose(Kind.REPUTATION, 41n, repIn, aDr),
    "PASS"
  );
  const aDf = execute(Kind.SLASH, 42n, slashF, 0b011n, r("dvt"));
  await expectCase(
    "DVTValidator route + forged messageInputs is MISMATCH",
    disclose(
      Kind.SLASH,
      42n,
      ABI.encode(
        ["address", "uint8", "uint256", "bytes32"],
        [slashF.operator, 2, slashF.epoch, slashF.evidenceHash]
      ),
      aDf
    ),
    { diff: "signed.messageInputs" }
  );
  const aDs = execute(Kind.SLASH, 43n, slashF, 0b011n, r("dvt", { createdAt: headNow() + 1 }));
  await expectCase(
    "DVTValidator proposal created in the same block is INCONCLUSIVE",
    disclose(Kind.SLASH, 43n, slashIn, aDs),
    {
      status: "INCONCLUSIVE",
      reason: "did not exist at block",
    }
  );
  const aFk = execute(Kind.SLASH, 44n, slashF, 0b011n, r("fake-dvt"));
  await expectCase(
    "DVTValidator selector at an UNPINNED address is INCONCLUSIVE",
    disclose(Kind.SLASH, 44n, slashIn, aFk),
    {
      status: "INCONCLUSIVE",
      reason: "not pin",
    }
  );
  const aDu = execute(Kind.SLASH, 45n, slashF, 0b011n, r("dvt"));
  await expectCase(
    "DVTValidator route with the forwarder NOT pinned is INCONCLUSIVE",
    disclose(Kind.SLASH, 45n, slashIn, aDu),
    { status: "INCONCLUSIVE", reason: "not pin" },
    { forwarders: { ownerSafe: SAFE } }
  );
  const aS1 = execute(Kind.GENERIC, 46n, genF, 0b111n, r("safe"));
  await expectCase(
    "owner Safe execTransaction (CALL) route",
    disclose(Kind.GENERIC, 46n, genIn, aS1),
    "PASS"
  );
  const aS2 = execute(Kind.SLASH, 47n, slashF, 0b011n, r("safe-delegate"));
  await expectCase(
    "Safe DELEGATECALL (not MultiSendCallOnly) is INCONCLUSIVE",
    disclose(Kind.SLASH, 47n, slashIn, aS2),
    {
      status: "INCONCLUSIVE",
      reason: "DELEGATECALL",
    }
  );
  const aM1 = execute(Kind.GENERIC, 48n, genF, 0b111n, r("multisend", { subs: [0] }));
  await expectCase(
    "Safe -> pinned MultiSendCallOnly, all CALL sub-txs",
    disclose(Kind.GENERIC, 48n, genIn, aM1),
    "PASS"
  );
  // A batch that also carries an unrelated aggregator call: only the call whose key matches counts.
  const otherCall = aggIface.encodeFunctionData("executeProposal", [
    99n,
    genF.target,
    "0xabcdef",
    3n,
    "0x",
  ]);
  const aM3 = execute(
    Kind.GENERIC,
    54n,
    genF,
    0b111n,
    r("multisend", { subs: [0], extraAgg: otherCall })
  );
  await expectCase(
    "MultiSend with a second, non-matching aggregator call",
    disclose(Kind.GENERIC, 54n, genIn, aM3),
    "PASS"
  );
  // Codex review of 022d80db.
  // H: a Safe inner call is not proven (execTransaction does not revert on inner failure). One
  // carrying a different message under the honest action's key must not accuse the honest entry.
  const otherMsg = aggIface.encodeFunctionData("executeProposal", [
    60n,
    genF.target,
    "0x99",
    3n,
    "0x",
  ]);
  const aH = execute(Kind.GENERIC, 60n, genF, 0b111n, r("safe", { inner: otherMsg }));
  await expectCase(
    "unauthenticated Safe inner call cannot accuse an honest entry",
    disclose(Kind.GENERIC, 60n, genIn, aH),
    {
      status: "INCONCLUSIVE",
      reason: "no recovered call is authenticated",
    }
  );
  // M1: two candidates under one key, only one authenticates -> that one is used. The second is a
  // nested Safe execTransaction whose inner call fails: with a nonzero safeTxGas (Safe v1.3.0
  // GnosisSafe.sol L168-170 reverts GS013 only when safeTxGas == 0 && gasPrice == 0) it returns
  // false without reverting, so the batch (and the honest call before it) still succeeds.
  const nestedFail = {
    op: 0,
    to: SAFE,
    data: safeIface.encodeFunctionData("execTransaction", [
      AGG,
      0,
      aggIface.encodeFunctionData("executeProposal", [61n, genF.target, "0x77", 3n, "0x"]),
      0,
      100000,
      0,
      0,
      ethers.ZeroAddress,
      ethers.ZeroAddress,
      "0x",
    ]),
  };
  const aTwo = execute(
    Kind.GENERIC,
    61n,
    genF,
    0b111n,
    r("multisend", { subs: [0], extraSub: nestedFail })
  );
  await expectCase(
    "same-key candidates (one inside a failing nested Safe call): the authenticated one is used",
    disclose(Kind.GENERIC, 61n, genIn, aTwo),
    "PASS"
  );
  // M3: a batch with any non-CALL sub-tx is skipped whole (MultiSendCallOnly would revert it).
  const aMix = execute(Kind.GENERIC, 62n, genF, 0b111n, r("multisend", { subs: [0, 1] }));
  await expectCase(
    "mixed CALL/DELEGATECALL MultiSend batch is skipped whole",
    disclose(Kind.GENERIC, 62n, genIn, aMix),
    {
      status: "INCONCLUSIVE",
      reason: "batch skipped",
    }
  );
  // M2: the trace walk enforces the module-route rule too.
  const aTm = execute(Kind.GENERIC, 63n, genF, 0b111n, r("trace-module"));
  await expectCase(
    "trace through a Safe module route is INCONCLUSIVE",
    disclose(Kind.GENERIC, 63n, genIn, aTm),
    {
      status: "INCONCLUSIVE",
      reason: "module route not followed",
    }
  );
  // Codex R2 Medium: a DVTValidator-derived candidate is not proven (its BLS_AGGREGATOR is mutable),
  // so when it does not reproduce the commitment it must not accuse: INCONCLUSIVE, not MISMATCH.
  {
    const aDv = execute(
      Kind.SLASH,
      65n,
      slashF,
      0b011n,
      r("dvt", { overrideProposal: { ...slashF, slashLevel: 2 } })
    );
    await expectCase(
      "unauthenticated DVTValidator candidate cannot accuse an honest entry",
      disclose(Kind.SLASH, 65n, slashIn, aDv),
      {
        status: "INCONCLUSIVE",
        reason: "no recovered call is authenticated",
      }
    );
  }
  const aTdg = execute(Kind.GENERIC, 64n, genF, 0b111n, r("trace-delegate"));
  await expectCase(
    "trace: aggregator call under a non-MultiSend DELEGATECALL is INCONCLUSIVE",
    disclose(Kind.GENERIC, 64n, genIn, aTdg),
    {
      status: "INCONCLUSIVE",
      reason: "DELEGATECALL subtree not followed",
    }
  );
  const aM2 = execute(Kind.GENERIC, 49n, genF, 0b111n, r("multisend", { subs: [1] }));
  await expectCase(
    "MultiSend sub-tx by DELEGATECALL is INCONCLUSIVE",
    disclose(Kind.GENERIC, 49n, genIn, aM2),
    {
      status: "INCONCLUSIVE",
      reason: "DELEGATECALL is not followed",
    }
  );
  const aMo = execute(Kind.GENERIC, 50n, genF, 0b111n, r("module"));
  await expectCase("Safe module route is INCONCLUSIVE", disclose(Kind.GENERIC, 50n, genIn, aMo), {
    status: "INCONCLUSIVE",
    reason: "module route",
  });
  const aT = execute(Kind.SLASH, 51n, slashF, 0b011n, r("trace"));
  await expectCase(
    "unpinned wrapper + callTracer frame to the aggregator",
    disclose(Kind.SLASH, 51n, slashIn, aT),
    "PASS"
  );
  const aTd = execute(Kind.SLASH, 52n, slashF, 0b011n, r("trace", { dvt: true }));
  await expectCase(
    "unpinned wrapper + trace through the pinned DVTValidator",
    disclose(Kind.SLASH, 52n, slashIn, aTd),
    "PASS"
  );
  const aTs = execute(Kind.SLASH, 53n, slashF, 0b011n, r("trace", { frameType: "STATICCALL" }));
  await expectCase(
    "trace frame that is not a CALL is not decoded",
    disclose(Kind.SLASH, 53n, slashIn, aTs),
    {
      status: "INCONCLUSIVE",
      reason: "no aggregator call recoverable",
    }
  );
}

// DSR follow-up to #396: an entry logged in the pre-#396 flat 13-argument event shape is never
// returned by the topic filter (INCONCLUSIVE, never MATCH), and its data does not decode.
{
  const OLD = new ethers.Interface([
    "event Disclosed(uint256 indexed entryId, uint8 indexed kind, uint256 indexed key, uint256 proposalId, bytes32 messageHash, address[] signers, address subjectToken, bytes32 txHash, uint64 blockNumber, bool blockVerified, bytes20 rulesetCommit, string recordURI, bytes32 recordHash)",
  ]);
  const oldTopic = OLD.getEvent("Disclosed").topicHash;
  results.push({
    name: "old flat event topic differs from the current one",
    ok: oldTopic !== regIface.getEvent("Disclosed").topicHash,
    want: "different topics",
    got: oldTopic,
  });
  const ev = OLD.encodeEventLog("Disclosed", [
    1n,
    0,
    7n,
    7n,
    ethers.id("m"),
    [],
    ethers.ZeroAddress,
    ethers.id("tx"),
    5n,
    true,
    "0x" + "ab".repeat(20),
    "u",
    ethers.id("r"),
  ]);
  let threw = false;
  try {
    regIface.decodeEventLog("Disclosed", ev.data, [
      regIface.getEvent("Disclosed").topicHash,
      ...ev.topics.slice(1),
    ]);
  } catch {
    threw = true;
  }
  results.push({
    name: "old flat event data does not decode as the current event",
    ok: threw,
    want: "throws",
    got: String(threw),
  });
  const oldOnly = {
    ...chain,
    async getLogs({ topics }) {
      return [
        {
          address: REG,
          topics: ev.topics,
          data: ev.data,
          blockNumber: 5,
          blockHash: ethers.id("block-5"),
          transactionHash: ethers.id("d"),
        },
      ].filter(l => l.topics[0] === topics[0] && l.topics[1] === topics[1]);
    },
  };
  await expectCase(
    "an old-shape log is never treated as an entry",
    1n,
    { status: "INCONCLUSIVE", reason: "no Disclosed log was found" },
    { chain: oldOnly }
  );
}

// Codex L4: a range-capped RPC still finds the entry (pages halve until they fit), across pages.
capRange(16);
const before = logCalls();
await expectCase("range-capped RPC: paged log search finds the entry", 1n, "PASS", { page: 64 });
const paged = logCalls() - before;
results.push({
  name: "paging actually split the range",
  ok: paged > 2,
  want: ">2 getLogs calls",
  got: String(paged),
});
capRange(Infinity);

let failed = 0;
for (const r of results) {
  console.log(
    `${r.ok ? "ok  " : "FAIL"} ${r.name}${r.ok ? "" : `\n     want ${r.want}\n     got  ${r.got}`}`
  );
  if (!r.ok) failed++;
}
const honest = results.filter(r => r.want === '"PASS"' || r.want.includes('"unverified"')).length;
console.log(
  `\n${results.length - failed}/${results.length} cells (${honest} must-pass, ${results.length - honest} must-fail)`
);
if (honest === 0 || honest === results.length) {
  console.log("FAIL: a recheck self-test needs both pass and fail cells");
  process.exit(1);
}
process.exit(failed ? 1 : 0);
