// Independent recheck of a DisclosureRegistry entry (M0 §4.4, DSR constraint): rebuild the entry
// from the ACTION transaction alone — RPC reads of the chain and the aggregator, nothing from DVT
// state, nothing from the registry's own view functions — and compare field by field.
//
// The encoding here is a second implementation of SuperPaymaster BLSAggregator-4.13.0 (rc.8 r3b),
// written from SP source, not from DisclosureRegistry.sol. contracts/test/DisclosureRecheckParity.t.sol
// checks the two against the shared vectors in contracts/test/fixtures/disclosure-vectors.json.
//
// Every function takes a `chain` with four methods, which an ethers v6 JsonRpcProvider satisfies:
//   getTransaction(hash), getTransactionReceipt(hash), getBlock(number), call({ to, data, blockTag })
import { ethers } from "ethers";

const ABI = ethers.AbiCoder.defaultAbiCoder();

export const TAG = {
  QUEUE_SLASH: ethers.id("SuperPaymaster.BLS.QueueSlash.v1"),
  EXECUTE_SLASH: ethers.id("SuperPaymaster.BLS.ExecuteSlash.v1"),
  REPUTATION: ethers.id("SuperPaymaster.BLS.Reputation.v1"),
  PROPOSAL: ethers.id("SuperPaymaster.BLS.Proposal.v1"),
  SIGNERS_COMMITMENT: ethers.id("SuperPaymaster.BLS.SignersCommitment.v1"),
};

/** Same order as DisclosureRegistry.Kind. */
export const Kind = { SLASH: 0, GENERIC: 1, QUEUE: 2, REPUTATION: 3 };
export const KIND_NAME = ["SLASH", "GENERIC", "QUEUE", "REPUTATION"];

export const RAW_ID_BOUND = 1n << 128n;
/** SP rc.8 r3a raises MAX_VALIDATORS to 64; scan every bit a uint256 mask can carry. */
export const MAX_SLOT = 256;

export const AGGREGATOR_ABI = [
  "function verifyAndExecute(uint256 proposalId, address operator, uint8 slashLevel, address[] repUsers, uint256[] newScores, uint256 epoch, bytes32 evidenceHash, bytes proof)",
  "function executeProposal(uint256 proposalId, address target, bytes callData, uint256 requiredThreshold, bytes proof)",
  "function queueSlashWithConsensus(address operator, uint8 slashLevel, uint256 epoch, bytes proof)",
  "function domainSeparator() view returns (bytes32)",
  "function proposalSignersCommitment(uint256) view returns (bytes32)",
  "function validatorAtSlot(uint8) view returns (address)",
  "event SignersCommitted(uint256 indexed proposalId, uint256 signerMask)",
];

export const REGISTRY_ABI = [
  "function disclose((uint8 kind, uint256 proposalId, bytes messageInputs, uint256 signerMask, address[] signers, bytes32 anchor) s, address subjectToken, bytes32 txHash, uint64 blockNumber, bytes20 rulesetCommit, string recordURI, bytes32 recordHash)",
  "event Disclosed(uint256 indexed entryId, uint8 indexed kind, uint256 indexed key, uint256 proposalId, bytes32 messageHash, address[] signers, address subjectToken, bytes32 txHash, uint64 blockNumber, bool blockVerified, bytes20 rulesetCommit, string recordURI, bytes32 recordHash)",
  "function AGGREGATOR() view returns (address)",
  "function entryCount() view returns (uint256)",
];

export const aggIface = new ethers.Interface(AGGREGATOR_ABI);
export const regIface = new ethers.Interface(REGISTRY_ABI);

// ------------------------------------------------------------------ pure encoding (SP mirror)

/** Message the guardians signed, per kind. `f` holds the decoded action fields. */
export function messageHashOf(ds, kind, proposalId, f) {
  switch (kind) {
    case Kind.SLASH:
      return ethers.keccak256(
        ABI.encode(
          ["bytes32", "bytes32", "uint256", "address", "uint8", "uint256", "bytes32"],
          [ds, TAG.EXECUTE_SLASH, proposalId, f.operator, f.slashLevel, f.epoch, f.evidenceHash]
        )
      );
    case Kind.GENERIC:
      return ethers.keccak256(
        ABI.encode(
          ["bytes32", "bytes32", "uint256", "address", "bytes32", "uint256"],
          [ds, TAG.PROPOSAL, proposalId, f.target, f.callDataHash, f.requiredThreshold]
        )
      );
    case Kind.QUEUE:
      return ethers.keccak256(
        ABI.encode(
          ["bytes32", "bytes32", "address", "uint8", "uint256"],
          [ds, TAG.QUEUE_SLASH, f.operator, f.slashLevel, f.epoch]
        )
      );
    case Kind.REPUTATION:
      return ethers.keccak256(
        ABI.encode(
          ["bytes32", "bytes32", "uint256", "address[]", "uint256[]", "uint256"],
          [ds, TAG.REPUTATION, proposalId, f.users, f.newScores, f.epoch]
        )
      );
    default:
      throw new Error(`unknown kind ${kind}`);
  }
}

/** Storage key of proposalSignersCommitment per path (r3b). */
export function commitmentKey(kind, proposalId, messageHash) {
  if (kind === Kind.GENERIC) {
    return BigInt(ethers.keccak256(ABI.encode(["bytes32", "uint256"], [TAG.PROPOSAL, proposalId])));
  }
  if (kind === Kind.QUEUE) return BigInt(messageHash);
  return BigInt(proposalId);
}

export function expectedCommitment(ds, key, messageHash, signerMask, signers, anchor) {
  return ethers.keccak256(
    ABI.encode(
      ["bytes32", "bytes32", "uint256", "bytes32", "uint256", "address[]", "bytes32"],
      [ds, TAG.SIGNERS_COMMITMENT, key, messageHash, signerMask, signers, anchor]
    )
  );
}

/** `messageInputs` bytes as the registry expects them for `kind`. */
export function encodeMessageInputs(kind, f) {
  switch (kind) {
    case Kind.SLASH:
      return ABI.encode(
        ["address", "uint8", "uint256", "bytes32"],
        [f.operator, f.slashLevel, f.epoch, f.evidenceHash]
      );
    case Kind.GENERIC:
      return ABI.encode(
        ["address", "bytes32", "uint256"],
        [f.target, f.callDataHash, f.requiredThreshold]
      );
    case Kind.QUEUE:
      return ABI.encode(["address", "uint8", "uint256"], [f.operator, f.slashLevel, f.epoch]);
    case Kind.REPUTATION:
      return ABI.encode(["address[]", "uint256[]", "uint256"], [f.users, f.newScores, f.epoch]);
    default:
      throw new Error(`unknown kind ${kind}`);
  }
}

export function sortAddresses(addrs) {
  return [...addrs].sort((a, b) => (BigInt(a) < BigInt(b) ? -1 : BigInt(a) > BigInt(b) ? 1 : 0));
}

/**
 * Decode a TOP-LEVEL aggregator call into { kind, proposalId, fields }. A call that is not one of
 * the three entry points (for example a wrapper contract) returns null: its message fields cannot
 * be read from the transaction alone, so the recheck fails closed rather than guess.
 */
export function decodeAction(data) {
  let parsed;
  try {
    parsed = aggIface.parseTransaction({ data });
  } catch {
    return null;
  }
  if (!parsed) return null;
  const a = parsed.args;
  if (parsed.name === "verifyAndExecute") {
    if (a.repUsers.length === 0) {
      return {
        kind: Kind.SLASH,
        proposalId: a.proposalId,
        fields: {
          operator: a.operator,
          slashLevel: a.slashLevel,
          epoch: a.epoch,
          evidenceHash: a.evidenceHash,
        },
      };
    }
    return {
      kind: Kind.REPUTATION,
      proposalId: a.proposalId,
      fields: { users: [...a.repUsers], newScores: [...a.newScores], epoch: a.epoch },
    };
  }
  if (parsed.name === "executeProposal") {
    return {
      kind: Kind.GENERIC,
      proposalId: a.proposalId,
      fields: {
        target: a.target,
        callDataHash: ethers.keccak256(a.callData),
        requiredThreshold: a.requiredThreshold,
      },
    };
  }
  if (parsed.name === "queueSlashWithConsensus") {
    return {
      kind: Kind.QUEUE,
      proposalId: 0n,
      fields: { operator: a.operator, slashLevel: a.slashLevel, epoch: a.epoch },
    };
  }
  return null;
}

// ------------------------------------------------------------------ chain reads

async function view(chain, to, fn, args, blockTag) {
  const data = aggIface.encodeFunctionData(fn, args);
  const ret = await chain.call({ to, data, blockTag });
  return aggIface.decodeFunctionResult(fn, ret)[0];
}

async function resolveSigners(chain, aggregator, mask, blockTag) {
  const out = [];
  for (let slot = 1; slot <= MAX_SLOT; slot++) {
    if (((mask >> BigInt(slot - 1)) & 1n) === 0n) continue;
    if (slot > 255) throw new Error(`signerMask bit ${slot - 1} has no uint8 slot`);
    out.push(ethers.getAddress(await view(chain, aggregator, "validatorAtSlot", [slot], blockTag)));
  }
  return sortAddresses(out);
}

export const Status = { MATCH: "MATCH", MISMATCH: "MISMATCH", INCONCLUSIVE: "INCONCLUSIVE" };

/**
 * ethers v6 providers cache identical requests (default 250 ms), which would let the closing
 * canonical check reuse the opening read and miss a reorg in between. Build providers through this,
 * and canonical() additionally reads block hashes through the uncached raw `send` when it exists.
 */
export function makeProvider(url) {
  return new ethers.JsonRpcProvider(url, undefined, { cacheTimeout: -1 });
}

/**
 * Canonical header { hash, parentHash } of block `number` now, or null. Read uncached through raw
 * `send` when the chain offers one (a Promise-returning `send(method, params) -> result`, as ethers'
 * is); otherwise through getBlock.
 */
async function canonicalHeader(chain, number) {
  const b =
    typeof chain.send === "function"
      ? await chain.send("eth_getBlockByNumber", [ethers.toQuantity(Number(number)), false])
      : await chain.getBlock(Number(number));
  return b && b.hash ? { hash: b.hash, parentHash: b.parentHash ?? undefined } : null;
}

async function canonical(chain, number, blockHash) {
  const h = (await canonicalHeader(chain, number))?.hash;
  return !!h && !!blockHash && h.toLowerCase() === String(blockHash).toLowerCase();
}

function assertBlockInt(name, v, { positive = false } = {}) {
  if (!Number.isSafeInteger(v) || v < (positive ? 1 : 0)) {
    throw new RangeError(
      `${name} must be a ${positive ? "positive" : "non-negative"} safe integer, got ${v}`
    );
  }
}

/**
 * Establish what the action tx `txHash` proves about the entry for `key`, every state read pinned
 * to block `snapshot`. Returns { status, reason?, facts }:
 *   status MISMATCH      the tx provably cannot back an entry for `key` (missing, reverted, no
 *                        commitment for `key`, calldata deriving a different key);
 *   status INCONCLUSIVE  the tx's inclusion is not settled (not canonical, newer than the snapshot);
 *   status null          the tx is usable. `facts` holds every field it established, and
 *                        `facts.incomplete` lists what it could not (wrapped call, slot table that
 *                        changed inside the block). The caller compares the established facts
 *                        FIRST, so a provable contradiction is MISMATCH even when other fields are
 *                        undecidable — a forger cannot hide behind INCONCLUSIVE.
 */
export async function rebuildFromAction(chain, aggregator, txHash, key, snapshot) {
  const agg = ethers.getAddress(aggregator);
  const tx = await chain.getTransaction(txHash);
  const rc = await chain.getTransactionReceipt(txHash);
  // Absence is not evidence: a pruned tx index, a reorg mid-check, or a fabricated hash all look
  // the same from one RPC.
  if (!tx || !rc) {
    return {
      status: Status.INCONCLUSIVE,
      reason:
        "action tx or receipt not available from this RPC (pruned index, reorg, or a fabricated hash)",
    };
  }
  const blockNumber = Number(rc.blockNumber);
  if (blockNumber > snapshot) {
    return {
      status: Status.INCONCLUSIVE,
      reason: "action tx is newer than the confirmed snapshot",
    };
  }
  const header = await canonicalHeader(chain, blockNumber);
  if (!header || header.hash.toLowerCase() !== String(rc.blockHash).toLowerCase()) {
    return {
      status: Status.INCONCLUSIVE,
      reason: "action receipt is not in the canonical chain (reorg?)",
    };
  }
  // A MISMATCH from the action side is final only while the action is still canonical.
  const mismatch = async reason =>
    (await canonical(chain, blockNumber, rc.blockHash))
      ? { status: Status.MISMATCH, reason }
      : { status: Status.INCONCLUSIVE, reason: "canonical chain changed during the check" };
  // Only a canonical receipt's status is evidence.
  // Only an explicit status is evidence: 0 = reverted, 1 = success; anything else is a bad answer.
  const st = rc.status === null || rc.status === undefined ? NaN : Number(rc.status);
  if (st === 0) return mismatch("action tx reverted");
  if (st !== 1) {
    return {
      status: Status.INCONCLUSIVE,
      reason: `action receipt has no valid status (${rc.status})`,
    };
  }

  const commits = rc.logs
    .filter(
      l =>
        ethers.getAddress(l.address) === agg &&
        l.topics[0] === aggIface.getEvent("SignersCommitted").topicHash
    )
    .map(l => ({
      key: BigInt(l.topics[1]),
      signerMask: BigInt(aggIface.decodeEventLog("SignersCommitted", l.data, l.topics).signerMask),
    }));
  const commit = commits.find(c => c.key === BigInt(key));
  if (!commit) {
    return mismatch(`action tx emits no SignersCommitted for key ${key}`);
  }

  // Facts that hold whatever the calldata looks like.
  const facts = {
    key: commit.key,
    signerMask: commit.signerMask,
    blockNumber,
    blockHash: rc.blockHash,
    // The anchor is blockhash(N-1): the canonical header's parentHash. Missing => not a fact.
    anchor: header.parentHash,
    caller: ethers.getAddress(tx.from),
    incomplete: [],
  };
  if (facts.anchor === undefined)
    facts.incomplete.push("action block header carries no parentHash");

  if (!tx.to || ethers.getAddress(tx.to) !== agg) {
    facts.incomplete.push(
      "action is not a top-level aggregator call (wrapped); message fields not recoverable from the tx"
    );
    return { status: null, facts };
  }
  const action = decodeAction(tx.data);
  if (!action) {
    facts.incomplete.push("action calldata is not an aggregator entry point");
    return { status: null, facts };
  }
  if (
    (action.kind === Kind.SLASH || action.kind === Kind.REPUTATION) &&
    BigInt(action.proposalId) >= RAW_ID_BOUND
  ) {
    return mismatch("action proposalId >= 2^128");
  }

  const ds = await view(chain, agg, "domainSeparator", [], blockNumber);
  const messageHash = messageHashOf(ds, action.kind, action.proposalId, action.fields);
  const derivedKey = commitmentKey(action.kind, action.proposalId, messageHash);
  if (derivedKey !== commit.key) {
    return mismatch("key derived from calldata differs from SignersCommitted key");
  }
  Object.assign(facts, {
    kind: action.kind,
    proposalId: BigInt(action.proposalId),
    messageHash,
    messageInputs: encodeMessageInputs(action.kind, action.fields),
  });

  // Without the anchor the commitment cannot be rebuilt; return the message facts for comparison.
  if (facts.anchor === undefined) return { status: null, facts };

  const onchain = await view(chain, agg, "proposalSignersCommitment", [commit.key], snapshot);
  // The aggregator resolved slots during the tx. Pre-block state equals that unless an earlier tx in
  // the same block re-registered a slot, so try the parent block first, then the block itself. A
  // change that is undone later in the same block is visible in neither: incomplete, not a mismatch.
  for (const tag of [blockNumber - 1, blockNumber]) {
    const s = await resolveSigners(chain, agg, commit.signerMask, tag);
    if (
      expectedCommitment(ds, commit.key, messageHash, commit.signerMask, s, facts.anchor) ===
      onchain
    ) {
      facts.signers = s;
      facts.slotBlock = tag;
      return { status: null, facts };
    }
  }
  facts.incomplete.push(
    "signers at the parent block and at the block do not reproduce proposalSignersCommitment " +
      "(slot table changed inside the block, or the commitment was overwritten); replay the block to decide"
  );
  return { status: null, facts };
}

/**
 * Compare the entry with every ESTABLISHED fact; a fact that is absent (undefined) is skipped.
 * `entry` = Disclosed event args; `signed` = the disclose() calldata struct, or null.
 */
export function compareEntry(entry, signed, facts) {
  const diffs = [];
  const eq = (name, a, b) => {
    if (b === undefined) return;
    const norm = v =>
      Array.isArray(v) ? v.map(x => String(x).toLowerCase()).join(",") : String(v).toLowerCase();
    if (norm(a) !== norm(b)) diffs.push({ field: name, entry: norm(a), rebuilt: norm(b) });
  };
  eq("key", BigInt(entry.key), facts.key);
  eq("blockNumber", Number(entry.blockNumber), facts.blockNumber);
  eq("kind", Number(entry.kind), facts.kind);
  eq("proposalId", BigInt(entry.proposalId), facts.proposalId);
  eq("messageHash", entry.messageHash, facts.messageHash);
  eq("signers", [...entry.signers], facts.signers);
  if (signed) {
    eq("signed.signerMask", BigInt(signed.signerMask), facts.signerMask);
    eq("signed.anchor", signed.anchor, facts.anchor);
    eq("signed.messageInputs", signed.messageInputs, facts.messageInputs);
  }
  return diffs;
}

/**
 * Disclosed logs for `entryId` in [fromBlock, toBlock], paged so a range-capped RPC still answers:
 * a page that errors is halved, down to a single block, before the error is passed on.
 */
export async function findEntryLogs(chain, registry, entryId, fromBlock, toBlock, page = 10_000) {
  assertBlockInt("fromBlock", fromBlock);
  assertBlockInt("toBlock", toBlock);
  assertBlockInt("page", page, { positive: true });
  const topics = [regIface.getEvent("Disclosed").topicHash, ethers.toBeHex(BigInt(entryId), 32)];
  const out = [];
  let from = fromBlock;
  let size = page;
  while (from <= toBlock) {
    const to = Math.min(toBlock, from + size - 1);
    try {
      out.push(
        ...(await chain.getLogs({ address: registry, topics, fromBlock: from, toBlock: to }))
      );
      from = to + 1;
      size = page;
    } catch (e) {
      if (size === 1) throw e;
      size = Math.max(1, Math.floor(size / 2));
    }
  }
  return out;
}

/** Fields an entry carries that no on-chain data can confirm; reported, never counted as verified. */
export const UNVERIFIED_FIELDS = ["subjectToken", "rulesetCommit", "recordURI", "recordHash"];

/**
 * Full recheck of entry `entryId` in `registry`, against one snapshot `head - confirmations`.
 * Returns { status, ok, reasons[], diffs[], unverified, rebuilt?, entry? }. `ok` is true only for
 * MATCH; MATCH covers the verified fields and says nothing about UNVERIFIED_FIELDS.
 *
 * `chain` must not serve block reads from a cache (see makeProvider); a chain with raw `send`
 * has its block hashes read through it.
 */
export async function recheckEntry(
  chain,
  { registry, aggregator, entryId, fromBlock = 0, confirmations = 0, page = 10_000 }
) {
  assertBlockInt("fromBlock", fromBlock);
  assertBlockInt("confirmations", confirmations);
  assertBlockInt("page", page, { positive: true }); // before any RPC; findEntryLogs re-checks
  const done = (status, extra) => ({
    status,
    ok: status === Status.MATCH,
    reasons: [],
    diffs: [],
    ...extra,
  });
  const head = await chain.getBlockNumber();
  const snapshot = head - confirmations;
  if (snapshot < fromBlock) {
    return done(Status.INCONCLUSIVE, {
      reasons: [`confirmed snapshot ${snapshot} is before fromBlock ${fromBlock}`],
    });
  }
  // No log found anywhere up to head. Only the registry's own counter can turn that into proof:
  // an id above entryCount was never issued (MISMATCH); otherwise the log search missed it.
  // The counter is read at the head block BY HASH where the chain allows it (EIP-1898), and the head
  // must still be canonical afterwards, so a reorg cannot turn an orphaned branch into proof.
  const noLogVerdict = async () => {
    if (BigInt(entryId) === 0n) {
      return done(Status.MISMATCH, { reasons: ["entry id 0 is never issued (ids start at 1)"] });
    }
    // Without by-hash state reads, a counter read by number could come from a branch that was
    // canonical only during the read (A->B->A); it cannot be the sole proof of absence.
    if (typeof chain.send !== "function") {
      return done(Status.INCONCLUSIVE, {
        reasons: [
          `no Disclosed log found for entry ${entryId}; this provider cannot read state by block hash`,
        ],
      });
    }
    const headHash = (await canonicalHeader(chain, head))?.hash;
    if (!headHash)
      return done(Status.INCONCLUSIVE, { reasons: [`head block ${head} header unavailable`] });
    const data = regIface.encodeFunctionData("entryCount", []);
    const ret = await chain.send("eth_call", [{ to: registry, data }, { blockHash: headHash }]);
    const count = regIface.decodeFunctionResult("entryCount", ret)[0];
    if (!(await canonical(chain, head, headHash))) {
      return done(Status.INCONCLUSIVE, { reasons: ["canonical chain changed during the check"] });
    }
    return BigInt(entryId) > count
      ? done(Status.MISMATCH, {
          reasons: [
            `entry ${entryId} not issued as of block ${head} ${headHash} (entryCount ${count})`,
          ],
        })
      : done(Status.INCONCLUSIVE, {
          reasons: [
            `entry ${entryId} exists (entryCount ${count}) but no Disclosed log was found from block ${fromBlock}`,
          ],
        });
  };
  const logs = await findEntryLogs(chain, registry, entryId, fromBlock, snapshot, page);
  if (logs.length > 1) {
    return done(Status.MISMATCH, {
      reasons: [`found ${logs.length} Disclosed logs for entry ${entryId}`],
    });
  }
  if (logs.length === 0) {
    // Not in the confirmed range. If it is in the unconfirmed tail it is pending, not wrong.
    const tail =
      snapshot < head
        ? await findEntryLogs(chain, registry, entryId, snapshot + 1, head, page)
        : [];
    return tail.length
      ? done(Status.INCONCLUSIVE, {
          reasons: [
            `entry ${entryId} is in block ${tail[0].blockNumber}, not yet ${confirmations} confirmations deep`,
          ],
        })
      : await noLogVerdict();
  }
  const log = logs[0];
  if (!(await canonical(chain, log.blockNumber, log.blockHash))) {
    return done(Status.INCONCLUSIVE, {
      reasons: ["Disclosed log is not in the canonical chain (reorg?)"],
    });
  }
  const entry = regIface.decodeEventLog("Disclosed", log.data, log.topics);
  const unverified = Object.fromEntries(UNVERIFIED_FIELDS.map(f => [f, String(entry[f])]));

  const dtx = await chain.getTransaction(log.transactionHash);
  let signed = null;
  try {
    const p = regIface.parseTransaction({ data: dtx.data });
    if (p && p.name === "disclose") signed = p.args.s;
  } catch {
    /* disclose through a wrapper: compare the event only */
  }

  const r = await rebuildFromAction(chain, aggregator, entry.txHash, entry.key, snapshot);
  if (r.status) {
    // A definitive verdict needs the disclosure to still be canonical, like the full path below.
    if (r.status === Status.MISMATCH && !(await canonical(chain, log.blockNumber, log.blockHash))) {
      return done(Status.INCONCLUSIVE, {
        reasons: ["canonical chain changed during the check"],
        entry,
        unverified,
      });
    }
    return done(r.status, { reasons: [r.reason], entry, unverified });
  }
  const diffs = compareEntry(entry, signed, r.facts);

  // Both inclusions must still be canonical after all reads, or a reorg ran underneath the check.
  const still =
    (await canonical(chain, log.blockNumber, log.blockHash)) &&
    (await canonical(chain, r.facts.blockNumber, r.facts.blockHash));
  if (!still) {
    return done(Status.INCONCLUSIVE, {
      reasons: ["canonical chain changed during the check"],
      entry,
      unverified,
    });
  }
  const reasons = [...r.facts.incomplete];
  if (!signed) reasons.push("disclose calldata not top-level; event fields only");
  // A proven contradiction outranks anything left undecided.
  const status = diffs.length
    ? Status.MISMATCH
    : r.facts.incomplete.length
      ? Status.INCONCLUSIVE
      : Status.MATCH;
  return done(status, { reasons, diffs, rebuilt: r.facts, entry, unverified });
}
