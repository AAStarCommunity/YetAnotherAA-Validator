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

/** True when `blockHash` is the canonical hash of `number` right now. */
async function canonical(chain, number, blockHash) {
  const b = await chain.getBlock(Number(number));
  return !!b && !!blockHash && b.hash.toLowerCase() === String(blockHash).toLowerCase();
}

/**
 * Rebuild what the registry entry for `key` should say, from the action tx `txHash` only, with every
 * state read pinned to block `snapshot`. Returns { status, reason?, rebuilt? }:
 *   MISMATCH      the tx provably does not support an entry for `key` (forged or wrong pointer);
 *   INCONCLUSIVE  the tx cannot be checked from its own data (wrapped call, non-canonical block,
 *                 or a slot table that changed inside the block) — neither confirmed nor refuted.
 */
export async function rebuildFromAction(chain, aggregator, txHash, key, snapshot) {
  const agg = ethers.getAddress(aggregator);
  const tx = await chain.getTransaction(txHash);
  const rc = await chain.getTransactionReceipt(txHash);
  if (!tx || !rc) return { status: Status.MISMATCH, reason: "action tx not found" };
  if (Number(rc.status) !== 1) return { status: Status.MISMATCH, reason: "action tx reverted" };
  const blockNumber = Number(rc.blockNumber);
  if (blockNumber > snapshot) {
    return {
      status: Status.INCONCLUSIVE,
      reason: "action tx is newer than the confirmed snapshot",
    };
  }
  if (!(await canonical(chain, blockNumber, rc.blockHash))) {
    return {
      status: Status.INCONCLUSIVE,
      reason: "action receipt is not in the canonical chain (reorg?)",
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
    return {
      status: Status.MISMATCH,
      reason: `action tx emits no SignersCommitted for key ${key}`,
    };
  }

  if (!tx.to || ethers.getAddress(tx.to) !== agg) {
    return {
      status: Status.INCONCLUSIVE,
      reason:
        "action is not a top-level aggregator call (wrapped); message fields not recoverable from the tx",
    };
  }
  const action = decodeAction(tx.data);
  if (!action) {
    return {
      status: Status.INCONCLUSIVE,
      reason: "action calldata is not an aggregator entry point",
    };
  }
  if (
    (action.kind === Kind.SLASH || action.kind === Kind.REPUTATION) &&
    BigInt(action.proposalId) >= RAW_ID_BOUND
  ) {
    return { status: Status.MISMATCH, reason: "action proposalId >= 2^128" };
  }

  const ds = await view(chain, agg, "domainSeparator", [], blockNumber);
  const messageHash = messageHashOf(ds, action.kind, action.proposalId, action.fields);
  const derivedKey = commitmentKey(action.kind, action.proposalId, messageHash);
  if (derivedKey !== commit.key) {
    return {
      status: Status.MISMATCH,
      reason: "key derived from calldata differs from SignersCommitted key",
    };
  }

  const anchor = (await chain.getBlock(blockNumber - 1)).hash;
  const onchain = await view(chain, agg, "proposalSignersCommitment", [commit.key], snapshot);

  // The aggregator resolved slots during the tx. Pre-block state equals that unless an earlier tx in
  // the same block re-registered a slot, so try the parent block first, then the block itself. A
  // change that is undone later in the same block is visible in neither: INCONCLUSIVE, not MISMATCH.
  let signers = null;
  let slotBlock = null;
  for (const tag of [blockNumber - 1, blockNumber]) {
    const s = await resolveSigners(chain, agg, commit.signerMask, tag);
    if (expectedCommitment(ds, commit.key, messageHash, commit.signerMask, s, anchor) === onchain) {
      signers = s;
      slotBlock = tag;
      break;
    }
  }
  if (!signers) {
    return {
      status: Status.INCONCLUSIVE,
      reason:
        "signers at the parent block and at the block do not reproduce proposalSignersCommitment " +
        "(slot table changed inside the block, or the commitment was overwritten); replay the block to decide",
    };
  }

  return {
    status: Status.MATCH,
    rebuilt: {
      kind: action.kind,
      key: commit.key,
      proposalId: BigInt(action.proposalId),
      messageHash,
      messageInputs: encodeMessageInputs(action.kind, action.fields),
      signerMask: commit.signerMask,
      signers,
      anchor,
      blockNumber,
      blockHash: rc.blockHash,
      caller: ethers.getAddress(tx.from),
      slotBlock,
    },
  };
}

/** Field-by-field comparison. `entry` = Disclosed event args; `signed` = the disclose() calldata struct. */
export function compareEntry(entry, signed, rebuilt) {
  const diffs = [];
  const eq = (name, a, b) => {
    const norm = v =>
      Array.isArray(v) ? v.map(x => String(x).toLowerCase()).join(",") : String(v).toLowerCase();
    if (norm(a) !== norm(b)) diffs.push({ field: name, entry: norm(a), rebuilt: norm(b) });
  };
  eq("kind", Number(entry.kind), rebuilt.kind);
  eq("key", BigInt(entry.key), rebuilt.key);
  eq("proposalId", BigInt(entry.proposalId), rebuilt.proposalId);
  eq("messageHash", entry.messageHash, rebuilt.messageHash);
  eq("signers", [...entry.signers], rebuilt.signers);
  eq("blockNumber", Number(entry.blockNumber), rebuilt.blockNumber);
  if (signed) {
    eq("signed.messageInputs", signed.messageInputs, rebuilt.messageInputs);
    eq("signed.signerMask", BigInt(signed.signerMask), rebuilt.signerMask);
    eq("signed.anchor", signed.anchor, rebuilt.anchor);
  }
  return diffs;
}

/**
 * Disclosed logs for `entryId` in [fromBlock, toBlock], paged so a range-capped RPC still answers:
 * a page that errors is halved, down to a single block, before the error is passed on.
 */
export async function findEntryLogs(chain, registry, entryId, fromBlock, toBlock, page = 10_000) {
  const topics = [regIface.getEvent("Disclosed").topicHash, ethers.toBeHex(BigInt(entryId), 32)];
  const out = [];
  let from = Number(fromBlock);
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
 */
export async function recheckEntry(
  chain,
  { registry, aggregator, entryId, fromBlock = 0, confirmations = 0, page }
) {
  const done = (status, extra) => ({
    status,
    ok: status === Status.MATCH,
    reasons: [],
    diffs: [],
    ...extra,
  });
  const snapshot = (await chain.getBlockNumber()) - confirmations;
  const logs = await findEntryLogs(chain, registry, entryId, fromBlock, snapshot, page);
  if (logs.length !== 1) {
    return done(Status.MISMATCH, {
      reasons: [
        `expected one Disclosed log for entry ${entryId} up to block ${snapshot}, found ${logs.length}`,
      ],
    });
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
  if (r.status !== Status.MATCH) return done(r.status, { reasons: [r.reason], entry, unverified });
  const diffs = compareEntry(entry, signed, r.rebuilt);

  // Both inclusions must still be canonical after all reads, or a reorg ran underneath the check.
  const still =
    (await canonical(chain, log.blockNumber, log.blockHash)) &&
    (await canonical(chain, r.rebuilt.blockNumber, r.rebuilt.blockHash));
  if (!still) {
    return done(Status.INCONCLUSIVE, {
      reasons: ["canonical chain changed during the check"],
      entry,
      unverified,
    });
  }
  return done(diffs.length === 0 ? Status.MATCH : Status.MISMATCH, {
    reasons: signed ? [] : ["disclose calldata not top-level; event fields only"],
    diffs,
    rebuilt: r.rebuilt,
    entry,
    unverified,
  });
}
