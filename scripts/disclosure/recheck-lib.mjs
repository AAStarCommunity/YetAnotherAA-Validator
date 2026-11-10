// Independent recheck of a DisclosureRegistry entry (M0 §4.4, DSR constraint): rebuild the entry
// from the ACTION transaction alone — RPC reads of the chain and the aggregator, nothing from DVT
// state, nothing from the registry's own view functions — and compare field by field.
//
// The encoding here is a second implementation of SuperPaymaster BLSAggregator-4.13.0 (rc.8 r3b,
// checked against cc125/rc8-bls @ f00be60374c5cc1d2c4c928a73cee90cf0e12e6c),
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
  "event Disclosed(uint256 indexed entryId, uint8 indexed kind, uint256 indexed key, uint256 proposalId, bytes32 messageHash, address[] signers, (address subjectToken, bytes32 txHash, uint64 blockNumber, bool blockVerified, bytes20 rulesetCommit, string recordURI, bytes32 recordHash) record)",
  "function AGGREGATOR() view returns (address)",
  "function entryCount() view returns (uint256)",
];

/** SuperPaymaster DVTValidator-0.7.0 (f00be603 :272-310) — the forwarder the guardians use. */
export const DVT_ABI = [
  "function executeWithProof(uint256 id, address[] repUsers, uint256[] newScores, uint256 epoch, bytes proof)",
  "function queueSlashWithProof(address operator, uint8 slashLevel, uint256 epoch, bytes proof)",
  "function proposals(uint256) view returns (address operator, uint8 slashLevel, string reason, bool executed, bool exists, bytes32 evidenceHash)",
];
/** Safe v1.3/v1.4 owner-transaction entry point, and the MultiSend(CallOnly) batch call. */
export const SAFE_ABI = [
  "function execTransaction(address to, uint256 value, bytes data, uint8 operation, uint256 safeTxGas, uint256 baseGas, uint256 gasPrice, address gasToken, address refundReceiver, bytes signatures)",
  "function execTransactionFromModule(address to, uint256 value, bytes data, uint8 operation)",
  "function execTransactionFromModuleReturnData(address to, uint256 value, bytes data, uint8 operation)",
  "function multiSend(bytes transactions)",
];

export const aggIface = new ethers.Interface(AGGREGATOR_ABI);
export const dvtIface = new ethers.Interface(DVT_ABI);
export const safeIface = new ethers.Interface(SAFE_ABI);
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

const eqAddr = (a, b) => !!a && !!b && ethers.getAddress(a) === ethers.getAddress(b);

/** Packed MultiSend payload: (uint8 op, address to, uint256 value, uint256 len, bytes data)*. */
export function parseMultiSend(transactions) {
  const b = ethers.getBytes(transactions);
  const out = [];
  let i = 0;
  while (i < b.length) {
    if (i + 85 > b.length) return null;
    const operation = b[i];
    const to = ethers.getAddress(ethers.hexlify(b.slice(i + 1, i + 21)));
    const len = Number(BigInt(ethers.hexlify(b.slice(i + 53, i + 85))));
    if (!Number.isSafeInteger(len) || i + 85 + len > b.length) return null;
    out.push({ operation, to, data: ethers.hexlify(b.slice(i + 85, i + 85 + len)) });
    i += 85 + len;
  }
  return out;
}

/**
 * Aggregator calls recoverable from tx `tx`, as candidates { kind, proposalId, fields, route }.
 * A forwarder is followed ONLY at the address the release manifest pins for its role
 * (`forwarders.dvtValidator`, `.ownerSafe`, `.multiSendCallOnly`); a look-alike elsewhere is
 * ignored. Safe: execTransaction with operation CALL is followed; DELEGATECALL only into the pinned
 * MultiSendCallOnly and only through sub-transactions that are all CALLs; module routes are not
 * followed. Anything else falls back to a callTracer trace limited to the pinned aggregator and
 * DVTValidator. `notes` says why something was not followed.
 */
export async function extractCandidates(chain, tx, aggregator, forwarders = {}, blockNumber) {
  const fw = forwarders || {};
  const candidates = [];
  const notes = [];

  // DVTValidator-derived candidates are never `proven`: DVTValidator propagates reverts, but it
  // forwards to its mutable BLS_AGGREGATOR (owner-settable, even within one block), so its success
  // does not show that the PINNED aggregator ran. They count only through the commitment. (In a
  // trace, the forwarded CALL into the pinned aggregator is decoded on its own and is proven.)
  async function fromDvt(data, route) {
    const proven = false;
    let p;
    try {
      p = dvtIface.parseTransaction({ data });
    } catch {
      p = null;
    }
    if (!p) return notes.push(`${route}: calldata is not a DVTValidator forwarding call`);
    if (p.name === "queueSlashWithProof") {
      candidates.push({
        kind: Kind.QUEUE,
        proposalId: 0n,
        fields: { operator: p.args.operator, slashLevel: p.args.slashLevel, epoch: p.args.epoch },
        route: `${route}.queueSlashWithProof`,
        proven,
      });
      return;
    }
    if (p.name !== "executeWithProof") {
      return notes.push(`${route}: ${p.name} is not a DVTValidator forwarding call`);
    }
    // The aggregator read proposals[id] during block N; its fields never change after creation
    // (DVTValidator f00be603 :215-238, :257), so the parent block shows what it used — unless the
    // proposal was created inside block N itself.
    const ret = await chain.call({
      to: fw.dvtValidator,
      data: dvtIface.encodeFunctionData("proposals", [p.args.id]),
      blockTag: blockNumber - 1,
    });
    const pr = dvtIface.decodeFunctionResult("proposals", ret);
    if (!pr.exists) {
      return notes.push(
        `${route}: proposal ${p.args.id} did not exist at block ${blockNumber - 1} (created in the same block?)`
      );
    }
    const repUsers = [...p.args.repUsers];
    candidates.push(
      repUsers.length === 0
        ? {
            kind: Kind.SLASH,
            proposalId: p.args.id,
            fields: {
              operator: pr.operator,
              slashLevel: pr.slashLevel,
              epoch: p.args.epoch,
              evidenceHash: pr.evidenceHash,
            },
            route: `${route}.executeWithProof`,
            proven,
          }
        : {
            kind: Kind.REPUTATION,
            proposalId: p.args.id,
            fields: { users: repUsers, newScores: [...p.args.newScores], epoch: p.args.epoch },
            route: `${route}.executeWithProof`,
            proven,
          }
    );
  }

  // `proven`: the call is known to have reached the pinned aggregator and succeeded. True only for
  // the top-level call of a successful tx; a Safe hop clears it (execTransaction does not revert
  // when its inner call fails), and DVTValidator-derived candidates never carry it (see fromDvt).
  async function follow(to, data, route, depth, proven) {
    if (depth > 4) return notes.push(`${route}: nesting too deep`);
    if (eqAddr(to, aggregator)) {
      const a = decodeAction(data);
      if (a) candidates.push({ ...a, route: `${route}.aggregator`, proven });
      else notes.push(`${route}: aggregator calldata is not an entry point`);
      return;
    }
    if (eqAddr(to, fw.dvtValidator)) return fromDvt(data, `${route}.dvtValidator`);
    if (eqAddr(to, fw.ownerSafe)) {
      let p;
      try {
        p = safeIface.parseTransaction({ data });
      } catch {
        p = null;
      }
      if (!p) return notes.push(`${route}: ownerSafe call is not a known Safe entry point`);
      if (p.name !== "execTransaction")
        return notes.push(`${route}: Safe ${p.name} (module route) is not followed`);
      const op = Number(p.args.operation);
      if (op === 0) return follow(p.args.to, p.args.data, `${route}.safe`, depth + 1, false);
      if (op === 1 && eqAddr(p.args.to, fw.multiSendCallOnly)) {
        let m;
        try {
          m = safeIface.parseTransaction({ data: p.args.data });
        } catch {
          m = null;
        }
        const subs = m && m.name === "multiSend" ? parseMultiSend(m.args.transactions) : null;
        if (!subs) return notes.push(`${route}: malformed MultiSendCallOnly batch`);
        // MultiSendCallOnly reverts the whole batch on any non-CALL operation: such a batch is
        // not followed at all.
        const bad = subs.findIndex(x => x.operation !== 0);
        if (bad >= 0)
          return notes.push(
            `${route}.multiSend[${bad}]: DELEGATECALL is not followed (batch skipped)`
          );
        for (let k = 0; k < subs.length; k++) {
          await follow(subs[k].to, subs[k].data, `${route}.safe.multiSend[${k}]`, depth + 1, false);
        }
        return;
      }
      return notes.push(
        `${route}: Safe DELEGATECALL to ${p.args.to} is not followed (only the pinned MultiSendCallOnly)`
      );
    }
    // Not a pinned contract: nothing is decoded from it here.
  }

  if (tx.to) await follow(tx.to, tx.data, "tx", 0, true);
  const pinnedTop =
    tx.to && [aggregator, fw.dvtValidator, fw.ownerSafe].some(a => eqAddr(a, tx.to));
  if (!pinnedTop) {
    // Trace fallback: decode only CALL frames whose target is the pinned aggregator or DVTValidator.
    let trace = null;
    if (typeof chain.send === "function") {
      try {
        trace = await chain.send("debug_traceTransaction", [tx.hash, { tracer: "callTracer" }]);
      } catch {
        trace = null;
      }
    }
    if (!trace) {
      notes.push(
        "action is wrapped by a contract the manifest does not pin, and no callTracer trace is available"
      );
    } else {
      const selectorOf = d =>
        typeof d === "string" && d.length >= 10 ? d.slice(0, 10).toLowerCase() : "";
      const moduleSelectors = new Set(
        ["execTransactionFromModule", "execTransactionFromModuleReturnData"].map(
          n => safeIface.getFunction(n).selector
        )
      );
      // A frame without `error` whose ancestors have none either did succeed, so what it decodes
      // to is proven. The direct path's route rules hold here too: a DELEGATECALL subtree is pruned
      // unless it enters the pinned MultiSendCallOnly with all-CALL children, and a Safe module
      // call subtree is pruned.
      const walk = async (f, path) => {
        if (!f || f.error) return;
        const type = String(f.type).toUpperCase();
        if (type === "DELEGATECALL") {
          if (!eqAddr(f.to, fw.multiSendCallOnly))
            return notes.push(`${path}: DELEGATECALL subtree not followed`);
          if ((f.calls || []).some(c => String(c.type).toUpperCase() !== "CALL"))
            return notes.push(`${path}: MultiSend with a non-CALL sub-transaction not followed`);
        }
        if (eqAddr(f.to, fw.ownerSafe) && moduleSelectors.has(selectorOf(f.input)))
          return notes.push(`${path}: Safe module route not followed`);
        if (type === "CALL") {
          if (eqAddr(f.to, aggregator)) {
            const a = decodeAction(f.input);
            if (a) candidates.push({ ...a, route: `${path}.aggregator`, proven: true });
          } else if (eqAddr(f.to, fw.dvtValidator)) {
            await fromDvt(f.input, `${path}.dvtValidator`);
          }
        }
        for (let k = 0; k < (f.calls || []).length; k++) await walk(f.calls[k], `${path}.${k}`);
      };
      await walk(trace, "trace");
    }
  }
  return { candidates, notes };
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
export async function rebuildFromAction(chain, aggregator, txHash, key, snapshot, forwarders = {}) {
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

  // Recover the aggregator call(s) this tx made, from the tx itself through the manifest-pinned
  // forwarders, or from a trace. A candidate counts only if it reproduces the SignersCommitted key;
  // the stored commitment is then the final gate, so a decoding mistake can never make a MATCH.
  const ds = await view(chain, agg, "domainSeparator", [], blockNumber);
  const found = await extractCandidates(chain, tx, agg, forwarders, blockNumber);
  facts.route = null;
  const matching = [];
  for (const c of found.candidates) {
    if (
      (c.kind === Kind.SLASH || c.kind === Kind.REPUTATION) &&
      BigInt(c.proposalId) >= RAW_ID_BOUND
    ) {
      continue; // the aggregator reverts these (InvalidProposalId), so it cannot be the committed call
    }
    const mh = messageHashOf(ds, c.kind, c.proposalId, c.fields);
    if (commitmentKey(c.kind, c.proposalId, mh) === commit.key)
      matching.push({ ...c, messageHash: mh });
  }
  if (matching.length === 0) {
    facts.incomplete.push(...found.notes);
    facts.incomplete.push(
      found.candidates.length
        ? "no recovered aggregator call reproduces the SignersCommitted key"
        : "no aggregator call recoverable from this tx (wrapped through a contract the manifest does not pin)"
    );
    return { status: null, facts };
  }
  // A recovered call's message becomes a FACT only if it is authenticated: it reproduces the stored
  // commitment, or the call is proven to have succeeded (`proven`: a top-level call to the pinned
  // aggregator/DVTValidator in a successful tx, or an error-free trace path). A Safe inner call is
  // not proven — execTransaction does not revert when its inner call fails — so until it matches
  // the commitment it is never compared, and it can neither accuse nor hide an honest entry.
  const distinct = [];
  for (const m of matching) {
    const d = distinct.find(x => x.messageHash === m.messageHash);
    if (d) d.proven = d.proven || m.proven;
    else distinct.push({ ...m });
  }
  const useMessage = c => {
    facts.route = c.route;
    Object.assign(facts, {
      kind: c.kind,
      proposalId: BigInt(c.proposalId),
      messageHash: c.messageHash,
      messageInputs: encodeMessageInputs(c.kind, c.fields),
    });
  };
  const proven = distinct.filter(c => c.proven);

  if (facts.anchor !== undefined) {
    const onchain = await view(chain, agg, "proposalSignersCommitment", [commit.key], snapshot);
    // The aggregator resolved slots during the tx. Pre-block state equals that unless an earlier
    // tx in the same block re-registered a slot, so try the parent block first, then the block
    // itself. A change undone later in the same block is visible in neither.
    const signerSets = [];
    for (const tag of [blockNumber - 1, blockNumber]) {
      signerSets.push({ tag, s: await resolveSigners(chain, agg, commit.signerMask, tag) });
    }
    const authenticated = [];
    for (const c of distinct) {
      const hit = signerSets.find(
        x =>
          expectedCommitment(
            ds,
            commit.key,
            c.messageHash,
            commit.signerMask,
            x.s,
            facts.anchor
          ) === onchain
      );
      if (hit) authenticated.push({ c, hit });
    }
    if (authenticated.length === 1) {
      useMessage(authenticated[0].c);
      facts.signers = authenticated[0].hit.s;
      facts.slotBlock = authenticated[0].hit.tag;
      return { status: null, facts };
    }
    if (authenticated.length > 1) {
      facts.incomplete.push("several recovered calls reproduce the commitment");
      return { status: null, facts };
    }
  }
  // Not authenticated by the commitment (no anchor, or the slot table changed inside the block).
  // Only a proven call's message may still be compared; the signer set stays undecided.
  if (proven.length === 1) {
    useMessage(proven[0]);
    facts.incomplete.push(
      facts.anchor === undefined
        ? "commitment not rebuilt (no anchor); signers undecided"
        : "signers at the parent block and at the block do not reproduce proposalSignersCommitment " +
            "(slot table changed inside the block, or the commitment was overwritten); replay the block to decide"
    );
    return { status: null, facts };
  }
  facts.incomplete.push(...found.notes);
  facts.incomplete.push(
    proven.length > 1
      ? "several proven calls claim the same key with different messages"
      : "no recovered call is authenticated (none reproduces the commitment, and none is a proven top-level call)"
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
  eq("blockNumber", Number(entry.record.blockNumber), facts.blockNumber);
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
  {
    registry,
    aggregator,
    forwarders = {},
    entryId,
    fromBlock = 0,
    confirmations = 0,
    page = 10_000,
  }
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
  const unverified = Object.fromEntries(UNVERIFIED_FIELDS.map(f => [f, String(entry.record[f])]));

  const dtx = await chain.getTransaction(log.transactionHash);
  let signed = null;
  try {
    const p = regIface.parseTransaction({ data: dtx.data });
    if (p && p.name === "disclose") signed = p.args.s;
  } catch {
    /* disclose through a wrapper: compare the event only */
  }

  const r = await rebuildFromAction(
    chain,
    aggregator,
    entry.record.txHash,
    entry.key,
    snapshot,
    forwarders
  );
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
