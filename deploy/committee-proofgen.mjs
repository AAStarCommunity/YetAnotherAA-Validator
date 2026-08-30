// CC-98 aggregator-side Merkle proof generator (reference for SDK/KMS + E2E).
//
// A committee op used during epoch e is verified against the FROZEN setRoot[e-1]. The submitter must
// provide, per signer, a Merkle proof of (slot -> nodeId) against that frozen root. getMerkleProof() on
// the contract only builds CURRENT-state proofs (valid only if the set is unchanged since the snapshot),
// so the aggregator reconstructs the frozen tree from the SlotAssigned/SlotCleared event log up to the
// epoch-(e-1) snapshot block, and reads the exact wire the account expects.
//
// The Merkle reconstruction is SELF-CHECKED: the recomputed root must equal the on-chain
// epochSetRoot[e-1], else it throws (never emits a proof that would fail-closed on chain). NOTE: only
// Merkle membership is checked here — the OTHER on-chain gates (sortition draw, quorum k>=ceil(2*m_e/3),
// current isRegistered/stake) are NOT validated by this tool; the caller/SDK must select signers that
// pass them (see buildCommitteePayload's caveat).
//
// SMT: fixed depth TREE_DEPTH=14, leaf[slot]=nodeId (0=empty), parent=keccak256(abi.encode(left,right)),
//      zeros[0]=0, zeros[l]=keccak(zeros[l-1],zeros[l-1]).
//
// env (.env.sepolia): SEPOLIA_RPC_URL, COMMITTEE_VALIDATOR
// Usage (demo): node deploy/committee-proofgen.mjs <epoch> <nodeId>
// Import:       import { reconstructFrozenTree, buildProof, buildCommitteePayload } from "./committee-proofgen.mjs"
import { ethers } from "ethers";
import { readFileSync } from "fs";

const TREE_DEPTH = 14;
const strip = s => s.replace(/^["']|["']$/g, "");

function loadEnv() {
  const env = Object.fromEntries(
    readFileSync(".env.sepolia", "utf8").split("\n").filter(l => l.includes("="))
      .map(l => { const i = l.indexOf("="); return [l.slice(0, i).trim(), strip(l.slice(i + 1).trim())]; })
  );
  return env;
}

const ABI = [
  "event SlotAssigned(bytes32 indexed nodeId, uint256 slot)",
  "event SlotCleared(bytes32 indexed nodeId, uint256 slot)",
  "event EpochSnapshotted(uint256 indexed epoch, bytes32 seed, bytes32 setRoot, uint256 setCount)",
  "function epochSetRoot(uint256) view returns(bytes32)",
  "function epochSeed(uint256) view returns(bytes32)",
];

const zeros = (() => {
  const z = [ethers.ZeroHash];
  for (let i = 0; i < TREE_DEPTH; i++) z.push(ethers.keccak256(ethers.solidityPacked(["bytes32", "bytes32"], [z[i], z[i]])));
  return z;
})();
const hashPair = (a, b) => ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(["bytes32", "bytes32"], [a, b]));

// Build the fixed-depth SMT from a slot->nodeId leaf map; return root + a proof-builder over it.
function buildTree(leafMap) {
  // level 0 nodes present (occupied slots + siblings computed on demand); we materialize a sparse map.
  let level = new Map(); // idx -> hash at current level
  for (const [slot, nid] of leafMap) level.set(slot, nid);
  const levels = [level];
  for (let d = 0; d < TREE_DEPTH; d++) {
    const cur = levels[d];
    const next = new Map();
    const seen = new Set();
    for (const idx of cur.keys()) {
      const p = idx >> 1n;
      if (seen.has(p)) continue;
      seen.add(p);
      const l = cur.get(p * 2n) ?? zeros[d];
      const r = cur.get(p * 2n + 1n) ?? zeros[d];
      next.set(p, hashPair(l, r));
    }
    levels.push(next);
  }
  const root = levels[TREE_DEPTH].get(0n) ?? zeros[TREE_DEPTH];
  const proofFor = slot => {
    let idx = BigInt(slot);
    const proof = [];
    for (let d = 0; d < TREE_DEPTH; d++) {
      const sib = idx ^ 1n;
      proof.push(levels[d].get(sib) ?? zeros[d]);
      idx >>= 1n;
    }
    return proof;
  };
  return { root, proofFor };
}

// Reconstruct the frozen tree for `epoch` (i.e. the setRoot committee ops in epoch+1 sample over).
// Replays events up to the snapshot block; self-checks the recomputed root vs on-chain epochSetRoot.
export async function reconstructFrozenTree(provider, validator, epoch) {
  const c = new ethers.Contract(validator, ABI, provider);
  const frozenRoot = await c.epochSetRoot(epoch);
  if (frozenRoot === ethers.ZeroHash) throw new Error(`epoch ${epoch} not snapshotted (epochSetRoot==0)`);
  const snapEvents = await c.queryFilter(c.filters.EpochSnapshotted(epoch));
  if (!snapEvents.length) throw new Error(`no EpochSnapshotted event for epoch ${epoch}`);
  const snapEvent = snapEvents[snapEvents.length - 1];
  const snapBlock = snapEvent.blockNumber;
  // Exact LOG POSITION of the pin, not just its block. The contract freezes the live set at the moment
  // snapshotEpoch executes, and can say nothing about mutations that land LATER IN THE SAME BLOCK — so
  // a block-granular cutoff would replay those too and rebuild a root the chain never froze.
  const snapPos = [snapBlock, snapEvent.transactionIndex, snapEvent.index];

  // Chunked eth_getLogs from the deploy block (not 0): the log set only grows and RPCs cap by result
  // count (~10k). fromBlock defaults to DEPLOY_BLOCK env, else 0 with a warning.
  const fromBlock = Number(process.env.DEPLOY_BLOCK ?? 0);
  if (!process.env.DEPLOY_BLOCK) console.warn("proofgen: DEPLOY_BLOCK unset — scanning from block 0 (set it to the validator's creation block for large histories)");
  const CHUNK = 9000;
  const getLogsChunked = async filter => {
    const out = [];
    for (let from = fromBlock; from <= snapBlock; from += CHUNK + 1) {
      const to = Math.min(from + CHUNK, snapBlock);
      out.push(...(await c.queryFilter(filter, from, to)));
    }
    return out;
  };
  const assigned = await getLogsChunked(c.filters.SlotAssigned());
  const cleared = await getLogsChunked(c.filters.SlotCleared());
  // Strict LOG ORDER. ethers v6 renamed Log.logIndex -> Log.index; using the wrong field yields NaN and
  // leaves same-tx events in concatenation order (assign-before-clear), corrupting slot-rotation replays.
  const mutations = [...assigned.map(e => ({ ...e, kind: "assign" })), ...cleared.map(e => ({ ...e, kind: "clear" }))]
    .sort((a, b) => a.blockNumber - b.blockNumber || a.transactionIndex - b.transactionIndex || a.index - b.index);

  // Contract semantics (CC-112 D2): snapshotEpoch freezes the LIVE set at the instant it executes.
  // Mutations EARLIER in the same block are therefore included, and mutations LATER in the same block
  // are not — which a block-number cutoff cannot express in either direction. Compare full log order.
  const leafMap = new Map(); // slot(bigint) -> nodeId
  for (const m of mutations) {
    const pos = [m.blockNumber, m.transactionIndex, m.index];
    if (pos[0] > snapPos[0]) continue;
    if (pos[0] === snapPos[0] && (pos[1] > snapPos[1] || (pos[1] === snapPos[1] && pos[2] > snapPos[2]))) continue;
    const slot = BigInt(m.args.slot);
    if (m.kind === "assign") leafMap.set(slot, m.args.nodeId);
    else leafMap.delete(slot);
  }
  const tree = buildTree(leafMap);
  if (tree.root.toLowerCase() !== frozenRoot.toLowerCase()) {
    const tail = mutations.filter(m => m.blockNumber <= snapBlock).slice(-5)
      .map(m => `${m.kind}(slot ${m.args.slot} @blk ${m.blockNumber})`).join(", ");
    throw new Error(`reconstructed root ${tree.root} != on-chain setRoot[${epoch}] ${frozenRoot} (${leafMap.size} leaves; last: ${tail})`);
  }
  const slotOfNode = new Map();
  for (const [slot, nid] of leafMap) slotOfNode.set(nid.toLowerCase(), slot);
  return { root: tree.root, tree, leafMap, slotOfNode, snapBlock };
}

// Per-signer proof against the frozen tree (throws if the node was not in the frozen set).
export function buildProof(reconstructed, nodeId) {
  const slot = reconstructed.slotOfNode.get(nodeId.toLowerCase());
  if (slot === undefined) throw new Error(`nodeId ${nodeId} not in the frozen set`);
  return { slot, proof: reconstructed.tree.proofFor(slot) };
}

// Assemble the submitter portion of validate()'s signature payload for committee mode.
// account prepends accountId(=address(this)); here we include it for completeness/testing.
//   [accountId(32)][ per signer: nodeId(32) || slot(32) || proof(TREE_DEPTH*32) ][ blsSig(256) ]
// signers MUST be strictly ascending by nodeId (the aggregator sorts before submitting).
export function buildCommitteePayload(reconstructed, accountId, signers, blsSig) {
  if (ethers.dataLength(blsSig) !== 256) throw new Error(`blsSig must be exactly 256 bytes, got ${ethers.dataLength(blsSig)}`);
  // Normalize to canonical 32-byte form FIRST, then sort by numeric value (BigInt compare — NOT
  // Array.sort's Number coercion, which loses precision above 2^53). Assert strictly increasing so
  // the on-chain nid <= prevId gate never rejects and duplicates are caught here.
  const norm = signers.map(s => ethers.zeroPadValue(s, 32));
  norm.sort((a, b) => (BigInt(a) < BigInt(b) ? -1 : BigInt(a) > BigInt(b) ? 1 : 0));
  for (let i = 1; i < norm.length; i++) {
    if (BigInt(norm[i]) <= BigInt(norm[i - 1])) throw new Error(`signers must be strictly increasing; dup/misorder at ${norm[i]}`);
  }
  let out = ethers.zeroPadValue(accountId, 32);
  for (const nid of norm) {
    const { slot, proof } = buildProof(reconstructed, nid);
    out = ethers.concat([out, nid, ethers.zeroPadValue(ethers.toBeHex(slot), 32), ...proof]);
  }
  return ethers.concat([out, blsSig]);
}

// ---- CLI demo ----
if (import.meta.url === `file://${process.argv[1]}`) {
  const env = loadEnv();
  const provider = new ethers.JsonRpcProvider(env.SEPOLIA_RPC_URL);
  const validator = process.env.COMMITTEE_VALIDATOR || env.COMMITTEE_VALIDATOR || "0x1A8Db639b5d8Bd5742edB083656EDD56f416cd64";
  const epoch = BigInt(process.argv[2] ?? "0");
  const nodeId = process.argv[3];
  (async () => {
    const r = await reconstructFrozenTree(provider, validator, epoch);
    console.log("frozen setRoot[" + epoch + "] reconstructed OK:", r.root, "(", r.leafMap.size, "leaves, snapBlock", r.snapBlock, ")");
    if (nodeId) console.log("proof for", nodeId, "=>", JSON.stringify(buildProof(r, nodeId)));
  })().catch(e => { console.error("proofgen:", e.message); process.exit(1); });
}
