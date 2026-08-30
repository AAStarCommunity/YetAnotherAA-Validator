// CC-98 snapshotEpoch keeper — permissionless per-epoch pin for AAStarCommitteeValidator.
//
// Committee mode fails closed unless each epoch is pinned within its 256-block window (blockhash
// availability). This keeper polls the validator and calls snapshotEpoch() when the CURRENT epoch is
// unpinned and still inside its window. Any funded key can run it (permissionless); run several for
// redundancy — a missed window fail-closes committee ops for that epoch and the next, then self-heals.
//
// While epochLength == 0 (committee mode OFF) snapshotEpoch reverts and this keeper idles.
//
// Works against BOTH validator generations: it selects `snapshotEpoch(bytes32[])` (CC-112 D2, #244) or
// the pre-D2 `snapshotEpoch()` by looking for the selector in the deployed bytecode.
//
// env (.env.sepolia): SEPOLIA_RPC_URL, KEEPER_PRIVATE_KEY (or PRIVATE_KEY), COMMITTEE_VALIDATOR
// Usage: node deploy/committee-keeper.mjs            (one pass)
//        node deploy/committee-keeper.mjs --watch    (loop every ~30s)
import { ethers } from "ethers";
import { readFileSync } from "fs";

const strip = s => s.replace(/^["']|["']$/g, "");
const env = Object.fromEntries(
  readFileSync(".env.sepolia", "utf8")
    .split("\n").filter(l => l.includes("="))
    .map(l => { const i = l.indexOf("="); return [l.slice(0, i).trim(), strip(l.slice(i + 1).trim())]; })
);
const RPC = env.SEPOLIA_RPC_URL || env.ETH_RPC_URL;
const KEY = env.KEEPER_PRIVATE_KEY || env.PRIVATE_KEY;
const VALIDATOR = process.env.COMMITTEE_VALIDATOR || env.COMMITTEE_VALIDATOR || "0x1A8Db639b5d8Bd5742edB083656EDD56f416cd64";
const WATCH = process.argv.includes("--watch");
// keccak("snapshotEpoch(bytes32[])")[0:4], the D2 stake-aware form.
const D2_SNAPSHOT_SELECTOR = "1ed58d67";

const ABI = [
  "function epochLength() view returns(uint256)",
  "function epochPinned(uint256) view returns(bool)",
  "function epochConfigVersion(uint256) view returns(uint256)",
  "function configVersion() view returns(uint256)",
  "function snapshotEpoch(bytes32[] activeNodeIds)",
  // Pre-D2 validators (deployed before #244) expose the no-argument form. The live Sepolia validator
  // 0x1A8Db639 is one of them, so a keeper that only knows the D2 shape cannot pin production at all.
  "function snapshotEpoch()",
  "function isEligibleForSnapshot(bytes32) view returns(bool)",
  "function activeCount() view returns(uint256)",
  "event SlotAssigned(bytes32 indexed nodeId, uint256 slot)",
  "event SlotCleared(bytes32 indexed nodeId, uint256 slot)",
];

/// Rebuild the active set from SlotAssigned/SlotCleared in strict log order, sorted ascending — the
/// order `snapshotEpoch` requires.
///
/// CHUNKED and pinned to a single head, like proofgen. A bare `queryFilter(filter)` defaults to
/// 0..latest in ethers v6, so as SlotAssigned history and churn grow it eventually exceeds the common
/// ~10k-log RPC cap and throws EVERY tick — the keeper would then miss its pin window entirely, and
/// the activeCount cross-check cannot save a request that never returns. Both filters are read at the
/// SAME head so the reconstruction and the cross-check describe one consistent state.
async function activeSetFromEvents(v, provider) {
  const head = await provider.getBlockNumber();
  const fromBlock = Number(process.env.DEPLOY_BLOCK ?? 0);
  if (!process.env.DEPLOY_BLOCK) {
    console.warn("  keeper: DEPLOY_BLOCK unset — scanning from block 0 (set it to the validator's creation block)");
  }
  const CHUNK = 9000;
  const getLogsChunked = async filter => {
    const out = [];
    for (let from = fromBlock; from <= head; from += CHUNK + 1) {
      out.push(...(await v.queryFilter(filter, from, Math.min(from + CHUNK, head))));
    }
    return out;
  };
  const assigned = await getLogsChunked(v.filters.SlotAssigned());
  const cleared = await getLogsChunked(v.filters.SlotCleared());
  // Strict LOG ORDER — ethers v6 exposes the intra-block position as `Log.index`; using the wrong
  // field yields NaN and leaves same-tx events in concatenation order, corrupting slot-rotation replay.
  const mutations = [...assigned.map(e => ({ e, kind: "assign" })), ...cleared.map(e => ({ e, kind: "clear" }))]
    .sort((a, b) =>
      a.e.blockNumber - b.e.blockNumber ||
      a.e.transactionIndex - b.e.transactionIndex ||
      a.e.index - b.e.index);
  const bySlot = new Map();
  for (const m of mutations) {
    const slot = BigInt(m.e.args.slot);
    if (m.kind === "assign") bySlot.set(slot, m.e.args.nodeId);
    else bySlot.delete(slot);
  }
  const ids = [...bySlot.values()].sort((a, b) => (BigInt(a) < BigInt(b) ? -1 : BigInt(a) > BigInt(b) ? 1 : 0));
  // Cross-check against the contract's own counter AT THE SAME HEAD: if these disagree the replay is
  // wrong and the snapshot would revert anyway — better to say so than to send a doomed transaction.
  const onChain = Number(await v.activeCount({ blockTag: head }));
  if (ids.length !== onChain) {
    throw new Error(`active-set replay mismatch at block ${head}: ${ids.length} from events vs activeCount ${onChain}`);
  }
  return ids;
}

async function tick() {
  const provider = new ethers.JsonRpcProvider(RPC);
  const wallet = new ethers.Wallet(KEY, provider);
  const v = new ethers.Contract(VALIDATOR, ABI, wallet);

  const epochLength = await v.epochLength();
  if (epochLength === 0n) { console.log(new Date().toISOString(), "epochLength=0 (committee OFF) — idle"); return; }

  const bn = BigInt(await provider.getBlockNumber());
  const e = bn / epochLength;
  const start = e * epochLength;
  const pinned = await v.epochPinned(e);
  const usable = pinned && (await v.epochConfigVersion(e)) === (await v.configVersion());

  // Window: strictly after the epoch's first block, within 256 blocks (blockhash availability).
  const inWindow = bn > start && bn <= start + 256n;

  if (usable) { console.log(new Date().toISOString(), `epoch ${e} already pinned (usable) — nothing to do`); return "ok"; }
  if (!inWindow) {
    console.log(new Date().toISOString(), `epoch ${e}: block ${bn} outside pin window [${start + 1n}, ${start + 256n}] — cannot pin (self-heals next epoch)`);
    return "outside-window";
  }
  console.log(new Date().toISOString(), `epoch ${e}: pinning (block ${bn}, window ok)...`);
  try {
    // CC-112 D2: the snapshot is stake-aware, so it takes the COMPLETE active set and verifies every
    // member is eligible (ROLE_DVT, >= minStake, no ROLE_DVT exit notice in flight). The contract
    // proves the list complete against its own storage — this is a convenience read, not a trusted input.
    //
    // Rebuilt from events rather than the contract's `activeNodeIdsSorted()` helper: that helper scans
    // the unbounded `registeredNodes` array and de-duplicates in O(n^2), which is fine for a local call
    // but is exactly what its own NatSpec tells production keepers not to rely on.
    // Pick the snapshotEpoch the DEPLOYED validator actually implements. #244 (CC-112 D2) changed the
    // signature to take the complete active set; validators deployed before it only have the
    // no-argument form. Selecting on the contract's own bytecode rather than assuming keeps one keeper
    // able to operate both — without this, master's keeper silently could not pin the live validator,
    // which is how epochs went unpinned and requiredQuorum() sat at the unsatisfiable sentinel while
    // committeeActive() still read true (the worst intermediate state).
    const code = await provider.getCode(VALIDATOR);
    const hasStakeAware = code.includes(D2_SNAPSHOT_SELECTOR);
    const tx = hasStakeAware
      ? await v["snapshotEpoch(bytes32[])"](await activeSetFromEvents(v, provider))
      : await v["snapshotEpoch()"]();
    if (!hasStakeAware) console.log("  (pre-D2 validator: using the no-argument snapshotEpoch)");
    console.log("  snapshotEpoch tx:", tx.hash);
    const r = await tx.wait(1, 120000); // 120s timeout so a mispriced tx doesn't hang forever
    if (!r) { console.warn("  pin tx not mined within timeout — retry next tick"); return "timeout"; }
    console.log("  pinned in block", r.blockNumber, "status", r.status);
    return "pinned";
  } catch (err) {
    const msg = err.shortMessage || err.reason || err.code || err.message || "";
    // A redundant keeper that lost the race sees "epoch already pinned" — benign, log-and-continue.
    if (/already pinned/i.test(msg)) { console.log("  another keeper pinned it first (benign):", msg); return "ok"; }
    // A set change between the event replay and the transaction makes the list stale; the contract's
    // completeness check rejects it and the next tick rebuilds from a fresh head.
    if (/activeNodeIds length != activeCount|contains a non-member/i.test(msg)) {
      console.log("  set changed under the replay — retry next tick (benign)");
      return "retry";
    }
    // An ineligible member must be evicted first; syncNode is permissionless, so name the offenders.
    if (/ineligible node in set/i.test(msg)) {
      const ids = await activeSetFromEvents(v, provider).catch(() => []);
      const bad = [];
      for (const id of ids) { if (!(await v.isEligibleForSnapshot(id).catch(() => true))) bad.push(id); }
      // syncNode handles role/stake staleness; an in-flight ROLE_DVT exit notice needs syncExitNotice,
      // because SP keeps role AND stake intact for the whole notice and syncNode would revert.
      console.error("  blocked by ineligible nodes — call syncNode (stake/role) or syncExitNotice (exit notice) on:",
        bad.length ? bad : "(could not enumerate)");
      return "ineligible";
    }
    console.error("  snapshotEpoch FAILED:", msg);
    return "error";
  }
}

if (WATCH) {
  console.log("keeper watching", VALIDATOR, "— Ctrl-C to stop");
  const loop = async () => { try { await tick(); } catch (e) { console.error("tick err", e.shortMessage || e.message); } setTimeout(loop, 30000); };
  loop();
} else {
  tick()
    .then(status => { if (status === "error" || status === "timeout") process.exit(1); }) // cron/systemd must see failure
    .catch(e => { console.error(e.shortMessage || e.message); process.exit(1); });
}
