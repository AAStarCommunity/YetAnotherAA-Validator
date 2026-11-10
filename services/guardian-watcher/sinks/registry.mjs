// DisclosureRegistry sink (W2): the writer EOA signs `disclose` txs; every completion read is at
// the FINALIZED block (publish.mjs contract). The writer must be a low-balance, single-purpose
// service EOA: assertWriterRole refuses the deployer, the aggregator owner and every guardian.
import { ethers } from "ethers";

export const REGISTRY_SINK_ABI = [
  "function disclose((uint8 kind, uint256 proposalId, bytes messageInputs, uint256 signerMask, address[] signers, bytes32 anchor) s, address subjectToken, bytes32 txHash, uint64 blockNumber, bytes20 rulesetCommit, string recordURI, bytes32 recordHash) returns (uint256)",
  "function entryOf(bytes32) view returns (uint256)",
  "function entryBinding(uint256) view returns (bytes32)",
  "function WRITER() view returns (address)",
  "event Disclosed(uint256 indexed entryId, uint8 indexed kind, uint256 indexed key, uint256 proposalId, bytes32 messageHash, address[] signers, (address subjectToken, bytes32 txHash, uint64 blockNumber, bool blockVerified, bytes20 rulesetCommit, string recordURI, bytes32 recordHash) record)",
  "event Amended(uint256 indexed entryId, (bytes32 txHash, uint64 blockNumber, bytes20 rulesetCommit, string recordURI, bytes32 recordHash) amendment, bytes32 reasonHash)",
];
export const regSinkIface = new ethers.Interface(REGISTRY_SINK_ABI);

/** Refuse a writer that holds any other role (M0 §5.5, DSR). */
export function assertWriterRole(writer, { deployer, aggregatorOwner, guardians = [] }) {
  const w = ethers.getAddress(writer);
  const bad = [
    ["deployer", deployer],
    ["aggregator owner", aggregatorOwner],
    ...guardians.map((g, i) => [`guardian ${i}`, g]),
  ].filter(([, a]) => a && ethers.getAddress(a) === w);
  if (bad.length)
    throw new Error(`writer ${w} is also the ${bad.map(b => b[0]).join(", ")}; refusing to run`);
}

export const actionId = (kind, key) =>
  ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(["uint8", "uint256"], [kind, key]));

/**
 * provider: ethers Provider with `send`; wallet: ethers Wallet (connected or not); registry address;
 * fromBlock: the registry's deploy block (log scans).
 */
export function registrySink({ provider, wallet, registry, fromBlock, feeBump = 1.25 }) {
  const addr = ethers.getAddress(registry);
  const call = async (fn, args, blockTag) =>
    regSinkIface.decodeFunctionResult(
      fn,
      await provider.call({ to: addr, data: regSinkIface.encodeFunctionData(fn, args), blockTag })
    )[0];
  const finalized = async () =>
    Number((await provider.send("eth_getBlockByNumber", ["finalized", false])).number);
  return {
    finalized,
    async canonical(n, hash) {
      const b = await provider.send("eth_getBlockByNumber", [ethers.toQuantity(Number(n)), false]);
      return !!b && String(b.hash).toLowerCase() === String(hash).toLowerCase();
    },
    async entryOf(kind, key, { blockTag } = {}) {
      return BigInt(await call("entryOf", [actionId(kind, key)], blockTag));
    },
    async entry(id, { blockTag } = {}) {
      const binding = await call("entryBinding", [id], blockTag);
      const topicId = ethers.toBeHex(BigInt(id), 32);
      const logs = name =>
        provider.getLogs({
          address: addr,
          topics: [regSinkIface.getEvent(name).topicHash, topicId],
          fromBlock,
          toBlock: blockTag,
        });
      const [d] = await logs("Disclosed");
      if (!d) return { binding, recordURI: null, recordHash: null, amendments: [] };
      const rec = regSinkIface.decodeEventLog("Disclosed", d.data, d.topics).record;
      const ams = (await logs("Amended"))
        .sort(
          (a, b) =>
            a.blockNumber - b.blockNumber || (a.index ?? a.logIndex) - (b.index ?? b.logIndex)
        )
        .map(l => regSinkIface.decodeEventLog("Amended", l.data, l.topics).amendment)
        .map(a => ({
          txHash: a.txHash,
          blockNumber: Number(a.blockNumber),
          rulesetCommit: a.rulesetCommit,
          recordURI: a.recordURI,
          recordHash: a.recordHash,
        }));
      return { binding, recordURI: rec.recordURI, recordHash: rec.recordHash, amendments: ams };
    },
    async sign(args, { nonce, replace } = {}) {
      const data = regSinkIface.encodeFunctionData("disclose", [
        args.signed,
        args.subjectToken,
        args.txHash,
        args.blockNumber,
        args.rulesetCommit,
        args.recordURI,
        args.recordHash,
      ]);
      const from = await wallet.getAddress();
      const n = nonce ?? (await provider.getTransactionCount(from, "pending"));
      const fee = await provider.getFeeData();
      const bump = x => (x == null ? x : (x * BigInt(Math.round(feeBump * 100))) / 100n);
      const tx = {
        to: addr,
        data,
        nonce: n,
        chainId: (await provider.getNetwork()).chainId,
        type: 2,
        maxFeePerGas: replace ? bump(fee.maxFeePerGas) : fee.maxFeePerGas,
        maxPriorityFeePerGas: replace ? bump(fee.maxPriorityFeePerGas) : fee.maxPriorityFeePerGas,
        gasLimit: ((await provider.estimateGas({ from, to: addr, data })) * 12n) / 10n,
      };
      const raw = await wallet.signTransaction(tx);
      return { raw, hash: ethers.keccak256(raw), nonce: n };
    },
    async broadcast(raw) {
      await provider.broadcastTransaction(raw);
    },
    async receipt(hash) {
      const rc = await provider.getTransactionReceipt(hash);
      if (!rc) return null;
      const ev = rc.logs.find(
        l =>
          ethers.getAddress(l.address) === addr &&
          l.topics[0] === regSinkIface.getEvent("Disclosed").topicHash
      );
      return {
        status: rc.status,
        entryId: ev ? BigInt(ev.topics[1]) : null,
        blockNumber: rc.blockNumber,
        blockHash: rc.blockHash,
      };
    },
    async nonce() {
      return provider.getTransactionCount(await wallet.getAddress(), await finalized());
    },
  };
}
