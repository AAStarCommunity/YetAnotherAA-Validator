// DisclosureRegistry sink (W2): the writer EOA signs `disclose` txs; every completion read is at
// the FINALIZED block (publish.mjs contract). The writer must be a low-balance, single-purpose
// service EOA: assertWriterRole refuses the deployer, the aggregator owner and every guardian.
import { ethers } from "ethers";
import { SinkError, guarded } from "./errors.mjs";

export const REGISTRY_SINK_ABI = [
  "function disclose((uint8 kind, uint256 proposalId, bytes messageInputs, uint256 signerMask, address[] signers, bytes32 anchor) s, address subjectToken, bytes32 txHash, uint64 blockNumber, bytes20 rulesetCommit, string recordURI, bytes32 recordHash) returns (uint256)",
  "function entryOf(bytes32) view returns (uint256)",
  "function entryBinding(uint256) view returns (bytes32)",
  "function WRITER() view returns (address)",
  "event Disclosed(uint256 indexed entryId, uint8 indexed kind, uint256 indexed key, uint256 proposalId, bytes32 messageHash, address[] signers, (address subjectToken, bytes32 txHash, uint64 blockNumber, bool blockVerified, bytes20 rulesetCommit, string recordURI, bytes32 recordHash) record)",
  "event Amended(uint256 indexed entryId, (bytes32 txHash, uint64 blockNumber, bytes20 rulesetCommit, string recordURI, bytes32 recordHash) amendment, bytes32 reasonHash)",
];
export const regSinkIface = new ethers.Interface(REGISTRY_SINK_ABI);

/**
 * Refuse a writer that holds any other role (M0 §5.5, DSR). Fail closed: every role must be known
 * (deployer and aggregator owner as addresses, a non-empty guardian list), or nothing is signed.
 */
/** The role set is complete and real: every address present and none of them zero. */
export function assertRolesComplete(roles) {
  const { deployer, aggregatorOwner, guardians } = roles ?? {};
  const real = a => ethers.isAddress(a) && ethers.getAddress(a) !== ethers.ZeroAddress;
  for (const [n, a] of [
    ["deployer", deployer],
    ["aggregator owner", aggregatorOwner],
  ])
    if (!real(a)) throw new SinkError(`writer role check: ${n} unknown; refusing to run`);
  if (!Array.isArray(guardians) || guardians.length === 0 || !guardians.every(real))
    throw new SinkError("writer role check: guardian list unknown; refusing to run");
}

export function assertWriterRole(writer, roles) {
  assertRolesComplete(roles);
  const { deployer, aggregatorOwner, guardians } = roles;
  const need = [
    ["deployer", deployer],
    ["aggregator owner", aggregatorOwner],
  ];
  const w = ethers.getAddress(writer);
  const bad = [...need, ...guardians.map((g, i) => [`guardian ${i}`, g])].filter(
    ([, a]) => ethers.getAddress(a) === w
  );
  if (bad.length)
    throw new SinkError(
      `writer ${w} is also the ${bad.map(b => b[0]).join(", ")}; refusing to run`
    );
}

// A record URI read from chain is untrusted text: only our own form leaves this sink; anything
// else becomes a marker that can never equal ours (Codex W2b R3 M3).
const uriOf = u => (/^ipfs:\/\/b[a-z2-7]{20,100}$/.test(String(u)) ? u : "invalid:uri");
// The digest of the ORIGINAL string, so distinct rejected values stay distinguishable (R4 L5).
const uriKeccak = u => ethers.keccak256(ethers.toUtf8Bytes(String(u)));

export const actionId = (kind, key) =>
  ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(["uint8", "uint256"], [kind, key]));

/**
 * Whether a broadcast error says the node already holds this exact tx (Codex W2c R4/R5). Each
 * message is matched WHOLE against the known client phrasings, never as a substring of joined
 * wrapper text ("unknown transaction" must not match "known transaction").
 */
export function alreadyKnown(e) {
  const known = new Set([
    "already known", // geth
    "known transaction", // older geth
    "transaction already imported", // nethermind / parity
  ]);
  const norm = m =>
    String(m)
      .trim()
      .toLowerCase()
      .replace(/^(rpc error|error|returned error):\s*/, "")
      .replace(/[.]$/, "");
  return [e?.error?.message, e?.info?.error?.message, e?.message]
    .filter(x => typeof x === "string")
    .some(m => known.has(norm(m)) || /^known transaction: 0x[0-9a-f]{64}$/.test(norm(m)));
}

/**
 * provider: ethers Provider with `send`; wallet: ethers Wallet (connected or not); registry address;
 * fromBlock: the registry's deploy block (log scans); roles: { deployer, aggregatorOwner, guardians }
 * (required: the wallet is checked against them before anything is signed).
 */
export function registrySink({
  provider,
  wallet,
  registry,
  fromBlock,
  roles,
  currentRoles,
  feeBump = 1.25,
  maxFeePerGas: feeCapIn,
  chainId: chainIdIn,
}) {
  const addr = ethers.getAddress(registry);
  // the configured chain (#413 review N2): every signature is for it, and only while the RPC is on
  // it; a wrong or hostile RPC cannot get a disclose tx signed for another chain
  let chainId;
  try {
    chainId = BigInt(chainIdIn);
  } catch {
    chainId = 0n;
  }
  if (!(chainId > 0n)) throw new SinkError("registry: chainId (the configured chain) is required");
  if (!(feeBump >= 1.125))
    throw new SinkError("registry: feeBump must be >= 1.125 (replacement rule)");
  // An absolute ceiling on maxFeePerGas, from config (#411 review F1, DSR): no fee ever above it.
  let feeCap;
  try {
    feeCap = BigInt(feeCapIn);
  } catch {
    feeCap = 0n;
  }
  if (!(feeCap > 0n))
    throw new SinkError("registry: maxFeePerGas (an absolute wei ceiling) is required");
  // completeness now (a zero address counts as unknown, #411 review F5); the wallet before signing
  assertRolesComplete(roles);
  const bumpNum = BigInt(Math.ceil(feeBump * 1000));
  // rounded up, and at least +1 wei, so a zero (or tiny) fee field still strictly rises (W2b R8)
  const bumpUp = x => {
    const b = (x * bumpNum + 999n) / 1000n;
    return b > x ? b : x + 1n;
  };
  const big = x => (x == null ? null : BigInt(x));
  const max = (a, b) => (a > b ? a : b);
  const call = async (fn, args, blockTag) =>
    regSinkIface.decodeFunctionResult(
      fn,
      await provider.call({ to: addr, data: regSinkIface.encodeFunctionData(fn, args), blockTag })
    )[0];
  const finalized = async () =>
    Number((await provider.send("eth_getBlockByNumber", ["finalized", false])).number);
  const api = {
    // which registry this sink writes to (W2d): every journal's registry stage is bound to it
    address: addr,
    chainId,
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
          recordURI: uriOf(a.recordURI),
          recordURIKeccak: uriKeccak(a.recordURI),
          recordHash: a.recordHash,
        }));
      return {
        binding,
        recordURI: uriOf(rec.recordURI),
        recordURIKeccak: uriKeccak(rec.recordURI),
        recordHash: rec.recordHash,
        amendments: ams,
      };
    },
    /**
     * Sign a disclose tx. With `replace`, `prevRaw` (the journalled raw tx being replaced) is
     * required: it must be ours, at the same nonce, and both fees become
     * max(current estimate, ceil(its fee * feeBump)), so every replacement clears the node's
     * >= 10% rule however the estimate moved, and successive replacements keep rising.
     */
    async sign(args, { nonce, replace, prevRaw } = {}) {
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
      assertWriterRole(from, roles);
      // Roles change between the pass's read and this signature (Codex W2c R1 H2): re-read them
      // now, at the current state, immediately before EVERY signature, replacements included. Any
      // failure to read them is a refusal, never a fallback to the older set.
      if (currentRoles) {
        let now;
        try {
          now = await currentRoles();
        } catch {
          throw new SinkError("writer role check: current roles unreadable; refusing to sign");
        }
        assertWriterRole(from, now);
      }
      const n = nonce ?? (await provider.getTransactionCount(from, "pending"));
      const fee = await provider.getFeeData();
      let maxFee = big(fee.maxFeePerGas);
      let tip = big(fee.maxPriorityFeePerGas);
      if (maxFee == null || tip == null) throw new SinkError("registry: no EIP-1559 fee data");
      if (replace) {
        let last;
        try {
          last = ethers.Transaction.from(prevRaw);
        } catch {
          throw new SinkError(
            "registry: a replacement needs the replaced tx's journalled raw bytes"
          );
        }
        if (last.from !== from || last.nonce !== n || last.type !== 2)
          throw new SinkError("registry: the journalled tx is not ours at this nonce; refusing");
        const pf = big(last.maxFeePerGas);
        const pt = big(last.maxPriorityFeePerGas);
        maxFee = max(maxFee, bumpUp(pf));
        tip = max(tip, bumpUp(pt));
      }
      if (tip > maxFee) maxFee = tip;
      // never above the configured ceiling: the caller alerts (degraded) instead of escalating
      if (maxFee > feeCap)
        throw new SinkError(
          "registry: the fee needed exceeds the configured maxFeePerGas",
          "FEE_CAP"
        );
      if (BigInt((await provider.getNetwork()).chainId) !== chainId)
        throw new SinkError(
          "registry: the RPC is on another chain than the configured chainId",
          "CHAIN"
        );
      const tx = {
        to: addr,
        data,
        nonce: n,
        chainId,
        type: 2,
        maxFeePerGas: maxFee,
        maxPriorityFeePerGas: tip,
        gasLimit: ((await provider.estimateGas({ from, to: addr, data })) * 12n) / 10n,
      };
      const raw = await wallet.signTransaction(tx);
      return {
        raw,
        hash: ethers.keccak256(raw),
        nonce: n,
        fees: { maxFeePerGas: maxFee.toString(), maxPriorityFeePerGas: tip.toString() },
      };
    },
    async broadcast(raw) {
      try {
        await provider.broadcastTransaction(raw);
      } catch (e) {
        // Rebroadcasting a tx the node already holds is the normal pending case, not a failure
        // (the text is only classified here; it never leaves this sink).
        if (alreadyKnown(e)) return { known: true };
        throw e;
      }
    },
    /** Does the node know this tx (pending or mined)? A replacement's fee floor is taken only
     * from a tx some node accepted (#411 review F1). */
    async knows(hash) {
      return (await provider.send("eth_getTransactionByHash", [hash])) != null;
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
  // Error boundary (Codex W2b R2 H3): an RPC failure leaves as "registry <op>: <code>", never with
  // the provider's message, URL or response.
  for (const k of Object.keys(api)) {
    const f = api[k];
    api[k] = (...a) => guarded(`registry ${k}`, () => f(...a));
  }
  return api;
}
