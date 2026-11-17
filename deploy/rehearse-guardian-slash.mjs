// #441 acceptance on a LOCAL anvil: a commitment written by BLSAggregator-4.13.0+ through its real
// execute path, recomputed by the parent-block-hash verifier (OverIssueFraudProofVerifier-2.0.0), and
// the full queueGuardianSlash -> executeGuardianSlash chain.
//
// Run through deploy/rehearse-guardian-slash.sh, which starts a fresh anvil, runs SP's DeployAnvil
// and passes the paths here. Local chain 31337 only; throwaway keys only (generated per run).
//
// The chain needs two things rc.8 will NOT have; this script sets them explicitly and records them,
// because they are the two 5.5.x enablement steps:
//   E1  GTokenStaking.setAuthorizedSlasher(aggregator, true)
//   E2  aggregator.proposeFraudProofVerifier(v2) -> wait VERIFIER_ROTATION_DELAY -> applyFraudProofVerifier()
//
// Usage: node deploy/rehearse-guardian-slash.mjs <rpc> <sp config.anvil.json> <dvt contracts/out dir> <report.json>
import { ethers } from "ethers";
import { readFileSync, writeFileSync } from "fs";
import { bls12_381 as bls } from "@noble/curves/bls12-381.js";

const [RPC, SP_CONFIG, DVT_OUT, REPORT] = process.argv.slice(2);
if (!REPORT) {
  console.error(
    "usage: rehearse-guardian-slash.mjs <rpc> <sp config.anvil.json> <dvt contracts/out> <report.json>"
  );
  process.exit(2);
}
const DST = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"; // SP BLS.hashToG2 uses this for every message
// anvil's well-known account 0 (the DeployAnvil deployer and owner of everything), chain 31337 only.
const K0 = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const ROLE_DVT = ethers.id("DVT");
const SLASH_LEVEL = 1; // MINOR: threshold 3 of 3
const EPOCH = 1n;
const coder = ethers.AbiCoder.defaultAbiCoder();

const report = { purpose: "#441 acceptance (anvil, throwaway keys)", steps: [], checks: [] };
let failed = false;
const step = (name, data = {}) => {
  report.steps.push({ name, ...data });
  console.log(`· ${name}${data.tx ? `  tx ${data.tx}` : ""}`);
};
const check = (name, ok, detail = {}) => {
  report.checks.push({ name, ok, ...detail });
  console.log(`${ok ? "✓" : "✗"} ${name}`);
  if (!ok) failed = true;
};

const provider = new ethers.JsonRpcProvider(RPC);
const owner = new ethers.NonceManager(new ethers.Wallet(K0, provider));
const net = await provider.getNetwork();
if (net.chainId !== 31337n) {
  console.error(`refusing: chainId ${net.chainId} is not a local anvil (31337)`);
  process.exit(2);
}
const cfg = JSON.parse(readFileSync(SP_CONFIG, "utf8"));
const artifact = name => JSON.parse(readFileSync(`${DVT_OUT}/${name}.sol/${name}.json`, "utf8"));

const AGG_ABI = [
  "function version() view returns (string)",
  "function owner() view returns (address)",
  "function popDigest(address,(bytes32,bytes32,bytes32,bytes32)) view returns (bytes32)",
  "function verifyAndExecute(uint256,address,uint8,address[],uint256[],uint256,bytes32,bytes)",
  "function queueSlashWithConsensus(address,uint8,uint256,bytes)",
  "function domainSeparator() view returns (bytes32)",
  "function proposalSignersCommitment(uint256) view returns (bytes32)",
  "function proposeFraudProofVerifier(address)",
  "function applyFraudProofVerifier()",
  "function fraudProofVerifier() view returns (address)",
  "function VERIFIER_ROTATION_DELAY() view returns (uint256)",
  "function queueGuardianSlash(uint256,address[],bytes)",
  "function executeGuardianSlash(uint256,address[],bytes)",
  "function guardianSlashCases(uint256) view returns (bytes32,bytes32,uint64,uint8,uint16,uint16,uint16,address)",
  "function guardianSlashBps() view returns (uint16)",
  "function slashThresholds(uint8) view returns (uint256)",
  "event GuardianSlashQueued(uint256 indexed fraudProofId, bytes32 guardiansHash, uint256 deadline, address[] guardians)",
  "event GuardianSlashed(uint256 indexed fraudProofId, address indexed guardian, uint256 penalty)",
  "event GuardianSlashFailed(uint256 indexed fraudProofId, address indexed guardian)",
  "event SignersCommitted(uint256 indexed proposalId, uint256 signerMask)",
  "error InvalidFraudProof(uint256)",
];
const DVT_ABI = [
  "function registerBLSPublicKey(address,(bytes32,bytes32,bytes32,bytes32),uint8,(bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32))",
  "function addValidator(address)",
  "function nextProposalId() view returns (uint256)",
  "function createProposal(address,uint8,string,bytes32) returns (uint256)",
  "function queueSlashWithProof(address,uint8,uint256,bytes)",
  "function executeWithProof(uint256,address[],uint256[],uint256,bytes)",
];
const REG_ABI = [
  "function registerRole(bytes32,address,bytes)",
  "function getRoleConfig(bytes32) view returns ((uint256 minStake,uint256 ticketPrice,uint32 slashThreshold,uint32 slashBase,uint32 slashInc,uint32 slashMax,uint16 exitFeePercent,bool isActive,uint256 minExitFee,string description,address owner,uint256 roleLockDuration))",
  "function hasRole(bytes32,address) view returns (bool)",
];
const STAKING_ABI = [
  "function setAuthorizedSlasher(address,bool)",
  "function authorizedSlashers(address) view returns (bool)",
  "function roleLocks(address,bytes32) view returns (uint128,uint128,uint48,bytes32,bytes)",
];
const TOKEN_ABI = [
  "function mint(address,uint256)",
  "function approve(address,uint256) returns (bool)",
];

const agg = new ethers.Contract(cfg.blsAggregator, AGG_ABI, owner);
const dvt = new ethers.Contract(cfg.dvtValidator, DVT_ABI, owner);
const registry = new ethers.Contract(cfg.registry, REG_ABI, owner);
const staking = new ethers.Contract(cfg.staking, STAKING_ABI, owner);
const gtoken = new ethers.Contract(cfg.gToken, TOKEN_ABI, owner);
const send = async (label, p, extra = {}) => {
  const tx = await p;
  const rc = await tx.wait();
  step(label, { tx: tx.hash, block: rc.blockNumber, ...extra });
  return rc;
};

const words = (hex, n) => {
  const b = ethers.getBytes(hex);
  if (b.length !== n) throw new Error(`expected ${n} bytes`);
  const w = [];
  for (let i = 0; i < n; i += 32) w.push(ethers.hexlify(b.slice(i, i + 32)));
  return w;
};
const fp = (v, o, at) => o.set(ethers.getBytes("0x" + v.toString(16).padStart(96, "0")), at);
const encG1 = p => {
  const o = new Uint8Array(128),
    a = p.toAffine();
  fp(a.x, o, 16);
  fp(a.y, o, 80);
  return ethers.hexlify(o);
};
const encG2 = p => {
  const o = new Uint8Array(256),
    a = p.toAffine();
  fp(a.x.c0, o, 16);
  fp(a.x.c1, o, 80);
  fp(a.y.c0, o, 144);
  fp(a.y.c1, o, 208);
  return ethers.hexlify(o);
};
const signHash = async (hash, sk) =>
  bls.longSignatures.sign(await bls.G2.hashToCurve(ethers.getBytes(hash), { DST }), sk);

const aggVersion = await agg.version();
check(
  "aggregator is an anchored release (>= 4.13.0)",
  /^BLSAggregator-(4\.(1[3-9]|[2-9]\d)|[5-9])/.test(aggVersion),
  {
    version: aggVersion,
  }
);
report.aggregator = cfg.blsAggregator;
report.aggregatorVersion = aggVersion;

// ---- 1. three throwaway guardians with ROLE_DVT stake and BLS keys ------------------------------
const roleCfg = await registry.getRoleConfig(ROLE_DVT);
const stake = roleCfg.minStake > 0n ? roleCfg.minStake : ethers.parseEther("30");
const guardians = [];
for (let i = 1; i <= 3; i++) {
  const w = new ethers.NonceManager(ethers.Wallet.createRandom().connect(provider));
  w.address = await w.getAddress();
  const sk = bls.utils.randomSecretKey();
  const pk = bls.longSignatures.getPublicKey(sk);
  guardians.push({
    slot: i,
    wallet: w,
    address: w.address,
    sk,
    pk,
    pkWords: words(encG1(pk), 128),
  });
  await send(
    `fund guardian ${i}`,
    owner.sendTransaction({ to: w.address, value: ethers.parseEther("1") })
  );
  await send(
    `mint GToken to guardian ${i}`,
    gtoken.mint(w.address, stake + roleCfg.ticketPrice + ethers.parseEther("10"))
  );
  const asG = c => c.connect(w);
  await send(`guardian ${i} approves staking`, asG(gtoken).approve(cfg.staking, ethers.MaxUint256));
  await send(
    `guardian ${i} registerRole(ROLE_DVT)`,
    asG(registry).registerRole(ROLE_DVT, w.address, coder.encode(["uint256"], [stake]))
  );
  const digest = await agg.popDigest(w.address, guardians[i - 1].pkWords);
  const pop = words(encG2(await signHash(digest, sk)), 256);
  await send(
    `register guardian ${i} BLS key, slot ${i} (owner path)`,
    dvt.registerBLSPublicKey(w.address, guardians[i - 1].pkWords, i, pop)
  );
}
check(
  "all three guardians hold ROLE_DVT",
  (await Promise.all(guardians.map(g => registry.hasRole(ROLE_DVT, g.address)))).every(Boolean)
);
for (const g of guardians)
  await send(`DVTValidator.addValidator(guardian ${g.slot}) (owner)`, dvt.addValidator(g.address));

// ---- 2. the v2 verifier and an over-issue token that is NOT over-issued (the slash was fraud) ---
const deploy = async (name, args = []) => {
  const a = artifact(name);
  const f = new ethers.ContractFactory(a.abi, a.bytecode.object, owner);
  const c = await f.deploy(...args);
  await c.waitForDeployment();
  step(`deploy ${name}`, { address: await c.getAddress() });
  return c;
};
const verifier = await deploy("OverIssueFraudProofVerifier", [cfg.blsAggregator, cfg.registry]);
const token = await deploy("MockOverIssuableToken");
check(
  "verifier build marker",
  (await verifier.VERIFIER_VERSION()) === "OverIssueFraudProofVerifier-2.0.0" &&
    (await verifier.COMMITMENT_BINDS_PARENT_BLOCKHASH()) === true
);
const tokenAddr = await token.getAddress();
// The slash target is the DeployAnvil deployer, a registered SuperPaymaster operator, so the SP side of
// the slash runs for real: queueSlashWithConsensus (BLS) then verifyAndExecute -> executeSlashWithBLS.
const operator = await owner.getAddress();
report.operator = operator;

// ---- 3. the guardians sign a slash; the aggregator executes it through verifyAndExecute -------
const evidenceHash = await verifier.evidenceHash(tokenAddr, operator, EPOCH);
// Guardian 1 files the proposal on the DVTValidator (the production path); the DVT allocates the id.
const g1dvt = dvt.connect(guardians[0].wallet);
const PROPOSAL_ID = await dvt.nextProposalId();
await send(
  "guardian 1 DVTValidator.createProposal(operator, MINOR, reason, evidenceHash)",
  g1dvt.createProposal(
    operator,
    SLASH_LEVEL,
    "441 acceptance: over-issue slash that is actually fraudulent",
    evidenceHash
  ),
  { proposalId: PROPOSAL_ID.toString() }
);
report.proposalId = PROPOSAL_ID.toString();
const messageHash = await verifier.slashMessageHash(
  PROPOSAL_ID,
  operator,
  SLASH_LEVEL,
  EPOCH,
  tokenAddr
);
const MASK0 = 0b111n;
const aggDomain = await agg.domainSeparator();
check(
  "verifier and aggregator agree on the domain separator",
  aggDomain === (await verifier.domainSeparator())
);
const queueHash = ethers.keccak256(
  coder.encode(
    ["bytes32", "bytes32", "address", "uint8", "uint256"],
    [aggDomain, ethers.id("SuperPaymaster.BLS.QueueSlash.v1"), operator, SLASH_LEVEL, EPOCH]
  )
);
const qSigs = await Promise.all(guardians.map(g => signHash(queueHash, g.sk)));
const qProof = coder.encode(
  ["uint256", "bytes"],
  [MASK0, encG2(bls.longSignatures.aggregateSignatures(qSigs))]
);
const qsRc = await send(
  "guardian 1 DVTValidator.queueSlashWithProof (BLS, SP two-step slash, step 1)",
  g1dvt.queueSlashWithProof(operator, SLASH_LEVEL, EPOCH, qProof)
);
const queueCommit = await agg.proposalSignersCommitment(BigInt(queueHash));
check(
  "the queue path stored its commitment under key uint256(messageHash)",
  queueCommit !== ethers.ZeroHash,
  { key: queueHash, block: qsRc.blockNumber }
);
const sigs = await Promise.all(guardians.map(g => signHash(messageHash, g.sk)));
const aggSig = bls.longSignatures.aggregateSignatures(sigs);
const MASK = 0b111n;
const proof = coder.encode(["uint256", "bytes"], [MASK, encG2(aggSig)]);
const execRc = await send(
  "guardian 1 DVTValidator.executeWithProof -> aggregator.verifyAndExecute (SP two-step slash step 2; writes the signer commitment)",
  g1dvt.executeWithProof(PROPOSAL_ID, [], [], EPOCH, proof),
  {
    proposalId: PROPOSAL_ID.toString(),
    threshold: (await agg.slashThresholds(SLASH_LEVEL)).toString(),
  }
);
const commitment = await agg.proposalSignersCommitment(PROPOSAL_ID);
check("the aggregator itself stored a non-zero commitment", commitment !== ethers.ZeroHash, {
  commitment,
});
const parentBlockHash = (await provider.getBlock(execRc.blockNumber - 1)).hash;
report.executionBlock = execRc.blockNumber;
report.parentBlockHash = parentBlockHash;

const sorted = guardians.map(g => g.address).sort((a, b) => (BigInt(a) < BigInt(b) ? -1 : 1));
const domainSep = await verifier.domainSeparator();
const recompute = withParent =>
  ethers.keccak256(
    withParent
      ? coder.encode(
          ["bytes32", "bytes32", "uint256", "bytes32", "uint256", "address[]", "bytes32"],
          [
            domainSep,
            ethers.id("SuperPaymaster.BLS.SignersCommitment.v1"),
            PROPOSAL_ID,
            messageHash,
            MASK,
            sorted,
            parentBlockHash,
          ]
        )
      : coder.encode(
          ["bytes32", "bytes32", "uint256", "bytes32", "uint256", "address[]"],
          [
            domainSep,
            ethers.id("SuperPaymaster.BLS.SignersCommitment.v1"),
            PROPOSAL_ID,
            messageHash,
            MASK,
            sorted,
          ]
        )
  );
check(
  "the 4.14 pre-image WITH the parent block hash reproduces the stored commitment",
  recompute(true) === commitment
);
check(
  "the 4.11 pre-image WITHOUT it does not (the #441 bug, observed)",
  recompute(false) !== commitment
);

// ---- 4. enablement step E2: arm the v2 verifier --------------------------------------------------
await send(
  "E2a proposeFraudProofVerifier(v2) (owner)",
  agg.proposeFraudProofVerifier(await verifier.getAddress())
);
const delay = await agg.VERIFIER_ROTATION_DELAY();
await provider.send("evm_increaseTime", [Number(delay)]);
await provider.send("evm_mine", []);
step(`wait VERIFIER_ROTATION_DELAY (${delay} s, anvil time warp)`);
await send("E2b applyFraudProofVerifier() (permissionless)", agg.applyFraudProofVerifier());
check(
  "fraudProofVerifier() is the v2 verifier",
  (await agg.fraudProofVerifier()).toLowerCase() === (await verifier.getAddress()).toLowerCase()
);

// ---- 5. proofs -----------------------------------------------------------------------------------
const fraudProofId = await verifier.deriveFraudProofId(PROPOSAL_ID);
const proofV2 = parent =>
  coder.encode(
    ["uint256", "address", "uint8", "uint256", "address", "uint256", "address[]", "bytes32"],
    [PROPOSAL_ID, operator, SLASH_LEVEL, EPOCH, tokenAddr, MASK, sorted, parent]
  );
const proofOld = coder.encode(
  ["uint256", "address", "uint8", "uint256", "address", "uint256", "address[]"],
  [PROPOSAL_ID, operator, SLASH_LEVEL, EPOCH, tokenAddr, MASK, sorted]
);
const flipped = ethers.hexlify(
  Uint8Array.from(ethers.getBytes(parentBlockHash), (b, i) => (i === 31 ? b ^ 1 : b))
);
const queueRejects = async (label, p) => {
  try {
    await agg.queueGuardianSlash.staticCall(fraudProofId, sorted, p);
    check(label, false, { got: "accepted" });
  } catch (e) {
    const name = agg.interface.parseError(e.data ?? "0x")?.name ?? e.shortMessage;
    check(label, name === "InvalidFraudProof", { revert: name });
  }
};
await queueRejects("N1 old 7-field proof (no parent block hash) -> InvalidFraudProof", proofOld);
await queueRejects("N2 parent block hash off by one bit -> InvalidFraudProof", proofV2(flipped));
check(
  "verifier.verify accepts the correct proof directly",
  await verifier.verify(
    await (async () => {
      const a = new ethers.Contract(
        cfg.blsAggregator,
        ["function fraudProofDigest(uint256,address[]) view returns (bytes32)"],
        provider
      );
      return a.fraudProofDigest(fraudProofId, sorted);
    })(),
    fraudProofId,
    sorted,
    proofV2(parentBlockHash)
  )
);

// ---- 6. queue -> execute ---------------------------------------------------------------------------
const qRc = await send(
  "queueGuardianSlash (correct proof)",
  agg.queueGuardianSlash(fraudProofId, sorted, proofV2(parentBlockHash))
);
check(
  "GuardianSlashQueued emitted",
  qRc.logs.some(l => {
    try {
      return agg.interface.parseLog(l)?.name === "GuardianSlashQueued";
    } catch {
      return false;
    }
  })
);

const locksBefore = await Promise.all(sorted.map(a => staking.roleLocks(a, ROLE_DVT)));
const wasAuthorized = await staking.authorizedSlashers(cfg.blsAggregator);
report.slasherAuthorizedAfterDeployAnvil = wasAuthorized;
check(
  "DeployAnvil leaves the aggregator NOT authorised as slasher (as rc.8 will)",
  wasAuthorized === false
);
if (wasAuthorized)
  await send(
    "deauthorize the aggregator as slasher (to observe E1 is load-bearing)",
    staking.setAuthorizedSlasher(cfg.blsAggregator, false)
  );
const names = rc =>
  rc.logs
    .map(l => {
      try {
        return agg.interface.parseLog(l)?.name;
      } catch {
        return null;
      }
    })
    .filter(Boolean);
const e1 = await send(
  "executeGuardianSlash WITHOUT slasher authorization",
  agg.executeGuardianSlash(fraudProofId, sorted, proofV2(parentBlockHash))
);
check(
  "without E1 every guardian slash fails (GuardianSlashFailed x3, no GuardianSlashed)",
  names(e1).filter(n => n === "GuardianSlashFailed").length === 3 &&
    !names(e1).includes("GuardianSlashed")
);

await send(
  "E1 GTokenStaking.setAuthorizedSlasher(aggregator, true) (owner)",
  staking.setAuthorizedSlasher(cfg.blsAggregator, true)
);
const e2 = await send(
  "executeGuardianSlash WITH slasher authorization",
  agg.executeGuardianSlash(fraudProofId, sorted, proofV2(parentBlockHash))
);
check("GuardianSlashed x3", names(e2).filter(n => n === "GuardianSlashed").length === 3);
const bps = BigInt(await agg.guardianSlashBps());
const locksAfter = await Promise.all(sorted.map(a => staking.roleLocks(a, ROLE_DVT)));
const deltas = sorted.map((a, i) => ({
  guardian: a,
  before: locksBefore[i][0].toString(),
  after: locksAfter[i][0].toString(),
}));
check(
  `each lock fell by guardianSlashBps (${bps}/10000)`,
  deltas.every((d, i) => BigInt(d.before) - BigInt(d.after) === (BigInt(d.before) * bps) / 10000n),
  { deltas }
);
const c = await agg.guardianSlashCases(fraudProofId);
check("the case is resolved (status 2)", Number(c[3]) === 2, { status: Number(c[3]) });

report.result = failed ? "FAILED" : "PASSED";
writeFileSync(
  REPORT,
  JSON.stringify(report, (k, v) => (typeof v === "bigint" ? v.toString() : v), 2) + "\n"
);
console.log(`\nACCEPTANCE ${report.result} — report ${REPORT}`);
process.exit(failed ? 1 : 0);
