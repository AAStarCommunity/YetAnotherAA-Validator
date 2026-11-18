// #441 acceptance on a LOCAL anvil: a commitment written by BLSAggregator-4.13.0+ through its real
// execute path, recomputed by the parent-block-hash verifier (OverIssueFraudProofVerifier-3.0.0), and
// the full queueGuardianSlash -> executeGuardianSlash chain, on DVTValidator-0.9.0 (SP #635).
//
// Run through deploy/rehearse-guardian-slash.sh, which starts a fresh anvil, runs SP's DeployAnvil
// and passes the paths here. Local chain 31337 only; throwaway keys only (generated per run).
//
// The chain needs three things rc.8 will NOT have; this script sets them explicitly and records them,
// because they are the three 5.5.x enablement steps:
//   E1  GTokenStaking.setAuthorizedSlasher(aggregator, true)
//   E2  aggregator.proposeFraudProofVerifier(v) -> wait VERIFIER_ROTATION_DELAY -> applyFraudProofVerifier()
//   E3  DVTValidator-0.9.0 fixes its evidence categories at construction (no setter), so enabling a slash
//       category means deploying a new DVTValidator with it and rotating: new.setBLSAggregator(agg),
//       agg.setDVTValidator(new), then addValidator for every guardian on the new DVTValidator. The BLS
//       keys stay in the aggregator. The category's checker here is SP's test-only MockEvidenceCategory,
//       which accepts every body: this proves the pipeline is connected, NOT that an over-issue verdict
//       is right (an honest checker would refuse this fraudulent slash; see #447).
//
// Usage: node deploy/rehearse-guardian-slash.mjs <rpc> <sp config.anvil.json> <dvt contracts/out dir> <report.json> <sp out dir>
import { ethers } from "ethers";
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from "fs";
import { spawnSync } from "child_process";
import { tmpdir } from "os";
import { dirname, join } from "path";
import { fileURLToPath } from "url";
import { bls12_381 as bls } from "@noble/curves/bls12-381.js";

const [RPC, SP_CONFIG, DVT_OUT, REPORT, SP_OUT] = process.argv.slice(2);
if (!SP_OUT) {
  console.error(
    "usage: rehearse-guardian-slash.mjs <rpc> <sp config.anvil.json> <dvt contracts/out> <report.json> <sp out>"
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
const spArtifact = name => JSON.parse(readFileSync(`${SP_OUT}/${name}.sol/${name}.json`, "utf8"));
// The OverIssue.v1 evidence category (proposal, not finalized; DSR 2026-11-17).
const OVERISSUE_CATEGORY = ethers.id("DVT.Evidence.OverIssue.v1");

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
  "function setDVTValidator(address)",
  "function DVT_VALIDATOR() view returns (address)",
  "function validatorAtSlot(uint8) view returns (address)",
  "function getBLSPublicKey(address) view returns ((bytes32,bytes32,bytes32,bytes32),uint8,bool)",
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
  "function queueSlashWithProof(address,uint8,uint256,bytes,bytes)",
  "function executeWithProof(uint256,address[],uint256[],uint256,bytes,bytes)",
  "function setBLSAggregator(address)",
  "function categoryCount() view returns (uint256)",
  "function checkerOf(bytes32) view returns (address)",
  "function version() view returns (string)",
  "event ValidatorAdded(address indexed v)",
  "error UnknownEvidenceCategory(bytes32 category)",
  "error NotCurrentDVT()",
  "error EvidenceHashMismatch()",
  "error EvidenceRejected(bytes32 category)",
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
const dvt0 = new ethers.Contract(cfg.dvtValidator, DVT_ABI, owner); // DeployAnvil's: no categories
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
    dvt0.registerBLSPublicKey(w.address, guardians[i - 1].pkWords, i, pop)
  );
}
check(
  "all three guardians hold ROLE_DVT",
  (await Promise.all(guardians.map(g => registry.hasRole(ROLE_DVT, g.address)))).every(Boolean)
);
for (const g of guardians)
  await send(`DVTValidator.addValidator(guardian ${g.slot}) (owner)`, dvt0.addValidator(g.address));

/** The custom error a static call reverts with, by name (or the short message when unparsed). */
const revertName = async (contract, fn, args) => {
  try {
    await contract[fn].staticCall(...args);
    return "accepted";
  } catch (e) {
    return contract.interface.parseError(e.data ?? "0x")?.name ?? e.shortMessage;
  }
};
const SLASH_TARGET = await owner.getAddress(); // see step 2: a registered SuperPaymaster operator

// ---- 1b. rc.8 state: no category, so every slash-shaped proposal is refused ----------------------
check(
  "DeployAnvil's DVTValidator has no evidence category (rc.8)",
  (await dvt0.categoryCount()) === 0n
);
const rc8Refusal = await revertName(dvt0.connect(guardians[0].wallet), "createProposal", [
  SLASH_TARGET,
  SLASH_LEVEL,
  "rc.8 state",
  ethers.id("any evidence hash"),
]);
check(
  "rc.8: a slash-shaped createProposal reverts UnknownEvidenceCategory",
  rc8Refusal === "UnknownEvidenceCategory",
  { revert: rc8Refusal }
);

// ---- 1c. enablement step E3: a DVTValidator with the OverIssue.v1 category, rotated in -----------
const spDeploy = async (name, args = []) => {
  const a = spArtifact(name);
  const f = new ethers.ContractFactory(a.abi, a.bytecode.object, owner);
  const c = await f.deploy(...args);
  await c.waitForDeployment();
  step(`deploy SP ${name}`, { address: await c.getAddress(), args: args.map(String) });
  return c;
};
const checker = await spDeploy("MockEvidenceCategory");
const checkerAddr = await checker.getAddress();
const dvtNew = await spDeploy("DVTValidator", [
  cfg.registry,
  1n, // below the aggregator's floor on purpose: nextProposalId() lifts it (SP #635)
  [OVERISSUE_CATEGORY],
  [checkerAddr],
]);
const dvt = new ethers.Contract(await dvtNew.getAddress(), DVT_ABI, owner);
report.e3 = {
  dvtValidator: await dvt.getAddress(),
  checker: checkerAddr,
  category: OVERISSUE_CATEGORY,
};
check("E3 DVTValidator version", (await dvt.version()) === (await dvt0.version()), {
  version: await dvt.version(),
});
check(
  "E3 DVTValidator holds exactly the OverIssue.v1 category with the mock checker",
  (await dvt.categoryCount()) === 1n &&
    (await dvt.checkerOf(OVERISSUE_CATEGORY)).toLowerCase() === checkerAddr.toLowerCase()
);
await send(
  "E3a newDVT.setBLSAggregator(aggregator) (owner)",
  dvt.setBLSAggregator(cfg.blsAggregator)
);
await send(
  "E3b aggregator.setDVTValidator(newDVT) (owner)",
  agg.setDVTValidator(await dvt.getAddress())
);
check(
  "aggregator.DVT_VALIDATOR() is the new DVTValidator",
  (await agg.DVT_VALIDATOR()).toLowerCase() === (await dvt.getAddress()).toLowerCase()
);
const oldAfter = await revertName(dvt0.connect(guardians[0].wallet), "createProposal", [
  SLASH_TARGET,
  SLASH_LEVEL,
  "old DVT after rotation",
  ethers.id("any evidence hash"),
]);
check(
  "the old DVTValidator can no longer file proposals (NotCurrentDVT)",
  oldAfter === "NotCurrentDVT",
  {
    revert: oldAfter,
  }
);
let added = 0;
for (const g of guardians) {
  const rc = await send(
    `E3c newDVT.addValidator(guardian ${g.slot}) (owner)`,
    dvt.addValidator(g.address)
  );
  added += rc.logs.filter(l => {
    try {
      return dvt.interface.parseLog(l)?.name === "ValidatorAdded";
    } catch {
      return false;
    }
  }).length;
}
check("ValidatorAdded emitted once per guardian on the new DVTValidator", added === 3, { added });
const keys = await Promise.all(guardians.map(g => agg.getBLSPublicKey(g.address)));
check(
  "the guardians' BLS keys survive the rotation (active, same slots)",
  keys.every((k, i) => k[2] === true && Number(k[1]) === guardians[i].slot)
);

// ---- 2. the #441 verifier (3.0.0) and an over-issue token that is NOT over-issued (the slash was fraud) ---
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
  (await verifier.VERIFIER_VERSION()) === "OverIssueFraudProofVerifier-3.0.0" &&
    (await verifier.COMMITMENT_BINDS_PARENT_BLOCKHASH()) === true
);
check(
  "verifier and E3 DVTValidator use the same evidence category",
  (await verifier.OVERISSUE_CATEGORY()) === OVERISSUE_CATEGORY
);
const tokenAddr = await token.getAddress();
// The slash target is the DeployAnvil deployer, a registered SuperPaymaster operator, so the SP side of
// the slash runs for real: queueSlashWithConsensus (BLS) then verifyAndExecute -> executeSlashWithBLS.
const operator = SLASH_TARGET;
report.operator = operator;

// ---- 3. the guardians sign a slash; the aggregator executes it through verifyAndExecute -------
const evidenceHash = await verifier.evidenceHash(tokenAddr, operator, EPOCH);
const evidence = await verifier.evidence(tokenAddr, operator, EPOCH);
report.evidenceHash = evidenceHash;
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
  g1dvt.queueSlashWithProof(operator, SLASH_LEVEL, EPOCH, evidence, qProof)
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
// N0: the checker accepts any body, so evidence naming another token decodes and passes the checker,
// but its evidenceHash differs from the proposal's: DVTValidator must refuse it.
const otherEvidence = await verifier.evidence(guardians[0].address, operator, EPOCH);
const n0 = await revertName(g1dvt, "executeWithProof", [
  PROPOSAL_ID,
  [],
  [],
  EPOCH,
  otherEvidence,
  proof,
]);
check(
  "N0 execute with evidence for another token -> EvidenceHashMismatch",
  n0 === "EvidenceHashMismatch",
  {
    revert: n0,
  }
);
// N0b: the category's checker is really consulted (Codex on #441 part 2). With it set to reject,
// the proposal's own, otherwise matching evidence must be refused; then it accepts again.
await send("N0b checker.setAccepted(false)", checker.setAccepted(false));
const n0b = await revertName(g1dvt, "executeWithProof", [
  PROPOSAL_ID,
  [],
  [],
  EPOCH,
  evidence,
  proof,
]);
check(
  "N0b with the checker rejecting, the matching evidence -> EvidenceRejected",
  n0b === "EvidenceRejected",
  {
    revert: n0b,
  }
);
await send("N0b checker.setAccepted(true)", checker.setAccepted(true));
const execRc = await send(
  "guardian 1 DVTValidator.executeWithProof -> aggregator.verifyAndExecute (SP two-step slash step 2; writes the signer commitment)",
  g1dvt.executeWithProof(PROPOSAL_ID, [], [], EPOCH, evidence, proof),
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

// The REAL wrapper transaction, for the watcher (Daybreak on #441, High): record the tx and every chain
// read buildGuardianSignerRecord makes, at the execution block, so a jest spec can replay it
// (src/modules/audit/guardian-slash-watcher.replay.spec.ts) and require a verified record.
{
  const B = execRc.blockNumber;
  const tx = await provider.getTransaction(execRc.hash);
  const dvtAt = await agg.DVT_VALIDATOR({ blockTag: B });
  const dvtRead = new ethers.Contract(
    dvtAt,
    [
      "function proposals(uint256) view returns (address operator, uint8 slashLevel, string reason, bool executed, bool exists, bytes32 evidenceHash)",
    ],
    provider
  );
  const pr = await dvtRead.proposals(PROPOSAL_ID, { blockTag: B });
  const slots = {};
  for (let i = 1; i <= 64; i++) {
    if ((MASK >> BigInt(i - 1)) & 1n) slots[i] = await agg.validatorAtSlot(i, { blockTag: B });
  }
  const fixture = {
    purpose:
      "#441 watcher replay: a real DVTValidator.executeWithProof tx from the anvil acceptance (throwaway keys)",
    chainId: net.chainId.toString(),
    aggregator: cfg.blsAggregator,
    registry: cfg.registry,
    txHash: execRc.hash,
    tx: { to: tx.to, data: tx.data },
    executionBlock: B,
    executionBlockTimestamp: (await provider.getBlock(B)).timestamp,
    parentBlockHash,
    dvtValidator: dvtAt,
    proposal: {
      id: PROPOSAL_ID.toString(),
      operator: pr.operator,
      slashLevel: Number(pr.slashLevel),
      reason: pr.reason,
      executed: pr.executed,
      exists: pr.exists,
      evidenceHash: pr.evidenceHash,
    },
    validatorAtSlot: slots,
    proposalSignersCommitment: await agg.proposalSignersCommitment(PROPOSAL_ID, { blockTag: B }),
  };
  writeFileSync(
    REPORT.replace(/\.json$/, "") + "-watcher-fixture.json",
    JSON.stringify(fixture, null, 2) + "\n"
  );
  check(
    "watcher fixture: the execution tx is sent to the DVTValidator (the wrapper path)",
    ethers.getAddress(tx.to) === ethers.getAddress(dvtAt)
  );
}

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

// ---- 4. enablement step E2: arm the #441 verifier -------------------------------------------------
await send(
  "E2a proposeFraudProofVerifier(#441 verifier) (owner)",
  agg.proposeFraudProofVerifier(await verifier.getAddress())
);
const delay = await agg.VERIFIER_ROTATION_DELAY();
await provider.send("evm_increaseTime", [Number(delay)]);
await provider.send("evm_mine", []);
step(`wait VERIFIER_ROTATION_DELAY (${delay} s, anvil time warp)`);
await send("E2b applyFraudProofVerifier() (permissionless)", agg.applyFraudProofVerifier());
check(
  "fraudProofVerifier() is the #441 verifier",
  (await agg.fraudProofVerifier()).toLowerCase() === (await verifier.getAddress()).toLowerCase()
);

// ---- 4b. the fork drill against this stack (#441 item 2) -------------------------------------------
// reregister-guardians.mjs --export-fraud-drill must accept the #441 verifier, write a TEMPLATE whose
// fraudProof has the trailing parentBlockHash word (zero, to be filled from a real execution), and
// no longer carry a commitment value to poke into storage.
{
  const tmp = mkdtempSync(join(tmpdir(), "drill-441-"));
  try {
    writeFileSync(join(tmp, "rpc.env"), `RPC_URL=${RPC}\n`, { mode: 0o600 });
    writeFileSync(
      join(tmp, "deployment.json"),
      JSON.stringify({
        dvtValidator: await dvt.getAddress(),
        blsAggregator: cfg.blsAggregator,
        registry: cfg.registry,
      })
    );
    const script = join(dirname(fileURLToPath(import.meta.url)), "reregister-guardians.mjs");
    const out = join(tmp, "drill.json");
    const r = spawnSync(
      process.execPath,
      [
        script,
        "--deployment",
        join(tmp, "deployment.json"),
        "--env",
        join(tmp, "rpc.env"),
        "--chain-id",
        String(net.chainId),
        "--verifier",
        await verifier.getAddress(),
        "--export-fraud-drill",
        out,
      ],
      { encoding: "utf8", env: { PATH: process.env.PATH, HOME: tmp } }
    );
    check("drill: --export-fraud-drill exits 0 against the #441 verifier", r.status === 0, {
      status: r.status,
      stderr: (r.stderr ?? "").slice(-400),
    });
    let d = null;
    try {
      d = JSON.parse(readFileSync(out, "utf8"));
    } catch {
      d = null;
    }
    // Strict: ABI decoding is lenient (a 7-field proof can decode as 8), so the decode must also
    // re-encode to exactly the same bytes.
    const T8 = [
      "uint256",
      "address",
      "uint8",
      "uint256",
      "address",
      "uint256",
      "address[]",
      "bytes32",
    ];
    const decode8 = hex => {
      try {
        const v = coder.decode(T8, hex);
        return coder.encode(T8, [...v]).toLowerCase() === String(hex).toLowerCase() ? v : null;
      } catch {
        return null;
      }
    };
    const valid = d ? decode8(d.valid.fraudProof) : null;
    check(
      "drill: the valid fraudProof has 8 fields and a zero parentBlockHash placeholder",
      valid !== null && valid[7] === ethers.ZeroHash
    );
    // Filling the template as its note says (decode, set field 8, re-encode) must change exactly
    // field 8 and keep the guardian array intact.
    const filled = (() => {
      if (!valid || !Array.isArray(d.valid.fraudProofTypes)) return null;
      const v = [...valid];
      v[7] = "0x" + "ab".repeat(32);
      return decode8(coder.encode(d.valid.fraudProofTypes, v));
    })();
    check(
      "drill: filling field 8 as the note says sets parentBlockHash and keeps the guardians",
      filled !== null &&
        filled[7] === "0x" + "ab".repeat(32) &&
        // with field 8 set back to zero, the bytes are exactly the template's: nothing else moved
        coder
          .encode(d.valid.fraudProofTypes, [...filled.slice(0, 7), ethers.ZeroHash])
          .toLowerCase() === d.valid.fraudProof.toLowerCase() &&
        /field 8/.test(d.valid.fraudProofNote) &&
        !/the last 32 bytes are zero/.test(d.valid.fraudProofNote)
    );
    check(
      "drill: forkState.commitment has no value to write, only how to produce it",
      d !== null &&
        !("value" in d.forkState.commitment) &&
        typeof d.forkState.commitment.produce === "string"
    );
    check(
      "drill: the four must-reject cases are present, N3 also with 8 fields",
      d !== null &&
        d.mustReject.map(c => c.id).join() === "N1,N2,N3,N4" &&
        decode8(d.mustReject[2].fraudProof)?.[7] === ethers.ZeroHash
    );
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
}

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

// ---- 5b. the drill's exported cases, EXECUTED (Daybreak on #441, Medium) ---------------------------
// Export the drill for THIS slash (--drill-case), fill field 8 from the real execution, require it to
// equal the proof built above byte for byte, then run the valid case and N1-N4 as the export states.
{
  const tmp = mkdtempSync(join(tmpdir(), "drill-case-441-"));
  try {
    writeFileSync(join(tmp, "rpc.env"), `RPC_URL=${RPC}\n`, { mode: 0o600 });
    writeFileSync(
      join(tmp, "deployment.json"),
      JSON.stringify({
        dvtValidator: await dvt.getAddress(),
        blsAggregator: cfg.blsAggregator,
        registry: cfg.registry,
      })
    );
    writeFileSync(
      join(tmp, "case.json"),
      JSON.stringify({
        proposalId: PROPOSAL_ID.toString(),
        operator,
        token: tokenAddr,
        epoch: EPOCH.toString(),
        slashLevel: SLASH_LEVEL,
        signerMask: MASK.toString(),
        guardians: sorted,
      })
    );
    const out = join(tmp, "drill-case.json");
    const r = spawnSync(
      process.execPath,
      [
        join(dirname(fileURLToPath(import.meta.url)), "reregister-guardians.mjs"),
        "--deployment",
        join(tmp, "deployment.json"),
        "--env",
        join(tmp, "rpc.env"),
        "--chain-id",
        String(net.chainId),
        "--verifier",
        await verifier.getAddress(),
        "--export-fraud-drill",
        out,
        "--drill-case",
        join(tmp, "case.json"),
      ],
      { encoding: "utf8", env: { PATH: process.env.PATH, HOME: tmp } }
    );
    check(
      "drill case: --export-fraud-drill --drill-case exits 0 for the executed slash",
      r.status === 0,
      {
        status: r.status,
        stderr: (r.stderr ?? "").slice(-400),
      }
    );
    const d = JSON.parse(readFileSync(out, "utf8"));
    const T8 = d.valid.fraudProofTypes;
    const fill = hex => {
      const v = [...coder.decode(T8, hex)];
      v[7] = parentBlockHash;
      return coder.encode(T8, v);
    };
    const validProof = fill(d.valid.fraudProof);
    check(
      "drill case: the filled exported proof equals the proof built from the execution, byte for byte",
      validProof.toLowerCase() === proofV2(parentBlockHash).toLowerCase() &&
        BigInt(d.valid.fraudProofId) === fraudProofId
    );
    const digestOf = gs =>
      new ethers.Contract(
        cfg.blsAggregator,
        ["function fraudProofDigest(uint256,address[]) view returns (bytes32)"],
        provider
      ).fraudProofDigest(fraudProofId, gs);
    check(
      "drill case: valid -> verifier.verify true and queueGuardianSlash accepts it (staticCall)",
      (await verifier.verify(
        await digestOf(d.valid.guiltyGuardians),
        fraudProofId,
        d.valid.guiltyGuardians,
        validProof
      )) &&
        (await agg.queueGuardianSlash
          .staticCall(fraudProofId, d.valid.guiltyGuardians, validProof)
          .then(
            () => true,
            () => false
          ))
    );
    const caseRejects = async (c, label) => {
      try {
        await agg.queueGuardianSlash.staticCall(
          fraudProofId,
          c.guiltyGuardians,
          fill(c.fraudProof)
        );
        check(label, false, { got: "accepted" });
      } catch (e) {
        const name = agg.interface.parseError(e.data ?? "0x")?.name ?? e.shortMessage;
        check(label, name === "InvalidFraudProof", { revert: name });
      }
    };
    const byId = Object.fromEntries(d.mustReject.map(c => [c.id, c]));
    await caseRejects(byId.N1, "drill case N1 (one guardian removed) -> InvalidFraudProof");
    await caseRejects(byId.N3, "drill case N3 (signerMask one bit off) -> InvalidFraudProof");
    const slot0 = await provider.getStorage(tokenAddr, 0);
    await provider.send("anvil_setStorageAt", [tokenAddr, "0x0", ethers.zeroPadValue("0x01", 32)]);
    await caseRejects(byId.N2, "drill case N2 (token over-issued) -> InvalidFraudProof");
    await provider.send("anvil_setStorageAt", [tokenAddr, "0x0", slot0]);
    check(
      "drill case N2: token storage restored",
      (await provider.getStorage(tokenAddr, 0)) === slot0
    );
    check(
      "drill case N4 (digest one bit off) -> verifier.verify false",
      (await verifier.verify(
        byId.N4.domainDigest,
        fraudProofId,
        byId.N4.guiltyGuardians,
        fill(byId.N4.fraudProof)
      )) === false
    );
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
}

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
  `each lock fell by guardianSlashBps (${bps}/10000), by a positive amount`,
  bps > 0n &&
    deltas.every(d => {
      const before = BigInt(d.before);
      const cut = (before * bps) / 10000n;
      return before > 0n && cut > 0n && before - BigInt(d.after) === cut;
    }),
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
