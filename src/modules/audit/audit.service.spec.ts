import { ethers } from "ethers";
import { AuditService } from "./audit.service.js";
import { IProofArchive, SlashProof, computeProofHash } from "./proof-archive.js";
import {
  IQuorumCoSigner,
  CoSignRequest,
  buildQueueMessageHash,
  buildExecuteMessageHash,
  encodeProof,
} from "./slash-consensus.js";

const OPERATOR = "0x" + "12".repeat(20);
const REGISTRY = "0xf5Bf37ca83AfdAab73691bA7eCcDfA69b8708E71";
const SUPER_PAYMASTER = "0x" + "34".repeat(20);
const DVT_VALIDATOR = "0x" + "56".repeat(20);
const GTOKEN_STAKING = "0x" + "78".repeat(20);
/** aPNTs xPNTs token — where getDebt actually lives (per the real SP ABI). */
const APNTS_TOKEN = "0x696A73701b104c6cCBbAadDD2216788ea08EaB89";
const BLOCK = 12_345;
/** Finalized-block hash the mock getViolationBlock returns (finding-3 reorg-safe evidence). */
const BLOCK_HASH = "0x" + "bb".repeat(32);

const BASE_CONFIG: Record<string, unknown> = {
  auditEnabled: true,
  auditIntervalMs: 60_000,
  auditCooldownMs: 3_600_000,
  auditWatchlist: [OPERATOR],
  auditCreditThresholdBps: 10_000,
  auditChainId: 11155111,
  auditRegistryAddress: REGISTRY,
  auditSuperPaymasterAddress: SUPER_PAYMASTER,
  auditDvtValidatorAddress: DVT_VALIDATOR,
  auditGtokenStakingAddress: GTOKEN_STAKING,
  auditApntsTokenAddress: APNTS_TOKEN,
  auditProofDir: "./audit-proofs-test",
};

function makeConfig(overrides: Record<string, unknown> = {}) {
  const cfg = { ...BASE_CONFIG, ...overrides };
  return { get: (k: string) => cfg[k] } as any;
}

/**
 * Blockchain mock. Defaults model a HEALTHY operator: debt (0) ≤ creditLimit (1000) → no
 * violation. Override getDebt to model a genuine over-limit (debt > creditLimit). getCode
 * returns real bytecode so the fail-closed bootstrap existence check passes by default.
 */
function makeBlockchain(
  overrides: Partial<{
    getBlockNumber: () => Promise<number>;
    getViolationBlock: (confirmations?: number) => Promise<{ number: number; hash: string }>;
    getRecentSlashExecuted: (
      addr: string,
      op: string,
      slashLevel: number,
      fromBlock: number
    ) => Promise<boolean | null>;
    getCode: (addr: string) => Promise<string>;
    getCreditLimit: (addr: string, op: string, bt?: number) => Promise<bigint>;
    getAvailableCredit: (addr: string, op: string, token: string, bt?: number) => Promise<bigint>;
    getDebt: (tokenAddr: string, op: string, bt?: number) => Promise<bigint | null>;
    getGlobalReputation: (addr: string, op: string, bt?: number) => Promise<bigint>;
    getRoleLockAmount: (...args: any[]) => Promise<bigint>;
    createProposalWithEvidence: (
      ...args: any[]
    ) => Promise<{ txHash: string; proposalId: bigint | null }>;
    queueSlashWithProof: (...args: any[]) => Promise<string>;
    executeSlashWithProof: (...args: any[]) => Promise<string>;
    isSlashPending: (...args: any[]) => Promise<boolean | null>;
    getWalletAddress: () => string | null;
  }> = {}
): any {
  return {
    getBlockNumber: overrides.getBlockNumber ?? (async () => BLOCK),
    // getViolationBlock delegates to this.getBlockNumber() (non-arrow so `this` binds to the mock),
    // so tests that reassign blockchain.getBlockNumber keep controlling the pinned violation block.
    getViolationBlock:
      overrides.getViolationBlock ??
      async function (this: any) {
        return { number: await this.getBlockNumber(), hash: BLOCK_HASH };
      },
    // No prior slash by default → the durable on-chain over-slash guard reports "not slashed".
    getRecentSlashExecuted: overrides.getRecentSlashExecuted ?? (async () => false),
    getCode: overrides.getCode ?? (async () => "0x60006000fd"),
    getCreditLimit: overrides.getCreditLimit ?? (async () => 1000n),
    getAvailableCredit: overrides.getAvailableCredit ?? (async () => 1000n),
    getDebt: overrides.getDebt ?? (async () => 0n),
    getGlobalReputation: overrides.getGlobalReputation ?? (async () => 500n),
    getRoleLockAmount: overrides.getRoleLockAmount ?? (async () => 42n),
    createProposalWithEvidence:
      overrides.createProposalWithEvidence ??
      (async () => ({ txHash: "0xPROPOSALTX", proposalId: 7n })),
    queueSlashWithProof: overrides.queueSlashWithProof ?? (async () => "0xQUEUETX"),
    executeSlashWithProof: overrides.executeSlashWithProof ?? (async () => "0xEXECUTETX"),
    // Current SP keeps _pendingSlash private → no getter → null ("unknown") by default.
    isSlashPending: overrides.isSlashPending ?? (async () => null),
    getWalletAddress: overrides.getWalletAddress ?? (() => "0x" + "99".repeat(20)),
  };
}

/** A deterministic mock quorum co-signer that always succeeds (fixed mask + sig). It records the
 *  messageHash of each structured CoSignRequest so existing assertions on `calls[i]` still hold. */
function makeCoSigner(
  signerMask = 0b111n,
  sigG2 = "0x" + "ab".repeat(64)
): IQuorumCoSigner & { calls: string[]; requests: CoSignRequest[] } {
  const calls: string[] = [];
  const requests: CoSignRequest[] = [];
  return {
    calls,
    requests,
    async coSign(req: CoSignRequest) {
      calls.push(req.messageHash);
      requests.push(req);
      return { signerMask, sigG2 };
    },
  };
}

/** In-memory archive so tests never touch the filesystem. */
function makeArchive(): IProofArchive & { records: SlashProof[]; slashed: Set<string> } {
  const records: SlashProof[] = [];
  const slashed = new Set<string>();
  return {
    records,
    slashed,
    async put(proof: SlashProof) {
      // Idempotent on proofHash, like LocalProofArchive.
      const existing = records.findIndex(r => r.proofHash === proof.proofHash);
      if (existing >= 0) records[existing] = proof;
      else records.push(proof);
      return { proofHash: proof.proofHash, location: `mem://${proof.proofHash}` };
    },
    async has(proofHash: string) {
      return records.some(r => r.proofHash === proofHash);
    },
    async count() {
      return records.length;
    },
    async recordSlashed(coarseKey: string) {
      slashed.add(coarseKey);
    },
    async hasSlashed(coarseKey: string) {
      return slashed.has(coarseKey);
    },
    async removeSlashed(coarseKey: string) {
      slashed.delete(coarseKey);
    },
  };
}

function makeRegistry() {
  const registered: string[] = [];
  return { registered, register: (cap: { name: string }) => registered.push(cap.name) } as any;
}

function clockAt(nowMs: number) {
  return () => nowMs;
}

function makeService(
  blockchain: any,
  config: any,
  archive: IProofArchive,
  clock: () => number = clockAt(1_700_000_000_000),
  coSigner?: IQuorumCoSigner
) {
  return new AuditService(blockchain, config, makeRegistry(), clock, () => 0, archive, coSigner);
}

/** A blockchain whose operator is genuinely OVER limit: debt (2000) > creditLimit (1000). */
function overLimitBlockchain(overrides: Record<string, any> = {}) {
  return makeBlockchain({
    getCreditLimit: async () => 1000n,
    getAvailableCredit: async () => 0n,
    getDebt: async () => 2000n,
    ...overrides,
  });
}

describe("AuditService", () => {
  it("registers the audit capability (enabled) with the CapabilityRegistry", () => {
    const registry = makeRegistry();
    new AuditService(makeBlockchain(), makeConfig(), registry, clockAt(0), () => 0, makeArchive());
    expect(registry.registered).toContain("audit");
  });

  it("disabled → onApplicationBootstrap never schedules a tick", async () => {
    const svc = makeService(makeBlockchain(), makeConfig({ auditEnabled: false }), makeArchive());
    await svc.onApplicationBootstrap();
    expect((svc as any).startupTimer).toBeNull();
    expect((svc as any).timer).toBeNull();
  });

  it("enabled → onApplicationBootstrap schedules a phase-jittered first tick", async () => {
    const svc = makeService(makeBlockchain(), makeConfig(), makeArchive());
    await svc.onApplicationBootstrap();
    // First tick is phase-jittered via setTimeout — startupTimer holds it, interval not armed.
    expect((svc as any).startupTimer).not.toBeNull();
    expect((svc as any).timer).toBeNull();
    svc.onApplicationShutdown();
    expect((svc as any).startupTimer).toBeNull();
  });

  it("enabled but empty watchlist → does not schedule", async () => {
    const svc = makeService(makeBlockchain(), makeConfig({ auditWatchlist: [] }), makeArchive());
    await svc.onApplicationBootstrap();
    expect((svc as any).startupTimer).toBeNull();
  });

  // ── MEDIUM 1: config fail-closed ──────────────────────────────────────────────
  it("fail-closed: a missing required contract address → DISABLED, never schedules", async () => {
    const svc = makeService(
      makeBlockchain(),
      makeConfig({ auditDvtValidatorAddress: undefined }),
      makeArchive()
    );
    await svc.onApplicationBootstrap();
    expect((svc as any).startupTimer).toBeNull();
    expect((await svc.getStatus()).enabled).toBe(false);
  });

  it("fail-closed: an address with no on-chain code (getCode=0x) → DISABLED", async () => {
    const blockchain = makeBlockchain({ getCode: async () => "0x" });
    const svc = makeService(blockchain, makeConfig(), makeArchive());
    await svc.onApplicationBootstrap();
    expect((svc as any).startupTimer).toBeNull();
    expect((await svc.getStatus()).enabled).toBe(false);
  });

  it("fail-closed: an invalid chainId → DISABLED", async () => {
    const svc = makeService(makeBlockchain(), makeConfig({ auditChainId: 0 }), makeArchive());
    await svc.onApplicationBootstrap();
    expect((svc as any).startupTimer).toBeNull();
    expect((await svc.getStatus()).enabled).toBe(false);
  });

  // ── CRITICAL 1: at-limit ≠ over-limit ─────────────────────────────────────────
  it("healthy operator (debt 0 ≤ limit) → no detection, no proposal", async () => {
    const created: any[] = [];
    const blockchain = makeBlockchain({
      createProposalWithEvidence: async (...args: any[]) => {
        created.push(args);
        return { txHash: "0xTX", proposalId: 7n };
      },
    });
    const archive = makeArchive();
    const svc = makeService(blockchain, makeConfig(), archive);
    await svc.tick();
    expect(created).toHaveLength(0);
    expect(archive.records).toHaveLength(0);
  });

  it("AT exactly the limit (debt == creditLimit) → NOT flagged (at limit, not over)", async () => {
    const created: any[] = [];
    const blockchain = makeBlockchain({
      getCreditLimit: async () => 1000n,
      getAvailableCredit: async () => 0n, // fully used, but that is AT the limit
      getDebt: async () => 1000n, // debt == limit → NOT over
      createProposalWithEvidence: async (...args: any[]) => {
        created.push(args);
        return { txHash: "0xTX", proposalId: 7n };
      },
    });
    const archive = makeArchive();
    const svc = makeService(blockchain, makeConfig(), archive);
    await svc.tick();
    expect(created).toHaveLength(0);
    expect(archive.records).toHaveLength(0);
  });

  it("fail-safe: debt unreadable (getDebt → null) → SKIP even when availableCredit is 0", async () => {
    const created: any[] = [];
    const blockchain = makeBlockchain({
      getCreditLimit: async () => 1000n,
      getAvailableCredit: async () => 0n,
      getDebt: async () => null, // BOTH SP and Registry reads revert
      createProposalWithEvidence: async (...args: any[]) => {
        created.push(args);
        return { txHash: "0xTX", proposalId: 7n };
      },
    });
    const archive = makeArchive();
    const svc = makeService(blockchain, makeConfig(), archive);
    await svc.tick();
    expect(created).toHaveLength(0);
    expect(archive.records).toHaveLength(0);
  });

  it("STRICT over-limit (debt > limit) → files a proposal AND archives a content-addressed proof", async () => {
    const created: any[] = [];
    const blockchain = overLimitBlockchain({
      createProposalWithEvidence: async (...args: any[]) => {
        created.push(args);
        return { txHash: "0xPROPOSALTX", proposalId: 7n };
      },
    });
    const archive = makeArchive();
    const now = 1_700_000_000_000;
    const svc = makeService(blockchain, makeConfig(), archive, clockAt(now));
    await svc.tick();

    // Proposal-intent filed: createProposal(operator, level=1, reason).
    expect(created).toHaveLength(1);
    expect(created[0][0]).toBe(DVT_VALIDATOR);
    expect(created[0][1]).toBe(OPERATOR);
    expect(created[0][2]).toBe(1); // SLASH_LEVEL_CREDIT_OVER_LIMIT
    expect(created[0][3]).toContain("credit-over-limit");

    // Exactly one proof archived.
    expect(archive.records).toHaveLength(1);
    const proof = archive.records[0];
    expect(proof.version).toBe("dvt-slash-proof/1");
    expect(proof.operator).toBe(OPERATOR);
    expect(proof.slashLevel).toBe(1);
    expect(proof.proposalTx).toBe("0xPROPOSALTX");

    // Evidence captured, with the raw view sources + the pinned block.
    expect(proof.evidence.rule).toBe("credit-over-limit");
    expect(proof.evidence.observed).toBe("2000"); // debt
    expect(proof.evidence.threshold).toBe("1000"); // creditLimit
    expect(proof.evidence.violationBlock).toBe(BLOCK);
    const sourceNames = proof.evidence.sources.map(s => s.name);
    expect(sourceNames).toContain("Registry.getCreditLimit");
    // Debt evidence must name the REAL source — the aPNTs xPNTs token, not SuperPaymaster.
    expect(sourceNames).toContain(`IxPNTsToken(${APNTS_TOKEN}).getDebt`);
    expect(sourceNames).toContain("SuperPaymaster.getAvailableCredit");

    // proofHash is a real content address over ON-CHAIN identity: recomputing matches.
    const recomputed = computeProofHash({
      chainId: proof.chainId,
      operator: proof.operator,
      rule: proof.evidence.rule,
      creditLimit: proof.evidence.threshold,
      debt: proof.evidence.observed,
      violationBlock: proof.evidence.violationBlock,
    });
    expect(recomputed).toBe(proof.proofHash);
    expect(proof.proofHash).toMatch(/^0x[0-9a-f]{64}$/);

    // Detection surfaced in status.
    const status = await svc.getStatus();
    expect(status.recentDetections).toHaveLength(1);
    expect(status.recentDetections[0].proofHash).toBe(proof.proofHash);
    expect(status.archivedProofCount).toBe(1);
  });

  // ── CRITICAL 2: block-pinned reads ────────────────────────────────────────────
  it("pins EVERY rule input to one block (blockTag threaded from a single getBlockNumber)", async () => {
    const seen: Record<string, number | undefined> = {};
    const blockchain = overLimitBlockchain();
    blockchain.getBlockNumber = async () => 999;
    blockchain.getCreditLimit = async (_a: string, _o: string, bt?: number) => {
      seen.limit = bt;
      return 1000n;
    };
    blockchain.getAvailableCredit = async (_a: string, _o: string, _token: string, bt?: number) => {
      seen.avail = bt;
      return 0n;
    };
    blockchain.getDebt = async (_a: string, _o: string, bt?: number) => {
      seen.debt = bt;
      return 2000n;
    };
    const archive = makeArchive();
    const svc = makeService(blockchain, makeConfig(), archive);
    await svc.tick();
    expect(seen.limit).toBe(999);
    expect(seen.avail).toBe(999);
    expect(seen.debt).toBe(999);
    expect(archive.records[0].evidence.violationBlock).toBe(999);
  });

  // ── HIGH 3: proofHash is wall-clock-free (stable across nodes/ticks) ───────────
  it("same on-chain violation → same proofHash regardless of observedAt (two nodes agree)", async () => {
    const nodeA = makeService(overLimitBlockchain(), makeConfig(), makeArchive(), clockAt(1_000));
    await nodeA.tick();
    const hashA = (await nodeA.getStatus()).recentDetections[0].proofHash;

    // A different node observing the same violation at a very different wall-clock time.
    const nodeB = makeService(
      overLimitBlockchain(),
      makeConfig(),
      makeArchive(),
      clockAt(9_999_999_999)
    );
    await nodeB.tick();
    const hashB = (await nodeB.getStatus()).recentDetections[0].proofHash;

    expect(hashA).toBe(hashB);
  });

  it("content-address is deterministic + idempotent: same violation twice → one archived proof", async () => {
    const created: any[] = [];
    const blockchain = overLimitBlockchain({
      createProposalWithEvidence: async (...args: any[]) => {
        created.push(args);
        return { txHash: "0xTX", proposalId: 7n };
      },
    });
    const archive = makeArchive();
    const svc = makeService(blockchain, makeConfig(), archive, clockAt(1_700_000_000_000));
    await svc.tick();
    await svc.tick();
    expect(archive.records).toHaveLength(1);
  });

  // ── HIGH 1: dedup prevents re-proposing the same violation ─────────────────────
  it("dedup: same violation@block over many ticks → exactly ONE proposal", async () => {
    const created: any[] = [];
    const blockchain = overLimitBlockchain({
      createProposalWithEvidence: async (...args: any[]) => {
        created.push(args);
        return { txHash: "0xTX", proposalId: 7n };
      },
    });
    const archive = makeArchive();
    const svc = makeService(blockchain, makeConfig(), archive, clockAt(1_700_000_000_000));
    await svc.tick();
    await svc.tick();
    await svc.tick();
    expect(created).toHaveLength(1);
  });

  it("dedup: an already-archived proof (prior process) → no new proposal", async () => {
    const created: any[] = [];
    const blockchain = overLimitBlockchain({
      createProposalWithEvidence: async (...args: any[]) => {
        created.push(args);
        return { txHash: "0xTX", proposalId: 7n };
      },
    });
    // Pre-seed the archive with the exact proof for this violation@block.
    const archive = makeArchive();
    const identityHash = computeProofHash({
      chainId: 11155111,
      operator: OPERATOR,
      rule: "credit-over-limit",
      creditLimit: "1000",
      debt: "2000",
      violationBlock: BLOCK,
    });
    (archive.records as SlashProof[]).push({ proofHash: identityHash } as SlashProof);
    const svc = makeService(blockchain, makeConfig(), archive);
    await svc.tick();
    expect(created).toHaveLength(0);
  });

  it("cooldown: an ongoing violation whose block advances is not re-proposed until cooldown elapses", async () => {
    const created: any[] = [];
    let block = 1000;
    let now = 1_700_000_000_000;
    const blockchain = overLimitBlockchain({
      createProposalWithEvidence: async (...args: any[]) => {
        created.push(args);
        return { txHash: "0xTX", proposalId: 7n };
      },
    });
    blockchain.getBlockNumber = async () => block;
    const svc = makeService(
      blockchain,
      makeConfig({ auditCooldownMs: 3_600_000 }),
      makeArchive(),
      () => now
    );

    // Tick 1 at block 1000 → proposes, arms cooldown.
    await svc.tick();
    // Tick 2 shortly after at a NEW block 1001 (ongoing violation) → within cooldown → skip.
    block = 1001;
    now += 60_000;
    await svc.tick();
    expect(created).toHaveLength(1);

    // Tick 3 after the cooldown elapses at yet another new block → re-proposes once.
    block = 1002;
    now += 3_600_001;
    await svc.tick();
    expect(created).toHaveLength(2);
  });

  it("proposal write failure → proof still archived (evidence never lost), proposalTx null", async () => {
    const blockchain = overLimitBlockchain({
      createProposalWithEvidence: async () => {
        throw new Error("reverted: not authorized");
      },
    });
    const archive = makeArchive();
    const svc = makeService(blockchain, makeConfig(), archive);
    await expect(svc.tick()).resolves.toBeUndefined(); // never throws
    expect(archive.records).toHaveLength(1);
    expect(archive.records[0].proposalTx).toBeUndefined();
    const status = await svc.getStatus();
    expect(status.recentDetections[0].proposalTx).toBeNull();
  });

  it("tick sweeps every operator; one failing operator does not abort the rest", async () => {
    const op2 = "0x" + "ab".repeat(20);
    const created: string[] = [];
    const blockchain = overLimitBlockchain({
      createProposalWithEvidence: async (_addr: string, operator: string) => {
        created.push(operator);
        return { txHash: "0xTX", proposalId: 7n };
      },
    });
    // Make the FIRST operator's read throw; the second must still be audited.
    let firstCall = true;
    blockchain.getCreditLimit = async () => {
      if (firstCall) {
        firstCall = false;
        throw new Error("rpc error");
      }
      return 1000n;
    };
    const svc = makeService(
      blockchain,
      makeConfig({ auditWatchlist: [OPERATOR, op2] }),
      makeArchive()
    );
    await svc.tick();
    // The watchlist is canonicalized (checksummed) at ingest, so the operator handed to
    // createProposal is the checksummed form of op2, not its raw lowercase input.
    expect(created).toEqual([ethers.getAddress(op2)]);
  });

  // ── HIGH 2: single-flight ─────────────────────────────────────────────────────
  it("single-flight: an overlapping tick is skipped while one is in-flight", async () => {
    let blockCalls = 0;
    let release!: () => void;
    const gate = new Promise<void>(res => {
      release = res;
    });
    const blockchain = overLimitBlockchain();
    blockchain.getBlockNumber = async () => {
      blockCalls++;
      await gate; // suspend the first tick mid-flight
      return BLOCK;
    };
    const svc = makeService(blockchain, makeConfig(), makeArchive());

    const p1 = svc.tick(); // enters, sets tickInFlight, suspends on the gate
    const p2 = svc.tick(); // overlapping → must skip immediately
    await p2;
    expect(blockCalls).toBe(1); // second tick never started auditing

    release();
    await p1;
    expect(blockCalls).toBe(1);
    expect((svc as any).tickInFlight).toBe(false);
  });

  // ── FIX 1: operator address checksum-normalized in the proofHash preimage ──────
  it("Fix 1: same violation, operator lowercase vs checksummed → identical proofHash", async () => {
    const lower = "0x" + "ab".repeat(20);
    const checksummed = ethers.getAddress(lower);
    expect(lower).not.toBe(checksummed); // sanity: the two casings genuinely differ

    const nodeLower = makeService(
      overLimitBlockchain(),
      makeConfig({ auditWatchlist: [lower] }),
      makeArchive()
    );
    await nodeLower.tick();
    const hashLower = (await nodeLower.getStatus()).recentDetections[0].proofHash;

    const nodeChecksum = makeService(
      overLimitBlockchain(),
      makeConfig({ auditWatchlist: [checksummed] }),
      makeArchive()
    );
    await nodeChecksum.tick();
    const hashChecksum = (await nodeChecksum.getStatus()).recentDetections[0].proofHash;

    // Two DVT nodes with differently-cased watchlist entries derive the SAME proofHash.
    expect(hashLower).toBe(hashChecksum);
  });

  // ── FIX 2: creditLimit==0 is unconfigured, NOT "over limit" ─────────────────────
  it("Fix 2: creditLimit==0 with debt>0 → unconfigured/de-registered → NO proposal", async () => {
    const created: any[] = [];
    const blockchain = makeBlockchain({
      getCreditLimit: async () => 0n, // unconfigured / de-registered
      getAvailableCredit: async () => 0n,
      getDebt: async () => 5000n, // has debt, but a zero limit must NOT be treated as over-limit
      createProposalWithEvidence: async (...args: any[]) => {
        created.push(args);
        return { txHash: "0xTX", proposalId: 7n };
      },
    });
    const archive = makeArchive();
    const svc = makeService(blockchain, makeConfig(), archive);
    await svc.tick();
    expect(created).toHaveLength(0);
    expect(archive.records).toHaveLength(0);
  });

  it("Fix 2: creditLimit>0 with debt>limit (credit exhausted) → proposal filed", async () => {
    const created: any[] = [];
    const blockchain = overLimitBlockchain({
      createProposalWithEvidence: async (...args: any[]) => {
        created.push(args);
        return { txHash: "0xTX", proposalId: 7n };
      },
    });
    const svc = makeService(blockchain, makeConfig(), makeArchive());
    await svc.tick();
    expect(created).toHaveLength(1);
  });

  // ── FIX 3: cooldown armed on ATTEMPT, not only on SUCCESS ───────────────────────
  it("Fix 3: a persistently-reverting proposal is attempted only ONCE within the cooldown window", async () => {
    let attempts = 0;
    let block = 5000;
    let now = 1_700_000_000_000;
    const blockchain = overLimitBlockchain({
      createProposalWithEvidence: async () => {
        attempts++;
        throw new Error("reverted: proposer not an active validator");
      },
    });
    blockchain.getBlockNumber = async () => block;
    const archive = makeArchive();
    const svc = makeService(
      blockchain,
      makeConfig({ auditCooldownMs: 3_600_000 }),
      archive,
      () => now
    );
    // Many ticks, each at a NEW head block, each a small time step (< cooldown).
    for (let i = 0; i < 5; i++) {
      await svc.tick();
      block += 1;
      now += 60_000;
    }
    // Armed on ATTEMPT → backs off for cooldownMs despite EVERY attempt failing (no gas/nonce burn).
    expect(attempts).toBe(1);
    // Evidence is still archived across ticks (not lost), just not re-attempted on-chain.
    expect(archive.records.length).toBeGreaterThan(1);
    expect(archive.records.every(r => r.proposalTx === undefined)).toBe(true);
  });

  it("Fix (PK): archive.put failure does NOT suppress retry — evidence never lost", async () => {
    let putCalls = 0;
    const records: SlashProof[] = [];
    const flakyArchive: IProofArchive = {
      async put(proof: SlashProof) {
        putCalls++;
        if (putCalls === 1) throw new Error("ENOSPC: disk full");
        // Idempotent on proofHash, like LocalProofArchive (same file overwritten).
        const existing = records.findIndex(r => r.proofHash === proof.proofHash);
        if (existing >= 0) records[existing] = proof;
        else records.push(proof);
        return { proofHash: proof.proofHash, location: `mem://${proof.proofHash}` };
      },
      async has(proofHash: string) {
        return records.some(r => r.proofHash === proofHash);
      },
      async count() {
        return records.length;
      },
      async recordSlashed() {},
      async hasSlashed() {
        return false;
      },
      async removeSlashed() {},
    };
    const blockchain = overLimitBlockchain({
      createProposalWithEvidence: async () => ({ txHash: "0xABC", proposalId: 1n }),
    });
    blockchain.getBlockNumber = async () => 5000; // SAME violation@block both ticks
    const svc = makeService(blockchain, makeConfig(), flakyArchive);

    await svc.tick(); // pre-execute archive put throws → recordStableKey NOT reached
    expect(records).toHaveLength(0);
    // The in-memory stableKey must NOT have suppressed the same violation — a later tick retries.
    await svc.tick();
    // Archive-before-execute writes the proof TWICE per successful tick (v0 intent BEFORE the
    // on-chain slash, then an idempotent update WITH the tx hashes after): 1 failed + 2 on retry.
    expect(putCalls).toBe(3);
    expect(records).toHaveLength(1); // evidence eventually persisted (invariant held)
  });

  // ── FIX 4: proof carries the REAL on-chain proposal id (no fabrication) ─────────
  it("Fix 4: the proof carries the REAL on-chain proposal id parsed from the event", async () => {
    const blockchain = overLimitBlockchain({
      createProposalWithEvidence: async () => ({ txHash: "0xABC", proposalId: 4242n }),
    });
    const archive = makeArchive();
    const svc = makeService(blockchain, makeConfig(), archive);
    await svc.tick();
    expect(archive.records).toHaveLength(1);
    expect(archive.records[0].proposalId).toBe("4242"); // real uint id, not a keccak
    expect(archive.records[0].proposalIdNote).toBeUndefined();
    expect(archive.records[0].proposalTx).toBe("0xABC");
    const status = await svc.getStatus();
    expect(status.recentDetections[0].proposalId).toBe("4242");
  });

  it("Fix 4: an unresolved id (event absent) → proposalId null + note, never fabricated", async () => {
    const blockchain = overLimitBlockchain({
      createProposalWithEvidence: async () => ({ txHash: "0xDEF", proposalId: null }),
    });
    const archive = makeArchive();
    const svc = makeService(blockchain, makeConfig(), archive);
    await svc.tick();
    expect(archive.records[0].proposalId).toBeNull();
    expect(archive.records[0].proposalIdNote).toMatch(/id-unresolved/);
    expect(archive.records[0].proposalTx).toBe("0xDEF"); // tx still recorded
  });

  // ── FIX 5: cross-contract limit mismatch must not false-positive ────────────────
  it("Fix 5: availableCredit>0 but registryLimit<debt → within SP ceiling → NO proposal", async () => {
    const created: any[] = [];
    const blockchain = makeBlockchain({
      getCreditLimit: async () => 1000n, // stale/low Registry limit
      getAvailableCredit: async () => 500n, // SP says the operator is still within its ceiling
      getDebt: async () => 2000n, // exceeds the Registry limit ONLY
      createProposalWithEvidence: async (...args: any[]) => {
        created.push(args);
        return { txHash: "0xTX", proposalId: 7n };
      },
    });
    const archive = makeArchive();
    const svc = makeService(blockchain, makeConfig(), archive);
    await svc.tick();
    expect(created).toHaveLength(0);
    expect(archive.records).toHaveLength(0);
  });

  // ── FIX 7: dedup/cooldown maps stay bounded ─────────────────────────────────────
  it("Fix 7: dedup/cooldown maps are pruned once entries age past cooldownMs", async () => {
    let now = 1_700_000_000_000;
    const blockchain = overLimitBlockchain();
    const svc = makeService(
      blockchain,
      makeConfig({ auditCooldownMs: 3_600_000 }),
      makeArchive(),
      () => now
    );
    await svc.tick(); // over-limit → arms a stableKey + a cooldown entry
    expect((svc as any).proposedStableKeys.size).toBe(1);
    expect((svc as any).lastProposalAt.size).toBe(1);

    // Advance well past the cooldown and make the operator healthy so no NEW entries are added.
    now += 3_600_001;
    blockchain.getDebt = async () => 0n;
    blockchain.getAvailableCredit = async () => 1000n;
    await svc.tick(); // prune runs at tick start → the stale entries are evicted
    expect((svc as any).proposedStableKeys.size).toBe(0);
    expect((svc as any).lastProposalAt.size).toBe(0);
  });

  // ── REAL SP ABI: debt lives on the xPNTs TOKEN, credit takes (user, token) ──────
  it("reads debt from the aPNTs TOKEN and passes the token to getAvailableCredit", async () => {
    const debtTargets: string[] = [];
    const creditArgs: Array<{ sp: string; op: string; token: string }> = [];
    const blockchain = overLimitBlockchain({
      getDebt: async (tokenAddr: string, _op: string) => {
        debtTargets.push(tokenAddr);
        return 2000n;
      },
      getAvailableCredit: async (sp: string, op: string, token: string) => {
        creditArgs.push({ sp, op, token });
        return 0n;
      },
    });
    const svc = makeService(blockchain, makeConfig(), makeArchive());
    await svc.tick();
    // getDebt is called against the TOKEN, never the SuperPaymaster or Registry.
    expect(debtTargets).toEqual([APNTS_TOKEN]);
    // getAvailableCredit gets (superPaymaster, operator, token).
    expect(creditArgs).toEqual([{ sp: SUPER_PAYMASTER, op: OPERATOR, token: APNTS_TOKEN }]);
  });

  it("fail-closed: a missing aPNTs token address → DISABLED, never schedules", async () => {
    const svc = makeService(
      makeBlockchain(),
      makeConfig({ auditApntsTokenAddress: undefined }),
      makeArchive()
    );
    await svc.onApplicationBootstrap();
    expect((svc as any).startupTimer).toBeNull();
    expect((await svc.getStatus()).enabled).toBe(false);
  });

  // ── FINDING 1 / FINDING 5: submitted vs intended EXECUTE preimage ────────────────
  it("Finding 5: file-only (executeSlash off) records the intendedExecuteMessageHash, NOT messageHash (nothing submitted)", async () => {
    const now = 1_700_000_000_000;
    const blockchain = overLimitBlockchain({
      createProposalWithEvidence: async () => ({ txHash: "0xTX", proposalId: 7n }),
    });
    const archive = makeArchive();
    const svc = makeService(blockchain, makeConfig(), archive, clockAt(now));
    await svc.tick();

    const proof = archive.records[0];
    // epoch is the violationBlock (deterministic), NOT Math.floor(now/1000).
    const epoch = BLOCK;
    const expected = buildExecuteMessageHash(7n, OPERATOR, 1, epoch, 11155111, proof.proofHash);
    // finding-5: nothing was submitted (file-only) → messageHash stays "0x"; the computed preimage
    // is kept, unambiguously, as INTENDED — never conflated with a submitted one.
    expect(proof.messageHash).toBe("0x");
    expect(proof.intendedExecuteMessageHash).toBe(expected);
    expect(proof.messageHashNote).toBeDefined();
    expect(proof.executeTx).toBeUndefined();
    // Sanity: the intended preimage is the 8-field one, NOT the retired 7-field inc-1 preimage.
    const retired7field = ethers.keccak256(
      new ethers.AbiCoder().encode(
        ["uint256", "address", "uint8", "address[]", "uint256[]", "uint256", "uint256"],
        [7n, OPERATOR, 1, [], [], epoch, 11155111]
      )
    );
    expect(proof.intendedExecuteMessageHash).not.toBe(retired7field);
  });

  it("Finding 5: file-only path binds the execute preimage as INTENT only (proposalId 9)", async () => {
    const blockchain = overLimitBlockchain({
      createProposalWithEvidence: async () => ({ txHash: "0xTX", proposalId: 9n }),
    });
    const archive = makeArchive();
    // Default config → executeSlash OFF; no queue/execute → intended preimage, not a submitted one.
    const svc = makeService(blockchain, makeConfig(), archive);
    await svc.tick();
    const proof = archive.records[0];
    const expected = buildExecuteMessageHash(9n, OPERATOR, 1, BLOCK, 11155111, proof.proofHash);
    expect(proof.messageHash).toBe("0x");
    expect(proof.intendedExecuteMessageHash).toBe(expected);
  });

  it("unresolved proposal id → messageHash placeholder '0x' + a note (no on-chain proposal to sign)", async () => {
    const blockchain = overLimitBlockchain({
      createProposalWithEvidence: async () => ({ txHash: "0xDEF", proposalId: null }),
    });
    const archive = makeArchive();
    const svc = makeService(blockchain, makeConfig(), archive);
    await svc.tick();
    expect(archive.records[0].messageHash).toBe("0x");
    expect(archive.records[0].messageHashNote).toMatch(/id-unresolved/);
  });

  // ── INCREMENT 2: two-step slash-consensus orchestration ─────────────────────────

  /** A blockchain whose write calls are recorded in a shared, ordered log. */
  function recordingBlockchain(order: string[], overrides: Record<string, any> = {}) {
    return overLimitBlockchain({
      queueSlashWithProof: async (...args: any[]) => {
        order.push("queue");
        return `0xQUEUE:${JSON.stringify(args.slice(1, 4))}`;
      },
      createProposalWithEvidence: async (...args: any[]) => {
        order.push("create");
        (recordingBlockchain as any).lastCreateArgs = args;
        return { txHash: "0xPROPOSALTX", proposalId: 7n };
      },
      executeSlashWithProof: async (...args: any[]) => {
        order.push("execute");
        (recordingBlockchain as any).lastExecuteArgs = args;
        return "0xEXECUTETX";
      },
      ...overrides,
    });
  }

  it("default (executeSlash off): files the proposal but NEVER queues/executes a slash", async () => {
    const order: string[] = [];
    const blockchain = recordingBlockchain(order);
    const archive = makeArchive();
    // Default config has no auditExecuteSlash → the second safety gate is closed.
    const svc = makeService(blockchain, makeConfig(), archive, undefined, makeCoSigner());
    await svc.tick();
    expect(order).toEqual(["create"]); // proposal filed, no queue/execute
    expect(archive.records).toHaveLength(1);
    // The filed proposal binds the archived evidence: evidenceHash === proofHash.
    const createArgs = (recordingBlockchain as any).lastCreateArgs;
    expect(createArgs[4]).toBe(archive.records[0].proofHash);
  });

  it("executeSlash=true: calls queue → createProposalWithEvidence → execute in that order", async () => {
    const order: string[] = [];
    const blockchain = recordingBlockchain(order);
    const archive = makeArchive();
    const coSigner = makeCoSigner();
    const now = 1_700_000_000_000;
    const svc = makeService(
      blockchain,
      makeConfig({ auditExecuteSlash: true }),
      archive,
      clockAt(now),
      coSigner
    );
    await svc.tick();

    // Exact on-chain call order.
    expect(order).toEqual(["queue", "create", "execute"]);
    expect(archive.records).toHaveLength(1);
    const proof = archive.records[0];
    // epoch is the DETERMINISTIC violationBlock, not a wall-clock value.
    const epoch = BLOCK;

    // createProposalWithEvidence bound the archived evidence: (dvt, op, level, reason, proofHash).
    const createArgs = (recordingBlockchain as any).lastCreateArgs;
    expect(createArgs[0]).toBe(DVT_VALIDATOR);
    expect(createArgs[1]).toBe(OPERATOR);
    expect(createArgs[2]).toBe(1); // SlashLevel.MINOR
    expect(createArgs[4]).toBe(proof.proofHash);

    // execute used the REAL proposal id (7) with empty rep arrays + the same deterministic epoch.
    const execArgs = (recordingBlockchain as any).lastExecuteArgs;
    expect(execArgs[0]).toBe(DVT_VALIDATOR);
    expect(execArgs[1]).toBe(7n);
    expect(execArgs[2]).toEqual([]);
    expect(execArgs[3]).toEqual([]);
    expect(execArgs[4]).toBe(epoch);

    // The quorum co-signer was invoked exactly twice — over the queue then the execute preimage.
    expect(coSigner.calls).toHaveLength(2);
    const expectedQueue = buildQueueMessageHash(OPERATOR, 1, epoch, 11155111);
    const expectedExec = buildExecuteMessageHash(7n, OPERATOR, 1, epoch, 11155111, proof.proofHash);
    expect(coSigner.calls[0]).toBe(expectedQueue);
    expect(coSigner.calls[1]).toBe(expectedExec);

    // The archived proof records BOTH signed preimages, the queue/execute tx hashes, and the
    // real co-sign material (finding-1 + finding-2).
    expect(proof.queueMessageHash).toBe(expectedQueue);
    expect(proof.messageHash).toBe(expectedExec);
    expect(proof.queueTx).not.toBeUndefined();
    expect(proof.executeTx).toBe("0xEXECUTETX");
    expect(proof.signerMask).toBe(ethers.toBeHex(0b111n));
    expect(proof.sigG2).toBe("0x" + "ab".repeat(64));

    // The detection surfaces the queue/execute txs too.
    const status = await svc.getStatus();
    expect(status.recentDetections[0].queueTx).not.toBeNull();
    expect(status.recentDetections[0].executeTx).toBe("0xEXECUTETX");

    // The execute step carried the abi-encoded proof (uint256 signerMask, bytes sigG2).
    const expectedProof = encodeProof(0b111n, "0x" + "ab".repeat(64));
    expect(execArgs[5]).toBe(expectedProof);
  });

  it("executeSlash=true + real proposalId: execute is bound to that exact id", async () => {
    const order: string[] = [];
    const blockchain = recordingBlockchain(order, {
      createProposalWithEvidence: async () => ({ txHash: "0xABC", proposalId: 4242n }),
      executeSlashWithProof: async (...args: any[]) => {
        order.push("execute");
        (recordingBlockchain as any).lastExecuteArgs = args;
        return "0xEXECUTETX";
      },
    });
    const svc = makeService(
      blockchain,
      makeConfig({ auditExecuteSlash: true }),
      makeArchive(),
      undefined,
      makeCoSigner()
    );
    await svc.tick();
    expect((recordingBlockchain as any).lastExecuteArgs[1]).toBe(4242n);
  });

  it("executeSlash=true but proposalId unresolved (event absent) → execute is SKIPPED", async () => {
    const order: string[] = [];
    const blockchain = recordingBlockchain(order, {
      createProposalWithEvidence: async () => {
        order.push("create");
        return { txHash: "0xDEF", proposalId: null };
      },
    });
    const archive = makeArchive();
    const svc = makeService(
      blockchain,
      makeConfig({ auditExecuteSlash: true }),
      archive,
      undefined,
      makeCoSigner()
    );
    await svc.tick();
    // A fabricated id would revert on-chain, so execute must not run; queue + proposal still did.
    expect(order).toEqual(["queue", "create"]);
    expect(archive.records).toHaveLength(1);
  });

  it("executeSlash=true with the default PendingSlotCoSigner stub → co-sign throws, caught, evidence archived", async () => {
    const order: string[] = [];
    const blockchain = recordingBlockchain(order);
    const archive = makeArchive();
    // No coSigner injected → defaults to PendingSlotCoSigner, whose coSign throws.
    const svc = makeService(blockchain, makeConfig({ auditExecuteSlash: true }), archive);
    // The tick must survive the stub's throw (loop never crashes).
    await expect(svc.tick()).resolves.toBeUndefined();
    // queue co-sign threw (queue skipped) but the proposal was still filed; execute co-sign
    // also threw (execute skipped) — yet the evidence is archived regardless.
    expect(order).toEqual(["create"]);
    expect(archive.records).toHaveLength(1);
    expect(archive.records[0].proposalTx).toBe("0xPROPOSALTX");
  });

  it("Finding 1 (CRITICAL): a queue tx failure ABORTS the slash — execute is NOT called (two-step safety)", async () => {
    const order: string[] = [];
    let executeCalls = 0;
    const blockchain = recordingBlockchain(order, {
      queueSlashWithProof: async () => {
        order.push("queue-fail");
        throw new Error("reverted: queue not authorized");
      },
      executeSlashWithProof: async (...args: any[]) => {
        executeCalls++;
        order.push("execute");
        (recordingBlockchain as any).lastExecuteArgs = args;
        return "0xEXECUTETX";
      },
    });
    const archive = makeArchive();
    const svc = makeService(
      blockchain,
      makeConfig({ auditExecuteSlash: true }),
      archive,
      undefined,
      makeCoSigner()
    );
    await expect(svc.tick()).resolves.toBeUndefined();
    // finding-1: queue reverted (queueTx null) → execute must NOT run even though the proposal
    // filed and resolved a real id. A slash never executes without a confirmed queue pre-flag.
    expect(order).toEqual(["queue-fail", "create"]);
    expect(executeCalls).toBe(0);
    expect(archive.records).toHaveLength(1);
    const proof = archive.records[0];
    // No execute tx recorded, and the (resolvable) execute preimage is kept as INTENT only.
    expect(proof.executeTx).toBeUndefined();
    expect(proof.messageHash).toBe("0x");
    expect(proof.intendedExecuteMessageHash).toBeDefined();
    // The over-slash guard was NOT armed durably (no slash executed).
    expect((archive as any).slashed.size).toBe(0);
    const status = await svc.getStatus();
    expect(status.recentDetections[0].executeTx).toBeNull();
  });

  // ── FINDING 3: epoch is the deterministic violationBlock (cross-node agreement) ──
  it("Finding 3: epoch == violationBlock — identical across two wildly different observedAt values", async () => {
    const mkNode = (nowMs: number) => {
      const blockchain = overLimitBlockchain();
      blockchain.getBlockNumber = async () => 8_888_888;
      const archive = makeArchive();
      const svc = makeService(blockchain, makeConfig(), archive, clockAt(nowMs));
      return { svc, archive };
    };
    const a = mkNode(1_000);
    const b = mkNode(9_999_999_999_000);
    await a.svc.tick();
    await b.svc.tick();
    // Both nodes derive epoch = violationBlock, regardless of their wall-clocks.
    expect(a.archive.records[0].epoch).toBe(8_888_888);
    expect(b.archive.records[0].epoch).toBe(8_888_888);
    // observedAt stays the ONLY wall-clock field and DOES differ between the nodes.
    expect(a.archive.records[0].evidence.observedAt).toBe(1_000);
    expect(b.archive.records[0].evidence.observedAt).toBe(9_999_999_999_000);
  });

  // ── FINDING 4: coarse operator|rule guard prevents over-slashing a sustained violation ──
  it("Finding 4: a sustained violation across ticks (advancing block, past cooldown) EXECUTES the slash only ONCE", async () => {
    const order: string[] = [];
    let block = 4000;
    let now = 1_700_000_000_000;
    const blockchain = recordingBlockchain(order);
    blockchain.getBlockNumber = async () => block;
    const archive = makeArchive();
    const svc = makeService(
      blockchain,
      makeConfig({ auditExecuteSlash: true, auditCooldownMs: 3_600_000 }),
      archive,
      () => now,
      makeCoSigner()
    );
    // Tick 1 → queue + create + execute (slash executes).
    await svc.tick();
    // More ticks, each a NEW block AND past cooldown — the coarse guard still blocks a 2nd execute.
    for (let i = 0; i < 3; i++) {
      block += 1;
      now += 3_600_001;
      await svc.tick();
    }
    expect(order.filter(o => o === "execute")).toHaveLength(1);
    // Evidence is still archived for each new block — just never re-slashed.
    expect(archive.records.length).toBeGreaterThan(1);
  });

  it("Finding 4: the over-slash guard CLEARS when the operator becomes healthy, so a NEW violation slashes again", async () => {
    const order: string[] = [];
    let block = 4000;
    let now = 1_700_000_000_000;
    let over = true;
    const blockchain = recordingBlockchain(order, {
      getDebt: async () => (over ? 2000n : 0n),
      getAvailableCredit: async () => (over ? 0n : 1000n),
    });
    blockchain.getBlockNumber = async () => block;
    const svc = makeService(
      blockchain,
      makeConfig({ auditExecuteSlash: true, auditCooldownMs: 1 }),
      makeArchive(),
      () => now,
      makeCoSigner()
    );
    await svc.tick(); // slash #1
    // Operator recovers → a healthy tick clears the coarse guard.
    over = false;
    block += 1;
    now += 10;
    await svc.tick();
    // Operator breaches again at a NEW block, past the (1ms) cooldown → slash #2 allowed.
    over = true;
    block += 1;
    now += 10;
    await svc.tick();
    expect(order.filter(o => o === "execute")).toHaveLength(2);
  });

  it("Finding 4: an on-chain isSlashPending=true short-circuits queue/create/execute (durable cross-restart guard)", async () => {
    const order: string[] = [];
    const blockchain = recordingBlockchain(order, { isSlashPending: async () => true });
    const archive = makeArchive();
    const svc = makeService(
      blockchain,
      makeConfig({ auditExecuteSlash: true }),
      archive,
      undefined,
      makeCoSigner()
    );
    await svc.tick();
    // Already pending on-chain → NO on-chain writes this tick; evidence still archived.
    expect(order).toEqual([]);
    expect(archive.records).toHaveLength(1);
    expect(archive.records[0].proposalIdNote).toMatch(/over-slash guard/);
  });

  // ── FINDING 5: archive-before-execute ordering (durable intent precedes the slash) ──
  it("Finding 5: the proof is archived (durable intent) BEFORE the irreversible on-chain execute, then updated after", async () => {
    const order: string[] = [];
    const blockchain = overLimitBlockchain({
      queueSlashWithProof: async () => {
        order.push("queue");
        return "0xQ";
      },
      createProposalWithEvidence: async () => {
        order.push("create");
        return { txHash: "0xP", proposalId: 7n };
      },
      executeSlashWithProof: async () => {
        order.push("execute");
        return "0xE";
      },
    });
    const records: SlashProof[] = [];
    const orderingArchive: IProofArchive = {
      async put(proof: SlashProof) {
        order.push("archive-put");
        const i = records.findIndex(r => r.proofHash === proof.proofHash);
        if (i >= 0) records[i] = proof;
        else records.push(proof);
        return { proofHash: proof.proofHash, location: `mem://${proof.proofHash}` };
      },
      async has(proofHash: string) {
        return records.some(r => r.proofHash === proofHash);
      },
      async count() {
        return records.length;
      },
      async recordSlashed() {},
      async hasSlashed() {
        return false;
      },
      async removeSlashed() {},
    };
    const svc = makeService(
      blockchain,
      makeConfig({ auditExecuteSlash: true }),
      orderingArchive,
      undefined,
      makeCoSigner()
    );
    await svc.tick();
    // The FIRST durable write must land before the slash executes.
    const firstArchive = order.indexOf("archive-put");
    expect(firstArchive).toBeGreaterThanOrEqual(0);
    expect(order.indexOf("execute")).toBeGreaterThan(firstArchive);
    // And a post-execute update records the executeTx on the proof (finding-2).
    expect(records[0].executeTx).toBe("0xE");
    expect(records[0].queueTx).toBe("0xQ");
  });

  // ── FINDING 2: durable, restart-surviving over-slash guard ──────────────────────
  it("Finding 2: getRecentSlashExecuted=true short-circuits queue/create/execute (on-chain durable guard)", async () => {
    const order: string[] = [];
    const blockchain = recordingBlockchain(order, { getRecentSlashExecuted: async () => true });
    const archive = makeArchive();
    const svc = makeService(
      blockchain,
      makeConfig({ auditExecuteSlash: true }),
      archive,
      undefined,
      makeCoSigner()
    );
    await svc.tick();
    // An on-chain SlashExecuted(WithProof) hit → NO on-chain writes this tick; evidence archived.
    expect(order).toEqual([]);
    expect(archive.records).toHaveLength(1);
    expect(archive.records[0].proposalIdNote).toMatch(/over-slash guard/);
    // The on-chain hit is cached into the DURABLE journal so later ticks/restarts short-circuit.
    expect(archive.slashed.size).toBe(1);
  });

  it("Finding 2: getRecentSlashExecuted scans within [violationBlock - lookback, latest]", async () => {
    let scannedFrom: number | undefined;
    const order: string[] = [];
    const blockchain = recordingBlockchain(order, {
      getRecentSlashExecuted: async (
        _addr: string,
        _op: string,
        _slashLevel: number,
        fromBlock: number
      ) => {
        scannedFrom = fromBlock;
        return false;
      },
    });
    blockchain.getBlockNumber = async () => 100_000;
    const svc = makeService(
      blockchain,
      makeConfig({ auditExecuteSlash: true, auditSlashLookbackBlocks: 40_000 }),
      makeArchive(),
      undefined,
      makeCoSigner()
    );
    await svc.tick();
    // violationBlock 100000 - lookback 40000 = 60000.
    expect(scannedFrom).toBe(60_000);
  });

  // ── Codex round-2 HIGH: an INDETERMINATE on-chain scan fails CLOSED (no double-slash) ──
  it("HIGH: getRecentSlashExecuted=null (provider error) → armed path SKIPS the slash (fail-closed)", async () => {
    const order: string[] = [];
    // Provider can't confirm slash state (null), and the pending flag is also unknown (null default).
    const blockchain = recordingBlockchain(order, { getRecentSlashExecuted: async () => null });
    const archive = makeArchive();
    const svc = makeService(
      blockchain,
      makeConfig({ auditExecuteSlash: true }),
      archive,
      undefined,
      makeCoSigner()
    );
    await svc.tick();
    // Indeterminate scan + indeterminate pending + no durable marker → over-slash guard fails CLOSED.
    expect(order).toEqual([]); // NO queue / create / execute
    expect(archive.records).toHaveLength(1); // evidence still archived (never lost)
    expect(archive.records[0].proposalIdNote).toMatch(/over-slash guard/);
  });

  it("HIGH: getRecentSlashExecuted THROWS → armed path SKIPS the slash (fail-closed)", async () => {
    const order: string[] = [];
    const blockchain = recordingBlockchain(order, {
      getRecentSlashExecuted: async () => {
        throw new Error("provider down");
      },
    });
    const archive = makeArchive();
    const svc = makeService(
      blockchain,
      makeConfig({ auditExecuteSlash: true }),
      archive,
      undefined,
      makeCoSigner()
    );
    await svc.tick();
    expect(order).toEqual([]); // NO on-chain writes when slash state is unconfirmable
    expect(archive.records).toHaveLength(1);
    expect(archive.records[0].proposalIdNote).toMatch(/over-slash guard/);
  });

  it("HIGH: an INDETERMINATE scan but a KNOWN pending flag (false) still lets the slash proceed", async () => {
    // Only ONE of the two signals is indeterminate → we still have an authoritative signal, so the
    // fail-closed backstop does NOT fire and the armed path slashes normally.
    const order: string[] = [];
    const blockchain = recordingBlockchain(order, {
      getRecentSlashExecuted: async () => null,
      isSlashPending: async () => false,
    });
    const svc = makeService(
      blockchain,
      makeConfig({ auditExecuteSlash: true }),
      makeArchive(),
      undefined,
      makeCoSigner()
    );
    await svc.tick();
    expect(order).toEqual(["queue", "create", "execute"]);
  });

  // ── Codex round-2 MEDIUM: executeTx + submitted messageHash archived TOGETHER (consistent) ──
  it("MEDIUM: the post-execute re-archive persists executeTx AND the 8-field messageHash together", async () => {
    const snapshots: Array<{ executeTx?: string; messageHash: string; proofHash: string }> = [];
    const records: SlashProof[] = [];
    const snapArchive: IProofArchive & { slashed: Set<string> } = {
      slashed: new Set<string>(),
      async put(proof: SlashProof) {
        snapshots.push({
          executeTx: proof.executeTx,
          messageHash: proof.messageHash,
          proofHash: proof.proofHash,
        });
        const i = records.findIndex(r => r.proofHash === proof.proofHash);
        if (i >= 0) records[i] = proof;
        else records.push(proof);
        return { proofHash: proof.proofHash, location: `mem://${proof.proofHash}` };
      },
      async has(proofHash: string) {
        return records.some(r => r.proofHash === proofHash);
      },
      async count() {
        return records.length;
      },
      async recordSlashed(k: string) {
        this.slashed.add(k);
      },
      async hasSlashed(k: string) {
        return this.slashed.has(k);
      },
      async removeSlashed(k: string) {
        this.slashed.delete(k);
      },
    };
    const order: string[] = [];
    const blockchain = recordingBlockchain(order);
    const svc = makeService(
      blockchain,
      makeConfig({ auditExecuteSlash: true }),
      snapArchive,
      undefined,
      makeCoSigner()
    );
    await svc.tick();

    // EVERY durable snapshot that carries executeTx must ALSO carry a real (non-"0x") messageHash —
    // no snapshot may persist executeTx alongside messageHash="0x" (the crash-window inconsistency).
    const withExec = snapshots.filter(s => s.executeTx !== undefined);
    expect(withExec.length).toBeGreaterThan(0);
    for (const s of withExec) {
      const expected = buildExecuteMessageHash(7n, OPERATOR, 1, BLOCK, 11155111, s.proofHash);
      expect(s.messageHash).toBe(expected);
      expect(s.messageHash).not.toBe("0x");
    }
    // Final durable state is likewise consistent.
    expect(records[0].executeTx).toBe("0xEXECUTETX");
    const finalExpected = buildExecuteMessageHash(
      7n,
      OPERATOR,
      1,
      BLOCK,
      11155111,
      records[0].proofHash
    );
    expect(records[0].messageHash).toBe(finalExpected);
  });

  it("Finding 2: a durable slashed marker (archive) survives a RESTART → the sustained violation is NOT re-slashed", async () => {
    const archive = makeArchive();
    let block = 4000;
    const now = 1_700_000_000_000;

    // Node instance #1 slashes the operator and persists the durable marker.
    const order1: string[] = [];
    const bc1 = recordingBlockchain(order1);
    bc1.getBlockNumber = async () => block;
    const svc1 = makeService(
      bc1,
      makeConfig({ auditExecuteSlash: true, auditCooldownMs: 1 }),
      archive,
      () => now,
      makeCoSigner()
    );
    await svc1.tick();
    expect(order1.filter(o => o === "execute")).toHaveLength(1);
    expect(archive.slashed.size).toBe(1); // durable marker persisted to the (shared) archive

    // Simulate a process RESTART: a BRAND-NEW service with FRESH in-memory guards but the SAME
    // archive (disk). The block ADVANCES so this is not per-block-deduped (a fresh proofHash).
    block = 4001;
    const order2: string[] = [];
    const bc2 = recordingBlockchain(order2);
    bc2.getBlockNumber = async () => block;
    const svc2 = makeService(
      bc2,
      makeConfig({ auditExecuteSlash: true, auditCooldownMs: 1 }),
      archive,
      () => now + 10_000,
      makeCoSigner()
    );
    await svc2.tick();
    // The durable marker (reloaded from the archive) blocks the re-slash across the restart.
    expect(order2.filter(o => o === "execute")).toHaveLength(0);
    // Evidence for the new block is still archived (never lost).
    expect(archive.records.some(r => r.evidence.violationBlock === 4001)).toBe(true);
  });

  // ── FINDING 3: evidence pinned to a FINALIZED block + its hash (reorg-safe) ──────
  it("Finding 3: rule inputs are read at a FINALIZED block and its hash is stored in the evidence", async () => {
    let confirmationsSeen: number | undefined;
    const finalizedHash = "0x" + "cc".repeat(32);
    const seen: Record<string, number | undefined> = {};
    const blockchain = overLimitBlockchain({
      getViolationBlock: async (confirmations?: number) => {
        confirmationsSeen = confirmations;
        return { number: 777, hash: finalizedHash };
      },
    });
    blockchain.getCreditLimit = async (_a: string, _o: string, bt?: number) => {
      seen.limit = bt;
      return 1000n;
    };
    blockchain.getAvailableCredit = async (_a: string, _o: string, _t: string, bt?: number) => {
      seen.avail = bt;
      return 0n;
    };
    blockchain.getDebt = async (_a: string, _o: string, bt?: number) => {
      seen.debt = bt;
      return 2000n;
    };
    const archive = makeArchive();
    const svc = makeService(blockchain, makeConfig({ auditFinalityConfirmations: 5 }), archive);
    await svc.tick();
    // The configured confirmation depth is threaded to getViolationBlock (finalized-tag fallback).
    expect(confirmationsSeen).toBe(5);
    // ALL rule inputs are block-pinned to the finalized number, not a live head.
    expect(seen.limit).toBe(777);
    expect(seen.avail).toBe(777);
    expect(seen.debt).toBe(777);
    // The evidence records both the finalized number AND its hash (reorg-safe justification).
    expect(archive.records[0].evidence.violationBlock).toBe(777);
    expect(archive.records[0].evidence.violationBlockHash).toBe(finalizedHash);
    // epoch (the co-sign preimage input) is the finalized block too.
    expect(archive.records[0].epoch).toBe(777);
  });

  // ── FINDING 4: per-step re-archive (durable after EACH confirmed on-chain step) ──
  it("Finding 4: the proof is RE-ARCHIVED after each confirmed on-chain step (queue then execute)", async () => {
    const snapshots: Array<{ queueTx?: string; executeTx?: string }> = [];
    const records: SlashProof[] = [];
    const snapArchive: IProofArchive & { slashed: Set<string> } = {
      slashed: new Set<string>(),
      async put(proof: SlashProof) {
        // Snapshot the tx fields AT put time so intermediate durable states are observable.
        snapshots.push({ queueTx: proof.queueTx, executeTx: proof.executeTx });
        const i = records.findIndex(r => r.proofHash === proof.proofHash);
        if (i >= 0) records[i] = proof;
        else records.push(proof);
        return { proofHash: proof.proofHash, location: `mem://${proof.proofHash}` };
      },
      async has(proofHash: string) {
        return records.some(r => r.proofHash === proofHash);
      },
      async count() {
        return records.length;
      },
      async recordSlashed(k: string) {
        this.slashed.add(k);
      },
      async hasSlashed(k: string) {
        return this.slashed.has(k);
      },
      async removeSlashed(k: string) {
        this.slashed.delete(k);
      },
    };
    const order: string[] = [];
    const blockchain = recordingBlockchain(order);
    const svc = makeService(
      blockchain,
      makeConfig({ auditExecuteSlash: true }),
      snapArchive,
      undefined,
      makeCoSigner()
    );
    await svc.tick();
    // A durable snapshot exists AFTER the queue confirmed (queueTx set, executeTx not yet)…
    expect(snapshots.some(s => s.queueTx !== undefined && s.executeTx === undefined)).toBe(true);
    // …and one AFTER the execute confirmed (both txs present).
    expect(snapshots.some(s => s.queueTx !== undefined && s.executeTx !== undefined)).toBe(true);
    // Final durable state carries both txs.
    expect(records[0].queueTx).toBeDefined();
    expect(records[0].executeTx).toBe("0xEXECUTETX");
  });

  it("computeJitterMs stays within [0, intervalMs)", () => {
    const mk = (rand: number) =>
      new AuditService(
        makeBlockchain(),
        makeConfig(),
        makeRegistry(),
        clockAt(0),
        () => rand,
        makeArchive()
      );
    expect(mk(0).computeJitterMs()).toBe(0);
    expect(mk(0.5).computeJitterMs()).toBe(30_000);
    expect(mk(0.999999).computeJitterMs()).toBeLessThan(60_000);
  });

  // ── PK perf findings ─────────────────────────────────────────────────────────
  it("PK-F2: the finalized evidence block is resolved ONCE per tick, shared across operators", async () => {
    let violationBlockCalls = 0;
    const opB = "0x" + "ab".repeat(20);
    const blockchain = makeBlockchain({
      getViolationBlock: async function (this: any) {
        violationBlockCalls++;
        return { number: await this.getBlockNumber(), hash: BLOCK_HASH };
      },
    });
    const svc = makeService(
      blockchain,
      makeConfig({ auditWatchlist: [OPERATOR, opB] }),
      makeArchive()
    );
    await svc.tick();
    // Two operators, but only ONE getViolationBlock RPC (shared snapshot), not one per operator.
    expect(violationBlockCalls).toBe(1);
  });

  it("PK-F2: a getViolationBlock failure skips the whole tick without throwing", async () => {
    const blockchain = makeBlockchain({
      getViolationBlock: async () => {
        throw new Error("RPC down");
      },
    });
    const archive = makeArchive();
    const svc = makeService(blockchain, makeConfig(), archive);
    await expect(svc.tick()).resolves.toBeUndefined();
    expect(archive.records).toHaveLength(0);
  });

  it("B-F3 regression: a healthy read clears a durable slashed marker even when DISARMED", async () => {
    // Simulate an armed→disarmed restart: a durable marker left by an earlier armed run exists on
    // disk, but the node now runs with executeSlash=false. A healthy read MUST still clear it — else
    // hasSlashed short-circuits before the on-chain scan and suppresses a legitimate future slash
    // indefinitely (Codex R3 B-F3). Default makeBlockchain models a HEALTHY operator (debt 0 ≤ 1000).
    const archive = makeArchive();
    const coarseKey = `11155111|${ethers.getAddress(OPERATOR)}|credit-over-limit`;
    await archive.recordSlashed(coarseKey);
    expect(archive.slashed.has(coarseKey)).toBe(true);
    const svc = makeService(makeBlockchain(), makeConfig({ auditExecuteSlash: false }), archive);
    await svc.tick();
    // The stale durable marker is gone — a genuine future violation can slash again.
    expect(archive.slashed.has(coarseKey)).toBe(false);
  });
});
