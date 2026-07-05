import { ethers } from "ethers";
import { AuditService } from "./audit.service.js";
import { IProofArchive, SlashProof, computeProofHash } from "./proof-archive.js";

const OPERATOR = "0x" + "12".repeat(20);
const REGISTRY = "0xf5Bf37ca83AfdAab73691bA7eCcDfA69b8708E71";
const SUPER_PAYMASTER = "0x" + "34".repeat(20);
const DVT_VALIDATOR = "0x" + "56".repeat(20);
const GTOKEN_STAKING = "0x" + "78".repeat(20);
const BLOCK = 12_345;

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
    getCode: (addr: string) => Promise<string>;
    getCreditLimit: (addr: string, op: string, bt?: number) => Promise<bigint>;
    getAvailableCredit: (addr: string, op: string, bt?: number) => Promise<bigint>;
    getDebt: (addr: string, op: string, bt?: number) => Promise<bigint | null>;
    getGlobalReputation: (addr: string, op: string, bt?: number) => Promise<bigint>;
    getRoleLockAmount: (...args: any[]) => Promise<bigint>;
    createSlashProposal: (...args: any[]) => Promise<{ txHash: string; proposalId: bigint | null }>;
    getWalletAddress: () => string | null;
  }> = {}
): any {
  return {
    getBlockNumber: overrides.getBlockNumber ?? (async () => BLOCK),
    getCode: overrides.getCode ?? (async () => "0x60006000fd"),
    getCreditLimit: overrides.getCreditLimit ?? (async () => 1000n),
    getAvailableCredit: overrides.getAvailableCredit ?? (async () => 1000n),
    getDebt: overrides.getDebt ?? (async () => 0n),
    getGlobalReputation: overrides.getGlobalReputation ?? (async () => 500n),
    getRoleLockAmount: overrides.getRoleLockAmount ?? (async () => 42n),
    createSlashProposal:
      overrides.createSlashProposal ?? (async () => ({ txHash: "0xPROPOSALTX", proposalId: 7n })),
    getWalletAddress: overrides.getWalletAddress ?? (() => "0x" + "99".repeat(20)),
  };
}

/** In-memory archive so tests never touch the filesystem. */
function makeArchive(): IProofArchive & { records: SlashProof[] } {
  const records: SlashProof[] = [];
  return {
    records,
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
  clock: () => number = clockAt(1_700_000_000_000)
) {
  return new AuditService(blockchain, config, makeRegistry(), clock, () => 0, archive);
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
      createSlashProposal: async (...args: any[]) => {
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
      createSlashProposal: async (...args: any[]) => {
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
      createSlashProposal: async (...args: any[]) => {
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
      createSlashProposal: async (...args: any[]) => {
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
    expect(sourceNames).toContain("SuperPaymaster.getDebt");
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
    blockchain.getAvailableCredit = async (_a: string, _o: string, bt?: number) => {
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
      createSlashProposal: async (...args: any[]) => {
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
      createSlashProposal: async (...args: any[]) => {
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
      createSlashProposal: async (...args: any[]) => {
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
      createSlashProposal: async (...args: any[]) => {
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
      createSlashProposal: async () => {
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
      createSlashProposal: async (_addr: string, operator: string) => {
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
      createSlashProposal: async (...args: any[]) => {
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
      createSlashProposal: async (...args: any[]) => {
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
      createSlashProposal: async () => {
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

  // ── FIX 4: proof carries the REAL on-chain proposal id (no fabrication) ─────────
  it("Fix 4: the proof carries the REAL on-chain proposal id parsed from the event", async () => {
    const blockchain = overLimitBlockchain({
      createSlashProposal: async () => ({ txHash: "0xABC", proposalId: 4242n }),
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
      createSlashProposal: async () => ({ txHash: "0xDEF", proposalId: null }),
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
      createSlashProposal: async (...args: any[]) => {
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

  it("coordinateQuorumCoSign is deferred to increment 2 (throws)", async () => {
    const svc = makeService(makeBlockchain(), makeConfig(), makeArchive());
    await expect(svc.coordinateQuorumCoSign()).rejects.toThrow(/increment 2/);
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
});
