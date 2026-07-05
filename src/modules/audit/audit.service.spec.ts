import { jest } from "@jest/globals";
import { AuditService } from "./audit.service.js";
import { IProofArchive, SlashProof, computeProofHash } from "./proof-archive.js";

const OPERATOR = "0x" + "12".repeat(20);
const REGISTRY = "0xf5Bf37ca83AfdAab73691bA7eCcDfA69b8708E71";
const SUPER_PAYMASTER = "0x" + "34".repeat(20);
const DVT_VALIDATOR = "0x" + "56".repeat(20);
const GTOKEN_STAKING = "0x" + "78".repeat(20);

const BASE_CONFIG: Record<string, unknown> = {
  auditEnabled: true,
  auditIntervalMs: 60_000,
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
 * Blockchain mock. Defaults model a HEALTHY operator (availableCredit == creditLimit →
 * usage 0bps → no violation). Override getAvailableCredit to model exhausted credit.
 */
function makeBlockchain(
  overrides: Partial<{
    getCreditLimit: () => Promise<bigint>;
    getAvailableCredit: () => Promise<bigint>;
    getGlobalReputation: () => Promise<bigint>;
    getRoleLockAmount: () => Promise<bigint>;
    createSlashProposal: (...args: any[]) => Promise<string>;
    getWalletAddress: () => string | null;
  }> = {}
): any {
  return {
    getCreditLimit: overrides.getCreditLimit ?? (async () => 1000n),
    getAvailableCredit: overrides.getAvailableCredit ?? (async () => 1000n),
    getGlobalReputation: overrides.getGlobalReputation ?? (async () => 500n),
    getRoleLockAmount: overrides.getRoleLockAmount ?? (async () => 42n),
    createSlashProposal: overrides.createSlashProposal ?? (async () => "0xPROPOSALTX"),
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

describe("AuditService", () => {
  it("registers the audit capability (enabled) with the CapabilityRegistry", () => {
    const registry = makeRegistry();
    new AuditService(makeBlockchain(), makeConfig(), registry, clockAt(0), () => 0, makeArchive());
    expect(registry.registered).toContain("audit");
  });

  it("disabled → onApplicationBootstrap never schedules a tick", () => {
    const svc = makeService(makeBlockchain(), makeConfig({ auditEnabled: false }), makeArchive());
    svc.onApplicationBootstrap();
    expect((svc as any).startupTimer).toBeNull();
    expect((svc as any).timer).toBeNull();
  });

  it("enabled → onApplicationBootstrap schedules a phase-jittered first tick", () => {
    const svc = makeService(makeBlockchain(), makeConfig(), makeArchive());
    svc.onApplicationBootstrap();
    // First tick is phase-jittered via setTimeout — startupTimer holds it, interval not armed.
    expect((svc as any).startupTimer).not.toBeNull();
    expect((svc as any).timer).toBeNull();
    svc.onApplicationShutdown();
    expect((svc as any).startupTimer).toBeNull();
  });

  it("enabled but empty watchlist → does not schedule", () => {
    const svc = makeService(makeBlockchain(), makeConfig({ auditWatchlist: [] }), makeArchive());
    svc.onApplicationBootstrap();
    expect((svc as any).startupTimer).toBeNull();
  });

  it("healthy operator (availableCredit == limit) → no detection, no proposal", async () => {
    const created: any[] = [];
    const blockchain = makeBlockchain({
      getAvailableCredit: async () => 1000n, // == limit → usage 0bps
      createSlashProposal: async (...args: any[]) => {
        created.push(args);
        return "0xTX";
      },
    });
    const archive = makeArchive();
    const svc = makeService(blockchain, makeConfig(), archive);
    await svc.tick();
    expect(created).toHaveLength(0);
    expect(archive.records).toHaveLength(0);
  });

  it("credit-over-limit → files a proposal AND archives a content-addressed proof with evidence", async () => {
    const created: any[] = [];
    const blockchain = makeBlockchain({
      getCreditLimit: async () => 1000n,
      getAvailableCredit: async () => 0n, // debt == limit → usage 10000bps ≥ threshold
      createSlashProposal: async (...args: any[]) => {
        created.push(args);
        return "0xPROPOSALTX";
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
    expect(proof.executedTx).toBe("0xPROPOSALTX");

    // Evidence captured, with the raw view sources.
    expect(proof.evidence.rule).toBe("credit-over-limit");
    expect(proof.evidence.observed).toBe("1000"); // debt
    expect(proof.evidence.threshold).toBe("1000"); // creditLimit
    const sourceNames = proof.evidence.sources.map(s => s.name);
    expect(sourceNames).toContain("Registry.getCreditLimit");
    expect(sourceNames).toContain("SuperPaymaster.getAvailableCredit");

    // proofHash is a real content address: recomputing from the immutable core matches.
    const recomputed = computeProofHash({
      version: proof.version,
      chainId: proof.chainId,
      operator: proof.operator,
      slashLevel: proof.slashLevel,
      reason: proof.reason,
      epoch: proof.epoch,
      messageHash: proof.messageHash,
      evidence: proof.evidence,
    });
    expect(recomputed).toBe(proof.proofHash);
    expect(proof.proofHash).toMatch(/^0x[0-9a-f]{64}$/);

    // Detection surfaced in status.
    const status = await svc.getStatus();
    expect(status.recentDetections).toHaveLength(1);
    expect(status.recentDetections[0].proofHash).toBe(proof.proofHash);
    expect(status.archivedProofCount).toBe(1);
  });

  it("content-address is deterministic + idempotent: same violation twice → one archived proof", async () => {
    const blockchain = makeBlockchain({
      getCreditLimit: async () => 1000n,
      getAvailableCredit: async () => 0n,
    });
    const archive = makeArchive();
    // Fixed clock so epoch (derived from observedAt) is identical across both ticks → same proofHash.
    const svc = makeService(blockchain, makeConfig(), archive, clockAt(1_700_000_000_000));
    await svc.tick();
    await svc.tick();
    expect(archive.records).toHaveLength(1);
  });

  it("proposal write failure → proof still archived (evidence never lost)", async () => {
    const blockchain = makeBlockchain({
      getCreditLimit: async () => 1000n,
      getAvailableCredit: async () => 0n,
      createSlashProposal: async () => {
        throw new Error("reverted: not authorized");
      },
    });
    const archive = makeArchive();
    const svc = makeService(blockchain, makeConfig(), archive);
    await expect(svc.tick()).resolves.toBeUndefined(); // never throws
    expect(archive.records).toHaveLength(1);
    expect(archive.records[0].executedTx).toBeUndefined();
    const status = await svc.getStatus();
    expect(status.recentDetections[0].proposalTx).toBeNull();
  });

  it("tick sweeps every operator; one failing operator does not abort the rest", async () => {
    const op2 = "0x" + "ab".repeat(20);
    const created: string[] = [];
    const blockchain = makeBlockchain({
      getCreditLimit: async () => 1000n,
      getAvailableCredit: async () => 0n,
      createSlashProposal: async (_addr: string, operator: string) => {
        created.push(operator);
        return "0xTX";
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
    expect(created).toEqual([op2]);
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
