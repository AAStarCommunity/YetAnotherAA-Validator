import { ethers } from "ethers";
import { AuditService } from "./audit.service.js";
import { IProofArchive, SlashProof } from "./proof-archive.js";

const OPERATOR = "0x" + "12".repeat(20);
const REGISTRY = "0xf5Bf37ca83AfdAab73691bA7eCcDfA69b8708E71";
const SUPER_PAYMASTER = "0x" + "34".repeat(20);
const DVT_VALIDATOR = "0x" + "56".repeat(20);
const GTOKEN_STAKING = "0x" + "78".repeat(20);
const BLOCK = 12_345;
/** Finalized-block hash the mock getViolationBlock returns (finding-3 reorg-safe evidence). */
const BLOCK_HASH = "0x" + "bb".repeat(32);

const BASE_CONFIG: Record<string, unknown> = {
  auditEnabled: true,
  auditIntervalMs: 60_000,
  auditCooldownMs: 3_600_000,
  auditWatchlist: [OPERATOR],
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
    getRegisteredOperators: (
      registry: string,
      roleIds: string[],
      fromBlock: number,
      toBlock: number,
      chunk: number,
      useGetter?: boolean
    ) => Promise<string[]>;
    hasRole: (
      registry: string,
      roleId: string,
      operator: string,
      blockTag?: number
    ) => Promise<boolean>;
    getOperatorNodeId: (blsAgg: string, operator: string) => Promise<string | null>;
    getBlockTimestamp: (blockNumber: number) => Promise<number>;
    getIsOverIssued: (token: string, blockTag?: number) => Promise<boolean>;
    getCommunityOwner: (token: string, blockTag?: number) => Promise<string | null>;
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
    // A1#6 — on-chain role enumeration. Default empty (roleDerive is off in BASE_CONFIG, so this is
    // never called unless a test opts in with auditRoleDerive: true).
    getRegisteredOperators: overrides.getRegisteredOperators ?? (async () => []),
    // A1#6 (round-3) — per-operator membership at the evidence block. Default TRUE (a derived operator
    // is still a role member); a test overrides to model an operator that exited by the epoch block.
    hasRole: overrides.hasRole ?? (async () => true),
    // Rule ③ over-issue — default WITHIN cap (isOverIssued false); a fixed community owner.
    getIsOverIssued: overrides.getIsOverIssued ?? (async () => false),
    getCommunityOwner:
      overrides.getCommunityOwner ?? (async () => ethers.getAddress("0x" + "c0".repeat(20))),
    // Rule ② offline — operator → nodeId resolution + block timestamp. Defaults model an operator with
    // an active slot (nodeId) and a fixed block time; offline tests override these.
    getOperatorNodeId: overrides.getOperatorNodeId ?? (async () => "0x" + "ab".repeat(32)),
    getBlockTimestamp: overrides.getBlockTimestamp ?? (async () => 1_700_000_000),
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
    async get(proofHash: string) {
      return records.find(r => r.proofHash === proofHash) ?? null;
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

/** Liveness mock for the offline rule (rule ②). getLastSeen returns a fixed epoch-ms (or null);
 *  setRelevantNodeIds records the last pushed set so tests can assert the relevant-set contents. */
function makeGossip(lastSeenMs: number | null): any {
  const g: any = {
    lastRelevant: null as string[] | null,
    getLastSeen: (_nodeId: string) => lastSeenMs,
    setRelevantNodeIds: (ids: Iterable<string>) => {
      g.lastRelevant = [...ids];
    },
  };
  return g;
}

function makeService(
  blockchain: any,
  config: any,
  archive: IProofArchive,
  clock: () => number = clockAt(1_700_000_000_000),
  coSigner?: any,
  gossip?: any
) {
  return new AuditService(
    blockchain,
    config,
    makeRegistry(),
    clock,
    () => 0,
    archive,
    coSigner,
    gossip
  );
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
  // ── A1#6: watchlist derived from on-chain Registry role membership ─────────────
  describe("A1#6 on-chain role-derived watchlist", () => {
    const opB = "0x" + "cd".repeat(20);
    const roleDeriveConfig = (overrides: Record<string, unknown> = {}) =>
      makeConfig({
        auditRoleDerive: true,
        auditRoleIds: ["DVT", "ANODE"],
        auditRoleFromBlock: 100,
        auditRoleLogChunk: 5000,
        auditRoleRefreshMs: 300_000,
        ...overrides,
      });

    it("hashes role NAMES to keccak256 roleIds and passes them to getRegisteredOperators", async () => {
      let seen: string[] = [];
      const blockchain = makeBlockchain({
        getRegisteredOperators: async (_r, roleIds) => {
          seen = roleIds;
          return [];
        },
      });
      const svc = makeService(blockchain, roleDeriveConfig({ auditWatchlist: [] }), makeArchive());
      await svc.onApplicationBootstrap();
      expect(seen).toEqual([ethers.id("DVT"), ethers.id("ANODE")]);
    });

    it("UNIONs the static watchlist with the derived set (static never subtracts)", async () => {
      const blockchain = makeBlockchain({ getRegisteredOperators: async () => [opB] });
      const svc = makeService(
        blockchain,
        roleDeriveConfig({ auditWatchlist: [OPERATOR] }),
        makeArchive()
      );
      await svc.onApplicationBootstrap();
      const status = await svc.getStatus();
      expect(status.watchlist.sort()).toEqual(
        [ethers.getAddress(OPERATOR), ethers.getAddress(opB)].sort()
      );
      expect(status.roleDerive).toBe(true);
      expect(status.derivedOperatorCount).toBe(1);
    });

    it("canonicalizes derived addresses to checksummed form", async () => {
      const lower = "0x" + "ef".repeat(20);
      const blockchain = makeBlockchain({ getRegisteredOperators: async () => [lower] });
      const svc = makeService(blockchain, roleDeriveConfig({ auditWatchlist: [] }), makeArchive());
      await svc.onApplicationBootstrap();
      expect((await svc.getStatus()).watchlist).toEqual([ethers.getAddress(lower)]);
    });

    it("KEEPS the previous derived set when a refresh fails (never shrinks to empty)", async () => {
      let call = 0;
      const blockchain = makeBlockchain({
        getRegisteredOperators: async () => {
          call++;
          if (call === 1) return [opB]; // eager bootstrap derive succeeds
          throw new Error("getLogs range too wide"); // subsequent refresh fails
        },
      });
      // refreshMs=0 so the next tick attempts a fresh (failing) derivation.
      const svc = makeService(
        blockchain,
        roleDeriveConfig({ auditWatchlist: [], auditRoleRefreshMs: 0 }),
        makeArchive()
      );
      await svc.onApplicationBootstrap();
      expect((await svc.getStatus()).derivedOperatorCount).toBe(1);
      await svc.tick(); // refresh throws → previous set kept
      expect((await svc.getStatus()).derivedOperatorCount).toBe(1);
      expect((await svc.getStatus()).watchlist).toEqual([ethers.getAddress(opB)]);
    });

    it("is a no-op when roleDerive is OFF (getRegisteredOperators never called)", async () => {
      let called = false;
      const blockchain = makeBlockchain({
        getRegisteredOperators: async () => {
          called = true;
          return [opB];
        },
      });
      // BASE_CONFIG has auditRoleDerive unset (falsy) and a non-empty static watchlist.
      const svc = makeService(blockchain, makeConfig(), makeArchive());
      await svc.onApplicationBootstrap();
      await svc.tick();
      expect(called).toBe(false);
      expect((await svc.getStatus()).watchlist).toEqual([ethers.getAddress(OPERATOR)]);
    });

    it("boots with an empty static watchlist when roleDerive is ON (no 'nothing to watch' bail)", async () => {
      const blockchain = makeBlockchain({ getRegisteredOperators: async () => [opB] });
      const svc = makeService(blockchain, roleDeriveConfig({ auditWatchlist: [] }), makeArchive());
      await svc.onApplicationBootstrap();
      // enabled stays true (did not early-return on the empty static list) and the derived op is live.
      expect((await svc.getStatus()).enabled).toBe(true);
      expect((await svc.getStatus()).watchlist).toEqual([ethers.getAddress(opB)]);
    });

    // ── Codex Medium-1: membership derived to the SAME finalized block as the evidence ──
    it("derives membership at the finalized block (not raw latest)", async () => {
      let seenToBlock = -1;
      const blockchain = makeBlockchain({
        getViolationBlock: async () => ({ number: 999, hash: BLOCK_HASH }),
        getRegisteredOperators: async (_r, _ids, _from, toBlock) => {
          seenToBlock = toBlock;
          return [];
        },
      });
      const svc = makeService(blockchain, roleDeriveConfig({ auditWatchlist: [] }), makeArchive());
      await svc.onApplicationBootstrap();
      expect(seenToBlock).toBe(999);
    });

    // ── Codex Medium-2: fail-closed when the event-scan has no explicit lower bound ──
    it("DISABLES fail-closed when roleDerive is on, no getter, and AUDIT_ROLE_FROM_BLOCK is 0", async () => {
      let called = false;
      const blockchain = makeBlockchain({
        getRegisteredOperators: async () => {
          called = true;
          return [opB];
        },
      });
      const svc = makeService(
        blockchain,
        roleDeriveConfig({ auditWatchlist: [], auditRoleFromBlock: 0, auditRoleUseGetter: false }),
        makeArchive()
      );
      await svc.onApplicationBootstrap();
      expect((await svc.getStatus()).enabled).toBe(false);
      expect(called).toBe(false); // never scanned from genesis
    });

    it("allows fromBlock 0 when the getter is enabled (no scan window needed)", async () => {
      let usedGetter: boolean | undefined;
      const blockchain = makeBlockchain({
        getRegisteredOperators: async (_r, _ids, _from, _to, _chunk, useGetter) => {
          usedGetter = useGetter;
          return [opB];
        },
      });
      const svc = makeService(
        blockchain,
        roleDeriveConfig({ auditWatchlist: [], auditRoleFromBlock: 0, auditRoleUseGetter: true }),
        makeArchive()
      );
      await svc.onApplicationBootstrap();
      expect((await svc.getStatus()).enabled).toBe(true);
      expect(usedGetter).toBe(true);
    });
    // ── Codex round-2: single-flight collapses concurrent refreshes onto ONE derivation ──
    it("concurrent refreshes share one in-flight derivation (single-flight, no double getLogs)", async () => {
      let calls = 0;
      let release!: () => void;
      const gate = new Promise<void>(res => {
        release = res;
      });
      let firstDone = false;
      const blockchain = makeBlockchain({
        getRegisteredOperators: async () => {
          calls++;
          if (!firstDone) {
            firstDone = true; // bootstrap eager derive resolves immediately
            return [opB];
          }
          await gate; // subsequent derive suspends so two callers overlap
          return [opB];
        },
      });
      const svc = makeService(
        blockchain,
        roleDeriveConfig({ auditWatchlist: [], auditRoleRefreshMs: 0 }),
        makeArchive()
      );
      await svc.onApplicationBootstrap(); // calls = 1 (bootstrap)
      // Fire two concurrent refreshes; the second must await the first's in-flight promise.
      const p1 = (svc as any).refreshDerivedOperators(false);
      const p2 = (svc as any).refreshDerivedOperators(false);
      release();
      await Promise.all([p1, p2]);
      expect(calls).toBe(2); // bootstrap + ONE shared derivation, not 3
    });
  });

  // ── Rule ② offline detection (inc-1) ──────────────────────────────────────────
  describe("rule ② offline detection", () => {
    const BLS_AGG = "0x" + "bb".repeat(20);
    const NODE_ID = "0x" + "ab".repeat(32);
    // clock/blockTs: block.timestamp 1_700_000_000s → 1_700_000_000_000ms; threshold 600_000ms →
    // deadline 1_699_999_400_000ms. lastSeen below deadline = OFFLINE, at/above = ONLINE.
    const OFFLINE_LAST_SEEN = 1_699_990_000_000; // 10_000_000ms (≈2.7h) before the block → offline
    const ONLINE_LAST_SEEN = 1_700_000_000_000; // == block time → online

    const offlineConfig = (overrides: Record<string, unknown> = {}) =>
      makeConfig({
        auditOfflineEnabled: true,
        auditOfflineThresholdMs: 600_000,
        auditBlsAggregatorAddress: BLS_AGG,
        ...overrides,
      });

    it("files an OFFLINE proposal when the operator's last heartbeat is older than the deadline", async () => {
      const created: string[] = [];
      const blockchain = makeBlockchain({
        getOperatorNodeId: async () => NODE_ID,
        createProposalWithEvidence: async (_a: string, operator: string) => {
          created.push(operator);
          return { txHash: "0xTX", proposalId: 9n };
        },
      });
      const archive = makeArchive();
      const svc = makeService(
        blockchain,
        offlineConfig(),
        archive,
        clockAt(1_700_000_000_000),
        undefined,
        makeGossip(OFFLINE_LAST_SEEN)
      );
      await svc.tick();
      // an offline proof was archived (rule=offline, WARNING=0) and a proposal filed for the operator.
      const offlineProof = archive.records.find(r => r.evidence.rule === "offline");
      expect(offlineProof).toBeDefined();
      expect(offlineProof!.slashLevel).toBe(0); // SlashLevel.WARNING
      expect(created).toEqual([ethers.getAddress(OPERATOR)]);
    });

    // Generic handleViolation behaviour (dedup / evidence-never-lost) is now exercised through the
    // offline rule — the only active rule — after the credit rule (its former test driver) was removed.
    it("dedup: the SAME offline violation over many ticks files exactly ONE proposal", async () => {
      const created: string[] = [];
      const blockchain = makeBlockchain({
        getOperatorNodeId: async () => NODE_ID,
        createProposalWithEvidence: async (_a: string, operator: string) => {
          created.push(operator);
          return { txHash: "0xTX", proposalId: 9n };
        },
      });
      const svc = makeService(
        blockchain,
        offlineConfig(),
        makeArchive(),
        clockAt(1_700_000_000_000),
        undefined,
        makeGossip(OFFLINE_LAST_SEEN)
      );
      await svc.tick();
      await svc.tick();
      await svc.tick();
      // coarseKey (subject|rule) guard + cooldown: one proposal despite three ticks on the same block.
      expect(created).toHaveLength(1);
    });

    it("proposal write failure → the offline proof is STILL archived (evidence never lost)", async () => {
      const blockchain = makeBlockchain({
        getOperatorNodeId: async () => NODE_ID,
        createProposalWithEvidence: async () => {
          throw new Error("RPC down");
        },
      });
      const archive = makeArchive();
      const svc = makeService(
        blockchain,
        offlineConfig(),
        archive,
        clockAt(1_700_000_000_000),
        undefined,
        makeGossip(OFFLINE_LAST_SEEN)
      );
      await svc.tick();
      // The archive-before-propose invariant: a failed on-chain write must never lose the evidence.
      expect(archive.records.find(r => r.evidence.rule === "offline")).toBeDefined();
    });

    it("does NOT flag an operator seen within the threshold (online)", async () => {
      const blockchain = makeBlockchain({ getOperatorNodeId: async () => NODE_ID });
      const archive = makeArchive();
      const svc = makeService(
        blockchain,
        offlineConfig(),
        archive,
        clockAt(1_700_000_000_000),
        undefined,
        makeGossip(ONLINE_LAST_SEEN)
      );
      await svc.tick();
      expect(archive.records.find(r => r.evidence.rule === "offline")).toBeUndefined();
    });

    it("SKIPS a never-seen node (getLastSeen null) — cannot prove offline-since-T", async () => {
      const blockchain = makeBlockchain({ getOperatorNodeId: async () => NODE_ID });
      const archive = makeArchive();
      const svc = makeService(
        blockchain,
        offlineConfig(),
        archive,
        clockAt(1_700_000_000_000),
        undefined,
        makeGossip(null)
      );
      await svc.tick();
      expect(archive.records.find(r => r.evidence.rule === "offline")).toBeUndefined();
    });

    it("SKIPS an operator with no active BLS slot (getOperatorNodeId null)", async () => {
      let gossipCalled = false;
      const blockchain = makeBlockchain({ getOperatorNodeId: async () => null });
      const archive = makeArchive();
      const gossip = {
        getLastSeen: () => {
          gossipCalled = true;
          return OFFLINE_LAST_SEEN;
        },
        setRelevantNodeIds: (_ids: any) => {},
      };
      const svc = makeService(
        blockchain,
        offlineConfig(),
        archive,
        clockAt(1_700_000_000_000),
        undefined,
        gossip
      );
      await svc.tick();
      expect(archive.records.find(r => r.evidence.rule === "offline")).toBeUndefined();
      expect(gossipCalled).toBe(false); // bailed before touching gossip
    });

    it("is a no-op when AUDIT_OFFLINE_ENABLED is not set (getOperatorNodeId never called)", async () => {
      let called = false;
      const blockchain = makeBlockchain({
        getOperatorNodeId: async () => {
          called = true;
          return NODE_ID;
        },
      });
      const svc = makeService(
        blockchain,
        makeConfig(),
        makeArchive(),
        clockAt(1_700_000_000_000),
        undefined,
        makeGossip(OFFLINE_LAST_SEEN)
      );
      await svc.tick();
      expect(called).toBe(false);
    });

    it("offline proofHash is DETERMINISTIC across nodes with DIFFERENT lastSeen (no per-node data)", async () => {
      const build = async (lastSeen: number) => {
        const archive = makeArchive();
        const svc = makeService(
          makeBlockchain({ getOperatorNodeId: async () => NODE_ID }),
          offlineConfig(),
          archive,
          clockAt(1_700_000_000_000),
          undefined,
          makeGossip(lastSeen)
        );
        await svc.tick();
        return archive.records.find(r => r.evidence.rule === "offline")!.proofHash;
      };
      // Two nodes observed the operator offline at DIFFERENT times — same block, same threshold.
      const hashA = await build(1_699_990_000_000);
      const hashB = await build(1_699_985_123_456);
      expect(hashA).toBe(hashB); // content-address excludes lastSeen → identical
    });

    it("SKIPS offline when the local clock is behind the finalized block (slow-clock guard, Codex High-2)", async () => {
      const blockchain = makeBlockchain({
        getOperatorNodeId: async () => NODE_ID,
        getBlockTimestamp: async () => 1_700_000_000, // block time = 1_700_000_000_000ms
      });
      const archive = makeArchive();
      // Local clock EARLIER than the finalized block time → broken/slow clock → refuse to trust
      // local liveness timestamps, even though lastSeen is "offline"-old.
      const svc = makeService(
        blockchain,
        offlineConfig(),
        archive,
        clockAt(1_699_999_999_000), // 1s before the finalized block
        undefined,
        makeGossip(OFFLINE_LAST_SEEN)
      );
      await svc.tick();
      expect(archive.records.find(r => r.evidence.rule === "offline")).toBeUndefined();
    });

    it("keeps a relevant operator's nodeId across a TRANSIENT resolve failure (no prune on RPC blip, Codex M1)", async () => {
      let call = 0;
      const blockchain = makeBlockchain({
        getOperatorNodeId: async () => {
          call++;
          if (call === 1) return NODE_ID; // tick 1 resolves
          throw new Error("rpc blip"); // tick 2 fails
        },
      });
      const gossip = makeGossip(ONLINE_LAST_SEEN);
      const svc = makeService(
        blockchain,
        offlineConfig(),
        makeArchive(),
        clockAt(1_700_000_000_000),
        undefined,
        gossip
      );
      await svc.tick(); // resolves → cache + relevant set has NODE_ID
      expect(gossip.lastRelevant).toEqual([NODE_ID]);
      await svc.tick(); // resolve throws → cached nodeId retained, NOT pruned
      expect(gossip.lastRelevant).toEqual([NODE_ID]);
    });

    it("DROPS the cached nodeId on an AUTHORITATIVE null (inactive/key-rotated), not on a throw (Codex M-final)", async () => {
      let call = 0;
      const blockchain = makeBlockchain({
        getOperatorNodeId: async () => {
          call++;
          if (call === 1) return NODE_ID; // tick 1: active
          return null; // tick 2: authoritative "no active slot" (rotated / exited)
        },
      });
      const gossip = makeGossip(ONLINE_LAST_SEEN);
      const svc = makeService(
        blockchain,
        offlineConfig(),
        makeArchive(),
        clockAt(1_700_000_000_000),
        undefined,
        gossip
      );
      await svc.tick();
      expect(gossip.lastRelevant).toEqual([NODE_ID]);
      await svc.tick(); // authoritative null → cache dropped → relevant set cleared
      expect(gossip.lastRelevant).toEqual([]);
    });

    it("is FILE-ONLY even when armed (executeSlash) — no queue/execute for offline in inc-1", async () => {
      let queued = false;
      const blockchain = makeBlockchain({
        getOperatorNodeId: async () => NODE_ID,
        queueSlashWithProof: async () => {
          queued = true;
          return "0xQUEUE";
        },
      });
      const svc = makeService(
        blockchain,
        offlineConfig({ auditExecuteSlash: true }),
        makeArchive(),
        clockAt(1_700_000_000_000),
        undefined,
        makeGossip(OFFLINE_LAST_SEEN)
      );
      await svc.tick();
      expect(queued).toBe(false); // offline never queues an on-chain slash in inc-1
    });
  });
});
