import { jest } from "@jest/globals";
import { ethers } from "ethers";
import {
  BlockchainService,
  OWNER_AUTH_FN,
  OWNER_AUTH_MAGIC,
  OWNER_AUTH_ABI,
  DRY_RUN_TX_SENTINEL,
} from "./blockchain.service.js";

/**
 * Focused unit tests for the durable over-slash guard read `getRecentSlashExecuted` (Codex round-2
 * HIGH fail-closed + MEDIUM level-narrowing). BlockchainService is constructed with a stub
 * ConfigService (no RPC dial), then its private `provider` is replaced with a mock exposing only the
 * `getLogs` the method calls.
 */
const CONTRACT = "0x" + "11".repeat(20);
const OPERATOR = "0x" + "22".repeat(20);
const OTHER_OPERATOR = "0x" + "33".repeat(20);

/** SlashExecuted(uint256 indexed proposalId, address indexed operator, uint8 level) — level NON-indexed. */
const SLASH_IFACE = new ethers.Interface([
  "event SlashExecuted(uint256 indexed proposalId, address indexed operator, uint8 level)",
]);

/** Build a real, decodable SlashExecuted log for (proposalId, operator, level). */
function makeSlashExecutedLog(proposalId: bigint, operator: string, level: number) {
  const encoded = SLASH_IFACE.encodeEventLog("SlashExecuted", [proposalId, operator, level]);
  return { topics: encoded.topics, data: encoded.data };
}

/** A BlockchainService whose `provider.getLogs` is the supplied stub. */
function makeService(getLogs: (filter: any) => Promise<any[]>): BlockchainService {
  const config = { get: (_k: string) => undefined } as any;
  const svc = new BlockchainService(config);
  (svc as any).provider = { getLogs };
  return svc;
}

describe("BlockchainService.getRecentSlashExecuted", () => {
  const LEVEL = 1; // SlashLevel.MINOR — the credit-over-limit rule's level.

  it("HIGH fail-closed: a getLogs/provider error returns null (indeterminate), NEVER false", async () => {
    const svc = makeService(async () => {
      throw new Error("RPC range too wide");
    });
    const result = await svc.getRecentSlashExecuted(CONTRACT, OPERATOR, LEVEL, 0);
    // Must be null ("cannot determine"), so the caller fails CLOSED rather than reading "not slashed".
    expect(result).toBeNull();
  });

  it("MEDIUM level-narrowing: a slash for a DIFFERENT level does NOT match (returns false)", async () => {
    // Only a level-2 slash exists; the rule asks about level-1 → no match.
    const svc = makeService(async () => [makeSlashExecutedLog(7n, OPERATOR, 2)]);
    const result = await svc.getRecentSlashExecuted(CONTRACT, OPERATOR, LEVEL, 0);
    expect(result).toBe(false);
  });

  it("a slash for the SAME operator + SAME level matches (returns true)", async () => {
    const svc = makeService(async () => [makeSlashExecutedLog(7n, OPERATOR, LEVEL)]);
    const result = await svc.getRecentSlashExecuted(CONTRACT, OPERATOR, LEVEL, 0);
    expect(result).toBe(true);
  });

  it("a clean scan with no matching logs returns false (determinate 'not slashed')", async () => {
    const svc = makeService(async () => []);
    const result = await svc.getRecentSlashExecuted(CONTRACT, OPERATOR, LEVEL, 0);
    expect(result).toBe(false);
  });

  it("an undecodable log (matched the topic filter but wrong shape) is ignored, not a match", async () => {
    // A log whose topics[0] is neither event's hash → parseLog throws → ignored → false.
    const svc = makeService(async () => [
      { topics: [ethers.id("SomethingElse(uint256)")], data: "0x" },
    ]);
    const result = await svc.getRecentSlashExecuted(CONTRACT, OTHER_OPERATOR, LEVEL, 0);
    expect(result).toBe(false);
  });
});

/**
 * Cross-repo interface lock for the owner-auth gate (airaccount-contract AAStarAirAccountV7).
 * The magic value the DVT gate checks MUST equal the function selector of the delegated view —
 * if airaccount ever changes this interface, updating OWNER_AUTH_FN/OWNER_AUTH_MAGIC/OWNER_AUTH_ABI
 * out of step fails CI here, forcing a deliberate sync. See docs/INTERFACES.md.
 */
describe("owner-auth cross-repo interface invariant", () => {
  it("OWNER_AUTH_MAGIC === selector(OWNER_AUTH_FN)", () => {
    expect(ethers.id(OWNER_AUTH_FN).slice(0, 10)).toBe(OWNER_AUTH_MAGIC);
  });

  it("OWNER_AUTH_ABI's fragment selector matches OWNER_AUTH_MAGIC (ABI kept in sync)", () => {
    const iface = new ethers.Interface(OWNER_AUTH_ABI);
    const frag = iface.getFunction("isValidOwnerAuth");
    expect(frag).not.toBeNull();
    expect(frag!.selector).toBe(OWNER_AUTH_MAGIC);
  });

  it("is NOT the standard ERC-1271 isValidSignature magic (0x1626ba7e)", () => {
    // Guards against a silent revert to standard ERC-1271, which would accept the wrong accounts.
    expect(OWNER_AUTH_MAGIC).not.toBe(ethers.id("isValidSignature(bytes32,bytes)").slice(0, 10));
  });
});

/**
 * HIGH 2 (Codex): the irreversible slash writes (queueSlashWithProof / executeWithProof) must run a
 * STATIC-CALL preflight with the EXACT args first. A deterministic revert (bad signerMask, sigG2,
 * threshold, proposal state, wrong address) must THROW before any gas is spent — never become a
 * PAID on-chain revert — and the real tx must broadcast ONLY when the simulation passes.
 */
const DVT_VALIDATOR = "0x" + "44".repeat(20);
const EPOCH = 999;
const PROOF = "0x" + "ab".repeat(32);

/** A BlockchainService with a truthy wallet + a provider exposing getFeeData (for bumpedFees). */
function makeWriterService(): BlockchainService {
  const config = { get: (_k: string) => undefined } as any;
  const svc = new BlockchainService(config);
  (svc as any).wallet = { address: "0x" + "99".repeat(20) };
  (svc as any).provider = {
    getFeeData: async () => ({ maxFeePerGas: 10n, maxPriorityFeePerGas: 2n }),
  };
  return svc;
}

/**
 * Install a mock contract on `svc` (via the `buildContract` seam) whose `method` has a `.staticCall`
 * that throws/resolves and whose plain call returns a tx with `receipt`. Returns the send spy.
 */
function installMockContract(
  svc: BlockchainService,
  method: string,
  opts: { staticReverts?: boolean; receipt?: any } = {}
): ReturnType<typeof jest.fn> {
  const receipt = opts.receipt ?? { status: 1, blockNumber: 1, logs: [] };
  const send = jest.fn(async () => ({ hash: "0xTXHASH", wait: async () => receipt }));
  (send as any).staticCall = jest.fn(async () => {
    if (opts.staticReverts) throw new Error("execution reverted: PreflightFailed");
  });
  (svc as any).buildContract = () => ({ [method]: send }) as any;
  return send;
}

describe("BlockchainService.queueSlashWithProof static-call preflight (HIGH 2)", () => {
  it("static call REVERTS → throws (preflight) and NEVER broadcasts the real tx", async () => {
    const svc = makeWriterService();
    const send = installMockContract(svc, "queueSlashWithProof", { staticReverts: true });
    await expect(svc.queueSlashWithProof(DVT_VALIDATOR, OPERATOR, 1, EPOCH, PROOF)).rejects.toThrow(
      /preflight \(staticCall\) reverted/
    );
    expect(send).not.toHaveBeenCalled(); // no gas spent — the send fn was never invoked
  });

  it("static call OK → proceeds and broadcasts the real tx (returns its hash)", async () => {
    const svc = makeWriterService();
    const send = installMockContract(svc, "queueSlashWithProof");
    const hash = await svc.queueSlashWithProof(DVT_VALIDATOR, OPERATOR, 1, EPOCH, PROOF);
    expect(hash).toBe("0xTXHASH");
    expect(send).toHaveBeenCalledTimes(1);
  });
});

describe("BlockchainService.executeSlashWithProof static-call preflight (HIGH 2)", () => {
  it("static call REVERTS → throws (preflight) and NEVER broadcasts the irreversible slash", async () => {
    const svc = makeWriterService();
    const send = installMockContract(svc, "executeWithProof", { staticReverts: true });
    await expect(
      svc.executeSlashWithProof(DVT_VALIDATOR, 7n, [], [], EPOCH, PROOF)
    ).rejects.toThrow(/preflight \(staticCall\) reverted/);
    expect(send).not.toHaveBeenCalled();
  });

  it("static call OK → proceeds and broadcasts the slash tx", async () => {
    const svc = makeWriterService();
    const send = installMockContract(svc, "executeWithProof");
    const hash = await svc.executeSlashWithProof(DVT_VALIDATOR, 7n, [], [], EPOCH, PROOF);
    expect(hash).toBe("0xTXHASH");
    expect(send).toHaveBeenCalledTimes(1);
  });
});

/**
 * AUDIT_DRY_RUN: queueSlashWithProof / executeSlashWithProof with dryRun=true must run the EXACT
 * staticCall preflight against the real contract (proving the proof is accepted) but then STOP —
 * NO real broadcast — and return DRY_RUN_TX_SENTINEL. A would-revert still throws (degrade to
 * archive), even in dry-run. dryRun=false keeps the byte-identical broadcast behavior.
 */
describe("BlockchainService dry-run (AUDIT_DRY_RUN) — queue/execute skip broadcast", () => {
  it("queue dryRun=true → staticCall IS called, real send is NOT, returns the sentinel", async () => {
    const svc = makeWriterService();
    const send = installMockContract(svc, "queueSlashWithProof");
    const hash = await svc.queueSlashWithProof(DVT_VALIDATOR, OPERATOR, 1, EPOCH, PROOF, true);
    expect(hash).toBe(DRY_RUN_TX_SENTINEL);
    // The preflight ran (proof validated against the real contract) …
    expect((send as any).staticCall).toHaveBeenCalledTimes(1);
    // … but the irreversible broadcast did NOT.
    expect(send).not.toHaveBeenCalled();
  });

  it("queue dryRun=true AND staticCall reverts → still THROWS (degrade), no send", async () => {
    const svc = makeWriterService();
    const send = installMockContract(svc, "queueSlashWithProof", { staticReverts: true });
    await expect(
      svc.queueSlashWithProof(DVT_VALIDATOR, OPERATOR, 1, EPOCH, PROOF, true)
    ).rejects.toThrow(/preflight \(staticCall\) reverted/);
    expect(send).not.toHaveBeenCalled();
  });

  it("queue dryRun=false → unchanged: send IS called, returns the real tx hash", async () => {
    const svc = makeWriterService();
    const send = installMockContract(svc, "queueSlashWithProof");
    const hash = await svc.queueSlashWithProof(DVT_VALIDATOR, OPERATOR, 1, EPOCH, PROOF, false);
    expect(hash).toBe("0xTXHASH");
    expect(send).toHaveBeenCalledTimes(1);
  });

  it("execute dryRun=true → staticCall IS called, real send is NOT, returns the sentinel", async () => {
    const svc = makeWriterService();
    const send = installMockContract(svc, "executeWithProof");
    const hash = await svc.executeSlashWithProof(DVT_VALIDATOR, 7n, [], [], EPOCH, PROOF, true);
    expect(hash).toBe(DRY_RUN_TX_SENTINEL);
    expect((send as any).staticCall).toHaveBeenCalledTimes(1);
    expect(send).not.toHaveBeenCalled();
  });

  it("execute dryRun=true AND staticCall reverts → still THROWS (degrade), no send", async () => {
    const svc = makeWriterService();
    const send = installMockContract(svc, "executeWithProof", { staticReverts: true });
    await expect(
      svc.executeSlashWithProof(DVT_VALIDATOR, 7n, [], [], EPOCH, PROOF, true)
    ).rejects.toThrow(/preflight \(staticCall\) reverted/);
    expect(send).not.toHaveBeenCalled();
  });

  it("execute dryRun=false → unchanged: send IS called, returns the real tx hash", async () => {
    const svc = makeWriterService();
    const send = installMockContract(svc, "executeWithProof");
    const hash = await svc.executeSlashWithProof(DVT_VALIDATOR, 7n, [], [], EPOCH, PROOF, false);
    expect(hash).toBe("0xTXHASH");
    expect(send).toHaveBeenCalledTimes(1);
  });

  it("the sentinel is NOT a valid 0x-hex-32 tx hash (never mistakable for a real one)", () => {
    expect(DRY_RUN_TX_SENTINEL).not.toMatch(/^0x[0-9a-fA-F]{64}$/);
  });
});

/**
 * MEDIUM 3 (Codex): createProposalWithEvidence must accept a ProposalCreated log ONLY when it was
 * emitted BY the DVTValidator it called AND its args match this proposal's operator + level.
 * A log from a different address, operator, or level must be IGNORED (proposalId → null), so the
 * evidence is never bound to someone else's proposal id.
 */
const PC_IFACE = new ethers.Interface([
  "event ProposalCreated(uint256 indexed id, address indexed operator, uint8 level)",
]);

function proposalCreatedLog(address: string, id: bigint, operator: string, level: number) {
  const e = PC_IFACE.encodeEventLog("ProposalCreated", [id, operator, level]);
  return { address, topics: e.topics, data: e.data };
}

/** Install a mock contract on `svc` whose createProposal returns a tx whose receipt carries `logs`. */
function installCreateContract(svc: BlockchainService, logs: any[]): void {
  const send = jest.fn(async () => ({
    hash: "0xPROP",
    wait: async () => ({ status: 1, blockNumber: 1, logs }),
  }));
  (svc as any).buildContract = () => ({ createProposal: send }) as any;
}

describe("BlockchainService.createProposalWithEvidence ProposalCreated verification (MEDIUM 3)", () => {
  const EVIDENCE = "0x" + "cd".repeat(32);

  it("accepts a ProposalCreated from the SAME validator with matching operator + level", async () => {
    const svc = makeWriterService();
    installCreateContract(svc, [proposalCreatedLog(DVT_VALIDATOR, 42n, OPERATOR, 1)]);
    const res = await svc.createProposalWithEvidence(
      DVT_VALIDATOR,
      OPERATOR,
      1,
      "reason",
      EVIDENCE
    );
    expect(res.proposalId).toBe(42n);
  });

  it("IGNORES a ProposalCreated emitted by a DIFFERENT contract address → proposalId null", async () => {
    const svc = makeWriterService();
    installCreateContract(svc, [proposalCreatedLog("0x" + "55".repeat(20), 42n, OPERATOR, 1)]);
    const res = await svc.createProposalWithEvidence(
      DVT_VALIDATOR,
      OPERATOR,
      1,
      "reason",
      EVIDENCE
    );
    expect(res.proposalId).toBeNull();
  });

  it("IGNORES a ProposalCreated for a DIFFERENT operator → proposalId null", async () => {
    const svc = makeWriterService();
    installCreateContract(svc, [proposalCreatedLog(DVT_VALIDATOR, 42n, OTHER_OPERATOR, 1)]);
    const res = await svc.createProposalWithEvidence(
      DVT_VALIDATOR,
      OPERATOR,
      1,
      "reason",
      EVIDENCE
    );
    expect(res.proposalId).toBeNull();
  });

  it("IGNORES a ProposalCreated for a DIFFERENT level → proposalId null", async () => {
    const svc = makeWriterService();
    installCreateContract(svc, [proposalCreatedLog(DVT_VALIDATOR, 42n, OPERATOR, 2)]);
    const res = await svc.createProposalWithEvidence(
      DVT_VALIDATOR,
      OPERATOR,
      1,
      "reason",
      EVIDENCE
    );
    expect(res.proposalId).toBeNull();
  });
});

/**
 * FINDING 1: getSlotForValidator scans slots 1..maxSlots for the one bound to an operator EOA. The
 * scan is now parallelized (Promise.all over getValidatorAtSlot) and must still return the LOWEST
 * matching slot, and null when the operator holds no slot or the address is malformed.
 */
describe("BlockchainService.getSlotForValidator (finding-1 parallel scan)", () => {
  const BLS_AGG = ethers.getAddress("0x" + "aa".repeat(20));

  /** A service whose getValidatorAtSlot resolves from a slot→address map (counting reads). */
  function makeSlotService(slotMap: Record<number, string>): {
    svc: BlockchainService;
    reads: () => number;
  } {
    const config = { get: (_k: string) => undefined } as any;
    const svc = new BlockchainService(config);
    let reads = 0;
    (svc as any).getValidatorAtSlot = async (
      _addr: string,
      slot: number
    ): Promise<string | null> => {
      reads++;
      return slotMap[slot] ?? null;
    };
    return { svc, reads: () => reads };
  }

  it("returns the correct 1-indexed slot when the operator is registered", async () => {
    const operator = ethers.getAddress("0x" + "12".repeat(20));
    const { svc } = makeSlotService({ 3: operator });
    expect(await svc.getSlotForValidator(BLS_AGG, operator, 13)).toBe(3);
  });

  it("returns null when the operator holds NO slot", async () => {
    const operator = ethers.getAddress("0x" + "12".repeat(20));
    const { svc } = makeSlotService({ 1: ethers.getAddress("0x" + "34".repeat(20)) });
    expect(await svc.getSlotForValidator(BLS_AGG, operator, 13)).toBeNull();
  });

  it("returns null for a malformed operator address (never scans)", async () => {
    const { svc, reads } = makeSlotService({ 1: ethers.getAddress("0x" + "12".repeat(20)) });
    expect(await svc.getSlotForValidator(BLS_AGG, "not-an-address", 13)).toBeNull();
    expect(reads()).toBe(0);
  });

  it("returns the LOWEST matching slot when the operator appears at multiple slots", async () => {
    const operator = ethers.getAddress("0x" + "12".repeat(20));
    const { svc } = makeSlotService({ 2: operator, 5: operator });
    expect(await svc.getSlotForValidator(BLS_AGG, operator, 13)).toBe(2);
  });

  it("scans every slot exactly once (parallel Promise.all over 1..maxSlots)", async () => {
    const operator = ethers.getAddress("0x" + "12".repeat(20));
    const { svc, reads } = makeSlotService({ 4: operator });
    expect(await svc.getSlotForValidator(BLS_AGG, operator, 7)).toBe(4);
    expect(reads()).toBe(7); // all 7 slots issued (parallel), none skipped
  });
});

/**
 * FINDING 3: getRegisteredSlot resolves a node's OWN slot in ONE getBLSPublicKey(operatorEoa) read
 * (the on-chain call returns the validator's slot + isActive directly) — no 1..maxSlots scan.
 * Returns the slot when ACTIVE and >= 1; null when inactive/unregistered, out of range, malformed,
 * or the read reverts.
 */
describe("BlockchainService.getRegisteredSlot (finding-3 O(1) own-slot)", () => {
  const BLS_AGG = ethers.getAddress("0x" + "aa".repeat(20));
  const OP = ethers.getAddress("0x" + "12".repeat(20));
  const CODER = ethers.AbiCoder.defaultAbiCoder();
  const RET = ["tuple(bytes32,bytes32,bytes32,bytes32)", "uint8", "bool"];
  const PK = [
    "0x" + "11".repeat(32),
    "0x" + "22".repeat(32),
    "0x" + "33".repeat(32),
    "0x" + "44".repeat(32),
  ];

  /** A service whose provider.call returns an ABI-encoded getBLSPublicKey tuple (or throws). */
  function makeService(call: () => Promise<string>): BlockchainService {
    const config = { get: (_k: string) => undefined } as any;
    const svc = new BlockchainService(config);
    (svc as any).provider = { call };
    return svc;
  }

  it("returns the 1-indexed slot for an ACTIVE registered validator (one read)", async () => {
    let calls = 0;
    const svc = makeService(async () => {
      calls++;
      return CODER.encode(RET, [PK, 5, true]);
    });
    expect(await svc.getRegisteredSlot(BLS_AGG, OP)).toBe(5);
    expect(calls).toBe(1); // O(1): a single getBLSPublicKey read, no slot scan
  });

  it("returns null when the validator is INACTIVE (revoked)", async () => {
    const svc = makeService(async () => CODER.encode(RET, [PK, 5, false]));
    expect(await svc.getRegisteredSlot(BLS_AGG, OP)).toBeNull();
  });

  it("returns null when the returned slot is 0 (unregistered / no slot)", async () => {
    const svc = makeService(async () => CODER.encode(RET, [PK, 0, true]));
    expect(await svc.getRegisteredSlot(BLS_AGG, OP)).toBeNull();
  });

  it("returns null when the on-chain read reverts (fail-closed)", async () => {
    const svc = makeService(async () => {
      throw new Error("execution reverted");
    });
    expect(await svc.getRegisteredSlot(BLS_AGG, OP)).toBeNull();
  });

  it("returns null for a malformed operator EOA WITHOUT any read", async () => {
    let calls = 0;
    const svc = makeService(async () => {
      calls++;
      return CODER.encode(RET, [PK, 5, true]);
    });
    expect(await svc.getRegisteredSlot(BLS_AGG, "not-an-address")).toBeNull();
    expect(calls).toBe(0);
  });
});
