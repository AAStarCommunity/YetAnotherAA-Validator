import { ethers } from "ethers";
import { buildGuardianSignerRecord, WatcherRecordError } from "./guardian-slash-watcher.core.js";
import {
  VERIFY_AND_EXECUTE_ABI,
  EXECUTE_WITH_PROOF_ABI,
  DVT_PROPOSALS_ABI,
  rawSlashMessageHash,
  computeSignersCommitment,
} from "./guardian-fraud-proof.js";
import type { BlsConsensusDomain } from "./bls-consensus-domain.js";

// blockhash(executionBlock - 1) in the fixtures (#441).
const PARENT = "0x" + "5a".repeat(32);
const coder = ethers.AbiCoder.defaultAbiCoder();

const S1 = ethers.getAddress("0x0000000000000000000000000000000000001111");
const S2 = ethers.getAddress("0x0000000000000000000000000000000000002222");
const S3 = ethers.getAddress("0x0000000000000000000000000000000000003333");
const OPERATOR = ethers.getAddress("0x000000000000000000000000000000000000abcd");
const AGG = ethers.getAddress("0x0000000000000000000000000000000000000a99");
const REG = ethers.getAddress("0x00000000000000000000000000000000000000b5");

const CHAIN_ID = 11155111n;
const DOMAIN: BlsConsensusDomain = { chainId: CHAIN_ID, aggregator: AGG, registry: REG };
const PID = 42n;
const LEVEL = 2;
const EPOCH = 1000n;
const MASK = 0x7n; // slots 1,2,3
const EVIDENCE = ethers.keccak256(ethers.toUtf8Bytes("disputed-over-issue-evidence"));
const EXEC_BLOCK = 500;
const blockHashAt = (n: number): string =>
  n === EXEC_BLOCK - 1 ? PARENT : ethers.keccak256(ethers.toBeHex(n, 32));
const TX_HASH = "0x" + "ab".repeat(32);

/**
 * Minimal ethers v6 provider/runner: `call` dispatches the two aggregator view reads by selector;
 * getTransaction/getBlock return the fixtures. Enough for buildGuardianSignerRecord + the
 * Contract reads it drives (validatorAtSlot, proposalSignersCommitment).
 */
class MockProvider {
  private readonly reads = new ethers.Interface([
    "function validatorAtSlot(uint8 slot) view returns (address)",
    "function proposalSignersCommitment(uint256 proposalId) view returns (bytes32)",
  ]);
  constructor(
    private readonly validators: Record<number, string>,
    private readonly commitments: Record<string, string>,
    private readonly txData: string
  ) {}

  get provider(): this {
    return this;
  }

  async resolveName(name: string): Promise<string> {
    return name;
  }

  async call(tx: { data: string }): Promise<string> {
    const sel = tx.data.slice(0, 10);
    if (sel === this.reads.getFunction("validatorAtSlot")!.selector) {
      const [slot] = this.reads.decodeFunctionData("validatorAtSlot", tx.data);
      const addr = this.validators[Number(slot)] ?? ethers.ZeroAddress;
      return this.reads.encodeFunctionResult("validatorAtSlot", [addr]);
    }
    if (sel === this.reads.getFunction("proposalSignersCommitment")!.selector) {
      const [pid] = this.reads.decodeFunctionData("proposalSignersCommitment", tx.data);
      const c = this.commitments[pid.toString()] ?? ethers.ZeroHash;
      return this.reads.encodeFunctionResult("proposalSignersCommitment", [c]);
    }
    throw new Error(`unexpected call selector ${sel}`);
  }

  async getTransaction(_hash: string): Promise<{ to: string; data: string }> {
    return { to: AGG, data: this.txData }; // a direct call to the aggregator
  }

  // Block-sensitive (clestons #468): only the execution block's parent carries PARENT, so a read of
  // any other block (e.g. getBlock(executionBlock)) yields a commitment that does not match.
  async getBlock(n: number): Promise<{ timestamp: number; hash: string }> {
    return { timestamp: 1_700_000_000, hash: blockHashAt(n) };
  }
}

function verifyAndExecuteCalldata(evidenceHash = EVIDENCE): string {
  const iface = new ethers.Interface([VERIFY_AND_EXECUTE_ABI]);
  const blsProof = coder.encode(["uint256", "bytes"], [MASK, "0xdead"]);
  return iface.encodeFunctionData("verifyAndExecute", [
    PID,
    OPERATOR,
    LEVEL,
    [],
    [],
    EPOCH,
    evidenceHash,
    blsProof,
  ]);
}

/** The commitment SP would store for this slash (what the watcher must reproduce). */
function correctCommitment(): string {
  const mh = rawSlashMessageHash(DOMAIN, PID, OPERATOR, LEVEL, EPOCH, EVIDENCE);
  return computeSignersCommitment(DOMAIN, PID, mh, MASK, [S1, S2, S3], PARENT);
}

describe("buildGuardianSignerRecord (CC-89 stage-2 watcher core)", () => {
  // Scrambled slot→address map to prove the ascending sort (slots 1,2,3 → S3,S1,S2 → sorted S1,S2,S3).
  const validators: Record<number, string> = { 1: S3, 2: S1, 3: S2 };

  it("captures the signer set and self-verifies against the on-chain commitment", async () => {
    const provider = new MockProvider(
      validators,
      { [PID.toString()]: correctCommitment() },
      verifyAndExecuteCalldata()
    );
    const rec = await buildGuardianSignerRecord(
      provider as unknown as ethers.Provider,
      AGG,
      REG,
      CHAIN_ID,
      PID,
      TX_HASH,
      EXEC_BLOCK
    );
    expect(rec.claimedSigners).toEqual([S1, S2, S3]); // sorted ascending
    expect(rec.commitmentVerified).toBe(true);
    expect(rec.operator).toBe(OPERATOR);
    expect(rec.epoch).toBe(EPOCH.toString());
    expect(rec.evidenceHash).toBe(EVIDENCE);
    expect(rec.signerMask).toBe(MASK.toString());
    expect(rec.executionBlock).toBe(EXEC_BLOCK);
    expect(rec.commitment).toBe(correctCommitment());
  });

  it("records but flags commitmentVerified=false when there is no on-chain commitment", async () => {
    const provider = new MockProvider(validators, {}, verifyAndExecuteCalldata());
    const rec = await buildGuardianSignerRecord(
      provider as unknown as ethers.Provider,
      AGG,
      REG,
      CHAIN_ID,
      PID,
      TX_HASH,
      EXEC_BLOCK
    );
    expect(rec.commitmentVerified).toBe(false);
    expect(rec.commitment).toBe(ethers.ZeroHash);
  });

  it("flags commitmentVerified=false when the on-chain commitment doesn't match (byte drift)", async () => {
    const provider = new MockProvider(
      validators,
      { [PID.toString()]: "0x" + "cd".repeat(32) },
      verifyAndExecuteCalldata()
    );
    const rec = await buildGuardianSignerRecord(
      provider as unknown as ethers.Provider,
      AGG,
      REG,
      CHAIN_ID,
      PID,
      TX_HASH,
      EXEC_BLOCK
    );
    expect(rec.commitmentVerified).toBe(false);
  });

  it("throws when the event proposalId doesn't match the calldata (won't misattribute)", async () => {
    const provider = new MockProvider(
      validators,
      { [PID.toString()]: correctCommitment() },
      verifyAndExecuteCalldata()
    );
    await expect(
      buildGuardianSignerRecord(
        provider as unknown as ethers.Provider,
        AGG,
        REG,
        CHAIN_ID,
        99n, // event says 99, calldata says 42
        TX_HASH,
        EXEC_BLOCK
      )
    ).rejects.toThrow(WatcherRecordError);
  });

  it("throws when a selected slot is a hole (never records a partial set)", async () => {
    const provider = new MockProvider(
      { 1: S3, 2: S1 }, // slot 3 missing → mask 0x7 selects a zero slot
      { [PID.toString()]: correctCommitment() },
      verifyAndExecuteCalldata()
    );
    await expect(
      buildGuardianSignerRecord(
        provider as unknown as ethers.Provider,
        AGG,
        REG,
        CHAIN_ID,
        PID,
        TX_HASH,
        EXEC_BLOCK
      )
    ).rejects.toThrow();
  });
});

// ---- the NORMAL path: DVTValidator.executeWithProof wrapping verifyAndExecute (Daybreak on #441, High)
const DVT = ethers.getAddress("0x0000000000000000000000000000000000000d07");

/** Provider for a tx sent to the DVTValidator: aggregator reads plus DVTValidator.proposals(id). */
class WrapperProvider {
  private readonly aggReads = new ethers.Interface([
    "function validatorAtSlot(uint8 slot) view returns (address)",
    "function proposalSignersCommitment(uint256 proposalId) view returns (bytes32)",
    "function DVT_VALIDATOR() view returns (address)",
  ]);
  private readonly dvtReads = new ethers.Interface([DVT_PROPOSALS_ABI]);
  constructor(
    private readonly validators: Record<number, string>,
    private readonly commitment: string,
    private readonly txTo: string,
    private readonly txData: string,
    private readonly proposal: { executed: boolean; exists: boolean }
  ) {}
  get provider(): this {
    return this;
  }
  async resolveName(name: string): Promise<string> {
    return name;
  }
  async call(tx: { to: string; data: string; blockTag?: unknown }): Promise<string> {
    const sel = tx.data.slice(0, 10);
    // Historical reads (Codex): at any block but the execution block the chain says something else,
    // so a read that drifted to "latest" gives a wrong DVT and a wrong proposal, and the test fails.
    const atExec = tx.blockTag !== undefined && Number(tx.blockTag) === EXEC_BLOCK;
    if (ethers.getAddress(tx.to) === DVT) {
      if (sel === this.dvtReads.getFunction("proposals")!.selector) {
        const [id] = this.dvtReads.decodeFunctionData("proposals", tx.data);
        if (BigInt(id) !== PID) throw new Error(`proposals(${id}) read, not the event's ${PID}`);
        return this.dvtReads.encodeFunctionResult(
          "proposals",
          atExec
            ? [
                OPERATOR,
                LEVEL,
                "over-issue",
                this.proposal.executed,
                this.proposal.exists,
                EVIDENCE,
              ]
            : [S1, 1, "a later re-proposal", false, true, ethers.ZeroHash]
        );
      }
      throw new Error(`unexpected DVT selector ${sel}`);
    }
    if (sel === this.aggReads.getFunction("DVT_VALIDATOR")!.selector)
      return this.aggReads.encodeFunctionResult("DVT_VALIDATOR", [
        atExec ? DVT : ethers.getAddress("0x0000000000000000000000000000000000000d08"),
      ]);
    if (sel === this.aggReads.getFunction("validatorAtSlot")!.selector) {
      const [slot] = this.aggReads.decodeFunctionData("validatorAtSlot", tx.data);
      return this.aggReads.encodeFunctionResult("validatorAtSlot", [
        this.validators[Number(slot)] ?? ethers.ZeroAddress,
      ]);
    }
    if (sel === this.aggReads.getFunction("proposalSignersCommitment")!.selector)
      return this.aggReads.encodeFunctionResult("proposalSignersCommitment", [this.commitment]);
    throw new Error(`unexpected aggregator selector ${sel}`);
  }
  async getTransaction(_h: string): Promise<{ to: string; data: string }> {
    return { to: this.txTo, data: this.txData };
  }
  // Block-sensitive (clestons #468): only the execution block's parent carries PARENT, so a read of
  // any other block (e.g. getBlock(executionBlock)) yields a commitment that does not match.
  async getBlock(n: number): Promise<{ timestamp: number; hash: string }> {
    return { timestamp: 1_700_000_000, hash: blockHashAt(n) };
  }
}

function executeWithProofCalldata(): string {
  const iface = new ethers.Interface([EXECUTE_WITH_PROOF_ABI]);
  const blsProof = coder.encode(["uint256", "bytes"], [MASK, "0xdead"]);
  // evidence bytes are DVTValidator's to check; the aggregator sees p.evidenceHash
  return iface.encodeFunctionData("executeWithProof", [PID, [], [], EPOCH, "0x1234", blsProof]);
}

describe("buildGuardianSignerRecord on DVTValidator.executeWithProof (the normal path)", () => {
  const validators: Record<number, string> = { 1: S3, 2: S1, 3: S2 };
  const build = (p: WrapperProvider) =>
    buildGuardianSignerRecord(
      p as unknown as ethers.Provider,
      AGG,
      REG,
      CHAIN_ID,
      PID,
      TX_HASH,
      EXEC_BLOCK
    );

  it("recovers operator, level and evidenceHash from proposals(id) and self-verifies the commitment", async () => {
    const rec = await build(
      new WrapperProvider(validators, correctCommitment(), DVT, executeWithProofCalldata(), {
        executed: true,
        exists: true,
      })
    );
    expect(rec.commitmentVerified).toBe(true);
    expect(rec.operator).toBe(OPERATOR);
    expect(rec.slashLevel).toBe(LEVEL);
    expect(rec.evidenceHash).toBe(EVIDENCE);
    expect(rec.claimedSigners).toEqual([S1, S2, S3]);
  });

  it("REFUSES a tx to neither the aggregator nor its DVTValidator", async () => {
    const other = ethers.getAddress("0x0000000000000000000000000000000000000e0e");
    await expect(
      build(
        new WrapperProvider(validators, correctCommitment(), other, executeWithProofCalldata(), {
          executed: true,
          exists: true,
        })
      )
    ).rejects.toThrow(/neither the aggregator nor its DVTValidator/);
  });

  it("REFUSES a DVTValidator proposal that is not executed at the execution block", async () => {
    await expect(
      build(
        new WrapperProvider(validators, correctCommitment(), DVT, executeWithProofCalldata(), {
          executed: false,
          exists: true,
        })
      )
    ).rejects.toThrow(WatcherRecordError);
  });

  it("REFUSES a proposal that does not exist at the execution block", async () => {
    await expect(
      build(
        new WrapperProvider(validators, correctCommitment(), DVT, executeWithProofCalldata(), {
          executed: true,
          exists: false,
        })
      )
    ).rejects.toThrow(/not an executed proposal/);
  });

  it("REFUSES when the event's proposalId differs from the wrapper calldata's", async () => {
    await expect(
      buildGuardianSignerRecord(
        new WrapperProvider(validators, correctCommitment(), DVT, executeWithProofCalldata(), {
          executed: true,
          exists: true,
        }) as unknown as ethers.Provider,
        AGG,
        REG,
        CHAIN_ID,
        PID + 1n,
        TX_HASH,
        EXEC_BLOCK
      )
    ).rejects.toThrow(/proposalId mismatch|not the event/);
  });

  it("REFUSES verifyAndExecute calldata sent to the DVTValidator (it is not executeWithProof)", async () => {
    await expect(
      build(
        new WrapperProvider(validators, correctCommitment(), DVT, verifyAndExecuteCalldata(), {
          executed: true,
          exists: true,
        })
      )
    ).rejects.toThrow(/not an executeWithProof call/);
  });
});
