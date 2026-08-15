import { ethers } from "ethers";
import { buildGuardianSignerRecord, WatcherRecordError } from "./guardian-slash-watcher.core.js";
import {
  VERIFY_AND_EXECUTE_ABI,
  rawSlashMessageHash,
  computeSignersCommitment,
} from "./guardian-fraud-proof.js";

const coder = ethers.AbiCoder.defaultAbiCoder();

const S1 = ethers.getAddress("0x0000000000000000000000000000000000001111");
const S2 = ethers.getAddress("0x0000000000000000000000000000000000002222");
const S3 = ethers.getAddress("0x0000000000000000000000000000000000003333");
const OPERATOR = ethers.getAddress("0x000000000000000000000000000000000000abcd");
const AGG = ethers.getAddress("0x0000000000000000000000000000000000000a99");

const CHAIN_ID = 11155111n;
const PID = 42n;
const LEVEL = 2;
const EPOCH = 1000n;
const MASK = 0x7n; // slots 1,2,3
const EVIDENCE = ethers.keccak256(ethers.toUtf8Bytes("disputed-over-issue-evidence"));
const EXEC_BLOCK = 500;
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

  async getTransaction(_hash: string): Promise<{ data: string }> {
    return { data: this.txData };
  }

  async getBlock(_n: number): Promise<{ timestamp: number }> {
    return { timestamp: 1_700_000_000 };
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
  const mh = rawSlashMessageHash(CHAIN_ID, PID, OPERATOR, LEVEL, EPOCH, EVIDENCE);
  return computeSignersCommitment(AGG, CHAIN_ID, PID, mh, MASK, [S1, S2, S3]);
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
        CHAIN_ID,
        PID,
        TX_HASH,
        EXEC_BLOCK
      )
    ).rejects.toThrow();
  });
});
