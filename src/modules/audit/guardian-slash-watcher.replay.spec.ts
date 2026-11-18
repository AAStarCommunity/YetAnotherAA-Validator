import { readFileSync } from "fs";
import { join } from "path";
import { ethers } from "ethers";
import { buildGuardianSignerRecord, WatcherRecordError } from "./guardian-slash-watcher.core.js";
import { DVT_PROPOSALS_ABI } from "./guardian-fraud-proof.js";

/**
 * #441 (Daybreak, High): replay a REAL DVTValidator.executeWithProof transaction, recorded by the anvil
 * acceptance (deploy/rehearse-guardian-slash.mjs, SP f2b2cd9b, throwaway keys), through the watcher.
 * The normal execution path reaches the aggregator through the DVTValidator, so the watcher must
 * attribute it and reproduce the commitment the aggregator itself stored.
 */
type Fixture = {
  chainId: string;
  aggregator: string;
  registry: string;
  txHash: string;
  tx: { to: string; data: string };
  executionBlock: number;
  executionBlockTimestamp: number;
  parentBlockHash: string;
  dvtValidator: string;
  proposal: {
    id: string;
    operator: string;
    slashLevel: number;
    reason: string;
    executed: boolean;
    exists: boolean;
    evidenceHash: string;
  };
  validatorAtSlot: Record<string, string>;
  proposalSignersCommitment: string;
};
const FX: Fixture = JSON.parse(
  readFileSync(
    join(process.cwd(), "src/modules/audit/fixtures/441-wrapper-tx.f2b2cd9b.json"),
    "utf8"
  )
);

/** Answers exactly the reads the watcher makes, from the fixture; anything else throws. */
class ReplayProvider {
  private readonly agg = new ethers.Interface([
    "function validatorAtSlot(uint8 slot) view returns (address)",
    "function proposalSignersCommitment(uint256 proposalId) view returns (bytes32)",
    "function DVT_VALIDATOR() view returns (address)",
  ]);
  private readonly dvt = new ethers.Interface([DVT_PROPOSALS_ABI]);
  constructor(private readonly tx: { to: string; data: string }) {}
  get provider(): this {
    return this;
  }
  async resolveName(n: string): Promise<string> {
    return n;
  }
  async call(t: { to: string; data: string; blockTag?: unknown }): Promise<string> {
    const to = ethers.getAddress(t.to);
    const sel = t.data.slice(0, 10);
    // Only what was recorded (Codex): every read must be AT the recorded execution block.
    if (t.blockTag === undefined || Number(t.blockTag) !== FX.executionBlock)
      throw new Error(`read not at the recorded execution block (blockTag ${String(t.blockTag)})`);
    if (to === ethers.getAddress(FX.dvtValidator)) {
      if (sel !== this.dvt.getFunction("proposals")!.selector) throw new Error(`dvt ${sel}`);
      const [id] = this.dvt.decodeFunctionData("proposals", t.data);
      if (id.toString() !== FX.proposal.id) throw new Error(`unrecorded proposal ${id}`);
      const p = FX.proposal;
      return this.dvt.encodeFunctionResult("proposals", [
        p.operator,
        p.slashLevel,
        p.reason,
        p.executed,
        p.exists,
        p.evidenceHash,
      ]);
    }
    if (to !== ethers.getAddress(FX.aggregator)) throw new Error(`unexpected target ${to}`);
    if (sel === this.agg.getFunction("DVT_VALIDATOR")!.selector)
      return this.agg.encodeFunctionResult("DVT_VALIDATOR", [FX.dvtValidator]);
    if (sel === this.agg.getFunction("validatorAtSlot")!.selector) {
      const [slot] = this.agg.decodeFunctionData("validatorAtSlot", t.data);
      const v = FX.validatorAtSlot[String(slot)];
      if (v === undefined) throw new Error(`unrecorded slot ${slot}`);
      return this.agg.encodeFunctionResult("validatorAtSlot", [v]);
    }
    if (sel === this.agg.getFunction("proposalSignersCommitment")!.selector) {
      const [key] = this.agg.decodeFunctionData("proposalSignersCommitment", t.data);
      if (key.toString() !== FX.proposal.id) throw new Error(`commitment read under key ${key}`);
      return this.agg.encodeFunctionResult("proposalSignersCommitment", [
        FX.proposalSignersCommitment,
      ]);
    }
    throw new Error(`unexpected aggregator selector ${sel}`);
  }
  async getTransaction(h: string): Promise<{ to: string; data: string } | null> {
    return h === FX.txHash ? this.tx : null;
  }
  async getBlock(n: number): Promise<{ timestamp: number; hash: string } | null> {
    if (n === FX.executionBlock - 1) return { timestamp: 0, hash: FX.parentBlockHash };
    if (n === FX.executionBlock)
      return { timestamp: FX.executionBlockTimestamp, hash: ethers.ZeroHash };
    return null;
  }
}

const build = (p: ReplayProvider) =>
  buildGuardianSignerRecord(
    p as unknown as ethers.Provider,
    FX.aggregator,
    FX.registry,
    BigInt(FX.chainId),
    BigInt(FX.proposal.id),
    FX.txHash,
    FX.executionBlock
  );

describe("watcher replay of a real DVTValidator.executeWithProof tx (#441, SP f2b2cd9b)", () => {
  it("the recorded tx is a wrapper call (sent to the DVTValidator, not the aggregator)", () => {
    expect(ethers.getAddress(FX.tx.to)).toBe(ethers.getAddress(FX.dvtValidator));
    expect(ethers.getAddress(FX.tx.to)).not.toBe(ethers.getAddress(FX.aggregator));
  });

  it("produces a VERIFIED record: the recomputed commitment equals the one the aggregator stored", async () => {
    const rec = await build(new ReplayProvider(FX.tx));
    expect(rec.commitmentVerified).toBe(true);
    expect(rec.commitment).toBe(FX.proposalSignersCommitment);
    expect(rec.operator).toBe(ethers.getAddress(FX.proposal.operator));
    expect(rec.evidenceHash).toBe(FX.proposal.evidenceHash);
    expect(rec.parentBlockHash).toBe(FX.parentBlockHash);
    expect(rec.claimedSigners).toEqual(
      Object.values(FX.validatorAtSlot)
        .map(a => ethers.getAddress(a))
        .sort((a, b) => (BigInt(a) < BigInt(b) ? -1 : 1))
    );
  });

  it("the same tx re-addressed to a third contract is refused, not misattributed", async () => {
    const other = { ...FX.tx, to: "0x000000000000000000000000000000000000dEaD" };
    await expect(build(new ReplayProvider(other))).rejects.toThrow(WatcherRecordError);
  });
});
