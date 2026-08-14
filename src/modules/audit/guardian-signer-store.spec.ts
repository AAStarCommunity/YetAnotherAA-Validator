import { promises as fs } from "fs";
import * as os from "os";
import * as path from "path";
import {
  LocalGuardianSignerStore,
  GuardianSignerRecord,
  GuardianCaptureFailure,
} from "./guardian-signer-store.js";

const makeRecord = (proposalId: string, verified = true): GuardianSignerRecord => ({
  proposalId,
  operator: "0x000000000000000000000000000000000000abcd",
  slashLevel: 2,
  epoch: "1000",
  evidenceHash: "0x" + "11".repeat(32),
  signerMask: "7",
  claimedSigners: [
    "0x0000000000000000000000000000000000001111",
    "0x0000000000000000000000000000000000002222",
  ],
  executionBlock: 500,
  txHash: "0x" + "ab".repeat(32),
  chainId: "11155111",
  commitment: "0x" + "22".repeat(32),
  commitmentVerified: verified,
  executionBlockTimestamp: 1_700_000_000,
});

const makeFailure = (block: number, logIndex: number): GuardianCaptureFailure => ({
  block,
  logIndex,
  txHash: "0x" + "cd".repeat(32),
  proposalId: "77",
  reason: "tx not found",
  attempts: 1,
  parked: false,
});

describe("LocalGuardianSignerStore (CC-89 stage-2 data availability)", () => {
  let dir: string;
  let store: LocalGuardianSignerStore;

  beforeEach(async () => {
    dir = await fs.mkdtemp(path.join(os.tmpdir(), "guardian-store-"));
    store = new LocalGuardianSignerStore(dir);
  });

  afterEach(async () => {
    await fs.rm(dir, { recursive: true, force: true });
  });

  it("putVerified → hasTerminal → getVerified round-trips a canonical record", async () => {
    const rec = makeRecord("42");
    await store.putVerified(rec);
    expect(await store.hasTerminal(42n)).toBe(true);
    expect(await store.getVerified(42n)).toEqual(rec);
  });

  it("hasTerminal/getVerified are false/null for an unknown proposalId", async () => {
    expect(await store.hasTerminal(999n)).toBe(false);
    expect(await store.getVerified(999n)).toBeNull();
  });

  it("quarantined (unverified) records are hasTerminal but NOT readable as verified", async () => {
    const rec = makeRecord("13", false);
    await store.putUnverified(rec);
    expect(await store.hasTerminal(13n)).toBe(true); // won't be re-scanned
    expect(await store.getVerified(13n)).toBeNull(); // assembler must never read it as canonical
  });

  it("count reflects only canonical verified records (ignores quarantine + cursor)", async () => {
    await store.putVerified(makeRecord("1"));
    await store.putVerified(makeRecord("2"));
    await store.putUnverified(makeRecord("3", false));
    await store.writeCursor(123);
    expect(await store.count()).toBe(2);
  });

  it("cursor round-trips and survives re-instantiation (restart-safe)", async () => {
    expect(await store.readCursor()).toBeNull();
    await store.writeCursor(8_888_888);
    expect(await store.readCursor()).toBe(8_888_888);
    const reopened = new LocalGuardianSignerStore(dir);
    expect(await reopened.readCursor()).toBe(8_888_888);
  });

  it("putVerified is idempotent — re-putting overwrites, count stays 1", async () => {
    await store.putVerified(makeRecord("7"));
    await store.putVerified({ ...makeRecord("7"), executionBlock: 501 });
    expect(await store.count()).toBe(1);
    expect((await store.getVerified(7n))?.executionBlock).toBe(501);
  });

  describe("dead-letter (capture failures)", () => {
    it("put/list/remove round-trips a failure keyed by block+logIndex", async () => {
      await store.putFailure(makeFailure(500, 2));
      await store.putFailure(makeFailure(501, 0));
      let failures = await store.listFailures();
      expect(failures).toHaveLength(2);

      await store.removeFailure(500, 2);
      failures = await store.listFailures();
      expect(failures).toHaveLength(1);
      expect(failures[0].block).toBe(501);
    });

    it("putFailure is idempotent on the same block+logIndex (last write wins)", async () => {
      await store.putFailure(makeFailure(500, 2));
      await store.putFailure({ ...makeFailure(500, 2), attempts: 5, parked: true });
      const failures = await store.listFailures();
      expect(failures).toHaveLength(1);
      expect(failures[0].attempts).toBe(5);
      expect(failures[0].parked).toBe(true);
    });

    it("hasFailure reflects an existing dead-letter keyed by block+logIndex", async () => {
      expect(await store.hasFailure(500, 2)).toBe(false);
      await store.putFailure(makeFailure(500, 2));
      expect(await store.hasFailure(500, 2)).toBe(true);
      expect(await store.hasFailure(500, 3)).toBe(false);
    });

    it("listFailures is empty when there is no failed dir", async () => {
      expect(await store.listFailures()).toEqual([]);
    });

    it("recovers a CORRUPT dead-letter from its filename as a parked entry (not silently lost)", async () => {
      await store.putFailure(makeFailure(500, 2));
      // Corrupt the file on disk (truncated/garbage JSON).
      await fs.writeFile(path.join(dir, "failed", "500-2.json"), "{not json", "utf8");
      const failures = await store.listFailures();
      expect(failures).toHaveLength(1);
      expect(failures[0].block).toBe(500);
      expect(failures[0].logIndex).toBe(2);
      expect(failures[0].parked).toBe(true);
      expect(failures[0].reason).toMatch(/corrupt/);
    });

    it("dead-letters do not count toward canonical records", async () => {
      await store.putFailure(makeFailure(500, 2));
      expect(await store.count()).toBe(0);
    });
  });
});
