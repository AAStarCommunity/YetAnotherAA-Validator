import { promises as fs } from "fs";
import * as os from "os";
import * as path from "path";
import { ethers } from "ethers";
import { GuardianSlashWatcherService } from "./guardian-slash-watcher.service.js";
import { LocalGuardianSignerStore } from "./guardian-signer-store.js";
import {
  VERIFY_AND_EXECUTE_ABI,
  rawSlashMessageHash,
  computeSignersCommitment,
} from "./guardian-fraud-proof.js";
import type { BlsConsensusDomain } from "./bls-consensus-domain.js";
import { domainSeparator } from "./bls-consensus-domain.js";
import { SLASH_EXECUTED_EVENT } from "./guardian-slash-watcher.core.js";

const coder = ethers.AbiCoder.defaultAbiCoder();
const S1 = ethers.getAddress("0x0000000000000000000000000000000000001111");
const S2 = ethers.getAddress("0x0000000000000000000000000000000000002222");
const S3 = ethers.getAddress("0x0000000000000000000000000000000000003333");
const OPERATOR = ethers.getAddress("0x000000000000000000000000000000000000abcd");
const AGG = ethers.getAddress("0x0000000000000000000000000000000000000a99");
const REG = ethers.getAddress("0x00000000000000000000000000000000000000b5");
const CHAIN_ID = 11155111n;
const DOMAIN: BlsConsensusDomain = { chainId: CHAIN_ID, aggregator: AGG, registry: REG };
const MASK = 0x7n;
const EPOCH = 1000n;
const LEVEL = 2;
const EVIDENCE = ethers.keccak256(ethers.toUtf8Bytes("ev"));
const TOPIC = new ethers.Interface([SLASH_EXECUTED_EVENT]).getEvent("SlashExecuted")!.topicHash;

const va = new ethers.Interface([
  "function validatorAtSlot(uint8 slot) view returns (address)",
  "function proposalSignersCommitment(uint256 proposalId) view returns (bytes32)",
  "function REGISTRY() view returns (address)",
  "function domainSeparator() view returns (bytes32)",
]);

/** A bootstrap provider whose aggregator answers all four probe reads. `domSepOverride` forges a
 *  mismatching on-chain domainSeparator to exercise the fail-closed attestation. */
function bootProvider(domSepOverride?: string): any {
  return {
    getCode: async () => "0x60006000fd",
    getNetwork: async () => ({ chainId: CHAIN_ID }),
    call: async (tx: { data: string }) => {
      const sel = tx.data.slice(0, 10);
      if (sel === va.getFunction("validatorAtSlot")!.selector) {
        return va.encodeFunctionResult("validatorAtSlot", [ethers.ZeroAddress]);
      }
      if (sel === va.getFunction("proposalSignersCommitment")!.selector) {
        return va.encodeFunctionResult("proposalSignersCommitment", [ethers.ZeroHash]);
      }
      if (sel === va.getFunction("REGISTRY")!.selector) {
        return va.encodeFunctionResult("REGISTRY", [REG]);
      }
      if (sel === va.getFunction("domainSeparator")!.selector) {
        return va.encodeFunctionResult("domainSeparator", [
          domSepOverride ?? domainSeparator(DOMAIN),
        ]);
      }
      throw new Error(`unexpected selector ${sel}`);
    },
  };
}

function calldataFor(pid: bigint): string {
  const iface = new ethers.Interface([VERIFY_AND_EXECUTE_ABI]);
  return iface.encodeFunctionData("verifyAndExecute", [
    pid,
    OPERATOR,
    LEVEL,
    [],
    [],
    EPOCH,
    EVIDENCE,
    coder.encode(["uint256", "bytes"], [MASK, "0xdead"]),
  ]);
}
function commitmentFor(pid: bigint): string {
  const mh = rawSlashMessageHash(DOMAIN, pid, OPERATOR, LEVEL, EPOCH, EVIDENCE);
  return computeSignersCommitment(DOMAIN, pid, mh, MASK, [S1, S2, S3]);
}

interface FakeLog {
  topics: string[];
  transactionHash: string;
  blockNumber: number;
  index: number;
}

/** Mock provider: getLogs returns the configured logs; call/getTransaction dispatch on fixtures. */
class MockProvider {
  private readonly validators: Record<number, string> = { 1: S3, 2: S1, 3: S2 };
  constructor(
    private readonly head: number,
    private readonly logs: FakeLog[],
    private readonly txData: Record<string, string>, // txHash → calldata (absent → getTransaction null)
    private readonly commitments: Record<string, string> // pid → commitment (absent → ZeroHash)
  ) {}
  get provider(): this {
    return this;
  }
  async resolveName(n: string): Promise<string> {
    return n;
  }
  async getBlockNumber(): Promise<number> {
    return this.head;
  }
  async getLogs(): Promise<FakeLog[]> {
    return this.logs;
  }
  async getBlock(): Promise<{ timestamp: number }> {
    return { timestamp: 1_700_000_000 };
  }
  async getTransaction(hash: string): Promise<{ data: string } | null> {
    return this.txData[hash] ? { data: this.txData[hash] } : null;
  }
  async call(tx: { data: string }): Promise<string> {
    const sel = tx.data.slice(0, 10);
    if (sel === va.getFunction("validatorAtSlot")!.selector) {
      const [slot] = va.decodeFunctionData("validatorAtSlot", tx.data);
      return va.encodeFunctionResult("validatorAtSlot", [
        this.validators[Number(slot)] ?? ethers.ZeroAddress,
      ]);
    }
    const [pid] = va.decodeFunctionData("proposalSignersCommitment", tx.data);
    return va.encodeFunctionResult("proposalSignersCommitment", [
      this.commitments[pid.toString()] ?? ethers.ZeroHash,
    ]);
  }
}

/** Build a service with internals wired to a mock provider + a real temp-dir store. */
function makeService(store: LocalGuardianSignerStore, provider: MockProvider) {
  const svc = new GuardianSlashWatcherService(undefined, undefined, store);
  // Bypass bootstrap (no live RPC): set the fields tick() reads.
  (svc as any).provider = provider;
  (svc as any).chainId = CHAIN_ID;
  (svc as any).aggregatorAddress = AGG;
  (svc as any).registryAddress = REG;
  (svc as any).slashExecutedTopic = TOPIC;
  (svc as any).fromBlock = 0;
  (svc as any).finalityConfirmations = 0;
  (svc as any).logChunk = 10_000;
  return svc;
}

const logFor = (pid: bigint, tx: string, block: number, index: number): FakeLog => ({
  topics: [TOPIC, ethers.zeroPadValue(ethers.toBeHex(pid), 32)],
  transactionHash: tx,
  blockNumber: block,
  index,
});

describe("GuardianSlashWatcherService (CC-89 stage-2 durability)", () => {
  let dir: string;
  let store: LocalGuardianSignerStore;

  beforeEach(async () => {
    dir = await fs.mkdtemp(path.join(os.tmpdir(), "guardian-svc-"));
    store = new LocalGuardianSignerStore(dir);
  });
  afterEach(async () => {
    await fs.rm(dir, { recursive: true, force: true });
  });

  it("routes a matching capture to VERIFIED and advances the cursor", async () => {
    const tx = "0x" + "a1".repeat(32);
    const provider = new MockProvider(
      100,
      [logFor(42n, tx, 50, 0)],
      { [tx]: calldataFor(42n) },
      { "42": commitmentFor(42n) }
    );
    await makeService(store, provider).tick();

    const rec = await store.getVerified(42n);
    expect(rec?.claimedSigners).toEqual([S1, S2, S3]);
    expect(rec?.commitmentVerified).toBe(true);
    expect(await store.readCursor()).toBe(100); // full chunk scanned → cursor at safeHead
    expect(await store.listFailures()).toHaveLength(0);
  });

  it("QUARANTINES a commitment mismatch (never canonical) instead of trusting it", async () => {
    const tx = "0x" + "b2".repeat(32);
    const provider = new MockProvider(
      100,
      [logFor(43n, tx, 50, 0)],
      { [tx]: calldataFor(43n) },
      { "43": "0x" + "ff".repeat(32) } // wrong commitment
    );
    await makeService(store, provider).tick();

    expect(await store.getVerified(43n)).toBeNull(); // NOT canonical
    expect(await store.hasTerminal(43n)).toBe(true); // quarantined (won't re-scan)
    expect(await store.count()).toBe(0);
  });

  it("DEAD-LETTERS an uncapturable log (tx not found) — visible, not silently lost", async () => {
    const tx = "0x" + "c3".repeat(32);
    const provider = new MockProvider(
      100,
      [logFor(44n, tx, 50, 0)],
      {}, // getTransaction returns null → build throws
      {}
    );
    await makeService(store, provider).tick();

    const failures = await store.listFailures();
    expect(failures).toHaveLength(1);
    expect(failures[0].proposalId).toBe("44");
    expect(failures[0].attempts).toBe(1);
    expect(await store.getVerified(44n)).toBeNull();
    // Cursor still advances (the failure is durably tracked + retried), not stuck.
    expect(await store.readCursor()).toBe(100);
  });

  it("retries a dead-letter and PROMOTES it once the tx becomes fetchable", async () => {
    const tx = "0x" + "d4".repeat(32);
    // First tick: tx missing → dead-letter.
    const p1 = new MockProvider(100, [logFor(45n, tx, 50, 0)], {}, {});
    await makeService(store, p1).tick();
    expect(await store.listFailures()).toHaveLength(1);

    // Second tick: tx now available → retryFailures promotes it, dead-letter cleared.
    const p2 = new MockProvider(
      100,
      [], // cursor already advanced past block 50; promotion comes from the retry path
      { [tx]: calldataFor(45n) },
      { "45": commitmentFor(45n) }
    );
    await makeService(store, p2).tick();

    expect(await store.getVerified(45n)).not.toBeNull();
    expect(await store.listFailures()).toHaveLength(0);
  });

  it("scanRange SKIPS an already-dead-lettered log (retry loop owns it — no double-count)", async () => {
    const tx = "0x" + "f6".repeat(32);
    // Pre-seed a dead-letter for this exact log (block 50, index 0), attempts already 1.
    await store.putFailure({
      block: 50,
      logIndex: 0,
      txHash: tx,
      proposalId: "47",
      reason: "prior failure",
      attempts: 1,
      parked: false,
    });
    // Provider CAN now serve the tx — but scanRange must NOT re-process it (retry loop's job).
    const provider = new MockProvider(
      100,
      [logFor(47n, tx, 50, 0)],
      { [tx]: calldataFor(47n) },
      { "47": commitmentFor(47n) }
    );
    const svc = makeService(store, provider);
    const completed = await (svc as any).scanRange(0, 100);
    expect(completed).toBe(true);
    // Not captured by scanRange; the dead-letter is untouched (attempts still 1).
    expect(await store.getVerified(47n)).toBeNull();
    const failures = await store.listFailures();
    expect(failures).toHaveLength(1);
    expect(failures[0].attempts).toBe(1);
  });

  it("scanRange signals INCOMPLETE (false) under shutdown so the cursor never advances past it", async () => {
    const tx = "0x" + "e5".repeat(32);
    const provider = new MockProvider(
      100,
      [logFor(46n, tx, 50, 0)],
      { [tx]: calldataFor(46n) },
      { "46": commitmentFor(46n) }
    );
    const svc = makeService(store, provider);
    (svc as any).stopping = true;

    // scanRange must return false (interrupted) and capture nothing.
    const completed = await (svc as any).scanRange(0, 100);
    expect(completed).toBe(false);
    expect(await store.getVerified(46n)).toBeNull();

    // And the whole tick() early-returns under shutdown → cursor untouched.
    await svc.tick();
    expect(await store.readCursor()).toBeNull();
  });

  it("bootstrap fail-closed: aggregator answers validatorAtSlot but REVERTS proposalSignersCommitment → DISABLED", async () => {
    // Proves the watcher's bootstrap probe exercises proposalSignersCommitment INDEPENDENTLY — a
    // wrong-but-deployed contract implementing only validatorAtSlot must not start the poller.
    let sawCommitmentProbe = false;
    const bootProvider: any = {
      getCode: async () => "0x60006000fd",
      getNetwork: async () => ({ chainId: CHAIN_ID }),
      call: async (tx: { data: string }) => {
        const sel = tx.data.slice(0, 10);
        if (sel === va.getFunction("validatorAtSlot")!.selector) {
          return va.encodeFunctionResult("validatorAtSlot", [ethers.ZeroAddress]);
        }
        sawCommitmentProbe = true;
        throw new Error("execution reverted (no proposalSignersCommitment)");
      },
    };
    const svc = new GuardianSlashWatcherService(undefined, undefined, store);
    (svc as any).provider = bootProvider;
    (svc as any).aggregatorAddress = AGG;
    (svc as any).expectedChainId = Number(CHAIN_ID);
    (svc as any).aggregatorFromEnv = true;

    await (svc as any).bootstrapAndPoll();

    expect(sawCommitmentProbe).toBe(true); // the second probe method actually fired
    expect((svc as any).timer).toBeNull(); // poller NOT started (fail-closed)
    expect((svc as any).chainId).toBeNull(); // never advanced past the probe
  });

  it("bootstrap fail-closed: aggregator domainSeparator disagrees with local domain → DISABLED", async () => {
    // The aggregator answers every probe BUT reports a domainSeparator bound to a different
    // deployment. The watcher must refuse to start rather than quarantine every future capture.
    const svc = new GuardianSlashWatcherService(undefined, undefined, store);
    (svc as any).provider = bootProvider("0x" + "de".repeat(32)); // forged, non-matching
    (svc as any).aggregatorAddress = AGG;
    (svc as any).registryAddress = REG;
    (svc as any).expectedChainId = Number(CHAIN_ID);
    (svc as any).aggregatorFromEnv = true;

    await (svc as any).bootstrapAndPoll();

    expect((svc as any).timer).toBeNull(); // poller NOT started (fail-closed)
    expect((svc as any).chainId).toBeNull(); // never advanced past the attestation
  });

  it("bootstrap OK: matching on-chain domain attests → advances past the probe", async () => {
    const svc = new GuardianSlashWatcherService(undefined, undefined, store);
    (svc as any).provider = bootProvider(); // aggregator agrees with the local domain
    (svc as any).aggregatorAddress = AGG;
    (svc as any).registryAddress = REG;
    (svc as any).expectedChainId = Number(CHAIN_ID);
    (svc as any).aggregatorFromEnv = true;
    (svc as any).stopping = true; // short-circuit before tick()/timer so we isolate the attestation

    await (svc as any).bootstrapAndPoll();

    expect((svc as any).chainId).toBe(CHAIN_ID); // attestation passed → chainId advanced
    expect((svc as any).timer).toBeNull(); // stopping short-circuits the poller
  });
});
