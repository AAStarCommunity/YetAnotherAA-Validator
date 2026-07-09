import { jest } from "@jest/globals";
import { BlockchainService } from "./blockchain.service.js";

const REGISTRY = "0x1111111111111111111111111111111111111111";
const OP = "0x2222222222222222222222222222222222222222";
const ANCHOR_HASH = "0x" + "ab".repeat(32);

function svcWithWallet(): BlockchainService {
  const config = { get: (_k: string) => undefined } as any;
  const svc = new BlockchainService(config);
  (svc as any).wallet = { address: OP };
  return svc;
}

/** Fee-data stub so bumpedFees() resolves without a real provider. */
const feeData = { maxFeePerGas: 100n, maxPriorityFeePerGas: 2n };

/** A tx whose wait(confirms, timeout) resolves/rejects as configured. */
function tx(hash: string, wait: () => Promise<any>) {
  return { hash, wait };
}

/** Install an attestLiveness contract: `staticCall` + a queue of per-attempt send behaviours. */
function installAttest(
  svc: BlockchainService,
  staticCall: () => Promise<any>,
  sends: Array<() => Promise<any>>
) {
  let i = 0;
  const attestLiveness: any = () => sends[Math.min(i++, sends.length - 1)]();
  attestLiveness.staticCall = staticCall;
  (svc as any).buildContract = () => ({ attestLiveness });
}

describe("BlockchainService.attestLiveness", () => {
  it("preflight revert (stale/bad anchor) throws BEFORE consuming a nonce", async () => {
    const svc = svcWithWallet();
    const getTransactionCount = jest.fn(async () => 5);
    (svc as any).provider = { getFeeData: async () => feeData, getTransactionCount };
    installAttest(svc, async () => {
      throw new Error("StaleAnchor");
    }, [async () => tx("0xnope", async () => ({ status: 1 }))]);
    await expect(svc.attestLiveness(REGISTRY, 984, ANCHOR_HASH)).rejects.toThrow(
      /preflight reverted/
    );
    expect(getTransactionCount).not.toHaveBeenCalled();
  });

  it("happy path: preflight ok, tx confirms status 1 → returns the tx hash", async () => {
    const svc = svcWithWallet();
    (svc as any).provider = { getFeeData: async () => feeData, getTransactionCount: async () => 5 };
    installAttest(svc, async () => undefined, [
      async () => tx("0xgood", async () => ({ status: 1 })),
    ]);
    await expect(svc.attestLiveness(REGISTRY, 984, ANCHOR_HASH)).resolves.toBe("0xgood");
  });

  it("mined-but-reverted receipt → throws not-confirmed (re-anchor next tick)", async () => {
    const svc = svcWithWallet();
    (svc as any).provider = {
      getFeeData: async () => feeData,
      getTransactionCount: async () => 5,
      getTransactionReceipt: async () => ({ status: 0 }),
    };
    installAttest(svc, async () => undefined, [
      async () => tx("0xrev", async () => ({ status: 0 })),
    ]);
    await expect(svc.attestLiveness(REGISTRY, 984, ANCHOR_HASH)).rejects.toThrow(/not confirmed/);
  });

  it("nonce dead-heat (slash grabbed it): refetches a fresh nonce and retries", async () => {
    const svc = svcWithWallet();
    const getTransactionCount = jest
      .fn<() => Promise<number>>()
      .mockResolvedValueOnce(5) // initial
      .mockResolvedValueOnce(6); // refetch after nonce-too-low
    (svc as any).provider = { getFeeData: async () => feeData, getTransactionCount };
    installAttest(svc, async () => undefined, [
      async () => {
        throw new Error("nonce too low");
      },
      async () => tx("0xafteryield", async () => ({ status: 1 })),
    ]);
    await expect(svc.attestLiveness(REGISTRY, 984, ANCHOR_HASH)).resolves.toBe("0xafteryield");
    expect(getTransactionCount).toHaveBeenCalledTimes(2); // refetched → yielded to the slash
  });

  it("both attempts time out but the FIRST later mined → reconciliation returns it", async () => {
    const svc = svcWithWallet();
    const receipts: Record<string, any> = { "0xt1": { status: 1 } };
    (svc as any).provider = {
      getFeeData: async () => feeData,
      getTransactionCount: async () => 5,
      getTransactionReceipt: async (h: string) => receipts[h] ?? null,
    };
    installAttest(svc, async () => undefined, [
      async () =>
        tx("0xt1", async () => {
          throw new Error("timeout waiting for tx");
        }),
      async () =>
        tx("0xt2", async () => {
          throw new Error("timeout waiting for tx");
        }),
    ]);
    await expect(svc.attestLiveness(REGISTRY, 984, ANCHOR_HASH)).resolves.toBe("0xt1");
  });

  it("throws without an operator wallet", async () => {
    const config = { get: (_k: string) => undefined } as any;
    const svc = new BlockchainService(config);
    await expect(svc.attestLiveness(REGISTRY, 1, ANCHOR_HASH)).rejects.toThrow(
      /no operator wallet/
    );
  });
});

describe("BlockchainService liveness reads", () => {
  it("getAttestAnchor returns head−depth block {number,hash}, floored at depth 1", async () => {
    const svc = svcWithWallet();
    const getBlock = jest.fn(async (n: number) => ({ number: n, hash: "0xh" }));
    (svc as any).provider = { getBlockNumber: async () => 1000, getBlock };
    const a = await svc.getAttestAnchor(16);
    expect(a).toEqual({ number: 984, hash: "0xh" });
    expect(getBlock).toHaveBeenCalledWith(984);
  });

  it("getAreOffline short-circuits to [] for an empty operator list (no RPC)", async () => {
    const svc = svcWithWallet();
    const areOffline = jest.fn();
    (svc as any).buildContract = () => ({ areOffline });
    (svc as any).provider = {};
    await expect(svc.getAreOffline(REGISTRY, [])).resolves.toEqual([]);
    expect(areOffline).not.toHaveBeenCalled();
  });

  it("getIsOffline reads the registry view at the pinned blockTag", async () => {
    const svc = svcWithWallet();
    const isOffline = jest.fn(async (_op: string, _opts: any) => true);
    (svc as any).provider = {};
    (svc as any).buildContract = () => ({ isOffline });
    await expect(svc.getIsOffline(REGISTRY, OP, 777)).resolves.toBe(true);
    expect(isOffline).toHaveBeenCalledWith(OP, { blockTag: 777 });
  });
});
