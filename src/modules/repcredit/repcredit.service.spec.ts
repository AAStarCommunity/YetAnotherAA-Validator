import { BadRequestException, ForbiddenException } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { RepCreditService } from "./repcredit.service.js";

function service(config: Record<string, unknown>, blockchain: Record<string, unknown> = {}) {
  const configService = { get: (key: string) => config[key] } as unknown as ConfigService;
  return new RepCreditService(configService, blockchain as any, {} as any, {} as any);
}

const EXPERIMENT_AGGREGATOR = "0x0000000000000000000000000000000000000001";
const PRODUCTION_AGGREGATOR = "0x00000000000000000000000000000000000000AA";

describe("RepCreditService opt-in gates", () => {
  it("is fail-closed by default before any RPC or signing work", async () => {
    await expect(service({}).sign({} as any)).rejects.toBeInstanceOf(ForbiddenException);
  });

  it("refuses aggregation below the BLSAggregator on-chain threshold", async () => {
    const instance = service(
      {
        repCreditExperimentSigning: true,
        repCreditBlsAggregatorAddress: EXPERIMENT_AGGREGATOR,
      },
      {
        getChainId: async () => 31337,
        getBlsDefaultThreshold: async () => 3,
      }
    );
    await expect(instance.aggregate({} as any, [], 2)).rejects.toBeInstanceOf(BadRequestException);
  });
});

describe("RepCreditService production-aggregator separation (CC-49 BLOCKER-1)", () => {
  const blockchain = {
    getChainId: async () => 31337,
    getBlsDefaultThreshold: async () => 1,
    getBlsSlashThreshold: async () => 1,
    getBlsPublicKeyAtSlot: async () => null,
  };

  function sameAddress(config: Record<string, unknown> = {}) {
    return service(
      {
        repCreditExperimentSigning: true,
        repCreditValidatorSlot: 1,
        repCreditBlsAggregatorAddress: PRODUCTION_AGGREGATOR,
        auditBlsAggregatorAddress: PRODUCTION_AGGREGATOR.toLowerCase(),
        ...config,
      },
      blockchain
    );
  }

  it("refuses to sign against the production audit aggregator (case-insensitive)", async () => {
    await expect(sameAddress().signSlash({ slashLevel: 1 } as any)).rejects.toBeInstanceOf(
      ForbiddenException
    );
  });

  it("refuses to aggregate against the production audit aggregator", async () => {
    await expect(
      sameAddress().aggregateSlash({ slashLevel: 1 } as any, [], 3)
    ).rejects.toBeInstanceOf(ForbiddenException);
  });

  it("allows an isolated experiment aggregator", async () => {
    const instance = sameAddress({ repCreditBlsAggregatorAddress: EXPERIMENT_AGGREGATOR });
    // Gets past the separation gate; fails later on the (unstubbed) slot binding instead.
    await expect(instance.aggregateSlash({ slashLevel: 1 } as any, [], 3)).rejects.toBeInstanceOf(
      BadRequestException
    );
  });
});

describe("RepCreditService slash threshold source (CC-49 MEDIUM-1)", () => {
  function slashService(
    slashThresholds: Record<number, number>,
    calls: { level?: number; defaultUsed?: boolean } = {}
  ) {
    return service(
      {
        repCreditExperimentSigning: true,
        repCreditBlsAggregatorAddress: EXPERIMENT_AGGREGATOR,
      },
      {
        getChainId: async () => 31337,
        getBlsDefaultThreshold: async () => {
          calls.defaultUsed = true;
          return 7;
        },
        getBlsSlashThreshold: async (_addr: string, level: number) => {
          calls.level = level;
          return slashThresholds[level];
        },
      }
    );
  }

  it("reads slashThresholds[slashLevel], not the reputation defaultThreshold", async () => {
    const calls: { level?: number; defaultUsed?: boolean } = {};
    const instance = slashService({ 0: 2, 1: 3, 2: 3 }, calls);
    // threshold 3 clears slashThresholds[MINOR]=3 but would fail defaultThreshold=7.
    await expect(instance.aggregateSlash({ slashLevel: 1 } as any, [], 3)).rejects.toBeInstanceOf(
      BadRequestException
    );
    expect(calls.level).toBe(1);
    expect(calls.defaultUsed).toBeUndefined();
  });

  it("rejects an aggregate below the severity-specific on-chain threshold", async () => {
    const instance = slashService({ 0: 2, 1: 3, 2: 3 });
    await expect(instance.aggregateSlash({ slashLevel: 2 } as any, [], 2)).rejects.toThrow(
      /below on-chain slashThresholds\[2\] 3/
    );
  });

  it("rejects a malformed slashLevel before spending an RPC read", async () => {
    const calls: { level?: number } = {};
    const instance = slashService({ 0: 2, 1: 3, 2: 3 }, calls);
    for (const slashLevel of [-1, 3, 1.5, "1", undefined]) {
      await expect(instance.aggregateSlash({ slashLevel } as any, [], 3)).rejects.toBeInstanceOf(
        BadRequestException
      );
    }
    expect(calls.level).toBeUndefined();
  });
});
