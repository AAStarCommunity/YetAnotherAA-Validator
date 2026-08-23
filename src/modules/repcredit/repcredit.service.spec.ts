import { BadRequestException, ForbiddenException } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { RepCreditService } from "./repcredit.service.js";

function service(config: Record<string, unknown>, blockchain: Record<string, unknown> = {}) {
  const configService = { get: (key: string) => config[key] } as unknown as ConfigService;
  return new RepCreditService(configService, blockchain as any, {} as any, {} as any);
}

describe("RepCreditService opt-in gates", () => {
  it("is fail-closed by default before any RPC or signing work", async () => {
    await expect(service({}).sign({} as any)).rejects.toBeInstanceOf(ForbiddenException);
  });

  it("refuses aggregation below the BLSAggregator on-chain threshold", async () => {
    const instance = service(
      {
        repCreditExperimentSigning: true,
        repCreditBlsAggregatorAddress: "0x0000000000000000000000000000000000000001",
      },
      {
        getChainId: async () => 31337,
        getBlsDefaultThreshold: async () => 3,
      }
    );
    await expect(instance.aggregate({} as any, [], 2)).rejects.toBeInstanceOf(BadRequestException);
  });
});
