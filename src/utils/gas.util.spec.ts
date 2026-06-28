import { bumpedFees } from "./gas.util.js";

function provider(fd: { maxFeePerGas: bigint | null; maxPriorityFeePerGas: bigint | null }) {
  return { getFeeData: async () => fd } as any;
}

const GWEI = 1_000_000_000n;
const FLOOR = 1_500_000_000n; // default priority floor = 1.5 gwei

describe("bumpedFees", () => {
  it("bumps the estimate by 15% by default", async () => {
    const r = await bumpedFees(
      provider({ maxFeePerGas: 4n * GWEI, maxPriorityFeePerGas: 2n * GWEI })
    );
    expect(r.maxPriorityFeePerGas).toBe((2n * GWEI * 115n) / 100n); // 2.3 gwei
    expect(r.maxFeePerGas).toBe((4n * GWEI * 115n) / 100n); // 4.6 gwei
  });

  it("honors a custom bump percent", async () => {
    const r = await bumpedFees(
      provider({ maxFeePerGas: 10n * GWEI, maxPriorityFeePerGas: 10n * GWEI }),
      50
    );
    expect(r.maxPriorityFeePerGas).toBe(15n * GWEI);
    expect(r.maxFeePerGas).toBe(15n * GWEI);
  });

  it("raises priority to the floor when the estimate is below it", async () => {
    const r = await bumpedFees(provider({ maxFeePerGas: 4n * GWEI, maxPriorityFeePerGas: 0n }));
    expect(r.maxPriorityFeePerGas).toBe(FLOOR);
    expect(r.maxFeePerGas).toBe((4n * GWEI * 115n) / 100n); // unchanged, still ≥ priority
  });

  it("derives maxFee from priority when the provider returns null fees", async () => {
    const r = await bumpedFees(provider({ maxFeePerGas: null, maxPriorityFeePerGas: null }));
    expect(r.maxPriorityFeePerGas).toBe(FLOOR);
    expect(r.maxFeePerGas).toBe(FLOOR * 2n);
  });

  it("lifts maxFee above priority if the estimate inverts them", async () => {
    // bumped priority (2.3 gwei) would exceed a tiny maxFee → maxFee = priority*2
    const r = await bumpedFees(provider({ maxFeePerGas: 1n, maxPriorityFeePerGas: 2n * GWEI }));
    expect(r.maxFeePerGas).toBe(r.maxPriorityFeePerGas * 2n);
    expect(r.maxFeePerGas).toBeGreaterThan(r.maxPriorityFeePerGas);
  });
});
