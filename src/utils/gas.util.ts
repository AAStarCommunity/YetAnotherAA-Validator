import { ethers } from "ethers";

/**
 * EIP-1559 fee override: take the provider's estimate and bump it, with a
 * priority-fee floor. Underpriced txs sit in the mempool — and for time-bound
 * txs (relay BuyIntents have a deadline, keeper updates chase a staleness
 * window) a tx that mines late is worse than useless (it reverts and still
 * burns gas). A modest bump buys timely inclusion.
 *
 * @param provider          ethers provider to read getFeeData() from
 * @param bumpPct           percent to add on top of the estimate (default 15)
 * @param priorityFloorWei  minimum maxPriorityFeePerGas (default 1.5 gwei) — RPC
 *                          estimates often suggest ~0 priority on quiet testnets,
 *                          which validators skip
 */
export async function bumpedFees(
  provider: ethers.Provider,
  bumpPct = 15,
  priorityFloorWei = 1_500_000_000n
): Promise<{ maxFeePerGas: bigint; maxPriorityFeePerGas: bigint }> {
  const fd = await provider.getFeeData();
  const bump = (x: bigint | null): bigint | null =>
    x == null ? null : (x * BigInt(100 + bumpPct)) / 100n;

  let maxPriorityFeePerGas = bump(fd.maxPriorityFeePerGas) ?? priorityFloorWei;
  if (maxPriorityFeePerGas < priorityFloorWei) maxPriorityFeePerGas = priorityFloorWei;

  let maxFeePerGas = bump(fd.maxFeePerGas);
  // If the provider gave no maxFeePerGas, or it's below the (bumped) priority,
  // derive a safe ceiling: priority covers the tip, ×2 leaves room for baseFee.
  if (maxFeePerGas == null || maxFeePerGas < maxPriorityFeePerGas) {
    maxFeePerGas = maxPriorityFeePerGas * 2n;
  }
  return { maxFeePerGas, maxPriorityFeePerGas };
}
