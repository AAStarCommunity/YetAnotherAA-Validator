import { checkAggregatorChainPolicy, SEPOLIA_CHAIN_ID } from "./aggregator-bootstrap-guard.js";

describe("checkAggregatorChainPolicy (CC-89 shared fail-closed guard)", () => {
  it("rejects a provider chain that differs from AUDIT_CHAIN_ID (always, regardless of required)", () => {
    const r = checkAggregatorChainPolicy({
      expectedChainId: SEPOLIA_CHAIN_ID,
      providerChainId: 1,
      aggregatorFromEnv: true,
      aggregatorRequired: false,
    });
    expect(r.ok).toBe(false);
    expect(r.reason).toContain("!= AUDIT_CHAIN_ID");
  });

  it("rejects the Sepolia default silently inherited off-Sepolia when the aggregator IS required", () => {
    const r = checkAggregatorChainPolicy({
      expectedChainId: 10, // OP-mainnet, matches provider
      providerChainId: 10,
      aggregatorFromEnv: false, // never set explicitly → would inherit the Sepolia default
      aggregatorRequired: true,
    });
    expect(r.ok).toBe(false);
    expect(r.reason).toContain("not set explicitly");
  });

  it("allows off-Sepolia when the aggregator was set explicitly", () => {
    expect(
      checkAggregatorChainPolicy({
        expectedChainId: 10,
        providerChainId: 10,
        aggregatorFromEnv: true,
        aggregatorRequired: true,
      }).ok
    ).toBe(true);
  });

  it("allows off-Sepolia with an unset aggregator when it is NOT required (chain matches)", () => {
    // e.g. the audit runs with offline disabled — the aggregator is never consumed.
    expect(
      checkAggregatorChainPolicy({
        expectedChainId: 10,
        providerChainId: 10,
        aggregatorFromEnv: false,
        aggregatorRequired: false,
      }).ok
    ).toBe(true);
  });

  it("allows the Sepolia default on Sepolia even when not set explicitly", () => {
    expect(
      checkAggregatorChainPolicy({
        expectedChainId: SEPOLIA_CHAIN_ID,
        providerChainId: SEPOLIA_CHAIN_ID,
        aggregatorFromEnv: false,
        aggregatorRequired: true,
      }).ok
    ).toBe(true);
  });
});
