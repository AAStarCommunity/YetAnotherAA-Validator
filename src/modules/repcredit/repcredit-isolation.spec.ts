import { checkRepCreditAggregatorPolicy } from "./repcredit-isolation.js";

const EXPERIMENT = "0x0000000000000000000000000000000000000001";
const PRODUCTION = "0x00000000000000000000000000000000000000AA";

describe("checkRepCreditAggregatorPolicy (CC-49 HIGH-A / MEDIUM-C)", () => {
  it("accepts distinct, explicitly configured aggregators", () => {
    expect(
      checkRepCreditAggregatorPolicy({
        repCreditAggregatorAddress: EXPERIMENT,
        auditAggregatorAddress: PRODUCTION,
        auditAggregatorFromEnv: true,
      })
    ).toEqual({ ok: true });
  });

  it("requires the experiment aggregator address", () => {
    const verdict = checkRepCreditAggregatorPolicy({
      auditAggregatorAddress: PRODUCTION,
      auditAggregatorFromEnv: true,
    });
    expect(verdict.ok).toBe(false);
    expect(verdict.reason).toMatch(/REPCREDIT_BLS_AGGREGATOR_ADDRESS is required/);
  });

  it("refuses to inherit the built-in Sepolia audit default", () => {
    // The resolved value is non-empty even when the env is unset, which is exactly how a
    // node on another chain would end up comparing against a foreign-chain address.
    const verdict = checkRepCreditAggregatorPolicy({
      repCreditAggregatorAddress: EXPERIMENT,
      auditAggregatorAddress: "0x174b60bB462b00550F0EC7Bc35Fe39dDB6310158",
      auditAggregatorFromEnv: false,
    });
    expect(verdict.ok).toBe(false);
    expect(verdict.reason).toMatch(/must be set EXPLICITLY/);
  });

  it("rejects an experiment pointed at the production aggregator, case-insensitively", () => {
    for (const audit of [PRODUCTION, PRODUCTION.toLowerCase(), PRODUCTION.toUpperCase()]) {
      const verdict = checkRepCreditAggregatorPolicy({
        repCreditAggregatorAddress: PRODUCTION,
        auditAggregatorAddress: audit,
        auditAggregatorFromEnv: true,
      });
      expect(verdict.ok).toBe(false);
      expect(verdict.reason).toMatch(/must not equal AUDIT_BLS_AGGREGATOR_ADDRESS/);
    }
  });
});
