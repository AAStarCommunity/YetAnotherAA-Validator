import { checkRepCreditAggregatorPolicy } from "./repcredit-isolation.js";

const EXPERIMENT = "0x0000000000000000000000000000000000000001";
const PRODUCTION = "0x00000000000000000000000000000000000000AA";
const OTHER_PRODUCTION = "0x00000000000000000000000000000000000000Bb";

describe("checkRepCreditAggregatorPolicy (CC-49 HIGH-A / MEDIUM-C)", () => {
  it("accepts distinct, explicitly configured aggregators", () => {
    expect(
      checkRepCreditAggregatorPolicy({
        repCreditAggregatorAddress: EXPERIMENT,
        auditAggregatorAddress: PRODUCTION,
        auditAggregatorFromEnv: true,
      })
    ).toEqual({ ok: true, forbidden: [PRODUCTION] });
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
      expect(verdict.reason).toMatch(/must not equal/);
    }
  });
});

/**
 * CC-49 round-3 MEDIUM. One AUDIT_BLS_AGGREGATOR_ADDRESS describes ONE aggregator, but a chain
 * can host several that hold stake — and a single address can itself be pointed at a decoy.
 * The deny-list lets an operator name every aggregator the experiment key must stay off; the
 * service scans each one and refuses on ANY failure.
 */
describe("checkRepCreditAggregatorPolicy deny-list (CC-49 round-3 MEDIUM)", () => {
  it("unions REPCREDIT_FORBIDDEN_AGGREGATORS with the audit aggregator", () => {
    const verdict = checkRepCreditAggregatorPolicy({
      repCreditAggregatorAddress: EXPERIMENT,
      auditAggregatorAddress: PRODUCTION,
      auditAggregatorFromEnv: true,
      forbiddenAggregators: [OTHER_PRODUCTION],
    });
    expect(verdict.ok).toBe(true);
    expect(verdict.forbidden).toEqual([PRODUCTION, OTHER_PRODUCTION]);
  });

  it("de-duplicates case-insensitively so a slot is not scanned twice", () => {
    const verdict = checkRepCreditAggregatorPolicy({
      repCreditAggregatorAddress: EXPERIMENT,
      auditAggregatorAddress: PRODUCTION,
      auditAggregatorFromEnv: true,
      forbiddenAggregators: [PRODUCTION.toLowerCase(), OTHER_PRODUCTION],
    });
    expect(verdict.forbidden).toEqual([PRODUCTION, OTHER_PRODUCTION]);
  });

  it("refuses an experiment aggregator that appears anywhere in the deny-list", () => {
    const verdict = checkRepCreditAggregatorPolicy({
      repCreditAggregatorAddress: EXPERIMENT,
      auditAggregatorAddress: PRODUCTION,
      auditAggregatorFromEnv: true,
      forbiddenAggregators: [EXPERIMENT.toUpperCase().replace("0X", "0x")],
    });
    expect(verdict.ok).toBe(false);
    expect(verdict.reason).toMatch(/must not equal/);
  });

  it("rejects a malformed deny-list entry rather than skipping it", () => {
    for (const bad of ["0x1234", "not-an-address", EXPERIMENT + "ff"]) {
      const verdict = checkRepCreditAggregatorPolicy({
        repCreditAggregatorAddress: EXPERIMENT,
        auditAggregatorAddress: PRODUCTION,
        auditAggregatorFromEnv: true,
        forbiddenAggregators: [bad],
      });
      expect(verdict.ok).toBe(false);
      expect(verdict.reason).toMatch(/not a valid aggregator address/);
    }
  });

  it("allows an EMPTY deny-list only under the explicit devnet acknowledgement", () => {
    const withoutAck = checkRepCreditAggregatorPolicy({
      repCreditAggregatorAddress: EXPERIMENT,
      auditAggregatorAddress: undefined,
      auditAggregatorFromEnv: false,
    });
    expect(withoutAck.ok).toBe(false);

    const withAck = checkRepCreditAggregatorPolicy({
      repCreditAggregatorAddress: EXPERIMENT,
      auditAggregatorAddress: undefined,
      auditAggregatorFromEnv: false,
      noProductionAggregator: true,
    });
    // Config-layer OK; RepCreditService still refuses this on any chain with real deployments.
    expect(withAck).toEqual({ ok: true, forbidden: [] });
  });

  it("keeps scanning the deny-list even under the devnet acknowledgement", () => {
    const verdict = checkRepCreditAggregatorPolicy({
      repCreditAggregatorAddress: EXPERIMENT,
      auditAggregatorFromEnv: false,
      noProductionAggregator: true,
      forbiddenAggregators: [OTHER_PRODUCTION],
    });
    expect(verdict).toEqual({ ok: true, forbidden: [OTHER_PRODUCTION] });
  });
});
