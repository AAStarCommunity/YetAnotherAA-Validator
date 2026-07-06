import configuration from "./configuration.js";

/**
 * Config-floor tests (Codex round-2 LOW): AUDIT_FINALITY_CONFIRMATIONS must be floored to a
 * POSITIVE value so the finalized-block fallback never resolves to the unconfirmed head (latest − 0).
 */
describe("configuration: auditFinalityConfirmations floor", () => {
  const saved = { ...process.env };

  beforeEach(() => {
    // Required vars so the config validator doesn't throw.
    process.env.ETH_RPC_URL = "http://localhost:8545";
    process.env.VALIDATOR_CONTRACT_ADDRESS = "0x" + "12".repeat(20);
  });

  afterEach(() => {
    process.env = { ...saved };
  });

  it("confirmations=0 → effective confirmations is floored to >= 1 (never the unconfirmed head)", () => {
    process.env.AUDIT_FINALITY_CONFIRMATIONS = "0";
    expect(configuration().auditFinalityConfirmations).toBe(1);
  });

  it("a negative value is floored to 1", () => {
    process.env.AUDIT_FINALITY_CONFIRMATIONS = "-5";
    expect(configuration().auditFinalityConfirmations).toBe(1);
  });

  it("a non-numeric value falls back to the default 12", () => {
    process.env.AUDIT_FINALITY_CONFIRMATIONS = "not-a-number";
    expect(configuration().auditFinalityConfirmations).toBe(12);
  });

  it("unset uses the default 12", () => {
    delete process.env.AUDIT_FINALITY_CONFIRMATIONS;
    expect(configuration().auditFinalityConfirmations).toBe(12);
  });

  it("a valid positive value is preserved", () => {
    process.env.AUDIT_FINALITY_CONFIRMATIONS = "20";
    expect(configuration().auditFinalityConfirmations).toBe(20);
  });
});
