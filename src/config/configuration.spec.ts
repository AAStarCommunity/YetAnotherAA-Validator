import configuration from "./configuration.js";

/**
 * Config-floor tests (Codex round-2 LOW): AUDIT_FINALITY_CONFIRMATIONS must be floored to a
 * POSITIVE value so the finalized-block fallback never resolves to the unconfirmed head (latest − 0).
 */
describe("configuration: auditBlsAggregatorAddressFromEnv (CC-89 explicit-presence flag)", () => {
  const saved = { ...process.env };
  beforeEach(() => {
    process.env.ETH_RPC_URL = "http://localhost:8545";
    process.env.VALIDATOR_CONTRACT_ADDRESS = "0x" + "12".repeat(20);
    delete process.env.AUDIT_BLS_AGGREGATOR_ADDRESS;
  });
  afterEach(() => {
    process.env = { ...saved };
  });

  it("unset env → resolved value carries the built-in default, but fromEnv is FALSE", () => {
    const c = configuration();
    expect(c.auditBlsAggregatorAddress).toBe("0xEaeC2F512eA50708211fa95533e4dBb60e3d2E5D");
    expect(c.auditBlsAggregatorAddressFromEnv).toBe(false);
  });

  it("explicit env → fromEnv is TRUE and the value is the env value", () => {
    process.env.AUDIT_BLS_AGGREGATOR_ADDRESS = "0x" + "cd".repeat(20);
    const c = configuration();
    expect(c.auditBlsAggregatorAddress).toBe("0x" + "cd".repeat(20));
    expect(c.auditBlsAggregatorAddressFromEnv).toBe(true);
  });
});

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

/**
 * AUDIT_DRY_RUN — the safe intermediate for the FIRST live slash drill. Off by default; only
 * meaningful when the node is ALSO armed (AUDIT_EXECUTE_SLASH), but the config flag itself is
 * independent (the audit gates dry-run on `armed && dryRun`).
 */
describe("configuration: auditDryRun", () => {
  const saved = { ...process.env };

  beforeEach(() => {
    process.env.ETH_RPC_URL = "http://localhost:8545";
    process.env.VALIDATOR_CONTRACT_ADDRESS = "0x" + "12".repeat(20);
  });

  afterEach(() => {
    process.env = { ...saved };
  });

  it("AUDIT_DRY_RUN=true → auditDryRun true", () => {
    process.env.AUDIT_DRY_RUN = "true";
    expect(configuration().auditDryRun).toBe(true);
  });

  it("unset → default false", () => {
    delete process.env.AUDIT_DRY_RUN;
    expect(configuration().auditDryRun).toBe(false);
  });

  it("any non-'true' value → false (strict, fail-safe off)", () => {
    process.env.AUDIT_DRY_RUN = "1";
    expect(configuration().auditDryRun).toBe(false);
  });
});

/**
 * HIGH 1 (Codex): AUDIT_SLASH_THRESHOLDS must be CLAMPED UP to the pinned live floor
 * (WARNING ≥ 2, MINOR ≥ 3, MAJOR ≥ 3) so a misconfiguration like `MINOR:1` can never let a single
 * local signature pass as quorum and defeat the 3-of-3 slash invariant. HIGHER values are kept.
 */
describe("configuration: auditSlashThresholds clamp (slash-quorum floor)", () => {
  const saved = { ...process.env };

  beforeEach(() => {
    process.env.ETH_RPC_URL = "http://localhost:8545";
    process.env.VALIDATOR_CONTRACT_ADDRESS = "0x" + "12".repeat(20);
  });

  afterEach(() => {
    process.env = { ...saved };
  });

  it("unset → the pinned live defaults 2/3/3", () => {
    delete process.env.AUDIT_SLASH_THRESHOLDS;
    expect(configuration().auditSlashThresholds).toEqual({ WARNING: 2, MINOR: 3, MAJOR: 3 });
  });

  it("MINOR:1 (below floor) → clamped UP to 3", () => {
    process.env.AUDIT_SLASH_THRESHOLDS = "MINOR:1";
    expect(configuration().auditSlashThresholds.MINOR).toBe(3);
  });

  it("WARNING:1 (below floor) → clamped UP to 2", () => {
    process.env.AUDIT_SLASH_THRESHOLDS = "WARNING:1";
    expect(configuration().auditSlashThresholds.WARNING).toBe(2);
  });

  it("MAJOR:1 (below floor) → clamped UP to 3", () => {
    process.env.AUDIT_SLASH_THRESHOLDS = "MAJOR:1";
    expect(configuration().auditSlashThresholds.MAJOR).toBe(3);
  });

  it("MINOR:4 (above floor) → preserved (higher thresholds still configurable)", () => {
    process.env.AUDIT_SLASH_THRESHOLDS = "MINOR:4";
    expect(configuration().auditSlashThresholds.MINOR).toBe(4);
  });

  it("mixed: MINOR:1,WARNING:5 → MINOR clamped to 3, WARNING preserved at 5", () => {
    process.env.AUDIT_SLASH_THRESHOLDS = "MINOR:1,WARNING:5";
    const t = configuration().auditSlashThresholds;
    expect(t.MINOR).toBe(3);
    expect(t.WARNING).toBe(5);
  });

  it("a malformed / non-positive entry keeps that level at its floor default", () => {
    process.env.AUDIT_SLASH_THRESHOLDS = "MINOR:0,MAJOR:notanumber";
    const t = configuration().auditSlashThresholds;
    expect(t.MINOR).toBe(3);
    expect(t.MAJOR).toBe(3);
  });

  it("LOW (Codex R2): a numeric-prefix junk value ('4oops') is IGNORED, not read as 4", () => {
    // parseInt would silently take 4; strict ^[0-9]+$ rejects it → the safe floor is kept.
    process.env.AUDIT_SLASH_THRESHOLDS = "MINOR:4oops";
    expect(configuration().auditSlashThresholds.MINOR).toBe(3);
  });

  it("LOW (Codex R2): an empty value ('MINOR:') keeps the floor", () => {
    process.env.AUDIT_SLASH_THRESHOLDS = "MINOR:";
    expect(configuration().auditSlashThresholds.MINOR).toBe(3);
  });
});
