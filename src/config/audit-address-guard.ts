/**
 * Startup assertion for the two SP contract addresses the audit stack reads (DSR 2026-11-15, rc.8).
 *
 * Why it exists: a node left on a superseded DVTValidator or BLSAggregator does not fail. The old
 * contracts still exist and still answer, so the node watches them and silently sees nothing
 * (configuration.ts, the "FAIL-SILENT" note on the aggregator default). The only safe reaction is to
 * refuse to start.
 *
 * When it applies: only when something that READS these addresses is switched on, i.e.
 * AUDIT_ENABLED=true (audit, and the co-sign responder it arms) or AUDIT_GUARDIAN_WATCH_ENABLED=true
 * (the guardian-slash watcher). The live signing nodes run with both off and never read either
 * address; failing their startup over an unused setting would stop co-signing UserOperations to
 * protect nothing.
 *
 * What it rejects, for each of AUDIT_DVT_VALIDATOR_ADDRESS and AUDIT_BLS_AGGREGATOR_ADDRESS:
 *   - unset or empty: the code default is a superseded address, so "unset" is the stale case;
 *   - an address on the superseded list below (case-insensitive).
 *
 * The superseded list must grow at every SP succession. Add the address being replaced in the same
 * PR that moves the nodes to its successor.
 */
export const SUPERSEDED_DVT_VALIDATORS: readonly string[] = [
  // DVTValidator wired to the BLSAggregator-4.11.0 stack; replaced by rc.8 step A7.dvt.
  "0x568b1486BFE036e603eA11f0D03Dc47fa62c9E0e",
];

export const SUPERSEDED_BLS_AGGREGATORS: readonly string[] = [
  // BLSAggregator-4.3.0; replaced on 2026-09-04.
  "0x174b60bB462b00550F0EC7Bc35Fe39dDB6310158",
  // BLSAggregator-4.11.0; replaced by rc.8 (BLSAggregator-4.14.0).
  "0xEaeC2F512eA50708211fa95533e4dBb60e3d2E5D",
];

type Env = Record<string, string | undefined>;

/** Returns one message per problem; an empty array means the node may start. */
export function auditAddressProblems(env: Env): string[] {
  const consumers = [
    env.AUDIT_ENABLED === "true" ? "AUDIT_ENABLED" : null,
    env.AUDIT_GUARDIAN_WATCH_ENABLED === "true" ? "AUDIT_GUARDIAN_WATCH_ENABLED" : null,
  ].filter((v): v is string => v !== null);
  if (consumers.length === 0) return [];

  const problems: string[] = [];
  // Every superseded address is rejected in EITHER setting (Codex review of 20a0088, M3): a superseded
  // aggregator pasted into the DVTValidator setting has code, so the audit bootstrap's getCode check
  // would let it through.
  const superseded = [...SUPERSEDED_DVT_VALIDATORS, ...SUPERSEDED_BLS_AGGREGATORS].map(a =>
    a.toLowerCase()
  );
  const check = (name: string) => {
    const value = (env[name] ?? "").trim();
    if (value === "") {
      problems.push(
        `${name} is required when ${consumers.join(" / ")} is on: the code default is a superseded contract`
      );
      return;
    }
    if (!/^0x[0-9a-fA-F]{40}$/.test(value)) {
      problems.push(`${name}=${value} is not a 20-byte hex address`);
      return;
    }
    if (superseded.includes(value.toLowerCase())) {
      problems.push(
        `${name}=${value} is a superseded contract: set it to the current one from the SP read-back`
      );
    }
  };
  check("AUDIT_DVT_VALIDATOR_ADDRESS");
  check("AUDIT_BLS_AGGREGATOR_ADDRESS");
  const dvt = (env.AUDIT_DVT_VALIDATOR_ADDRESS ?? "").trim().toLowerCase();
  if (dvt !== "" && dvt === (env.AUDIT_BLS_AGGREGATOR_ADDRESS ?? "").trim().toLowerCase()) {
    problems.push(
      "AUDIT_DVT_VALIDATOR_ADDRESS and AUDIT_BLS_AGGREGATOR_ADDRESS are the same address"
    );
  }
  return problems;
}

/**
 * One startup log line saying whether the check ran, so an operator never reads "it started" as
 * "the addresses were checked" (DSR 2026-11-17).
 */
export function auditAddressStatusLine(env: Env): string {
  const on = env.AUDIT_ENABLED === "true" || env.AUDIT_GUARDIAN_WATCH_ENABLED === "true";
  return on
    ? `Audit addresses checked: DVTValidator ${env.AUDIT_DVT_VALIDATOR_ADDRESS?.trim()}, BLSAggregator ${env.AUDIT_BLS_AGGREGATOR_ADDRESS?.trim()}`
    : "Audit off (AUDIT_ENABLED and AUDIT_GUARDIAN_WATCH_ENABLED not true): audit addresses NOT checked";
}

/** Throws at startup if any problem is found. */
export function assertAuditAddresses(env: Env = process.env): void {
  const problems = auditAddressProblems(env);
  if (problems.length > 0) {
    throw new Error(`Audit address check failed:\n${problems.map(p => `  - ${p}`).join("\n")}`);
  }
}
