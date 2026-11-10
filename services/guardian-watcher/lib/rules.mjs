// Pure rule evaluation (M0 §5.2). No I/O: the same record and ruleset always give the same verdict,
// so a flag can be re-derived from the pinned ruleset commit after the fact.
import { ethers } from "ethers";

const KINDS = ["SLASH", "GENERIC", "QUEUE", "REPUTATION"];

/** Validate a parsed ruleset; throws on a shape the evaluator would silently misread. */
export function validateRuleset(rs) {
  if (!rs || rs.schema !== "dvt.guardian-watcher.ruleset.v1")
    throw new Error("ruleset: unknown schema");
  for (const k of [...KINDS, "UNRECOVERED"]) {
    if (!rs.bls || !rs.bls[k]) throw new Error(`ruleset: bls.${k} missing`);
  }
  if (!Array.isArray(rs.bls.GENERIC.expected) || !rs.bls.GENERIC.unexpected) {
    throw new Error("ruleset: bls.GENERIC.expected / unexpected missing");
  }
  for (const e of rs.bls.GENERIC.expected) {
    if (typeof e.target !== "string" || typeof e.signature !== "string") {
      throw new Error("ruleset: GENERIC.expected entries need target (role) and signature");
    }
  }
  if (!rs.ownerRoute || typeof rs.ownerRoute.label !== "string" || !rs.ownerRoute.events) {
    throw new Error("ruleset: ownerRoute missing");
  }
  return rs;
}

/** The expected-set entry a GENERIC call matches, by target role address and selector, or null. */
export function matchGeneric(rs, roles, target, callData) {
  const sel =
    typeof callData === "string" && callData.length >= 10
      ? callData.slice(0, 10).toLowerCase()
      : null;
  for (const e of rs.bls.GENERIC.expected) {
    const addr = roles[e.target];
    if (!addr || !target) continue;
    if (ethers.getAddress(addr) !== ethers.getAddress(target)) continue;
    if (sel !== null && ethers.id(e.signature).slice(0, 10) === sel) return e;
  }
  return null;
}

/**
 * Verdict for one record: { flagged, reasons[], rule }.
 * record.route is "bls" (with kind, or kind === undefined when not authenticated) or "owner".
 */
export function evaluate(rs, roles, record) {
  if (record.route === "owner") {
    const r = rs.ownerRoute.events[record.event];
    if (!r)
      return {
        flagged: true,
        reasons: [`unlisted SuperPaymaster event ${record.event}`],
        rule: "ownerRoute.unlisted",
      };
    return {
      flagged: !!r.flag,
      reasons: [`${rs.ownerRoute.label}: ${record.event}`],
      rule: `ownerRoute.events.${record.event}`,
    };
  }
  if (record.kind === undefined) {
    const r = rs.bls.UNRECOVERED;
    return { flagged: !!r.flag, reasons: [r.reason], rule: "bls.UNRECOVERED" };
  }
  if (record.kind === "GENERIC") {
    const e = matchGeneric(rs, roles, record.fields?.target, record.fields?.callData);
    if (e)
      return {
        flagged: !!e.flag,
        reasons: [e.reason],
        rule: `bls.GENERIC.expected:${e.target}.${e.signature}`,
      };
    const u = rs.bls.GENERIC.unexpected;
    return { flagged: !!u.flag, reasons: [u.reason], rule: "bls.GENERIC.unexpected" };
  }
  const r = rs.bls[record.kind];
  if (!r) return { flagged: true, reasons: [`unknown kind ${record.kind}`], rule: "bls.unknown" };
  return { flagged: !!r.flag, reasons: [r.reason], rule: `bls.${record.kind}` };
}

/** Whether this record wants prices read before/after (price-update rules). */
export function wantsPrice(rs, roles, record) {
  if (record.route === "owner") return !!rs.ownerRoute.events[record.event]?.readPrice;
  if (record.kind !== "GENERIC") return false;
  return !!matchGeneric(rs, roles, record.fields?.target, record.fields?.callData)?.readPrice;
}
