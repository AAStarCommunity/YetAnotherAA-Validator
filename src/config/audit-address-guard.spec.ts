import { afterEach, beforeEach, describe, expect, it, jest } from "@jest/globals";
import {
  assertAuditAddresses,
  auditAddressProblems,
  auditAddressStatusLine,
  SUPERSEDED_BLS_AGGREGATORS,
  SUPERSEDED_DVT_VALIDATORS,
} from "./audit-address-guard.js";
import configuration from "./configuration.js";

// Stand-ins for the rc.8 read-back. Not real deployments.
const NEW_DVT = "0x1111111111111111111111111111111111111111";
const NEW_AGG = "0x2222222222222222222222222222222222222222";

const good = { AUDIT_DVT_VALIDATOR_ADDRESS: NEW_DVT, AUDIT_BLS_AGGREGATOR_ADDRESS: NEW_AGG };

describe("audit address guard (rc.8 startup assertion)", () => {
  describe("off: nothing reads the addresses", () => {
    it("CONTROL: audit and guardian watch off, addresses unset → no problem", () => {
      expect(auditAddressProblems({})).toEqual([]);
    });

    it("audit off with superseded addresses → still no problem (the node never reads them)", () => {
      expect(
        auditAddressProblems({
          AUDIT_DVT_VALIDATOR_ADDRESS: SUPERSEDED_DVT_VALIDATORS[0],
          AUDIT_BLS_AGGREGATOR_ADDRESS: SUPERSEDED_BLS_AGGREGATORS[0],
        })
      ).toEqual([]);
    });

    it('a non-"true" flag value does not switch the check on', () => {
      expect(auditAddressProblems({ AUDIT_ENABLED: "1" })).toEqual([]);
    });
  });

  for (const flag of ["AUDIT_ENABLED", "AUDIT_GUARDIAN_WATCH_ENABLED"]) {
    describe(`${flag}=true`, () => {
      it("CONTROL: both addresses set to current contracts → no problem", () => {
        expect(auditAddressProblems({ [flag]: "true", ...good })).toEqual([]);
      });

      it("DVTValidator address unset → refused", () => {
        const p = auditAddressProblems({ [flag]: "true", AUDIT_BLS_AGGREGATOR_ADDRESS: NEW_AGG });
        expect(p).toHaveLength(1);
        expect(p[0]).toContain("AUDIT_DVT_VALIDATOR_ADDRESS is required");
      });

      it("aggregator address empty (whitespace) → refused", () => {
        const p = auditAddressProblems({
          [flag]: "true",
          AUDIT_DVT_VALIDATOR_ADDRESS: NEW_DVT,
          AUDIT_BLS_AGGREGATOR_ADDRESS: "  ",
        });
        expect(p).toHaveLength(1);
        expect(p[0]).toContain("AUDIT_BLS_AGGREGATOR_ADDRESS is required");
      });

      it("both unset → two problems", () => {
        expect(auditAddressProblems({ [flag]: "true" })).toHaveLength(2);
      });
    });
  }

  it.each(SUPERSEDED_DVT_VALIDATORS.map(a => [a]))("superseded DVTValidator %s → refused", addr => {
    const p = auditAddressProblems({
      AUDIT_ENABLED: "true",
      ...good,
      AUDIT_DVT_VALIDATOR_ADDRESS: addr,
    });
    expect(p).toHaveLength(1);
    expect(p[0]).toContain("AUDIT_DVT_VALIDATOR_ADDRESS");
    expect(p[0]).toContain("superseded");
  });

  it.each(SUPERSEDED_BLS_AGGREGATORS.map(a => [a]))(
    "superseded BLSAggregator %s → refused",
    addr => {
      const p = auditAddressProblems({
        AUDIT_ENABLED: "true",
        ...good,
        AUDIT_BLS_AGGREGATOR_ADDRESS: addr,
      });
      expect(p).toHaveLength(1);
      expect(p[0]).toContain("AUDIT_BLS_AGGREGATOR_ADDRESS");
      expect(p[0]).toContain("superseded");
    }
  );

  it("superseded match ignores case", () => {
    const p = auditAddressProblems({
      AUDIT_ENABLED: "true",
      ...good,
      AUDIT_BLS_AGGREGATOR_ADDRESS: SUPERSEDED_BLS_AGGREGATORS[1].toLowerCase(),
    });
    expect(p).toHaveLength(1);
  });

  it("a superseded aggregator pasted into the DVTValidator setting → refused (Codex M3)", () => {
    const p = auditAddressProblems({
      AUDIT_ENABLED: "true",
      ...good,
      AUDIT_DVT_VALIDATOR_ADDRESS: SUPERSEDED_BLS_AGGREGATORS[1],
    });
    expect(p).toHaveLength(1);
    expect(p[0]).toContain("AUDIT_DVT_VALIDATOR_ADDRESS");
    expect(p[0]).toContain("superseded");
  });

  it("a superseded DVTValidator pasted into the aggregator setting → refused", () => {
    const p = auditAddressProblems({
      AUDIT_ENABLED: "true",
      ...good,
      AUDIT_BLS_AGGREGATOR_ADDRESS: SUPERSEDED_DVT_VALIDATORS[0],
    });
    expect(p).toHaveLength(1);
    expect(p[0]).toContain("AUDIT_BLS_AGGREGATOR_ADDRESS");
  });

  it("surrounding whitespace → refused, not trimmed (#442 review L1)", () => {
    for (const padded of [` ${NEW_AGG}`, `${NEW_AGG} `, `\t${NEW_AGG}\n`]) {
      const p = auditAddressProblems({
        AUDIT_ENABLED: "true",
        ...good,
        AUDIT_BLS_AGGREGATOR_ADDRESS: padded,
      });
      expect(p).toHaveLength(1);
      expect(p[0]).toContain("whitespace");
    }
  });

  it("a mixed-case address with a bad EIP-55 checksum → refused (#445 review note 1)", () => {
    const p = auditAddressProblems({
      AUDIT_ENABLED: "true",
      ...good,
      AUDIT_BLS_AGGREGATOR_ADDRESS: "0xabcDEF1234ABCDEf1234ABcdef1234ABCDef1234",
    });
    expect(p).toHaveLength(1);
    expect(p[0]).toContain("EIP-55");
  });

  it("CONTROL: correctly checksummed, all-lowercase and all-uppercase addresses are accepted", () => {
    const sum = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"; // EIP-55 reference vector
    for (const a of [sum, sum.toLowerCase(), "0x" + sum.slice(2).toUpperCase()]) {
      expect(
        auditAddressProblems({ AUDIT_ENABLED: "true", ...good, AUDIT_BLS_AGGREGATOR_ADDRESS: a })
      ).toEqual([]);
    }
  });

  it("the zero address → refused (#442 review L2)", () => {
    const p = auditAddressProblems({
      AUDIT_ENABLED: "true",
      ...good,
      AUDIT_DVT_VALIDATOR_ADDRESS: "0x0000000000000000000000000000000000000000",
    });
    expect(p).toHaveLength(1);
    expect(p[0]).toContain("zero address");
  });

  it("a malformed address → refused", () => {
    const p = auditAddressProblems({
      AUDIT_ENABLED: "true",
      ...good,
      AUDIT_BLS_AGGREGATOR_ADDRESS: "0x1234",
    });
    expect(p).toHaveLength(1);
    expect(p[0]).toContain("not a 20-byte hex address");
  });

  it("the same address in both settings → refused", () => {
    const p = auditAddressProblems({
      AUDIT_ENABLED: "true",
      AUDIT_DVT_VALIDATOR_ADDRESS: NEW_AGG,
      AUDIT_BLS_AGGREGATOR_ADDRESS: NEW_AGG.toUpperCase().replace("0X", "0x"),
    });
    expect(p).toHaveLength(1);
    expect(p[0]).toContain("the same address");
  });

  it("assertAuditAddresses throws with every problem listed", () => {
    expect(() => assertAuditAddresses({ AUDIT_ENABLED: "true" })).toThrow(
      /AUDIT_DVT_VALIDATOR_ADDRESS[\s\S]*AUDIT_BLS_AGGREGATOR_ADDRESS/
    );
  });

  describe("wired into configuration()", () => {
    const saved = { ...process.env };
    beforeEach(() => {
      process.env.ETH_RPC_URL = "http://127.0.0.1:8545";
      process.env.VALIDATOR_CONTRACT_ADDRESS = "0x3333333333333333333333333333333333333333";
      delete process.env.AUDIT_ENABLED;
      delete process.env.AUDIT_GUARDIAN_WATCH_ENABLED;
      delete process.env.AUDIT_DVT_VALIDATOR_ADDRESS;
      delete process.env.AUDIT_BLS_AGGREGATOR_ADDRESS;
      jest.spyOn(console, "log").mockImplementation(() => {});
    });
    afterEach(() => {
      process.env = { ...saved };
      jest.restoreAllMocks();
    });

    it("CONTROL: audit off, addresses unset → configuration loads", () => {
      expect(() => configuration()).not.toThrow();
    });

    it("audit on with addresses unset → configuration throws at load", () => {
      process.env.AUDIT_ENABLED = "true";
      expect(() => configuration()).toThrow(/Audit address check failed/);
    });

    it("guardian watch on with a superseded aggregator → configuration throws at load", () => {
      process.env.AUDIT_GUARDIAN_WATCH_ENABLED = "true";
      process.env.AUDIT_DVT_VALIDATOR_ADDRESS = NEW_DVT;
      process.env.AUDIT_BLS_AGGREGATOR_ADDRESS = SUPERSEDED_BLS_AGGREGATORS[1];
      expect(() => configuration()).toThrow(/superseded/);
    });

    it("CONTROL: audit on with current addresses → configuration loads", () => {
      process.env.AUDIT_ENABLED = "true";
      process.env.AUDIT_DVT_VALIDATOR_ADDRESS = NEW_DVT;
      process.env.AUDIT_BLS_AGGREGATOR_ADDRESS = NEW_AGG;
      expect(() => configuration()).not.toThrow();
    });
  });
});

describe("audit address status line (startup log)", () => {
  it("off → says the addresses were NOT checked", () => {
    expect(auditAddressStatusLine({})).toContain("NOT checked");
  });
  it("on → names both checked addresses", () => {
    const line = auditAddressStatusLine({ AUDIT_GUARDIAN_WATCH_ENABLED: "true", ...good });
    expect(line).toContain(NEW_DVT);
    expect(line).toContain(NEW_AGG);
    expect(line).not.toContain("NOT checked");
  });
});
