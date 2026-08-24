import { BadRequestException, ForbiddenException } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { RepCreditService } from "./repcredit.service.js";

function service(
  config: Record<string, unknown>,
  blockchain: Record<string, unknown> = {},
  node: Record<string, unknown> = {},
  bls: Record<string, unknown> = {}
) {
  const configService = { get: (key: string) => config[key] } as unknown as ConfigService;
  return new RepCreditService(configService, blockchain as any, node as any, bls as any);
}

const EXPERIMENT_AGGREGATOR = "0x0000000000000000000000000000000000000001";
const PRODUCTION_AGGREGATOR = "0x00000000000000000000000000000000000000AA";

/** Config that satisfies the pure isolation policy: armed, distinct + EXPLICIT aggregators. */
function armed(config: Record<string, unknown> = {}) {
  return {
    repCreditExperimentSigning: true,
    repCreditBlsAggregatorAddress: EXPERIMENT_AGGREGATOR,
    auditBlsAggregatorAddress: PRODUCTION_AGGREGATOR,
    auditBlsAggregatorAddressFromEnv: true,
    ...config,
  };
}

describe("RepCreditService opt-in gates", () => {
  it("is fail-closed by default before any RPC or signing work", async () => {
    await expect(service({}).sign({} as any)).rejects.toBeInstanceOf(ForbiddenException);
  });

  it("refuses aggregation below the BLSAggregator on-chain threshold", async () => {
    const instance = service(armed(), {
      getChainId: async () => 31337,
      getBlsDefaultThreshold: async () => 3,
    });
    await expect(instance.aggregate({} as any, [], 2)).rejects.toBeInstanceOf(BadRequestException);
  });
});

describe("RepCreditService aggregator config policy (CC-49 BLOCKER-1 / HIGH-A / MEDIUM-C)", () => {
  const blockchain = {
    getChainId: async () => 31337,
    getBlsDefaultThreshold: async () => 1,
    getBlsSlashThreshold: async () => 1,
    getBlsPublicKeyAtSlot: async () => null,
  };

  function sameAddress(config: Record<string, unknown> = {}) {
    return service(
      armed({
        repCreditValidatorSlot: 1,
        repCreditBlsAggregatorAddress: PRODUCTION_AGGREGATOR,
        auditBlsAggregatorAddress: PRODUCTION_AGGREGATOR.toLowerCase(),
        ...config,
      }),
      blockchain
    );
  }

  it("refuses to sign against the production audit aggregator (case-insensitive)", async () => {
    await expect(sameAddress().signSlash({ slashLevel: 1 } as any)).rejects.toBeInstanceOf(
      ForbiddenException
    );
  });

  it("refuses to aggregate against the production audit aggregator", async () => {
    await expect(
      sameAddress().aggregateSlash({ slashLevel: 1 } as any, [], 3)
    ).rejects.toBeInstanceOf(ForbiddenException);
  });

  it("allows an isolated experiment aggregator", async () => {
    const instance = sameAddress({ repCreditBlsAggregatorAddress: EXPERIMENT_AGGREGATOR });
    // Gets past the separation gate; fails later on the (unstubbed) slot binding instead.
    await expect(instance.aggregateSlash({ slashLevel: 1 } as any, [], 3)).rejects.toBeInstanceOf(
      BadRequestException
    );
  });

  it("refuses to arm when AUDIT_BLS_AGGREGATOR_ADDRESS was not set explicitly (MEDIUM-C)", async () => {
    // The resolved value always carries the built-in Sepolia default, so an unset env would
    // otherwise compare the experiment aggregator against a foreign-chain address.
    const instance = service(armed({ auditBlsAggregatorAddressFromEnv: false }), blockchain);
    await expect(instance.signSlash({ slashLevel: 1 } as any)).rejects.toThrow(
      /must be set EXPLICITLY/
    );
    await expect(instance.aggregateSlash({ slashLevel: 1 } as any, [], 3)).rejects.toThrow(
      /must be set EXPLICITLY/
    );
  });

  it("refuses to arm without REPCREDIT_BLS_AGGREGATOR_ADDRESS", async () => {
    const instance = service(armed({ repCreditBlsAggregatorAddress: undefined }), blockchain);
    await expect(instance.signSlash({ slashLevel: 1 } as any)).rejects.toThrow(
      /REPCREDIT_BLS_AGGREGATOR_ADDRESS is required/
    );
  });
});

describe("RepCreditService key isolation from the audit aggregator (CC-49 HIGH-A)", () => {
  // A well-formed compressed G1 point (the generator) — encodeRepCreditPublicKey must parse it.
  const NODE_PUBLIC_KEY =
    "0x97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb";
  const SIGNING_NODE = { nodeId: "node-1", publicKey: NODE_PUBLIC_KEY };
  const EXPERIMENT_SLOT_KEY = "0x" + "ab".repeat(128);

  function build(
    overrides: {
      auditSlotKeys?: (string | null)[];
      auditSlotThrowsAt?: number;
      code?: string;
      probeThrows?: boolean;
      experimentSlotKey?: string | null;
      config?: Record<string, unknown>;
    } = {}
  ) {
    const signed: string[] = [];
    const blockchain = {
      getChainId: async () => 31337,
      getBlsPublicKeyAtSlot: async () =>
        overrides.experimentSlotKey === undefined
          ? EXPERIMENT_SLOT_KEY
          : overrides.experimentSlotKey,
      getCode: async () => overrides.code ?? "0x60006000",
      probeBlsAggregator: async () => {
        if (overrides.probeThrows) throw new Error("no such method");
      },
      getBlsPublicKeyAtSlotStrict: async (_addr: string, slot: number) => {
        if (overrides.auditSlotThrowsAt === slot) throw new Error("RPC timeout");
        return overrides.auditSlotKeys?.[slot - 1] ?? null;
      },
    };
    const instance = service(
      armed({ repCreditValidatorSlot: 1, auditMaxSlots: 3, ...overrides.config }),
      blockchain,
      { getNodeForSigning: () => SIGNING_NODE },
      {
        signRepCreditHash: async (hash: string) => {
          signed.push(hash);
          return { signatureCompact: "0xdead", publicKey: "0xbeef" };
        },
      }
    );
    return { instance, signed, blockchain };
  }

  /** A valid reputation proposal, self-consistent with the production hash builder. */
  async function proposal() {
    const { buildRepCreditMessageHash } = await import("./repcredit-consensus.js");
    const base = {
      schemaVersion: "repcredit-reputation-v1" as const,
      proposalId: "1",
      operator: "0x0000000000000000000000000000000000000000",
      slashLevel: 0,
      users: ["0x1111111111111111111111111111111111111111"],
      scores: ["10"],
      epoch: "1",
      chainId: "31337",
      messageHash: "0x" + "00".repeat(32),
    };
    return { ...base, messageHash: buildRepCreditMessageHash(base as any) };
  }

  /**
   * Derived through the PRODUCTION encoder so the fixture cannot drift from it: the service
   * binds the local key to the experiment slot before scanning the audit aggregator, so the
   * stubbed experiment slot must return exactly what the node itself would produce.
   */
  async function encodedLocalKey(): Promise<string> {
    const { encodeRepCreditPublicKey } = await import("./repcredit-consensus.js");
    return encodeRepCreditPublicKey(NODE_PUBLIC_KEY);
  }

  it("signs when the local key is absent from every audit-aggregator slot", async () => {
    const key = await encodedLocalKey();
    const { instance, signed } = build({
      experimentSlotKey: key,
      auditSlotKeys: [null, "0x" + "cd".repeat(128), null],
    });
    await expect(instance.sign((await proposal()) as any)).resolves.toMatchObject({ slot: 1 });
    expect(signed).toHaveLength(1);
  });

  it("refuses to sign when the local key is active in ANY audit-aggregator slot", async () => {
    const key = await encodedLocalKey();
    for (const slot of [1, 2, 3]) {
      const auditSlotKeys: (string | null)[] = [null, null, null];
      auditSlotKeys[slot - 1] = key.toUpperCase().replace("0X", "0x");
      const { instance, signed } = build({ experimentSlotKey: key, auditSlotKeys });
      await expect(instance.sign((await proposal()) as any)).rejects.toThrow(
        new RegExp(`also active at slot ${slot} on production aggregator`)
      );
      expect(signed).toHaveLength(0);
    }
  });

  it("refuses to sign when a single audit-slot read fails (never reads as 'absent')", async () => {
    const key = await encodedLocalKey();
    const { instance, signed } = build({ experimentSlotKey: key, auditSlotThrowsAt: 2 });
    await expect(instance.sign((await proposal()) as any)).rejects.toThrow(
      /could not determine whether the local BLS key is active at aggregator .* slot 2/
    );
    expect(signed).toHaveLength(0);
  });

  it("does not echo the underlying RPC error back to the caller", async () => {
    // ethers wraps provider failures with request detail that can carry the RPC URL, and the
    // RPC URL carries the provider API key. The refusal is reported; the cause is only logged.
    const key = await encodedLocalKey();
    const { instance } = build({ experimentSlotKey: key, auditSlotThrowsAt: 2 });
    await expect(instance.sign((await proposal()) as any)).rejects.not.toThrow(/RPC timeout/);
  });

  it("scans at least MAX_VALIDATORS slots even when AUDIT_MAX_SLOTS is lowered", async () => {
    // A security scan must not be shrinkable by an operator env into missing the slot the
    // key actually sits in.
    const key = await encodedLocalKey();
    const auditSlotKeys: (string | null)[] = new Array(13).fill(null);
    auditSlotKeys[12] = key;
    const { instance, signed } = build({
      experimentSlotKey: key,
      auditSlotKeys,
      config: { auditMaxSlots: 3 },
    });
    await expect(instance.sign((await proposal()) as any)).rejects.toThrow(
      /also active at slot 13 on production aggregator/
    );
    expect(signed).toHaveLength(0);
  });

  it("refuses to sign when the audit aggregator has no code on this chain (MEDIUM-C)", async () => {
    const key = await encodedLocalKey();
    const { instance, signed } = build({ experimentSlotKey: key, code: "0x" });
    await expect(instance.sign((await proposal()) as any)).rejects.toThrow(
      /no contract deployed at/
    );
    expect(signed).toHaveLength(0);
  });

  it("refuses to sign when the audit aggregator does not answer the BLSAggregator ABI", async () => {
    const key = await encodedLocalKey();
    const { instance, signed } = build({ experimentSlotKey: key, probeThrows: true });
    await expect(instance.sign((await proposal()) as any)).rejects.toThrow(
      /does not answer the BLSAggregator interface/
    );
    expect(signed).toHaveLength(0);
  });

  it("still enforces the experiment-slot binding before the audit scan", async () => {
    const { instance, signed } = build({ experimentSlotKey: "0x" + "cd".repeat(128) });
    await expect(instance.sign((await proposal()) as any)).rejects.toThrow(
      /local BLS key is not registered at validator slot 1/
    );
    expect(signed).toHaveLength(0);
  });
});

/**
 * CC-49 round-3 MEDIUM. The key-reuse scan now covers the audit aggregator AND every
 * REPCREDIT_FORBIDDEN_AGGREGATORS entry, and the "this devnet has no production aggregator"
 * escape is refused on any chain that carries real deployments.
 */
describe("RepCreditService production-aggregator deny-list (CC-49 round-3 MEDIUM)", () => {
  const NODE_PUBLIC_KEY =
    "0x97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb";
  const SIGNING_NODE = { nodeId: "node-1", publicKey: NODE_PUBLIC_KEY };
  const SECOND_PRODUCTION = "0x00000000000000000000000000000000000000Bb";

  async function encodedLocalKey(): Promise<string> {
    const { encodeRepCreditPublicKey } = await import("./repcredit-consensus.js");
    return encodeRepCreditPublicKey(NODE_PUBLIC_KEY);
  }

  async function proposal(chainId = 31337) {
    const { buildRepCreditMessageHash } = await import("./repcredit-consensus.js");
    const base = {
      schemaVersion: "repcredit-reputation-v1" as const,
      proposalId: "1",
      operator: "0x0000000000000000000000000000000000000000",
      slashLevel: 0,
      users: ["0x1111111111111111111111111111111111111111"],
      scores: ["10"],
      epoch: "1",
      chainId: String(chainId),
      messageHash: "0x" + "00".repeat(32),
    };
    return { ...base, messageHash: buildRepCreditMessageHash(base as any) };
  }

  function build(
    config: Record<string, unknown>,
    slots: (aggregator: string, slot: number) => string | null | Error,
    chainId = 31337,
    hooks: { codeThrowsOn?: string } = {}
  ) {
    const scanned: string[] = [];
    const signed: string[] = [];
    const blockchain = {
      getChainId: async () => chainId,
      getBlsPublicKeyAtSlot: async () => encodedKey,
      getCode: async (address: string) => {
        if (hooks.codeThrowsOn === address) {
          throw new Error(`server response 401 url="https://rpc.test/v2/SECRET"`);
        }
        return "0x60006000";
      },
      probeBlsAggregator: async () => undefined,
      getBlsPublicKeyAtSlotStrict: async (aggregator: string, slot: number) => {
        scanned.push(`${aggregator}#${slot}`);
        const out = slots(aggregator, slot);
        if (out instanceof Error) throw out;
        return out;
      },
    };
    let encodedKey = "";
    const instance = service(
      armed({ repCreditValidatorSlot: 1, auditMaxSlots: 2, ...config }),
      blockchain,
      { getNodeForSigning: () => SIGNING_NODE },
      {
        signRepCreditHash: async (h: string) => (
          signed.push(h),
          { signatureCompact: "0xa", publicKey: "0xb" }
        ),
      }
    );
    return {
      instance,
      scanned,
      signed,
      setLocalKey: (key: string) => {
        encodedKey = key;
      },
    };
  }

  it("scans EVERY listed aggregator, not just the audit one", async () => {
    const key = await encodedLocalKey();
    const built = build({ repCreditForbiddenAggregators: [SECOND_PRODUCTION] }, () => null);
    built.setLocalKey(key);
    await expect(built.instance.sign((await proposal()) as any)).resolves.toMatchObject({
      slot: 1,
    });
    expect(built.scanned.some(entry => entry.startsWith(PRODUCTION_AGGREGATOR))).toBe(true);
    expect(built.scanned.some(entry => entry.startsWith(SECOND_PRODUCTION))).toBe(true);
  });

  it("refuses when the key sits on a deny-listed aggregator the audit address does not cover", async () => {
    const key = await encodedLocalKey();
    const built = build(
      { repCreditForbiddenAggregators: [SECOND_PRODUCTION] },
      (aggregator, slot) => (aggregator === SECOND_PRODUCTION && slot === 2 ? key : null)
    );
    built.setLocalKey(key);
    await expect(built.instance.sign((await proposal()) as any)).rejects.toThrow(
      new RegExp(`also active at slot 2 on production aggregator ${SECOND_PRODUCTION}`)
    );
    expect(built.signed).toHaveLength(0);
  });

  it("refuses on ANY read failure across the parallel scan", async () => {
    const key = await encodedLocalKey();
    const built = build(
      { repCreditForbiddenAggregators: [SECOND_PRODUCTION] },
      (aggregator, slot) =>
        aggregator === SECOND_PRODUCTION && slot === 5 ? new Error("RPC timeout") : null
    );
    built.setLocalKey(key);
    await expect(built.instance.sign((await proposal()) as any)).rejects.toThrow(
      /refusing to sign on an indeterminate isolation check/
    );
    expect(built.signed).toHaveLength(0);
  });

  it("never echoes a provider error (which carries the RPC key) back to the caller", async () => {
    const key = await encodedLocalKey();
    const built = build({}, () => null, 31337, { codeThrowsOn: PRODUCTION_AGGREGATOR });
    built.setLocalKey(key);
    const error = await built.instance.sign((await proposal()) as any).catch(e => e);
    expect(String(error.message)).not.toContain("SECRET");
    expect(String(error.message)).not.toContain("rpc.test");
    expect(String(error.message)).toMatch(/cannot read the production aggregator/);
  });

  it("accepts the devnet acknowledgement on a throwaway chain", async () => {
    const key = await encodedLocalKey();
    const built = build(
      {
        auditBlsAggregatorAddress: undefined,
        auditBlsAggregatorAddressFromEnv: false,
        repCreditNoProductionAggregator: true,
      },
      () => null,
      31337
    );
    built.setLocalKey(key);
    await expect(built.instance.sign((await proposal()) as any)).resolves.toMatchObject({
      slot: 1,
    });
    expect(built.scanned).toHaveLength(0);
  });

  it("refuses the devnet acknowledgement on every chain that carries real deployments", async () => {
    const key = await encodedLocalKey();
    for (const chainId of [1, 10, 137, 8453, 42161, 11155111]) {
      const built = build(
        {
          auditBlsAggregatorAddress: undefined,
          auditBlsAggregatorAddressFromEnv: false,
          repCreditNoProductionAggregator: true,
        },
        () => null,
        chainId
      );
      built.setLocalKey(key);
      await expect(built.instance.sign((await proposal(chainId)) as any)).rejects.toThrow(
        /REPCREDIT_NO_PRODUCTION_AGGREGATOR is not accepted on chain/
      );
      expect(built.signed).toHaveLength(0);
    }
  });
});

describe("RepCreditService slash threshold source (CC-49 MEDIUM-1)", () => {
  function slashService(
    slashThresholds: Record<number, number>,
    calls: { level?: number; defaultUsed?: boolean } = {}
  ) {
    return service(armed(), {
      getChainId: async () => 31337,
      getBlsDefaultThreshold: async () => {
        calls.defaultUsed = true;
        return 7;
      },
      getBlsSlashThreshold: async (_addr: string, level: number) => {
        calls.level = level;
        return slashThresholds[level];
      },
    });
  }

  it("reads slashThresholds[slashLevel], not the reputation defaultThreshold", async () => {
    const calls: { level?: number; defaultUsed?: boolean } = {};
    const instance = slashService({ 0: 2, 1: 3, 2: 3 }, calls);
    // threshold 3 clears slashThresholds[MINOR]=3 but would fail defaultThreshold=7.
    await expect(instance.aggregateSlash({ slashLevel: 1 } as any, [], 3)).rejects.toBeInstanceOf(
      BadRequestException
    );
    expect(calls.level).toBe(1);
    expect(calls.defaultUsed).toBeUndefined();
  });

  it("rejects an aggregate below the severity-specific on-chain threshold", async () => {
    const instance = slashService({ 0: 2, 1: 3, 2: 3 });
    await expect(instance.aggregateSlash({ slashLevel: 2 } as any, [], 2)).rejects.toThrow(
      /below on-chain slashThresholds\[2\] 3/
    );
  });

  it("rejects a malformed slashLevel before spending an RPC read", async () => {
    const calls: { level?: number } = {};
    const instance = slashService({ 0: 2, 1: 3, 2: 3 }, calls);
    for (const slashLevel of [-1, 3, 1.5, "1", undefined]) {
      await expect(instance.aggregateSlash({ slashLevel } as any, [], 3)).rejects.toBeInstanceOf(
        BadRequestException
      );
    }
    expect(calls.level).toBeUndefined();
  });
});
