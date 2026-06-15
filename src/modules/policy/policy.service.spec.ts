import { ethers } from "ethers";
import { PolicyService } from "./policy.service.js";
import type { PackedUserOp } from "../blockchain/blockchain.service.js";

/**
 * Fix 2 Stage 2 — DVT independent policy gate tests.
 *
 * The gate decides WHETHER the node co-signs, independently of the owner signature.
 * It must be fail-closed: when enabled, anything it cannot decode into concrete
 * (to, value) calls is rejected, and any call outside limits/allowlist is rejected.
 * When disabled it must allow everything (preserve Stage 1 behavior).
 */

const coder = new ethers.AbiCoder();
const RECIPIENT = "0x" + "11".repeat(20);
const OTHER = "0x" + "22".repeat(20);

/** Build callData for the account `execute(address,uint256,bytes)` surface. */
function executeCallData(to: string, valueWei: bigint): string {
  const selector = ethers.id("execute(address,uint256,bytes)").slice(0, 10);
  return selector + coder.encode(["address", "uint256", "bytes"], [to, valueWei, "0x"]).slice(2);
}

function executeBatchCallData(tos: string[], values: bigint[]): string {
  const selector = ethers.id("executeBatch(address[],uint256[],bytes[])").slice(0, 10);
  const funcs = tos.map(() => "0x");
  return (
    selector + coder.encode(["address[]", "uint256[]", "bytes[]"], [tos, values, funcs]).slice(2)
  );
}

function userOpWith(callData: string): PackedUserOp {
  return {
    sender: "0x" + "ab".repeat(20),
    nonce: "0",
    initCode: "0x",
    callData,
    accountGasLimits: "0x" + "00".repeat(32),
    preVerificationGas: "0",
    gasFees: "0x" + "00".repeat(32),
    paymasterAndData: "0x",
    signature: "0x",
  };
}

/**
 * Minimal ConfigService stub + BlockchainService stub. `checkPolicyImpl` lets a
 * test drive the layer-1 on-chain decision (or throw to simulate a revert).
 */
function makeService(
  config: Record<string, unknown>,
  checkPolicyImpl?: (...args: any[]) => Promise<{ decision: number; remainingDaily: bigint }>
): PolicyService {
  const configService = {
    get: (key: string) => config[key],
  } as any;
  const blockchainService = {
    checkPolicy: checkPolicyImpl ?? (async () => ({ decision: 1, remainingDaily: 0n })), // default REQUIRE_DVT
  } as any;
  return new PolicyService(configService, blockchainService);
}

describe("PolicyService — layer 2 (node-operator floor)", () => {
  it("allows everything when disabled (preserves Stage 1 behavior)", async () => {
    const svc = makeService({ policyEnabled: false });
    // even garbage callData passes when the gate is off
    expect((await svc.evaluate(userOpWith("0xdeadbeef"))).allowed).toBe(true);
  });

  it("allows an execute() within the per-tx limit", async () => {
    const svc = makeService({ policyEnabled: true, policyPerTxMaxWei: "1000000000000000000" });
    const op = userOpWith(executeCallData(RECIPIENT, 5n));
    expect((await svc.evaluate(op)).allowed).toBe(true);
  });

  it("rejects an execute() above the per-tx limit", async () => {
    const svc = makeService({ policyEnabled: true, policyPerTxMaxWei: "100" });
    const op = userOpWith(executeCallData(RECIPIENT, 101n));
    const d = await svc.evaluate(op);
    expect(d.allowed).toBe(false);
    expect(d.reason).toMatch(/exceeds perTxMaxWei/);
  });

  it("rejects a recipient outside the allowlist", async () => {
    const svc = makeService({ policyEnabled: true, policyRecipientAllowlist: [RECIPIENT] });
    const op = userOpWith(executeCallData(OTHER, 0n));
    const d = await svc.evaluate(op);
    expect(d.allowed).toBe(false);
    expect(d.reason).toMatch(/not in allowlist/);
  });

  it("allows a recipient inside the allowlist (case-insensitive)", async () => {
    const svc = makeService({
      policyEnabled: true,
      policyRecipientAllowlist: [RECIPIENT.toUpperCase()],
    });
    const op = userOpWith(executeCallData(RECIPIENT, 0n));
    expect((await svc.evaluate(op)).allowed).toBe(true);
  });

  it("enforces the limit against EVERY call in executeBatch", async () => {
    const svc = makeService({ policyEnabled: true, policyPerTxMaxWei: "100" });
    const op = userOpWith(executeBatchCallData([RECIPIENT, OTHER], [10n, 999n]));
    const d = await svc.evaluate(op);
    expect(d.allowed).toBe(false);
    expect(d.reason).toMatch(/call\[1\]/);
  });

  it("fails closed on undecodable callData when enabled", async () => {
    const svc = makeService({ policyEnabled: true, policyPerTxMaxWei: "100" });
    const d = await svc.evaluate(userOpWith("0xdeadbeef"));
    expect(d.allowed).toBe(false);
    expect(d.reason).toMatch(/unsupported callData selector|undecodable/);
  });

  it("fails closed on an empty/malformed callData when enabled", async () => {
    const svc = makeService({ policyEnabled: true });
    expect((await svc.evaluate(userOpWith("0x"))).allowed).toBe(false);
  });
});

describe("PolicyService — layer 1 (on-chain IPolicyRegistry)", () => {
  const REGISTRY = "0x" + "99".repeat(20);

  it("is off when no registry configured (layer-2 only)", async () => {
    let called = false;
    const svc = makeService({ policyEnabled: true }, async () => {
      called = true;
      return { decision: 2, remainingDaily: 0n };
    });
    expect((await svc.evaluate(userOpWith(executeCallData(RECIPIENT, 5n)))).allowed).toBe(true);
    expect(called).toBe(false); // registry never consulted
  });

  it("allows when registry returns ALLOW (0) / REQUIRE_DVT (1)", async () => {
    for (const decision of [0, 1]) {
      const svc = makeService(
        { policyEnabled: true, policyRegistryAddress: REGISTRY },
        async () => ({
          decision,
          remainingDaily: 0n,
        })
      );
      expect((await svc.evaluate(userOpWith(executeCallData(RECIPIENT, 5n)))).allowed).toBe(true);
    }
  });

  it("refuses when registry returns REJECT (2)", async () => {
    const svc = makeService({ policyEnabled: true, policyRegistryAddress: REGISTRY }, async () => ({
      decision: 2,
      remainingDaily: 0n,
    }));
    const d = await svc.evaluate(userOpWith(executeCallData(RECIPIENT, 5n)));
    expect(d.allowed).toBe(false);
    expect(d.reason).toMatch(/REJECT/);
  });

  it("fails closed when checkPolicy reverts", async () => {
    const svc = makeService({ policyEnabled: true, policyRegistryAddress: REGISTRY }, async () => {
      throw new Error("execution reverted");
    });
    const d = await svc.evaluate(userOpWith(executeCallData(RECIPIENT, 5n)));
    expect(d.allowed).toBe(false);
    expect(d.reason).toMatch(/checkPolicy reverted/);
  });

  it("passes native-ETH calls to the registry with the ETH sentinel asset", async () => {
    const seen: any[] = [];
    const svc = makeService(
      {
        policyEnabled: true,
        policyRegistryAddress: REGISTRY,
        policyEthSentinel: "0x" + "ee".repeat(20),
      },
      async (_registry, sender, target, asset, amount) => {
        seen.push({ sender, target, asset, amount });
        return { decision: 1, remainingDaily: 0n };
      }
    );
    await svc.evaluate(userOpWith(executeCallData(RECIPIENT, 777n)));
    expect(seen[0].asset.toLowerCase()).toBe("0x" + "ee".repeat(20));
    expect(seen[0].amount).toBe(777n);
    expect(seen[0].target.toLowerCase()).toBe(RECIPIENT.toLowerCase());
  });

  it("layer-2 floor still applies before layer-1 (operator floor wins)", async () => {
    let called = false;
    const svc = makeService(
      { policyEnabled: true, policyPerTxMaxWei: "100", policyRegistryAddress: REGISTRY },
      async () => {
        called = true;
        return { decision: 0, remainingDaily: 0n };
      }
    );
    const d = await svc.evaluate(userOpWith(executeCallData(RECIPIENT, 999n)));
    expect(d.allowed).toBe(false);
    expect(d.reason).toMatch(/exceeds perTxMaxWei/);
    expect(called).toBe(false); // layer-2 rejected before consulting the chain
  });
});
