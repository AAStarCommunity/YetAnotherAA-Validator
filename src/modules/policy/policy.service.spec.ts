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

/** Minimal ConfigService stub returning policy config by key. */
function makeService(config: Record<string, unknown>): PolicyService {
  const configService = {
    get: (key: string) => config[key],
  } as any;
  return new PolicyService(configService);
}

describe("PolicyService — DVT independent policy gate (Fix 2 Stage 2)", () => {
  it("allows everything when disabled (preserves Stage 1 behavior)", () => {
    const svc = makeService({ policyEnabled: false });
    // even garbage callData passes when the gate is off
    expect(svc.evaluate(userOpWith("0xdeadbeef")).allowed).toBe(true);
  });

  it("allows an execute() within the per-tx limit", () => {
    const svc = makeService({ policyEnabled: true, policyPerTxMaxWei: "1000000000000000000" });
    const op = userOpWith(executeCallData(RECIPIENT, 5n));
    expect(svc.evaluate(op).allowed).toBe(true);
  });

  it("rejects an execute() above the per-tx limit", () => {
    const svc = makeService({ policyEnabled: true, policyPerTxMaxWei: "100" });
    const op = userOpWith(executeCallData(RECIPIENT, 101n));
    const d = svc.evaluate(op);
    expect(d.allowed).toBe(false);
    expect(d.reason).toMatch(/exceeds perTxMaxWei/);
  });

  it("rejects a recipient outside the allowlist", () => {
    const svc = makeService({ policyEnabled: true, policyRecipientAllowlist: [RECIPIENT] });
    const op = userOpWith(executeCallData(OTHER, 0n));
    const d = svc.evaluate(op);
    expect(d.allowed).toBe(false);
    expect(d.reason).toMatch(/not in allowlist/);
  });

  it("allows a recipient inside the allowlist (case-insensitive)", () => {
    const svc = makeService({
      policyEnabled: true,
      policyRecipientAllowlist: [RECIPIENT.toUpperCase()],
    });
    const op = userOpWith(executeCallData(RECIPIENT, 0n));
    expect(svc.evaluate(op).allowed).toBe(true);
  });

  it("enforces the limit against EVERY call in executeBatch", () => {
    const svc = makeService({ policyEnabled: true, policyPerTxMaxWei: "100" });
    const op = userOpWith(executeBatchCallData([RECIPIENT, OTHER], [10n, 999n]));
    const d = svc.evaluate(op);
    expect(d.allowed).toBe(false);
    expect(d.reason).toMatch(/call\[1\]/);
  });

  it("fails closed on undecodable callData when enabled", () => {
    const svc = makeService({ policyEnabled: true, policyPerTxMaxWei: "100" });
    const d = svc.evaluate(userOpWith("0xdeadbeef"));
    expect(d.allowed).toBe(false);
    expect(d.reason).toMatch(/unsupported callData selector|undecodable/);
  });

  it("fails closed on an empty/malformed callData when enabled", () => {
    const svc = makeService({ policyEnabled: true });
    expect(svc.evaluate(userOpWith("0x")).allowed).toBe(false);
  });
});
