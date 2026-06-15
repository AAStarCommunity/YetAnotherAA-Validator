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

/** Build callData for execute() wrapping an ERC-20 transfer(to, amount) on `token`. */
function erc20TransferCallData(token: string, to: string, amount: bigint): string {
  const transferSel = ethers.id("transfer(address,uint256)").slice(0, 10);
  const innerFunc = transferSel + coder.encode(["address", "uint256"], [to, amount]).slice(2);
  const exec = ethers.id("execute(address,uint256,bytes)").slice(0, 10);
  return exec + coder.encode(["address", "uint256", "bytes"], [token, 0n, innerFunc]).slice(2);
}

/** Build callData for execute() wrapping an ERC-20 approve(spender, amount) on `token`. */
function erc20ApproveCallData(token: string, spender: string, amount: bigint): string {
  const approveSel = ethers.id("approve(address,uint256)").slice(0, 10);
  const innerFunc = approveSel + coder.encode(["address", "uint256"], [spender, amount]).slice(2);
  const exec = ethers.id("execute(address,uint256,bytes)").slice(0, 10);
  return exec + coder.encode(["address", "uint256", "bytes"], [token, 0n, innerFunc]).slice(2);
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
    expect(d.reason).toMatch(/decision = 2|not ALLOW/);
  });

  it("fails closed on an UNKNOWN registry decision, not just REJECT [Codex F4]", async () => {
    const svc = makeService({ policyEnabled: true, policyRegistryAddress: REGISTRY }, async () => ({
      decision: 3, // future REQUIRE_EXTRA / garbage — must NOT be treated as allow (fail-open)
      remainingDaily: 0n,
    }));
    const d = await svc.evaluate(userOpWith(executeCallData(RECIPIENT, 5n)));
    expect(d.allowed).toBe(false);
    expect(d.reason).toMatch(/not ALLOW/);
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

  it("extracts ERC-20 transfer amount/asset/recipient from inner calldata", async () => {
    const TOKEN = "0x" + "cc".repeat(20);
    const seen: any[] = [];
    const svc = makeService(
      { policyEnabled: true, policyRegistryAddress: REGISTRY },
      async (_registry, _sender, target, asset, amount) => {
        seen.push({ target, asset, amount });
        return { decision: 1, remainingDaily: 0n };
      }
    );
    // execute(TOKEN, 0, transfer(RECIPIENT, 1_000_000)) — native value is 0.
    await svc.evaluate(userOpWith(erc20TransferCallData(TOKEN, RECIPIENT, 1_000_000n)));
    expect(seen[0].asset.toLowerCase()).toBe(TOKEN.toLowerCase()); // asset = the token
    expect(seen[0].amount).toBe(1_000_000n); // amount from calldata, NOT 0
    expect(seen[0].target.toLowerCase()).toBe(RECIPIENT.toLowerCase()); // real recipient
  });

  it("captures ERC-20 approve(spender, amount) so allowances are gated [Codex F7]", async () => {
    const TOKEN = "0x" + "cc".repeat(20);
    const SPENDER = "0x" + "dd".repeat(20);
    const seen: any[] = [];
    const svc = makeService(
      { policyEnabled: true, policyRegistryAddress: REGISTRY },
      async (_registry, _sender, target, asset, amount) => {
        seen.push({ target, asset, amount });
        return { decision: 1, remainingDaily: 0n };
      }
    );
    await svc.evaluate(userOpWith(erc20ApproveCallData(TOKEN, SPENDER, 999_999n)));
    expect(seen[0].asset.toLowerCase()).toBe(TOKEN.toLowerCase());
    expect(seen[0].amount).toBe(999_999n); // approved amount gated, not 0
    expect(seen[0].target.toLowerCase()).toBe(SPENDER.toLowerCase());
  });

  it("layer-2 allowlist checks the REAL ERC-20 recipient, not the token contract [Codex F3]", async () => {
    const TOKEN = "0x" + "cc".repeat(20); // token contract NOT in allowlist
    // allowlist only RECIPIENT — a transfer to RECIPIENT must pass (recipient allowlisted),
    // a transfer to OTHER must fail, even though both call the same (non-listed) token.
    const allow = makeService({ policyEnabled: true, policyRecipientAllowlist: [RECIPIENT] });
    expect(
      (await allow.evaluate(userOpWith(erc20TransferCallData(TOKEN, RECIPIENT, 1n)))).allowed
    ).toBe(true);
    const deny = makeService({ policyEnabled: true, policyRecipientAllowlist: [RECIPIENT] });
    const d = await deny.evaluate(userOpWith(erc20TransferCallData(TOKEN, OTHER, 1n)));
    expect(d.allowed).toBe(false);
    expect(d.reason).toMatch(/not in allowlist/);
  });

  it("REJECTs an over-limit ERC-20 transfer that amount=0 would have missed", async () => {
    const TOKEN = "0x" + "cc".repeat(20);
    const svc = makeService(
      { policyEnabled: true, policyRegistryAddress: REGISTRY },
      async (_r, _s, _t, _a, amount) => ({
        decision: amount > 500_000n ? 2 : 1, // registry rejects over-cap token spend
        remainingDaily: 0n,
      })
    );
    const d = await svc.evaluate(userOpWith(erc20TransferCallData(TOKEN, RECIPIENT, 1_000_000n)));
    expect(d.allowed).toBe(false);
    expect(d.reason).toMatch(/decision = 2|not ALLOW/);
  });

  it("fails closed on a malformed ERC-20 transfer payload", async () => {
    const TOKEN = "0x" + "cc".repeat(20);
    const exec = ethers.id("execute(address,uint256,bytes)").slice(0, 10);
    const transferSel = ethers.id("transfer(address,uint256)").slice(0, 10);
    // transfer selector but truncated args → decode throws → fail-closed
    const badInner = transferSel + "00";
    const callData =
      exec + coder.encode(["address", "uint256", "bytes"], [TOKEN, 0n, badInner]).slice(2);
    const svc = makeService({ policyEnabled: true, policyRegistryAddress: REGISTRY }, async () => ({
      decision: 1,
      remainingDaily: 0n,
    }));
    const d = await svc.evaluate(userOpWith(callData));
    expect(d.allowed).toBe(false);
    expect(d.reason).toMatch(/undecodable transfer/);
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
