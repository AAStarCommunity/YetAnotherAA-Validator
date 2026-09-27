import { jest } from "@jest/globals";
import { NodeKeyConsistencyService } from "./node-key-consistency.service.js";
import { bls, sigs } from "../../utils/bls.util.js";
import { NodeState } from "../../interfaces/node.interface.js";
import { BlockchainService } from "../blockchain/blockchain.service.js";
import { BlsService } from "../bls/bls.service.js";

/**
 * A real BlsService — NOT a mock — used purely for its `encodePublicKeyToEIP2537` (a pure
 * function of its argument; it reads none of the injected BlockchainService/SignerService
 * state). Fixtures are built with the exact same encoder the check itself is required to
 * use (CC-36 round-2 review), so "ok" here means byte-identical agreement with what
 * `registerOnChain()` actually writes on-chain — not agreement with a second, possibly
 * drifted, re-implementation.
 */
const realBls = new BlsService({} as any, {} as any);

/**
 * Real BLS keypairs (not hardcoded fixtures) so every fixture is internally
 * consistent by construction, and mismatches are constructed by mixing two
 * distinct, genuinely-derived keypairs — never by hand-editing hex.
 */
function makeKeyPair(seed: number) {
  const privBytes = new Uint8Array(32);
  privBytes[31] = seed;
  const privateKey = "0x" + Buffer.from(privBytes).toString("hex");
  const pub = sigs.getPublicKey(privBytes);
  const compressedHex = "0x" + pub.toHex(); // node_state.publicKey format (48-byte compressed)
  const point = bls.G1.Point.fromHex(pub.toHex());
  const eip2537Hex = realBls.encodePublicKeyToEIP2537(point); // on-chain format (128-byte)
  return { privateKey, compressedHex, eip2537Hex };
}

const KEY_A = makeKeyPair(1);
const KEY_B = makeKeyPair(2);

function baseNodeState(overrides: Partial<NodeState> = {}): NodeState {
  return {
    nodeId: "0x" + "ab".repeat(32),
    nodeName: "test-node",
    privateKey: KEY_A.privateKey,
    publicKey: KEY_A.compressedHex,
    createdAt: new Date(0).toISOString(),
    description: "test",
    ...overrides,
  };
}

function makeBlockchainMock(overrides: {
  checkNodeRegistration?: () => Promise<boolean>;
  getNodePublicKey?: () => Promise<string>;
}): BlockchainService {
  return {
    checkNodeRegistration: jest.fn(
      overrides.checkNodeRegistration ?? (() => Promise.resolve(false))
    ),
    getNodePublicKey: jest.fn(overrides.getNodePublicKey ?? (() => Promise.resolve("0x"))),
  } as unknown as BlockchainService;
}

describe("NodeKeyConsistencyService (CC-36)", () => {
  it("ok: local privateKey derives publicKey AND on-chain registeredKeys matches", async () => {
    const chain = makeBlockchainMock({
      checkNodeRegistration: () => Promise.resolve(true),
      getNodePublicKey: () => Promise.resolve(KEY_A.eip2537Hex),
    });
    const service = new NodeKeyConsistencyService(chain, realBls);
    const result = await service.check(baseNodeState(), "0xcontract");
    expect(result.status).toBe("ok");
    expect(service.getLastResult()).toEqual(result);
  });

  it("mismatch_local: privateKey does NOT derive node_state.publicKey", async () => {
    const chain = makeBlockchainMock({
      checkNodeRegistration: () => Promise.resolve(true),
      getNodePublicKey: () => Promise.resolve(KEY_A.eip2537Hex),
    });
    const service = new NodeKeyConsistencyService(chain, realBls);
    // privateKey is A's, but publicKey on disk is B's — a corrupted/swapped node_state.
    const state = baseNodeState({ publicKey: KEY_B.compressedHex });
    const result = await service.check(state, "0xcontract");
    expect(result.status).toBe("mismatch_local");
  });

  it("mismatch_onchain: registered, but registeredKeys() differs from local publicKey — the silent failure", async () => {
    const chain = makeBlockchainMock({
      checkNodeRegistration: () => Promise.resolve(true),
      getNodePublicKey: () => Promise.resolve(KEY_B.eip2537Hex), // someone else's key is registered
    });
    const service = new NodeKeyConsistencyService(chain, realBls);
    const result = await service.check(baseNodeState(), "0xcontract");
    expect(result.status).toBe("mismatch_onchain");
  });

  it("not_registered: isRegistered() false is informational, NOT a failure", async () => {
    const chain = makeBlockchainMock({
      checkNodeRegistration: () => Promise.resolve(false),
    });
    const service = new NodeKeyConsistencyService(chain, realBls);
    const result = await service.check(baseNodeState(), "0xcontract");
    expect(result.status).toBe("not_registered");
    // getNodePublicKey must not even be consulted once we know it's unregistered.
    expect(chain.getNodePublicKey).not.toHaveBeenCalled();
  });

  it("unknown: an RPC error must NEVER collapse to mismatch_onchain or ok", async () => {
    const chain = makeBlockchainMock({});
    (chain.checkNodeRegistration as jest.Mock).mockRejectedValueOnce(
      new Error("RPC timeout") as never
    );
    const service = new NodeKeyConsistencyService(chain, realBls);
    const result = await service.check(baseNodeState(), "0xcontract");
    expect(result.status).toBe("unknown");
  });

  it("unknown: a getNodePublicKey RPC error (registered, but read fails) also stays unknown, not a mismatch", async () => {
    const chain = makeBlockchainMock({
      checkNodeRegistration: () => Promise.resolve(true),
    });
    (chain.getNodePublicKey as jest.Mock).mockRejectedValueOnce(
      new Error("RPC timeout") as never
    );
    const service = new NodeKeyConsistencyService(chain, realBls);
    const result = await service.check(baseNodeState(), "0xcontract");
    expect(result.status).toBe("unknown");
  });

  it("skipped_no_private_key: key-less (KMS-TEE) node with a clean on-chain match is NOT reported ok", async () => {
    const chain = makeBlockchainMock({
      checkNodeRegistration: () => Promise.resolve(true),
      getNodePublicKey: () => Promise.resolve(KEY_A.eip2537Hex),
    });
    const service = new NodeKeyConsistencyService(chain, realBls);
    const state = baseNodeState();
    delete (state as Partial<NodeState>).privateKey;
    const result = await service.check(state, "0xcontract");
    expect(result.status).toBe("skipped_no_private_key");
  });

  it("skipped_no_private_key still surfaces a real on-chain problem instead of masking it", async () => {
    const chain = makeBlockchainMock({
      checkNodeRegistration: () => Promise.resolve(true),
      getNodePublicKey: () => Promise.resolve(KEY_B.eip2537Hex),
    });
    const service = new NodeKeyConsistencyService(chain, realBls);
    const state = baseNodeState();
    delete (state as Partial<NodeState>).privateKey;
    const result = await service.check(state, "0xcontract");
    expect(result.status).toBe("mismatch_onchain");
  });

  it("REGRESSION: a bootstrap-registered node (nodeId !== keccak256(pubkey)) is still `ok`, never a mismatch", async () => {
    // registerPublicKey(nodeId, publicKey) (the old bootstrap path) lets the caller pick ANY
    // nodeId — it is NOT required to be keccak256(publicKey). This guards against someone
    // later "upgrading" derivedMatches into a consistency judgment by mistake.
    const chain = makeBlockchainMock({
      checkNodeRegistration: () => Promise.resolve(true),
      getNodePublicKey: () => Promise.resolve(KEY_A.eip2537Hex),
    });
    const service = new NodeKeyConsistencyService(chain, realBls);
    const bootstrapNodeId = "0x" + "11".repeat(32); // deliberately NOT keccak256(KEY_A.eip2537Hex)
    const state = baseNodeState({ nodeId: bootstrapNodeId });
    const result = await service.check(state, "0xcontract");
    expect(result.status).toBe("ok");
    expect(result.derivedMatches).toBe(false);
    expect(result.nodeId).toBe(bootstrapNodeId);
  });

  it("derivedMatches is true when nodeId genuinely is keccak256(EIP-2537 publicKey)", async () => {
    const { ethers } = await import("ethers");
    const derivedNodeId = ethers.keccak256(KEY_A.eip2537Hex);
    const chain = makeBlockchainMock({
      checkNodeRegistration: () => Promise.resolve(true),
      getNodePublicKey: () => Promise.resolve(KEY_A.eip2537Hex),
    });
    const service = new NodeKeyConsistencyService(chain, realBls);
    const result = await service.check(baseNodeState({ nodeId: derivedNodeId }), "0xcontract");
    expect(result.status).toBe("ok");
    expect(result.derivedMatches).toBe(true);
  });

  it("hex comparisons are case/prefix-insensitive (0x vs bare, upper vs lower)", async () => {
    const chain = makeBlockchainMock({
      checkNodeRegistration: () => Promise.resolve(true),
      // Same bytes as KEY_A.eip2537Hex, but uppercase and without the 0x prefix.
      getNodePublicKey: () => Promise.resolve(KEY_A.eip2537Hex.slice(2).toUpperCase()),
    });
    const service = new NodeKeyConsistencyService(chain, realBls);
    const result = await service.check(baseNodeState(), "0xcontract");
    expect(result.status).toBe("ok");
  });

  it("uses BlsService.encodePublicKeyToEIP2537 — NOT a local re-implementation — to encode for the on-chain comparison (CC-36 round 2)", async () => {
    // A stub BlsService that returns an unmistakable sentinel instead of a real encoding.
    // If the check ever reverted to a local re-implementation of the encoder (ignoring the
    // injected BlsService), this stub's output would never be consulted, the comparison
    // would use the REAL encoding instead, `getNodePublicKey`'s sentinel wouldn't match it,
    // and this test would go red on "ok" -> "mismatch_onchain".
    const sentinelEip2537 = "0x" + "ee".repeat(128);
    const encodeSpy = jest.fn(() => sentinelEip2537);
    const stubBls = { encodePublicKeyToEIP2537: encodeSpy } as unknown as BlsService;
    const chain = makeBlockchainMock({
      checkNodeRegistration: () => Promise.resolve(true),
      getNodePublicKey: () => Promise.resolve(sentinelEip2537),
    });
    const service = new NodeKeyConsistencyService(chain, stubBls);
    const result = await service.check(baseNodeState(), "0xcontract");
    expect(encodeSpy).toHaveBeenCalled();
    expect(result.status).toBe("ok");
  });

  it("a mismatch is still correctly detected when the STUB encoder disagrees with the on-chain read", async () => {
    // Same stub as above, but getNodePublicKey now returns something OTHER than the stub's
    // sentinel — proves the comparison is actually USING the injected BlsService's output
    // (not, say, ignoring it and always returning ok).
    const sentinelEip2537 = "0x" + "ee".repeat(128);
    const stubBls = {
      encodePublicKeyToEIP2537: jest.fn(() => sentinelEip2537),
    } as unknown as BlsService;
    const chain = makeBlockchainMock({
      checkNodeRegistration: () => Promise.resolve(true),
      getNodePublicKey: () => Promise.resolve("0x" + "11".repeat(128)),
    });
    const service = new NodeKeyConsistencyService(chain, stubBls);
    const result = await service.check(baseNodeState(), "0xcontract");
    expect(result.status).toBe("mismatch_onchain");
  });
});
