import { jest } from "@jest/globals";
import { NodeKeyConsistencyService } from "./node-key-consistency.service.js";
import { bls, sigs } from "../../utils/bls.util.js";
import { NodeState } from "../../interfaces/node.interface.js";
import { BlockchainService } from "../blockchain/blockchain.service.js";
import { BlsService } from "../bls/bls.service.js";
import { SignerService } from "../signer/signer.service.js";
import { ConfigService } from "@nestjs/config";

function makeConfig(overrides: Record<string, unknown> = {}): ConfigService {
  return { get: (k: string) => overrides[k] } as unknown as ConfigService;
}

/**
 * A real SignerService (round-2 Medium-5) — resolves to `LocalKeySigner` under the default
 * "local" backend — so the local branch of `BlsService.resolveSigningPublicKey` derives keys
 * through the EXACT validation the node signs with, never a separate hex re-parse.
 */
const realSigner = new SignerService(makeConfig());

/**
 * A real BlsService — NOT a mock — built with `realSigner` and a controllable config, so
 * `resolveSigningPublicKey` (round-3 High-2) exercises the SAME signer-selection logic
 * `signDerivedHash()` uses. Fixtures are built with the exact same `encodePublicKeyToEIP2537`
 * encoder the check itself is required to use (round-2 review), so "ok" here means
 * byte-identical agreement with what `registerOnChain()` actually writes on-chain — not
 * agreement with a second, possibly drifted, re-implementation.
 */
function makeBls(configOverrides: Record<string, unknown> = {}): BlsService {
  return new BlsService({} as any, realSigner, makeConfig(configOverrides));
}
const realBls = makeBls(); // no rustSignerUrl -> local signer selection (the common case)

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
  const eip2537Hex = realBls.encodePublicKeyToEIP2537(point); // on-chain / dashboard-create format (128-byte)
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
  getBlockNumber?: () => Promise<number>;
}): BlockchainService {
  return {
    checkNodeRegistration: jest.fn(
      overrides.checkNodeRegistration ?? (() => Promise.resolve(false))
    ),
    getNodePublicKey: jest.fn(overrides.getNodePublicKey ?? (() => Promise.resolve("0x"))),
    // Round-6 M1: checkOnchain() pins both reads to one block — every test gets a fixed
    // default so existing assertions (which predate the blockTag param) are unaffected.
    getBlockNumber: jest.fn(overrides.getBlockNumber ?? (() => Promise.resolve(12345))),
  } as unknown as BlockchainService;
}

function makeService(chain: BlockchainService, blsService: BlsService = realBls) {
  return new NodeKeyConsistencyService(chain, blsService);
}

describe("NodeKeyConsistencyService (CC-36)", () => {
  it("ok: local privateKey derives publicKey AND on-chain registeredKeys matches", async () => {
    const chain = makeBlockchainMock({
      checkNodeRegistration: () => Promise.resolve(true),
      getNodePublicKey: () => Promise.resolve(KEY_A.eip2537Hex),
    });
    const service = makeService(chain);
    const result = await service.check(baseNodeState(), "0xcontract");
    expect(result.status).toBe("ok");
    expect(service.getLastResult()).toEqual(result);
  });

  it("mismatch_local: privateKey does NOT derive node_state.publicKey", async () => {
    const chain = makeBlockchainMock({
      checkNodeRegistration: () => Promise.resolve(true),
      getNodePublicKey: () => Promise.resolve(KEY_A.eip2537Hex),
    });
    const service = makeService(chain);
    // privateKey is A's, but publicKey on disk is B's — a corrupted/swapped node_state.
    const state = baseNodeState({ publicKey: KEY_B.compressedHex });
    const result = await service.check(state, "0xcontract");
    expect(result.status).toBe("mismatch_local");
  });

  it("MEDIUM-5 regression: a private key the REAL signer would reject must NOT be reported ok", async () => {
    // LocalKeySigner requires exactly 64 hex chars, all valid hex digits. An odd-length /
    // non-hex-char key is something the node itself could never sign with — the check must
    // agree, not silently coerce it (e.g. via parseInt-NaN -> 0) into a false "ok".
    const chain = makeBlockchainMock({
      checkNodeRegistration: () => Promise.resolve(true),
      getNodePublicKey: () => Promise.resolve(KEY_A.eip2537Hex),
    });
    const service = makeService(chain);
    const state = baseNodeState({ privateKey: "0x" + "zz".repeat(32) }); // non-hex chars
    const result = await service.check(state, "0xcontract");
    expect(result.status).not.toBe("ok");
    expect(result.status).toBe("mismatch_local");
  });

  it("MEDIUM-5: an uppercase 0X-prefixed private key (which LocalKeySigner rejects) is NOT reported ok", async () => {
    // LocalKeySigner's `startsWith("0x")` check is case-sensitive, so an uppercase "0X" prefix
    // is NOT stripped and the remaining string fails the 64-hex-char regex — the real signer
    // throws. A check that case-insensitively strips "0x" before validating would disagree.
    const chain = makeBlockchainMock({
      checkNodeRegistration: () => Promise.resolve(true),
      getNodePublicKey: () => Promise.resolve(KEY_A.eip2537Hex),
    });
    const service = makeService(chain);
    const upper = "0X" + KEY_A.privateKey.slice(2);
    const state = baseNodeState({ privateKey: upper });
    const result = await service.check(state, "0xcontract");
    expect(result.status).not.toBe("ok");
  });

  it("mismatch_onchain: registered, but registeredKeys() differs from local publicKey — the silent failure", async () => {
    const chain = makeBlockchainMock({
      checkNodeRegistration: () => Promise.resolve(true),
      getNodePublicKey: () => Promise.resolve(KEY_B.eip2537Hex), // someone else's key is registered
    });
    const service = makeService(chain);
    const result = await service.check(baseNodeState(), "0xcontract");
    expect(result.status).toBe("mismatch_onchain");
  });

  it("not_registered: isRegistered() false is informational, NOT a failure", async () => {
    const chain = makeBlockchainMock({
      checkNodeRegistration: () => Promise.resolve(false),
    });
    const service = makeService(chain);
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
    const service = makeService(chain);
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
    const service = makeService(chain);
    const result = await service.check(baseNodeState(), "0xcontract");
    expect(result.status).toBe("unknown");
  });

  it("skipped_no_private_key: key-less (KMS-TEE) node with a clean on-chain match is NOT reported ok", async () => {
    const chain = makeBlockchainMock({
      checkNodeRegistration: () => Promise.resolve(true),
      getNodePublicKey: () => Promise.resolve(KEY_A.eip2537Hex),
    });
    const service = makeService(chain);
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
    const service = makeService(chain);
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
    const service = makeService(chain);
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
    const service = makeService(chain);
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
    const service = makeService(chain);
    const result = await service.check(baseNodeState(), "0xcontract");
    expect(result.status).toBe("ok");
  });

  it("uses BlsService.encodePublicKeyToEIP2537 — NOT a local re-implementation — to encode for the on-chain comparison (CC-36 round 2)", async () => {
    // A stub BlsService that returns an unmistakable sentinel instead of a real encoding
    // (resolveSigningPublicKey is delegated to the real realBls instance so the LOCAL branch
    // still works normally — only the encoder is stubbed). If the check ever reverted to a
    // local re-implementation of the encoder (ignoring the injected BlsService), this stub's
    // output would never be consulted, the comparison would use the REAL encoding instead,
    // getNodePublicKey's sentinel wouldn't match it, and this test would go red on
    // "ok" -> "mismatch_onchain".
    const sentinelEip2537 = "0x" + "ee".repeat(128);
    const encodeSpy = jest.fn(() => sentinelEip2537);
    const stubBls = {
      encodePublicKeyToEIP2537: encodeSpy,
      resolveSigningPublicKey: realBls.resolveSigningPublicKey.bind(realBls),
    } as unknown as BlsService;
    const chain = makeBlockchainMock({
      checkNodeRegistration: () => Promise.resolve(true),
      getNodePublicKey: () => Promise.resolve(sentinelEip2537),
    });
    const service = makeService(chain, stubBls);
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
      resolveSigningPublicKey: realBls.resolveSigningPublicKey.bind(realBls),
    } as unknown as BlsService;
    const chain = makeBlockchainMock({
      checkNodeRegistration: () => Promise.resolve(true),
      getNodePublicKey: () => Promise.resolve("0x" + "11".repeat(128)),
    });
    const service = makeService(chain, stubBls);
    const result = await service.check(baseNodeState(), "0xcontract");
    expect(result.status).toBe("mismatch_onchain");
  });

  describe("HIGH-1: node_state.publicKey may legitimately be 128-byte EIP-2537 (dashboard.service.ts create path)", () => {
    it("a dashboard-created node (128-byte publicKey on disk) is reported ok, not mismatch_local", async () => {
      // dashboard.service.ts's createNode() stores `publicKey =
      // this.blsService.encodePublicKeyToEIP2537(publicKeyPoint)` — the FULL 128-byte form —
      // in node_state.json, never the 48-byte compressed form a signing node normally has.
      const chain = makeBlockchainMock({
        checkNodeRegistration: () => Promise.resolve(true),
        getNodePublicKey: () => Promise.resolve(KEY_A.eip2537Hex),
      });
      const service = makeService(chain);
      const state = baseNodeState({ publicKey: KEY_A.eip2537Hex }); // 128 bytes, not compressed
      const result = await service.check(state, "0xcontract");
      expect(result.status).toBe("ok");
    });

    it("a 128-byte publicKey still correctly detects a REAL mismatch (not a blanket pass)", async () => {
      const chain = makeBlockchainMock({
        checkNodeRegistration: () => Promise.resolve(true),
        getNodePublicKey: () => Promise.resolve(KEY_A.eip2537Hex),
      });
      const service = makeService(chain);
      // privateKey is A's, but the 128-byte publicKey on disk is B's.
      const state = baseNodeState({ publicKey: KEY_B.eip2537Hex });
      const result = await service.check(state, "0xcontract");
      expect(result.status).toBe("mismatch_local");
    });

    it("on-chain comparison also works when node_state.publicKey is 128-byte (round-trips through the same encoder)", async () => {
      const chain = makeBlockchainMock({
        checkNodeRegistration: () => Promise.resolve(true),
        getNodePublicKey: () => Promise.resolve(KEY_B.eip2537Hex), // a DIFFERENT key registered
      });
      const service = makeService(chain);
      const state = baseNodeState({ publicKey: KEY_A.eip2537Hex, privateKey: KEY_A.privateKey });
      const result = await service.check(state, "0xcontract");
      expect(result.status).toBe("mismatch_onchain");
    });

    it("derivedMatches is computed correctly for a 128-byte publicKey too", async () => {
      const { ethers } = await import("ethers");
      const derivedNodeId = ethers.keccak256(KEY_A.eip2537Hex);
      const chain = makeBlockchainMock({
        checkNodeRegistration: () => Promise.resolve(true),
        getNodePublicKey: () => Promise.resolve(KEY_A.eip2537Hex),
      });
      const service = makeService(chain);
      const state = baseNodeState({ publicKey: KEY_A.eip2537Hex, nodeId: derivedNodeId });
      const result = await service.check(state, "0xcontract");
      expect(result.derivedMatches).toBe(true);
    });

    it("a malformed 128-byte-length publicKey (not a real point) is rejected, not silently accepted", async () => {
      const chain = makeBlockchainMock({
        checkNodeRegistration: () => Promise.resolve(true),
      });
      const service = makeService(chain);
      // Right length (256 hex chars) but NOT a valid curve point (all zero x, all-ones y — off
      // curve, and the padding is non-zero too). Must be rejected rather than @noble/curves
      // silently accepting it.
      const bogus = "0x" + "00".repeat(64) + "ff".repeat(64);
      const state = baseNodeState({ publicKey: bogus, privateKey: undefined as any });
      const result = await service.check(state, "0xcontract");
      // No private key (skipped local) and the bogus on-chain-format key can't be parsed ->
      // checkOnchain must say "unknown" (never guess ok/mismatch for something unparsable).
      expect(result.status).toBe("unknown");
    });

    it("HIGH-1.1: non-zero padding is rejected as malformed, not silently normalized (round 3)", async () => {
      // Flip only the FIRST padding nibble (byte offset 0, which must be zero in a real
      // EIP-2537 encoding) from '0' to '1'. X and Y are untouched — WITHOUT a padding check,
      // this would still parse to the exact same point as KEY_A.eip2537Hex and report "ok".
      const body = KEY_A.eip2537Hex.slice(2);
      const mutated = "0x1" + body.slice(1);
      const chain = makeBlockchainMock({
        checkNodeRegistration: () => Promise.resolve(true),
        getNodePublicKey: () => Promise.resolve(KEY_A.eip2537Hex), // the CORRECTLY-encoded key
      });
      const service = makeService(chain);
      const state = baseNodeState({ publicKey: mutated, privateKey: undefined as any });
      const result = await service.check(state, "0xcontract");
      expect(result.status).not.toBe("ok");
      expect(result.status).toBe("unknown"); // can't parse the local (malformed) key to compare
    });

    it("HIGH-1.2: the point-at-infinity (128-byte all-zero) is rejected, NEVER reported ok — the rogue-key bypass registerWithProof guards against on-chain", async () => {
      const infinityKey = "0x" + "00".repeat(128);
      const chain = makeBlockchainMock({
        checkNodeRegistration: () => Promise.resolve(true),
        // Adversarially assume the chain ALSO somehow has the same (it shouldn't, but even so
        // this must never be reported ok).
        getNodePublicKey: () => Promise.resolve(infinityKey),
      });
      const service = makeService(chain);
      const state = baseNodeState({ publicKey: infinityKey, privateKey: undefined as any });
      const result = await service.check(state, "0xcontract");
      expect(result.status).not.toBe("ok");
      expect(result.status).toBe("unknown"); // infinity is rejected -> unparsable -> can't compare
    });

    it("HIGH-1.2b: the point-at-infinity (compressed 48-byte canonical encoding) is rejected too", async () => {
      // Canonical BLS12-381 compressed-infinity: compression flag (0x80) | infinity flag
      // (0x40) on the first byte, all remaining bytes zero. @noble/curves' assertValidity()
      // ALONE does not reject this (it's a mathematically valid group-identity point) — only
      // an explicit .is0() check does.
      const bytes = new Uint8Array(48);
      bytes[0] = 0xc0;
      const infinityCompressed = "0x" + Buffer.from(bytes).toString("hex");
      const chain = makeBlockchainMock({
        checkNodeRegistration: () => Promise.resolve(true),
        // A REAL registered key (not another all-zero value) — if the infinity guard were
        // missing, encoding the (wrongly-accepted) infinity point would ALSO produce all-zero
        // 128 bytes, and comparing that against an all-zero on-chain value would coincidentally
        // still read "not ok" (skipped_no_private_key) for the WRONG reason, masking the bug.
        getNodePublicKey: () => Promise.resolve(KEY_A.eip2537Hex),
      });
      const service = makeService(chain);
      const state = baseNodeState({ publicKey: infinityCompressed, privateKey: undefined as any });
      const result = await service.check(state, "0xcontract");
      expect(result.status).not.toBe("ok");
      expect(result.status).toBe("unknown"); // infinity rejected -> unparsable -> can't compare
    });
  });

  describe("M1 (round 6): isRegistered and registeredKeys must be read at the SAME blockTag — never two independent `latest` reads", () => {
    it("both on-chain reads receive the identical blockTag returned by getBlockNumber()", async () => {
      const seen: { isRegistered: (number | undefined)[]; registeredKeys: (number | undefined)[] } =
        { isRegistered: [], registeredKeys: [] };
      const chain = {
        getBlockNumber: jest.fn(() => Promise.resolve(100)),
        checkNodeRegistration: jest.fn((_addr: string, _id: string, blockTag?: number) => {
          seen.isRegistered.push(blockTag);
          return Promise.resolve(true);
        }),
        getNodePublicKey: jest.fn((_addr: string, _id: string, blockTag?: number) => {
          seen.registeredKeys.push(blockTag);
          return Promise.resolve(KEY_A.eip2537Hex);
        }),
      } as unknown as BlockchainService;
      const service = makeService(chain);
      await service.check(baseNodeState(), "0xcontract");
      expect(seen.isRegistered).toEqual([100]);
      expect(seen.registeredKeys).toEqual([100]);
      expect(chain.getBlockNumber).toHaveBeenCalledTimes(1); // one shared read, not two
    });

    it("REGRESSION: a node deactivated between the two reads (syncNode race) never surfaces as mismatch_onchain — a status that was never actually true", async () => {
      // Simulate: at block 100 the node is registered with the correct key; by block 101
      // (one block later) syncNode() deactivated it and cleared registeredKeys. Pinning both
      // reads to ONE getBlockNumber() call means both see the consistent block-100 snapshot
      // (registered + correct key -> ok), never the impossible "registered + empty key" blend
      // a pair of independent `latest` reads straddling the transition could produce.
      const chain = {
        getBlockNumber: jest.fn(() => Promise.resolve(100)),
        checkNodeRegistration: jest.fn((_addr: string, _id: string, blockTag?: number) =>
          Promise.resolve(blockTag === 100) // true only "as of block 100"
        ),
        getNodePublicKey: jest.fn((_addr: string, _id: string, blockTag?: number) =>
          Promise.resolve(blockTag === 100 ? KEY_A.eip2537Hex : "0x") // empty "as of block 101+"
        ),
      } as unknown as BlockchainService;
      const service = makeService(chain);
      const result = await service.check(baseNodeState(), "0xcontract");
      expect(result.status).toBe("ok");
    });

    it("defense-in-depth: an empty registeredKeys() return is treated as not_registered, never mismatch_onchain, even if isRegistered() somehow still said true", async () => {
      const chain = makeBlockchainMock({
        checkNodeRegistration: () => Promise.resolve(true),
        getNodePublicKey: () => Promise.resolve("0x"), // empty bytes
      });
      const service = makeService(chain);
      const result = await service.check(baseNodeState(), "0xcontract");
      expect(result.status).toBe("not_registered");
    });
  });

  describe("HIGH-2: signer selection must match the REAL signing path (local @noble/curves vs. remote Rust/TEE-KMS)", () => {
    // Round-4 correction (coordinator + Codex): an earlier version of this check PROBED the
    // remote signer's /sign endpoint to read its public key back. That was rejected — it
    // makes a background health check itself produce a real, unauthorized signature (see
    // BlsService.resolveSigningPublicKey's docstring). No probe, no network call, ever.
    //
    // Round-7 correction (coordinator + Codex): round-4/5 then made ANY remote config —
    // required OR optional — collapse to skipped_remote_signer unconditionally. That itself
    // was a gap: in OPTIONAL mode, signDerivedHash() SILENTLY FALLS BACK to the local
    // privateKey whenever the remote call fails, so the local key is a REAL signing key that
    // must be verified — skipping it left exactly the silent-failure gap this check exists to
    // close (see the "silent failure" test below, which replaces the round-4/5 test that used
    // to pin this unsafe behavior). Required mode has no fallback path, so it still skips.
    const originalFetch = global.fetch;
    afterEach(() => {
      global.fetch = originalFetch;
    });

    it("REQUIRED mode: skipped_remote_signer regardless of what node_state.privateKey/publicKey say locally — no fallback path exists, so the local key is signing-irrelevant", async () => {
      const remoteBls = makeBls({
        rustSignerUrl: "http://fake-signer.local",
        rustSignerRequired: true,
      });
      const chain = makeBlockchainMock({
        checkNodeRegistration: () => Promise.resolve(true),
        getNodePublicKey: () => Promise.resolve(KEY_A.eip2537Hex),
      });
      const service = makeService(chain, remoteBls);
      // Everything LOCAL still looks consistent as A (privateKey derives A, state.publicKey
      // is A) — required mode never even looks at it.
      const result = await service.check(baseNodeState(), "0xcontract");
      expect(result.status).not.toBe("ok");
      expect(result.status).not.toBe("mismatch_local");
      expect(result.status).toBe("skipped_remote_signer");
      expect(result.scope).toBeUndefined(); // never scoped — the local dimension wasn't touched
    });

    it("REQUIRED mode + a stale local privateKey (A) that no longer matches state/chain (B): still skipped_remote_signer — the stale local key is irrelevant when there's no fallback", async () => {
      const remoteBls = makeBls({
        rustSignerUrl: "http://fake-signer.local",
        rustSignerRequired: true,
      });
      const chain = makeBlockchainMock({
        checkNodeRegistration: () => Promise.resolve(true),
        getNodePublicKey: () => Promise.resolve(KEY_B.eip2537Hex),
      });
      const service = makeService(chain, remoteBls);
      const state = baseNodeState({ publicKey: KEY_B.compressedHex }); // privateKey stays A (stale)
      const result = await service.check(state, "0xcontract");
      expect(result.status).toBe("skipped_remote_signer");
      expect(result.scope).toBeUndefined();
    });

    it("OPTIONAL mode + NO local private key: no fallback exists to verify => skipped_remote_signer", async () => {
      const remoteBls = makeBls({ rustSignerUrl: "http://fake-signer.local" }); // required NOT set
      const chain = makeBlockchainMock({
        checkNodeRegistration: () => Promise.resolve(true),
        getNodePublicKey: () => Promise.resolve(KEY_A.eip2537Hex),
      });
      const service = makeService(chain, remoteBls);
      const state = baseNodeState();
      delete (state as Partial<NodeState>).privateKey;
      const result = await service.check(state, "0xcontract");
      expect(result.status).toBe("skipped_remote_signer");
      expect(result.scope).toBeUndefined();
    });

    it("OPTIONAL mode + local fallback key (A) internally consistent with state and chain: ok, but EXPLICITLY scoped to local_fallback_only", async () => {
      const remoteBls = makeBls({ rustSignerUrl: "http://fake-signer.local" }); // required NOT set
      const chain = makeBlockchainMock({
        checkNodeRegistration: () => Promise.resolve(true),
        getNodePublicKey: () => Promise.resolve(KEY_A.eip2537Hex),
      });
      const service = makeService(chain, remoteBls);
      // baseNodeState(): privateKey=A, publicKey=A — internally consistent.
      const result = await service.check(baseNodeState(), "0xcontract");
      expect(result.status).toBe("ok");
      // The scope tag is load-bearing: without it, this "ok" would be misread as "the remote
      // signer's primary key is fine too" — it was never checked (no probe, no signature).
      expect(result.scope).toBe("local_fallback_only");
    });

    it("SILENT-FAILURE regression (replaces the round-4/5 test that used to pin this unsafe behavior): OPTIONAL mode + stale local fallback key (A) + on-chain re-registered to B => mismatch_onchain, scoped to local_fallback_only", async () => {
      // The exact scenario the whole feature exists to catch: signDerivedHash() will fall
      // back to signing with the stale local key A whenever the remote call fails, but the
      // chain has since been re-registered to B — every such fallback signature fails
      // verification forever. Previously (round-4/5) this silently reported
      // skipped_remote_signer; now the fallback key is actually checked.
      const remoteBls = makeBls({ rustSignerUrl: "http://fake-signer.local" }); // optional
      const chain = makeBlockchainMock({
        checkNodeRegistration: () => Promise.resolve(true),
        getNodePublicKey: () => Promise.resolve(KEY_B.eip2537Hex), // chain has moved on to B
      });
      const service = makeService(chain, remoteBls);
      // baseNodeState(): privateKey=A, publicKey=A — the fallback key (A) is internally
      // consistent with node_state, so the LOCAL dimension alone reports ok; it's the
      // ON-CHAIN dimension (state A vs. chain B) that catches the drift.
      const result = await service.check(baseNodeState(), "0xcontract");
      expect(result.status).toBe("mismatch_onchain");
      expect(result.scope).toBe("local_fallback_only");
    });

    it("SILENT-FAILURE regression #2 (the coverage gap the previous test's status assertion didn't catch): OPTIONAL mode + stale local privateKey (A) but node_state.publicKey correctly re-imported as B (= on-chain B) => mismatch_local, scoped to local_fallback_only", async () => {
      // The previous test's fixture had node_state.publicKey === A (the same stale key as
      // privateKey), so the ON-CHAIN comparison (A vs. chain B) already caught the drift on
      // its own — disabling local_fallback entirely still left `status` at mismatch_onchain
      // (only `scope` went missing), so that test alone could not prove the LOCAL check was
      // the one doing the work.
      //
      // This fixture is the scenario Codex flagged as the real danger: privateKey is stale
      // (A), but node_state.publicKey was separately (and correctly) re-imported as B, and
      // the chain ALSO has B (import-node.dto.ts accepts publicKey and privateKey as two
      // independent fields — nothing forces them to be a matching pair). Now the ON-CHAIN
      // comparison is B vs. chain B => ok, so ONLY the local_fallback comparison (privateKey
      // A's derived key vs. node_state.publicKey B) can catch that the private key on disk
      // doesn't actually correspond to the identity everything else agrees on.
      const remoteBls = makeBls({ rustSignerUrl: "http://fake-signer.local" }); // optional
      const chain = makeBlockchainMock({
        checkNodeRegistration: () => Promise.resolve(true),
        getNodePublicKey: () => Promise.resolve(KEY_B.eip2537Hex), // chain: B
      });
      const service = makeService(chain, remoteBls);
      // privateKey stays A (stale/mismatched); publicKey correctly reflects B (= chain).
      const state = baseNodeState({ publicKey: KEY_B.compressedHex });
      const result = await service.check(state, "0xcontract");
      expect(result.status).toBe("mismatch_local");
      expect(result.scope).toBe("local_fallback_only");
    });

    it("INVARIANT (round-4/7, the most important test in this file): a remote-signer node NEVER causes the checker to call fetch — no probe, no signature, in EITHER required or optional mode", async () => {
      const fetchSpy = jest.fn();
      global.fetch = fetchSpy as any;

      // Optional mode (exercises the NEW local_fallback derivation path too — pure
      // computation, must still never touch the network).
      const optionalBls = makeBls({ rustSignerUrl: "http://fake-signer.local" });
      const chainA = makeBlockchainMock({
        checkNodeRegistration: () => Promise.resolve(true),
        getNodePublicKey: () => Promise.resolve(KEY_A.eip2537Hex),
      });
      await makeService(chainA, optionalBls).check(baseNodeState(), "0xcontract");

      // Required mode.
      const requiredBls = makeBls({
        rustSignerUrl: "http://fake-signer.local",
        rustSignerRequired: true,
      });
      const chainB = makeBlockchainMock({
        checkNodeRegistration: () => Promise.resolve(true),
        getNodePublicKey: () => Promise.resolve(KEY_A.eip2537Hex),
      });
      await makeService(chainB, requiredBls).check(baseNodeState(), "0xcontract");

      expect(fetchSpy).not.toHaveBeenCalled();
    });
  });
});
