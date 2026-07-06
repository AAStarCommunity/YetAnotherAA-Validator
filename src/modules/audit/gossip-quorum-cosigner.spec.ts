import { ethers } from "ethers";
import { GossipQuorumCoSigner } from "./gossip-quorum-cosigner.js";
import { BlsService } from "../bls/bls.service.js";
import { SignerService } from "../signer/signer.service.js";
import {
  CoSignRequest,
  CoSignVerifier,
  SlashLevel,
  buildExecuteMessageHash,
  buildQueueMessageHash,
  buildSignerMask,
} from "./slash-consensus.js";
import type { CoSignRequestPayload, CoSignResponsePayload } from "../gossip/gossip.interfaces.js";
import { bls, sigs, BLS_DST } from "../../utils/bls.util.js";

/**
 * inc-2-live — GossipQuorumCoSigner unit tests. Uses REAL BLS keys/signatures so the requester's
 * cryptographic verification + on-chain binding are exercised for real (mocked GossipService +
 * BlockchainService supply the transport + slot registry). The single most safety-critical unit.
 */

const OPERATOR = ethers.getAddress("0x" + "12".repeat(20));
const CHAIN_ID = 11155111;
const BLS_AGG = ethers.getAddress("0x" + "aa".repeat(20));
const EPOCH = 12_345;
const PROPOSAL_ID = "7";

// Three deterministic BLS keypairs, one per node/slot.
const PRIVS = ["0x" + "11".repeat(32), "0x" + "22".repeat(32), "0x" + "33".repeat(32)];

// A real BlsService (real SignerService, no Rust) — all crypto is genuine.
const signerService = new SignerService({ get: () => "local" } as any);
const blsService = new BlsService({} as any, signerService, undefined);

function privBytes(privHex: string): Uint8Array {
  const h = privHex.slice(2);
  const b = new Uint8Array(32);
  for (let i = 0; i < 32; i++) b[i] = parseInt(h.substr(i * 2, 2), 16);
  return b;
}

function compressedPub(privHex: string): string {
  return "0x" + sigs.getPublicKey(privBytes(privHex)).toHex();
}

function uncompressedPub(privHex: string): string {
  return blsService.encodePublicKeyToEIP2537(sigs.getPublicKey(privBytes(privHex))).toLowerCase();
}

async function signPoint(privHex: string, messageHash: string): Promise<any> {
  const msgPoint = await bls.G2.hashToCurve(ethers.getBytes(messageHash), { DST: BLS_DST });
  return sigs.sign(msgPoint, privBytes(privHex));
}

async function signOver(privHex: string, messageHash: string): Promise<string> {
  return (await signPoint(privHex, messageHash)).toHex();
}

/** On-chain slot registry mock: slot i (1-indexed) → PRIVS[i-1]. */
function makeBlockchain(slotCount = 3) {
  return {
    async getValidatorAtSlot(_addr: string, slot: number): Promise<string | null> {
      if (slot >= 1 && slot <= slotCount)
        return ethers.getAddress("0x" + String(slot).padStart(2, "0").repeat(20));
      return null;
    },
    async getBlsPublicKeyAtSlot(_addr: string, slot: number): Promise<string | null> {
      if (slot >= 1 && slot <= slotCount) return uncompressedPub(PRIVS[slot - 1]);
      return null;
    },
  } as any;
}

function makeNode(privHex: string, nodeId = "node-1") {
  return {
    getNodeForSigning: () => ({
      nodeId,
      nodeName: nodeId,
      privateKey: privHex,
      publicKey: compressedPub(privHex).slice(2),
      description: "",
    }),
  } as any;
}

function makeConfig(overrides: Record<string, unknown> = {}) {
  const cfg: Record<string, unknown> = {
    auditBlsAggregatorAddress: BLS_AGG,
    auditMaxSlots: 13,
    auditCoSignTimeoutMs: 1000,
    auditSlashThresholds: { WARNING: 2, MINOR: 3, MAJOR: 3 },
    auditExecuteSlash: true,
    auditWatchlist: [OPERATOR],
    ...overrides,
  };
  return { get: (k: string) => cfg[k] } as any;
}

/** A gossip mock whose requestCoSignatures returns a fixed set of peer responses. */
function makeGossip(peerResponses: CoSignResponsePayload[], peers = 2) {
  return {
    registered: null as any,
    registerCoSignHandler(fn: any) {
      this.registered = fn;
    },
    getPeers() {
      return new Array(peers).fill({ nodeId: "peer" });
    },
    async requestCoSignatures(_payload: CoSignRequestPayload, opts: { threshold: number }) {
      // Emulate the collector: return up to `threshold` distinct responses (or all if fewer).
      return peerResponses.slice(0, Math.max(opts.threshold, peerResponses.length));
    },
  } as any;
}

const ALWAYS_CONFIRM: CoSignVerifier = async req => ({
  confirmed: true,
  proofHash: req.evidenceHash ?? "0x" + "ee".repeat(32),
});

function executeReq(overrides: Partial<CoSignRequest> = {}): CoSignRequest {
  const evidenceHash = (overrides.evidenceHash as string) ?? "0x" + "ee".repeat(32);
  const base: CoSignRequest = {
    step: "execute",
    operator: OPERATOR,
    slashLevel: SlashLevel.MINOR,
    epoch: EPOCH,
    chainId: CHAIN_ID,
    proposalId: PROPOSAL_ID,
    evidenceHash,
    messageHash: buildExecuteMessageHash(
      BigInt(PROPOSAL_ID),
      OPERATOR,
      SlashLevel.MINOR,
      EPOCH,
      CHAIN_ID,
      evidenceHash
    ),
    ...overrides,
  };
  return base;
}

async function peerResponse(
  privHex: string,
  slot: number,
  messageHash: string,
  nodeId: string
): Promise<CoSignResponsePayload> {
  return {
    requestId: "req",
    slot,
    signerNodeId: nodeId,
    signerPublicKey: compressedPub(privHex),
    signatureCompact: await signOver(privHex, messageHash),
    messageHash,
  };
}

describe("GossipQuorumCoSigner", () => {
  it("happy 3-of-3 execute → signerMask 7n + a re-verifiable aggregate", async () => {
    const req = executeReq();
    const peers = [
      await peerResponse(PRIVS[1], 2, req.messageHash, "node-2"),
      await peerResponse(PRIVS[2], 3, req.messageHash, "node-3"),
    ];
    const cs = new GossipQuorumCoSigner(
      makeGossip(peers),
      blsService,
      makeNode(PRIVS[0]),
      makeBlockchain(),
      makeConfig()
    );
    cs.arm(ALWAYS_CONFIRM);

    const { signerMask, sigG2 } = await cs.coSign(req);
    expect(signerMask).toBe(buildSignerMask([1, 2, 3]));
    expect(signerMask).toBe(7n);
    // sigG2 is EIP-2537 (256 bytes = 512 hex).
    expect(sigG2).toMatch(/^0x[0-9a-f]{512}$/);

    // sigG2 must be EXACTLY the EIP-2537 encoding of the aggregate of the 3 real signatures…
    const rawSigs = await Promise.all(PRIVS.map(p => signPoint(p, req.messageHash)));
    const expectedAgg = await blsService.aggregateSignaturesOnly(rawSigs);
    expect(sigG2).toBe(blsService.encodeToEIP2537(expectedAgg));
    // …and that aggregate verifies against the summed public keys over hashToCurve(messageHash).
    const aggPub = PRIVS.map(p => sigs.getPublicKey(privBytes(p))).reduce((acc, pk) => acc.add(pk));
    const msgPoint = await bls.G2.hashToCurve(ethers.getBytes(req.messageHash), { DST: BLS_DST });
    expect(await sigs.verify(expectedAgg, msgPoint, aggPub)).toBe(true);
  });

  it("threshold NOT met (MINOR=3, only 2 signers) → THROWS (never aggregates)", async () => {
    const req = executeReq();
    const peers = [await peerResponse(PRIVS[1], 2, req.messageHash, "node-2")];
    const cs = new GossipQuorumCoSigner(
      makeGossip(peers),
      blsService,
      makeNode(PRIVS[0]),
      makeBlockchain(),
      makeConfig()
    );
    cs.arm(ALWAYS_CONFIRM);
    await expect(cs.coSign(req)).rejects.toThrow(/only 2 valid unique-slot/);
  });

  it("timeout partial (no peer responses) → THROWS", async () => {
    const req = executeReq();
    const cs = new GossipQuorumCoSigner(
      makeGossip([]),
      blsService,
      makeNode(PRIVS[0]),
      makeBlockchain(),
      makeConfig()
    );
    cs.arm(ALWAYS_CONFIRM);
    await expect(cs.coSign(req)).rejects.toThrow(/need 3/);
  });

  it("forged participation: a signature that does not verify is DROPPED → below threshold → THROWS", async () => {
    const req = executeReq();
    // node-2 signs a DIFFERENT hash (forged) → its sig won't verify over req.messageHash.
    const forged = await peerResponse(PRIVS[1], 2, req.messageHash, "node-2");
    forged.signatureCompact = await signOver(
      PRIVS[1],
      buildQueueMessageHash(OPERATOR, 1, EPOCH, CHAIN_ID)
    );
    const good = await peerResponse(PRIVS[2], 3, req.messageHash, "node-3");
    const cs = new GossipQuorumCoSigner(
      makeGossip([forged, good]),
      blsService,
      makeNode(PRIVS[0]),
      makeBlockchain(),
      makeConfig()
    );
    cs.arm(ALWAYS_CONFIRM);
    // own(1) + good(3) = 2 valid < 3 (forged dropped).
    await expect(cs.coSign(req)).rejects.toThrow(/only 2 valid unique-slot/);
  });

  it("slot↔pubkey mismatch on-chain: a valid sig from a key NOT registered at the claimed slot is DROPPED", async () => {
    const req = executeReq();
    // node-3's REAL key/sig, but it claims slot 2 (on-chain slot 2 = node-2's key) → binding fails.
    const spoofed = await peerResponse(PRIVS[2], 2, req.messageHash, "node-3");
    const cs = new GossipQuorumCoSigner(
      makeGossip([spoofed]),
      blsService,
      makeNode(PRIVS[0]),
      makeBlockchain(),
      makeConfig()
    );
    cs.arm(ALWAYS_CONFIRM);
    // own(1) + spoofed(dropped) = 1 < 3.
    await expect(cs.coSign(req)).rejects.toThrow(/only 1 valid unique-slot/);
  });

  it("duplicate slot from two responses counts once (dedup by slot)", async () => {
    const req = executeReq();
    // Two DISTINCT nodes both (impossibly) claim slot 2 with slot-2's key → count once.
    const a = await peerResponse(PRIVS[1], 2, req.messageHash, "node-2a");
    const b = await peerResponse(PRIVS[1], 2, req.messageHash, "node-2b");
    const cs = new GossipQuorumCoSigner(
      makeGossip([a, b]),
      blsService,
      makeNode(PRIVS[0]),
      makeBlockchain(),
      makeConfig()
    );
    cs.arm(ALWAYS_CONFIRM);
    // own(1) + slot2(once) = 2 < 3.
    await expect(cs.coSign(req)).rejects.toThrow(/only 2 valid unique-slot/);
  });

  it("requester with no on-chain slot → THROWS (fail-closed precondition)", async () => {
    const req = executeReq();
    // Local node uses a key registered at NO slot (a 4th unregistered key).
    const cs = new GossipQuorumCoSigner(
      makeGossip([]),
      blsService,
      makeNode("0x" + "44".repeat(32)),
      makeBlockchain(3),
      makeConfig()
    );
    cs.arm(ALWAYS_CONFIRM);
    await expect(cs.coSign(req)).rejects.toThrow(/no on-chain validator slot/);
  });

  it("requester with no gossip peers → THROWS", async () => {
    const req = executeReq();
    const cs = new GossipQuorumCoSigner(
      makeGossip([], 0),
      blsService,
      makeNode(PRIVS[0]),
      makeBlockchain(),
      makeConfig()
    );
    cs.arm(ALWAYS_CONFIRM);
    await expect(cs.coSign(req)).rejects.toThrow(/no gossip peers/);
  });

  it("disarmed (AUDIT_EXECUTE_SLASH=false) → coSign THROWS", async () => {
    const req = executeReq();
    const cs = new GossipQuorumCoSigner(
      makeGossip([]),
      blsService,
      makeNode(PRIVS[0]),
      makeBlockchain(),
      makeConfig({ auditExecuteSlash: false })
    );
    cs.arm(ALWAYS_CONFIRM);
    await expect(cs.coSign(req)).rejects.toThrow(/not armed/);
  });

  it("requester cannot independently confirm the violation → THROWS", async () => {
    const req = executeReq();
    const cs = new GossipQuorumCoSigner(
      makeGossip([]),
      blsService,
      makeNode(PRIVS[0]),
      makeBlockchain(),
      makeConfig()
    );
    cs.arm(async () => ({ confirmed: false, proofHash: null }));
    await expect(cs.coSign(req)).rejects.toThrow(/could not independently confirm/);
  });

  it("WARNING threshold is 2 → own + 1 peer suffices", async () => {
    const req = executeReq({
      slashLevel: SlashLevel.WARNING,
      messageHash: buildExecuteMessageHash(
        BigInt(PROPOSAL_ID),
        OPERATOR,
        SlashLevel.WARNING,
        EPOCH,
        CHAIN_ID,
        "0x" + "ee".repeat(32)
      ),
    });
    const peers = [await peerResponse(PRIVS[1], 2, req.messageHash, "node-2")];
    const cs = new GossipQuorumCoSigner(
      makeGossip(peers),
      blsService,
      makeNode(PRIVS[0]),
      makeBlockchain(),
      makeConfig()
    );
    cs.arm(ALWAYS_CONFIRM);
    const { signerMask } = await cs.coSign(req);
    expect(signerMask).toBe(buildSignerMask([1, 2]));
    expect(signerMask).toBe(3n);
  });

  // ── RESPONDER gate (verifyAndSign) ─────────────────────────────────────────────
  function payload(req: CoSignRequest): CoSignRequestPayload {
    return { ...req, requestId: "rid", requesterNodeId: "requester" };
  }

  it("responder signs on FULL agreement (own slot 2)", async () => {
    const req = executeReq();
    const cs = new GossipQuorumCoSigner(
      makeGossip([]),
      blsService,
      makeNode(PRIVS[1], "node-2"),
      makeBlockchain(),
      makeConfig()
    );
    cs.arm(ALWAYS_CONFIRM);
    const resp = await cs.verifyAndSign(payload(req));
    expect(resp).not.toBeNull();
    expect(resp!.slot).toBe(2);
    expect(resp!.messageHash).toBe(req.messageHash);
    // The returned signature verifies over the recomputed hash.
    const sig = sigs.Signature.fromHex(resp!.signatureCompact.replace(/^0x/, ""));
    const pk = bls.G1.Point.fromHex(resp!.signerPublicKey.replace(/^0x/, ""));
    const msgPoint = await bls.G2.hashToCurve(ethers.getBytes(req.messageHash), { DST: BLS_DST });
    expect(await sigs.verify(sig, msgPoint, pk)).toBe(true);
  });

  it("responder REFUSES when disarmed (AUDIT_EXECUTE_SLASH=false)", async () => {
    const cs = new GossipQuorumCoSigner(
      makeGossip([]),
      blsService,
      makeNode(PRIVS[1], "node-2"),
      makeBlockchain(),
      makeConfig({ auditExecuteSlash: false })
    );
    cs.arm(ALWAYS_CONFIRM);
    expect(await cs.verifyAndSign(payload(executeReq()))).toBeNull();
  });

  it("responder REFUSES an un-watchlisted operator", async () => {
    const cs = new GossipQuorumCoSigner(
      makeGossip([]),
      blsService,
      makeNode(PRIVS[1], "node-2"),
      makeBlockchain(),
      makeConfig({ auditWatchlist: [] })
    );
    cs.arm(ALWAYS_CONFIRM);
    expect(await cs.verifyAndSign(payload(executeReq()))).toBeNull();
  });

  it("responder REFUSES a messageHash that does not match the recompute (never trusts it)", async () => {
    const req = executeReq({ messageHash: "0x" + "de".repeat(32) });
    const cs = new GossipQuorumCoSigner(
      makeGossip([]),
      blsService,
      makeNode(PRIVS[1], "node-2"),
      makeBlockchain(),
      makeConfig()
    );
    cs.arm(ALWAYS_CONFIRM);
    expect(await cs.verifyAndSign(payload(req))).toBeNull();
  });

  it("responder REFUSES when re-derived proofHash != evidenceHash (execute innocent-operator defense)", async () => {
    const req = executeReq();
    const cs = new GossipQuorumCoSigner(
      makeGossip([]),
      blsService,
      makeNode(PRIVS[1], "node-2"),
      makeBlockchain(),
      makeConfig()
    );
    // Verifier confirms but returns a DIFFERENT proofHash than the bound evidenceHash.
    cs.arm(async () => ({ confirmed: true, proofHash: "0x" + "ba".repeat(32) }));
    expect(await cs.verifyAndSign(payload(req))).toBeNull();
  });

  it("responder REFUSES when the violation is indeterminate (verifier not confirmed)", async () => {
    const cs = new GossipQuorumCoSigner(
      makeGossip([]),
      blsService,
      makeNode(PRIVS[1], "node-2"),
      makeBlockchain(),
      makeConfig()
    );
    cs.arm(async () => ({ confirmed: false, proofHash: null }));
    expect(await cs.verifyAndSign(payload(executeReq()))).toBeNull();
  });

  it("responder REFUSES when it has no on-chain slot", async () => {
    const cs = new GossipQuorumCoSigner(
      makeGossip([]),
      blsService,
      makeNode("0x" + "44".repeat(32), "node-x"), // unregistered key
      makeBlockchain(3),
      makeConfig()
    );
    cs.arm(ALWAYS_CONFIRM);
    expect(await cs.verifyAndSign(payload(executeReq()))).toBeNull();
  });

  it("responder confirms a QUEUE step (no evidenceHash binding required)", async () => {
    const queueReq: CoSignRequest = {
      step: "queue",
      operator: OPERATOR,
      slashLevel: SlashLevel.MINOR,
      epoch: EPOCH,
      chainId: CHAIN_ID,
      messageHash: buildQueueMessageHash(OPERATOR, SlashLevel.MINOR, EPOCH, CHAIN_ID),
    };
    const cs = new GossipQuorumCoSigner(
      makeGossip([]),
      blsService,
      makeNode(PRIVS[1], "node-2"),
      makeBlockchain(),
      makeConfig()
    );
    cs.arm(async () => ({ confirmed: true, proofHash: "0x" + "cc".repeat(32) }));
    const resp = await cs.verifyAndSign(payload(queueReq));
    expect(resp).not.toBeNull();
    expect(resp!.slot).toBe(2);
  });

  // ── sigG2 aggregate round-trip (256B, re-verifies) ──────────────────────────────
  it("sigG2 aggregate round-trips: 3 real sigs → EIP-2537 256B → re-verifies", async () => {
    const messageHash = buildExecuteMessageHash(
      1n,
      OPERATOR,
      SlashLevel.MINOR,
      EPOCH,
      CHAIN_ID,
      "0x" + "ee".repeat(32)
    );
    const msgPoint = await bls.G2.hashToCurve(ethers.getBytes(messageHash), { DST: BLS_DST });
    const rawSigs = PRIVS.map(p => sigs.sign(msgPoint, privBytes(p)));
    const agg = await blsService.aggregateSignaturesOnly(rawSigs);
    const sigG2 = blsService.encodeToEIP2537(agg);
    expect(sigG2).toMatch(/^0x[0-9a-f]{512}$/); // 256 bytes (uncompressed EIP-2537 G2)

    // The aggregate point verifies against the summed public keys (the on-chain BLS.pairing check
    // does the equivalent over these exact bytes via the EIP-2537 precompiles).
    const aggPub = PRIVS.map(p => sigs.getPublicKey(privBytes(p))).reduce((acc, pk) => acc.add(pk));
    expect(await sigs.verify(agg, msgPoint, aggPub)).toBe(true);
  });
});
