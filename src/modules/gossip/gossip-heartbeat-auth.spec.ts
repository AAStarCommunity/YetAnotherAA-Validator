import { ethers } from "ethers";
import { GossipService } from "./gossip.service.js";
import { BlsService } from "../bls/bls.service.js";
import { SignerService } from "../signer/signer.service.js";
import { bls, sigs, BLS_DST } from "../../utils/bls.util.js";
import type { GossipMessage } from "./gossip.interfaces.js";

/**
 * Offline-audit rule ② inc-2 — heartbeat AUTHENTICATION. A heartbeat's liveness is recorded in the
 * ledger ONLY when its BLS signature verifies: the pubkey must hash to the claimed nodeId and the
 * signature must cover keccak256(nodeId | authTs). This makes a spoofed `from` useless. Uses REAL BLS
 * keys so the verification path is exercised for real.
 */

const CONFIG: Record<string, string> = { PORT: "3000" };
function makeConfig() {
  return { get: (k: string) => CONFIG[k] } as any;
}
function makeNodeService() {
  return { getNodeState: () => ({ nodeId: "self", publicKey: "0xpub" }) } as any;
}

const signerService = new SignerService({ get: () => "local" } as any);
const blsService = new BlsService({} as any, signerService, undefined);

const PRIV_A = "0x" + "11".repeat(32);
const PRIV_B = "0x" + "22".repeat(32);

function privBytes(privHex: string): Uint8Array {
  const h = privHex.slice(2);
  const b = new Uint8Array(32);
  for (let i = 0; i < 32; i++) b[i] = parseInt(h.substr(i * 2, 2), 16);
  return b;
}

/** nodeId = keccak256(EIP-2537 G1 pubkey) — the same derivation gen-node-state / the resolver use. */
function nodeIdFor(privHex: string): string {
  const pk = sigs.getPublicKey(privBytes(privHex));
  return ethers.keccak256(blsService.encodePublicKeyToEIP2537(pk));
}

/** Build a heartbeat message signed by `privHex` over keccak256(from | authTs). `overrides` can force
 *  a mismatched `from`, a bad sig, or a different authTs to exercise the negative paths. */
async function signedHeartbeat(
  privHex: string,
  authTs: number,
  overrides: { from?: string; authSig?: string; publicKey?: string } = {}
): Promise<GossipMessage> {
  const pk = sigs.getPublicKey(privBytes(privHex));
  const from = overrides.from ?? nodeIdFor(privHex);
  const digest = ethers.solidityPackedKeccak256(["bytes32", "uint256"], [from, authTs]);
  const msgPoint = await bls.G2.hashToCurve(ethers.getBytes(digest), { DST: BLS_DST });
  const sig = sigs.sign(msgPoint, privBytes(privHex));
  return {
    type: "heartbeat",
    from: overrides.from ?? nodeIdFor(privHex),
    data: {
      status: "active",
      auth: {
        publicKey: overrides.publicKey ?? "0x" + pk.toHex(),
        authTs,
        authSig: overrides.authSig ?? "0x" + sig.toHex(),
      },
    },
    timestamp: authTs,
    ttl: 1,
    messageId: "m",
    version: 0,
  } as GossipMessage;
}

function buildService(): GossipService {
  return new GossipService(makeConfig(), makeNodeService(), blsService);
}

describe("GossipService heartbeat authentication (offline-audit rule ② inc-2)", () => {
  const NOW = 1_700_000_000_000;

  it("records liveness for a VALID signed heartbeat (stores the signed authTs)", async () => {
    const svc = buildService();
    const nid = nodeIdFor(PRIV_A);
    expect(svc.getLastSeen(nid)).toBeNull();
    await (svc as any).handleHeartbeatMessage(await signedHeartbeat(PRIV_A, NOW));
    expect(svc.getLastSeen(nid)).toBe(NOW);
  });

  it("REJECTS a spoofed `from` (pubkey does not hash to the claimed nodeId)", async () => {
    const svc = buildService();
    const victim = nodeIdFor(PRIV_B);
    // Attacker signs with its OWN key A but claims victim B's nodeId.
    const hb = await signedHeartbeat(PRIV_A, NOW, { from: victim });
    await (svc as any).handleHeartbeatMessage(hb);
    expect(svc.getLastSeen(victim)).toBeNull(); // spoof cannot record victim's liveness
  });

  it("REJECTS a bad signature", async () => {
    const svc = buildService();
    const nid = nodeIdFor(PRIV_A);
    const hb = await signedHeartbeat(PRIV_A, NOW, { authSig: "0x" + "cd".repeat(96) });
    await (svc as any).handleHeartbeatMessage(hb);
    expect(svc.getLastSeen(nid)).toBeNull();
  });

  it("REJECTS a future-dated heartbeat (authTs beyond the skew bound)", async () => {
    const svc = buildService();
    const nid = nodeIdFor(PRIV_A);
    // authTs far in the future relative to real Date.now() → rejected.
    const hb = await signedHeartbeat(PRIV_A, Date.now() + 10 * 60_000);
    await (svc as any).handleHeartbeatMessage(hb);
    expect(svc.getLastSeen(nid)).toBeNull();
  });

  it("is MONOTONIC — a replayed OLDER signed heartbeat cannot roll liveness backward", async () => {
    const svc = buildService();
    const nid = nodeIdFor(PRIV_A);
    await (svc as any).handleHeartbeatMessage(await signedHeartbeat(PRIV_A, NOW));
    expect(svc.getLastSeen(nid)).toBe(NOW);
    // Replay an older (still validly-signed) heartbeat → must NOT overwrite the newer value.
    await (svc as any).handleHeartbeatMessage(await signedHeartbeat(PRIV_A, NOW - 5_000));
    expect(svc.getLastSeen(nid)).toBe(NOW);
    // A newer one DOES advance it.
    await (svc as any).handleHeartbeatMessage(await signedHeartbeat(PRIV_A, NOW + 5_000));
    expect(svc.getLastSeen(nid)).toBe(NOW + 5_000);
  });

  it("does NOT record an UNSIGNED heartbeat (no auth payload)", async () => {
    const svc = buildService();
    const nid = nodeIdFor(PRIV_A);
    const unsigned: GossipMessage = {
      type: "heartbeat",
      from: nid,
      data: { status: "active" },
      timestamp: NOW,
      ttl: 1,
      messageId: "m",
      version: 0,
    } as GossipMessage;
    await (svc as any).handleHeartbeatMessage(unsigned);
    expect(svc.getLastSeen(nid)).toBeNull();
  });

  it("ledger survives peer cleanup (records even with no peer in the connection map)", async () => {
    const svc = buildService();
    const nid = nodeIdFor(PRIV_A);
    await (svc as any).handleHeartbeatMessage(await signedHeartbeat(PRIV_A, NOW));
    expect((svc as any).peers.has(nid)).toBe(false);
    expect(svc.getLastSeen(nid)).toBe(NOW);
  });
});
