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
  overrides: { from?: string; messageFrom?: string; authSig?: string; publicKey?: string } = {}
): Promise<GossipMessage> {
  const pk = sigs.getPublicKey(privBytes(privHex));
  // `from` = the nodeId the digest is SIGNED over; `messageFrom` = the (possibly differently-cased /
  // spoofed) value placed in message.from. Default: both are the real nodeId.
  const from = overrides.from ?? nodeIdFor(privHex);
  const digest = ethers.solidityPackedKeccak256(
    ["string", "bytes32", "uint256"],
    ["YAA_HEARTBEAT_AUTH_V1", from, authTs]
  );
  const msgPoint = await bls.G2.hashToCurve(ethers.getBytes(digest), { DST: BLS_DST });
  const sig = sigs.sign(msgPoint, privBytes(privHex));
  return {
    type: "heartbeat",
    from: overrides.messageFrom ?? overrides.from ?? nodeIdFor(privHex),
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
  const svc = new GossipService(makeConfig(), makeNodeService(), blsService);
  // The ledger records ONLY nodeIds the auditor marks relevant (default record-nothing). Mark both
  // test identities relevant so the happy-path tests record; the registration test overrides this.
  svc.setRelevantNodeIds([nodeIdFor(PRIV_A), nodeIdFor(PRIV_B)]);
  return svc;
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

  it("CANONICALIZES nodeId casing — an upper-cased message.from records ONE lowercase entry (Codex High)", async () => {
    const svc = buildService();
    const nid = nodeIdFor(PRIV_A); // lowercase keccak
    // Same valid heartbeat but message.from is upper-cased — must collapse to the one canonical key,
    // not create a second ledger entry (the casing-inflation attack).
    await (svc as any).handleHeartbeatMessage(
      await signedHeartbeat(PRIV_A, NOW, { messageFrom: nid.toUpperCase().replace("0X", "0x") })
    );
    expect((svc as any).lastSeenLedger.size).toBe(1);
    expect(svc.getLastSeen(nid)).toBe(NOW);
    expect(svc.getLastSeen(nid.toUpperCase().replace("0X", "0x"))).toBe(NOW); // case-insensitive read
  });

  it("default is RECORD-NOTHING — a valid heartbeat with NO relevant set is dropped (no startup Sybil window)", async () => {
    // Fresh service WITHOUT any setRelevantNodeIds → the ledger records nothing (closes the pre-first-
    // tick Sybil window).
    const svc = new GossipService(makeConfig(), makeNodeService(), blsService);
    const nid = nodeIdFor(PRIV_A);
    await (svc as any).handleHeartbeatMessage(await signedHeartbeat(PRIV_A, NOW));
    expect(svc.getLastSeen(nid)).toBeNull();
    expect((svc as any).lastSeenLedger.size).toBe(0);
  });

  it("setRelevantNodeIds PRUNES ledger entries no longer relevant (evicts a poisoned/exited entry)", async () => {
    const svc = buildService(); // A + B relevant
    const nidA = nodeIdFor(PRIV_A);
    const nidB = nodeIdFor(PRIV_B);
    await (svc as any).handleHeartbeatMessage(await signedHeartbeat(PRIV_A, NOW));
    await (svc as any).handleHeartbeatMessage(await signedHeartbeat(PRIV_B, NOW));
    expect((svc as any).lastSeenLedger.size).toBe(2);
    // Narrow the audited set to A only → B is pruned from the ledger.
    svc.setRelevantNodeIds([nidA]);
    expect(svc.getLastSeen(nidB)).toBeNull();
    expect(svc.getLastSeen(nidA)).toBe(NOW);
    expect((svc as any).lastSeenLedger.size).toBe(1);
  });

  it("a same-authTs replay does NOT advance liveness (monotonic on authTs, closes the future-date replay)", async () => {
    const svc = buildService();
    const nid = nodeIdFor(PRIV_A);
    await (svc as any).handleHeartbeatMessage(await signedHeartbeat(PRIV_A, NOW));
    const seen1 = svc.getLastSeen(nid);
    // Replay the exact same signed heartbeat (same authTs) → rejected by the authTs-monotonic guard.
    await (svc as any).handleHeartbeatMessage(await signedHeartbeat(PRIV_A, NOW));
    expect(svc.getLastSeen(nid)).toBe(seen1);
  });

  it("registration gate: with a relevant set, an UNREGISTERED (Sybil) valid heartbeat is NOT recorded (Codex High)", async () => {
    const svc = buildService();
    const nidA = nodeIdFor(PRIV_A);
    const nidB = nodeIdFor(PRIV_B);
    svc.setRelevantNodeIds([nidA]); // only A is audited
    // B is a genuine key-owner (valid sig) but NOT in the audited set → dropped before recording.
    await (svc as any).handleHeartbeatMessage(await signedHeartbeat(PRIV_B, NOW));
    expect(svc.getLastSeen(nidB)).toBeNull();
    // A (in the set) IS recorded.
    await (svc as any).handleHeartbeatMessage(await signedHeartbeat(PRIV_A, NOW));
    expect(svc.getLastSeen(nidA)).toBe(NOW);
  });
});
