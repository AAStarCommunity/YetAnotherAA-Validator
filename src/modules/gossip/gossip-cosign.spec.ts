import { GossipService } from "./gossip.service.js";
import type {
  CoSignRequestPayload,
  CoSignResponsePayload,
  GossipMessage,
} from "./gossip.interfaces.js";
import { PROOF_SCHEMA_VERSION } from "../audit/proof-archive.js";

/**
 * inc-2-live — gossip co-sign TRANSPORT tests. The gossip service is a dumb point-to-point
 * carrier: it invokes the registered handler and relays its reply, routes responses by requestId,
 * mints a FRESH messageId per send, and sends with ttl=0 (never flood-propagated). ZERO slash
 * logic lives here. We drive the private handlers directly with a fake ws to avoid a live server.
 */

const CONFIG: Record<string, string> = { PORT: "3000" };
function makeConfig() {
  return { get: (k: string) => CONFIG[k] } as any;
}
function makeNodeService(nodeId = "self-node") {
  return { getNodeState: () => ({ nodeId, publicKey: "0xpub" }) } as any;
}

/** A minimal ws that records every JSON message sent to it. */
function fakeWs() {
  const sent: GossipMessage[] = [];
  return {
    sent,
    readyState: 1, // WebSocket.OPEN
    send(data: string) {
      sent.push(JSON.parse(data));
    },
  };
}

function buildService(nodeId = "self-node"): GossipService {
  const svc = new GossipService(makeConfig(), makeNodeService(nodeId));
  // nodeState.version is read when composing messages — the constructor already initialized it.
  return svc;
}

function reqPayload(overrides: Partial<CoSignRequestPayload> = {}): CoSignRequestPayload {
  return {
    proofSchemaVersion: PROOF_SCHEMA_VERSION,
    step: "queue",
    operator: "0x" + "12".repeat(20),
    slashLevel: 1,
    epoch: 10,
    chainId: 11155111,
    messageHash: "0x" + "ab".repeat(32),
    requestId: "req-1",
    requesterNodeId: "requester",
    ...overrides,
  };
}

describe("GossipService co-sign transport", () => {
  it("handleCoSignRequest invokes the registered handler and replies on the SAME ws (ttl=0)", async () => {
    const svc = buildService();
    const response: CoSignResponsePayload = {
      requestId: "req-1",
      slot: 2,
      signerNodeId: "self-node",
      signerPublicKey: "0xpk",
      signatureCompact: "0xsig",
      messageHash: reqPayload().messageHash,
    };
    let received: CoSignRequestPayload | null = null;
    svc.registerCoSignHandler(async payload => {
      received = payload;
      return response;
    });

    const ws = fakeWs();
    const message: GossipMessage = {
      type: "cosign-request",
      from: "requester",
      data: reqPayload(),
      timestamp: Date.now(),
      ttl: 0,
      messageId: "m-1",
      version: 0,
    };
    (svc as any).handleCoSignRequest(ws, message);
    // handler is async → let the microtask reply.
    await new Promise(r => setTimeout(r, 0));

    expect(received).not.toBeNull();
    expect(ws.sent).toHaveLength(1);
    expect(ws.sent[0].type).toBe("cosign-response");
    expect(ws.sent[0].ttl).toBe(0); // directed reply, never propagated
    expect(ws.sent[0].data).toEqual(response);
  });

  it("a null handler return (refusal) sends NOTHING (silent fail-closed)", async () => {
    const svc = buildService();
    svc.registerCoSignHandler(async () => null);
    const ws = fakeWs();
    (svc as any).handleCoSignRequest(ws, {
      type: "cosign-request",
      from: "requester",
      data: reqPayload(),
      timestamp: Date.now(),
      ttl: 0,
      messageId: "m-1",
      version: 0,
    });
    await new Promise(r => setTimeout(r, 0));
    expect(ws.sent).toHaveLength(0);
  });

  it("no registered handler (disarmed node) → request silently refused", () => {
    const svc = buildService();
    const ws = fakeWs();
    (svc as any).handleCoSignRequest(ws, {
      type: "cosign-request",
      from: "requester",
      data: reqPayload(),
      timestamp: Date.now(),
      ttl: 0,
      messageId: "m-1",
      version: 0,
    });
    expect(ws.sent).toHaveLength(0);
  });

  it("requestCoSignatures resolves at threshold and dedups by signerNodeId", async () => {
    const svc = buildService();
    // No connections → broadcast is a no-op; we inject responses directly.
    const payload = reqPayload({ requestId: "req-A" });
    const promise = (svc as any).requestCoSignatures(payload, { threshold: 2, timeoutMs: 5000 });

    const mk = (nodeId: string, slot: number): GossipMessage => ({
      type: "cosign-response",
      from: nodeId,
      data: {
        requestId: "req-A",
        slot,
        signerNodeId: nodeId,
        signerPublicKey: "0xpk",
        signatureCompact: "0xsig",
        messageHash: payload.messageHash,
      },
      timestamp: Date.now(),
      ttl: 0,
      messageId: `resp-${nodeId}`,
      version: 0,
    });

    (svc as any).handleCoSignResponse(mk("node-2", 2));
    (svc as any).handleCoSignResponse(mk("node-2", 2)); // duplicate node → deduped
    (svc as any).handleCoSignResponse(mk("node-3", 3)); // reaches threshold 2

    const responses = (await promise) as CoSignResponsePayload[];
    expect(responses).toHaveLength(2);
    expect(responses.map(r => r.signerNodeId).sort()).toEqual(["node-2", "node-3"]);
  });

  it("requestCoSignatures resolves on TIMEOUT with the partial set", async () => {
    const svc = buildService();
    const payload = reqPayload({ requestId: "req-T" });
    const promise = (svc as any).requestCoSignatures(payload, { threshold: 3, timeoutMs: 20 });
    (svc as any).handleCoSignResponse({
      type: "cosign-response",
      from: "node-2",
      data: {
        requestId: "req-T",
        slot: 2,
        signerNodeId: "node-2",
        signerPublicKey: "0xpk",
        signatureCompact: "0xsig",
        messageHash: payload.messageHash,
      },
      timestamp: Date.now(),
      ttl: 0,
      messageId: "resp-2",
      version: 0,
    });
    const responses = (await promise) as CoSignResponsePayload[];
    // Threshold (3) never met → resolved on timeout with the single partial response.
    expect(responses).toHaveLength(1);
  });

  it("requestCoSignatures with threshold<=0 resolves immediately (empty set)", async () => {
    const svc = buildService();
    const responses = (await (svc as any).requestCoSignatures(reqPayload({ requestId: "req-0" }), {
      threshold: 0,
      timeoutMs: 5000,
    })) as CoSignResponsePayload[];
    expect(responses).toEqual([]);
  });

  it("a response for an unknown/expired requestId is ignored", async () => {
    const svc = buildService();
    // No pending request registered → must be a safe no-op (no throw).
    expect(() =>
      (svc as any).handleCoSignResponse({
        type: "cosign-response",
        from: "node-2",
        data: {
          requestId: "does-not-exist",
          slot: 2,
          signerNodeId: "node-2",
          signerPublicKey: "0xpk",
          signatureCompact: "0xsig",
          messageHash: "0x00",
        },
        timestamp: Date.now(),
        ttl: 0,
        messageId: "resp-x",
        version: 0,
      })
    ).not.toThrow();
  });

  it("each requestCoSignatures send mints a FRESH messageId (retries are not history-deduped)", async () => {
    const svc = buildService();
    const sentIds: string[] = [];
    // Capture broadcast messageIds.
    (svc as any).broadcastMessage = (m: GossipMessage) => sentIds.push(m.messageId);
    void (svc as any).requestCoSignatures(reqPayload({ requestId: "r1" }), {
      threshold: 1,
      timeoutMs: 5,
    });
    void (svc as any).requestCoSignatures(reqPayload({ requestId: "r2" }), {
      threshold: 1,
      timeoutMs: 5,
    });
    expect(sentIds).toHaveLength(2);
    expect(sentIds[0]).not.toBe(sentIds[1]); // fresh uuid per send
    await new Promise(r => setTimeout(r, 10)); // let the timers clear
  });
});

/**
 * MEDIUM 1 (Codex): the collector counts ONLY validated responses toward the threshold and dedups
 * by an app-supplied key (the co-signer keys by on-chain slot) — so one connected peer cannot flood
 * bogus responses with distinct signer ids, crowd out honest signers, and force a premature
 * under-threshold resolution.
 */
describe("GossipService co-sign collector: validate + dedupKey", () => {
  const flush = () => new Promise(r => setTimeout(r, 0));
  const bySlot = (r: CoSignResponsePayload) => r.slot;
  const validateOk = async (r: CoSignResponsePayload) => (r as any).ok === true;

  function respMsg(nodeId: string, slot: number, ok: boolean, requestId = "req-V"): GossipMessage {
    return {
      type: "cosign-response",
      from: nodeId,
      data: {
        requestId,
        slot,
        signerNodeId: nodeId,
        signerPublicKey: "0xpk",
        signatureCompact: "0xsig",
        messageHash: "0xhash",
        ok,
      } as any,
      timestamp: Date.now(),
      ttl: 0,
      messageId: `resp-${nodeId}-${slot}`,
      version: 0,
    };
  }

  it("bogus responses that fail validation do NOT count and cannot crowd out honest signers", async () => {
    const svc = buildService();
    const promise = (svc as any).requestCoSignatures(reqPayload({ requestId: "req-V" }), {
      threshold: 2,
      timeoutMs: 1000,
      validate: validateOk,
      dedupKey: bySlot,
    }) as Promise<CoSignResponsePayload[]>;
    let settled = false;
    void promise.then(() => (settled = true));

    // One peer floods 3 bogus responses with DISTINCT signer ids + slots → none validate.
    (svc as any).handleCoSignResponse(respMsg("bad-1", 5, false));
    (svc as any).handleCoSignResponse(respMsg("bad-2", 6, false));
    (svc as any).handleCoSignResponse(respMsg("bad-3", 7, false));
    await flush();
    expect(settled).toBe(false); // still waiting — bogus never counted

    // Two honest, valid, distinct-slot responses → resolves with EXACTLY those.
    (svc as any).handleCoSignResponse(respMsg("good-1", 1, true));
    (svc as any).handleCoSignResponse(respMsg("good-2", 2, true));
    const responses = await promise;
    expect(responses).toHaveLength(2);
    expect(responses.map(r => r.slot).sort((a, b) => a - b)).toEqual([1, 2]);
  });

  it("MEDIUM 1: EXACT resends are dropped BEFORE validate + total validations are capped", async () => {
    const svc = buildService();
    let validateCalls = 0;
    const countingValidate = async (r: CoSignResponsePayload) => {
      validateCalls++;
      return (r as any).ok === true;
    };
    const promise = (svc as any).requestCoSignatures(reqPayload({ requestId: "req-cap" }), {
      threshold: 3,
      timeoutMs: 20,
      validate: countingValidate,
      dedupKey: bySlot,
      maxValidations: 5,
    }) as Promise<CoSignResponsePayload[]>;

    // Same peer resends the IDENTICAL bogus response 10× → validate runs at most ONCE for it.
    for (let i = 0; i < 10; i++) {
      (svc as any).handleCoSignResponse(respMsg("flood", 5, false, "req-cap"));
    }
    await flush();
    expect(validateCalls).toBe(1); // exact-dedup collapsed the 10 resends to a single validate

    // Distinct bogus responses beyond the cap are dropped without validating.
    for (let i = 0; i < 20; i++) {
      (svc as any).handleCoSignResponse(respMsg(`d-${i}`, (i % 12) + 1, false, "req-cap"));
    }
    await flush();
    expect(validateCalls).toBeLessThanOrEqual(5); // maxValidations cap enforced
    await promise; // times out (never reached threshold) — bogus flood never formed a quorum
  });

  it("MEDIUM 1: a bogus early claim on a slot does NOT poison the honest signer's real response", async () => {
    const svc = buildService();
    const promise = (svc as any).requestCoSignatures(reqPayload({ requestId: "req-poison" }), {
      threshold: 1,
      timeoutMs: 1000,
      validate: validateOk,
      dedupKey: bySlot,
    }) as Promise<CoSignResponsePayload[]>;

    // Attacker claims slot 2 FIRST with a bogus (invalid) response → fails validate, not counted.
    (svc as any).handleCoSignResponse(respMsg("attacker", 2, false, "req-poison"));
    await flush();
    // The HONEST dvt2 then sends its real slot-2 response → still validates + counts (no poisoning).
    (svc as any).handleCoSignResponse(respMsg("dvt2", 2, true, "req-poison"));
    const responses = await promise;
    expect(responses).toHaveLength(1);
    expect(responses[0].slot).toBe(2);
    expect(responses[0].signerNodeId).toBe("dvt2");
  });

  it("resolves EARLY once enough validated unique-slot responses arrive (before timeout)", async () => {
    const svc = buildService();
    const promise = (svc as any).requestCoSignatures(reqPayload({ requestId: "req-V" }), {
      threshold: 2,
      timeoutMs: 5000, // long — must resolve on validated count, not timeout
      validate: validateOk,
      dedupKey: bySlot,
    }) as Promise<CoSignResponsePayload[]>;
    (svc as any).handleCoSignResponse(respMsg("a", 1, true));
    (svc as any).handleCoSignResponse(respMsg("b", 2, true));
    const responses = await promise;
    expect(responses).toHaveLength(2);
  });

  it("resolves on TIMEOUT with the validated partial set", async () => {
    const svc = buildService();
    const promise = (svc as any).requestCoSignatures(reqPayload({ requestId: "req-V" }), {
      threshold: 3,
      timeoutMs: 20,
      validate: validateOk,
      dedupKey: bySlot,
    }) as Promise<CoSignResponsePayload[]>;
    (svc as any).handleCoSignResponse(respMsg("a", 1, true));
    (svc as any).handleCoSignResponse(respMsg("bad", 2, false)); // dropped
    const responses = await promise;
    // Threshold 3 never met (only 1 valid) → resolves on timeout with the single validated response.
    expect(responses).toHaveLength(1);
    expect(responses[0].slot).toBe(1);
  });

  it("the SAME slot from two distinct nodes counts ONCE (dedup by slot)", async () => {
    const svc = buildService();
    const promise = (svc as any).requestCoSignatures(reqPayload({ requestId: "req-V" }), {
      threshold: 2,
      timeoutMs: 20,
      validate: validateOk,
      dedupKey: bySlot,
    }) as Promise<CoSignResponsePayload[]>;
    // Two DISTINCT nodes both claim slot 2 (valid sigs) → deduped to one → threshold 2 NOT met.
    (svc as any).handleCoSignResponse(respMsg("node-2a", 2, true));
    (svc as any).handleCoSignResponse(respMsg("node-2b", 2, true));
    const responses = await promise; // resolves on timeout with the single unique slot
    expect(responses).toHaveLength(1);
    expect(responses[0].slot).toBe(2);
  });

  it("a validated response arriving AFTER resolution is safely ignored (no leak / no throw)", async () => {
    const svc = buildService();
    const promise = (svc as any).requestCoSignatures(reqPayload({ requestId: "req-V" }), {
      threshold: 1,
      timeoutMs: 1000,
      validate: validateOk,
      dedupKey: bySlot,
    }) as Promise<CoSignResponsePayload[]>;
    (svc as any).handleCoSignResponse(respMsg("a", 1, true));
    const responses = await promise;
    expect(responses).toHaveLength(1);
    // Pending entry cleaned up → a late response is a no-op (no throw, nothing counted).
    expect((svc as any).pendingCoSign.has("req-V")).toBe(false);
    expect(() => (svc as any).handleCoSignResponse(respMsg("late", 9, true))).not.toThrow();
  });
});

/**
 * FINDING 3 (per-connection anti-DoS): the global `maxValidations` budget can be exhausted by ONE
 * malicious peer flooding distinct bogus responses (varying signerNodeId/slot/sig) before honest
 * peers' responses arrive → honest signers dropped (liveness). signerNodeId/from is
 * attacker-controlled; the CONNECTION (ws) is the un-forgeable identity, so validations are capped
 * per connection. The global cap + exact-dedup remain as backstops; a response with no ws (direct
 * test injection) skips only the per-connection check.
 */
describe("GossipService co-sign collector: per-connection cap (finding-3)", () => {
  const flush = () => new Promise(r => setTimeout(r, 0));
  const bySlot = (r: CoSignResponsePayload) => r.slot;

  function respMsg(nodeId: string, slot: number, ok: boolean, requestId: string): GossipMessage {
    return {
      type: "cosign-response",
      from: nodeId,
      data: {
        requestId,
        slot,
        signerNodeId: nodeId,
        signerPublicKey: "0xpk",
        signatureCompact: "0xsig",
        messageHash: "0xhash",
        ok,
      } as any,
      timestamp: Date.now(),
      ttl: 0,
      messageId: `resp-${nodeId}-${slot}`,
      version: 0,
    };
  }

  it("one flooding connection is capped at perConnCap and CANNOT crowd out honest signers on OTHER connections", async () => {
    const svc = buildService();
    let floodValidations = 0;
    const validate = async (r: CoSignResponsePayload) => {
      if (String(r.signerNodeId).startsWith("bad-")) floodValidations++;
      return (r as any).ok === true;
    };
    const promise = (svc as any).requestCoSignatures(reqPayload({ requestId: "req-conn" }), {
      threshold: 2,
      timeoutMs: 1000,
      validate,
      dedupKey: bySlot,
      perConnCap: 4,
    }) as Promise<CoSignResponsePayload[]>;
    let settled = false;
    void promise.then(() => (settled = true));

    const wsFlood = {} as any; // one attacker connection

    // Flooder sends 10 DISTINCT bogus responses on ONE connection → only perConnCap (4) validate.
    for (let i = 0; i < 10; i++) {
      (svc as any).handleCoSignResponse(respMsg(`bad-${i}`, i + 1, false, "req-conn"), wsFlood);
    }
    await flush();
    expect(floodValidations).toBe(4); // per-connection cap enforced — NOT all 10
    expect(settled).toBe(false); // bogus never counted → still waiting for honest signers

    // Honest peers on OTHER connections still validate + count to the threshold (not crowded out).
    (svc as any).handleCoSignResponse(respMsg("good-1", 11, true, "req-conn"), {} as any);
    (svc as any).handleCoSignResponse(respMsg("good-2", 12, true, "req-conn"), {} as any);
    const responses = await promise;
    expect(responses).toHaveLength(2);
    expect(responses.map(r => r.slot).sort((a, b) => a - b)).toEqual([11, 12]);
  });

  it("exact-dedup still fires FIRST (identical resends on one ws validate at most once)", async () => {
    const svc = buildService();
    let validateCalls = 0;
    const validate = async () => {
      validateCalls++;
      return false;
    };
    const promise = (svc as any).requestCoSignatures(reqPayload({ requestId: "req-exact" }), {
      threshold: 3,
      timeoutMs: 20,
      validate,
      dedupKey: bySlot,
      perConnCap: 4,
    }) as Promise<CoSignResponsePayload[]>;
    const ws = {} as any;
    for (let i = 0; i < 10; i++) {
      (svc as any).handleCoSignResponse(respMsg("flood", 5, false, "req-exact"), ws);
    }
    await flush();
    expect(validateCalls).toBe(1); // exact-dedup collapsed the 10 identical resends
    await promise;
  });

  it("a response with NO ws still respects the global maxValidations cap", async () => {
    const svc = buildService();
    let validateCalls = 0;
    const validate = async () => {
      validateCalls++;
      return false;
    };
    const promise = (svc as any).requestCoSignatures(reqPayload({ requestId: "req-nows" }), {
      threshold: 3,
      timeoutMs: 20,
      validate,
      dedupKey: bySlot,
      maxValidations: 5,
      perConnCap: 4,
    }) as Promise<CoSignResponsePayload[]>;
    // 20 distinct responses injected with NO ws → per-connection check skipped, global cap bounds.
    for (let i = 0; i < 20; i++) {
      (svc as any).handleCoSignResponse(respMsg(`n-${i}`, (i % 12) + 1, false, "req-nows"));
    }
    await flush();
    expect(validateCalls).toBeLessThanOrEqual(5); // global cap still enforced without a ws
    await promise;
  });
});

describe("GossipService liveness ledger (offline-audit rule ②)", () => {
  it("records lastSeen on heartbeat and returns null for a never-seen node", () => {
    const svc = buildService();
    expect(svc.getLastSeen("peer-x")).toBeNull();
    const before = Date.now();
    (svc as any).handleHeartbeatMessage({ from: "peer-x" } as GossipMessage);
    const seen = svc.getLastSeen("peer-x");
    expect(seen).not.toBeNull();
    expect(seen!).toBeGreaterThanOrEqual(before);
    expect(svc.getLastSeen("other")).toBeNull();
  });

  it("advances lastSeen on a later heartbeat", () => {
    const svc = buildService();
    (svc as any).handleHeartbeatMessage({ from: "peer-y" } as GossipMessage);
    const first = svc.getLastSeen("peer-y")!;
    (svc as any).handleHeartbeatMessage({ from: "peer-y" } as GossipMessage);
    expect(svc.getLastSeen("peer-y")!).toBeGreaterThanOrEqual(first);
  });

  it("ledger survives peer cleanup (records lastSeen even with no peer in the connection map)", () => {
    const svc = buildService();
    // A heartbeat from a peer NOT in the `peers` map still records liveness — the offline proof needs
    // the lastSeen even after SWIM cleanup removes the peer entry.
    (svc as any).handleHeartbeatMessage({ from: "ghost" } as GossipMessage);
    expect((svc as any).peers.has("ghost")).toBe(false);
    expect(svc.getLastSeen("ghost")).not.toBeNull();
  });
});
