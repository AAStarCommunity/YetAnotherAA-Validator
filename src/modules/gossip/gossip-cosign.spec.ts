import { GossipService } from "./gossip.service.js";
import type {
  CoSignRequestPayload,
  CoSignResponsePayload,
  GossipMessage,
} from "./gossip.interfaces.js";

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
