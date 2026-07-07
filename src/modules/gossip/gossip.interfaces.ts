import type { CoSignRequest } from "../audit/slash-consensus.js";

export interface GossipMessage {
  type: "gossip" | "sync" | "heartbeat" | "join" | "leave" | "cosign-request" | "cosign-response";
  from: string;
  to?: string; // Optional: for directed messages
  data: any;
  timestamp: number;
  ttl: number; // Time to live for message propagation
  messageId: string; // Unique message identifier
  version: number; // Version for conflict resolution
}

/**
 * DVT Phase 2 (目标2, inc-2 live) — slash quorum co-sign transport payloads.
 *
 * The gossip layer is a DUMB point-to-point transport for these: it carries the request to
 * peers and routes their responses back by `requestId`, and runs ZERO slash logic (no rule
 * evaluation, no signing, no verification). All safety lives in the registered handler
 * (GossipQuorumCoSigner) — the gossip service only invokes it and relays its reply.
 */
export interface CoSignRequestPayload extends CoSignRequest {
  /** Correlation id, distinct from the gossip `messageId` (which is fresh per send). */
  requestId: string;
  /** The requesting node's id (for logging / observability only — never trusted). */
  requesterNodeId: string;
}

export interface CoSignResponsePayload {
  /** Echoes the request's correlation id so the requester can route this reply. */
  requestId: string;
  /** The signer's 1-indexed on-chain validator slot. */
  slot: number;
  /** The responding node's id. */
  signerNodeId: string;
  /** The signer's 48-byte compressed G1 public key (0x-hex). */
  signerPublicKey: string;
  /** The signer's 96-byte compressed G2 signature over hashToCurve(messageHash) (0x-hex). */
  signatureCompact: string;
  /** The messageHash the responder recomputed and actually signed. */
  messageHash: string;
}

export interface PeerInfo {
  nodeId: string;
  publicKey: string;
  apiEndpoint: string;
  gossipEndpoint: string;
  status: "active" | "inactive" | "suspected";
  lastSeen: Date;
  region?: string;
  capabilities?: string[];
  version?: string;
  heartbeatCount: number; // For failure detection
}

export interface NodeState {
  nodeId: string;
  data: Map<string, any>; // Key-value store for gossip data
  version: number; // Version vector for consistency
  lastUpdated: Date;
}

export interface GossipConfig {
  gossipInterval: number; // How often to gossip (ms)
  fanout: number; // Number of peers to gossip to each round
  maxTTL: number; // Maximum TTL for messages
  heartbeatInterval: number; // Heartbeat frequency (ms)
  suspicionTimeout: number; // Time before marking peer as suspected (ms)
  cleanupTimeout: number; // Time before removing inactive peers (ms)
  maxMessageHistory: number; // Maximum messages to keep in history
}

export interface GossipStats {
  totalPeers: number;
  activePeers: number;
  suspectedPeers: number;
  messagesSent: number;
  messagesReceived: number;
  gossipRounds: number;
  lastGossipTime: Date | null;
}

export interface MessageHistory {
  messageId: string;
  timestamp: number;
  propagatedTo: Set<string>; // Track which peers we've sent this message to
}
