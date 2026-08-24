import { Controller, Get, Post, UseGuards } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { ApiTags, ApiOperation, ApiResponse } from "@nestjs/swagger";
import { NodeAdminGuard } from "../../common/node-admin.guard.js";
import { NodeService } from "./node.service.js";

@ApiTags("node")
@Controller("node")
export class NodeController {
  constructor(
    private readonly nodeService: NodeService,
    private readonly configService: ConfigService
  ) {}

  @ApiOperation({ summary: "Get current node information (private key never exposed)" })
  @ApiResponse({
    status: 200,
    description: "Current node information — the private key is omitted entirely",
    schema: {
      type: "object",
      properties: {
        nodeId: {
          type: "string",
          description: "Unique identifier of the node",
        },
        nodeName: { type: "string", description: "Name of the node" },
        publicKey: { type: "string", description: "Public key in hex format" },
        createdAt: { type: "string", description: "Node creation timestamp" },
      },
    },
  })
  @Get("info")
  getCurrentNodeInfo() {
    // Strip the private key OUT of the response (not just mask its value) so the
    // public endpoint never even names the field. Other callers read the key via
    // NodeService.getNodeForSigning(), not this DTO.
    const { privateKey: _omitted, ...safe } = this.nodeService.getCurrentNode();
    void _omitted;
    // Surface the PUBLIC keeper EOA (secp256k1 address for on-chain keeper txs) so it can be
    // verified/funded (CC-34). null when the keeper isn't provisioned into this node's config.
    const keeperAddress = this.configService.get<string>("keeperAddress") || null;
    return { ...safe, keeperAddress };
  }

  // STATE-CHANGING ADMIN ENDPOINT (CC-49 round-4 HIGH-1). This sends an on-chain transaction
  // from the node's funded account and, before this guard existed, was callable by any
  // unauthenticated remote caller (the node binds 0.0.0.0 and dvt1/2/3 are publicly tunnelled).
  // NodeAdminGuard is DISABLED by default; the supported registration path is the operator CLI
  // scripts/register-node.mjs.
  @UseGuards(NodeAdminGuard)
  @ApiOperation({
    summary: "Register current node on-chain (node-admin only; disabled by default)",
  })
  @ApiResponse({
    status: 200,
    description: "Node registration result",
    schema: {
      type: "object",
      properties: {
        success: {
          type: "boolean",
          description: "Registration success status",
        },
        message: { type: "string", description: "Result message" },
        nodeId: { type: "string", description: "Node ID that was registered" },
        txHash: {
          type: "string",
          description: "Transaction hash (if new registration)",
        },
      },
    },
  })
  @ApiResponse({ status: 401, description: "X-Node-Admin-Token missing" })
  @ApiResponse({ status: 403, description: "Node admin disabled, non-loopback, or bad token" })
  @ApiResponse({ status: 429, description: "Node admin rate limit exceeded" })
  @ApiResponse({
    status: 502,
    description:
      "On-chain registration failed upstream. The provider's own error text is NEVER echoed " +
      "— it carries the RPC credential; read the (scrubbed) node log instead.",
  })
  @Post("register")
  async registerOnChain() {
    // registerOnChain FIRST: it owns the "no node state" case and answers a structured 503,
    // whereas getCurrentNode() throws a bare Error (→ 500) for the same condition.
    const result = await this.nodeService.registerOnChain();
    const nodeState = this.nodeService.getNodeState();

    return {
      ...result,
      nodeId: nodeState?.nodeId,
    };
  }

  @ApiOperation({ summary: "Health check endpoint" })
  @ApiResponse({
    status: 200,
    description: "Node health status",
    schema: {
      type: "object",
      properties: {
        status: { type: "string", description: "Node status" },
        timestamp: { type: "number", description: "Current timestamp" },
        nodeId: { type: "string", description: "Node identifier" },
        uptime: { type: "number", description: "Uptime in milliseconds" },
      },
    },
  })
  @Get("health")
  getHealth() {
    const nodeState = this.nodeService.getCurrentNode();
    return {
      status: "active",
      timestamp: Date.now(),
      nodeId: nodeState?.nodeId || "unknown",
      uptime: process.uptime() * 1000,
    };
  }
}
