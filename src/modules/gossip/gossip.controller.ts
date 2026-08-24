import { Controller, Get, Post, Body, Param, UseGuards } from "@nestjs/common";
import { ApiTags, ApiOperation, ApiResponse, ApiParam, ApiBody } from "@nestjs/swagger";
import { scrubProviderError } from "../../config/redact.js";
import { NodeAdminGuard } from "../../common/node-admin.guard.js";
import { GossipService } from "./gossip.service.js";
import { PeerInfo, GossipStats } from "./gossip.interfaces.js";

import { IsString, IsNotEmpty, IsOptional } from "class-validator";

export class SetDataDto {
  @IsString()
  @IsNotEmpty()
  key: string;

  @IsOptional()
  value?: any;
}

@ApiTags("gossip")
@Controller("gossip")
export class GossipController {
  constructor(private readonly gossipService: GossipService) {}

  @Get("peers")
  @ApiOperation({
    summary: "Get all nodes in the gossip network including self",
  })
  @ApiResponse({
    status: 200,
    description: "List of all active nodes including current node",
  })
  getPeers(): { success: boolean; peers: PeerInfo[] } {
    return {
      success: true,
      peers: this.gossipService.getAllPeersIncludingSelf(),
    };
  }

  @Get("stats")
  @ApiOperation({ summary: "Get gossip network statistics" })
  @ApiResponse({ status: 200, description: "Gossip network statistics" })
  getStats(): { success: boolean; stats: GossipStats } {
    return {
      success: true,
      stats: this.gossipService.getStats(),
    };
  }

  @Get("data")
  @ApiOperation({ summary: "Get all gossip data" })
  @ApiResponse({ status: 200, description: "All gossip data" })
  getAllData(): { success: boolean; data: Record<string, any> } {
    const dataMap = this.gossipService.getAllData();
    const dataObject = Object.fromEntries(dataMap.entries());

    return {
      success: true,
      data: dataObject,
    };
  }

  @Get("data/:key")
  @ApiOperation({ summary: "Get specific gossip data by key" })
  @ApiParam({ name: "key", description: "Data key" })
  @ApiResponse({
    status: 200,
    description: "Gossip data for the specified key",
  })
  @ApiResponse({ status: 404, description: "Key not found" })
  getData(@Param("key") key: string): {
    success: boolean;
    data?: any;
    message?: string;
  } {
    const value = this.gossipService.getData(key);

    if (value !== undefined) {
      return {
        success: true,
        data: value,
      };
    } else {
      return {
        success: false,
        message: `Key '${key}' not found`,
      };
    }
  }

  // STATE-CHANGING ADMIN ENDPOINT (CC-49 round-4 HIGH-1 audit). Writes into the gossip state
  // this node republishes to its peers, and was unauthenticated on 0.0.0.0. The peer protocol
  // itself runs over the authenticated WebSocket transport, never this route — it is an
  // operator/debug affordance, so it takes the same default-off node-admin gate.
  @UseGuards(NodeAdminGuard)
  @Post("data")
  @ApiOperation({ summary: "Set gossip data (node-admin only; disabled by default)" })
  @ApiBody({
    type: SetDataDto,
    description: "Key-value pair to set in gossip state",
    examples: {
      example1: {
        summary: "Set node status",
        value: {
          key: "node-status",
          value: { status: "active", timestamp: Date.now() },
        },
      },
    },
  })
  @ApiResponse({ status: 200, description: "Data set successfully" })
  @ApiResponse({ status: 400, description: "Invalid request body" })
  setData(@Body() setDataDto: SetDataDto): {
    success: boolean;
    message: string;
  } {
    try {
      const { key, value } = setDataDto;

      if (!key) {
        return {
          success: false,
          message: "Key is required",
        };
      }

      this.gossipService.setData(key, value);

      return {
        success: true,
        message: `Data set for key '${key}'`,
      };
    } catch (error) {
      // Scrubbed, and never the raw text: this handler swallows its own error, so the global
      // ScrubbingExceptionFilter never sees it (CC-49 round-4, same shape as /node/register).
      return {
        success: false,
        message: `Failed to set data: ${scrubProviderError(error)}`,
      };
    }
  }

  @Get("state")
  @ApiOperation({ summary: "Get current node state" })
  @ApiResponse({
    status: 200,
    description: "Current node state including version and data",
  })
  getNodeState(): { success: boolean; state: any } {
    const state = this.gossipService.getNodeState();

    return {
      success: true,
      state: {
        nodeId: state.nodeId,
        version: state.version,
        lastUpdated: state.lastUpdated,
        dataCount: state.data.size,
        data: Object.fromEntries(state.data.entries()),
      },
    };
  }

  @Get("health")
  @ApiOperation({ summary: "Get gossip service health status" })
  @ApiResponse({
    status: 200,
    description: "Health status of the gossip service",
  })
  getHealth(): { success: boolean; health: any } {
    const stats = this.gossipService.getStats();

    const health = {
      status: "healthy",
      timestamp: new Date().toISOString(),
      peers: {
        total: stats.totalPeers,
        active: stats.activePeers,
        suspected: stats.suspectedPeers,
      },
      gossip: {
        rounds: stats.gossipRounds,
        messagesSent: stats.messagesSent,
        messagesReceived: stats.messagesReceived,
        lastGossipTime: stats.lastGossipTime,
      },
      connectivity: {
        hasActivePeers: stats.activePeers > 0,
        isGossiping: stats.lastGossipTime !== null,
      },
    };

    // Determine overall health status
    if (stats.activePeers === 0) {
      health.status = "isolated";
    } else if (stats.suspectedPeers > stats.activePeers) {
      health.status = "degraded";
    }

    return {
      success: true,
      health,
    };
  }
}
