import {
  Controller,
  Get,
  Post,
  Delete,
  Body,
  Param,
  HttpCode,
  HttpStatus,
  Render,
  Res,
  UseGuards,
} from "@nestjs/common";
import { ApiTags, ApiOperation, ApiResponse, ApiParam, ApiBody } from "@nestjs/swagger";
import { DashboardService, NodeInfo } from "./dashboard.service.js";
import { BlockchainService } from "../blockchain/blockchain.service.js";
import { ConfigService } from "@nestjs/config";
import type { Response } from "express";
import { NodeAdminGuard } from "../../common/node-admin.guard.js";
import { CreateNodeDto } from "./dto/create-node.dto.js";
import { ImportNodeDto } from "./dto/import-node.dto.js";

@ApiTags("dashboard")
@Controller("dashboard")
export class DashboardController {
  private readonly contractAddress: string;

  constructor(
    private readonly dashboardService: DashboardService,
    private readonly blockchainService: BlockchainService,
    private readonly configService: ConfigService
  ) {
    this.contractAddress = this.configService.get<string>("validatorContractAddress")!;
  }

  @Get()
  @ApiOperation({ summary: "Get dashboard page" })
  async getDashboardPage(@Res() res: Response) {
    const nodes = await this.dashboardService.listNodes();
    const currentNode = await this.dashboardService.getCurrentRunningNode();
    const registeredCount = await this.blockchainService.getRegisteredNodeCount(
      this.contractAddress
    );
    const walletAddress = this.blockchainService.getWalletAddress();

    // Return HTML page
    const html = this.generateDashboardHTML(nodes, currentNode, registeredCount, walletAddress);
    res.setHeader("Content-Type", "text/html");
    res.send(html);
  }

  @Get("nodes")
  @ApiOperation({ summary: "List all nodes from blockchain" })
  @ApiResponse({ status: 200, description: "List of all nodes" })
  async listNodes(): Promise<NodeInfo[]> {
    return this.dashboardService.listNodes();
  }

  @Get("current-node")
  @ApiOperation({ summary: "Get current running node" })
  @ApiResponse({ status: 200, description: "Current node information" })
  async getCurrentNode(): Promise<NodeInfo | null> {
    return this.dashboardService.getCurrentRunningNode();
  }

  // STATE-CHANGING ADMIN ENDPOINTS (CC-49 round-4 HIGH-1 audit of the same class of route).
  // These three create, import (a RAW BLS PRIVATE KEY) and destroy this node's key material,
  // and were reachable unauthenticated on 0.0.0.0 exactly like POST /node/register. Same gate,
  // same default-off. The read endpoints and the HTML page are unchanged: they expose only
  // values that are already public on-chain.
  @UseGuards(NodeAdminGuard)
  @Post("nodes")
  @ApiOperation({
    summary: "Create a new BLS node (node-admin only; disabled by default)",
  })
  @ApiBody({ type: CreateNodeDto })
  @ApiResponse({ status: 201, description: "Node created successfully" })
  async createNode(@Body() dto: CreateNodeDto): Promise<NodeInfo> {
    return this.dashboardService.createNode(dto);
  }

  @UseGuards(NodeAdminGuard)
  @Post("import-node")
  @ApiOperation({
    summary: "Import an existing node state (node-admin only; disabled by default)",
  })
  @ApiBody({ type: ImportNodeDto })
  @ApiResponse({ status: 201, description: "Node imported successfully" })
  async importNode(@Body() dto: ImportNodeDto): Promise<NodeInfo> {
    return this.dashboardService.importNode(dto);
  }

  @UseGuards(NodeAdminGuard)
  @Delete("current-node")
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: "Delete the current running node (node-admin only; disabled by default)",
  })
  @ApiResponse({ status: 200, description: "Node deleted successfully" })
  @ApiResponse({ status: 400, description: "Cannot delete registered node" })
  async deleteCurrentNode(): Promise<{ success: boolean; message: string }> {
    return this.dashboardService.deleteCurrentNode();
  }

  @Get("contract/info")
  @ApiOperation({ summary: "Get contract information" })
  @ApiResponse({ status: 200, description: "Contract information" })
  async getContractInfo(): Promise<{
    contractAddress: string;
    registeredCount: number;
    walletAddress: string | null;
    isConfigured: boolean;
  }> {
    const registeredCount = await this.blockchainService.getRegisteredNodeCount(
      this.contractAddress
    );
    const walletAddress = this.blockchainService.getWalletAddress();
    const isConfigured = this.blockchainService.isConfigured();

    return {
      contractAddress: this.contractAddress,
      registeredCount,
      walletAddress,
      isConfigured,
    };
  }

  @Get("contract/nodes")
  @ApiOperation({ summary: "Get registered nodes from contract" })
  @ApiResponse({ status: 200, description: "Registered nodes from contract" })
  async getContractNodes(): Promise<{ nodeIds: string[]; publicKeys: string[] }> {
    const count = await this.blockchainService.getRegisteredNodeCount(this.contractAddress);

    if (count === 0) {
      return { nodeIds: [], publicKeys: [] };
    }

    return this.blockchainService.getRegisteredNodes(this.contractAddress, 0, count);
  }

  private generateDashboardHTML(
    nodes: NodeInfo[],
    currentNode: NodeInfo | null,
    registeredCount: number,
    walletAddress: string | null
  ): string {
    // Separate nodes with and without private keys
    const nodesWithKeys = nodes.filter(node => node.hasPrivateKey);
    const nodesWithoutKeys = nodes.filter(node => !node.hasPrivateKey);

    // Check if there are any registered nodes with private keys
    const hasRegisteredNode = nodesWithKeys.some(node => node.isRegistered);

    // Generate rows for nodes with private keys
    const privateKeyNodeRows = nodesWithKeys
      .map(
        node => `
      <tr>
        <td class="px-4 py-3 text-sm font-mono" title="${node.nodeId}">${node.nodeId.substring(0, 20)}...</td>
        <td class="px-4 py-3 text-sm">${node.metadata?.nodeName || "N/A"}</td>
        <td class="px-4 py-3 text-sm text-center">
          <span class="status-badge ${node.isRegistered ? "status-registered" : "status-pending"}">
            ${node.isRegistered ? "✓ On-Chain" : "✗ Not Registered"}
          </span>
        </td>
        <td class="px-4 py-3 text-sm">${node.metadata?.createdAt ? new Date(node.metadata.createdAt).toLocaleString() : "N/A"}</td>
        <td class="px-4 py-3 text-sm">
          <div class="flex space-x-2">
            ${
              !node.isRegistered
                ? `
            <button onclick="registerNode('${node.nodeId}')" class="btn btn-primary btn-sm">
              Register
            </button>
            <button onclick="deletePrivateKey('${node.nodeId}')" class="btn btn-danger btn-sm">
              Delete Key
            </button>
            `
                : `
            <button onclick="revokeNode('${node.nodeId}')" class="btn btn-warning btn-sm">
              Revoke
            </button>
            `
            }
          </div>
        </td>
      </tr>
    `
      )
      .join("");

    // Generate rows for nodes without private keys (chain-only nodes)
    const chainNodeRows = nodesWithoutKeys
      .map(
        node => `
      <tr class="chain-node-row">
        <td class="px-4 py-3 text-sm font-mono" title="${node.nodeId}">${node.nodeId.substring(0, 20)}...</td>
        <td class="px-4 py-3 text-sm">${node.metadata?.nodeName || "N/A"}</td>
        <td class="px-4 py-3 text-sm text-center">
          <span class="status-badge status-registered">✓ On-Chain</span>
        </td>
        <td class="px-4 py-3 text-sm">${node.metadata?.createdAt ? new Date(node.metadata.createdAt).toLocaleString() : "N/A"}</td>
      </tr>
    `
      )
      .join("");

    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Dashboard - AAStarValidator</title>
  <script src="https://cdn.jsdelivr.net/npm/ethers@5.7.2/dist/ethers.umd.min.js"></script>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');

    * { margin: 0; padding: 0; box-sizing: border-box; }

    body {
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
      background: #0a0e27;
      min-height: 100vh;
      padding: 24px;
      color: #e2e8f0;
    }

    .container {
      max-width: 1400px;
      margin: 0 auto;
    }

    .header {
      background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
      border: 1px solid rgba(148, 163, 184, 0.1);
      border-radius: 16px;
      padding: 32px;
      margin-bottom: 32px;
      position: relative;
      overflow: hidden;
    }

    .header::before {
      content: '';
      position: absolute;
      top: 0;
      left: 0;
      right: 0;
      height: 2px;
      background: linear-gradient(90deg, #3b82f6, #8b5cf6, #ec4899);
    }

    .header h1 {
      font-size: 32px;
      font-weight: 700;
      background: linear-gradient(135deg, #60a5fa 0%, #a78bfa 50%, #f472b6 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
      margin-bottom: 8px;
      letter-spacing: -0.02em;
    }

    .header p {
      color: #94a3b8;
      font-size: 15px;
      font-weight: 500;
    }
    .stats {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
      gap: 20px;
      margin-bottom: 32px;
    }

    .stat-card {
      background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
      border: 1px solid rgba(148, 163, 184, 0.1);
      padding: 24px;
      border-radius: 16px;
      position: relative;
      overflow: hidden;
      transition: all 0.3s ease;
    }

    .stat-card::before {
      content: '';
      position: absolute;
      top: 0;
      left: 0;
      right: 0;
      height: 3px;
      background: linear-gradient(90deg, #3b82f6, #8b5cf6);
      opacity: 0;
      transition: opacity 0.3s ease;
    }

    .stat-card:hover {
      transform: translateY(-2px);
      border-color: rgba(148, 163, 184, 0.3);
    }

    .stat-card:hover::before {
      opacity: 1;
    }

    .stat-label {
      font-size: 13px;
      color: #94a3b8;
      text-transform: uppercase;
      font-weight: 600;
      letter-spacing: 0.05em;
      margin-bottom: 12px;
    }

    .stat-value {
      font-size: 28px;
      color: #f1f5f9;
      font-weight: 700;
      letter-spacing: -0.02em;
    }

    .stat-value.small {
      font-size: 18px;
      font-family: 'JetBrains Mono', monospace;
      color: #60a5fa;
    }

    .copy-btn {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 28px;
      height: 28px;
      background: rgba(59, 130, 246, 0.1);
      border: 1px solid rgba(59, 130, 246, 0.3);
      border-radius: 6px;
      cursor: pointer;
      transition: all 0.2s ease;
      margin-left: 8px;
    }

    .copy-btn:hover {
      background: rgba(59, 130, 246, 0.2);
      border-color: rgba(59, 130, 246, 0.5);
      transform: translateY(-1px);
    }

    .copy-btn:active {
      transform: translateY(0);
    }

    .copy-btn svg {
      width: 14px;
      height: 14px;
      fill: #60a5fa;
    }

    .address-container {
      display: flex;
      align-items: center;
      justify-content: center;
    }

    .card {
      background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
      border: 1px solid rgba(148, 163, 184, 0.1);
      border-radius: 16px;
      overflow: hidden;
      margin-bottom: 32px;
      backdrop-filter: blur(10px);
    }

    .card-header {
      background: rgba(30, 41, 59, 0.5);
      padding: 24px 32px;
      border-bottom: 1px solid rgba(148, 163, 184, 0.1);
      display: flex;
      justify-content: space-between;
      align-items: center;
    }

    .card-title {
      font-size: 20px;
      font-weight: 600;
      color: #f1f5f9;
      letter-spacing: -0.01em;
    }
    table {
      width: 100%;
      border-collapse: collapse;
    }

    th {
      background: rgba(30, 41, 59, 0.5);
      padding: 16px 20px;
      text-align: left;
      font-size: 12px;
      font-weight: 600;
      color: #94a3b8;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }

    td {
      padding: 20px;
      border-top: 1px solid rgba(148, 163, 184, 0.1);
      color: #cbd5e1;
      font-size: 14px;
    }

    tr:hover {
      background: rgba(30, 41, 59, 0.3);
    }

    .btn {
      padding: 10px 20px;
      border: none;
      border-radius: 8px;
      font-size: 14px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.2s ease;
      font-family: 'Inter', sans-serif;
      letter-spacing: -0.01em;
    }

    .btn:disabled {
      opacity: 0.4;
      cursor: not-allowed;
    }

    .btn-primary {
      background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%);
      color: white;
      box-shadow: 0 4px 12px rgba(59, 130, 246, 0.3);
    }

    .btn-primary:hover:not(:disabled) {
      transform: translateY(-1px);
      box-shadow: 0 6px 16px rgba(59, 130, 246, 0.4);
    }

    .btn-warning {
      background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%);
      color: white;
      box-shadow: 0 4px 12px rgba(245, 158, 11, 0.3);
    }

    .btn-warning:hover:not(:disabled) {
      transform: translateY(-1px);
      box-shadow: 0 6px 16px rgba(245, 158, 11, 0.4);
    }

    .btn-danger {
      background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);
      color: white;
      box-shadow: 0 4px 12px rgba(239, 68, 68, 0.3);
    }

    .btn-danger:hover:not(:disabled) {
      transform: translateY(-1px);
      box-shadow: 0 6px 16px rgba(239, 68, 68, 0.4);
    }

    .btn-success {
      background: linear-gradient(135deg, #10b981 0%, #059669 100%);
      color: white;
      box-shadow: 0 4px 12px rgba(16, 185, 129, 0.3);
    }

    .btn-success:hover:not(:disabled) {
      transform: translateY(-1px);
      box-shadow: 0 6px 16px rgba(16, 185, 129, 0.4);
    }

    .btn-sm {
      padding: 8px 16px;
      font-size: 13px;
    }
    .status-badge {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 6px 14px;
      border-radius: 20px;
      font-size: 12px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.03em;
    }

    .status-pending {
      background: rgba(245, 158, 11, 0.1);
      color: #fbbf24;
      border: 1px solid rgba(245, 158, 11, 0.2);
    }

    .status-registered {
      background: rgba(16, 185, 129, 0.1);
      color: #34d399;
      border: 1px solid rgba(16, 185, 129, 0.2);
    }

    .status-failed {
      background: rgba(239, 68, 68, 0.1);
      color: #f87171;
      border: 1px solid rgba(239, 68, 68, 0.2);
    }

    .flex {
      display: flex;
    }

    .space-x-2 > * + * {
      margin-left: 10px;
    }

    .toast {
      position: fixed;
      top: 24px;
      right: 24px;
      background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
      border: 1px solid rgba(148, 163, 184, 0.2);
      padding: 16px 24px;
      border-radius: 12px;
      box-shadow: 0 10px 40px rgba(0, 0, 0, 0.5);
      display: none;
      z-index: 1000;
      color: #f1f5f9;
      font-weight: 500;
      max-width: 400px;
    }

    .toast.show {
      display: block;
      animation: slideIn 0.3s cubic-bezier(0.68, -0.55, 0.265, 1.55);
    }

    @keyframes slideIn {
      from {
        transform: translateX(120%) scale(0.9);
        opacity: 0;
      }
      to {
        transform: translateX(0) scale(1);
        opacity: 1;
      }
    }

    /* Modal styles */
    .modal-overlay {
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      background: rgba(0, 0, 0, 0.8);
      backdrop-filter: blur(8px);
      display: none;
      align-items: center;
      justify-content: center;
      z-index: 2000;
      animation: fadeIn 0.3s ease;
    }

    .modal-overlay.show {
      display: flex;
    }

    .modal {
      background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
      border: 1px solid rgba(148, 163, 184, 0.2);
      border-radius: 20px;
      padding: 40px;
      max-width: 520px;
      width: 90%;
      max-height: 90vh;
      overflow-y: auto;
      box-shadow: 0 25px 80px rgba(0, 0, 0, 0.6);
      animation: slideUp 0.4s cubic-bezier(0.68, -0.55, 0.265, 1.55);
    }

    .modal-title {
      font-size: 26px;
      font-weight: 700;
      color: #f1f5f9;
      margin-bottom: 28px;
      letter-spacing: -0.01em;
    }

    .form-group {
      margin-bottom: 24px;
    }

    .form-label {
      display: block;
      font-size: 14px;
      font-weight: 600;
      color: #cbd5e1;
      margin-bottom: 10px;
      letter-spacing: -0.01em;
    }

    .form-input {
      width: 100%;
      padding: 14px 16px;
      background: rgba(15, 23, 42, 0.6);
      border: 1px solid rgba(148, 163, 184, 0.2);
      border-radius: 10px;
      font-size: 15px;
      color: #f1f5f9;
      transition: all 0.2s ease;
      box-sizing: border-box;
      font-family: 'Inter', sans-serif;
    }

    .form-input:focus {
      outline: none;
      border-color: #3b82f6;
      background: rgba(15, 23, 42, 0.8);
      box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1);
    }

    .form-input::placeholder {
      color: #64748b;
    }

    .form-hint {
      font-size: 13px;
      color: #94a3b8;
      margin-top: 6px;
    }

    .modal-actions {
      display: flex;
      gap: 16px;
      margin-top: 32px;
    }

    .modal-actions .btn {
      flex: 1;
    }

    @keyframes fadeIn {
      from {
        opacity: 0;
      }
      to {
        opacity: 1;
      }
    }

    @keyframes slideUp {
      from {
        transform: translateY(40px) scale(0.95);
        opacity: 0;
      }
      to {
        transform: translateY(0) scale(1);
        opacity: 1;
      }
    }

    /* Mobile responsive */
    @media (max-width: 640px) {
      .modal {
        padding: 24px;
        width: 95%;
      }

      .modal-title {
        font-size: 20px;
      }

      .stats {
        grid-template-columns: 1fr;
      }

      table {
        font-size: 12px;
      }

      th, td {
        padding: 8px;
      }

      .btn-sm {
        padding: 4px 8px;
        font-size: 11px;
      }
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="header" style="display: flex; justify-content: space-between; align-items: center;">
      <div>
        <h1>🔐 Dashboard - Signer Management</h1>
        <p>AAStarValidator - ERC-4337 Account Abstraction</p>
      </div>
      <div style="display: flex; align-items: center; gap: 12px;">
        <button id="connectWalletBtn" onclick="toggleWallet()" class="btn btn-primary btn-sm" style="display: flex; align-items: center; gap: 8px;">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" style="flex-shrink: 0;">
            <path d="M21 18V19C21 20.1 20.1 21 19 21H5C3.9 21 3 20.1 3 19V5C3 3.9 3.9 3 5 3H19C20.1 3 21 3.9 21 5V6H12C10.9 6 10 6.9 10 8V16C10 17.1 10.9 18 12 18H21ZM12 16H22V8H12V16ZM16 13.5C15.17 13.5 14.5 12.83 14.5 12C14.5 11.17 15.17 10.5 16 10.5C16.83 10.5 17.5 11.17 17.5 12C17.5 12.83 16.83 13.5 16 13.5Z" fill="currentColor"/>
          </svg>
          <span>Connect Wallet</span>
        </button>
      </div>
    </div>

    ${
      currentNode
        ? `
    <div class="card">
      <div class="card-header">
        <h2 class="card-title" style="display: flex; align-items: center; gap: 10px;">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
            <circle cx="12" cy="12" r="3" fill="currentColor"/>
            <circle cx="12" cy="12" r="8" stroke="currentColor" stroke-width="2" fill="none"/>
            <path d="M12 2V4M12 20V22M22 12H20M4 12H2" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
          </svg>
          <span>Current Running Node</span>
        </h2>
      </div>
      <div style="padding: 24px;">
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px;">
          <div>
            <p style="margin-bottom: 8px;"><strong>Node ID:</strong></p>
            <div style="display: flex; align-items: center;">
              <p style="font-family: monospace; color: #4a5568; margin: 0;" title="${currentNode.nodeId}">${currentNode.nodeId}</p>
              <button class="copy-btn" onclick="copyToClipboard('${currentNode.nodeId}', this)" title="Copy Node ID">
                <svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                  <path d="M16 1H4c-1.1 0-2 .9-2 2v14h2V3h12V1zm3 4H8c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h11c1.1 0 2-.9 2-2V7c0-1.1-.9-2-2-2zm0 16H8V7h11v14z"/>
                </svg>
              </button>
            </div>
          </div>
          <div>
            <p style="margin-bottom: 8px;"><strong>Node Name:</strong></p>
            <p style="color: #4a5568;">${currentNode.metadata?.nodeName || "N/A"}</p>
          </div>
          <div>
            <p style="margin-bottom: 8px;"><strong>Registration Status:</strong></p>
            <span class="status-badge ${currentNode.isRegistered ? "status-registered" : "status-pending"}">
              ${currentNode.isRegistered ? "✓ Registered On-Chain" : "⏳ Not Registered"}
            </span>
          </div>
          <div>
            <p style="margin-bottom: 8px;"><strong>Stake Status:</strong></p>
            <span class="status-badge ${currentNode.metadata?.stakeStatus === "staked" ? "status-registered" : "status-pending"}">
              ${currentNode.metadata?.stakeStatus === "staked" ? "✓ Staked" : currentNode.metadata?.stakeStatus === "unstaking" ? "⏳ Unstaking" : "✗ Not Staked"}
            </span>
          </div>
          ${
            currentNode.metadata?.stakeAmount
              ? `
          <div>
            <p style="margin-bottom: 8px;"><strong>Stake Amount:</strong></p>
            <p style="color: #4a5568;">${currentNode.metadata.stakeAmount} ETH</p>
          </div>
          `
              : ""
          }
          <div>
            <p style="margin-bottom: 8px;"><strong>Created At:</strong></p>
            <p style="color: #4a5568;">${currentNode.metadata?.createdAt ? new Date(currentNode.metadata.createdAt).toLocaleString() : "N/A"}</p>
          </div>
          ${
            currentNode.metadata?.registeredAt
              ? `
          <div>
            <p style="margin-bottom: 8px;"><strong>Registered At:</strong></p>
            <p style="color: #4a5568;">${new Date(currentNode.metadata.registeredAt).toLocaleString()}</p>
          </div>
          `
              : ""
          }
        </div>
        <div style="margin-top: 16px; padding-top: 16px; border-top: 1px solid #e2e8f0;">
          <p style="margin-bottom: 8px;"><strong>Actions:</strong></p>
          <div style="display: flex; gap: 8px; flex-wrap: wrap;">
            ${
              !currentNode.isRegistered
                ? `
            <button onclick="registerCurrentNode('${currentNode.nodeId}')" class="btn btn-primary btn-sm">
              Register On-Chain
            </button>
            <button onclick="deleteCurrentNode()" class="btn btn-danger btn-sm">
              Delete Node
            </button>
            `
                : ""
            }
            ${
              currentNode.isRegistered && currentNode.metadata?.stakeStatus !== "staked"
                ? `
            <button onclick="stakeCurrentNode('${currentNode.nodeId}')" class="btn btn-success btn-sm" disabled title="Stake功能即将推出">
              Stake Node (Coming Soon)
            </button>
            `
                : ""
            }
          </div>
        </div>
      </div>
    </div>
    `
        : `
    <div class="card">
      <div class="card-header">
        <h2 class="card-title" style="display: flex; align-items: center; gap: 10px;">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
            <circle cx="12" cy="12" r="3" fill="currentColor"/>
            <circle cx="12" cy="12" r="8" stroke="currentColor" stroke-width="2" fill="none"/>
            <path d="M12 2V4M12 20V22M22 12H20M4 12H2" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
          </svg>
          <span>Current Running Node</span>
        </h2>
      </div>
      <div style="padding: 24px; text-align: center; color: #718096;">
        <p>No running node detected. Start a node with NODE_ID or NODE_STATE_FILE environment variable.</p>
      </div>
    </div>
    `
    }

    <div class="stats">
      <div class="stat-card">
        <div class="stat-label">Total Nodes</div>
        <div class="stat-value">${nodes.length}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">On-Chain Registered</div>
        <div class="stat-value">${registeredCount}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Contract Address</div>
        <div class="address-container">
          <div class="stat-value small" title="${this.contractAddress}">${this.contractAddress.substring(0, 20)}...</div>
          <button class="copy-btn" onclick="copyToClipboard('${this.contractAddress}', this)" title="Copy full address">
            <svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
              <path d="M16 1H4c-1.1 0-2 .9-2 2v14h2V3h12V1zm3 4H8c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h11c1.1 0 2-.9 2-2V7c0-1.1-.9-2-2-2zm0 16H8V7h11v14z"/>
            </svg>
          </button>
        </div>
      </div>
    </div>

    ${
      nodesWithKeys.length > 0
        ? `
    <div class="card">
      <div class="card-header">
        <h2 class="card-title">🔑 My Nodes (With Private Key)</h2>
        <button onclick="createNode()" class="btn btn-success" ${hasRegisteredNode ? 'disabled title="Cannot create new node when registered node exists"' : ""}>➕ Create New Node</button>
      </div>
      <table>
        <thead>
          <tr>
            <th>Node ID</th>
            <th>Name</th>
            <th>On-Chain Status</th>
            <th>Created At</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          ${privateKeyNodeRows}
        </tbody>
      </table>
    </div>
    `
        : `
    <div class="card">
      <div class="card-header">
        <h2 class="card-title">🔑 My Nodes (With Private Key)</h2>
        <button onclick="createNode()" class="btn btn-success" ${hasRegisteredNode ? 'disabled title="Cannot create new node when registered node exists"' : ""}>➕ Create New Node</button>
      </div>
      <div style="padding: 40px; text-align: center; color: #718096;">
        <p>No local nodes found. Create your first node!</p>
      </div>
    </div>
    `
    }

    ${
      nodesWithoutKeys.length > 0
        ? `
    <div class="card">
      <div class="card-header">
        <h2 class="card-title">🌐 Chain Registered Nodes (${nodesWithoutKeys.length} total)</h2>
        <input type="text"
               id="nodeSearch"
               placeholder="Search by Node ID..."
               class="form-input"
               style="max-width: 300px; padding: 8px 12px;"
               onkeyup="filterChainNodes()">
      </div>
      <table id="chainNodesTable">
        <thead>
          <tr>
            <th>Node ID</th>
            <th>Name</th>
            <th>Status</th>
            <th>Created At</th>
          </tr>
        </thead>
        <tbody id="chainNodesBody">
          ${chainNodeRows}
        </tbody>
      </table>
      <div id="chainNodesPagination" style="padding: 16px; text-align: center; color: #718096; font-size: 14px;">
        Showing <span id="displayCount">0</span> of ${nodesWithoutKeys.length} nodes
      </div>
    </div>
    `
        : ""
    }
  </div>

  <div id="toast" class="toast"></div>

  <!-- Create Node Modal -->
  <div id="createNodeModal" class="modal-overlay">
    <div class="modal">
      <h2 class="modal-title">🔐 Create New BLS Node</h2>
      <form id="createNodeForm">
        <div class="form-group">
          <label class="form-label" for="nodeName">Node Name</label>
          <input type="text" id="nodeName" class="form-input" placeholder="e.g., my-validator-node" />
          <div class="form-hint">Optional: A friendly name for your node</div>
        </div>
        <div class="form-group">
          <label class="form-label" for="nodeDescription">Description</label>
          <input type="text" id="nodeDescription" class="form-input" placeholder="e.g., Production validator node" />
          <div class="form-hint">Optional: Description of this node's purpose</div>
        </div>
        <div class="modal-actions">
          <button type="button" onclick="closeCreateNodeModal()" class="btn btn-warning">Cancel</button>
          <button type="submit" class="btn btn-primary">Create Node</button>
        </div>
      </form>
    </div>
  </div>

  <script>
    let userWalletAddress = null;
    const contractAddress = '${this.contractAddress}';

    // Contract ABI (kept for potential future use)
    const contractABI = [];

    function showToast(message, duration = 3000) {
      const toast = document.getElementById('toast');
      toast.textContent = message;
      toast.classList.add('show');
      setTimeout(() => toast.classList.remove('show'), duration);
    }

    // Copy to clipboard function
    function copyToClipboard(text, element) {
      navigator.clipboard.writeText(text).then(() => {
        // Check if it's a button element
        if (element.tagName === 'BUTTON') {
          const originalHTML = element.innerHTML;
          element.innerHTML = '<svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" style="width: 14px; height: 14px; fill: #34d399;"><path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/></svg>';
          element.style.background = 'rgba(16, 185, 129, 0.1)';
          element.style.borderColor = 'rgba(16, 185, 129, 0.3)';
          setTimeout(() => {
            element.innerHTML = originalHTML;
            element.style.background = '';
            element.style.borderColor = '';
          }, 2000);
        } else {
          const originalHTML = element.innerHTML;
          element.innerHTML = '<span style="color: #48bb78;">✓ Copied!</span>';
          setTimeout(() => {
            element.innerHTML = originalHTML;
          }, 2000);
        }
        showToast('✅ Copied to clipboard!');
      }).catch(err => {
        showToast('❌ Failed to copy: ' + err.message);
      });
    }

    // Filter chain nodes
    function filterChainNodes() {
      const searchInput = document.getElementById('nodeSearch');
      if (!searchInput) return; // No search input, skip filtering

      const searchValue = searchInput.value.toLowerCase();
      const rows = document.querySelectorAll('.chain-node-row');
      let visibleCount = 0;
      let displayedCount = 0;
      const maxDisplay = 10;

      rows.forEach(row => {
        const nodeId = row.querySelector('td').textContent.toLowerCase();
        const matches = nodeId.includes(searchValue);

        if (matches) {
          visibleCount++;
          if (displayedCount < maxDisplay) {
            row.style.display = '';
            displayedCount++;
          } else {
            row.style.display = 'none';
          }
        } else {
          row.style.display = 'none';
        }
      });

      const displayCountEl = document.getElementById('displayCount');
      if (displayCountEl) {
        displayCountEl.textContent = displayedCount;
      }
    }

    // Initialize chain nodes display on page load
    window.addEventListener('DOMContentLoaded', () => {
      // Only filter if search input exists
      if (document.getElementById('nodeSearch')) {
        filterChainNodes();
      }

      // Restore wallet connection from localStorage
      const savedWallet = localStorage.getItem('connectedWallet');
      if (savedWallet && typeof window.ethereum !== 'undefined') {
        // Try to reconnect automatically
        window.ethereum.request({ method: 'eth_accounts' })
          .then(accounts => {
            if (accounts.length > 0 && accounts[0].toLowerCase() === savedWallet.toLowerCase()) {
              userWalletAddress = accounts[0];
              updateWalletUI(accounts[0]);
            } else {
              localStorage.removeItem('connectedWallet');
            }
          })
          .catch(err => {
            console.error('Failed to restore wallet connection:', err);
            localStorage.removeItem('connectedWallet');
          });
      }

      // Listen for account changes
      if (typeof window.ethereum !== 'undefined') {
        window.ethereum.on('accountsChanged', (accounts) => {
          if (accounts.length === 0) {
            // User disconnected wallet
            userWalletAddress = null;
            localStorage.removeItem('connectedWallet');
            resetWalletUI();
          } else if (accounts[0] !== userWalletAddress) {
            // User switched accounts
            userWalletAddress = accounts[0];
            localStorage.setItem('connectedWallet', accounts[0]);
            updateWalletUI(accounts[0]);
          }
        });
      }
    });

    function updateWalletUI(address) {
      const btn = document.getElementById('connectWalletBtn');
      btn.innerHTML = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" style="flex-shrink: 0;"><path d="M13 3L4 14H11L10 21L19 10H12L13 3Z" fill="currentColor" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg><span>Disconnect</span>';
      btn.classList.remove('btn-primary');
      btn.classList.add('btn-danger');
      userWalletAddress = address;
    }

    function resetWalletUI() {
      const btn = document.getElementById('connectWalletBtn');
      btn.innerHTML = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" style="flex-shrink: 0;"><path d="M21 18V19C21 20.1 20.1 21 19 21H5C3.9 21 3 20.1 3 19V5C3 3.9 3.9 3 5 3H19C20.1 3 21 3.9 21 5V6H12C10.9 6 10 6.9 10 8V16C10 17.1 10.9 18 12 18H21ZM12 16H22V8H12V16ZM16 13.5C15.17 13.5 14.5 12.83 14.5 12C14.5 11.17 15.17 10.5 16 10.5C16.83 10.5 17.5 11.17 17.5 12C17.5 12.83 16.83 13.5 16 13.5Z" fill="currentColor"/></svg><span>Connect Wallet</span>';
      btn.classList.remove('btn-danger');
      btn.classList.add('btn-primary');
      userWalletAddress = null;
    }

    async function connectWallet() {
      if (typeof window.ethereum === 'undefined') {
        showToast('❌ Please install MetaMask!');
        return;
      }

      try {
        const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' });

        // Save to localStorage
        localStorage.setItem('connectedWallet', accounts[0]);

        updateWalletUI(accounts[0]);
        showToast('✅ Wallet connected: ' + accounts[0].substring(0, 6) + '...' + accounts[0].substring(38));
      } catch (error) {
        showToast('❌ Failed to connect wallet: ' + error.message);
      }
    }

    function disconnectWallet() {
      localStorage.removeItem('connectedWallet');
      resetWalletUI();
      showToast('👋 Wallet disconnected');
    }

    async function toggleWallet() {
      if (userWalletAddress) {
        disconnectWallet();
      } else {
        await connectWallet();
      }
    }

    async function registerCurrentNode(nodeId) {
      if (!userWalletAddress) {
        showToast('❌ Please connect your wallet first!');
        return;
      }

      if (!confirm('Register current node on-chain using your connected wallet? You will pay gas fees.')) return;

      try {
        console.log('Starting node registration...');

        // Get node details from backend
        const nodeResponse = await fetch('/dashboard/current-node');
        const nodeData = await nodeResponse.json();

        console.log('Node data:', nodeData);

        if (!nodeData || !nodeData.nodeId || !nodeData.publicKey) {
          showToast('❌ Failed to get node details');
          return;
        }

        // Use MetaMask to sign and send transaction
        const provider = new ethers.providers.Web3Provider(window.ethereum);
        const network = await provider.getNetwork();
        console.log('Connected to network:', network.name, 'Chain ID:', network.chainId);

        const signer = provider.getSigner();
        const signerAddress = await signer.getAddress();
        console.log('Signer address:', signerAddress);

        // Contract ABI for node registration
        const nodeABI = [
          'function registerPublicKey(bytes32 nodeId, bytes calldata publicKey) external',
          'function isRegistered(bytes32 nodeId) external view returns (bool)'
        ];

        const contract = new ethers.Contract(contractAddress, nodeABI, signer);
        console.log('Contract address:', contractAddress);

        // Check if already registered
        showToast('🔍 Checking registration status...');
        const isRegistered = await contract.isRegistered(nodeData.nodeId);
        console.log('Is registered:', isRegistered);

        if (isRegistered) {
          showToast('ℹ️ Node is already registered on-chain');
          setTimeout(() => location.reload(), 2000);
          return;
        }

        // Estimate gas before sending
        showToast('⚙️ Estimating gas...');
        try {
          const gasEstimate = await contract.estimateGas.registerPublicKey(nodeData.nodeId, nodeData.publicKey);
          console.log('Gas estimate:', gasEstimate.toString());
        } catch (gasError) {
          console.error('Gas estimation failed:', gasError);
          showToast('❌ Gas estimation failed: ' + gasError.message);
          return;
        }

        // Call registerPublicKey - user pays gas
        showToast('📝 Please confirm transaction in MetaMask...');
        console.log('Calling registerPublicKey with:', {
          nodeId: nodeData.nodeId,
          publicKey: nodeData.publicKey
        });

        const tx = await contract.registerPublicKey(nodeData.nodeId, nodeData.publicKey);
        console.log('Transaction sent:', tx.hash);

        showToast('⏳ Transaction submitted: ' + tx.hash.substring(0, 10) + '...');
        const receipt = await tx.wait();
        console.log('Transaction confirmed:', receipt);

        showToast('✅ Node registered successfully! Block: ' + receipt.blockNumber);

        // Reload page after successful registration
        setTimeout(() => location.reload(), 2000);
      } catch (error) {
        console.error('Registration error:', error);
        console.error('Error details:', {
          code: error.code,
          message: error.message,
          data: error.data
        });

        let errorMessage = 'Failed to register node';

        if (error.code === 4001) {
          errorMessage = 'Transaction rejected by user';
        } else if (error.code === -32603) {
          errorMessage = 'Insufficient funds for gas';
        } else if (error.code === 'CALL_EXCEPTION') {
          errorMessage = 'Contract call failed: ' + (error.reason || error.message);
        } else if (error.message) {
          errorMessage = error.message;
        }

        showToast('❌ ' + errorMessage);
      }
    }

    async function stakeCurrentNode(nodeId) {
      showToast('ℹ️ Stake功能即将推出...');
      // TODO: Implement stake functionality
      // This will be implemented when staking is ready
    }

    // CC-49 round-4 HIGH-1. The dashboard write actions now go through NodeAdminGuard, so the
    // browser must present X-Node-Admin-Token. The token is asked for once per tab and kept in
    // sessionStorage only (never localStorage, never rendered into the page source, and gone
    // when the tab closes). Read-only views need nothing.
    function nodeAdminHeaders(extra) {
      let token = sessionStorage.getItem('dvtNodeAdminToken');
      if (!token) {
        token = prompt('Node admin token (NODE_ADMIN_TOKEN) — required for write actions:') || '';
        if (token) sessionStorage.setItem('dvtNodeAdminToken', token);
      }
      return Object.assign({ 'X-Node-Admin-Token': token }, extra || {});
    }

    // Drop a rejected token so the next attempt re-prompts instead of looping on a stale value.
    function forgetNodeAdminTokenIfRejected(status) {
      if (status === 401 || status === 403) sessionStorage.removeItem('dvtNodeAdminToken');
    }

    async function deleteCurrentNode() {
      console.log('deleteCurrentNode called');

      if (!confirm('⚠️ Delete current node?\\n\\nThis will permanently delete node_state.json.\\nThe node is not registered on-chain, so it is safe to delete.\\n\\nYou will need to restart the service after deletion.')) {
        console.log('User cancelled deletion');
        return;
      }

      try {
        console.log('Sending DELETE request...');
        const response = await fetch('/dashboard/current-node', {
          method: 'DELETE',
          headers: nodeAdminHeaders()
        });
        console.log('Response status:', response.status);

        const result = await response.json();
        console.log('Result:', result);

        if (response.ok && result.success) {
          showToast('✅ ' + result.message);
          setTimeout(() => location.reload(), 2000);
        } else {
          forgetNodeAdminTokenIfRejected(response.status);
          showToast('❌ ' + (result.message || 'Failed to delete node'));
        }
      } catch (error) {
        console.error('Delete error:', error);
        showToast('❌ Error: ' + error.message);
      }
    }

    function openCreateNodeModal() {
      document.getElementById('createNodeModal').classList.add('show');
      document.getElementById('nodeName').value = '';
      document.getElementById('nodeDescription').value = '';
      document.getElementById('nodeName').focus();
    }

    function closeCreateNodeModal() {
      document.getElementById('createNodeModal').classList.remove('show');
    }

    // Close modal when clicking outside
    document.getElementById('createNodeModal').addEventListener('click', (e) => {
      if (e.target.id === 'createNodeModal') {
        closeCreateNodeModal();
      }
    });

    // Handle form submission
    document.getElementById('createNodeForm').addEventListener('submit', async (e) => {
      e.preventDefault();

      const nodeName = document.getElementById('nodeName').value.trim();
      const description = document.getElementById('nodeDescription').value.trim();

      try {
        const submitBtn = e.target.querySelector('button[type="submit"]');
        submitBtn.disabled = true;
        submitBtn.textContent = 'Creating...';

        const response = await fetch('/dashboard/nodes', {
          method: 'POST',
          headers: nodeAdminHeaders({ 'Content-Type': 'application/json' }),
          body: JSON.stringify({
            nodeName: nodeName || undefined,
            description: description || undefined
          })
        });

        if (response.ok) {
          closeCreateNodeModal();
          showToast('✅ Node created successfully!');
          setTimeout(() => location.reload(), 1000);
        } else {
          forgetNodeAdminTokenIfRejected(response.status);
          const error = await response.json();
          showToast('❌ Failed to create node: ' + error.message);
          submitBtn.disabled = false;
          submitBtn.textContent = 'Create Node';
        }
      } catch (error) {
        showToast('❌ Error: ' + error.message);
        const submitBtn = e.target.querySelector('button[type="submit"]');
        submitBtn.disabled = false;
        submitBtn.textContent = 'Create Node';
      }
    });

    // Keep the old function name for button click
    function createNode() {
      openCreateNodeModal();
    }

    async function registerNode(nodeId) {
      showToast('ℹ️ Chain nodes cannot be registered from dashboard. Use the running node instead.');
    }

    async function revokeNode(nodeId) {
      showToast('ℹ️ Revoke operation is not available for chain nodes.');
    }

    async function deletePrivateKey(nodeId) {
      showToast('ℹ️ Private key management is only available for the current running node.');
    }
  </script>
</body>
</html>`;
  }
}
