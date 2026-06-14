import { Injectable, Logger } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { ethers } from "ethers";

@Injectable()
export class BlockchainService {
  private readonly logger = new Logger(BlockchainService.name);
  private provider: ethers.Provider;
  private wallet: ethers.Wallet;

  constructor(private configService: ConfigService) {
    this.initializeProvider();
  }

  private initializeProvider(): void {
    const privateKey = this.configService.get<string>("ethPrivateKey");

    // Create provider (read-only connection)
    this.provider = new ethers.JsonRpcProvider(this.configService.get<string>("ethRpcUrl"));

    if (!privateKey || privateKey === "your_eth_private_key_here") {
      this.logger.warn(
        "ETH_PRIVATE_KEY not set or using placeholder, blockchain operations will be disabled"
      );
      return;
    }

    try {
      this.wallet = new ethers.Wallet(privateKey, this.provider);
      this.logger.log(`Blockchain service initialized with wallet: ${this.wallet.address}`);
    } catch (error: any) {
      this.logger.error(`Invalid private key provided: ${error.message}`);
      this.logger.warn("Blockchain write operations will be disabled");
    }
  }

  async registerNodeOnChain(
    contractAddress: string,
    nodeId: string,
    publicKey: string
  ): Promise<string> {
    if (!this.wallet) {
      throw new Error("Blockchain not configured. Set ETH_PRIVATE_KEY environment variable.");
    }

    const abi = [
      "function registerPublicKey(bytes32 nodeId, bytes calldata publicKey) external",
      "function isRegistered(bytes32 nodeId) external view returns (bool)",
    ];

    const contract = new ethers.Contract(contractAddress, abi, this.wallet);

    try {
      // Check if already registered
      const isAlreadyRegistered = await contract.isRegistered(nodeId);
      if (isAlreadyRegistered) {
        this.logger.warn(`Node ${nodeId} is already registered on-chain`);
        return "already_registered";
      }

      this.logger.log(`Registering node ${nodeId} on contract ${contractAddress}`);

      // Call registerPublicKey function
      const tx = await contract.registerPublicKey(nodeId, publicKey);
      this.logger.log(`Transaction submitted: ${tx.hash}`);

      // Wait for transaction confirmation
      const receipt = await tx.wait();
      this.logger.log(`Transaction confirmed in block: ${receipt.blockNumber}`);

      return tx.hash;
    } catch (error: any) {
      this.logger.error(`Failed to register node on-chain: ${error.message}`);
      throw error;
    }
  }

  async checkNodeRegistration(contractAddress: string, nodeId: string): Promise<boolean> {
    if (!this.provider) {
      throw new Error("Blockchain provider not configured");
    }

    const abi = ["function isRegistered(bytes32 nodeId) external view returns (bool)"];

    const contract = new ethers.Contract(contractAddress, abi, this.provider);

    try {
      const isRegistered = await contract.isRegistered(nodeId);
      return isRegistered;
    } catch (error: any) {
      this.logger.error(`Failed to check registration status: ${error.message}`);
      throw error;
    }
  }

  async getRegisteredNodeCount(contractAddress: string): Promise<number> {
    if (!this.provider) {
      throw new Error("Blockchain provider not configured");
    }

    const abi = ["function getRegisteredNodeCount() external view returns (uint256)"];

    const contract = new ethers.Contract(contractAddress, abi, this.provider);

    try {
      const count = await contract.getRegisteredNodeCount();
      return Number(count);
    } catch (error: any) {
      this.logger.error(`Failed to get registered node count: ${error.message}`);
      throw error;
    }
  }

  isConfigured(): boolean {
    return !!this.wallet;
  }

  getWalletAddress(): string | null {
    return this.wallet?.address || null;
  }

  async revokeNodeOnChain(contractAddress: string, nodeId: string): Promise<string> {
    if (!this.wallet) {
      throw new Error("Blockchain not configured. Set ETH_PRIVATE_KEY environment variable.");
    }

    const abi = [
      "function revokePublicKey(bytes32 nodeId) external",
      "function isRegistered(bytes32 nodeId) external view returns (bool)",
    ];

    const contract = new ethers.Contract(contractAddress, abi, this.wallet);

    try {
      // Check if registered
      const isRegistered = await contract.isRegistered(nodeId);
      if (!isRegistered) {
        this.logger.warn(`Node ${nodeId} is not registered on-chain`);
        return "not_registered";
      }

      this.logger.log(`Revoking node ${nodeId} on contract ${contractAddress}`);

      // Call revokePublicKey function
      const tx = await contract.revokePublicKey(nodeId);
      this.logger.log(`Transaction submitted: ${tx.hash}`);

      // Wait for transaction confirmation
      const receipt = await tx.wait();
      this.logger.log(`Transaction confirmed in block: ${receipt.blockNumber}`);

      return tx.hash;
    } catch (error: any) {
      this.logger.error(`Failed to revoke node on-chain: ${error.message}`);
      throw error;
    }
  }

  async batchRegisterNodesOnChain(
    contractAddress: string,
    nodeIds: string[],
    publicKeys: string[]
  ): Promise<string> {
    if (!this.wallet) {
      throw new Error("Blockchain not configured. Set ETH_PRIVATE_KEY environment variable.");
    }

    if (nodeIds.length !== publicKeys.length) {
      throw new Error("Node IDs and public keys array length mismatch");
    }

    const abi = [
      "function batchRegisterPublicKeys(bytes32[] calldata nodeIds, bytes[] calldata publicKeys) external",
    ];

    const contract = new ethers.Contract(contractAddress, abi, this.wallet);

    try {
      this.logger.log(`Batch registering ${nodeIds.length} nodes on contract ${contractAddress}`);

      const tx = await contract.batchRegisterPublicKeys(nodeIds, publicKeys);
      this.logger.log(`Batch registration transaction submitted: ${tx.hash}`);

      const receipt = await tx.wait();
      this.logger.log(`Batch registration confirmed in block: ${receipt.blockNumber}`);

      return tx.hash;
    } catch (error: any) {
      this.logger.error(`Failed to batch register nodes on-chain: ${error.message}`);
      throw error;
    }
  }

  async getNodePublicKey(contractAddress: string, nodeId: string): Promise<string> {
    if (!this.provider) {
      throw new Error("Blockchain provider not configured");
    }

    const abi = ["function registeredKeys(bytes32 nodeId) external view returns (bytes memory)"];

    const contract = new ethers.Contract(contractAddress, abi, this.provider);

    try {
      const publicKey = await contract.registeredKeys(nodeId);
      return publicKey;
    } catch (error: any) {
      this.logger.error(`Failed to get node public key: ${error.message}`);
      throw error;
    }
  }

  /**
   * Read the on-chain owner of an AirAccount.
   *
   * Used by the Fix 2 Stage 1 owner-authorization gate. The v0.18 account exposes
   * `address public owner` (see AAStarAirAccountBase.sol), which Solidity surfaces as
   * a `owner() view returns (address)` getter. Uses the read-only provider (no wallet
   * required), so it works on nodes that have no ETH_PRIVATE_KEY configured.
   */
  async getAccountOwner(account: string): Promise<string> {
    if (!this.provider) {
      throw new Error("Blockchain provider not configured");
    }

    const abi = ["function owner() view returns (address)"];
    const contract = new ethers.Contract(account, abi, this.provider);

    try {
      const owner: string = await contract.owner();
      return ethers.getAddress(owner);
    } catch (error: any) {
      this.logger.error(`Failed to read owner() for account ${account}: ${error.message}`);
      throw error;
    }
  }

  async getRegisteredNodes(
    contractAddress: string,
    offset: number,
    limit: number
  ): Promise<{ nodeIds: string[]; publicKeys: string[] }> {
    if (!this.provider) {
      throw new Error("Blockchain provider not configured");
    }

    const abi = [
      "function getRegisteredNodes(uint256 offset, uint256 limit) external view returns (bytes32[] memory nodeIds, bytes[] memory publicKeys)",
    ];

    const contract = new ethers.Contract(contractAddress, abi, this.provider);

    try {
      const result = await contract.getRegisteredNodes(offset, limit);
      return {
        nodeIds: result.nodeIds,
        publicKeys: result.publicKeys,
      };
    } catch (error: any) {
      this.logger.error(`Failed to get registered nodes: ${error.message}`);
      throw error;
    }
  }
}
