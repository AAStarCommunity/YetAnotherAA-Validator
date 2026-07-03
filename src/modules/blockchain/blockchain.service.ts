import { Injectable, Logger } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { ethers } from "ethers";
import { bumpedFees } from "../../utils/gas.util.js";

/** ERC-4337 v0.7 PackedUserOperation (the exact tuple EntryPoint.getUserOpHash takes). */
export interface PackedUserOp {
  sender: string;
  nonce: ethers.BigNumberish;
  initCode: string;
  callData: string;
  accountGasLimits: string;
  preVerificationGas: ethers.BigNumberish;
  gasFees: string;
  paymasterAndData: string;
  signature: string;
}

@Injectable()
export class BlockchainService {
  private readonly logger = new Logger(BlockchainService.name);
  private provider: ethers.Provider;
  private wallet: ethers.Wallet;
  /** Dedicated keeper signer (KEEPER_PRIVATE_KEY) — kept SEPARATE from the relay
   *  operator key and the admin/registration key so the keeper's updatePrice()
   *  nonce queue can't contend with relay submissions on the same EOA. Falls back
   *  to `wallet` (ETH_PRIVATE_KEY) only when KEEPER_PRIVATE_KEY is unset. */
  private keeperWallet?: ethers.Wallet;

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
    } else {
      try {
        this.wallet = new ethers.Wallet(privateKey, this.provider);
        this.logger.log(`Blockchain service initialized with wallet: ${this.wallet.address}`);
      } catch (error: any) {
        this.logger.error(`Invalid private key provided: ${error.message}`);
        this.logger.warn("Blockchain write operations will be disabled");
      }
    }

    // Dedicated keeper signer (optional). Unset → keeper reuses `wallet`.
    const keeperKey = this.configService.get<string>("keeperPrivateKey");
    if (keeperKey && /^0x[0-9a-fA-F]{64}$/.test(keeperKey)) {
      try {
        this.keeperWallet = new ethers.Wallet(keeperKey, this.provider);
        this.logger.log(`Keeper signer (dedicated): ${this.keeperWallet.address}`);
      } catch (error: any) {
        this.logger.error(`Invalid KEEPER_PRIVATE_KEY: ${error.message}`);
      }
    }
  }

  /** Signer the keeper uses for updatePrice() — dedicated key if set, else the admin wallet. */
  private get keeperSigner(): ethers.Wallet | undefined {
    return this.keeperWallet ?? this.wallet;
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

  /**
   * Derive the authoritative ERC-4337 v0.7 userOpHash for a full UserOperation by
   * calling `getUserOpHash` on the canonical EntryPoint via the read-only provider.
   *
   * This is the binding step of the Fix 2 Stage 1 owner-authorization gate: the
   * EntryPoint computes the hash from `userOp.sender`, chainId, and the EntryPoint
   * address itself, so the resulting hash cannot be detached from its account.
   * A caller therefore cannot pair a signature over their own account's hash with
   * a victim's UserOperation.
   */
  async getUserOpHash(userOp: PackedUserOp): Promise<string> {
    if (!this.provider) {
      throw new Error("Blockchain provider not configured");
    }

    const entryPoint = this.configService.get<string>("entryPointAddress");
    if (!entryPoint) {
      throw new Error("EntryPoint address not configured");
    }

    const abi = [
      "function getUserOpHash((address sender,uint256 nonce,bytes initCode,bytes callData,bytes32 accountGasLimits,uint256 preVerificationGas,bytes32 gasFees,bytes paymasterAndData,bytes signature) userOp) view returns (bytes32)",
    ];
    const contract = new ethers.Contract(entryPoint, abi, this.provider);

    try {
      const hash: string = await contract.getUserOpHash({
        sender: userOp.sender,
        nonce: userOp.nonce,
        initCode: userOp.initCode,
        callData: userOp.callData,
        accountGasLimits: userOp.accountGasLimits,
        preVerificationGas: userOp.preVerificationGas,
        gasFees: userOp.gasFees,
        paymasterAndData: userOp.paymasterAndData,
        signature: userOp.signature,
      });
      return hash;
    } catch (error: any) {
      this.logger.error(
        `Failed to derive userOpHash via EntryPoint ${entryPoint}: ${error.message}`
      );
      throw error;
    }
  }

  /**
   * Read the DVT policy decision for one decoded call from the on-chain
   * IPolicyRegistry (Fix 2 Stage 2 — layer 1). This is the sender-keyed,
   * validation-time `view` defined by SuperPaymaster #283 and confirmed by
   * airaccount-contract #110:
   *
   *   checkPolicy(sender, target, asset, amount, selector)
   *     -> (PolicyDecision decision, uint256 remainingDaily)
   *   enum PolicyDecision { ALLOW = 0, REQUIRE_DVT = 1, REJECT = 2 }
   *
   * The registry is the SAME source slashing references (node-policy-source ==
   * slash-source), so a node that honors this read cannot be unfairly slashed.
   * Read-only — works without a wallet.
   */
  async checkPolicy(
    registryAddress: string,
    sender: string,
    target: string,
    asset: string,
    amount: ethers.BigNumberish,
    selector: string
  ): Promise<{ decision: number; remainingDaily: bigint }> {
    if (!this.provider) {
      throw new Error("Blockchain provider not configured");
    }

    const abi = [
      "function checkPolicy(address sender, address target, address asset, uint256 amount, bytes4 selector) view returns (uint8 decision, uint256 remainingDaily)",
    ];
    const contract = new ethers.Contract(registryAddress, abi, this.provider);

    try {
      const [decision, remainingDaily] = await contract.checkPolicy(
        sender,
        target,
        asset,
        amount,
        selector
      );
      return { decision: Number(decision), remainingDaily: BigInt(remainingDaily) };
    } catch (error: any) {
      this.logger.error(
        `checkPolicy revert on registry ${registryAddress} for sender ${sender}: ${error.message}`
      );
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

  // ── Price Keeper (Phase 1, #58) ────────────────────────────────────────────

  /**
   * Read SuperPaymaster's cached-price freshness info.
   * ABI confirmed against SuperPaymaster v5.4.x `getCachedPriceInfo()` + `priceStalenessThreshold()`.
   */
  async getPriceInfo(paymasterAddress: string): Promise<{ updatedAt: bigint; threshold: bigint }> {
    // Both SuperPaymaster v3 (PriceCache: int256 price, uint256 updatedAt, uint80
    // roundId, uint8 decimals) and PaymasterV4 (uint208 price, uint48 updatedAt)
    // expose `cachedPrice()` — NOT `getCachedPriceInfo()` (which reverts on the
    // current deployments). ABI encoding pads each field to its own word, so
    // `updatedAt` is the 2nd return value in BOTH; a single minimal 2-field ABI
    // reads it correctly for either type. (ABI mirrors @aastar/sdk PaymasterClient;
    // the node stays standalone — no SDK runtime dep, per the DVT↛SDK contract.)
    const abi = [
      "function cachedPrice() view returns (uint256 price, uint256 updatedAt)",
      "function priceStalenessThreshold() view returns (uint256)",
    ];
    const contract = new ethers.Contract(paymasterAddress, abi, this.provider);
    const [, updatedAt] = await contract.cachedPrice();
    const threshold = await contract.priceStalenessThreshold();
    return { updatedAt: BigInt(updatedAt), threshold: BigInt(threshold) };
  }

  /** Read Chainlink AggregatorV3 `latestRoundData().updatedAt` (unix seconds). */
  async getChainlinkUpdatedAt(feedAddress: string): Promise<bigint> {
    const abi = [
      "function latestRoundData() view returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound)",
    ];
    const contract = new ethers.Contract(feedAddress, abi, this.provider);
    const [, , , updatedAt] = await contract.latestRoundData();
    return BigInt(updatedAt);
  }

  /** Current network base-fee in gwei (0 on chains without EIP-1559). */
  async getBaseFeeGwei(): Promise<bigint> {
    const block = await this.provider.getBlock("latest");
    const baseFee = block?.baseFeePerGas ?? 0n;
    return BigInt(baseFee) / 1_000_000_000n;
  }

  /**
   * Validate owner authorization via ERC-1271 style view: eth_call the account's
   * `isValidOwnerAuth(userOpHash, ownerAuth)` and verify it returns the magic value.
   *
   * This replaces local ECDSA/P256 verification, ensuring DVT never drifts from the
   * contract's actual validation logic. The account is the single source of truth.
   *
   * @param account The account address to call
   * @param userOpHash The derived userOpHash to validate against
   * @param ownerAuth The owner authorization (ECDSA signature or WebAuthn blob)
   * @returns true if the account returns the magic value; false otherwise (fail-closed)
   */
  async isValidOwnerAuth(account: string, userOpHash: string, ownerAuth: string): Promise<boolean> {
    if (!this.provider) {
      throw new Error("Blockchain provider not configured");
    }

    // AAStarAirAccount custom magic value for isValidOwnerAuth (not standard ERC-1271)
    const MAGIC_VALUE = "0xa0cf00cf";

    const abi = [
      "function isValidOwnerAuth(bytes32 userOpHash, bytes calldata ownerAuth) view returns (bytes4)",
    ];
    const contract = new ethers.Contract(account, abi, this.provider);

    try {
      const result = await contract.isValidOwnerAuth(userOpHash, ownerAuth);
      return result === MAGIC_VALUE;
    } catch (error: any) {
      this.logger.warn(`isValidOwnerAuth eth_call failed for account ${account}: ${error.message}`);
      return false;
    }
  }

  /**
   * Static-simulate updatePrice() WITHOUT sending a tx. Returns true if it would
   * succeed, false if it would revert (e.g. SuperPaymaster's OracleError when the
   * cached price is already as fresh as Chainlink). The keeper calls this right
   * before submitting so that, when several redundant keepers tick close together,
   * only the first actually spends gas — the rest see the just-updated price and
   * skip instead of broadcasting a doomed (revert) tx. Cheap eth_call, no nonce.
   */
  async canUpdatePrice(paymasterAddress: string): Promise<boolean> {
    const signer = this.keeperSigner;
    const abi = ["function updatePrice() external"];
    const contract = new ethers.Contract(paymasterAddress, abi, signer ?? this.provider);
    try {
      await contract.updatePrice.staticCall();
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Call SuperPaymaster/PaymasterV4 updatePrice() — pushes a fresh Chainlink price
   * on-chain. Uses the dedicated keeper signer (KEEPER_PRIVATE_KEY) when set, and
   * bumps the EIP-1559 fees (estimate +15%, priority floor) so the tx mines
   * promptly instead of sitting underpriced. Returns the transaction hash.
   */
  async updatePrice(paymasterAddress: string): Promise<string> {
    const signer = this.keeperSigner;
    if (!signer) {
      throw new Error("Keeper: no wallet configured — set KEEPER_PRIVATE_KEY or ETH_PRIVATE_KEY");
    }
    const abi = ["function updatePrice() external"];
    const contract = new ethers.Contract(paymasterAddress, abi, signer);
    const fees = await bumpedFees(this.provider);
    const tx: ethers.TransactionResponse = await contract.updatePrice(fees);
    return tx.hash;
  }
}
