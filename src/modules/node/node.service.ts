import { Injectable, OnModuleInit, Logger, Inject, forwardRef } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { NodeKeyPair, NodeState } from "../../interfaces/node.interface.js";
import { readFileSync, writeFileSync, existsSync, readdirSync } from "fs";
import { join } from "path";
import { BlsService } from "../bls/bls.service.js";
import { BlockchainService } from "../blockchain/blockchain.service.js";
import { randomBytes, createHash } from "crypto";
import { decryptKeystore, isKeystore } from "../../utils/keystore.util.js";

@Injectable()
export class NodeService implements OnModuleInit {
  private readonly logger = new Logger(NodeService.name);
  private nodeState: NodeState | null;
  private nodeStateFilePath: string;
  private contractAddress: string;

  constructor(
    @Inject(forwardRef(() => BlsService))
    private blsService: BlsService,
    private blockchainService: BlockchainService,
    private configService: ConfigService
  ) {}

  async onModuleInit() {
    await this.initializeNode();
  }

  private async initializeNode(): Promise<void> {
    this.loadContractAddress();

    // Use fixed file name: node_state.json
    this.nodeStateFilePath = join(process.cwd(), "node_state.json");

    if (existsSync(this.nodeStateFilePath)) {
      this.loadExistingNodeState();
      if (this.nodeState) {
        this.logger.log(`Loaded node state: ${this.nodeState.nodeId}`);
      }
    } else {
      this.logger.log("No node state file found. Node is not created yet.");
      this.nodeState = null;
    }
  }

  private loadContractAddress(): void {
    this.contractAddress = this.configService.get<string>("validatorContractAddress")!;
    this.logger.log(`Using contract address from environment: ${this.contractAddress}`);
  }

  private loadExistingNodeState(): void {
    let state: NodeState;
    try {
      state = JSON.parse(readFileSync(this.nodeStateFilePath, "utf8"));
    } catch (error: any) {
      throw new Error(`Failed to load node state: ${error.message}`);
    }
    this.nodeState = this.resolvePrivateKey(state);
  }

  /**
   * Resolve the in-memory private key (#5). If the on-disk state carries an EIP-2335
   * `keystore`, decrypt it with NODE_KEY_PASSPHRASE and populate `privateKey`. Plaintext
   * `privateKey` (dev/legacy) is used as-is. Fails closed: an encrypted keystore with no
   * passphrase — or a wrong one — throws, so the node never boots with an unusable key.
   */
  private resolvePrivateKey(state: NodeState): NodeState {
    if (isKeystore(state.keystore)) {
      const passphrase = this.configService.get<string>("keyPassphrase");
      if (!passphrase) {
        throw new Error(
          "node_state.json holds an encrypted keystore but NODE_KEY_PASSPHRASE is not set"
        );
      }
      const secret = decryptKeystore(state.keystore, passphrase); // throws on wrong passphrase
      state.privateKey = "0x" + Buffer.from(secret).toString("hex");
      this.logger.log("BLS key loaded from encrypted keystore (EIP-2335)");
    } else if (!state.privateKey) {
      // Merged (KMS-TEE) mode: the BLS private key lives in the KMS TEE and NEVER touches disk.
      // A key-less node_state.json (nodeId + publicKey only) is valid ONLY when signing is BOTH
      // delegated (RUST_SIGNER_URL set) AND required (RUST_SIGNER_REQUIRED=true → never a local
      // fallback) — every signature is produced by the remote TEE signer, addressed by node_id.
      // The publicKey must still be present so nodeId derivation / gossip announcements work.
      const delegatedAndRequired =
        !!this.configService.get<string>("rustSignerUrl") &&
        this.configService.get<boolean>("rustSignerRequired") === true;
      if (!delegatedAndRequired) {
        throw new Error(
          "node_state.json has neither a keystore nor a plaintext privateKey " +
            "(a key-less node_state is only valid in KMS-TEE mode: RUST_SIGNER_URL + RUST_SIGNER_REQUIRED=true)"
        );
      }
      if (!state.publicKey) {
        throw new Error(
          "node_state.json has no privateKey and no publicKey — KMS-TEE (delegated) mode still needs the publicKey"
        );
      }
      this.logger.log(
        "BLS private key delegated to the remote TEE signer (RUST_SIGNER_REQUIRED) — no local key on disk (KMS-TEE mode)"
      );
    }
    return state;
  }

  saveNodeState(): void {
    try {
      // SECURITY (#5): when the key is stored encrypted (keystore present), NEVER write
      // the in-memory-decrypted plaintext privateKey back to disk — that would defeat
      // the at-rest encryption. Persist the keystore form only.
      let toWrite = this.nodeState;
      if (this.nodeState && isKeystore(this.nodeState.keystore)) {
        const { privateKey: _omit, ...rest } = this.nodeState;
        toWrite = rest as NodeState;
      }
      writeFileSync(this.nodeStateFilePath, JSON.stringify(toWrite, null, 2), "utf8");
    } catch (error: any) {
      throw new Error(`Failed to save node state: ${error.message}`);
    }
  }

  getCurrentNode(): NodeState {
    if (!this.nodeState) {
      throw new Error("Node not initialized");
    }
    return { ...this.nodeState };
  }

  getNodeForSigning(): NodeKeyPair {
    const currentNode = this.getCurrentNode();
    return {
      nodeId: currentNode.nodeId,
      nodeName: currentNode.nodeName,
      privateKey: currentNode.privateKey,
      publicKey: currentNode.publicKey,
      description: currentNode.description,
    };
  }

  async registerOnChain(): Promise<{
    success: boolean;
    txHash?: string;
    message: string;
  }> {
    if (!this.nodeState) {
      throw new Error("No node state loaded. Create a node first.");
    }

    if (!this.blockchainService.isConfigured()) {
      throw new Error(
        "Blockchain service not configured. Set ETH_PRIVATE_KEY and ETH_RPC_URL environment variables."
      );
    }

    try {
      // Check current registration status on-chain
      const isRegistered = await this.blockchainService.checkNodeRegistration(
        this.contractAddress,
        this.nodeState.nodeId
      );

      if (isRegistered) {
        this.nodeState.registeredAt = new Date().toISOString();
        this.saveNodeState();

        return {
          success: true,
          message: `Node ${this.nodeState.nodeId} is already registered on-chain`,
        };
      }

      // Perform actual registration
      this.logger.log(`Registering node ${this.nodeState.nodeId} on-chain...`);

      // Convert 48-byte public key to 128-byte EIP2537 format for contract registration
      const privateKeyHex = this.nodeState.privateKey.substring(2);
      const privateKeyBytes = new Uint8Array(privateKeyHex.length / 2);
      for (let i = 0; i < privateKeyHex.length; i += 2) {
        privateKeyBytes[i / 2] = parseInt(privateKeyHex.substr(i, 2), 16);
      }

      const { sigs } = await import("../../utils/bls.util.js");
      const publicKeyPoint = sigs.getPublicKey(privateKeyBytes);
      const eip2537PublicKey = this.blsService.encodePublicKeyToEIP2537(publicKeyPoint);

      const txHash = await this.blockchainService.registerNodeOnChain(
        this.contractAddress,
        this.nodeState.nodeId,
        eip2537PublicKey
      );

      if (txHash === "already_registered") {
        this.nodeState.registeredAt = new Date().toISOString();
        this.saveNodeState();

        return {
          success: true,
          message: "Node was already registered on-chain",
        };
      }

      // Update local state with registration time
      this.nodeState.registeredAt = new Date().toISOString();
      this.saveNodeState();

      this.logger.log(`Node ${this.nodeState.nodeId} registered successfully. TX: ${txHash}`);

      return {
        success: true,
        txHash,
        message: `Node registered successfully on-chain`,
      };
    } catch (error: any) {
      this.logger.error(`Failed to register node on-chain: ${error.message}`);

      return {
        success: false,
        message: `Registration failed: ${error.message}`,
      };
    }
  }

  getContractAddress(): string {
    return this.contractAddress;
  }

  getNodeState(): NodeState | null {
    return this.nodeState || null;
  }

  /**
   * Reload node state from file (useful after create/delete operations)
   */
  reloadNodeState(): void {
    if (existsSync(this.nodeStateFilePath)) {
      this.loadExistingNodeState();
      this.logger.log(`Reloaded node state: ${this.nodeState?.nodeId || "unknown"}`);
    } else {
      this.nodeState = null;
      this.logger.log("Node state file not found, cleared internal state");
    }
  }
}
