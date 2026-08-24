import { Injectable } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { redactRpcUrl } from "./redact.js";

export interface EnvironmentConfig {
  // Server
  port: number;
  host: string;
  publicUrl: string;

  // Blockchain
  ethRpcUrl: string;
  ethPrivateKey?: string;
  validatorContractAddress: string;

  // Node Configuration
  nodeId?: string;
  nodeStateFile?: string;

  // Gossip Network
  gossipPublicUrl?: string;
  gossipBootstrapPeers: string[];
  gossipInterval: number;
  gossipFanout: number;
  gossipMaxTtl: number;
  gossipHeartbeatInterval: number;
  gossipSuspicionTimeout: number;
  gossipCleanupTimeout: number;
  gossipMaxMessageHistory: number;
}

@Injectable()
export class EnvConfigService {
  private static instance: EnvironmentConfig;

  constructor(private configService: ConfigService) {
    if (!EnvConfigService.instance) {
      EnvConfigService.instance = this.loadConfig();
      this.validateConfig();
    }
  }

  private loadConfig(): EnvironmentConfig {
    const port = parseInt(this.configService.get<string>("PORT", "3000"), 10);

    return {
      // Server
      port,
      host: "0.0.0.0",
      publicUrl: this.configService.get<string>("PUBLIC_URL", `http://localhost:${port}`),

      // Blockchain
      ethRpcUrl: this.configService.get<string>("ETH_RPC_URL") || "",
      ethPrivateKey: this.configService.get<string>("ETH_PRIVATE_KEY"),
      validatorContractAddress: this.configService.get<string>("VALIDATOR_CONTRACT_ADDRESS") || "",

      // Node Configuration
      nodeId: this.configService.get<string>("NODE_ID"),
      nodeStateFile: this.configService.get<string>("NODE_STATE_FILE"),

      // Gossip Network
      gossipPublicUrl: this.configService.get<string>(
        "GOSSIP_PUBLIC_URL",
        `ws://localhost:${port}/ws`
      ),
      gossipBootstrapPeers: this.parseBootstrapPeers(),
      gossipInterval: parseInt(this.configService.get<string>("GOSSIP_INTERVAL", "5000"), 10),
      gossipFanout: parseInt(this.configService.get<string>("GOSSIP_FANOUT", "3"), 10),
      gossipMaxTtl: parseInt(this.configService.get<string>("GOSSIP_MAX_TTL", "5"), 10),
      gossipHeartbeatInterval: parseInt(
        this.configService.get<string>("GOSSIP_HEARTBEAT_INTERVAL", "10000"),
        10
      ),
      gossipSuspicionTimeout: parseInt(
        this.configService.get<string>("GOSSIP_SUSPICION_TIMEOUT", "30000"),
        10
      ),
      gossipCleanupTimeout: parseInt(
        this.configService.get<string>("GOSSIP_CLEANUP_TIMEOUT", "60000"),
        10
      ),
      gossipMaxMessageHistory: parseInt(
        this.configService.get<string>("GOSSIP_MAX_MESSAGE_HISTORY", "1000"),
        10
      ),
    };
  }

  private parseBootstrapPeers(): string[] {
    const peersString = this.configService.get<string>("GOSSIP_BOOTSTRAP_PEERS", "");
    if (!peersString) return [];
    return peersString
      .split(",")
      .map(p => p.trim())
      .filter(p => p.length > 0);
  }

  private validateConfig(): void {
    const config = EnvConfigService.instance;
    const errors: string[] = [];

    // Validate required fields
    if (!config.ethRpcUrl) {
      errors.push("ETH_RPC_URL is required");
    }

    if (!config.validatorContractAddress) {
      errors.push("VALIDATOR_CONTRACT_ADDRESS is required");
    }

    // Validate port
    if (config.port < 1 || config.port > 65535) {
      errors.push("PORT must be between 1 and 65535");
    }

    // Validate gossip configuration
    if (config.gossipInterval < 1000) {
      errors.push("GOSSIP_INTERVAL must be at least 1000ms");
    }

    if (config.gossipFanout < 1) {
      errors.push("GOSSIP_FANOUT must be at least 1");
    }

    if (config.gossipMaxTtl < 1) {
      errors.push("GOSSIP_MAX_TTL must be at least 1");
    }

    // If there are errors, throw them all at once
    if (errors.length > 0) {
      throw new Error(
        `Environment configuration validation failed:\n${errors.map(e => `  - ${e}`).join("\n")}`
      );
    }

    console.log("✅ Environment configuration validated successfully");
    console.log(`   - Validator Contract: ${config.validatorContractAddress}`);
    console.log(`   - ETH RPC URL: ${redactRpcUrl(config.ethRpcUrl)}`);
    console.log(`   - Port: ${config.port}`);
    if (config.nodeId) {
      console.log(`   - Node ID: ${config.nodeId}`);
    }
    if (config.nodeStateFile) {
      console.log(`   - Node State File: ${config.nodeStateFile}`);
    }
  }

  static get(): EnvironmentConfig {
    if (!EnvConfigService.instance) {
      throw new Error(
        "EnvConfigService not initialized. Please ensure it is imported in AppModule"
      );
    }
    return EnvConfigService.instance;
  }

  get config(): EnvironmentConfig {
    return EnvConfigService.instance;
  }
}

// Export a function for direct access
export function getEnvConfig(): EnvironmentConfig {
  return EnvConfigService.get();
}
