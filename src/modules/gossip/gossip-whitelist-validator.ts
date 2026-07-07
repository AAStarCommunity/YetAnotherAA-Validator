import { URL } from "url";

/**
 * Whitelist-based validator for gossip endpoints
 *
 * Current implementation: Allows all nodes (unconditional access)
 * Future implementation: Will validate against on-chain staking records
 */
export class GossipWhitelistValidator {
  // Allowed protocols for gossip connections
  private static readonly ALLOWED_PROTOCOLS = ["ws:", "wss:"];

  /**
   * Check if running in development mode
   */
  private static isDevelopmentMode(): boolean {
    const nodeEnv = process.env.NODE_ENV?.toLowerCase();
    return nodeEnv === "development" || nodeEnv === "dev" || nodeEnv === "local";
  }

  /**
   * Validate an endpoint using whitelist approach
   *
   * Current behavior: Allows all valid WebSocket URLs
   *
   * @param endpoint The endpoint URL to validate
   * @returns Sanitized endpoint URL
   * @throws Error if the endpoint format is invalid
   */
  public static validateEndpoint(endpoint: string): string {
    // Basic validation
    if (!endpoint || typeof endpoint !== "string") {
      throw new Error("Endpoint must be a non-empty string");
    }

    // Trim whitespace
    endpoint = endpoint.trim();

    // Parse URL
    let url: URL;
    try {
      url = new URL(endpoint);
    } catch (error) {
      throw new Error(`Invalid URL format: ${endpoint}`, { cause: error });
    }

    // Validate protocol
    if (!this.ALLOWED_PROTOCOLS.includes(url.protocol)) {
      throw new Error(
        `Invalid protocol: ${url.protocol}. Allowed protocols: ${this.ALLOWED_PROTOCOLS.join(", ")}`
      );
    }

    const isDev = this.isDevelopmentMode();
    const hostname = url.hostname.toLowerCase();

    // Development mode: Log localhost connections
    if (isDev && (hostname === "localhost" || hostname === "127.0.0.1" || hostname === "::1")) {
      console.log(`🔧 Development mode: Allowing localhost connection to ${hostname}`);
    }

    // TODO: Implement on-chain staking verification
    // const nodeAddress = await this.resolveNodeAddress(endpoint);
    // const hasStaked = await this.verifyOnChainStaking(nodeAddress);
    // if (!hasStaked) {
    //   throw new Error(`Node ${nodeAddress} has not staked the required amount`);
    // }

    // TODO: Implement whitelist check against on-chain records
    // const isWhitelisted = await this.checkOnChainWhitelist(nodeAddress);
    // if (!isWhitelisted) {
    //   throw new Error(`Node ${nodeAddress} is not in the on-chain whitelist`);
    // }

    // Current implementation: Allow all nodes (temporary)
    if (!isDev) {
      console.log(
        `⚠️  Whitelist check passed (currently allowing all nodes - on-chain validation pending)`
      );
    }

    // Sanitize URL - remove authentication and query parameters
    url.username = "";
    url.password = "";
    url.search = "";
    url.hash = "";

    return url.toString();
  }

  /**
   * Validate multiple endpoints at once
   */
  public static validateEndpoints(endpoints: string[]): string[] {
    const validatedEndpoints: string[] = [];
    const errors: string[] = [];

    for (const endpoint of endpoints) {
      try {
        const validated = this.validateEndpoint(endpoint);
        validatedEndpoints.push(validated);
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        errors.push(`${endpoint}: ${errorMessage}`);
      }
    }

    if (errors.length > 0) {
      console.warn("⚠️ Some endpoints failed validation:", errors);
    }

    return validatedEndpoints;
  }

  /**
   * TODO: Resolve node address from endpoint
   * This will map a WebSocket endpoint to an Ethereum address
   *
   * @param endpoint The WebSocket endpoint
   * @returns The Ethereum address of the node
   */
  private static async resolveNodeAddress(endpoint: string): Promise<string> {
    // Implementation will query the node for its address
    // or maintain a registry mapping endpoints to addresses
    throw new Error("Not implemented: resolveNodeAddress");
  }

  /**
   * TODO: Verify on-chain staking status
   * This will check if a node has staked the required amount
   *
   * @param address The Ethereum address to check
   * @returns Whether the address has sufficient stake
   */
  private static async verifyOnChainStaking(address: string): Promise<boolean> {
    // Implementation will:
    // 1. Connect to the staking contract
    // 2. Check if the address has staked >= minStakeAmount
    // 3. Verify the stake is not slashed
    // 4. Check stake expiration time
    throw new Error("Not implemented: verifyOnChainStaking");
  }

  /**
   * TODO: Check on-chain whitelist
   * This will verify if a node is in the on-chain whitelist
   *
   * @param address The Ethereum address to check
   * @returns Whether the address is whitelisted
   */
  private static async checkOnChainWhitelist(address: string): Promise<boolean> {
    // Implementation will:
    // 1. Connect to the whitelist contract
    // 2. Check if the address is in the whitelist
    // 3. Verify whitelist expiration (if applicable)
    throw new Error("Not implemented: checkOnChainWhitelist");
  }
}
