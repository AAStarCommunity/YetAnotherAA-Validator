export default () => {
  // Validate required environment variables
  const requiredVars = ["ETH_RPC_URL", "VALIDATOR_CONTRACT_ADDRESS"];

  const missingVars = requiredVars.filter(varName => !process.env[varName]);

  if (missingVars.length > 0) {
    throw new Error(
      `Environment configuration validation failed:\n${missingVars.map(v => `  - ${v} is required`).join("\n")}`
    );
  }

  const port = parseInt(process.env.PORT || "3000", 10);

  console.log("✅ Environment configuration validated successfully");
  console.log(`   - Validator Contract: ${process.env.VALIDATOR_CONTRACT_ADDRESS}`);
  console.log(`   - ETH RPC URL: ${process.env.ETH_RPC_URL}`);
  console.log(`   - Port: ${port}`);
  console.log(`   - Node State File: node_state.json (fixed)`);

  return {
    // Server
    port,
    host: "0.0.0.0",
    publicUrl: process.env.PUBLIC_URL || `http://localhost:${port}`,

    // Blockchain
    ethRpcUrl: process.env.ETH_RPC_URL,
    ethPrivateKey: process.env.ETH_PRIVATE_KEY,
    validatorContractAddress: process.env.VALIDATOR_CONTRACT_ADDRESS,
    // Canonical ERC-4337 v0.7 EntryPoint (same address across chains). Used to
    // derive the authoritative userOpHash for the Fix 2 Stage 1 owner-auth gate.
    entryPointAddress:
      process.env.ENTRY_POINT_ADDRESS || "0x0000000071727De22E5E9d8BAf0edAc6f37da032",

    // DVT independent policy gate (Fix 2 Stage 2, issue #40).
    // Disabled by default so existing deployments keep Stage 1 behavior unchanged.
    // When enabled, the node refuses to co-sign ops outside its OWN policy — the
    // owner and CA cannot change these rules, which is what makes the second factor
    // independent. perTxMaxWei unset = no per-tx cap; allowlist empty = any recipient.
    policyEnabled: process.env.POLICY_ENABLED === "true",
    policyPerTxMaxWei: process.env.POLICY_PER_TX_MAX_WEI || undefined,
    policyRecipientAllowlist: parseAllowlist(process.env.POLICY_RECIPIENT_ALLOWLIST || ""),
    // Layer-1 (on-chain IPolicyRegistry, Fix 2 Stage 2). Empty = layer-1 off.
    // ethSentinel: asset key for native ETH in checkPolicy — default 0xEee… per
    // airaccount-contract #110 (Q4, pending SP final confirm).
    policyRegistryAddress: process.env.POLICY_REGISTRY_ADDRESS || undefined,
    policyEthSentinel:
      process.env.POLICY_ETH_SENTINEL || "0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE",

    // Multi-channel user notification (#52). Opt-in; fire-and-forget (never blocks
    // signing). Contacts file is git-ignored. threshold 0 = notify every co-sign.
    notifyEnabled: process.env.NOTIFY_ENABLED === "true",
    notifyThresholdWei: process.env.NOTIFY_THRESHOLD_WEI || "0",
    telegramBotToken: process.env.TELEGRAM_BOT_TOKEN || undefined,
    notifyContactsFile: process.env.NOTIFY_CONTACTS_FILE || undefined,

    // Out-of-band confirmation (scheme A, #50 ⑤). Opt-in; a high-value op is withheld
    // until the user approves over an independent channel. Fail-closed if undeliverable.
    confirmEnabled: process.env.CONFIRM_ENABLED === "true",
    confirmThresholdWei: process.env.CONFIRM_THRESHOLD_WEI || "0",
    confirmTtlMs: parseInt(process.env.CONFIRM_TTL_MS || "600000", 10),
    // KMS endpoint for passkey out-of-band confirmation (path-2, #124/#193): the node
    // delegates WebAuthn RP verification to KMS (POST /verify-confirm-assertion) and
    // resolves verified contacts (GET /contact/{account}). Use a DEDICATED per-node,
    // revocable API key (it reads PII). Unset → passkey confirm fail-closed.
    kmsBaseUrl: process.env.KMS_BASE_URL || undefined,
    kmsApiKey: process.env.KMS_API_KEY || undefined,

    // Per-IP rate limiting on signature endpoints (#50 hardening ⑦). Opt-in;
    // bounds pre-auth on-chain RPC amplification. Default off = behavior unchanged.
    rateLimitEnabled: process.env.RATE_LIMIT_ENABLED === "true",
    rateLimitWindowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || "60000", 10),
    rateLimitMax: parseInt(process.env.RATE_LIMIT_MAX || "30", 10),

    // BLS key-custody backend (#50; arch #67). "local" (default) = in-process key from
    // node_state.json. Future: "kms"/"hsm" via a BLS-capable HSM. Signing output is
    // backend-independent (algorithm/wire is the fixed kernel — see conformance/).
    signerBackend: process.env.SIGNER_BACKEND || "local",

    // Price Keeper (#58). Opt-in; keeps paymaster cachedPrice permanently fresh via
    // on-chain updatePrice() calls when approaching the staleness threshold. Requires
    // ETH_PRIVATE_KEY (or a dedicated KEEPER_PRIVATE_KEY in a future phase). Default off.
    // KEEPER_CHAINLINK_FEED defaults to the canonical Sepolia ETH/USD feed.
    // KEEPER_PAYMASTER_ADDRESS is comma-separated — keep multiple paymasters fresh with
    // one keeper (e.g. SuperPaymaster + a community PaymasterV4). The reader binds to
    // `cachedPrice()` (returns price, updatedAt) which both SuperPaymaster v3 and
    // PaymasterV4 expose; each paymaster's own priceStalenessThreshold is honored.
    keeperEnabled: process.env.KEEPER_ENABLED === "true",
    keeperIntervalMs: parseInt(process.env.KEEPER_INTERVAL_MS || "60000", 10),
    keeperRefreshBufferS: process.env.KEEPER_REFRESH_BUFFER_S || "300",
    keeperMaxUpdatesPerDay: parseInt(process.env.KEEPER_MAX_UPDATES_PER_DAY || "48", 10),
    keeperMaxBaseFeeGwei: process.env.KEEPER_MAX_BASE_FEE_GWEI || "50",
    keeperPaymasterAddress: process.env.KEEPER_PAYMASTER_ADDRESS || "",
    // Dedicated keeper signer — keep it SEPARATE from RELAY_OPERATOR_PK so the
    // keeper's updatePrice() nonce queue can't contend with relay submissions on
    // one EOA. Falls back to ETH_PRIVATE_KEY only when unset.
    keeperPrivateKey: process.env.KEEPER_PRIVATE_KEY || undefined,
    keeperChainlinkFeed:
      process.env.KEEPER_CHAINLINK_FEED || "0x694AA1769357215DE4FAC081bf1f309aDC325306",

    // Gasless purchase relay (#98). Opt-in; ports the launch-sale relayer (v3:
    // EIP-3009 + BuyIntent → BuyHelper) into the node so the token sale no longer
    // depends on a single centralized Cloudflare Worker. Default off. Requires a
    // DEDICATED RELAY_OPERATOR_PK (funded hot wallet that pays gas) — it does NOT
    // fall back to ETH_PRIVATE_KEY, keeping the public-facing gas key isolated
    // from the validator-owner key. Addresses default to the Sepolia Path-A stack.
    relayEnabled: process.env.RELAY_ENABLED === "true",
    relayOperatorPk: process.env.RELAY_OPERATOR_PK || undefined,
    relayRpcUrl: process.env.RELAY_RPC_URL || undefined,
    relayChainId: parseInt(process.env.RELAY_CHAIN_ID || "11155111", 10),
    relayBuyHelper: process.env.RELAY_BUY_HELPER || undefined,
    relayUsdc: process.env.RELAY_USDC || undefined,
    relayGtoken: process.env.RELAY_GTOKEN || undefined,
    relayApnts: process.env.RELAY_APNTS || undefined,
    relayMaxPaymentAmount: process.env.RELAY_MAX_PAYMENT_USDC || undefined,
    relayRateLimitPerAddressPerHour: parseInt(
      process.env.RELAY_RATE_LIMIT_PER_ADDRESS_PER_HOUR || "5",
      10
    ),
    relayRateLimitGlobalPerHour: parseInt(
      process.env.RELAY_RATE_LIMIT_GLOBAL_PER_HOUR || "100",
      10
    ),

    // x402 payment facilitator (#130). Opt-in; operates the x402 facilitator service
    // (verify off-chain → settle on the standalone X402Facilitator contract) as a DVT
    // node module, mirroring relay. Default off → behavior unchanged. Requires a
    // DEDICATED X402_OPERATOR_PK (funded EOA holding ROLE_PAYMASTER_SUPER + listed in
    // each supported xPNTs token's approvedFacilitators) — it does NOT fall back to
    // ETH_PRIVATE_KEY or RELAY_OPERATOR_PK, keeping the public settlement key isolated.
    // X402_SUPPORTED_ASSETS are the xPNTs the operator is approved for (settled `direct`);
    // anything else settles via EIP-3009. Addresses default to the Sepolia v5.4.1 stack.
    x402FacilitatorEnabled: process.env.X402_FACILITATOR_ENABLED === "true",
    x402FacilitatorContract: process.env.X402_FACILITATOR_CONTRACT || undefined,
    x402SupportedAssets: parseAllowlist(process.env.X402_SUPPORTED_ASSETS || ""),
    x402OperatorPk: process.env.X402_OPERATOR_PK || undefined,
    x402FeeBPS: parseInt(process.env.X402_FEE_BPS || "200", 10),
    x402ChainId: parseInt(process.env.X402_CHAIN_ID || "11155111", 10),
    x402RpcUrl: process.env.X402_RPC_URL || undefined,
    // Optional stateless HMAC request-auth on /x402/settle (public nodes), shaped to
    // map onto the SDK's FacilitatorConfig.createAuthHeaders(): the client sends
    // X-X402-Timestamp + X-X402-Auth = HMAC-SHA256(secret, `${ts}.${rawBody}`); the
    // node accepts within X402_AUTH_TTL_MS. Default off → settle unchanged.
    x402AuthEnabled: process.env.X402_AUTH_ENABLED === "true",
    x402AuthSecret: process.env.X402_AUTH_SECRET || undefined,
    x402AuthTtlMs: parseInt(process.env.X402_AUTH_TTL_MS || "300000", 10),

    // Gossip Network
    gossipPublicUrl: process.env.GOSSIP_PUBLIC_URL || `ws://localhost:${port}/ws`,
    gossipBootstrapPeers: parseBootstrapPeers(process.env.GOSSIP_BOOTSTRAP_PEERS || ""),
    gossipInterval: parseInt(process.env.GOSSIP_INTERVAL || "5000", 10),
    gossipFanout: parseInt(process.env.GOSSIP_FANOUT || "3", 10),
    gossipMaxTtl: parseInt(process.env.GOSSIP_MAX_TTL || "5", 10),
    gossipHeartbeatInterval: parseInt(process.env.GOSSIP_HEARTBEAT_INTERVAL || "10000", 10),
    gossipSuspicionTimeout: parseInt(process.env.GOSSIP_SUSPICION_TIMEOUT || "30000", 10),
    gossipCleanupTimeout: parseInt(process.env.GOSSIP_CLEANUP_TIMEOUT || "60000", 10),
    gossipMaxMessageHistory: parseInt(process.env.GOSSIP_MAX_MESSAGE_HISTORY || "1000", 10),
  };
};

function parseBootstrapPeers(peersString: string): string[] {
  if (!peersString) return [];
  return peersString
    .split(",")
    .map(p => p.trim())
    .filter(p => p.length > 0);
}

function parseAllowlist(allowlistString: string): string[] {
  if (!allowlistString) return [];
  return allowlistString
    .split(",")
    .map(a => a.trim())
    .filter(a => a.length > 0);
}
