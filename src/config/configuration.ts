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

    // Hybrid signing (feat/rust-signer): when set, BLS signing is delegated to a local
    // Rust signer over loopback HTTP (byte-identical output, faster on ARM). UNSET →
    // pure in-process Node signing (no probe, zero overhead). On any Rust error the node
    // falls back to Node signing unless RUST_SIGNER_REQUIRED=true (then it fails closed).
    rustSignerUrl: process.env.RUST_SIGNER_URL || undefined,
    rustSignerRequired: process.env.RUST_SIGNER_REQUIRED === "true",
    // KMS-TEE custody mode: when the Rust signer is AirAccount KMS (127.0.0.1:3100)
    // and KMS has KMS_BLS_SIGNER_TOKEN set, /sign requires this shared secret in the
    // X-Signer-Token header so only this DVT process (not any co-located process) can
    // invoke the TEE signer. Unset = no header sent (backward-compatible).
    rustSignerToken: process.env.RUST_SIGNER_TOKEN || undefined,

    // Operator alerting → aastar-monitor Telegram bot (#100). Opt-in; fire-and-forget
    // (never blocks signing/relaying). Distinct from NOTIFY_* (which alerts end users).
    // Two transports (Telegram takes priority): OPS_ALERT_BOT_TOKEN + OPS_ALERT_CHAT_ID
    // send straight to the bot's chat; OR AASTAR_MONITOR_URL (+ optional token) for a
    // generic webhook. OPS_ALERT_NODE labels which node raised the alert.
    opsAlertEnabled: process.env.OPS_ALERT_ENABLED === "true",
    opsAlertBotToken: process.env.OPS_ALERT_BOT_TOKEN || undefined,
    opsAlertChatId: process.env.OPS_ALERT_CHAT_ID || undefined,
    opsAlertUrl: process.env.AASTAR_MONITOR_URL || undefined,
    opsAlertToken: process.env.AASTAR_MONITOR_TOKEN || undefined,
    opsAlertNode: process.env.OPS_ALERT_NODE || undefined,
    // Scheduled status heartbeat (#100). 0 = off. Pushes a periodic "still alive +
    // health check" summary to the ops channel, plus online/offline on boot/shutdown.
    // `|| 0` guards a non-numeric value (parseInt → NaN) from leaking through as an
    // interval, which would make setInterval fire continuously (eval#299).
    opsStatusIntervalMs: parseInt(process.env.OPS_STATUS_INTERVAL_MS || "0", 10) || 0,

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

    // EIP-2335 keystore passphrase (#5, #50 ④). When node_state.json holds an encrypted
    // keystore, this decrypts it at boot. Supply it from OUTSIDE the machine's disk —
    // an env var injected at boot (systemd LoadCredential, an orchestrator, or typed).
    // Never store it next to the keystore. Unset + encrypted keystore → fail to boot.
    keyPassphrase: process.env.NODE_KEY_PASSPHRASE || undefined,

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
    // KMS-TEE keeper signer (CC-34) — takes precedence over KEEPER_PRIVATE_KEY. The secp256k1
    // key is sealed in the co-located KMS; DVT signs raw 32B digests via loopback :3100 and never
    // holds the key. KEEPER_ADDRESS is the funded keeper EOA (from KMS provisioning). Fail-closed:
    // KMS rejects signing without KEEPER_SIGNER_TOKEN. Unset KEEPER_SIGNER_URL → plaintext fallback.
    keeperSignerUrl: process.env.KEEPER_SIGNER_URL || undefined,
    keeperSignerToken: process.env.KEEPER_SIGNER_TOKEN || undefined,
    keeperAddress: process.env.KEEPER_ADDRESS || undefined,
    keeperId: process.env.KEEPER_ID || undefined,
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

    // DVT Phase 2 (目标2) — autonomous audit of SuperPaymaster operators.
    // Opt-in; default off → behavior unchanged. When enabled, a background poll audits each
    // watchlisted operator's gossip liveness (rule ② offline) and, on a confirmed violation, archives
    // a content-addressed slash proof and files a slash proposal on the DVTValidator. The credit-over-
    // limit (rule ①) and over-issue (rule ③) SLASH rules were retired by design review; the slash-
    // consensus pipeline is kept as dormant scaffolding for future rules.
    //
    // AUDIT_WATCHLIST: comma-separated operator addresses to monitor.
    // FAIL-CLOSED: when AUDIT_ENABLED=true, ALL of AUDIT_REGISTRY_ADDRESS /
    //   AUDIT_SUPER_PAYMASTER_ADDRESS / AUDIT_DVT_VALIDATOR_ADDRESS must be set explicitly
    //   (no silent default), and each must have on-chain code (getCode != "0x") at bootstrap
    //   or the audit self-disables. GTokenStaking is optional (auxiliary evidence only).
    // AUDIT_COOLDOWN_MS: min gap between proposals for the same operator+rule so an ongoing
    //   violation is not re-proposed every tick (default 1h).
    auditEnabled: process.env.AUDIT_ENABLED === "true",
    auditIntervalMs: parseInt(process.env.AUDIT_INTERVAL_MS || "60000", 10),
    auditCooldownMs: parseInt(process.env.AUDIT_COOLDOWN_MS || "3600000", 10),
    auditWatchlist: parseAllowlist(process.env.AUDIT_WATCHLIST || ""),
    auditProofDir: process.env.AUDIT_PROOF_DIR || "./audit-proofs",
    // CC-89 stage-2 guardian-slash WATCHER (opt-in, default off). Captures each SlashExecuted's
    // signer ADDRESS set (validatorAtSlot @ execution block) so a later over-issue fraud proof can
    // reproduce SP's irreversible A' commitment. Pure observer — never signs/files/slashes. Runs in
    // every node; the fleet's redundancy is what guarantees a slash's set is never wholly missed.
    // AUDIT_GUARDIAN_WATCH_FROM_BLOCK: the BLSAggregator (A' commitment) deploy block — scan lower
    //   bound (0 = genesis, slow). AUDIT_GUARDIAN_WATCH_DIR: per-node record store (contains no keys).
    //   Reuses AUDIT_BLS_AGGREGATOR_ADDRESS, AUDIT_FINALITY_CONFIRMATIONS, AUDIT_ROLE_LOG_CHUNK.
    auditGuardianWatchEnabled: process.env.AUDIT_GUARDIAN_WATCH_ENABLED === "true",
    auditGuardianWatchDir: process.env.AUDIT_GUARDIAN_WATCH_DIR || "./guardian-signer-records",
    auditGuardianWatchIntervalMs: parseInt(
      process.env.AUDIT_GUARDIAN_WATCH_INTERVAL_MS || "60000",
      10
    ),
    auditGuardianWatchFromBlock: (() => {
      const parsed = parseInt(process.env.AUDIT_GUARDIAN_WATCH_FROM_BLOCK || "0", 10);
      return Math.max(0, Number.isFinite(parsed) ? parsed : 0);
    })(),
    auditChainId: parseInt(process.env.AUDIT_CHAIN_ID || "11155111", 10),
    auditRegistryAddress: process.env.AUDIT_REGISTRY_ADDRESS || undefined,
    auditSuperPaymasterAddress: process.env.AUDIT_SUPER_PAYMASTER_ADDRESS || undefined,
    // DVTValidator (SP #329 finalized interface). Default is the Sepolia deployment.
    auditDvtValidatorAddress:
      process.env.AUDIT_DVT_VALIDATOR_ADDRESS || "0x568b1486BFE036e603eA11f0D03Dc47fa62c9E0e",
    // SP BLSAggregator (A' 4.11.0) — the aggregator the guardian-slash watcher (CC-89) reads
    // proposalSignersCommitment/validatorAtSlot from, and the offline-audit rule resolves
    // operator→BLS key through. Default is the Sepolia PRODUCTION deployment, i.e. whatever
    // `Registry.blsAggregator()` currently returns (read 2026-09-04: 0xEaeC2F51…, version
    // "BLSAggregator-4.11.0"; it is also the aggregator whose fraud-proof verifier was armed that
    // day — docs/evidence/cc115-b3-arming-sepolia.md).
    //
    // This default was 0x174b60bB… (4.3.0) until 2026-09-04. That contract still exists and still
    // answers `validatorAtSlot(1)` with the SAME guardian address as the live one, so a node left on
    // it does not fail — it watches a superseded contract and silently sees no SlashExecuted events.
    // A stale aggregator default is therefore a FAIL-SILENT bug, not a fail-closed one. Nothing
    // automated catches it today: `scripts/check-deps.mjs` does not cover this address, and
    // aggregator-bootstrap-guard.ts only rejects the default OFF-Sepolia — on Sepolia it lets a
    // stale default through by design. The source of truth is `Registry.blsAggregator()` on
    // 0xf5Bf37ca…; re-read it after every SP aggregator succession. Tracked as a gap, not a
    // guarantee.
    //
    // ALWAYS set AUDIT_BLS_AGGREGATOR_ADDRESS explicitly per network — never rely on the default
    // off-Sepolia (aggregator-bootstrap-guard.ts enforces that).
    auditBlsAggregatorAddress:
      process.env.AUDIT_BLS_AGGREGATOR_ADDRESS || "0xEaeC2F512eA50708211fa95533e4dBb60e3d2E5D",
    // Whether the aggregator address was set EXPLICITLY (not the resolved value — the resolved value
    // always carries the Sepolia default above, which would mask the unset case). Consumed by the
    // fail-closed off-Sepolia guard so the Sepolia default is never silently inherited on another
    // chain. See aggregator-bootstrap-guard.ts.
    auditBlsAggregatorAddressFromEnv: Boolean(process.env.AUDIT_BLS_AGGREGATOR_ADDRESS),
    auditGtokenStakingAddress: process.env.AUDIT_GTOKEN_STAKING_ADDRESS || undefined,
    // SECOND safety gate (increment 2). AUDIT_ENABLED alone only FILES slash proposals; the
    // two-step on-chain slash (queueSlashWithProof → executeWithProof, each quorum co-signed)
    // fires ONLY when this is ALSO "true". Default FALSE so nothing is auto-slashed until an
    // operator explicitly opts in AND the SP validator slots (registerBLSPublicKey) are ready.
    auditExecuteSlash: process.env.AUDIT_EXECUTE_SLASH === "true",
    // DRY-RUN drill (safe intermediate for the FIRST live slash of money-moving code). Only meaningful
    // when the node is ALSO armed (AUDIT_EXECUTE_SLASH=true). When true, the audit runs the FULL gossip
    // quorum co-sign AND the staticCall preflight against the REAL deployed contracts (proving the
    // signerMask/sigG2 are accepted by verifyAndExecute) but does NOT broadcast the real queue/execute
    // transaction — no operator is actually slashed, and NO durable over-slash marker is written (so the
    // drill is repeatable). It logs the would-slash target and records a sentinel tx (0xDRYRUN) in the
    // archived proof. Flip this OFF once the path is proven end-to-end to go live. Default false.
    auditDryRun: process.env.AUDIT_DRY_RUN === "true",
    // Reorg-safety (finding-3): the audit reads all rule inputs at a FINALIZED (fallback: safe)
    // block. On chains that expose neither tag, fall back to latest MINUS this many confirmations.
    // FLOORED at 1 (never 0): a 0 (or non-numeric) value would make the fallback resolve to the
    // UNCONFIRMED head (latest − 0), defeating the finality guard. A positive floor guarantees the
    // fallback is always at least one confirmation behind the head. Default 12.
    auditFinalityConfirmations: (() => {
      const parsed = parseInt(process.env.AUDIT_FINALITY_CONFIRMATIONS || "12", 10);
      return Math.max(1, Number.isFinite(parsed) ? parsed : 12);
    })(),
    // Durable over-slash guard (finding-2): how far back to scan slash-executed events when
    // deciding whether an operator was already slashed (a restart-surviving, on-chain-truth guard).
    // NOTE (PK finding): on a range-limited RPC, a getLogs span wider than the provider's cap makes
    // the scan error → indeterminate. When the pending flag is ALSO indeterminate (as on the current
    // SP deployment, which has no isSlashPending getter), the over-slash guard then fails CLOSED (the
    // slash is SKIPPED, logged as "indeterminate") — the safe direction, but it suppresses legitimate
    // slashes. Size this to your RPC's getLogs block-range limit (many public endpoints cap ~10k) so
    // the scan stays determinate. It is only consulted on the armed executeSlash path.
    auditSlashLookbackBlocks: parseInt(process.env.AUDIT_SLASH_LOOKBACK_BLOCKS || "50000", 10),
    // Live gossip quorum co-sign (inc-2). Only consulted on the armed executeSlash path.
    // AUDIT_COSIGN_TIMEOUT_MS: how long the requester waits for peer signatures before resolving
    //   with whatever partial set arrived (then it enforces the threshold; under → no submit).
    // AUDIT_SLASH_THRESHOLDS: optional per-severity quorum override "WARNING:2,MINOR:3,MAJOR:3"
    //   (the on-chain BLSAggregator bootstrap for N=3). Must match / not exceed the on-chain table.
    // AUDIT_MAX_SLOTS: how many 1-indexed BLSAggregator slots to scan (= on-chain MAX_VALIDATORS).
    // AUDIT_SLOT_MAP: optional boot-time cross-check only (never the runtime slot source — the
    //   on-chain BLSAggregator is authoritative); format "0xoperator:slot,..." for diagnostics.
    auditCoSignTimeoutMs: parseInt(process.env.AUDIT_COSIGN_TIMEOUT_MS || "15000", 10),
    auditSlashThresholds: parseSlashThresholds(process.env.AUDIT_SLASH_THRESHOLDS),
    auditMaxSlots: (() => {
      const parsed = parseInt(process.env.AUDIT_MAX_SLOTS || "13", 10);
      return Number.isFinite(parsed) && parsed > 0 ? parsed : 13;
    })(),
    auditSlotMap: process.env.AUDIT_SLOT_MAP || undefined,
    // A1#6 — derive the watchlist from the on-chain Registry role set instead of a hand-curated
    // AUDIT_WATCHLIST. When AUDIT_ROLE_DERIVE=true, the audit enumerates the CURRENT members of
    // AUDIT_ROLE_IDS (default "DVT,ANODE") from Registry.roleMembers (getRoleMembers getter-first,
    // role-event reconstruction fallback) each refresh, and UNIONs them with the static
    // AUDIT_WATCHLIST (which stays as an optional manual override / addition — never subtracts).
    // Default OFF → today's static-list behavior is unchanged.
    // AUDIT_ROLE_IDS: comma-separated role NAMES (hashed via keccak256) — e.g. "DVT,ANODE".
    // AUDIT_ROLE_FROM_BLOCK: the Registry deploy block (event-scan lower bound; 0 = genesis, slow).
    // AUDIT_ROLE_LOG_CHUNK: getLogs block-range per request for the event-scan fallback (RPC cap).
    // AUDIT_ROLE_REFRESH_MS: how often to re-derive the set (not every tick — getLogs is heavy).
    auditRoleDerive: process.env.AUDIT_ROLE_DERIVE === "true",
    auditRoleIds: parseRoleIds(process.env.AUDIT_ROLE_IDS || "DVT,ANODE"),
    auditRoleFromBlock: (() => {
      const parsed = parseInt(process.env.AUDIT_ROLE_FROM_BLOCK || "0", 10);
      return Math.max(0, Number.isFinite(parsed) ? parsed : 0);
    })(),
    auditRoleLogChunk: (() => {
      const parsed = parseInt(process.env.AUDIT_ROLE_LOG_CHUNK || "10000", 10);
      return Math.max(1, Number.isFinite(parsed) && parsed > 0 ? parsed : 10000);
    })(),
    auditRoleRefreshMs: (() => {
      const parsed = parseInt(process.env.AUDIT_ROLE_REFRESH_MS || "300000", 10);
      return Math.max(1, Number.isFinite(parsed) && parsed > 0 ? parsed : 300000);
    })(),
    // AUDIT_ROLE_USE_GETTER: trust a Registry.getRoleMembers(bytes32) getter (O(1)) instead of the
    // event scan. Default OFF — the deployed Registry has no such getter and a 4-byte selector
    // collision could return a valid-looking wrong set (Codex Medium-3). Turn on ONLY against a
    // Registry known to implement it. AUDIT_ROLE_MAX_STALE_MS: a DERIVED-only operator is NOT
    // slashed once the last successful derivation is older than this (stale membership must not drive
    // an irreversible slash of a possibly-exited operator; Codex High-2). Default 15min.
    auditRoleUseGetter: process.env.AUDIT_ROLE_USE_GETTER === "true",
    auditRoleMaxStaleMs: (() => {
      const parsed = parseInt(process.env.AUDIT_ROLE_MAX_STALE_MS || "900000", 10);
      return Math.max(1, Number.isFinite(parsed) && parsed > 0 ? parsed : 900000);
    })(),
    // Rule ② offline detection. Opt-in; audits liveness of the SAME operators the credit rule watches.
    // An operator is OFFLINE when this node last heard its gossip heartbeat more than the VERSION-BOUND
    // OFFLINE_THRESHOLD_MS constant (NOT env — it enters the proofHash, so it must be identical across
    // the fleet; see audit.service) before the finalized evidence block's on-chain timestamp (a
    // globally-consistent deadline, not local wall-clock). Slash level WARNING. Reuses
    // AUDIT_BLS_AGGREGATOR_ADDRESS to resolve operator → registered BLS key → nodeId.
    auditOfflineEnabled: (() => {
      if (process.env.AUDIT_OFFLINE_THRESHOLD_MS !== undefined) {
        console.warn(
          "⚠️  AUDIT_OFFLINE_THRESHOLD_MS is IGNORED — the offline threshold is now a version-bound " +
            "constant (it enters the proofHash and must be identical fleet-wide). Remove the env var."
        );
      }
      return process.env.AUDIT_OFFLINE_ENABLED === "true";
    })(),

    // inc-2 liveness attest keeper (SP LivenessRegistry, CC-29). Opt-in. Each DVT node self-proves
    // liveness on-chain so SP's auto-jail only excludes genuinely-silent operators. Reads NOTHING
    // for slash-threshold math (BLSAggregator owns the fixed on-chain threshold) — this only writes
    // attestLiveness(anchorBlock, anchorHash) from the operator EOA. Interval is wall-clock; set it
    // to ~livenessWindow/3 worth of time for the target chain (keeper logs the on-chain window at boot).
    auditAttestEnabled: process.env.AUDIT_ATTEST_ENABLED === "true",
    auditLivenessRegistryAddress: process.env.AUDIT_LIVENESS_REGISTRY_ADDRESS || "",
    auditAttestIntervalMs: parseInt(process.env.AUDIT_ATTEST_INTERVAL_MS || "600000", 10),
    // Anchor depth for attestLiveness: head−depth. Must sit ABOVE typical reorg depth (stable hash →
    // no BadAnchorHash) yet well BELOW SP's 256-block staleness bound. Default 16.
    auditAttestAnchorDepth: parseInt(process.env.AUDIT_ATTEST_ANCHOR_DEPTH || "16", 10),

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

/**
 * Parse AUDIT_ROLE_IDS ("DVT,ANODE") into a de-duplicated list of role NAME strings. The names
 * are hashed to their bytes32 roleId (keccak256) downstream in the audit service (which owns the
 * ethers dependency) — keeping this config module free of ethers. Empty entries are dropped.
 */
function parseRoleIds(raw: string): string[] {
  const seen = new Set<string>();
  for (const name of raw.split(",").map(r => r.trim())) {
    if (name.length > 0) seen.add(name);
  }
  return [...seen];
}

/**
 * Per-severity SAFE MINIMUM quorum (the pinned live policy, N=3 BLSAggregator bootstrap). A
 * configured override may only RAISE a threshold, never lower it below this floor — otherwise a
 * value like `MINOR:1` would let a single local signature pass as quorum and defeat the 3-of-3
 * invariant that gates a REAL, irreversible on-chain GToken slash. HIGH 1 (Codex): clamp UP.
 */
const SLASH_THRESHOLD_FLOOR = { WARNING: 2, MINOR: 3, MAJOR: 3 } as const;

/**
 * Parse the optional AUDIT_SLASH_THRESHOLDS override ("WARNING:2,MINOR:3,MAJOR:3") into the
 * per-severity quorum table. Defaults to the on-chain BLSAggregator bootstrap (N=3): 2/3/3.
 * Malformed / non-positive entries are ignored (the default for that level is kept). Any parsed
 * value BELOW the safe floor is CLAMPED UP to the floor (with a warning) so a misconfiguration can
 * never weaken the quorum below the pinned live policy; HIGHER values are preserved as configured.
 */
function parseSlashThresholds(raw?: string): { WARNING: number; MINOR: number; MAJOR: number } {
  const out = { ...SLASH_THRESHOLD_FLOOR } as { WARNING: number; MINOR: number; MAJOR: number };
  if (!raw) return out;
  for (const pair of raw.split(",")) {
    const [k, v] = pair.split(":").map(s => s.trim());
    // STRICT numeric parse (Codex R2 LOW): reject "4oops"/"" — parseInt would silently take 4.
    // A malformed value is IGNORED so the safe floor is kept (never a weaker/garbage quorum).
    const n = /^[0-9]+$/.test(v ?? "") ? Number(v) : NaN;
    if ((k === "WARNING" || k === "MINOR" || k === "MAJOR") && Number.isSafeInteger(n) && n > 0) {
      const floor = SLASH_THRESHOLD_FLOOR[k];
      if (n < floor) {
        console.warn(
          `⚠️  AUDIT_SLASH_THRESHOLDS ${k}:${n} is below the safe minimum (${floor}) — ` +
            `clamping UP to ${floor} (the 3-of-3 slash quorum invariant cannot be weakened)`
        );
        out[k] = floor;
      } else {
        out[k] = n;
      }
    }
  }
  return out;
}
