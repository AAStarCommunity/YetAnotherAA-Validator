import { Injectable, Logger } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { ethers } from "ethers";
import { bumpedFees } from "../../utils/gas.util.js";

/**
 * CROSS-REPO INTERFACE CONTRACT — the account owner-auth gate.
 *
 * The DVT owner-gate (bls.service.ts) delegates all owner-auth validation to the ACCOUNT
 * contract via this view (see docs/INTERFACES.md). It is NOT standard ERC-1271: the account
 * is airaccount-contract's AAStarAirAccountV7, which owns the validation logic (k1 ECDSA /
 * P256 passkey / future), so DVT never verifies locally and never drifts.
 *
 * `OWNER_AUTH_MAGIC` is the function selector of `OWNER_AUTH_FN` used as the success magic
 * value (exactly how ERC-1271's 0x1626ba7e is selector(isValidSignature(bytes32,bytes))).
 * The invariant `selector(OWNER_AUTH_FN) === OWNER_AUTH_MAGIC` is LOCKED by a unit test
 * (blockchain.service.spec.ts) — if airaccount ever changes this interface, updating one
 * without the other fails CI, forcing a deliberate cross-repo sync. This is the DVT half of
 * the auto-check; the airaccount half is that airaccount MUST flag a change to this signature
 * (tracked in docs/INTERFACES.md as a hard dependency).
 */
export const OWNER_AUTH_FN = "isValidOwnerAuth(bytes32,bytes)";
export const OWNER_AUTH_MAGIC = "0xa0cf00cf";
/** Human-readable ABI for the ethers.Contract call — must stay in sync with OWNER_AUTH_FN. */
export const OWNER_AUTH_ABI = [
  "function isValidOwnerAuth(bytes32 userOpHash, bytes calldata ownerAuth) view returns (bytes4)",
];

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

  // ── DVT Phase 2 audit (目标2, increment 1) ─────────────────────────────────
  //
  // Read-only SuperPaymaster-stack views used by AuditService to evaluate the
  // credit-over-limit rule, plus the one write (createProposal) that files a
  // slash proposal. All reads use the shared read-only provider (no wallet
  // required); the write uses the admin wallet (ETH_PRIVATE_KEY).

  /**
   * Current chain head block number. AuditService reads it ONCE per operator and pins
   * every subsequent view read to it (blockTag) so all rule inputs come from one block —
   * no cross-block / phantom mixing of creditLimit, availableCredit and debt.
   */
  async getBlockNumber(): Promise<number> {
    if (!this.provider) {
      throw new Error("Blockchain provider not configured");
    }
    return this.provider.getBlockNumber();
  }

  /**
   * The block an irreversible slash is justified against — a FINALIZED (fallback: safe) block,
   * returned as `{ number, hash }` (finding-3). Pinning the slash evidence to a finalized block,
   * and recording its HASH, makes the justification reorg-safe: a reorg that rewrites the chain
   * head cannot silently invalidate the block the audit read its rule inputs at.
   *
   * Order of preference: `provider.getBlock("finalized")`, then `"safe"` (post-Merge PoS tags),
   * then — for RPCs/chains that expose neither — latest MINUS `confirmations` blocks. Throws only
   * if even that fallback cannot resolve a block (misconfigured provider). All rule reads are then
   * block-pinned to the returned `number` (via blockTag), so nothing is read at an unstable head.
   */
  async getViolationBlock(confirmations = 12): Promise<{ number: number; hash: string }> {
    if (!this.provider) {
      throw new Error("Blockchain provider not configured");
    }
    for (const tag of ["finalized", "safe"] as const) {
      try {
        const b = await this.provider.getBlock(tag);
        if (b && typeof b.number === "number" && b.hash) {
          return { number: b.number, hash: b.hash };
        }
      } catch {
        // This RPC/chain does not support the tag — fall through to the next.
      }
    }
    // Fallback: latest minus a confirmation depth (chains without finalized/safe tags). The
    // confirmation depth is floored at 1 so the fallback NEVER resolves to the unconfirmed head
    // (latest − 0): a finality-safe fallback must always sit at least one confirmation back.
    const latest = await this.provider.getBlockNumber();
    const target = Math.max(0, latest - Math.max(1, confirmations));
    const b = await this.provider.getBlock(target);
    if (!b || typeof b.number !== "number" || !b.hash) {
      throw new Error(
        `getViolationBlock: could not resolve a finalized/safe block (latest ${latest}, target ${target})`
      );
    }
    return { number: b.number, hash: b.hash };
  }

  /**
   * DURABLE (restart-surviving) over-slash guard (finding-2): did `operator` already get slashed
   * recently on `contractAddress`? Queries the on-chain slash-executed events within a bounded
   * `[fromBlock, latest]` window and returns true on the first match. Both event shapes are tried
   * (either can carry the executed slash), each topic-filtered by the indexed `operator`:
   *
   *   SuperPaymaster.SlashExecutedWithProof(address indexed operator, uint8 level, ...)
   *   BLSAggregator.SlashExecuted(uint256 indexed proposalId, address indexed operator, uint8 level)
   *
   * Unlike the private `_pendingSlash` (no getter → isSlashPending returns null), an emitted event
   * is a permanent on-chain fact, so this survives a node restart and is the authoritative guard
   * against re-slashing a sustained violation.
   *
   * Returns `boolean | null`:
   *   - `true`  — a matching slash event (operator + slashLevel) exists in the window.
   *   - `false` — the window was scanned cleanly and NO matching event exists.
   *   - `null`  — a provider/getLogs error made the scan INDETERMINATE. For a DUPLICATE-slash guard
   *               on an IRREVERSIBLE action a provider error must NEVER be read as "not slashed"; the
   *               caller treats `null` as "cannot determine" and fails CLOSED (do-not-slash).
   *
   * Match is narrowed to operator + slashLevel (NOT operator alone). `level` is a NON-indexed field
   * in both events, so it is decoded from the log data and compared. This is INTENTIONALLY
   * CONSERVATIVE: the audit rule is not itself on-chain, so a same-operator+level slash within the
   * lookback window OVER-skips (never risks a double slash) rather than under-skips. A slash for a
   * DIFFERENT level does not mark this rule as already-slashed.
   */
  async getRecentSlashExecuted(
    contractAddress: string,
    operator: string,
    slashLevel: number,
    fromBlock: number
  ): Promise<boolean | null> {
    if (!this.provider) {
      throw new Error("Blockchain provider not configured");
    }
    const iface = new ethers.Interface([
      "event SlashExecutedWithProof(address indexed operator, uint8 level, uint256 penalty, bytes32 proofHash, uint256 timestamp)",
      "event SlashExecuted(uint256 indexed proposalId, address indexed operator, uint8 level)",
    ]);
    const opTopic = ethers.zeroPadValue(ethers.getAddress(operator), 32);
    const filters = [
      // SlashExecutedWithProof: operator is the 1st indexed field (topics[1]).
      {
        name: "SlashExecutedWithProof",
        topics: [iface.getEvent("SlashExecutedWithProof")!.topicHash, opTopic],
      },
      // SlashExecuted: proposalId is 1st indexed (topics[1]), operator 2nd (topics[2]).
      {
        name: "SlashExecuted",
        topics: [iface.getEvent("SlashExecuted")!.topicHash, null, opTopic],
      },
    ];
    for (const f of filters) {
      let logs;
      try {
        logs = await this.provider.getLogs({
          address: contractAddress,
          fromBlock: Math.max(0, fromBlock),
          toBlock: "latest",
          topics: f.topics as (string | null)[],
        });
      } catch (error: any) {
        // FAIL-CLOSED: a getLogs/provider error means the window could NOT be scanned. Return null
        // ("indeterminate") rather than swallowing to a false "no match" — the caller must not read
        // an unreadable chain as "safe to slash" for an irreversible action.
        this.logger.warn(
          `getRecentSlashExecuted getLogs failed on ${contractAddress} (${f.name}): ${error.message} — indeterminate`
        );
        return null;
      }
      for (const log of logs) {
        try {
          // level is NON-indexed in both events → decode it from the log data and compare.
          const parsed = iface.parseLog({ topics: log.topics as string[], data: log.data });
          if (parsed && Number(parsed.args.level) === slashLevel) return true;
        } catch {
          // A log the topic filter matched but we could not decode — ignore (not our event shape).
        }
      }
    }
    return false;
  }

  // ── BLSAggregator slot registry (inc-2 live gossip co-sign) ────────────────────
  //
  // The authoritative slot→validator→BLS-key mapping the quorum co-sign binds against. Slot is
  // 1-indexed in [1, MAX_VALIDATORS]; signerMask bit `s-1` ⇔ slot `s` (see BLSAggregator.sol
  // `_reconstructPkAgg`). All reads are best-effort → `null` on revert/absence (fail-closed at
  // the caller: an unresolvable slot/key means "cannot bind" → refuse to count that signature).

  /**
   * BLSAggregator.validatorAtSlot(slot) — the validator address bound to a 1-indexed slot.
   * Returns the checksummed address, or `null` when the slot is empty (zero address) or the read
   * reverts.
   */
  async getValidatorAtSlot(blsAggregatorAddress: string, slot: number): Promise<string | null> {
    if (!this.provider) {
      throw new Error("Blockchain provider not configured");
    }
    const abi = ["function validatorAtSlot(uint8 slot) view returns (address)"];
    const contract = new ethers.Contract(blsAggregatorAddress, abi, this.provider);
    try {
      const addr: string = await contract.validatorAtSlot(slot);
      if (!addr || addr === ethers.ZeroAddress) return null;
      return ethers.getAddress(addr);
    } catch (error: any) {
      this.logger.warn(
        `validatorAtSlot(${slot}) failed on ${blsAggregatorAddress}: ${error.message}`
      );
      return null;
    }
  }

  /**
   * The active BLS G1 public key registered at a slot, as its uncompressed EIP-2537 128-byte
   * encoding (0x-hex, lowercase) — the concatenation of the on-chain BLS.G1Point words
   * `x_a || x_b || y_a || y_b`, byte-identical to `BlsService.encodePublicKeyToEIP2537`. Resolves
   * the slot's validator (validatorAtSlot) then reads BLSAggregator.getBLSPublicKey(validator).
   * Returns `null` when the slot is empty, the key is inactive (revoked), or the read reverts.
   * The requester uses this to bind a peer's returned slot to the exact on-chain key.
   */
  async getBlsPublicKeyAtSlot(blsAggregatorAddress: string, slot: number): Promise<string | null> {
    if (!this.provider) {
      throw new Error("Blockchain provider not configured");
    }
    const validator = await this.getValidatorAtSlot(blsAggregatorAddress, slot);
    if (!validator) return null;
    const abi = [
      "function getBLSPublicKey(address validator) view returns (tuple(bytes32 x_a, bytes32 x_b, bytes32 y_a, bytes32 y_b) publicKey, uint8 slot, bool isActive)",
    ];
    const contract = new ethers.Contract(blsAggregatorAddress, abi, this.provider);
    try {
      const res = await contract.getBLSPublicKey(validator);
      const pk = res.publicKey ?? res[0];
      const isActive = res.isActive ?? res[2];
      if (!isActive) return null;
      const words = [
        pk.x_a ?? pk[0],
        pk.x_b ?? pk[1],
        pk.y_a ?? pk[2],
        pk.y_b ?? pk[3],
      ] as string[];
      if (words.some(w => typeof w !== "string")) return null;
      const hex = "0x" + words.map(w => w.slice(2)).join("");
      return hex.toLowerCase();
    } catch (error: any) {
      this.logger.warn(
        `getBLSPublicKey(${validator}) failed on ${blsAggregatorAddress}: ${error.message}`
      );
      return null;
    }
  }

  /**
   * Scan slots `1..maxSlots` for the one bound to `operatorEoa` (checksum-compared), returning its
   * 1-indexed slot or `null` when the operator holds no slot. A node whose operator is at no slot
   * MUST refuse to participate in the quorum co-sign (fail-closed).
   */
  async getSlotForValidator(
    blsAggregatorAddress: string,
    operatorEoa: string,
    maxSlots: number
  ): Promise<number | null> {
    let target: string;
    try {
      target = ethers.getAddress(operatorEoa);
    } catch {
      return null;
    }
    for (let slot = 1; slot <= maxSlots; slot++) {
      const v = await this.getValidatorAtSlot(blsAggregatorAddress, slot);
      if (v && v === target) return slot;
    }
    return null;
  }

  /** Runtime bytecode at `address` ("0x" when there's no contract). Used for a fail-closed
   *  bootstrap existence check before the audit poll trusts an address. */
  async getCode(address: string, blockTag?: number): Promise<string> {
    if (!this.provider) {
      throw new Error("Blockchain provider not configured");
    }
    return this.provider.getCode(address, blockTag);
  }

  /** Registry.getCreditLimit(operator) — the operator's on-chain credit ceiling (wei-scaled). */
  async getCreditLimit(
    registryAddress: string,
    operator: string,
    blockTag?: number
  ): Promise<bigint> {
    if (!this.provider) {
      throw new Error("Blockchain provider not configured");
    }
    const abi = ["function getCreditLimit(address account) view returns (uint256)"];
    const contract = new ethers.Contract(registryAddress, abi, this.provider);
    return BigInt(await contract.getCreditLimit(operator, { blockTag }));
  }

  /**
   * Best-effort operator debt read: `getDebt(address user) view returns (uint256)` on the xPNTs
   * TOKEN contract (`tokenAddress`) — NOT SuperPaymaster/Registry. Per the verified SP ABI, debt
   * lives on the xPNTs token itself (IxPNTsToken.getDebt), and SuperPaymaster.getAvailableCredit
   * internally reads `creditLimit - IxPNTsToken(token).getDebt(user)`. Returns the debt as a bigint,
   * or `null` when the read reverts / the getter is absent — the caller MUST treat `null` as "debt
   * unknown" and SKIP (fail-safe: never guess an over-limit from missing data).
   */
  async getDebt(tokenAddress: string, operator: string, blockTag?: number): Promise<bigint | null> {
    if (!this.provider) {
      throw new Error("Blockchain provider not configured");
    }
    const abi = ["function getDebt(address user) view returns (uint256)"];
    const contract = new ethers.Contract(tokenAddress, abi, this.provider);
    try {
      const debt = await contract.getDebt(operator, { blockTag });
      return BigInt(debt);
    } catch (error: any) {
      this.logger.warn(
        `getDebt read failed on token ${tokenAddress} for ${operator}: ${error.message}`
      );
      return null;
    }
  }

  /** Registry.globalReputation(operator) — the operator's global reputation score. */
  async getGlobalReputation(
    registryAddress: string,
    operator: string,
    blockTag?: number
  ): Promise<bigint> {
    if (!this.provider) {
      throw new Error("Blockchain provider not configured");
    }
    const abi = ["function globalReputation(address account) view returns (uint256)"];
    const contract = new ethers.Contract(registryAddress, abi, this.provider);
    return BigInt(await contract.globalReputation(operator, { blockTag }));
  }

  /**
   * SuperPaymaster.getAvailableCredit(user, token) — remaining credit for `operator` against a
   * specific xPNTs `token`. Per the verified SP ABI this takes TWO args (user, token) and returns
   * `creditLimit - IxPNTsToken(token).getDebt(user)` clamped ≥0.
   */
  async getAvailableCredit(
    superPaymasterAddress: string,
    operator: string,
    token: string,
    blockTag?: number
  ): Promise<bigint> {
    if (!this.provider) {
      throw new Error("Blockchain provider not configured");
    }
    const abi = ["function getAvailableCredit(address user, address token) view returns (uint256)"];
    const contract = new ethers.Contract(superPaymasterAddress, abi, this.provider);
    return BigInt(await contract.getAvailableCredit(operator, token, { blockTag }));
  }

  /**
   * GTokenStaking.roleLocks(operator, role) — the operator's staked amount locked
   * behind a role (role = keccak256("DVT") for ROLE_DVT). The mapping returns a
   * struct whose exact shape varies across GTokenStaking versions; we only need the
   * leading `amount` word, so a single-field ABI reads it for either layout. Auxiliary
   * (informational) evidence — best-effort: reverts/decode errors resolve to 0.
   */
  async getRoleLockAmount(
    gtokenStakingAddress: string,
    operator: string,
    role: string,
    blockTag?: number
  ): Promise<bigint> {
    if (!this.provider) {
      throw new Error("Blockchain provider not configured");
    }
    const abi = ["function roleLocks(address account, bytes32 role) view returns (uint256 amount)"];
    const contract = new ethers.Contract(gtokenStakingAddress, abi, this.provider);
    try {
      const amount = await contract.roleLocks(operator, role, { blockTag });
      return BigInt(amount);
    } catch (error: any) {
      this.logger.warn(
        `roleLocks read failed on ${gtokenStakingAddress} for ${operator}: ${error.message}`
      );
      return 0n;
    }
  }

  /**
   * File a slash proposal on the DVTValidator:
   *   createProposal(address operator, uint8 level, string reason) returns (uint256 id)
   * Uses the admin wallet (ETH_PRIVATE_KEY). This is the proposal-INTENT only — the
   * multi-node BLS quorum co-sign + BLSAggregator.verifyAndExecute is deferred to
   * increment 2 (see AuditService.coordinateQuorumCoSign).
   *
   * The contract assigns an auto-incrementing `uint256 id` and emits `ProposalCreated`.
   * A transaction's Solidity return value is NOT recoverable off-chain, so the REAL id is
   * parsed from the emitted event in the receipt (best-effort). Returns both the tx hash and
   * the on-chain proposal id (`proposalId` is `null` when the event can't be found — e.g. an
   * older contract with a different event shape — so the caller never fabricates an id).
   */
  async createSlashProposal(
    dvtValidatorAddress: string,
    operator: string,
    level: number,
    reason: string
  ): Promise<{ txHash: string; proposalId: bigint | null }> {
    if (!this.wallet) {
      throw new Error("Blockchain not configured. Set ETH_PRIVATE_KEY environment variable.");
    }
    // Minimal fragment set: the write function plus the event we parse the real id from.
    const abi = [
      "function createProposal(address operator, uint8 level, string reason) returns (uint256)",
      "event ProposalCreated(uint256 indexed id, address indexed operator, uint8 level)",
    ];
    const iface = new ethers.Interface(abi);
    const contract = new ethers.Contract(dvtValidatorAddress, abi, this.wallet);
    const fees = await bumpedFees(this.provider);
    const tx: ethers.TransactionResponse = await contract.createProposal(
      operator,
      level,
      reason,
      fees
    );
    this.logger.log(`createProposal(${operator}, ${level}) submitted: ${tx.hash}`);
    // Await the receipt: a dropped/reverted proposal must NOT be recorded as success.
    // Throw on failure so the caller archives the evidence but records proposalTx=null.
    const receipt = await tx.wait();
    if (!receipt || receipt.status !== 1) {
      throw new Error(
        `createProposal tx ${tx.hash} failed (status ${receipt?.status ?? "unknown"})`
      );
    }
    // Parse the REAL on-chain proposal id from the emitted ProposalCreated event. Best-effort:
    // decode by topic, ignore unrelated logs, and fall back to null (never fabricate an id).
    let proposalId: bigint | null = null;
    for (const log of receipt.logs) {
      try {
        const parsed = iface.parseLog({ topics: [...log.topics], data: log.data });
        if (parsed && parsed.name === "ProposalCreated") {
          proposalId = BigInt(parsed.args.id ?? parsed.args[0]);
          break;
        }
      } catch {
        // Not a ProposalCreated log (or from another contract) — skip.
      }
    }
    if (proposalId === null) {
      this.logger.warn(
        `createProposal ${tx.hash} confirmed but no ProposalCreated event found — id unresolved`
      );
    }
    this.logger.log(
      `createProposal(${operator}, ${level}) confirmed in block ${receipt.blockNumber}` +
        (proposalId !== null ? ` (proposalId ${proposalId})` : "")
    );
    return { txHash: tx.hash, proposalId };
  }

  /**
   * Best-effort read of an operator's on-chain pending-slash flag. This is the DURABLE
   * cross-restart guard against double-slashing a sustained violation (finding-4/5): if a slash
   * is already queued/pending, the audit must NOT queue+execute another.
   *
   * SP #329 keeps `_pendingSlash` PRIVATE with no public getter, so on the current deployment this
   * call reverts and returns `null` ("unknown") — the caller then falls back to the in-memory
   * coarse operator|rule guard. Should a future SuperPaymaster expose `pendingSlash(address)`
   * (or `isSlashPending`), this begins returning the real flag and becomes the authoritative,
   * restart-surviving guard with no caller change. `null` is treated as "unknown", never "false".
   */
  async isSlashPending(
    superPaymasterAddress: string,
    operator: string,
    blockTag?: number
  ): Promise<boolean | null> {
    if (!this.provider) {
      throw new Error("Blockchain provider not configured");
    }
    // Try both plausible public getter names; either returning a bool answers the question.
    const abi = [
      "function pendingSlash(address operator) view returns (bool)",
      "function isSlashPending(address operator) view returns (bool)",
    ];
    const contract = new ethers.Contract(superPaymasterAddress, abi, this.provider);
    for (const fn of ["pendingSlash", "isSlashPending"] as const) {
      try {
        const pending: boolean = await contract[fn](operator, { blockTag });
        return Boolean(pending);
      } catch {
        // getter absent on this deployment — try the next name.
      }
    }
    return null;
  }

  /**
   * File a slash proposal binding the archived evidence (SP #329 4-arg createProposal):
   *   createProposal(address operator, uint8 level, string reason, bytes32 evidenceHash) returns (uint256 id)
   *
   * NOTE: the 4-arg `createProposal` selector is ONLY exposed by the #329 DVTValidator
   * (Sepolia default 0x568b1486BFE036e603eA11f0D03Dc47fa62c9E0e, config-overridable via
   * AUDIT_DVT_VALIDATOR_ADDRESS), which ships both the legacy 3-arg and this evidence-binding
   * 4-arg overload. Pointing this at an older 3-arg-only validator would revert (no matching
   * selector). Same admin-wallet + bumped-fees + await-receipt contract as createSlashProposal;
   * the extra `evidenceHash` (the content-addressed proofHash) binds the on-chain proposal to the
   * archived proof. Returns the tx hash and the REAL on-chain id parsed from ProposalCreated
   * (`null` when the event is absent, so the caller never fabricates an id).
   */
  async createProposalWithEvidence(
    dvtValidatorAddress: string,
    operator: string,
    level: number,
    reason: string,
    evidenceHash: string
  ): Promise<{ txHash: string; proposalId: bigint | null }> {
    if (!this.wallet) {
      throw new Error("Blockchain not configured. Set ETH_PRIVATE_KEY environment variable.");
    }
    const abi = [
      "function createProposal(address operator, uint8 level, string reason, bytes32 evidenceHash) returns (uint256)",
      "event ProposalCreated(uint256 indexed id, address indexed operator, uint8 level)",
    ];
    const iface = new ethers.Interface(abi);
    const contract = new ethers.Contract(dvtValidatorAddress, abi, this.wallet);
    const fees = await bumpedFees(this.provider);
    const tx: ethers.TransactionResponse = await contract.createProposal(
      operator,
      level,
      reason,
      evidenceHash,
      fees
    );
    this.logger.log(
      `createProposal(${operator}, ${level}, evidence ${evidenceHash}) submitted: ${tx.hash}`
    );
    const receipt = await tx.wait();
    if (!receipt || receipt.status !== 1) {
      throw new Error(
        `createProposal tx ${tx.hash} failed (status ${receipt?.status ?? "unknown"})`
      );
    }
    let proposalId: bigint | null = null;
    for (const log of receipt.logs) {
      try {
        const parsed = iface.parseLog({ topics: [...log.topics], data: log.data });
        if (parsed && parsed.name === "ProposalCreated") {
          proposalId = BigInt(parsed.args.id ?? parsed.args[0]);
          break;
        }
      } catch {
        // Not a ProposalCreated log (or from another contract) — skip.
      }
    }
    if (proposalId === null) {
      this.logger.warn(
        `createProposal ${tx.hash} confirmed but no ProposalCreated event found — id unresolved`
      );
    }
    this.logger.log(
      `createProposal(${operator}, ${level}) confirmed in block ${receipt.blockNumber}` +
        (proposalId !== null ? ` (proposalId ${proposalId})` : "")
    );
    return { txHash: tx.hash, proposalId };
  }

  /**
   * Step 1 of the two-step slash (SP #329):
   *   queueSlashWithProof(address operator, uint8 slashLevel, uint256 epoch, bytes proof)
   * `proof` is abi.encode(uint256 signerMask, bytes sigG2) from the quorum co-sign over the
   * step-1 messageHash. Admin wallet + bumped fees + await-receipt (throws on non-success so the
   * caller logs and archives the evidence anyway). Returns the tx hash.
   */
  async queueSlashWithProof(
    dvtValidatorAddress: string,
    operator: string,
    slashLevel: number,
    epoch: bigint | number,
    proof: string
  ): Promise<string> {
    if (!this.wallet) {
      throw new Error("Blockchain not configured. Set ETH_PRIVATE_KEY environment variable.");
    }
    const abi = [
      "function queueSlashWithProof(address operator, uint8 slashLevel, uint256 epoch, bytes proof) external",
    ];
    const contract = new ethers.Contract(dvtValidatorAddress, abi, this.wallet);
    const fees = await bumpedFees(this.provider);
    const tx: ethers.TransactionResponse = await contract.queueSlashWithProof(
      operator,
      slashLevel,
      epoch,
      proof,
      fees
    );
    this.logger.log(
      `queueSlashWithProof(${operator}, ${slashLevel}, epoch ${epoch}) submitted: ${tx.hash}`
    );
    const receipt = await tx.wait();
    if (!receipt || receipt.status !== 1) {
      throw new Error(
        `queueSlashWithProof tx ${tx.hash} failed (status ${receipt?.status ?? "unknown"})`
      );
    }
    this.logger.log(`queueSlashWithProof(${operator}) confirmed in block ${receipt.blockNumber}`);
    return tx.hash;
  }

  /**
   * Step 2 of the two-step slash (SP #329):
   *   executeWithProof(uint256 id, address[] repUsers, uint256[] newScores, uint256 epoch, bytes proof)
   * For a slash-only proposal repUsers/newScores are empty. `proof` is abi.encode(signerMask, sigG2)
   * from the quorum co-sign over the step-2 messageHash. Admin wallet + bumped fees +
   * await-receipt (throws on non-success). Returns the tx hash.
   */
  async executeSlashWithProof(
    dvtValidatorAddress: string,
    id: bigint | number,
    repUsers: string[],
    newScores: Array<bigint | number>,
    epoch: bigint | number,
    proof: string
  ): Promise<string> {
    if (!this.wallet) {
      throw new Error("Blockchain not configured. Set ETH_PRIVATE_KEY environment variable.");
    }
    const abi = [
      "function executeWithProof(uint256 id, address[] repUsers, uint256[] newScores, uint256 epoch, bytes proof) external",
    ];
    const contract = new ethers.Contract(dvtValidatorAddress, abi, this.wallet);
    const fees = await bumpedFees(this.provider);
    const tx: ethers.TransactionResponse = await contract.executeWithProof(
      id,
      repUsers,
      newScores,
      epoch,
      proof,
      fees
    );
    this.logger.log(`executeWithProof(id ${id}, epoch ${epoch}) submitted: ${tx.hash}`);
    const receipt = await tx.wait();
    if (!receipt || receipt.status !== 1) {
      throw new Error(
        `executeWithProof tx ${tx.hash} failed (status ${receipt?.status ?? "unknown"})`
      );
    }
    this.logger.log(`executeWithProof(id ${id}) confirmed in block ${receipt.blockNumber}`);
    return tx.hash;
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

    // AAStarAirAccount custom magic value for isValidOwnerAuth (not standard ERC-1271).
    // Sourced from the single cross-repo interface contract at module top (invariant-tested).
    const contract = new ethers.Contract(account, OWNER_AUTH_ABI, this.provider);

    try {
      const result = await contract.isValidOwnerAuth(userOpHash, ownerAuth);
      return result === OWNER_AUTH_MAGIC;
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
