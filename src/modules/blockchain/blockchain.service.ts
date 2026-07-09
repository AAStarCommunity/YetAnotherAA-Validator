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

/**
 * Sentinel "tx hash" returned by queueSlashWithProof / executeSlashWithProof when they run in
 * DRY-RUN mode (AUDIT_DRY_RUN): the staticCall preflight ran against the REAL contracts and passed,
 * but the real broadcast was intentionally SKIPPED (no operator was slashed). It is NOT a real tx
 * hash — it is deliberately NOT 0x-hex-32 so it can never be mistaken for one. Shared with
 * AuditService (which records it verbatim in the archived proof and skips the durable slashed
 * marker) and the tests, so the "was this a dry run?" check has a single source of truth.
 */
export const DRY_RUN_TX_SENTINEL = "0xDRYRUN";

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

  /**
   * Nonce-race protection for the shared operator EOA (`this.wallet`): the attest keeper (inc-2)
   * and every slash/proposal/registration/updatePrice write share the same EOA. The rule is
   * BROADCAST-under-lock, WAIT-outside-lock: `enqueueWalletWrite` serializes only the nonce
   * allocation + send of each tx, NOT its receipt wait. That is what makes it deadlock-free — if a
   * write held the FIFO through its (possibly 20s) wait, a stuck lower-nonce attest could never be
   * replaced while a higher-nonce slash sat waiting on it (nonce head-of-line deadlock, Codex r3).
   * With waits outside the lock, the attest can always reacquire the FIFO to fee-bump a stuck nonce.
   *
   * Slash PRIORITY is a SEPARATE signal from the lock: `runWithSlashPriority` bumps `slashPending`
   * for a slash's whole lifetime (broadcast + wait), so a running attest sees it via
   * `hasPendingSlashWrite` and yields BEFORE taking a nonce (letting the slash take the lower nonce).
   * Once the attest has broadcast nonce N, a slash is at N+1 and DEPENDS on N mining, so the attest
   * then drives N to inclusion rather than yielding. slashPending does NOT hold the FIFO.
   */
  private walletChain: Promise<unknown> = Promise.resolve();
  private slashPending = 0;

  constructor(private configService: ConfigService) {
    this.initializeProvider();
  }

  /** True while any slash write is queued or running — the attest polls this to yield priority. */
  protected hasPendingSlashWrite(): boolean {
    return this.slashPending > 0;
  }

  /**
   * Serialize a single operator-wallet BROADCAST (nonce alloc + send) on the FIFO chain. Callers
   * MUST await the returned tx's receipt OUTSIDE this call (do not `await tx.wait()` inside `fn`),
   * or a slow inclusion would hold the lock and reintroduce the nonce head-of-line deadlock.
   */
  protected enqueueWalletWrite<T>(fn: () => Promise<T>): Promise<T> {
    const run = this.walletChain.then(fn, fn);
    // Keep the chain alive regardless of fn's outcome; swallow here so one failure
    // doesn't reject every future waiter (each caller still gets its own result/throw).
    this.walletChain = run.then(
      () => undefined,
      () => undefined
    );
    return run;
  }

  /**
   * Run a PRIORITY slash operation: bump `slashPending` for its WHOLE lifetime (so a running attest
   * yields before taking a nonce) — but do NOT hold the FIFO here. The slash method wraps only its
   * BROADCAST in `enqueueWalletWrite` and awaits the receipt outside it, so its wait never blocks the
   * attest from replacing a stuck nonce (the r3 deadlock).
   */
  protected runWithSlashPriority<T>(fn: () => Promise<T>): Promise<T> {
    this.slashPending++;
    return fn().finally(() => {
      this.slashPending--;
    });
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
        const kw = new ethers.Wallet(keeperKey, this.provider);
        // If KEEPER_PRIVATE_KEY resolves to the SAME EOA as ETH_PRIVATE_KEY (two Wallet objects, one
        // address), do NOT treat it as dedicated — else `keeperSigner` would be a distinct object and
        // `signer === this.wallet` in updatePrice would be false, leaving that periodic broadcast
        // OUTSIDE the shared nonce FIFO (Codex r3 High). Keep keeperWallet only for a DIFFERENT EOA.
        if (this.wallet && kw.address.toLowerCase() === this.wallet.address.toLowerCase()) {
          this.logger.warn(
            "KEEPER_PRIVATE_KEY is the SAME EOA as ETH_PRIVATE_KEY — treating as the operator wallet " +
              "(keeper writes serialize on the shared nonce FIFO)"
          );
        } else {
          this.keeperWallet = kw;
          this.logger.log(`Keeper signer (dedicated): ${this.keeperWallet.address}`);
        }
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
      // Broadcast on the shared operator-EOA FIFO so a concurrent attest/keeper can't race the nonce.
      const tx = await this.enqueueWalletWrite(() => contract.registerPublicKey(nodeId, publicKey));
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
      const tx = await this.enqueueWalletWrite(() => contract.revokePublicKey(nodeId));
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

      const tx = await this.enqueueWalletWrite(() =>
        contract.batchRegisterPublicKeys(nodeIds, publicKeys)
      );
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
   * Contract factory seam. All wallet-signed write paths (createProposal, queue/execute slash) build
   * their `ethers.Contract` through this one method so a test can override it to inject a mock —
   * `ethers` is an ESM namespace (read-only) and cannot be spied on directly. Production behaviour is
   * exactly `new ethers.Contract(...)`.
   */
  protected buildContract(
    address: string,
    abi: ethers.InterfaceAbi,
    runner: ethers.ContractRunner
  ): ethers.Contract {
    return new ethers.Contract(address, abi, runner);
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

  // ── SP LivenessRegistry (CC-29) reads — objective on-chain liveness. inc-2 uses these for
  //    OBSERVABILITY (alerting/forensics) + a soft co-sign request-set optimization, NOT for
  //    threshold math (BLSAggregator owns the fixed on-chain threshold; see INC2_DESIGN.md). All
  //    reads are `blockTag`-capable so a co-signer can reproduce the live-set at a slash epoch.
  //    Stable read ABI locked by SP PR #346 (Codex-APPROVED).

  private static readonly LIVENESS_READ_ABI = [
    "function isOffline(address op) view returns (bool)",
    "function areOffline(address[] ops) view returns (bool[])",
    "function lastLive(address op) view returns (uint256)",
    "function livenessWindow() view returns (uint256)",
  ];

  /** LivenessRegistry.livenessWindow() — fleet-global governance value (blocks). */
  async getLivenessWindow(registryAddress: string, blockTag?: number): Promise<bigint> {
    if (!this.provider) throw new Error("Blockchain provider not configured");
    const c = this.buildContract(
      registryAddress,
      BlockchainService.LIVENESS_READ_ABI,
      this.provider
    );
    return BigInt(await c.livenessWindow({ blockTag }));
  }

  /** LivenessRegistry.lastLive(op) — last block the operator attested (0 = never). Forensics/audit. */
  async getLastLive(registryAddress: string, op: string, blockTag?: number): Promise<bigint> {
    if (!this.provider) throw new Error("Blockchain provider not configured");
    const c = this.buildContract(
      registryAddress,
      BlockchainService.LIVENESS_READ_ABI,
      this.provider
    );
    return BigInt(await c.lastLive(op, { blockTag }));
  }

  /** LivenessRegistry.isOffline(op) — objective `block.number > lastLive + window`; never-attested ⇒ true. */
  async getIsOffline(registryAddress: string, op: string, blockTag?: number): Promise<boolean> {
    if (!this.provider) throw new Error("Blockchain provider not configured");
    const c = this.buildContract(
      registryAddress,
      BlockchainService.LIVENESS_READ_ABI,
      this.provider
    );
    return await c.isOffline(op, { blockTag });
  }

  /** LivenessRegistry.areOffline(ops) — batch; build the epoch live-set in one call (pin blockTag=epoch). */
  async getAreOffline(
    registryAddress: string,
    ops: string[],
    blockTag?: number
  ): Promise<boolean[]> {
    if (!this.provider) throw new Error("Blockchain provider not configured");
    if (ops.length === 0) return [];
    const c = this.buildContract(
      registryAddress,
      BlockchainService.LIVENESS_READ_ABI,
      this.provider
    );
    const res: boolean[] = await c.areOffline(ops, { blockTag });
    return res.map(Boolean);
  }

  /**
   * A recent anchor block `{ number, hash }` for `attestLiveness`, at `head − depth`. SP's M-01
   * fix requires anchorBlock ∈ [head−256, head−1] AND anchorHash == blockhash(anchorBlock). Pick
   * `depth` well ABOVE typical reorg depth (so the hash is stable → no BadAnchorHash) yet well
   * BELOW 256 (so the tx has ample inclusion margin before StaleAnchor). Depth is floored at 1.
   */
  async getAttestAnchor(depth: number): Promise<{ number: number; hash: string }> {
    if (!this.provider) throw new Error("Blockchain provider not configured");
    // Coerce to a protocol-valid depth: a finite integer in [1, 255]. An out-of-range/NaN depth
    // would otherwise select genesis, a stale block, or `getBlock(NaN)` (permanent tick failure).
    const safeDepth = Number.isFinite(depth) ? Math.min(255, Math.max(1, Math.floor(depth))) : 16;
    const latest = await this.provider.getBlockNumber();
    const target = Math.max(0, latest - safeDepth);
    const b = await this.provider.getBlock(target);
    if (!b || typeof b.number !== "number" || !b.hash) {
      throw new Error(
        `getAttestAnchor: could not resolve anchor block (latest ${latest}, target ${target})`
      );
    }
    return { number: b.number, hash: b.hash };
  }

  /**
   * Next fee bundle for an attest (re)send. For a same-nonce REPLACEMENT (`prev` set) it must
   * STRICTLY exceed the previous tx on BOTH fields (geth requires ≥10%; we use +12.5%), else the
   * node rejects it as `REPLACEMENT_UNDERPRICED` and the stuck tx never clears. It also floors at
   * the fresh network estimate, so a rising base fee is followed rather than undercut.
   */
  private async nextAttestFees(
    prev: { maxFeePerGas: bigint; maxPriorityFeePerGas: bigint } | null
  ): Promise<{ maxFeePerGas: bigint; maxPriorityFeePerGas: bigint }> {
    const fresh = await bumpedFees(this.provider);
    if (!prev) return fresh;
    // +12.5% (ceil, and at least prev+1) so a REPLACEMENT strictly exceeds prev on BOTH fields even
    // at tiny wei values where integer *1125/1000 would round back down to prev (geth wants ≥10%).
    const bump = (x: bigint): bigint => {
      const b = (x * 1125n + 999n) / 1000n;
      return b > x ? b : x + 1n;
    };
    const max = (a: bigint, b: bigint): bigint => (a > b ? a : b);
    return {
      maxFeePerGas: max(fresh.maxFeePerGas, bump(prev.maxFeePerGas)),
      maxPriorityFeePerGas: max(fresh.maxPriorityFeePerGas, bump(prev.maxPriorityFeePerGas)),
    };
  }

  /**
   * LivenessRegistry.attestLiveness(anchorBlock, anchorHash) — the operator (this node) self-proves
   * liveness on-chain so SP's auto-jail excludes it only when it is genuinely silent (inc-2 C1).
   *
   * msg.sender MUST be the registered operator EOA (`this.wallet`) — the registry attests the SENDER.
   *
   * Concurrency (Codex inc-2 rounds): the BROADCAST (nonce allocation + send) runs inside the shared
   * operator-EOA FIFO (`enqueueWalletWrite`) — that window is exclusive so no attest/slash nonce race
   * is possible — but the receipt WAIT runs OUTSIDE the lock, so a slash arriving during the wait
   * grabs the lock (and the next nonce) immediately instead of blocking behind our timeout.
   * Slash priority: we yield (bail) to a pending slash ONLY before our first broadcast (a slash then
   * takes the lower nonce). Once we've broadcast at nonce N, a slash is at N+1 and DEPENDS on N
   * mining, so we do NOT abandon N — we drive it to inclusion via same-nonce STRICTLY-increasing fee
   * replacement (`nextAttestFees`; a tx stuck > 256 blocks would freeze `lastLive` into false-offline),
   * which also unblocks the slash. A `maxSends` budget bounds real broadcasts; nonce-consumed /
   * underpriced recoveries don't consume it (bounded separately) so a refetch always gets a resend.
   * NOTE: this bounds a slash's wait to attest INCLUSION time, not zero — true tx-level preemption is
   * out of scope and unnecessary: DVT slashes are finalized-evidence-driven + two-step/multi-block,
   * not sub-block-time-sensitive.
   */
  async attestLiveness(
    registryAddress: string,
    anchorBlock: number,
    anchorHash: string,
    opts: { perAttemptMs?: number; maxAttempts?: number } = {}
  ): Promise<string> {
    if (!this.wallet) {
      throw new Error("attestLiveness: no operator wallet (ETH_PRIVATE_KEY unset)");
    }
    const perAttemptMs =
      Number.isFinite(opts.perAttemptMs) && (opts.perAttemptMs as number) > 0
        ? (opts.perAttemptMs as number)
        : 20_000;
    // Finite integer send budget, capped — an adversarial Infinity/NaN/fractional must not spin.
    const maxSends =
      Number.isInteger(opts.maxAttempts) && (opts.maxAttempts as number) > 0
        ? Math.min(opts.maxAttempts as number, 10)
        : 3;
    const op = this.wallet.address;
    const abi = ["function attestLiveness(uint256 anchorBlock, bytes32 anchorHash) external"];
    const contract = this.buildContract(registryAddress, abi, this.wallet);
    const sent: string[] = [];
    // Best-effort: return the first broadcast hash that already confirmed status 1.
    const reconcile = async (): Promise<string | null> => {
      for (const h of sent) {
        try {
          const r = await this.provider.getTransactionReceipt(h);
          if (r?.status === 1) return h;
        } catch {
          // ignore — best-effort
        }
      }
      return null;
    };

    // Early yield: a slash already pending → bail before ANY work (no preflight, no nonce).
    if (this.hasPendingSlashWrite()) {
      throw new Error("attestLiveness yielded to a pending slash write");
    }
    // Preflight is a READ (staticCall) — no nonce, no lock. A stale/bad anchor reverts here BEFORE
    // consuming a nonce, so the keeper re-anchors next tick instead of burning gas.
    try {
      await contract.attestLiveness.staticCall(anchorBlock, anchorHash);
    } catch (e: any) {
      throw new Error(
        `attestLiveness preflight reverted (stale/bad anchor?): ${e?.shortMessage ?? e?.message ?? e}`,
        { cause: e }
      );
    }

    let nonce: number | null = null;
    let prevFees: { maxFeePerGas: bigint; maxPriorityFeePerGas: bigint } | null = null;
    let lastErr: any;
    let sends = 0;
    // A recovery (nonce refetch / underpriced retry) does NOT consume the SEND budget — it only
    // consumes a separate recovery budget — so `maxSends` real broadcasts are guaranteed even when a
    // recovery lands on what would have been the last iteration (Codex r3 High #3 / Medium).
    let recoveries = 0;
    const maxRecoveries = maxSends * 2 + 2;
    while (sends < maxSends) {
      // 1) BROADCAST under the lock (only nonce-alloc + send are exclusive; the wait below is not).
      let tx: ethers.TransactionResponse;
      try {
        tx = await this.enqueueWalletWrite(async () => {
          // Yield to a pending slash ONLY before our first broadcast — once we hold nonce N a slash
          // is at N+1 and needs N to mine, so we must finish N rather than abandon it.
          if (sent.length === 0 && this.hasPendingSlashWrite()) {
            throw new Error("attestLiveness yielded to a pending slash write");
          }
          if (nonce === null) nonce = await this.provider.getTransactionCount(op, "pending");
          const fees = await this.nextAttestFees(prevFees);
          prevFees = fees;
          const t: ethers.TransactionResponse = await contract.attestLiveness(
            anchorBlock,
            anchorHash,
            { nonce, ...fees }
          );
          sent.push(t.hash);
          return t;
        });
        sends++;
      } catch (e: any) {
        lastErr = e;
        const code = e?.code;
        const msg = String(e?.shortMessage ?? e?.message ?? e);
        if (msg.includes("yielded")) break; // slash priority — re-anchor next tick
        if (++recoveries > maxRecoveries) break; // too many recoveries — give up (reconcile + throw)
        // Nonce consumed: our OWN earlier tx may have mined (reconcile → don't double-attest);
        // otherwise a slash took the nonce → refetch a fresh nonce (new tx → fresh fee baseline) and
        // retry. Recovery does NOT increment `sends`, so a real resend still follows.
        if (code === "NONCE_EXPIRED" || /nonce too low|nonce has already been used/i.test(msg)) {
          const hit = await reconcile();
          if (hit) return hit;
          nonce = null;
          prevFees = null;
          continue;
        }
        // Replacement underpriced → prevFees already bumped; retry same nonce (not a send).
        if (
          code === "REPLACEMENT_UNDERPRICED" ||
          /replacement transaction underpriced/i.test(msg)
        ) {
          continue;
        }
        break; // unknown send error — reconcile + throw
      }
      // 2) WAIT outside the lock — a slash can grab the lock + nonce N+1 during this window.
      try {
        const receipt = await tx.wait(1, perAttemptMs);
        if (receipt?.status === 1) return tx.hash;
        lastErr = new Error(
          `attest tx ${tx.hash} reverted (status ${receipt?.status ?? "unknown"})`
        );
        break; // mined but reverted → terminal for this anchor
      } catch (e: any) {
        lastErr = e;
        // Timeout / not yet mined → keep the SAME nonce, escalate fees next iteration (replacement).
      }
    }
    const hit = await reconcile();
    if (hit) return hit;
    throw new Error(
      `attestLiveness not confirmed after ${sends} send(s): ${lastErr?.message ?? lastErr}`
    );
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
    lookbackBlocks: number
  ): Promise<boolean | null> {
    if (!this.provider) {
      throw new Error("Blockchain provider not configured");
    }
    // Scan a BOUNDED window ending at the chain HEAD: [latest - lookbackBlocks, latest]. Slash
    // events are emitted near `latest` (a slash fires AFTER the finalized violation is detected), so
    // anchoring the window at the head — not at the ~60-blocks-behind finalized violationBlock — both
    // catches the real events AND keeps the getLogs range == lookbackBlocks. Size lookbackBlocks to
    // your RPC's getLogs cap (Alchemy free = 10) so the scan stays determinate; a range wider than the
    // cap errors → indeterminate → the over-slash guard fails CLOSED (real-env finding).
    let latest: number;
    try {
      latest = await this.provider.getBlockNumber();
    } catch (error: any) {
      this.logger.warn(
        `getRecentSlashExecuted getBlockNumber failed: ${error.message} — indeterminate`
      );
      return null;
    }
    const fromBlock = Math.max(0, latest - Math.max(0, lookbackBlocks));
    const iface = new ethers.Interface([
      "event SlashExecutedWithProof(address indexed operator, uint8 level, uint256 penalty, bytes32 proofHash, uint256 timestamp)",
      "event SlashExecuted(uint256 indexed proposalId, address indexed operator, uint8 level)",
      "event OperatorSlashed(address indexed operator, uint256 amount, uint8 level)",
    ]);
    const opTopic = ethers.zeroPadValue(ethers.getAddress(operator), 32);
    const filters = [
      // SlashExecutedWithProof (BLS/DVT execute) + OperatorSlashed (emitted by `_slash` on BOTH the
      // BLS path AND owner-manual `slashOperator`, which does NOT emit SlashExecutedWithProof — WITHOUT
      // it an owner-slashed operator reads "not slashed" and the audit double-slashes). Operator is
      // topics[1] in BOTH → fetch them in ONE getLogs with an OR of the two topic0 hashes.
      {
        name: "SlashExecutedWithProof|OperatorSlashed",
        topics: [
          [
            iface.getEvent("SlashExecutedWithProof")!.topicHash,
            iface.getEvent("OperatorSlashed")!.topicHash,
          ],
          opTopic,
        ],
      },
      // SlashExecuted: proposalId is 1st indexed (topics[1]), operator 2nd (topics[2]) — different
      // position, so it needs its own filter.
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
          topics: f.topics as (string | string[] | null)[],
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

  /**
   * Reconstruct whether `operator` is currently pending-slash on the SuperPaymaster WITHOUT an
   * on-chain getter. SP is at the EIP-170 size limit (39 bytes free) so it deliberately exposes NO
   * `isSlashPending` view; the state is instead rebuilt from the events SP emits at every
   * `_pendingSlash` flip. Rule (authoritative, from repo:sp): over a head-anchored window, take the
   * LATEST (by blockNumber, then logIndex) event for `operator` among —
   *   SET   → `SlashQueued(operator)`
   *   CLEAR → `SlashCancelled(operator)`         (owner `cancelSlash`)
   *   CLEAR → `OperatorSlashed(operator, ...)`   (emitted by BOTH the BLS execute path AND owner
   *                                               manual `slashOperator`; the latter does NOT emit
   *                                               `SlashExecutedWithProof`, so keying off that alone
   *                                               would forever mis-read a manually-slashed operator
   *                                               as still pending — hence `OperatorSlashed` is the
   *                                               authoritative CLEAR signal).
   * pending == (the latest such event is `SlashQueued`).
   *
   * Returns `null` (INDETERMINATE, fail-closed) on any getBlockNumber/getLogs error — the caller must
   * not read an unreadable chain as a definite pending/not-pending. Returns `false` when the window
   * holds no such event: size `lookbackBlocks` to the queue→execute latency / your RPC's getLogs cap
   * (Alchemy free = 10). A `SlashQueued` OLDER than the window reads as not-pending → the caller then
   * re-queues → the BLSAggregator `usedSlashQueueHashes` replay guard reverts the duplicate → the
   * queue step aborts transiently → retry next tick. Never a wrong slash, just a bounded retry.
   */
  async isSlashPending(
    superPaymasterAddress: string,
    operator: string,
    lookbackBlocks: number
  ): Promise<boolean | null> {
    if (!this.provider) {
      throw new Error("Blockchain provider not configured");
    }
    // PREFER the O(1) authoritative typed getter added in SuperPaymaster 5.4.2
    // (ISuperPaymaster.isSlashPending → reads _pendingSlash directly): no getLogs window, no reorg
    // edge, no owner-path OperatorSlashed miss — and it closes the fresh-node "peer slash aged out of
    // the window" residual. FALL BACK to the event reconstruction only when the getter is absent
    // (pre-5.4.2 SP → the call reverts) so the same DVT binary works against both. A getter that
    // returns a real bool is authoritative; a getter revert is treated as "not present", NOT as a
    // definite state.
    try {
      const contract = new ethers.Contract(
        superPaymasterAddress,
        ["function isSlashPending(address operator) view returns (bool)"],
        this.provider
      );
      const pending: boolean = await contract.isSlashPending(operator);
      return pending;
    } catch (err: unknown) {
      // The getter call did not return a bool. Two reasons collapse here — a pre-5.4.2 SP with no
      // isSlashPending function (call reverts), or a TRANSIENT RPC error — and we cannot always tell
      // them apart, so we log at debug (not warn: on a healthy 5.4.2 SP this branch never runs) and
      // fall back to the durable event reconstruction (which has its own fail-closed null on error).
      const msg = err instanceof Error ? err.message : String(err);
      this.logger.debug(
        `isSlashPending getter unavailable on ${superPaymasterAddress} (${msg}) — ` +
          `falling back to event reconstruction`
      );
      return this.isSlashPendingFromEvents(superPaymasterAddress, operator, lookbackBlocks);
    }
  }

  /**
   * Fallback pending reconstruction from SP events (used only against a pre-5.4.2 SP with no
   * isSlashPending getter). See the getter above for the authoritative path.
   */
  private async isSlashPendingFromEvents(
    superPaymasterAddress: string,
    operator: string,
    lookbackBlocks: number
  ): Promise<boolean | null> {
    if (!this.provider) {
      throw new Error("Blockchain provider not configured");
    }
    let latest: number;
    try {
      latest = await this.provider.getBlockNumber();
    } catch (error: any) {
      this.logger.warn(`isSlashPending getBlockNumber failed: ${error.message} — indeterminate`);
      return null;
    }
    const fromBlock = Math.max(0, latest - Math.max(0, lookbackBlocks));
    const iface = new ethers.Interface([
      "event SlashQueued(address indexed operator)",
      "event SlashCancelled(address indexed operator)",
      "event OperatorSlashed(address indexed operator, uint256 amount, uint8 level)",
    ]);
    // `operator` is the 1st indexed field (topics[1]) in ALL three events, so ONE getLogs with an
    // OR of the three topic0 hashes fetches them together (was 3 round-trips → 1). pending == the
    // LATEST match (by block, then logIndex) is SlashQueued.
    const opTopic = ethers.zeroPadValue(ethers.getAddress(operator), 32);
    const setTopic = iface.getEvent("SlashQueued")!.topicHash; // the only "pending = true" event
    const topic0s = [
      setTopic,
      iface.getEvent("SlashCancelled")!.topicHash,
      iface.getEvent("OperatorSlashed")!.topicHash,
    ];
    let logs;
    try {
      logs = await this.provider.getLogs({
        address: superPaymasterAddress,
        fromBlock,
        toBlock: "latest",
        topics: [topic0s, opTopic], // topics[0] = OR(SlashQueued|SlashCancelled|OperatorSlashed)
      });
    } catch (error: any) {
      // FAIL-CLOSED: an unscannable window is INDETERMINATE, never a silent "not pending".
      this.logger.warn(
        `isSlashPending getLogs failed on ${superPaymasterAddress}: ${error.message} — indeterminate`
      );
      return null;
    }
    let best: { block: number; index: number; pending: boolean } | null = null;
    for (const log of logs) {
      const block = log.blockNumber;
      const index = log.index; // ethers v6: logIndex within the block
      if (best === null || block > best.block || (block === best.block && index > best.index)) {
        best = { block, index, pending: log.topics[0] === setTopic };
      }
    }
    return best === null ? false : best.pending;
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
   * O(1) own-slot lookup (finding-3): BLSAggregator.getBLSPublicKey(validator) returns the
   * validator's (publicKey, slot, isActive) in a SINGLE read, so a node resolves its OWN registered
   * slot directly from its operator EOA — no 1..maxSlots scan. Returns the 1-indexed `slot` when the
   * validator is ACTIVE and `slot >= 1`; `null` when unregistered/inactive, the slot is out of
   * range, the EOA is malformed, or the read reverts (fail-closed).
   */
  async getRegisteredSlot(
    blsAggregatorAddress: string,
    operatorEoa: string
  ): Promise<number | null> {
    if (!this.provider) {
      throw new Error("Blockchain provider not configured");
    }
    let validator: string;
    try {
      validator = ethers.getAddress(operatorEoa);
    } catch {
      return null;
    }
    const abi = [
      "function getBLSPublicKey(address validator) view returns (tuple(bytes32 x_a, bytes32 x_b, bytes32 y_a, bytes32 y_b) publicKey, uint8 slot, bool isActive)",
    ];
    const contract = new ethers.Contract(blsAggregatorAddress, abi, this.provider);
    try {
      const res = await contract.getBLSPublicKey(validator);
      const isActive = res.isActive ?? res[2];
      if (!isActive) return null;
      const slot = Number(res.slot ?? res[1]);
      if (!Number.isInteger(slot) || slot < 1) return null;
      return slot;
    } catch (error: any) {
      this.logger.warn(
        `getRegisteredSlot(${validator}) failed on ${blsAggregatorAddress}: ${error.message}`
      );
      return null;
    }
  }

  /**
   * Offline-audit rule ② — the UNIX timestamp (seconds) of a block. The offline proof anchors its
   * "offline since" deadline to a FINALIZED block's on-chain timestamp (a globally-consistent clock)
   * so every DVT node computes the SAME deadline from the SAME block, independent of local wall-clock.
   * THROWS if the block can't be read (caller fails closed — no deterministic deadline → no slash).
   */
  async getBlockTimestamp(blockNumber: number): Promise<number> {
    if (!this.provider) {
      throw new Error("Blockchain provider not configured");
    }
    const block = await this.provider.getBlock(blockNumber);
    if (!block) {
      throw new Error(`getBlockTimestamp: block ${blockNumber} not found`);
    }
    return Number(block.timestamp);
  }

  /**
   * Over-issue-audit rule ③ (CC-28) — read a community xPNTs token's OBJECTIVE over-issuance flag,
   * pinned to a finalized block. `isOverIssued()` is the SP-delivered getter: true when the token's
   * issued value (totalSupply × exchangeRate × apntsPrice) exceeds its governance effectiveCap
   * (industryScale × capRatio + staked backing). A pure on-chain bool → every DVT node reads the SAME
   * value → deterministic content-address (unlike gossip-offline, this is objectively slashable).
   * THROWS on a provider/read error (fail-loud: the caller skips this token, never guesses a violation).
   */
  async getIsOverIssued(xpntsToken: string, blockTag?: number): Promise<boolean> {
    if (!this.provider) {
      throw new Error("Blockchain provider not configured");
    }
    const abi = ["function isOverIssued() view returns (bool)"];
    const contract = new ethers.Contract(xpntsToken, abi, this.provider);
    return await contract.isOverIssued({ blockTag });
  }

  /**
   * Over-issue-audit rule ③ — the community owner of an xPNTs token (the SLASH SUBJECT for over-
   * issuance; it is the community that minted beyond its cap). Read pinned to the evidence block so
   * the subject is fixed with the violation. Returns null on a read error (caller skips the token).
   */
  async getCommunityOwner(xpntsToken: string, blockTag?: number): Promise<string | null> {
    if (!this.provider) {
      throw new Error("Blockchain provider not configured");
    }
    const abi = ["function communityOwner() view returns (address)"];
    const contract = new ethers.Contract(xpntsToken, abi, this.provider);
    try {
      return ethers.getAddress(await contract.communityOwner({ blockTag }));
    } catch (error: any) {
      this.logger.warn(`getCommunityOwner(${xpntsToken}) failed: ${error.message}`);
      return null;
    }
  }

  /**
   * Offline-audit rule ② — resolve an on-chain operator to its gossip `nodeId`, the bridge between
   * the on-chain slash target (operator EOA) and the off-chain liveness key (gossip peer id). Reads
   * BLSAggregator.getBLSPublicKey(operator) → the registered EIP-2537 G1 key tuple (x_a,x_b,y_a,y_b =
   * the 128-byte encoding), then nodeId = keccak256(encoding) — IDENTICAL to gen-node-state.mjs /
   * registerWithProof. Returns null when the operator holds no ACTIVE slot (nothing to bind / slash).
   */
  async getOperatorNodeId(
    blsAggregatorAddress: string,
    operatorEoa: string
  ): Promise<string | null> {
    if (!this.provider) {
      throw new Error("Blockchain provider not configured");
    }
    let validator: string;
    try {
      validator = ethers.getAddress(operatorEoa);
    } catch {
      return null;
    }
    const abi = [
      "function getBLSPublicKey(address validator) view returns (tuple(bytes32 x_a, bytes32 x_b, bytes32 y_a, bytes32 y_b) publicKey, uint8 slot, bool isActive)",
    ];
    const contract = new ethers.Contract(blsAggregatorAddress, abi, this.provider);
    try {
      const res = await contract.getBLSPublicKey(validator);
      const isActive = res.isActive ?? res[2];
      if (!isActive) return null;
      const pk = res.publicKey ?? res[0];
      // Concatenate x_a ++ x_b ++ y_a ++ y_b = the 128-byte EIP-2537 G1 encoding, then keccak256.
      const encoding = ethers.concat([
        pk.x_a ?? pk[0],
        pk.x_b ?? pk[1],
        pk.y_a ?? pk[2],
        pk.y_b ?? pk[3],
      ]);
      return ethers.keccak256(encoding);
    } catch (error: any) {
      // THROW on a transient RPC/contract error — the caller (offline nodeId cache) must NOT conflate
      // this with an AUTHORITATIVE `null` (inactive/no-slot). null = "definitely not an active
      // validator" (drop the cache); throw = "unknown, keep the last-known nodeId" (Codex Medium).
      this.logger.warn(
        `getOperatorNodeId(${validator}) failed on ${blsAggregatorAddress}: ${error.message}`
      );
      throw new Error(
        `getOperatorNodeId(${validator}) failed on ${blsAggregatorAddress}: ${error.message}`,
        { cause: error }
      );
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
    // Parallelize the slot scan (was a serial RPC per slot): issue all validatorAtSlot(1..maxSlots)
    // reads at once, then pick the LOWEST-indexed slot that matches. Each getValidatorAtSlot already
    // fails closed to null on revert/absence, so a bad address / empty slot never matches.
    const slots = Array.from({ length: Math.max(0, maxSlots) }, (_, i) => i + 1);
    const validators = await Promise.all(
      slots.map(slot => this.getValidatorAtSlot(blsAggregatorAddress, slot))
    );
    for (let i = 0; i < validators.length; i++) {
      if (validators[i] && validators[i] === target) return slots[i];
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
   * Registry.hasRole(roleId, account) — does `operator` CURRENTLY hold the role, read at `blockTag`
   * (A1#6). A cheap O(1) eth_call used to CONFIRM a derived operator is still a role member at the
   * SAME finalized block the slash evidence is pinned to — closing the "cached membership block ≠
   * evidence block" gap without re-scanning events. THROWS on a provider error so the caller can
   * fail-closed (an unconfirmable membership must not authorize an irreversible slash).
   */
  async hasRole(
    registryAddress: string,
    roleId: string,
    operator: string,
    blockTag?: number
  ): Promise<boolean> {
    if (!this.provider) {
      throw new Error("Blockchain provider not configured");
    }
    const abi = ["function hasRole(bytes32 role, address account) view returns (bool)"];
    const contract = new ethers.Contract(registryAddress, abi, this.provider);
    return await contract.hasRole(roleId, operator, { blockTag });
  }

  /** Hard cap on role events accumulated in one derivation — bounds memory against a huge history
   *  or a malicious register/exit flood (Codex Medium-2). Exceeding it THROWS so the caller keeps its
   *  previous set rather than OOMing. ~100k events ≫ any realistic staked-role churn. */
  private static readonly MAX_ROLE_EVENTS = 100_000;

  /**
   * Enumerate the CURRENT members of one or more Registry roles — the on-chain
   * source of truth for "who is a registered operator" (A1#6). This replaces the
   * hand-curated AUDIT_WATCHLIST env with the permissionless registration set.
   *
   * Membership is derived up to `toBlock` — the caller passes the SAME FINALIZED block it evaluates
   * violations at, so a head-only (unfinalized) RoleExited/Registered can neither add nor drop an
   * operator relative to the evidence, and a reorg cannot flip the set after it was used (Codex
   * Medium-1). Never derive to a raw `latest`.
   *
   * `useGetter`-gated getter-FIRST, event-scan FALLBACK:
   *   1. Only when `useGetter` — call `getRoleMembers(bytes32) view returns (address[])` at
   *      `{ blockTag: toBlock }`. Default OFF: the deployed 5.4.2 Registry has no such getter
   *      (roleMembers is `internal`), and blindly trusting ANY ABI-decodable return from that 4-byte
   *      selector risks a selector-collision returning a valid-looking wrong set (Codex Medium-3).
   *      Enable only against a Registry known to implement it.
   *   2. FALLBACK (default): reconstruct the live set from role events over [fromBlock, toBlock]:
   *      ADD on RoleRegistered|RoleGranted, REMOVE on RoleExited|RoleRevoked, replayed in
   *      (block, logIndex) order so a re-join after an exit resurfaces the member.
   *
   * `roleId` is topics[1] (indexed) in ALL FOUR events; `user`/`account` is topics[2].
   * Returns CHECKSUMMED addresses, de-duplicated across the given roleIds.
   *
   * THROWS on a provider/getLogs error (fail-loud): the caller must treat an unscannable window as
   * "could not derive" and keep its previous set, NOT silently audit an empty list.
   */
  async getRegisteredOperators(
    registryAddress: string,
    roleIds: string[],
    fromBlock: number,
    toBlock: number,
    chunkSize: number,
    useGetter = false
  ): Promise<string[]> {
    if (!this.provider) {
      throw new Error("Blockchain provider not configured");
    }
    const out = new Set<string>();
    for (const roleId of roleIds) {
      if (useGetter) {
        // getter-first — one static read of the maintained roleMembers array, pinned to toBlock.
        // Still best-effort: a revert/decode error falls through to the event scan.
        try {
          const getterAbi = ["function getRoleMembers(bytes32 roleId) view returns (address[])"];
          const c = new ethers.Contract(registryAddress, getterAbi, this.provider);
          const members: string[] = await c.getRoleMembers(roleId, { blockTag: toBlock });
          for (const m of members) out.add(ethers.getAddress(m));
          continue; // getter succeeded for this role — skip the event scan
        } catch (error: any) {
          this.logger.debug(
            `getRoleMembers(${roleId}) failed on ${registryAddress} (${error.message}) — event scan`
          );
        }
      }
      // fallback (default) — reconstruct from events, replayed in chain order. REFUSE a from-genesis
      // scan (Codex Medium-2): with the getter enabled but fromBlock=0, a getter revert would
      // otherwise silently drop into a genesis-wide getLogs DoS. Throwing keeps the caller's previous
      // set instead. (roleDerive without the getter is already fail-closed at bootstrap.)
      if (fromBlock <= 0) {
        throw new Error(
          `getRegisteredOperators: refusing a from-genesis event scan for role ${roleId} ` +
            `(fromBlock=0) — set AUDIT_ROLE_FROM_BLOCK to the Registry deploy block`
        );
      }
      const derived = await this.deriveRoleMembersFromEvents(
        registryAddress,
        roleId,
        fromBlock,
        toBlock,
        chunkSize
      );
      for (const m of derived) out.add(m);
    }
    return [...out];
  }

  /**
   * Reconstruct one role's live member set from Registry events over [fromBlock, toBlock], chunked
   * to `chunkSize`. ADD on RoleRegistered|RoleGranted, REMOVE on RoleExited|RoleRevoked. On a getLogs
   * error the range is ADAPTIVELY HALVED down to a single block before giving up (handles a provider's
   * "too many results" on a dense window without failing the whole derivation), and only a
   * single-block failure THROWS — so a partial scan can never masquerade as a smaller member set.
   */
  private async deriveRoleMembersFromEvents(
    registryAddress: string,
    roleId: string,
    fromBlock: number,
    toBlock: number,
    chunkSize: number
  ): Promise<string[]> {
    if (!this.provider) {
      throw new Error("Blockchain provider not configured");
    }
    const iface = new ethers.Interface([
      "event RoleRegistered(bytes32 indexed roleId, address indexed user, uint256 burnAmount, uint256 timestamp)",
      "event RoleExited(bytes32 indexed roleId, address indexed user, uint256 exitFee, uint256 timestamp)",
      "event RoleGranted(bytes32 indexed role, address indexed account, address indexed sender)",
      "event RoleRevoked(bytes32 indexed role, address indexed account, address indexed sender)",
    ]);
    const addTopics = [
      iface.getEvent("RoleRegistered")!.topicHash,
      iface.getEvent("RoleGranted")!.topicHash,
    ];
    const removeTopics = [
      iface.getEvent("RoleExited")!.topicHash,
      iface.getEvent("RoleRevoked")!.topicHash,
    ];
    const roleTopic = ethers.zeroPadValue(roleId, 32); // roleId is topics[1] in all four
    const topicFilter = [[...addTopics, ...removeTopics], roleTopic];
    const events: { block: number; index: number; user: string; add: boolean }[] = [];

    // Scan [lo, hi]; on a getLogs error, halve until a single block fails (then throw). This absorbs
    // a provider's result-count cap on a dense range instead of aborting the whole derivation.
    const scanRange = async (lo: number, hi: number): Promise<void> => {
      let logs;
      try {
        logs = await this.provider!.getLogs({
          address: registryAddress,
          fromBlock: lo,
          toBlock: hi,
          topics: topicFilter,
        });
      } catch (error: any) {
        if (hi > lo) {
          const mid = Math.floor((lo + hi) / 2);
          await scanRange(lo, mid);
          await scanRange(mid + 1, hi);
          return;
        }
        // single block still fails — genuinely unscannable → fail-loud (caller keeps previous set).
        throw new Error(
          `deriveRoleMembers getLogs failed on ${registryAddress} block ${lo}: ${error.message}`,
          { cause: error }
        );
      }
      for (const log of logs) {
        if (events.length >= BlockchainService.MAX_ROLE_EVENTS) {
          throw new Error(
            `deriveRoleMembers exceeded ${BlockchainService.MAX_ROLE_EVENTS} events on ${registryAddress} ` +
              `role ${roleId} — refusing to derive (possible event flood / misconfigured fromBlock)`
          );
        }
        const user = ethers.getAddress(ethers.dataSlice(log.topics[2], 12)); // topics[2] = user (20B, left-padded)
        events.push({
          block: log.blockNumber,
          index: log.index,
          user,
          add: addTopics.includes(log.topics[0]),
        });
      }
    };

    const step = Math.max(1, chunkSize);
    for (let start = Math.max(0, fromBlock); start <= toBlock; start += step) {
      await scanRange(start, Math.min(start + step - 1, toBlock));
    }
    // Replay in (block, logIndex) order so the LAST event per user wins (re-join after exit).
    events.sort((a, b) => (a.block !== b.block ? a.block - b.block : a.index - b.index));
    const live = new Set<string>();
    for (const e of events) {
      if (e.add) live.add(e.user);
      else live.delete(e.user);
    }
    return [...live];
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
    // Priority slash write on the shared operator-wallet FIFO (bumps slashPending so a running
    // attest yields). Broadcast is wrapped in `enqueueWalletWrite`; the wait stays OUTSIDE it.
    return this.runWithSlashPriority(async () => {
      if (!this.wallet) {
        throw new Error("Blockchain not configured. Set ETH_PRIVATE_KEY environment variable.");
      }
      // Minimal fragment set: the write function plus the event we parse the real id from.
      const abi = [
        "function createProposal(address operator, uint8 level, string reason) returns (uint256)",
        "event ProposalCreated(uint256 indexed id, address indexed operator, uint8 level)",
      ];
      const iface = new ethers.Interface(abi);
      const contract = this.buildContract(dvtValidatorAddress, abi, this.wallet);
      const fees = await bumpedFees(this.provider);
      const tx: ethers.TransactionResponse = await this.enqueueWalletWrite(() =>
        contract.createProposal(operator, level, reason, fees)
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
          // MEDIUM 3 (Codex): only trust a ProposalCreated emitted BY the DVTValidator we called AND
          // matching THIS proposal's operator + level. A decodable log from another contract, or one
          // whose args disagree, must NEVER be mistaken for our proposal id (a wrong id would bind the
          // evidence to someone else's proposal and later make executeWithProof slash the wrong thing).
          if (ethers.getAddress(log.address) !== ethers.getAddress(dvtValidatorAddress)) continue;
          const parsed = iface.parseLog({ topics: [...log.topics], data: log.data });
          if (!parsed || parsed.name !== "ProposalCreated") continue;
          const evOperator = parsed.args.operator ?? parsed.args[1];
          const evLevel = parsed.args.level ?? parsed.args[2];
          if (ethers.getAddress(evOperator) !== ethers.getAddress(operator)) continue;
          if (Number(evLevel) !== level) continue;
          proposalId = BigInt(parsed.args.id ?? parsed.args[0]);
          break;
        } catch {
          // Not a ProposalCreated log from this validator (or from another contract) — skip.
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
    });
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
    evidenceHash: string,
    dryRun = false
  ): Promise<{ txHash: string; proposalId: bigint | null }> {
    return this.runWithSlashPriority(async () => {
      if (!this.wallet) {
        throw new Error("Blockchain not configured. Set ETH_PRIVATE_KEY environment variable.");
      }
      const abi = [
        "function createProposal(address operator, uint8 level, string reason, bytes32 evidenceHash) returns (uint256)",
        "event ProposalCreated(uint256 indexed id, address indexed operator, uint8 level)",
      ];
      const iface = new ethers.Interface(abi);
      const contract = this.buildContract(dvtValidatorAddress, abi, this.wallet);
      // DRY RUN (Codex #181 F1): createProposal is a REAL governance tx — broadcasting it in a drill
      // would leave an orphaned on-chain proposal. staticCall instead: it validates the call AND returns
      // the would-be proposalId (createProposal's return value) for the execute messageHash, with NO
      // broadcast and no side effect.
      if (dryRun) {
        const wouldBeId: bigint = await contract.createProposal.staticCall(
          operator,
          level,
          reason,
          evidenceHash
        );
        this.logger.log(
          `createProposal DRY RUN: staticCall passed (would-be id ${wouldBeId}) — NOT broadcasting`
        );
        return { txHash: DRY_RUN_TX_SENTINEL, proposalId: wouldBeId };
      }
      const fees = await bumpedFees(this.provider);
      const tx: ethers.TransactionResponse = await this.enqueueWalletWrite(() =>
        contract.createProposal(operator, level, reason, evidenceHash, fees)
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
          // MEDIUM 3 (Codex): only trust a ProposalCreated emitted BY the DVTValidator we called AND
          // matching THIS proposal's operator + level. A decodable log from another contract, or one
          // whose args disagree, must NEVER be mistaken for our proposal id (a wrong id would bind the
          // evidence to someone else's proposal and later make executeWithProof slash the wrong thing).
          if (ethers.getAddress(log.address) !== ethers.getAddress(dvtValidatorAddress)) continue;
          const parsed = iface.parseLog({ topics: [...log.topics], data: log.data });
          if (!parsed || parsed.name !== "ProposalCreated") continue;
          const evOperator = parsed.args.operator ?? parsed.args[1];
          const evLevel = parsed.args.level ?? parsed.args[2];
          if (ethers.getAddress(evOperator) !== ethers.getAddress(operator)) continue;
          if (Number(evLevel) !== level) continue;
          proposalId = BigInt(parsed.args.id ?? parsed.args[0]);
          break;
        } catch {
          // Not a ProposalCreated log from this validator (or from another contract) — skip.
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
    });
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
    proof: string,
    dryRun = false
  ): Promise<string> {
    return this.runWithSlashPriority(async () => {
      if (!this.wallet) {
        throw new Error("Blockchain not configured. Set ETH_PRIVATE_KEY environment variable.");
      }
      const abi = [
        "function queueSlashWithProof(address operator, uint8 slashLevel, uint256 epoch, bytes proof) external",
      ];
      const contract = this.buildContract(dvtValidatorAddress, abi, this.wallet);
      // STATIC-CALL PREFLIGHT (Codex HIGH 2): simulate the EXACT call first. Any deterministic
      // mismatch (bad signerMask, sigG2 encoding, DST, on-chain threshold, stale slot mapping, wrong
      // address, proposal state) reverts HERE — before spending a single wei of gas — so the audit's
      // try/catch degrades to file+archive instead of eating a PAID on-chain revert. Only a passing
      // simulation lets the real, irreversible tx broadcast.
      try {
        await contract.queueSlashWithProof.staticCall(operator, slashLevel, epoch, proof);
      } catch (err: unknown) {
        const reason = err instanceof Error ? err.message : String(err);
        throw new Error(
          `queueSlashWithProof preflight (staticCall) reverted — NOT broadcasting: ${reason}`,
          { cause: err }
        );
      }
      // DRY-RUN (AUDIT_DRY_RUN): the preflight above ran against the REAL contract and passed, proving
      // the signerMask/sigG2/threshold/slot mapping are accepted by verifyAndExecute. Stop HERE — do
      // NOT broadcast the real queue tx and do NOT await a receipt (there is no tx). Return the sentinel
      // so the caller records that this step was a dry run instead of a real slash queue.
      if (dryRun) {
        this.logger.warn(
          `queueSlashWithProof DRY RUN: staticCall passed, NOT broadcasting — would queue slash of ` +
            `${operator} (slashLevel ${slashLevel}, epoch ${epoch})`
        );
        return DRY_RUN_TX_SENTINEL;
      }
      const fees = await bumpedFees(this.provider);
      const tx: ethers.TransactionResponse = await this.enqueueWalletWrite(() =>
        contract.queueSlashWithProof(operator, slashLevel, epoch, proof, fees)
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
    });
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
    proof: string,
    dryRun = false
  ): Promise<string> {
    return this.runWithSlashPriority(async () => {
      if (!this.wallet) {
        throw new Error("Blockchain not configured. Set ETH_PRIVATE_KEY environment variable.");
      }
      const abi = [
        "function executeWithProof(uint256 id, address[] repUsers, uint256[] newScores, uint256 epoch, bytes proof) external",
      ];
      const contract = this.buildContract(dvtValidatorAddress, abi, this.wallet);
      // STATIC-CALL PREFLIGHT (Codex HIGH 2): simulate the EXACT execute call first so any
      // deterministic revert (signerMask/sigG2/threshold/proposal-state mismatch) surfaces BEFORE the
      // irreversible slash tx spends gas. Only a passing simulation lets the real tx broadcast.
      try {
        await contract.executeWithProof.staticCall(id, repUsers, newScores, epoch, proof);
      } catch (err: unknown) {
        const reason = err instanceof Error ? err.message : String(err);
        throw new Error(
          `executeWithProof preflight (staticCall) reverted — NOT broadcasting: ${reason}`,
          { cause: err }
        );
      }
      // DRY-RUN (AUDIT_DRY_RUN): the preflight above simulated the EXACT irreversible slash against the
      // REAL contract and passed — proving verifyAndExecute accepts the proof — but this is a drill, so
      // stop HERE. Do NOT broadcast the real slash and do NOT await a receipt. Return the sentinel so the
      // caller records that NO operator was actually slashed (and skips the durable over-slash marker).
      if (dryRun) {
        this.logger.warn(
          `executeSlashWithProof DRY RUN: staticCall passed, NOT broadcasting — would slash proposal ` +
            `id ${id} (epoch ${epoch})`
        );
        return DRY_RUN_TX_SENTINEL;
      }
      const fees = await bumpedFees(this.provider);
      const tx: ethers.TransactionResponse = await this.enqueueWalletWrite(() =>
        contract.executeWithProof(id, repUsers, newScores, epoch, proof, fees)
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
    });
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
    // When no dedicated KEEPER_PRIVATE_KEY is set, `signer` IS the operator EOA — serialize this
    // periodic broadcast on the shared FIFO so it can't race the attest/slash nonce. A dedicated
    // keeper key is a SEPARATE EOA (its own nonce space) and needs no serialization.
    const broadcast = (): Promise<ethers.TransactionResponse> => contract.updatePrice(fees);
    const tx: ethers.TransactionResponse =
      signer === this.wallet ? await this.enqueueWalletWrite(broadcast) : await broadcast();
    return tx.hash;
  }
}
