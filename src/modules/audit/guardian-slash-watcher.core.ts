import { ethers } from "ethers";
import {
  decodeVerifyAndExecuteCalldata,
  resolveClaimedSigners,
  rawSlashMessageHash,
  repSlashMessageHash,
  computeSignersCommitment,
} from "./guardian-fraud-proof.js";
import { BlsConsensusDomain } from "./bls-consensus-domain.js";
import { GuardianSignerRecord } from "./guardian-signer-store.js";

/**
 * The pure, testable core of the watcher: given a `SlashExecuted` occurrence (its proposalId, tx
 * hash, and execution block) plus a provider, reconstruct the durable {@link GuardianSignerRecord}
 * and self-verify it against SP's on-chain A' commitment.
 *
 * Kept standalone (no NestJS/DI) so it can be unit-tested with a mock provider — the same reason
 * `orderSignersFromSlotMap` was extracted (CC-89 Codex Medium). The service just polls events and
 * calls this.
 */

/** Minimal ABI for the two aggregator reads the builder needs. */
const AGGREGATOR_READ_ABI = [
  "function proposalSignersCommitment(uint256 proposalId) view returns (bytes32)",
  "function validatorAtSlot(uint8 slot) view returns (address)",
];

/** BLSAggregator.SlashExecuted — the event the watcher polls. */
export const SLASH_EXECUTED_EVENT =
  "event SlashExecuted(uint256 indexed proposalId, address indexed operator, uint8 level)";

export class WatcherRecordError extends Error {}

/**
 * Build + self-check the record for one executed slash. THROWS ({@link WatcherRecordError}) when the
 * capture is UNSAFE to persist — a wrong selector, a proposalId mismatch, or a zero/hole slot — so
 * the watcher NEVER stores a guessed or partial signer set (an incorrect set is worse than none: it
 * would misattribute the slash). A `commitmentVerified: false` record (recompute ≠ on-chain, or no
 * commitment) is still returned — it is durable evidence the capture needs manual review, not a
 * silent drop.
 */
export async function buildGuardianSignerRecord(
  provider: ethers.Provider,
  aggregatorAddress: string,
  registryAddress: string,
  chainId: bigint,
  eventProposalId: bigint,
  txHash: string,
  executionBlock: number
): Promise<GuardianSignerRecord> {
  // The node-local BLS-consensus domain (chainId+aggregator+Registry). MUST be this deployment's
  // real Registry, or every reconstructed messageHash/commitment differs from SP's and the capture
  // is (correctly) flagged commitmentVerified:false.
  const domain: BlsConsensusDomain = {
    chainId,
    aggregator: aggregatorAddress,
    registry: registryAddress,
  };
  const tx = await provider.getTransaction(txHash);
  if (!tx) throw new WatcherRecordError(`tx ${txHash} not found`);

  // Decode the OUTER verifyAndExecute call. Throws if not that call (intermediary-wrapped calls are
  // Phase-3; see decodeVerifyAndExecuteCalldata). The decoded fields are exactly what SP hashed.
  const args = decodeVerifyAndExecuteCalldata(tx.data);

  // Cross-check the event's proposalId against the calldata — a mismatch means this tx is not the
  // one that produced this event (e.g. a batched/multicall tx we can't attribute); refuse to record.
  if (args.proposalId !== eventProposalId) {
    throw new WatcherRecordError(
      `proposalId mismatch: event ${eventProposalId} vs calldata ${args.proposalId} (tx ${txHash})`
    );
  }

  const agg = new ethers.Contract(aggregatorAddress, AGGREGATOR_READ_ABI, provider);

  // Resolve co-signers at the EXECUTION block (SP byte-critical: validatorAtSlot at exec block, NOT
  // the epoch block). resolveClaimedSigners throws on a zero/hole slot → we never record a partial set.
  const claimedSigners = await resolveClaimedSigners(
    provider,
    aggregatorAddress,
    args.signerMask,
    executionBlock
  );

  // Reconstruct the signed messageHash on the SAME branch SP used (slash-only vs rep/combined), so
  // the recomputed commitment is byte-identical.
  const messageHash =
    args.repUsers.length === 0
      ? rawSlashMessageHash(
          domain,
          args.proposalId,
          args.operator,
          args.slashLevel,
          args.epoch,
          args.evidenceHash
        )
      : repSlashMessageHash(
          domain,
          args.proposalId,
          args.operator,
          args.slashLevel,
          args.repUsers,
          args.newScores,
          args.epoch
        );

  const localCommitment = computeSignersCommitment(
    domain,
    args.proposalId,
    messageHash,
    args.signerMask,
    claimedSigners
  );

  // Read the on-chain commitment at the execution block (immutable once set, but pin for reorg
  // determinism). A match proves our claimedSigners derivation is byte-aligned with SP.
  const onChainCommitment: string = await agg.proposalSignersCommitment(args.proposalId, {
    blockTag: executionBlock,
  });
  const commitmentVerified =
    onChainCommitment !== ethers.ZeroHash && localCommitment === onChainCommitment;

  const block = await provider.getBlock(executionBlock);
  const executionBlockTimestamp = block?.timestamp ?? 0;

  return {
    proposalId: args.proposalId.toString(),
    operator: args.operator,
    slashLevel: args.slashLevel,
    epoch: args.epoch.toString(),
    evidenceHash: args.evidenceHash,
    signerMask: args.signerMask.toString(),
    claimedSigners,
    executionBlock,
    txHash,
    chainId: chainId.toString(),
    commitment: onChainCommitment,
    commitmentVerified,
    executionBlockTimestamp,
  };
}
