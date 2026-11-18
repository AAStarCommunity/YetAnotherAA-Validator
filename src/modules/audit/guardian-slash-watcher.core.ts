import { ethers } from "ethers";
import {
  decodeVerifyAndExecuteCalldata,
  decodeExecuteWithProofCalldata,
  decodeSignerMaskFromBlsProof,
  DVT_PROPOSALS_ABI,
  VerifyAndExecuteArgs,
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
  "function DVT_VALIDATOR() view returns (address)",
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

  // Recover exactly the arguments the aggregator's verifyAndExecute saw. Two shapes reach it:
  // - a direct call to the aggregator: decode verifyAndExecute itself;
  // - the NORMAL path (SP DVTValidator-0.9.0, Daybreak on #441, High): a call to the DVTValidator
  //   the aggregator names at that block, executeWithProof(id, repUsers, newScores, epoch, evidence,
  //   proof). The DVTValidator forwards (id, p.operator, p.slashLevel, repUsers, newScores, epoch,
  //   p.evidenceHash, proof), having required its recomputed evidence hash to equal p.evidenceHash,
  //   so operator, level and evidenceHash are read from its proposals(id) at the execution block.
  // Any other target is refused. The on-chain commitment comparison below then checks the result.
  const agg = new ethers.Contract(aggregatorAddress, AGGREGATOR_READ_ABI, provider);
  const target = (tx.to ?? "").toLowerCase();
  let args: VerifyAndExecuteArgs;
  if (target === aggregatorAddress.toLowerCase()) {
    args = decodeVerifyAndExecuteCalldata(tx.data);
  } else {
    let dvtAddr: string;
    try {
      dvtAddr = await agg.DVT_VALIDATOR({ blockTag: executionBlock });
    } catch (e) {
      throw new WatcherRecordError(
        `cannot read aggregator.DVT_VALIDATOR() at block ${executionBlock}: ${(e as Error).message}`
      );
    }
    if (target !== dvtAddr.toLowerCase()) {
      throw new WatcherRecordError(
        `tx ${txHash} targets ${tx.to}, neither the aggregator nor its DVTValidator ${dvtAddr}`
      );
    }
    let w;
    try {
      w = decodeExecuteWithProofCalldata(tx.data);
    } catch (e) {
      throw new WatcherRecordError(`tx ${txHash} to the DVTValidator: ${(e as Error).message}`);
    }
    const dvt = new ethers.Contract(dvtAddr, [DVT_PROPOSALS_ABI], provider);
    let p;
    try {
      p = await dvt.proposals(w.proposalId, { blockTag: executionBlock });
    } catch (e) {
      throw new WatcherRecordError(
        `cannot read DVTValidator.proposals(${w.proposalId}) at block ${executionBlock}: ${(e as Error).message}`
      );
    }
    if (!p.exists || !p.executed) {
      throw new WatcherRecordError(
        `DVTValidator proposal ${w.proposalId} is not an executed proposal at block ${executionBlock}`
      );
    }
    args = {
      proposalId: w.proposalId,
      operator: ethers.getAddress(p.operator),
      slashLevel: Number(p.slashLevel),
      repUsers: w.repUsers,
      newScores: w.newScores,
      epoch: w.epoch,
      evidenceHash: p.evidenceHash,
      signerMask: decodeSignerMaskFromBlsProof(w.proof),
    };
  }

  // Cross-check the event's proposalId against the calldata — a mismatch means this tx is not the
  // one that produced this event (e.g. a batched/multicall tx we can't attribute); refuse to record.
  if (args.proposalId !== eventProposalId) {
    throw new WatcherRecordError(
      `proposalId mismatch: event ${eventProposalId} vs calldata ${args.proposalId} (tx ${txHash})`
    );
  }

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

  // SP 4.14.0 binds blockhash(block.number - 1) of the executing block into the commitment (#441).
  // Read it from the chain here: it is the one input that cannot be rebuilt from calldata later.
  const parent = await provider.getBlock(executionBlock - 1);
  if (!parent?.hash)
    throw new WatcherRecordError(`parent block ${executionBlock - 1} not available`);
  const parentBlockHash = parent.hash;

  const localCommitment = computeSignersCommitment(
    domain,
    args.proposalId,
    messageHash,
    args.signerMask,
    claimedSigners,
    parentBlockHash
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
    parentBlockHash,
  };
}
