import { ethers } from "ethers";

/**
 * DVT Phase 2 (目标2) — slash-consensus primitives, increment 2.
 *
 * These are the PURE, side-effect-free building blocks the two-step slash orchestration
 * (AuditService.coordinateQuorumCoSign) is composed from, plus the quorum co-sign seam.
 * They are broken out here so the exact on-chain preimages can be unit-tested in isolation
 * against a hand-computed ethers.AbiCoder reference — a byte mismatch here would make every
 * DVTValidator write revert (BLS aggregate verification is over these exact hashes).
 *
 * Interface source of truth: SuperPaymaster #329 (finalized). The two slash steps are
 * INDEPENDENT (each quorum co-signed once over its own preimage, each carrying its own proof):
 *
 *   Step 1 (queue):   DVTValidator.queueSlashWithProof(operator, slashLevel, epoch, proof)
 *     messageHash = keccak256(abi.encode(
 *       keccak256("QUEUE_SLASH"), operator, slashLevel, epoch, block.chainid))   // 5 fields
 *
 *   Step 2 (execute): DVTValidator.executeWithProof(id, repUsers, newScores, epoch, proof)
 *     messageHash = keccak256(abi.encode(
 *       proposalId, operator, slashLevel, repUsers[], newScores[],
 *       epoch, block.chainid, evidenceHash))                                     // 8 fields
 *     For a slash-only proposal repUsers and newScores are BOTH empty ([]).
 *
 *   proof (both steps): abi.encode(uint256 signerMask, bytes sigG2)
 */

const ABI = new ethers.AbiCoder();

/**
 * Domain-separation tag for the queue-slash preimage. keccak256("QUEUE_SLASH") — the UTF-8
 * bytes of the literal, exactly matching the Solidity `keccak256("QUEUE_SLASH")`.
 */
export const QUEUE_SLASH_TAG = ethers.id("QUEUE_SLASH");

/**
 * On-chain slash severity enum (SP #329 SlashLevel). The audit's credit-over-limit rule maps
 * to MINOR (see AuditService). WARNING is 2-of-3 quorum in the N=3 bootstrap; MINOR/MAJOR 3-of-3.
 */
export enum SlashLevel {
  WARNING = 0,
  MINOR = 1,
  MAJOR = 2,
}

/**
 * Step-1 queue preimage — keccak256 over the 5-field encoding with the QUEUE_SLASH domain tag.
 * This is the message the DVT quorum co-signs before queueSlashWithProof.
 */
export function buildQueueMessageHash(
  operator: string,
  slashLevel: number,
  epoch: bigint | number,
  chainId: bigint | number
): string {
  return ethers.keccak256(
    ABI.encode(
      ["bytes32", "address", "uint8", "uint256", "uint256"],
      [QUEUE_SLASH_TAG, operator, slashLevel, epoch, chainId]
    )
  );
}

/**
 * Step-2 execute preimage — keccak256 over the 8-field encoding. repUsers/newScores are empty
 * for a slash-only proposal; evidenceHash binds the on-chain slash to the archived proof
 * (the audit passes proofHash here). This is the message the DVT quorum co-signs before
 * executeWithProof.
 */
export function buildExecuteMessageHash(
  proposalId: bigint | number,
  operator: string,
  slashLevel: number,
  epoch: bigint | number,
  chainId: bigint | number,
  evidenceHash: string
): string {
  return ethers.keccak256(
    ABI.encode(
      ["uint256", "address", "uint8", "address[]", "uint256[]", "uint256", "uint256", "bytes32"],
      [proposalId, operator, slashLevel, [], [], epoch, chainId, evidenceHash]
    )
  );
}

/** abi.encode(uint256 signerMask, bytes sigG2) — the wire proof both slash steps carry. */
export function encodeProof(signerMask: bigint, sigG2: string): string {
  return ABI.encode(["uint256", "bytes"], [signerMask, sigG2]);
}

/**
 * The quorum co-sign seam. Given a messageHash, an implementation gathers enough peer BLS
 * signatures to meet the slash-level threshold, aggregates them into a single G2 signature,
 * and returns the aggregate together with the signerMask bitmap (bit i set ⇔ SP validator
 * slot i contributed). AuditService injects this so the two-step orchestration is fully
 * unit-testable now, ahead of the real gossip aggregator.
 */
export interface IQuorumCoSigner {
  coSign(messageHash: string): Promise<{ signerMask: bigint; sigG2: string }>;
}

/**
 * Default (deferred) co-signer. The real multi-node gossip BLS aggregation — collect peer
 * signatures over the messageHash, build the signerMask by SP-assigned validator slot, and
 * aggregate into sigG2 — needs SuperPaymaster to hand out slots via registerBLSPublicKey,
 * which is gated behind a 24h timelock. Until then every co-sign fails closed, so the audit
 * still FILES + ARCHIVES the proposal but never sends a queue/execute that would revert.
 *
 * TODO(inc-2 live): real gossip aggregator once SP assigns slots.
 */
export class PendingSlotCoSigner implements IQuorumCoSigner {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  async coSign(_messageHash: string): Promise<{ signerMask: bigint; sigG2: string }> {
    throw new Error(
      "quorum co-sign deferred — gossip BLS aggregation needs SP validator slots " +
        "(registerBLSPublicKey, pending 24h timelock)"
    );
  }
}
