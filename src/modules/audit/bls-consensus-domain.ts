import { ethers } from "ethers";

/**
 * SINGLE SOURCE OF TRUTH for every SuperPaymaster BLS-consensus pre-image the DVT reproduces
 * off-chain (CC-115 B1). Byte-for-byte identical to the live aggregator
 * `SuperPaymaster/contracts/src/modules/monitoring/BLSAggregator.sol`:
 *   DOMAIN_NAME            :238  keccak256("SuperPaymaster.BLSConsensus.v1")
 *   TAG_QUEUE_SLASH        :242  keccak256("SuperPaymaster.BLS.QueueSlash.v1")
 *   TAG_EXECUTE_SLASH      :243  keccak256("SuperPaymaster.BLS.ExecuteSlash.v1")
 *   TAG_REPUTATION         :244  keccak256("SuperPaymaster.BLS.Reputation.v1")
 *   TAG_SIGNERS_COMMITMENT :247  keccak256("SuperPaymaster.BLS.SignersCommitment.v1")
 *   TAG_FRAUD_PROOF        :248  keccak256("SuperPaymaster.BLS.FraudProof.v1")
 *   domainSeparator()      :255  keccak256(abi.encode(DOMAIN_NAME, chainId, aggregator, registry))
 *   queue slash message    :911  keccak256(abi.encode(domainSeparator, TAG_QUEUE_SLASH, operator, slashLevel, epoch))
 *   execute slash message  :977  keccak256(abi.encode(domainSeparator, TAG_EXECUTE_SLASH, proposalId, operator, slashLevel, epoch, evidenceHash))
 *   reputation message    :1330  keccak256(abi.encode(domainSeparator, TAG_REPUTATION, proposalId, users, newScores, epoch))
 *   signers commitment    :1299  keccak256(abi.encode(domainSeparator, TAG_SIGNERS_COMMITMENT, proposalId, messageHash, signerMask, signers))
 *   fraud-proof digest     :265  keccak256(abi.encode(domainSeparator, TAG_FRAUD_PROOF, fraudProofId, guiltyGuardians))
 *
 * The domain separator binds chainId + aggregator + Registry, so — unlike the obsolete pre-4.11
 * encodings this replaces — NO inner pre-image carries a raw chainId/aggregator or a string tag.
 *
 * SECURITY: the {@link BlsConsensusDomain} is ALWAYS the signing node's OWN configuration, never a
 * value taken from a gossip request. A node therefore only ever signs a hash bound to the aggregator
 * + Registry + chain it is configured for; a misconfigured or hostile peer simply fails to reach
 * quorum (fail-closed) rather than eliciting a signature valid on a different contract/chain.
 */

const ABI = ethers.AbiCoder.defaultAbiCoder();

/** keccak256(utf8("SuperPaymaster.BLSConsensus.v1")) — matches Solidity keccak256 of the literal. */
export const DOMAIN_NAME = ethers.id("SuperPaymaster.BLSConsensus.v1");
export const TAG_QUEUE_SLASH = ethers.id("SuperPaymaster.BLS.QueueSlash.v1");
export const TAG_EXECUTE_SLASH = ethers.id("SuperPaymaster.BLS.ExecuteSlash.v1");
export const TAG_REPUTATION = ethers.id("SuperPaymaster.BLS.Reputation.v1");
export const TAG_SIGNERS_COMMITMENT = ethers.id("SuperPaymaster.BLS.SignersCommitment.v1");
export const TAG_FRAUD_PROOF = ethers.id("SuperPaymaster.BLS.FraudProof.v1");

/** The three fields that identify a BLSAggregator deployment for domain separation. Node-local. */
export interface BlsConsensusDomain {
  chainId: bigint;
  aggregator: string;
  registry: string;
}

/** BLSAggregator.domainSeparator() (:255). */
export function domainSeparator(d: BlsConsensusDomain): string {
  return ethers.keccak256(
    ABI.encode(
      ["bytes32", "uint256", "address", "address"],
      [DOMAIN_NAME, d.chainId, ethers.getAddress(d.aggregator), ethers.getAddress(d.registry)]
    )
  );
}

/** Step-1 queue-slash pre-image (BLSAggregator.sol:911). */
export function queueSlashMessageHash(
  d: BlsConsensusDomain,
  operator: string,
  slashLevel: number,
  epoch: bigint
): string {
  return ethers.keccak256(
    ABI.encode(
      ["bytes32", "bytes32", "address", "uint8", "uint256"],
      [domainSeparator(d), TAG_QUEUE_SLASH, operator, slashLevel, epoch]
    )
  );
}

/** Step-2 execute (slash-only) pre-image (BLSAggregator.sol:977). repUsers/newScores are NOT fields. */
export function executeSlashMessageHash(
  d: BlsConsensusDomain,
  proposalId: bigint,
  operator: string,
  slashLevel: number,
  epoch: bigint,
  evidenceHash: string
): string {
  return ethers.keccak256(
    ABI.encode(
      ["bytes32", "bytes32", "uint256", "address", "uint8", "uint256", "bytes32"],
      [domainSeparator(d), TAG_EXECUTE_SLASH, proposalId, operator, slashLevel, epoch, evidenceHash]
    )
  );
}

/** Reputation / combined-path pre-image (BLSAggregator.sol:1330). */
export function reputationMessageHash(
  d: BlsConsensusDomain,
  proposalId: bigint,
  repUsers: string[],
  newScores: bigint[],
  epoch: bigint
): string {
  return ethers.keccak256(
    ABI.encode(
      ["bytes32", "bytes32", "uint256", "address[]", "uint256[]", "uint256"],
      [domainSeparator(d), TAG_REPUTATION, proposalId, repUsers, newScores, epoch]
    )
  );
}

/** A' signer-set commitment (BLSAggregator._computeSignersCommitment :1299). `signers` sorted asc. */
export function signersCommitment(
  d: BlsConsensusDomain,
  proposalId: bigint,
  messageHash: string,
  signerMask: bigint,
  signers: string[]
): string {
  return ethers.keccak256(
    ABI.encode(
      ["bytes32", "bytes32", "uint256", "bytes32", "uint256", "address[]"],
      [domainSeparator(d), TAG_SIGNERS_COMMITMENT, proposalId, messageHash, signerMask, signers]
    )
  );
}

/** The `domainDigest` SP hands to IFraudProofVerifier.verify (BLSAggregator.fraudProofDigest :265). */
export function fraudProofDigest(
  d: BlsConsensusDomain,
  fraudProofId: bigint,
  guiltyGuardians: string[]
): string {
  return ethers.keccak256(
    ABI.encode(
      ["bytes32", "bytes32", "uint256", "address[]"],
      [domainSeparator(d), TAG_FRAUD_PROOF, fraudProofId, guiltyGuardians]
    )
  );
}
