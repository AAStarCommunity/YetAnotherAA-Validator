import { ethers } from "ethers";

/**
 * CC-89 stage-2 (over-issue class) — the off-chain half that feeds
 * `OverIssueFraudProofVerifier`. Two concerns live here:
 *
 *  1. `resolveClaimedSigners` — the byte-critical derivation the watcher runs: from a
 *     `verifyAndExecute` tx's `signerMask`, resolve the co-signer ADDRESSES using the
 *     aggregator's `validatorAtSlot` **pinned to the verifyAndExecute EXECUTION block**
 *     (NOT the over-issue epoch block — SP correction, CC-89 7b4f237e #2), sorted strictly
 *     ascending by uint160. This MUST match SP's `_computeSignersCommitment` `sorted`
 *     derivation byte-for-byte, else the on-chain commitment check rejects every proof.
 *
 *  2. `encodeOverIssueFraudProof` / `deriveFraudProofId` — the assembler: builds the exact
 *     `fraudProof` bytes + `fraudProofId` the verifier decodes. The over-issue slash's
 *     `evidenceHash` has a FIXED preimage the E2E filer must also use (docs §4b).
 *
 * The commitment is irreversible, so the watcher MUST record `claimedSigners` at
 * fraud-observation time and MUST be run redundantly on multiple nodes — if every watcher
 * misses a slash's signer set, attribution is permanently lost.
 */

/** Domain tags — MUST match OverIssueFraudProofVerifier.sol exactly. */
export const FRAUD_ID_TAG = "GUARDIAN_FRAUD_V1";
export const OVERISSUE_EVIDENCE_TAG = "DVT_OVERISSUE_EVIDENCE_V1";
/** BLSAggregator.MAX_VALIDATORS. */
export const MAX_VALIDATORS = 13;

/** Decode the `signerMask` from a verifyAndExecute `proof` (= abi.encode(uint256 signerMask, bytes sigG2)). */
export function decodeSignerMask(proof: string): bigint {
  // Only the first 32-byte word is the mask; SP decodes proof[:32] likewise.
  const [signerMask] = ethers.AbiCoder.defaultAbiCoder().decode(["uint256"], ethers.dataSlice(proof, 0, 32));
  return BigInt(signerMask);
}

/**
 * Resolve co-signer addresses for a `signerMask`, reading `validatorAtSlot` pinned to
 * `executionBlock` (the block the verifyAndExecute tx was mined in), sorted ascending by
 * uint160 — byte-identical to SP `_computeSignersCommitment`.
 *
 * THROWS if any selected slot resolves to the zero address at that block (a hole means the
 * mask/block pair is wrong — never silently record a partial/incorrect set).
 */
export async function resolveClaimedSigners(
  provider: ethers.Provider,
  aggregator: string,
  signerMask: bigint,
  executionBlock: number
): Promise<string[]> {
  const agg = new ethers.Contract(
    aggregator,
    ["function validatorAtSlot(uint8 slot) view returns (address)"],
    provider
  );
  const signers: string[] = [];
  for (let slot = 1; slot <= MAX_VALIDATORS; slot++) {
    if (((signerMask >> BigInt(slot - 1)) & 1n) === 0n) continue;
    const addr: string = await agg.validatorAtSlot(slot, { blockTag: executionBlock });
    if (addr === ethers.ZeroAddress) {
      throw new Error(
        `resolveClaimedSigners: slot ${slot} is zero at block ${executionBlock} — wrong mask/block?`
      );
    }
    signers.push(ethers.getAddress(addr));
  }
  // Strictly ascending by uint160(address). getAddress → checksummed; compare on the numeric value.
  signers.sort((a, b) => {
    const x = BigInt(a);
    const y = BigInt(b);
    return x < y ? -1 : x > y ? 1 : 0;
  });
  // Reject a duplicate (a healthy slot map never repeats an address across selected slots).
  for (let i = 1; i < signers.length; i++) {
    if (BigInt(signers[i - 1]) >= BigInt(signers[i])) {
      throw new Error(`resolveClaimedSigners: duplicate/unordered signer ${signers[i]}`);
    }
  }
  return signers;
}

/** Canonical fraudProofId — MUST match verifier.deriveFraudProofId. */
export function deriveFraudProofId(proposalId: bigint): bigint {
  return BigInt(
    ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(["string", "uint256"], [FRAUD_ID_TAG, proposalId]))
  );
}

/** The over-issue evidenceHash the slash filer MUST use — binds token+operator+epoch. */
export function overIssueEvidenceHash(disputedToken: string, operator: string, epoch: bigint): string {
  return ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["string", "address", "address", "uint256"],
      [OVERISSUE_EVIDENCE_TAG, disputedToken, operator, epoch]
    )
  );
}

export interface OverIssueFraudProofInputs {
  proposalId: bigint;
  operator: string;
  slashLevel: number;
  epoch: bigint;
  disputedToken: string;
  signerMask: bigint;
  /** MUST be the strictly-ascending set from resolveClaimedSigners. */
  claimedSigners: string[];
}

/**
 * Assemble the `fraudProof` bytes the verifier decodes:
 *   abi.encode(uint256 proposalId, address operator, uint8 slashLevel, uint256 epoch,
 *              address disputedToken, uint256 signerMask, address[] claimedSigners)
 */
export function encodeOverIssueFraudProof(i: OverIssueFraudProofInputs): string {
  return ethers.AbiCoder.defaultAbiCoder().encode(
    ["uint256", "address", "uint8", "uint256", "address", "uint256", "address[]"],
    [i.proposalId, i.operator, i.slashLevel, i.epoch, i.disputedToken, i.signerMask, i.claimedSigners]
  );
}
