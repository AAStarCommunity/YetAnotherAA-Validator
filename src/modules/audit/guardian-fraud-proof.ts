import { ethers } from "ethers";
import {
  BlsConsensusDomain,
  executeSlashMessageHash,
  reputationMessageHash,
  signersCommitment,
} from "./bls-consensus-domain.js";

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

/**
 * Decode the `signerMask` from a raw verifyAndExecute BLS `proof`
 * (= `abi.encode(uint256 signerMask, bytes sigG2)`). NOTE: this is the SP-side BLS proof,
 * NOT the verifier's `fraudProof` (which starts with `proposalId`, mask being its 6th field).
 * Only the first 32-byte word is the mask; SP decodes `proof[:32]` likewise.
 */
export function decodeSignerMaskFromBlsProof(proof: string): bigint {
  const [signerMask] = ethers.AbiCoder.defaultAbiCoder().decode(
    ["uint256"],
    ethers.dataSlice(proof, 0, 32)
  );
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
  return orderSignersFromSlotMap(signerMask, slot =>
    agg.validatorAtSlot(slot, { blockTag: executionBlock })
  );
}

/**
 * The pure, testable core of the derivation: given a `signerMask` and an async slot→address
 * resolver (pinned to the execution block), produce the strictly-ascending-by-uint160 signer set
 * that reproduces SP's `_computeSignersCommitment` `sorted` array. Rejects high mask bits, zero
 * slots, and duplicates (never a partial/wrong set).
 */
export async function orderSignersFromSlotMap(
  signerMask: bigint,
  resolveSlot: (slot: number) => Promise<string>
): Promise<string[]> {
  // Reject mask bits beyond MAX_VALIDATORS — SP's _reconstructPkAgg rejects them outright, so a
  // high bit means the mask is wrong; never silently drop it (the fraudProof embeds the raw mask).
  if (signerMask >> BigInt(MAX_VALIDATORS) !== 0n) {
    throw new Error(
      `orderSignersFromSlotMap: signerMask ${signerMask.toString(16)} has bits above slot ${MAX_VALIDATORS}`
    );
  }
  const signers: string[] = [];
  for (let slot = 1; slot <= MAX_VALIDATORS; slot++) {
    if (((signerMask >> BigInt(slot - 1)) & 1n) === 0n) continue;
    const addr = await resolveSlot(slot);
    if (addr === ethers.ZeroAddress) {
      throw new Error(`orderSignersFromSlotMap: slot ${slot} is zero — wrong mask/block?`);
    }
    signers.push(ethers.getAddress(addr));
  }
  // Strictly ascending by uint160(address) — matches SP's uint160 sort (checksum doesn't affect it).
  signers.sort((a, b) => {
    const x = BigInt(a);
    const y = BigInt(b);
    return x < y ? -1 : x > y ? 1 : 0;
  });
  for (let i = 1; i < signers.length; i++) {
    if (BigInt(signers[i - 1]) >= BigInt(signers[i])) {
      throw new Error(`orderSignersFromSlotMap: duplicate/unordered signer ${signers[i]}`);
    }
  }
  return signers;
}

/** Canonical fraudProofId — MUST match verifier.deriveFraudProofId. */
export function deriveFraudProofId(proposalId: bigint): bigint {
  return BigInt(
    ethers.keccak256(
      ethers.AbiCoder.defaultAbiCoder().encode(["string", "uint256"], [FRAUD_ID_TAG, proposalId])
    )
  );
}

/** The over-issue evidenceHash the slash filer MUST use — binds token+operator+epoch. */
export function overIssueEvidenceHash(
  disputedToken: string,
  operator: string,
  epoch: bigint
): string {
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
    [
      i.proposalId,
      i.operator,
      i.slashLevel,
      i.epoch,
      i.disputedToken,
      i.signerMask,
      i.claimedSigners,
    ]
  );
}

/**
 * Reconstruct SP's slash-only `expectedMessageHash` from a RAW evidenceHash — byte-identical to the
 * LIVE BLSAggregator execute-slash branch (:977): `keccak256(abi.encode(domainSeparator,
 * TAG_EXECUTE_SLASH, proposalId, operator, slashLevel, epoch, evidenceHash))`. The domain separator
 * binds chainId+aggregator+Registry, so there is no raw chainId field and no empty rep arrays (the
 * obsolete pre-4.11 shape). The watcher uses this with the evidenceHash it read from the
 * verifyAndExecute calldata — it does NOT need to know which token the slash cited.
 */
export function rawSlashMessageHash(
  domain: BlsConsensusDomain,
  proposalId: bigint,
  operator: string,
  slashLevel: number,
  epoch: bigint,
  evidenceHash: string
): string {
  return executeSlashMessageHash(domain, proposalId, operator, slashLevel, epoch, evidenceHash);
}

/**
 * Reconstruct SP's reputation/combined-path `expectedMessageHash` — byte-identical to the LIVE
 * BLSAggregator reputation branch (:1330): `keccak256(abi.encode(domainSeparator, TAG_REPUTATION,
 * proposalId, users, newScores, epoch))`. The watcher needs this to self-check the commitment for
 * combined proposals; over-issue fraud proofs themselves only target the slash-only branch.
 */
export function repSlashMessageHash(
  domain: BlsConsensusDomain,
  proposalId: bigint,
  _operator: string,
  _slashLevel: number,
  repUsers: string[],
  newScores: bigint[],
  epoch: bigint
): string {
  return reputationMessageHash(domain, proposalId, repUsers, newScores, epoch);
}

/**
 * Reconstruct SP's slash-only `expectedMessageHash` for the OVER-ISSUE class (binds the disputed
 * token via the fixed-preimage evidenceHash). Byte-identical to `verifier.slashMessageHash` — this
 * is what the fraud-proof ASSEMBLER uses when it knows the token; the watcher uses
 * `rawSlashMessageHash` with the on-chain evidenceHash instead.
 */
export function overIssueSlashMessageHash(
  domain: BlsConsensusDomain,
  proposalId: bigint,
  operator: string,
  slashLevel: number,
  epoch: bigint,
  disputedToken: string
): string {
  return rawSlashMessageHash(
    domain,
    proposalId,
    operator,
    slashLevel,
    epoch,
    overIssueEvidenceHash(disputedToken, operator, epoch)
  );
}

/** The exact ABI of BLSAggregator.verifyAndExecute (SP `contracts/src/modules/monitoring/BLSAggregator.sol`). */
export const VERIFY_AND_EXECUTE_ABI =
  "function verifyAndExecute(uint256 proposalId, address operator, uint8 slashLevel, " +
  "address[] repUsers, uint256[] newScores, uint256 epoch, bytes32 evidenceHash, bytes proof)";

export interface VerifyAndExecuteArgs {
  proposalId: bigint;
  operator: string;
  slashLevel: number;
  repUsers: string[];
  newScores: bigint[];
  epoch: bigint;
  evidenceHash: string;
  /** signerMask decoded from proof[:32] (proof = abi.encode(uint256 signerMask, bytes sigG2)). */
  signerMask: bigint;
}

/**
 * Decode a top-level `verifyAndExecute` tx's calldata into the fields the watcher needs to
 * reproduce SP's A' commitment. THROWS if `data` is not a verifyAndExecute call (wrong selector
 * / undecodable) — the caller treats that as "not the direct call I expected" and skips (never
 * records a guessed set). NOTE: this decodes the OUTER call; a proposal executed through an
 * intermediary (e.g. DVT_VALIDATOR wrapping the call) won't decode here — a Phase-3 hardening
 * concern (trace/internal-call resolution), out of scope for the direct-call E2E.
 */
export function decodeVerifyAndExecuteCalldata(data: string): VerifyAndExecuteArgs {
  const iface = new ethers.Interface([VERIFY_AND_EXECUTE_ABI]);
  const parsed = iface.parseTransaction({ data });
  if (!parsed || parsed.name !== "verifyAndExecute") {
    throw new Error("decodeVerifyAndExecuteCalldata: not a verifyAndExecute call");
  }
  const a = parsed.args;
  return {
    proposalId: BigInt(a[0]),
    operator: ethers.getAddress(a[1]),
    slashLevel: Number(a[2]),
    repUsers: [...a[3]].map((x: string) => ethers.getAddress(x)),
    newScores: [...a[4]].map((x: bigint) => BigInt(x)),
    epoch: BigInt(a[5]),
    evidenceHash: a[6],
    signerMask: decodeSignerMaskFromBlsProof(a[7]),
  };
}

/**
 * Recompute SP's A' `proposalSignersCommitment` — byte-identical to the LIVE
 * `_computeSignersCommitment` (:1299): `keccak256(abi.encode(domainSeparator, TAG_SIGNERS_COMMITMENT,
 * proposalId, messageHash, signerMask, signers))`. The watcher can self-check that its assembled
 * proof WILL pass on-chain before submitting. `messageHash` MUST be built with the SAME `domain`.
 */
export function computeSignersCommitment(
  domain: BlsConsensusDomain,
  proposalId: bigint,
  messageHash: string,
  signerMask: bigint,
  claimedSigners: string[]
): string {
  return signersCommitment(domain, proposalId, messageHash, signerMask, claimedSigners);
}
