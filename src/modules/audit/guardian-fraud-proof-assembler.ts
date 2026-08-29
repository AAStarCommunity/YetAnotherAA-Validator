import { ethers } from "ethers";
import {
  encodeOverIssueFraudProof,
  deriveFraudProofId,
  overIssueEvidenceHash,
  MAX_VALIDATORS,
} from "./guardian-fraud-proof.js";
import type { GuardianSignerRecord } from "./guardian-signer-store.js";

/**
 * CC-89 stage-2 F2 — the fraud-proof ASSEMBLER (downstream of the watcher, upstream of
 * `BLSAggregator.queueGuardianSlash` / `executeGuardianSlash`).
 *
 * Given a VERIFIED watcher record (the signer set of a disputed slash), the token that was over-
 * issued, it builds the exact `(fraudProofId, guiltyGuardians, fraudProof)`
 * the on-chain `OverIssueFraudProofVerifier` (PR #223) accepts. It REFUSES to assemble anything the
 * verifier would reject, so a caller never files a proof that reverts / returns false:
 *   - only from a self-VERIFIED record (its claimedSigners reproduce SP's A' commitment),
 *   - `guiltyGuardians` is derived as the exact canonical `claimedSigners` set. The caller cannot
 *     supply a subset: SP consumes each fraudProofId at queue time, so a subset-lenient filing lets
 *     a front-runner slash one signer and permanently immunise the remaining colluders,
 *   - the disputed token BINDS to the slash: `overIssueEvidenceHash(token, operator, epoch)` MUST
 *     equal the record's on-chain `evidenceHash` (else this token isn't what the slash cited → the
 *     verifier's messageHash→commitment recompute won't match → every proof rejected).
 *
 * The assembler is PURE. Queueing and executing are separate, explicitly-armed steps;
 * `preflightVerify` lets a caller confirm the proof passes on-chain BEFORE broadcasting.
 */

export interface AssembledFraudProof {
  /** deriveFraudProofId(proposalId) — the verifier binds this to the disputed proposal. */
  fraudProofId: bigint;
  /** Accused colluders, exactly equal to the record's canonical claimedSigners. */
  guiltyGuardians: string[];
  /** abi-encoded fraudProof bytes the verifier decodes. */
  fraudProof: string;
}

/**
 * Assert the record's `claimedSigners` are already canonical — MIRRORS the verifier's
 * `_canonicalSigners` exactly (non-empty, ≤ MAX_VALIDATORS, non-zero, strictly ascending by uint160,
 * no dup). NOT re-sorted: the encoded array must stay byte-identical to SP's commitment `sorted`, so a
 * non-canonical record is corrupt → throw rather than "fix" it into a mismatching proof.
 */
function assertCanonicalClaimedSigners(claimed: string[]): void {
  if (claimed.length === 0) throw new Error("assembler: record has no claimedSigners");
  if (claimed.length > MAX_VALIDATORS) {
    throw new Error(
      `assembler: claimedSigners length ${claimed.length} exceeds MAX ${MAX_VALIDATORS}`
    );
  }
  for (let i = 0; i < claimed.length; i++) {
    if (claimed[i] === ethers.ZeroAddress) {
      throw new Error("assembler: claimedSigners contains the zero address (corrupt record)");
    }
    if (i > 0 && BigInt(claimed[i - 1]) >= BigInt(claimed[i])) {
      throw new Error(
        `assembler: claimedSigners not strictly ascending at ${claimed[i]} (corrupt record)`
      );
    }
  }
}

/**
 * Build the fraud proof for an over-issue guardian-collusion slash. THROWS if the inputs could not
 * produce an accepted proof (unverified record, token not bound to the slash, or corrupt signer
 * set). `disputedToken` is the community xPNTs the operator over-issued; the caller
 * (detector) supplies it — the record only holds the opaque on-chain evidenceHash.
 */
export function assembleOverIssueFraudProof(
  record: GuardianSignerRecord,
  disputedToken: string
): AssembledFraudProof {
  // Strict === true: a malformed record with commitmentVerified: "false"/"0" (truthy string) must
  // NOT slip past the assembler's most important local safety gate.
  if (record.commitmentVerified !== true) {
    throw new Error(
      `assembler: record for proposal ${record.proposalId} is not self-verified — refusing to assemble`
    );
  }

  const proposalId = BigInt(record.proposalId);
  const operator = ethers.getAddress(record.operator);
  const epoch = BigInt(record.epoch);
  const token = ethers.getAddress(disputedToken);

  // Token binding: the disputed token MUST reproduce the on-chain evidenceHash, else the verifier's
  // evidenceHash→messageHash→commitment recompute won't match (this is the token-swap Critical guard,
  // the assembler's mirror of it — fail early instead of filing a doomed proof).
  const expectedEvidence = overIssueEvidenceHash(token, operator, epoch);
  if (expectedEvidence.toLowerCase() !== record.evidenceHash.toLowerCase()) {
    throw new Error(
      `assembler: disputedToken ${token} does not bind to proposal ${record.proposalId}'s slash ` +
        `(evidenceHash ${expectedEvidence} != on-chain ${record.evidenceHash})`
    );
  }

  const claimed = record.claimedSigners.map(a => ethers.getAddress(a));
  // Defense-in-depth: the watcher only stores canonical sets, but never trust a possibly-corrupted
  // record — re-assert exactly what the on-chain verifier requires before encoding.
  assertCanonicalClaimedSigners(claimed);
  // SET-EXACT is load-bearing. Derive rather than accept this list from a caller, so the
  // off-chain filing path cannot re-introduce the subset front-run fixed in the verifier.
  const guilty = [...claimed];

  const fraudProof = encodeOverIssueFraudProof({
    proposalId,
    operator,
    slashLevel: record.slashLevel,
    epoch,
    disputedToken: token,
    signerMask: BigInt(record.signerMask),
    claimedSigners: claimed,
  });

  return { fraudProofId: deriveFraudProofId(proposalId), guiltyGuardians: guilty, fraudProof };
}

/** SP 4.11 verifier seam plus the two-step guardian-slash lifecycle. */
const VERIFIER_ABI = [
  "function verify(bytes32 domainDigest, uint256 fraudProofId, address[] guiltyGuardians, bytes fraudProof) view returns (bool)",
];
const AGGREGATOR_SLASH_ABI = [
  "function fraudProofDigest(uint256 fraudProofId, address[] guiltyGuardians) view returns (bytes32)",
  "function queueGuardianSlash(uint256 fraudProofId, address[] guiltyGuardians, bytes fraudProof)",
  "function executeGuardianSlash(uint256 fraudProofId, address[] guiltyGuardians, bytes fraudProof)",
];

/**
 * Preflight: staticcall the on-chain verifier so a caller confirms the proof WILL be accepted before
 * broadcasting `queueGuardianSlash`. Returns the verifier's boolean; never throws on a `false`
 * (the verifier is fail-closed and returns false rather than reverting), only on RPC failure.
 */
export async function preflightVerify(
  provider: ethers.Provider,
  verifierAddress: string,
  aggregatorAddress: string,
  assembled: AssembledFraudProof
): Promise<boolean> {
  const aggregator = new ethers.Contract(aggregatorAddress, AGGREGATOR_SLASH_ABI, provider);
  const domainDigest: string = await aggregator.fraudProofDigest(
    assembled.fraudProofId,
    assembled.guiltyGuardians
  );
  const verifier = new ethers.Contract(verifierAddress, VERIFIER_ABI, provider);
  return verifier.verify(
    domainDigest,
    assembled.fraudProofId,
    assembled.guiltyGuardians,
    assembled.fraudProof
  );
}

/**
 * Queue a verifier-approved case (ARMED — freezes the exact guilty set's ROLE_DVT exits).
 * Callers should `preflightVerify` first. Permissionless at the contract: the verifier verdict,
 * not caller identity, authorises the case. Returns the queue transaction hash.
 */
export async function queueGuardianSlash(
  signer: ethers.Signer,
  aggregatorAddress: string,
  assembled: AssembledFraudProof
): Promise<string> {
  const agg = new ethers.Contract(aggregatorAddress, AGGREGATOR_SLASH_ABI, signer);
  const tx = await agg.queueGuardianSlash(
    assembled.fraudProofId,
    assembled.guiltyGuardians,
    assembled.fraudProof
  );
  return tx.hash;
}

/** Execute an already queued case (ARMED — slashes the exact guilty set's full ROLE_DVT locks). */
export async function executeGuardianSlash(
  signer: ethers.Signer,
  aggregatorAddress: string,
  assembled: AssembledFraudProof
): Promise<string> {
  const agg = new ethers.Contract(aggregatorAddress, AGGREGATOR_SLASH_ABI, signer);
  const tx = await agg.executeGuardianSlash(
    assembled.fraudProofId,
    assembled.guiltyGuardians,
    assembled.fraudProof
  );
  return tx.hash;
}
