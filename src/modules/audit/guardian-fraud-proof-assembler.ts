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
 * `BLSAggregator.executeGuardianSlash`).
 *
 * Given a VERIFIED watcher record (the signer set of a disputed slash), the token that was over-
 * issued, and the accused colluders, it builds the exact `(fraudProofId, guiltyGuardians, fraudProof)`
 * the on-chain `OverIssueFraudProofVerifier` (PR #223) accepts. It REFUSES to assemble anything the
 * verifier would reject, so a caller never files a proof that reverts / returns false:
 *   - only from a self-VERIFIED record (its claimedSigners reproduce SP's A' commitment),
 *   - `guiltyGuardians` non-empty, canonical (strictly ascending uint160), ⊆ `claimedSigners`
 *     (the verifier's subset check — without it a valid commitment could slash an innocent address),
 *   - the disputed token BINDS to the slash: `overIssueEvidenceHash(token, operator, epoch)` MUST
 *     equal the record's on-chain `evidenceHash` (else this token isn't what the slash cited → the
 *     verifier's messageHash→commitment recompute won't match → every proof rejected).
 *
 * The assembler is PURE. Submitting is a separate, explicitly-armed step (`submitGuardianSlash`);
 * `preflightVerify` lets a caller confirm the proof passes on-chain BEFORE broadcasting.
 */

export interface AssembledFraudProof {
  /** deriveFraudProofId(proposalId) — the verifier binds this to the disputed proposal. */
  fraudProofId: bigint;
  /** Accused colluders, strictly ascending uint160, ⊆ claimedSigners. */
  guiltyGuardians: string[];
  /** abi-encoded fraudProof bytes the verifier decodes. */
  fraudProof: string;
}

/** Sorted-ascending, deduped, non-zero copy of `addrs`; throws on a zero address. */
function canonicalize(addrs: string[]): string[] {
  const norm = addrs.map(a => ethers.getAddress(a));
  for (const a of norm) {
    if (a === ethers.ZeroAddress)
      throw new Error("assembler: guiltyGuardians contains the zero address");
  }
  const sorted = [...norm].sort((a, b) => {
    const x = BigInt(a);
    const y = BigInt(b);
    return x < y ? -1 : x > y ? 1 : 0;
  });
  for (let i = 1; i < sorted.length; i++) {
    if (BigInt(sorted[i - 1]) >= BigInt(sorted[i])) {
      throw new Error(`assembler: duplicate guilty guardian ${sorted[i]}`);
    }
  }
  return sorted;
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
 * produce an accepted proof (unverified record, token not bound to the slash, guilty set not a
 * canonical subset). `disputedToken` is the community xPNTs the operator over-issued; the caller
 * (detector) supplies it — the record only holds the opaque on-chain evidenceHash.
 */
export function assembleOverIssueFraudProof(
  record: GuardianSignerRecord,
  disputedToken: string,
  guiltyGuardians: string[]
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
  const guilty = canonicalize(guiltyGuardians);
  if (guilty.length === 0) throw new Error("assembler: guiltyGuardians is empty");
  if (guilty.length > claimed.length) {
    throw new Error("assembler: more guilty guardians than signers — cannot be a subset");
  }
  const claimedSet = new Set(claimed.map(a => a.toLowerCase()));
  for (const g of guilty) {
    if (!claimedSet.has(g.toLowerCase())) {
      throw new Error(
        `assembler: guilty guardian ${g} is not among the slash's signers (not a subset)`
      );
    }
  }

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

/** Minimal verifier ABI (staticcall preflight) + aggregator submit ABI. */
const VERIFIER_ABI = [
  "function verify(uint256 fraudProofId, address[] guiltyGuardians, bytes fraudProof) view returns (bool)",
];
const AGGREGATOR_SLASH_ABI = [
  "function executeGuardianSlash(uint256 fraudProofId, address[] guiltyGuardians, bytes fraudProof)",
];

/**
 * Preflight: staticcall the on-chain verifier so a caller confirms the proof WILL be accepted before
 * broadcasting `executeGuardianSlash`. Returns the verifier's boolean; never throws on a `false`
 * (the verifier is fail-closed and returns false rather than reverting), only on RPC failure.
 */
export async function preflightVerify(
  provider: ethers.Provider,
  verifierAddress: string,
  assembled: AssembledFraudProof
): Promise<boolean> {
  const verifier = new ethers.Contract(verifierAddress, VERIFIER_ABI, provider);
  return verifier.verify(assembled.fraudProofId, assembled.guiltyGuardians, assembled.fraudProof);
}

/**
 * Submit `executeGuardianSlash` (ARMED — broadcasts a tx that slashes the guilty guardians' ROLE_DVT
 * stake). Callers should `preflightVerify` first. Permissionless at the contract (the verifier's
 * boolean authorizes, not the sender), so any funded signer can file. Returns the tx hash.
 */
export async function submitGuardianSlash(
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
