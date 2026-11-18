// Plain-ESM (ethers-only) mirror of the SP 4.11 BLS-consensus encoding, so the cc89-cosign.mjs CLI
// does NOT duplicate the domain/tag/layout constants inline. The TypeScript source of truth is
// src/modules/audit/bls-consensus-domain.ts; this module reproduces the SAME layout for the plain
// Node script, and bls-consensus-encoding.spec.ts pins the two together on the golden vector so a
// drift in either fails CI. Keep this in lock-step with the .ts helper.
import { ethers } from "ethers";
import { evidenceCategory, evidenceHashOf } from "../evidence/evidence-lib.mjs";

const ABI = ethers.AbiCoder.defaultAbiCoder();

export const DOMAIN_NAME = ethers.id("SuperPaymaster.BLSConsensus.v1");
export const TAG_EXECUTE_SLASH = ethers.id("SuperPaymaster.BLS.ExecuteSlash.v1");
export const TAG_SIGNERS_COMMITMENT = ethers.id("SuperPaymaster.BLS.SignersCommitment.v1");
/** keccak256("DVT.Evidence.OverIssue.v1"): proposal, not finalized (DSR 2026-11-17). */
export const OVERISSUE_CATEGORY = evidenceCategory("OverIssue", 1);

/** BLSAggregator.domainSeparator() (:255). `d = { chainId, aggregator, registry }`. */
export function domainSeparator(d) {
  return ethers.keccak256(
    ABI.encode(
      ["bytes32", "uint256", "address", "address"],
      [DOMAIN_NAME, d.chainId, ethers.getAddress(d.aggregator), ethers.getAddress(d.registry)]
    )
  );
}

/** Execute (slash-only) message pre-image (BLSAggregator.sol:977). */
export function executeSlashMessageHash(d, proposalId, operator, slashLevel, epoch, evidenceHash) {
  return ethers.keccak256(
    ABI.encode(
      ["bytes32", "bytes32", "uint256", "address", "uint8", "uint256", "bytes32"],
      [domainSeparator(d), TAG_EXECUTE_SLASH, proposalId, operator, slashLevel, epoch, evidenceHash]
    )
  );
}

/** Over-issue evidenceHash under the M0 §3.1 category rule; body = abi.encode(token, operator, epoch). */
export function overIssueEvidenceHash(token, operator, epoch) {
  const body = ABI.encode(
    ["address", "address", "uint256"],
    [ethers.getAddress(token), ethers.getAddress(operator), epoch]
  );
  return evidenceHashOf(OVERISSUE_CATEGORY, body);
}
