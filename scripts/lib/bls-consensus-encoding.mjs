// Plain-ESM (ethers-only) mirror of the SP 4.11 BLS-consensus encoding, so the cc89-cosign.mjs CLI
// does NOT duplicate the domain/tag/layout constants inline. The TypeScript source of truth is
// src/modules/audit/bls-consensus-domain.ts; this module reproduces the SAME layout for the plain
// Node script, and bls-consensus-encoding.spec.ts pins the two together on the golden vector so a
// drift in either fails CI. Keep this in lock-step with the .ts helper.
import { ethers } from "ethers";

const ABI = ethers.AbiCoder.defaultAbiCoder();

export const DOMAIN_NAME = ethers.id("SuperPaymaster.BLSConsensus.v1");
export const TAG_EXECUTE_SLASH = ethers.id("SuperPaymaster.BLS.ExecuteSlash.v1");
export const TAG_SIGNERS_COMMITMENT = ethers.id("SuperPaymaster.BLS.SignersCommitment.v1");
export const OVERISSUE_EVIDENCE_TAG = "DVT_OVERISSUE_EVIDENCE_V1";

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

/** Over-issue evidenceHash (DVT convention) — binds token/operator/epoch. */
export function overIssueEvidenceHash(token, operator, epoch) {
  return ethers.keccak256(
    ABI.encode(
      ["string", "address", "address", "uint256"],
      [OVERISSUE_EVIDENCE_TAG, ethers.getAddress(token), ethers.getAddress(operator), epoch]
    )
  );
}
