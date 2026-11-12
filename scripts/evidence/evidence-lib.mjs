// The on-chain evidence encoding of M0 §3.1, which SP's DVTValidator checks at execute (0.8.0,
// EvidenceHashMismatch). Moved verbatim from scripts/disclosure/recheck-lib.mjs when the
// DisclosureRegistry recheck was retired (DSR 009967e4, 502ccd64; archive tag
// archive/guardian-watcher-w2-2026-11-12): the fraud-proof consumers still depend on it.
import { ethers } from "ethers";

/**
 * The on-chain evidence encoding of M0 §3.1 (DVTValidator checks it at execute: SP 0.8.0,
 * EvidenceHashMismatch). abi.encode throughout, never encodePacked. (For evidenceHash the two
 * coincide, as its inputs are three static bytes32 words; for `evidence` they differ, as `bytes` is
 * dynamic and abi.encode adds its offset and length.)
 *   evidence     = abi.encode(bytes32 category, bytes body)
 *   category     = keccak256("DVT.Evidence.<Name>.v<N>")
 *   evidenceHash = keccak256(abi.encode(TAG_EVIDENCE, category, keccak256(body)))
 * Vectors: contracts/test/fixtures/evidence-vectors.json (gen-evidence-vectors.mjs), asserted by
 * contracts/test/EvidenceHashParity.t.sol.
 */
export const TAG_EVIDENCE = ethers.id("SuperPaymaster.DVT.Evidence.v2");

/** keccak256("DVT.Evidence.<name>.v<version>"); name is letters and digits, version a positive integer. */
export function evidenceCategory(name, version) {
  if (typeof name !== "string" || !/^[A-Za-z][A-Za-z0-9]*$/.test(name))
    throw new Error(`evidence category name must be alphanumeric: ${name}`);
  if (!Number.isSafeInteger(version) || version < 1)
    throw new Error(`evidence category version must be a positive integer: ${version}`);
  return ethers.id(`DVT.Evidence.${name}.v${version}`);
}

const isBytes32 = x => typeof x === "string" && /^0x[0-9a-fA-F]{64}$/.test(x);

/** abi.encode(bytes32 category, bytes body). */
export function encodeEvidence(category, body) {
  if (!isBytes32(category)) throw new Error("evidence category must be bytes32");
  return ethers.AbiCoder.defaultAbiCoder().encode(
    ["bytes32", "bytes"],
    [category, ethers.getBytes(body)]
  );
}

/** The inverse of encodeEvidence: { category, body } (body as 0x hex). */
export function decodeEvidence(evidence) {
  const [category, body] = ethers.AbiCoder.defaultAbiCoder().decode(["bytes32", "bytes"], evidence);
  return { category, body: ethers.hexlify(body) };
}

/** keccak256(abi.encode(TAG_EVIDENCE, category, keccak256(body))). */
export function evidenceHashOf(category, body) {
  if (!isBytes32(category)) throw new Error("evidence category must be bytes32");
  return ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes32", "bytes32", "bytes32"],
      [TAG_EVIDENCE, category, ethers.keccak256(ethers.getBytes(body))]
    )
  );
}
