// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.19;

/**
 * @title IFraudProofVerifier
 * @notice The seam BLSAggregator.executeGuardianSlash (SuperPaymaster PR #370) plugs into.
 *         SP trusts only an owner-set verifier and never judges fraud itself: it slashes the
 *         addresses in `guiltyGuardians` iff `verify(...)` returns true. Correctness of "are
 *         these guardians truly guilty" is entirely the verifier's job (CC-89 A').
 *
 * @dev    `view` — the fraud proof must reduce to on-chain-checkable facts (see
 *         docs/design/guardian-collusion-slash.md §4b). MUST fail-closed: any malformed input,
 *         missing/mismatched signer-set commitment, non-subset accusation, or unproven fraud
 *         returns `false` (never revert on a rejected proof — a revert would let the caller
 *         distinguish rejection reasons and grief the permissionless entry).
 */
interface IFraudProofVerifier {
    /// @param fraudProofId    Replay-guard key (SP-side, per (proof,guardian)); the verifier binds it
    ///                        to the disputed content so a valid proof can't be filed under an unrelated id.
    /// @param guiltyGuardians Addresses the caller wants slashed — the verifier MUST prove
    ///                        `guiltyGuardians ⊆ claimedSigners` or a valid commitment could slash innocents.
    /// @param fraudProof      Opaque proof bytes, decoded and interpreted solely by the verifier.
    /// @return ok             true iff the slash of `guiltyGuardians` is proven fraudulent-collusion.
    function verify(uint256 fraudProofId, address[] calldata guiltyGuardians, bytes calldata fraudProof)
        external
        view
        returns (bool ok);
}
