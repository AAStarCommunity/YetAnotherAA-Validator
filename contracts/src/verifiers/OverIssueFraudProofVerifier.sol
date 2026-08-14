// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.19;

import {IFraudProofVerifier} from "../interfaces/IFraudProofVerifier.sol";

/// @dev The BLSAggregator's A' commitment getter (SuperPaymaster PR #371).
interface IBLSAggregatorCommitment {
    function proposalSignersCommitment(uint256 proposalId) external view returns (bytes32);
}

/// @dev A community xPNTs token's objective over-issue flag (CC-28).
interface IOverIssuable {
    function isOverIssued() external view returns (bool);
}

/**
 * @title OverIssueFraudProofVerifier
 * @notice CC-89 stage-2, over-issue class. Proves a guardian-collusion slash was fraudulent so
 *         `BLSAggregator.executeGuardianSlash` can slash the colluding guardians' ROLE_DVT stake.
 *
 * A fraud proof is accepted iff ALL hold (fail-closed → `false` otherwise, never revert):
 *   1. `fraudProofId` is the canonical derivation of the disputed `proposalId` (content-bound).
 *   2. `claimedSigners` is canonical: strictly ascending by uint160, non-zero, bounded.
 *   3. `claimedSigners` matches SP's fraud-time A' commitment for `proposalId` (byte-identical recompute).
 *   4. `guiltyGuardians ⊆ claimedSigners` — the commitment proves the SET, not that the accused are
 *      in it; without this, a valid commitment could slash an innocent address.
 *   5. the over-issue the slash cited is FALSE — i.e. the token is not over-issued → the slash was unjust.
 *
 * @dev STAGE / SCOPE. Step 5 reads the disputed token's CURRENT `isOverIssued()`. This is the
 *      **testnet-E2E variant** and is sound ONLY while the token's over-issue state is held constant
 *      between the disputed slash and this proof. The **production** variant must recompute against
 *      the disputed epoch-block state (BLOCKHASH + EIP-1186 storage proof, bounded challenge window)
 *      — the historical-state gap in docs/design/guardian-collusion-slash.md §4b. NOT for mainnet as-is.
 *
 * Skeleton status: logic complete for E2E scope; pending Foundry coverage + Codex review + the
 * three CC-89 alignment points (E2E state-hold, watcher `claimedSigners` byte-alignment, fraudProof format).
 */
contract OverIssueFraudProofVerifier is IFraudProofVerifier {
    /// @notice Domain tag for the deterministic fraudProofId ↔ proposalId binding (step 1).
    string internal constant FRAUD_ID_TAG = "GUARDIAN_FRAUD_V1";
    /// @notice Domain tag SP anchors the signer-set commitment under (must match PR #371 exactly).
    string internal constant SIGNERS_COMMITMENT_TAG = "BLS_SIGNERS_COMMITMENT_V1";
    /// @notice Upper bound on the signer set == BLSAggregator.MAX_VALIDATORS.
    uint256 internal constant MAX_SIGNERS = 13;

    /// @notice The BLSAggregator whose `proposalSignersCommitment` we read AND whose address is
    ///         bound into the commitment (`address(this)` inside SP's `_computeSignersCommitment`).
    ///         The recompute only matches when this equals the aggregator that stored the commitment.
    address public immutable AGGREGATOR;

    constructor(address aggregator) {
        require(aggregator != address(0), "aggregator=0");
        AGGREGATOR = aggregator;
    }

    /// @notice Canonical fraudProofId for a disputed proposal (callers derive the same value).
    function deriveFraudProofId(uint256 proposalId) public pure returns (uint256) {
        return uint256(keccak256(abi.encode(FRAUD_ID_TAG, proposalId)));
    }

    /// @inheritdoc IFraudProofVerifier
    /// @dev fraudProof = abi.encode(
    ///        uint256 proposalId, bytes32 messageHash, uint256 signerMask,
    ///        address[] claimedSigners, address disputedToken)
    function verify(uint256 fraudProofId, address[] calldata guiltyGuardians, bytes calldata fraudProof)
        external
        view
        override
        returns (bool)
    {
        // Malformed proof bytes ⇒ reject (abi.decode reverts are contained by the caller's try/pattern;
        // executeGuardianSlash treats a revert as a failed proof — but we avoid reverting on shape here).
        if (fraudProof.length < 160) return false; // 5 head words minimum

        (
            uint256 proposalId,
            bytes32 messageHash,
            uint256 signerMask,
            address[] memory claimedSigners,
            address disputedToken
        ) = abi.decode(fraudProof, (uint256, bytes32, uint256, address[], address));

        // 1. Content binding: fraudProofId MUST be the canonical derivation of proposalId.
        if (fraudProofId != deriveFraudProofId(proposalId)) return false;

        // 2. claimedSigners canonical: strictly ascending uint160, non-zero, bounded.
        uint256 n = claimedSigners.length;
        if (n == 0 || n > MAX_SIGNERS) return false;
        for (uint256 i = 0; i < n; i++) {
            if (claimedSigners[i] == address(0)) return false;
            if (i > 0 && uint160(claimedSigners[i - 1]) >= uint160(claimedSigners[i])) return false;
        }

        // 3. Commitment check: the claimed set must equal SP's fraud-time snapshot for this proposal.
        bytes32 anchor = IBLSAggregatorCommitment(AGGREGATOR).proposalSignersCommitment(proposalId);
        if (anchor == bytes32(0)) return false; // no such recorded proposal
        bytes32 recomputed = keccak256(
            abi.encode(
                SIGNERS_COMMITMENT_TAG, block.chainid, AGGREGATOR, proposalId, messageHash, signerMask, claimedSigners
            )
        );
        if (recomputed != anchor) return false;

        // 4. Subset: guiltyGuardians ⊆ claimedSigners (both strictly ascending → single merge pass).
        if (!_isSubset(guiltyGuardians, claimedSigners)) return false;

        // 5. Over-issue evidence. E2E variant: current-state read (see contract-level @dev). A `false`
        //    value means the token was not over-issued ⇒ the slash citing over-issue was fraudulent.
        if (IOverIssuable(disputedToken).isOverIssued()) return false;

        return true;
    }

    /// @dev `sub ⊆ set` where BOTH are strictly ascending by uint160. Requires ≥1 accused.
    function _isSubset(address[] calldata sub, address[] memory set) internal pure returns (bool) {
        uint256 m = sub.length;
        if (m == 0) return false;
        uint256 j = 0;
        uint256 len = set.length;
        for (uint256 i = 0; i < m; i++) {
            if (sub[i] == address(0)) return false;
            if (i > 0 && uint160(sub[i - 1]) >= uint160(sub[i])) return false; // sub not canonical
            while (j < len && uint160(set[j]) < uint160(sub[i])) {
                unchecked {
                    j++;
                }
            }
            if (j >= len || set[j] != sub[i]) return false; // sub[i] not present in set
        }
        return true;
    }
}
