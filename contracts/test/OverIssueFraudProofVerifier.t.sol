// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.19;

import {Test} from "forge-std/Test.sol";
import {OverIssueFraudProofVerifier} from "../src/verifiers/OverIssueFraudProofVerifier.sol";

/// @dev Mirrors SuperPaymaster BLSAggregator's A' commitment (PR #371). `signers` MUST be pre-sorted
///      ascending by uint160 — identical encoding to `_computeSignersCommitment`, keyed on address(this).
contract MockAggregator {
    mapping(uint256 => bytes32) public proposalSignersCommitment;

    function record(uint256 proposalId, bytes32 messageHash, uint256 signerMask, address[] memory sortedSigners)
        external
    {
        proposalSignersCommitment[proposalId] = keccak256(
            abi.encode(
                "BLS_SIGNERS_COMMITMENT_V1",
                block.chainid,
                address(this),
                proposalId,
                messageHash,
                signerMask,
                sortedSigners
            )
        );
    }
}

contract MockToken {
    bool public over;

    function setOver(bool v) external {
        over = v;
    }

    function isOverIssued() external view returns (bool) {
        return over;
    }
}

contract OverIssueFraudProofVerifierTest is Test {
    OverIssueFraudProofVerifier internal verifier;
    MockAggregator internal agg;
    MockToken internal token;

    // Ascending-by-uint160 signer set (numeric order == uint160 order for these).
    address internal constant S1 = address(0x1111);
    address internal constant S2 = address(0x2222);
    address internal constant S3 = address(0x3333);
    address internal constant OUTSIDER = address(0x9999);

    uint256 internal constant PROPOSAL_ID = 42;
    bytes32 internal constant MESSAGE_HASH = keccak256("msg");
    uint256 internal constant SIGNER_MASK = 0x7; // bits 1,2,3

    function setUp() public {
        agg = new MockAggregator();
        token = new MockToken();
        verifier = new OverIssueFraudProofVerifier(address(agg));
    }

    // ---- helpers ----------------------------------------------------------

    function _claimed() internal pure returns (address[] memory a) {
        a = new address[](3);
        a[0] = S1;
        a[1] = S2;
        a[2] = S3;
    }

    function _recordCommitment(address[] memory signers) internal {
        agg.record(PROPOSAL_ID, MESSAGE_HASH, SIGNER_MASK, signers);
    }

    function _fraudProof(address[] memory claimedSigners) internal view returns (bytes memory) {
        return abi.encode(PROPOSAL_ID, MESSAGE_HASH, SIGNER_MASK, claimedSigners, address(token));
    }

    function _fpid() internal view returns (uint256) {
        return verifier.deriveFraudProofId(PROPOSAL_ID);
    }

    function _guilty(address one) internal pure returns (address[] memory g) {
        g = new address[](1);
        g[0] = one;
    }

    // ---- happy path -------------------------------------------------------

    function test_HappyPath_ProvenFraud_ReturnsTrue() public {
        _recordCommitment(_claimed());
        token.setOver(false); // NOT over-issued ⇒ the over-issue slash was fraudulent
        assertTrue(verifier.verify(_fpid(), _guilty(S2), _fraudProof(_claimed())));
    }

    // ---- fail-closed negatives -------------------------------------------

    function test_Reject_GuiltyNotSubset_CannotSlashInnocent() public {
        _recordCommitment(_claimed());
        token.setOver(false);
        // OUTSIDER co-signed nothing; a valid commitment must not let it be slashed.
        assertFalse(verifier.verify(_fpid(), _guilty(OUTSIDER), _fraudProof(_claimed())));
    }

    function test_Reject_CommitmentMissing() public {
        // no agg.record(...)
        token.setOver(false);
        assertFalse(verifier.verify(_fpid(), _guilty(S2), _fraudProof(_claimed())));
    }

    function test_Reject_TamperedClaimedSigners_CommitmentMismatch() public {
        _recordCommitment(_claimed());
        token.setOver(false);
        // Present a different (but canonical) set than the one committed.
        address[] memory tampered = new address[](2);
        tampered[0] = S1;
        tampered[1] = S3;
        assertFalse(verifier.verify(_fpid(), _guilty(S1), _fraudProof(tampered)));
    }

    function test_Reject_StillOverIssued_SlashWasJustified() public {
        _recordCommitment(_claimed());
        token.setOver(true); // still over-issued ⇒ slash justified ⇒ not fraud
        assertFalse(verifier.verify(_fpid(), _guilty(S2), _fraudProof(_claimed())));
    }

    function test_Reject_WrongFraudProofId() public {
        _recordCommitment(_claimed());
        token.setOver(false);
        assertFalse(verifier.verify(_fpid() + 1, _guilty(S2), _fraudProof(_claimed())));
    }

    function test_Reject_ClaimedSignersNotCanonical_Unsorted() public {
        address[] memory unsorted = new address[](3);
        unsorted[0] = S3;
        unsorted[1] = S1;
        unsorted[2] = S2;
        _recordCommitment(unsorted); // commitment over the unsorted set...
        token.setOver(false);
        // verifier rejects non-canonical claimedSigners regardless of commitment match.
        assertFalse(verifier.verify(_fpid(), _guilty(S1), _fraudProof(unsorted)));
    }

    function test_Reject_ClaimedSignersHasZero() public {
        address[] memory withZero = new address[](2);
        withZero[0] = address(0);
        withZero[1] = S1;
        _recordCommitment(withZero);
        token.setOver(false);
        assertFalse(verifier.verify(_fpid(), _guilty(S1), _fraudProof(withZero)));
    }

    // TODO(stage-2): multi-guardian guilty subset; empty guilty; guilty not ascending;
    // fuzz over signer sets; historical-state (production) variant once challenge-window lands.
}
