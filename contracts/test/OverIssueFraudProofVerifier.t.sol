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

contract RevertingToken {
    function isOverIssued() external pure returns (bool) {
        revert("boom");
    }
}

contract OverIssueFraudProofVerifierTest is Test {
    OverIssueFraudProofVerifier internal verifier;
    MockAggregator internal agg;
    MockToken internal token;

    address internal constant S1 = address(0x1111);
    address internal constant S2 = address(0x2222);
    address internal constant S3 = address(0x3333);
    address internal constant OUTSIDER = address(0x9999);

    address internal constant OPERATOR = address(0xABCD);
    uint8 internal constant SLASH_LEVEL = 2; // MAJOR
    uint256 internal constant EPOCH = 1000;
    uint256 internal constant PROPOSAL_ID = 42;
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

    /// records the commitment for a slash over `disputedToken`, using the verifier's own messageHash
    /// reconstruction (so test + contract are guaranteed consistent).
    function _record(address[] memory signers, address disputedToken) internal {
        bytes32 mh = verifier.slashMessageHash(PROPOSAL_ID, OPERATOR, SLASH_LEVEL, EPOCH, disputedToken);
        agg.record(PROPOSAL_ID, mh, SIGNER_MASK, signers);
    }

    function _proof(address[] memory claimedSigners, address disputedToken) internal pure returns (bytes memory) {
        return abi.encode(PROPOSAL_ID, OPERATOR, SLASH_LEVEL, EPOCH, disputedToken, SIGNER_MASK, claimedSigners);
    }

    function _fpid() internal view returns (uint256) {
        return verifier.deriveFraudProofId(PROPOSAL_ID);
    }

    function _g(address a) internal pure returns (address[] memory g) {
        g = new address[](1);
        g[0] = a;
    }

    // ---- happy path -------------------------------------------------------

    function test_HappyPath_ProvenFraud_ReturnsTrue() public {
        _record(_claimed(), address(token));
        token.setOver(false); // NOT over-issued ⇒ the over-issue slash was fraudulent
        assertTrue(verifier.verify(_fpid(), _g(S2), _proof(_claimed(), address(token))));
    }

    function test_HappyPath_MultiGuardianGuilty() public {
        _record(_claimed(), address(token));
        token.setOver(false);
        address[] memory guilty = new address[](2);
        guilty[0] = S1;
        guilty[1] = S3; // ascending subset
        assertTrue(verifier.verify(_fpid(), guilty, _proof(_claimed(), address(token))));
    }

    // ---- CRITICAL regression: disputedToken must be bound to the slash --------

    function test_Reject_TokenSwap_CannotSlashHonestSignersOfARealSlash() public {
        // A real slash cited tokenA (say tokenA IS over-issued → the slash was JUST, signers honest).
        _record(_claimed(), address(token));
        // Attacker keeps the same proposalId/signers/commitment but points at a fresh not-over-issued token.
        MockToken tokenB = new MockToken();
        tokenB.setOver(false);
        assertFalse(verifier.verify(_fpid(), _g(S2), _proof(_claimed(), address(tokenB))));
    }

    // ---- fail-closed negatives -------------------------------------------

    function test_Reject_GuiltyNotSubset_CannotSlashInnocent() public {
        _record(_claimed(), address(token));
        token.setOver(false);
        assertFalse(verifier.verify(_fpid(), _g(OUTSIDER), _proof(_claimed(), address(token))));
    }

    function test_Reject_CommitmentMissing() public {
        token.setOver(false);
        assertFalse(verifier.verify(_fpid(), _g(S2), _proof(_claimed(), address(token))));
    }

    function test_Reject_TamperedClaimedSigners_CommitmentMismatch() public {
        _record(_claimed(), address(token));
        token.setOver(false);
        address[] memory tampered = new address[](2);
        tampered[0] = S1;
        tampered[1] = S3;
        assertFalse(verifier.verify(_fpid(), _g(S1), _proof(tampered, address(token))));
    }

    function test_Reject_StillOverIssued_SlashWasJustified() public {
        _record(_claimed(), address(token));
        token.setOver(true);
        assertFalse(verifier.verify(_fpid(), _g(S2), _proof(_claimed(), address(token))));
    }

    function test_Reject_WrongFraudProofId() public {
        _record(_claimed(), address(token));
        token.setOver(false);
        assertFalse(verifier.verify(_fpid() + 1, _g(S2), _proof(_claimed(), address(token))));
    }

    function test_Reject_ClaimedSignersNotCanonical_Unsorted() public {
        address[] memory unsorted = new address[](3);
        unsorted[0] = S3;
        unsorted[1] = S1;
        unsorted[2] = S2;
        _record(unsorted, address(token));
        token.setOver(false);
        assertFalse(verifier.verify(_fpid(), _g(S1), _proof(unsorted, address(token))));
    }

    function test_Reject_ClaimedSignersHasZero() public {
        address[] memory withZero = new address[](2);
        withZero[0] = address(0);
        withZero[1] = S1;
        _record(withZero, address(token));
        token.setOver(false);
        assertFalse(verifier.verify(_fpid(), _g(S1), _proof(withZero, address(token))));
    }

    function test_Reject_EmptyGuilty() public {
        _record(_claimed(), address(token));
        token.setOver(false);
        assertFalse(verifier.verify(_fpid(), new address[](0), _proof(_claimed(), address(token))));
    }

    function test_Reject_GuiltyNotAscending() public {
        _record(_claimed(), address(token));
        token.setOver(false);
        address[] memory guilty = new address[](2);
        guilty[0] = S3;
        guilty[1] = S1; // descending → rejected
        assertFalse(verifier.verify(_fpid(), guilty, _proof(_claimed(), address(token))));
    }

    // ---- never-revert (fail-closed) --------------------------------------

    function test_MalformedProof_ReturnsFalse_NoRevert() public view {
        bytes memory garbage = hex"deadbeef";
        assertFalse(verifier.verify(_fpid(), _g(S2), garbage));
    }

    function test_MaliciousTokenRevert_ReturnsFalse_NoRevert() public {
        RevertingToken bad = new RevertingToken();
        _record(_claimed(), address(bad));
        // token reverts on isOverIssued() → verify catches → false (not a revert, no slash).
        assertFalse(verifier.verify(_fpid(), _g(S2), _proof(_claimed(), address(bad))));
    }

    // ---- golden vector: Solidity commitment == the TS watcher's (byte-alignment) ----

    function test_Golden_CommitmentByteAlignment_MatchesTS() public {
        // Same fixed vector asserted in src/modules/audit/guardian-fraud-proof.spec.ts.
        // If Solidity abi.encode and ethers abi.encode ever diverge for these types, both break.
        vm.chainId(1);
        address AGG = address(0x0A99);
        address goldToken = address(0xBEEF);
        bytes32 mh = verifier.slashMessageHash(42, OPERATOR, 2, 1000, goldToken);
        assertEq(mh, bytes32(0x593a53c8408d4f89674782c8cf0d3d2b3def99ac442ee6431f64e05965c50a46), "messageHash");

        address[] memory signers = new address[](3);
        signers[0] = S1;
        signers[1] = S2;
        signers[2] = S3;
        bytes32 commitment = keccak256(
            abi.encode("BLS_SIGNERS_COMMITMENT_V1", block.chainid, AGG, uint256(42), mh, uint256(0x7), signers)
        );
        assertEq(commitment, bytes32(0x8c38195124813c84cddbf33daca3efbb3f4718ba43167e6b30550229693f6588), "commitment");
    }

    function test_Check_NotSelfCallable() public {
        // Pre-compute args so vm.expectRevert applies to the check() call, not the view helpers.
        uint256 id = _fpid();
        address[] memory g = _g(S2);
        bytes memory p = _proof(_claimed(), address(token));
        vm.expectRevert(bytes("self only"));
        verifier.check(id, g, p);
    }
}
