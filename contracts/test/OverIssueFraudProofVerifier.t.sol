// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.19;

import {Test} from "forge-std/Test.sol";
import {OverIssueFraudProofVerifier} from "../src/verifiers/OverIssueFraudProofVerifier.sol";
import {IFraudProofVerifier} from "../src/interfaces/IFraudProofVerifier.sol";
import {FraudProofVerifierConformance as Conformance} from "./helpers/FraudProofVerifierConformance.sol";

/// @dev Mirrors SuperPaymaster BLSAggregator (ABI ≥ 4.7.0) for the two things the DVT verifier reads:
///      (a) the A' signer-set commitment (PR #371), and (b) the CC-48 domain-separated
///      `fraudProofDigest` SP passes as `domainDigest`. Both encodings are byte-for-byte copies of
///      SuperPaymaster contracts/src/modules/monitoring/BLSAggregator.sol (lines 238,248,255,265 +
///      _computeSignersCommitment). `signers` MUST be pre-sorted ascending by uint160.
contract MockAggregator {
    mapping(uint256 => bytes32) public proposalSignersCommitment;

    /// @notice Fourth field of the BLS-consensus domain separator. Set at construction so two mock
    ///         aggregators can share a Registry (the hardest replay case: same chain, same Registry,
    ///         different contract address).
    address public immutable REGISTRY;

    bytes32 internal constant DOMAIN_NAME = keccak256("SuperPaymaster.BLSConsensus.v1");
    bytes32 internal constant TAG_FRAUD_PROOF = keccak256("SuperPaymaster.BLS.FraudProof.v1");

    constructor(address registry) {
        REGISTRY = registry;
    }

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

    function domainSeparator() public view returns (bytes32) {
        return keccak256(abi.encode(DOMAIN_NAME, block.chainid, address(this), REGISTRY));
    }

    /// @notice The exact value SP hands to `IFraudProofVerifier.verify` as `domainDigest`.
    function fraudProofDigest(uint256 fraudProofId, address[] calldata guiltyGuardians)
        external
        view
        returns (bytes32)
    {
        return keccak256(abi.encode(domainSeparator(), TAG_FRAUD_PROOF, fraudProofId, guiltyGuardians));
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

    address internal constant REGISTRY = address(0x5E6157); // shared Registry for the aggregator + verifier
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
        agg = new MockAggregator(REGISTRY);
        token = new MockToken();
        verifier = new OverIssueFraudProofVerifier(address(agg), REGISTRY);
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

    /// The domainDigest SP would pass: the bound aggregator's fraudProofDigest over (id, guilty).
    function _digest(uint256 fpid, address[] memory guilty) internal view returns (bytes32) {
        return agg.fraudProofDigest(fpid, guilty);
    }

    // ---- (1) happy path ---------------------------------------------------

    function test_HappyPath_ProvenFraud_ReturnsTrue() public {
        _record(_claimed(), address(token));
        token.setOver(false); // NOT over-issued ⇒ the over-issue slash was fraudulent
        address[] memory guilty = _claimed(); // SET-EXACT: the whole signer set colluded
        assertTrue(verifier.verify(_digest(_fpid(), guilty), _fpid(), guilty, _proof(_claimed(), address(token))));
    }

    /// The verifier's reconstructed digest is byte-identical to the aggregator's — the conformance
    /// property the deploy script also asserts.
    function test_DomainDigest_MatchesAggregatorByteForByte() public view {
        address[] memory guilty = _claimed();
        assertEq(verifier.expectedFraudProofDigest(_fpid(), guilty), agg.fraudProofDigest(_fpid(), guilty));
    }

    // ---- (2) wrong-domain rejected ---------------------------------------

    function test_Reject_WrongDomainDigest_Arbitrary() public {
        _record(_claimed(), address(token));
        token.setOver(false);
        address[] memory guilty = _claimed();
        bytes32 bogus = keccak256("not any aggregator's digest");
        assertFalse(verifier.verify(bogus, _fpid(), guilty, _proof(_claimed(), address(token))));
    }

    function test_Reject_ZeroDomainDigest() public {
        _record(_claimed(), address(token));
        token.setOver(false);
        address[] memory guilty = _claimed();
        assertFalse(verifier.verify(bytes32(0), _fpid(), guilty, _proof(_claimed(), address(token))));
    }

    // ---- (3) cross-chain / aggregator / registry replay rejected ---------

    /// Same (id, guardians, proof) but the digest was built for a DIFFERENT aggregator on the same
    /// chain and Registry — the hardest replay case (an experiment stack onto production).
    function test_Reject_CrossAggregatorReplay() public {
        _record(_claimed(), address(token));
        token.setOver(false);
        address[] memory guilty = _claimed();
        MockAggregator aggB = new MockAggregator(REGISTRY); // same chain, same Registry, diff address
        bytes32 foreignDigest = aggB.fraudProofDigest(_fpid(), guilty);
        assertFalse(verifier.verify(foreignDigest, _fpid(), guilty, _proof(_claimed(), address(token))));
    }

    /// A digest captured on chain A does not authorize a case after a fork to chain B.
    function test_Reject_CrossChainReplay() public {
        vm.chainId(11155111);
        _record(_claimed(), address(token));
        token.setOver(false);
        address[] memory guilty = _claimed();
        bytes32 digestOnSepolia = agg.fraudProofDigest(_fpid(), guilty);
        vm.chainId(1); // mainnet fork: block.chainid enters both the domain digest AND the commitment
        assertFalse(verifier.verify(digestOnSepolia, _fpid(), guilty, _proof(_claimed(), address(token))));
    }

    /// A digest built for an aggregator wired to a DIFFERENT Registry is refused (Registry is the
    /// fourth domain-separator field). Constructed directly so only the Registry field varies.
    function test_Reject_CrossRegistryReplay() public {
        _record(_claimed(), address(token));
        token.setOver(false);
        address[] memory guilty = _claimed();
        address foreignRegistry = address(0xBAD0);
        bytes32 foreignSeparator =
            keccak256(abi.encode(keccak256("SuperPaymaster.BLSConsensus.v1"), block.chainid, address(agg), foreignRegistry));
        bytes32 foreignDigest = keccak256(
            abi.encode(foreignSeparator, keccak256("SuperPaymaster.BLS.FraudProof.v1"), _fpid(), guilty)
        );
        assertFalse(verifier.verify(foreignDigest, _fpid(), guilty, _proof(_claimed(), address(token))));
    }

    // ---- (4) guiltyGuardians set manipulation -----------------------------
    // SET-EXACT (CC-115 B1): the accused set must EQUAL the committed signer set. This supersedes the
    // pre-existing subset-lenient `⊆` rule, which SP's assertSetBound rejects as the CC-48 round-5
    // front-run-and-shrink vector (see the verifier contract's SET-EXACT @dev). Each perturbed set is
    // handed its OWN correct domainDigest, so these fail on the set gate, not the domain gate.

    function test_Reject_Subset_ShrunkBlame() public {
        _record(_claimed(), address(token));
        token.setOver(false);
        address[] memory subset = new address[](2); // dropped S3 — the exact front-run
        subset[0] = S1;
        subset[1] = S2;
        assertFalse(verifier.verify(_digest(_fpid(), subset), _fpid(), subset, _proof(_claimed(), address(token))));
    }

    function test_Reject_Superset_ExtraAddress() public {
        _record(_claimed(), address(token));
        token.setOver(false);
        address[] memory superset = new address[](4);
        superset[0] = S1;
        superset[1] = S2;
        superset[2] = S3;
        superset[3] = address(0x4444); // an address the evidence never named
        assertFalse(verifier.verify(_digest(_fpid(), superset), _fpid(), superset, _proof(_claimed(), address(token))));
    }

    function test_Reject_Reordered_NonAscending() public {
        _record(_claimed(), address(token));
        token.setOver(false);
        address[] memory reordered = new address[](3);
        reordered[0] = S3;
        reordered[1] = S1;
        reordered[2] = S2;
        assertFalse(
            verifier.verify(_digest(_fpid(), reordered), _fpid(), reordered, _proof(_claimed(), address(token)))
        );
    }

    function test_Reject_Duplicate() public {
        _record(_claimed(), address(token));
        token.setOver(false);
        address[] memory dup = new address[](3);
        dup[0] = S1;
        dup[1] = S2;
        dup[2] = S2; // duplicate, not S3
        assertFalse(verifier.verify(_digest(_fpid(), dup), _fpid(), dup, _proof(_claimed(), address(token))));
    }

    function test_Reject_UnrelatedSet() public {
        _record(_claimed(), address(token));
        token.setOver(false);
        address[] memory unrelated = new address[](3);
        unrelated[0] = address(0xA1);
        unrelated[1] = address(0xB2);
        unrelated[2] = address(0xC3);
        assertFalse(
            verifier.verify(_digest(_fpid(), unrelated), _fpid(), unrelated, _proof(_claimed(), address(token)))
        );
    }

    // ---- CRITICAL regression: disputedToken must be bound to the slash --------

    function test_Reject_TokenSwap_CannotSlashHonestSignersOfARealSlash() public {
        _record(_claimed(), address(token));
        MockToken tokenB = new MockToken();
        tokenB.setOver(false);
        address[] memory guilty = _claimed();
        assertFalse(verifier.verify(_digest(_fpid(), guilty), _fpid(), guilty, _proof(_claimed(), address(tokenB))));
    }

    // ---- fail-closed negatives (content/commitment/evidence) -------------

    function test_Reject_CommitmentMissing() public {
        token.setOver(false);
        address[] memory guilty = _claimed();
        assertFalse(verifier.verify(_digest(_fpid(), guilty), _fpid(), guilty, _proof(_claimed(), address(token))));
    }

    function test_Reject_TamperedClaimedSigners_CommitmentMismatch() public {
        _record(_claimed(), address(token));
        token.setOver(false);
        address[] memory tampered = new address[](2);
        tampered[0] = S1;
        tampered[1] = S3;
        // guilty must equal claimedSigners-in-proof to reach the commitment gate; both are `tampered`.
        assertFalse(
            verifier.verify(_digest(_fpid(), tampered), _fpid(), tampered, _proof(tampered, address(token)))
        );
    }

    function test_Reject_StillOverIssued_SlashWasJustified() public {
        _record(_claimed(), address(token));
        token.setOver(true);
        address[] memory guilty = _claimed();
        assertFalse(verifier.verify(_digest(_fpid(), guilty), _fpid(), guilty, _proof(_claimed(), address(token))));
    }

    function test_Reject_WrongFraudProofId() public {
        _record(_claimed(), address(token));
        token.setOver(false);
        address[] memory guilty = _claimed();
        uint256 wrong = _fpid() + 1;
        // Digest must match the (wrong) id passed, else it fails on the domain gate instead of the id gate.
        assertFalse(verifier.verify(_digest(wrong, guilty), wrong, guilty, _proof(_claimed(), address(token))));
    }

    function test_Reject_ClaimedSignersNotCanonical_Unsorted() public {
        address[] memory unsorted = new address[](3);
        unsorted[0] = S3;
        unsorted[1] = S1;
        unsorted[2] = S2;
        _record(unsorted, address(token));
        token.setOver(false);
        assertFalse(
            verifier.verify(_digest(_fpid(), unsorted), _fpid(), unsorted, _proof(unsorted, address(token)))
        );
    }

    function test_Reject_ClaimedSignersHasZero() public {
        address[] memory withZero = new address[](2);
        withZero[0] = address(0);
        withZero[1] = S1;
        _record(withZero, address(token));
        token.setOver(false);
        assertFalse(
            verifier.verify(_digest(_fpid(), withZero), _fpid(), withZero, _proof(withZero, address(token)))
        );
    }

    function test_Reject_EmptyGuilty() public {
        _record(_claimed(), address(token));
        token.setOver(false);
        address[] memory empty = new address[](0);
        assertFalse(verifier.verify(_digest(_fpid(), empty), _fpid(), empty, _proof(_claimed(), address(token))));
    }

    // ---- never-revert (fail-closed) --------------------------------------

    function test_MalformedProof_ReturnsFalse_NoRevert() public {
        address[] memory guilty = _claimed();
        bytes memory garbage = hex"deadbeef";
        // Correct domain digest, but the proof bytes don't decode → catch → false (no revert).
        assertFalse(verifier.verify(_digest(_fpid(), guilty), _fpid(), guilty, garbage));
    }

    function test_MaliciousTokenRevert_ReturnsFalse_NoRevert() public {
        RevertingToken bad = new RevertingToken();
        _record(_claimed(), address(bad));
        address[] memory guilty = _claimed();
        assertFalse(verifier.verify(_digest(_fpid(), guilty), _fpid(), guilty, _proof(_claimed(), address(bad))));
    }

    // ---- (5) old 3-param selector is gone --------------------------------

    function test_Selector_Is_0x61077735() public pure {
        assertEq(IFraudProofVerifier.verify.selector, bytes4(0x61077735), "new 4-param selector");
    }

    function test_OldSelector_IsNotTheNewOne() public pure {
        bytes4 oldSel = bytes4(keccak256(bytes("verify(uint256,address[],bytes)")));
        assertEq(oldSel, bytes4(0x05579e4d), "documented old 3-param selector");
        assertTrue(oldSel != IFraudProofVerifier.verify.selector, "old selector must differ from new");
    }

    /// The 3-param ABI is not callable on the deployed verifier: no function matches that selector and
    /// there is no fallback, so the call reverts (staticcall ok == false).
    function test_OldSelector_NotCallable_OnVerifier() public {
        bytes memory oldCalldata = abi.encodeWithSelector(
            bytes4(keccak256(bytes("verify(uint256,address[],bytes)"))),
            _fpid(),
            _claimed(),
            _proof(_claimed(), address(token))
        );
        (bool ok,) = address(verifier).staticcall(oldCalldata);
        assertFalse(ok, "old 3-param verify must not be callable");
    }

    // ---- golden vector: Solidity commitment == the TS watcher's (byte-alignment) ----

    function test_Golden_CommitmentByteAlignment_MatchesTS() public {
        // Same fixed vector asserted in src/modules/audit/guardian-fraud-proof.spec.ts.
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
        uint256 id = _fpid();
        address[] memory g = _claimed();
        bytes memory p = _proof(_claimed(), address(token));
        bytes32 d = _digest(id, g);
        vm.expectRevert(bytes("self only"));
        verifier.check(d, id, g, p);
    }
}

// =====================================================================
// (6) SP conformance — ported FraudProofVerifierConformance fixture
// =====================================================================

/// @dev Runs the DVT verifier against BOTH release gates of SuperPaymaster's real conformance
///      fixture (documented port in test/helpers/FraudProofVerifierConformance.sol):
///        - assertDomainBound: accepts its own domain, rejects a foreign aggregator's and an
///          arbitrary digest.
///        - assertSetBound:    accepts the exact committed set, rejects every strict subset, the
///          superset, and an unrelated set.
contract OverIssueFraudProofVerifierConformanceTest is Test {
    OverIssueFraudProofVerifier internal verifier;
    MockAggregator internal aggA;
    MockAggregator internal aggB;
    MockToken internal token;

    address internal constant REGISTRY = address(0x5E6157);
    address internal constant S1 = address(0x1111);
    address internal constant S2 = address(0x2222);
    address internal constant S3 = address(0x3333);
    address internal constant OPERATOR = address(0xABCD);
    uint8 internal constant SLASH_LEVEL = 2;
    uint256 internal constant EPOCH = 1000;
    uint256 internal constant PROPOSAL_ID = 42;
    uint256 internal constant SIGNER_MASK = 0x7;

    function setUp() public {
        aggA = new MockAggregator(REGISTRY);
        aggB = new MockAggregator(REGISTRY); // same chain + Registry, different address (hardest case)
        token = new MockToken();
        token.setOver(false); // not over-issued ⇒ the disputed slash was fraudulent
        verifier = new OverIssueFraudProofVerifier(address(aggA), REGISTRY);

        // Record the A' commitment on aggA for the exact claimed signer set.
        bytes32 mh = verifier.slashMessageHash(PROPOSAL_ID, OPERATOR, SLASH_LEVEL, EPOCH, address(token));
        aggA.record(PROPOSAL_ID, mh, SIGNER_MASK, _claimed());
    }

    function _claimed() internal pure returns (address[] memory a) {
        a = new address[](3);
        a[0] = S1;
        a[1] = S2;
        a[2] = S3;
    }

    function _fpid() internal view returns (uint256) {
        return verifier.deriveFraudProofId(PROPOSAL_ID);
    }

    function _proof() internal view returns (bytes memory) {
        return abi.encode(PROPOSAL_ID, OPERATOR, SLASH_LEVEL, EPOCH, address(token), SIGNER_MASK, _claimed());
    }

    /// SP release gate 1: domain binding.
    function test_Conformance_DomainBound() public view {
        Conformance.assertDomainBound(
            address(verifier), address(aggA), address(aggB), _fpid(), _claimed(), _proof()
        );
    }

    /// SP release gate 2: guilty-set completeness (rejects subset/superset/unrelated).
    function test_Conformance_SetBound() public view {
        Conformance.assertSetBound(address(verifier), address(aggA), _fpid(), _claimed(), _proof());
    }
}
