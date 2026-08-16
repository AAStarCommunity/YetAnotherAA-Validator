// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import "../src/AAStarValidator.sol";

/// SuperPaymaster Registry stand-in for the eligible-count-under-stake test.
contract QuorumStakeRegistry is IDVTRegistry {
    mapping(bytes32 => mapping(address => bool)) public roles;
    mapping(address => uint256) public stake;

    function setRole(bytes32 roleId, address user, bool v) external { roles[roleId][user] = v; }
    function setStake(address user, uint256 amount) external { stake[user] = amount; }

    function hasRole(bytes32 roleId, address user) external view returns (bool) { return roles[roleId][user]; }
    function getEffectiveStake(address user, bytes32) external view returns (uint256) { return stake[user]; }
}

/// @title CC-97 — on-chain BFT quorum (⌈2N/3⌉, committee ≥ 3) for tier-2/3 BLS co-sign.
/// @notice Before CC-97, validate() accepted an aggregate carrying as few as ONE registered
///         signer. This suite proves the new on-chain floor: the aggregate must carry ⌈2N/3⌉
///         distinct signers of the eligible committee, and the committee must be ≥ minCommittee.
///
///         The decisive test reuses the cross-repo golden 2-node aggregate (same vector as
///         AAStarValidatorRouter.t.sol — a cryptographically VALID PUB0+PUB1 signature over
///         USER_OP_HASH). Because that aggregate really verifies, we can isolate the quorum GATE
///         from the crypto: the identical 2-signer aggregate returns 0 when quorum is 2 (N=3) and
///         1 when quorum is 3 (N=4). Only the gate changed — the signature is byte-identical.
contract AAStarValidatorQuorumTest is Test {
    AAStarValidator v;

    bytes32 constant ROLE_DVT = keccak256("DVT");
    uint256 constant MIN_STAKE = 30 ether;

    bytes32 constant USER_OP_HASH =
        bytes32(uint256(0x1111111111111111111111111111111111111111111111111111111111111111));

    bytes[2] PUB; // real signing pubkeys (sk 0x..07 / 0x..0b), same golden vector as the router test
    // Valid 2-node aggregate over hashToCurve(USER_OP_HASH, DST) — @noble verify == true.
    bytes AGG_SIG =
        hex"000000000000000000000000000000000b9f176f5113c4ccad075895d342d551ab705281d3a134902b8f6f0eb172a02b476efe18a58791bb5308a721bd87a417000000000000000000000000000000000f28139976fdab5e48503ad8d94c08ed65ef56219e423aa5942ae4b1926545ecabd48cde24179509a99ccac4b958499e000000000000000000000000000000000b7f5bcdb9f61925e00695c3a8c04dfe93258e7db5b923f6dd9b18a620e86ad45df02f23039a3ece1a09ea58e0e1677b0000000000000000000000000000000009ccf8330835ca4660012e0f587a6e0727241c3ac771858cc6d3b01d8659e3bf8a4582015610cacb9bee5f10945887af";

    function setUp() public {
        v = new AAStarValidator();
        PUB[0] =
            hex"000000000000000000000000000000001928f3beb93519eecf0145da903b40a4c97dca00b21f12ac0df3be9116ef2ef27b2ae6bcd4c5bc2d54ef5a70627efcb700000000000000000000000000000000108dadbaa4b636445639d5ae3089b3c43a8a1d47818edd1839d7383959a41c10fdc66849cfa1b08c5a11ec7e28981a1c";
        PUB[1] =
            hex"0000000000000000000000000000000000fd75ebcc0a21649e3177bcce15426da0e4f25d6828fbf4038d4d7ed3bd4421de3ef61d70f794687b12b2d571971a550000000000000000000000000000000004523f5a3915fc57ee889cdb057e3e76109112d125217546ccfe26810c99b130d1b27820595ad61c7527dc5bbb132a90";
    }

    // A registerable non-signing pubkey (valid length, non-infinity) that only inflates N. Its
    // key material never enters an aggregate, so any distinct non-zero 128-byte value works.
    function _filler(uint8 tag) internal pure returns (bytes memory pk) {
        pk = new bytes(128);
        pk[127] = bytes1(tag); // one non-zero byte ⇒ passes the !_isInfinity check
    }

    function _bootstrap(bytes memory pk) internal {
        v.registerPublicKey(keccak256(pk), pk);
    }

    /// The 2-node golden aggregate wire: sorted(nodeId0, nodeId1) ‖ AGG_SIG.
    function _goldenSig() internal view returns (bytes memory) {
        bytes32 a = keccak256(PUB[0]);
        bytes32 b = keccak256(PUB[1]);
        (bytes32 lo, bytes32 hi) = a < b ? (a, b) : (b, a);
        return abi.encodePacked(lo, hi, AGG_SIG);
    }

    // =========================================================================
    //                       Formula ⌈2N/3⌉ (pure)
    // =========================================================================
    function test_quorumFor_matches_BFT_table() public view {
        // The confirmed CC-97 table (Jason 2026-08-16).
        assertEq(v.quorumFor(3), 2, "N=3 -> 2");
        assertEq(v.quorumFor(4), 3, "N=4 -> 3");
        assertEq(v.quorumFor(5), 4, "N=5 -> 4");
        assertEq(v.quorumFor(6), 4, "N=6 -> 4");
        assertEq(v.quorumFor(7), 5, "N=7 -> 5");
        // Degenerate n (below minCommittee, never used by validate) — formula is still ⌈2n/3⌉.
        assertEq(v.quorumFor(0), 0, "N=0 -> 0");
        assertEq(v.quorumFor(1), 1, "N=1 -> 1");
        assertEq(v.quorumFor(2), 2, "N=2 -> 2");
        assertEq(v.quorumFor(100), 67, "N=100 -> 67");
    }

    // =========================================================================
    //                       minCommittee floor
    // =========================================================================
    function test_minCommittee_defaults_to_3_and_is_floored() public {
        assertEq(v.minCommittee(), 3, "default 3");
        vm.expectRevert("minCommittee < 3");
        v.setMinCommittee(2);
        v.setMinCommittee(5);
        assertEq(v.minCommittee(), 5, "raised to 5");
    }

    // =========================================================================
    //                       Active-node counters
    // =========================================================================
    function test_activeNodeCount_tracks_register_and_revoke() public {
        assertEq(v.activeNodeCount(), 0);
        _bootstrap(PUB[0]);
        _bootstrap(PUB[1]);
        bytes memory f = _filler(1);
        _bootstrap(f);
        assertEq(v.activeNodeCount(), 3, "3 registered");
        assertEq(v.bootstrapNodeCount(), 3, "all bootstrap");

        v.revokePublicKey(keccak256(f));
        assertEq(v.activeNodeCount(), 2, "1 revoked");
        assertEq(v.bootstrapNodeCount(), 2, "bootstrap decremented");
    }

    // =========================================================================
    //          Quorum OFF (default) — legacy behaviour preserved
    // =========================================================================
    function test_quorumOff_dualSigner_still_valid() public {
        _bootstrap(PUB[0]);
        _bootstrap(PUB[1]);
        assertFalse(v.quorumRequired(), "off by default");
        assertEq(v.requiredQuorum(), 0, "no quorum demanded while off");
        // N=2 (< minCommittee 3) but quorum is OFF, so the valid aggregate still passes.
        assertEq(v.validate(USER_OP_HASH, _goldenSig()), 0, "legacy dual-signer passes when quorum off");
    }

    // =========================================================================
    //   Quorum ON — the decisive gate isolation (same valid aggregate, N flips verdict)
    // =========================================================================
    function test_quorumOn_met_passes_then_subquorum_rejects_same_aggregate() public {
        _bootstrap(PUB[0]);
        _bootstrap(PUB[1]);
        _bootstrap(_filler(1)); // N = 3, quorum = 2
        v.setQuorumRequired(true);

        assertEq(v.eligibleNodeCount(), 3, "committee N=3");
        assertEq(v.requiredQuorum(), 2, "quorum 2 of 3");
        // 2 distinct valid signers == quorum(2) → gate passes → valid crypto → 0.
        assertEq(v.validate(USER_OP_HASH, _goldenSig()), 0, "2-of-3 meets quorum, valid aggregate passes");

        // Grow the committee to 4 → quorum 3. The SAME cryptographically-valid 2-signer aggregate
        // now carries too few signers. Only the gate changed; the signature is byte-identical.
        _bootstrap(_filler(2)); // N = 4, quorum = 3
        assertEq(v.eligibleNodeCount(), 4, "committee N=4");
        assertEq(v.requiredQuorum(), 3, "quorum 3 of 4");
        assertEq(v.validate(USER_OP_HASH, _goldenSig()), 1, "2-of-4 is sub-quorum: same valid sig now rejected");
    }

    // =========================================================================
    //   Quorum ON but committee below minimum — fail closed even for a valid sig
    // =========================================================================
    function test_quorumOn_belowMinCommittee_rejects_valid_aggregate() public {
        _bootstrap(PUB[0]);
        _bootstrap(PUB[1]); // N = 2 < minCommittee 3
        v.setQuorumRequired(true);

        assertEq(v.eligibleNodeCount(), 2, "N=2");
        assertEq(v.requiredQuorum(), type(uint256).max, "unsatisfiable while committee < min");
        // The aggregate is cryptographically valid, but a 2-node committee is not BFT — reject.
        assertEq(v.validate(USER_OP_HASH, _goldenSig()), 1, "committee < 3 fails closed even for a valid sig");
    }

    // =========================================================================
    //   Eligible committee excludes retired bootstrap nodes once staking is on
    // =========================================================================
    function test_eligibleNodeCount_excludes_bootstrap_when_requireStake() public {
        _bootstrap(PUB[0]);
        _bootstrap(PUB[1]);
        _bootstrap(_filler(1));
        assertEq(v.eligibleNodeCount(), 3, "all 3 eligible while requireStake off");

        // Flip staking on: bootstrap nodes are retired, so the eligible committee drops to 0.
        // (In production the committee is rebuilt via registerWithProof; here we only assert the
        // count so a stale bootstrap set can never satisfy a staked-mode quorum.)
        QuorumStakeRegistry reg = new QuorumStakeRegistry();
        v.setRegistry(address(reg));
        v.setMinStake(MIN_STAKE);
        v.setRequireStake(true);
        assertEq(v.eligibleNodeCount(), 0, "bootstrap nodes excluded under requireStake");

        v.setQuorumRequired(true);
        assertEq(v.requiredQuorum(), type(uint256).max, "no eligible committee -> unsatisfiable");
    }
}
