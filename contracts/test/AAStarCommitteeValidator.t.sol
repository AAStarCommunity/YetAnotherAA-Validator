// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import "../src/AAStarCommitteeValidator.sol";

/// @dev Test seam: mock the aggregate BLS verify (real pairing tested elsewhere) so these tests
///      isolate the CC-98 committee gate -- SMT membership, sortition, quorum, snapshot/look-ahead.
///      Also exposes the internal pure helpers for direct unit assertions.
contract MockCommitteeValidator is AAStarCommitteeValidator {
    bool public blsResult = true;

    function setBlsResult(bool v) external {
        blsResult = v;
    }

    function _validateBLSSignatureMem(bytes32[] memory, bytes memory, bytes memory)
        internal
        view
        override
        returns (bool)
    {
        return blsResult;
    }

    function exposedVerifyMerkle(bytes32 root, uint256 slot, bytes32 leaf, bytes calldata proof)
        external
        pure
        returns (bool)
    {
        return _verifyMerkle(root, slot, leaf, proof);
    }

    function exposedThreshold(uint256 n, uint256 m) external view returns (uint256) {
        return _thresholdOf(n, m);
    }
}

contract AAStarCommitteeValidatorTest is Test {
    MockCommitteeValidator v;

    uint256 constant EPOCH_LEN = 100;
    address constant ACCOUNT = address(0xA11CE);

    // A valid-length, non-infinity G1 key / G2 sig (content irrelevant -- BLS verify is mocked).
    bytes DUMMY_KEY;
    bytes DUMMY_SIG;

    function setUp() public {
        v = new MockCommitteeValidator();
        v.setEpochLength(EPOCH_LEN);
        vm.prank(ACCOUNT);
        v.enroll(); // committee ops require the account to have self-enrolled (B2 defense-in-depth)

        DUMMY_KEY = new bytes(128);
        DUMMY_SIG = new bytes(256);
        for (uint256 i = 0; i < 128; i++) {
            DUMMY_KEY[i] = bytes1(uint8(1 + (i % 250)));
        }
        for (uint256 i = 0; i < 256; i++) {
            DUMMY_SIG[i] = bytes1(uint8(1 + (i % 250)));
        }
    }

    // ---- helpers -------------------------------------------------------------------------------

    /// @dev Register n bootstrap nodes with distinct, ascending nodeIds. Returns them sorted.
    function _registerNodes(uint256 n) internal returns (bytes32[] memory ids) {
        ids = new bytes32[](n);
        for (uint256 i = 0; i < n; i++) {
            bytes32 nid = keccak256(abi.encode("node", i));
            v.registerPublicKey(nid, DUMMY_KEY);
            ids[i] = nid;
        }
        _sortAsc(ids);
    }

    function _sortAsc(bytes32[] memory a) internal pure {
        for (uint256 i = 0; i < a.length; i++) {
            for (uint256 j = i + 1; j < a.length; j++) {
                if (a[j] < a[i]) (a[i], a[j]) = (a[j], a[i]);
            }
        }
    }

    /// @dev Advance to the first block of `epoch`, set its blockhash, and pin it.
    function _rollAndSnapshot(uint256 epoch, bytes32 bh) internal {
        uint256 startBlock = epoch * EPOCH_LEN;
        vm.roll(startBlock + 1);
        vm.setBlockhash(startBlock, bh);
        v.snapshotEpoch();
    }

    /// @dev Build the committee payload: accountId || [nodeId || proof]... || blsSig.
    function _payload(address account, bytes32[] memory signers) internal view returns (bytes memory out) {
        out = abi.encodePacked(bytes32(uint256(uint160(account))));
        for (uint256 i = 0; i < signers.length; i++) {
            (uint256 slot, bytes32[] memory proof) = v.getMerkleProof(signers[i]);
            out = abi.encodePacked(out, signers[i], bytes32(slot));
            for (uint256 j = 0; j < proof.length; j++) {
                out = abi.encodePacked(out, proof[j]);
            }
        }
        out = abi.encodePacked(out, DUMMY_SIG);
    }

    // ---- SMT / Merkle --------------------------------------------------------------------------

    function test_smt_proof_verifies_against_running_root() public {
        bytes32[] memory ids = _registerNodes(5);
        for (uint256 i = 0; i < ids.length; i++) {
            (uint256 slot, bytes32[] memory proof) = v.getMerkleProof(ids[i]);
            bytes memory flat;
            for (uint256 j = 0; j < proof.length; j++) {
                flat = abi.encodePacked(flat, proof[j]);
            }
            assertTrue(
                v.exposedVerifyMerkle(v.runningRoot(), slot, ids[i], flat), "proof must verify against current root"
            );
            // A wrong leaf must NOT verify.
            assertFalse(v.exposedVerifyMerkle(v.runningRoot(), slot, keccak256("wrong"), flat), "wrong leaf must fail");
        }
    }

    function test_smt_slot_reuse_on_deactivation() public {
        bytes32[] memory ids = _registerNodes(3);
        assertEq(v.activeCount(), 3);
        uint256 slot1 = v.slotPlusOne(ids[1]) - 1;
        v.revokePublicKey(ids[1]);
        assertEq(v.activeCount(), 2);
        assertEq(v.slotPlusOne(ids[1]), 0, "revoked node loses its slot");
        // New registration reuses the freed slot.
        bytes32 fresh = keccak256("fresh");
        v.registerPublicKey(fresh, DUMMY_KEY);
        assertEq(v.slotPlusOne(fresh) - 1, slot1, "freed slot is recycled");
        assertEq(v.activeCount(), 3);
    }

    // pr-daemon Medium (coverage): _deactivate (via permissionless syncNode) must fire the SMT hook.
    // Exercised through the syncNode path (distinct from revokePublicKey), which the mutant survives.
    function test_syncNode_updates_smt() public {
        bytes32[] memory ids = _registerNodes(3);
        assertEq(v.activeCount(), 3);
        uint256 slot = v.slotPlusOne(ids[1]) - 1;
        bytes32 rootBefore = v.runningRoot();

        v.setRequireStake(true); // now bootstrap nodes are stale -> syncNode can deactivate them
        v.syncNode(ids[1]); // permissionless; goes through _deactivate -> _onNodeDeactivated

        assertEq(v.activeCount(), 2, "syncNode must decrement activeCount via the hook");
        assertEq(v.slotPlusOne(ids[1]), 0, "syncNode must free the slot via the hook");
        assertTrue(v.runningRoot() != rootBefore, "syncNode must update the SMT root via the hook");
        // Slot is recycled on the next activation.
        v.setRequireStake(false);
        bytes32 fresh = keccak256("fresh-after-sync");
        v.registerPublicKey(fresh, DUMMY_KEY);
        assertEq(v.slotPlusOne(fresh) - 1, slot, "freed slot recycled after syncNode");
    }

    // ---- snapshot / epoch ----------------------------------------------------------------------

    function test_snapshot_pins_seed_setroot_count() public {
        _registerNodes(4);
        bytes32 root = v.runningRoot();
        _rollAndSnapshot(1, bytes32(uint256(0xBEEF)));
        assertTrue(v.epochPinned(1));
        assertEq(v.epochSeed(1), bytes32(uint256(0xBEEF)));
        assertEq(v.epochSetRoot(1), root);
        assertEq(v.epochSetCount(1), 4);
    }

    function test_snapshot_rejects_double_pin() public {
        _rollAndSnapshot(1, bytes32(uint256(1)));
        vm.setBlockhash(EPOCH_LEN, bytes32(uint256(1)));
        vm.expectRevert("epoch already pinned");
        v.snapshotEpoch();
    }

    function test_snapshot_rejects_before_start_block() public {
        vm.roll(EPOCH_LEN); // exactly the start block -- blockhash(startBlock) not yet available
        vm.expectRevert("wait for epoch start block");
        v.snapshotEpoch();
    }

    function test_snapshot_rejects_after_window() public {
        // The blockhash(startBlock) window is 256 blocks. It is only reachable when the epoch is
        // LONGER than 256 blocks (otherwise the whole epoch is inside the window). Use a 300-block epoch.
        MockCommitteeValidator w = new MockCommitteeValidator();
        w.setEpochLength(300);
        vm.roll(300 + 257); // epoch 1, startBlock 300, block 557 > 300+256 => window elapsed
        vm.expectRevert("pin window elapsed");
        w.snapshotEpoch();
    }

    // ---- committee math ------------------------------------------------------------------------

    // Two-tail curve (B5): m_e = N for N<=8; else clamp(ceil(N/5), 30, 86).
    function test_expectedCommittee_curve() public view {
        assertEq(v.expectedCommittee(3), 3); // bootstrap: whole set
        assertEq(v.expectedCommittee(8), 8);
        assertEq(v.expectedCommittee(9), 9); // floor 30 > n => capped to n (whole set)
        assertEq(v.expectedCommittee(29), 29); // still capped at n
        assertEq(v.expectedCommittee(30), 30); // floor 30
        assertEq(v.expectedCommittee(100), 30); // ceil(100/5)=20 -> floor 30
        assertEq(v.expectedCommittee(150), 30); // ceil(150/5)=30
        assertEq(v.expectedCommittee(155), 31); // ceil(155/5)=31
        assertEq(v.expectedCommittee(300), 60); // ceil(300/5)=60
        assertEq(v.expectedCommittee(430), 86); // ceil(430/5)=86 = cap
        assertEq(v.expectedCommittee(1000), 86); // cap
    }

    // pr-daemon B5 discriminator: the table must assert BOTH tails, not just forgery. On-chain we assert
    // the (m_e, requiredQuorum) pair AND the deterministic liveness precondition the low liveness tail
    // rests on — E[committee] = ceil(1.25*m_e) clears requiredQuorum with margin. Offline exact tails
    // (oversample=1.25, verified by a full Binom/Poisson scan over n in [9,20000]):
    //   N=40   m_e=30 req=20  forgery @β10% ~4.4e-9   liveness ~1.6e-4
    //   N=150  m_e=30 req=20  forgery ~4.4e-9         liveness ~1.6e-4 (worst liveness point ~n=160)
    //   N=300  m_e=60 req=40  forgery ~1e-16          liveness ~1e-8
    //   N=430  m_e=86 req=58  forgery ~1e-24          liveness ~0
    function test_B5_curve_two_tail_table() public view {
        uint256[3][6] memory rows = [
            [uint256(40), 30, 20],
            [uint256(100), 30, 20],
            [uint256(150), 30, 20],
            [uint256(300), 60, 40],
            [uint256(430), 86, 58],
            [uint256(2000), 86, 58]
        ];
        for (uint256 i = 0; i < rows.length; i++) {
            uint256 me = v.expectedCommittee(rows[i][0]);
            uint256 req = (2 * me + 2) / 3;
            assertEq(me, rows[i][1], "m_e mismatch");
            assertEq(req, rows[i][2], "requiredQuorum mismatch");
            // Liveness precondition: the oversampled mean committee must exceed requiredQuorum.
            uint256 target = (v.oversampleNum() * me + v.oversampleDen() - 1) / v.oversampleDen();
            assertGt(target, req, "E[committee] must clear requiredQuorum (liveness margin)");
        }
    }

    // The whole two-tail argument rests on oversample=1.25; pin the constructor default (a prior-round
    // surviving mutant flipped it back to 1/1 with all-green tests).
    function test_constructor_oversample() public view {
        assertEq(v.oversampleNum(), 5);
        assertEq(v.oversampleDen(), 4);
    }

    function test_B1_curve_monotonic() public view {
        uint256 prev = 0;
        for (uint256 n = 9; n <= 3000; n += 7) {
            uint256 me = v.expectedCommittee(n);
            assertGe(me, prev, "m_e must be non-decreasing in N (tail non-increasing)");
            prev = me;
        }
        assertEq(prev, 86, "curve tops out at the cap");
    }

    /// @dev Regression for the 9..15 pool liveness DoS: quorum must be satisfiable (<= n).
    function test_validate_liveness_midsize_pool() public {
        bytes32[] memory ids = _registerNodes(12); // pre-fix: m=16, quorum=11 unsatisfiable-ish; now whole set
        _rollAndSnapshot(1, bytes32(uint256(0xAA)));
        _rollAndSnapshot(2, bytes32(uint256(0xBB)));
        // whole set (m=12), quorum = ceil(2*12/3) = 8. Provide 8 ascending signers.
        assertEq(v.requiredQuorum(), 8);
        bytes32[] memory signers = new bytes32[](8);
        for (uint256 i = 0; i < 8; i++) {
            signers[i] = ids[i];
        }
        assertEq(v.validate(keccak256("op"), _payload(ACCOUNT, signers)), 0, "12-node pool must be satisfiable");
    }

    function test_threshold_wholeset_for_small_pool() public view {
        // n=3, m=3 -> target=ceil(1.15*3)=4 >= n => whole set (T = max).
        assertEq(v.exposedThreshold(3, 3), type(uint256).max);
        // n=100, m=20 -> target=23 < 100 => partial.
        assertLt(v.exposedThreshold(100, 20), type(uint256).max);
        assertGt(v.exposedThreshold(100, 20), 0);
    }

    // ---- validate: happy path ------------------------------------------------------------------

    function test_validate_committee_happypath() public {
        bytes32[] memory ids = _registerNodes(3); // n=3 => whole set, quorum ceil(2*3/3) = 2
        _rollAndSnapshot(1, bytes32(uint256(0xAA))); // freeze setRoot[1]
        _rollAndSnapshot(2, bytes32(uint256(0xBB))); // pin seed[2]; committee uses setRoot[1]

        // 2 signers (meets quorum), ascending, all in the whole-set committee (T=max).
        bytes32[] memory signers = new bytes32[](2);
        signers[0] = ids[0];
        signers[1] = ids[1];
        bytes memory payload = _payload(ACCOUNT, signers);
        assertEq(v.validate(keccak256("op"), payload), 0, "valid committee op must pass");
    }

    function test_validate_rejects_below_quorum() public {
        bytes32[] memory ids = _registerNodes(3);
        _rollAndSnapshot(1, bytes32(uint256(0xAA)));
        _rollAndSnapshot(2, bytes32(uint256(0xBB)));

        bytes32[] memory signers = new bytes32[](1); // 1 < quorum 2
        signers[0] = ids[0];
        assertEq(v.validate(keccak256("op"), _payload(ACCOUNT, signers)), 1, "below quorum must fail");
    }

    function test_validate_fails_closed_without_snapshot() public {
        bytes32[] memory ids = _registerNodes(3);
        // Only pin the CURRENT epoch, not the look-ahead (e-1) one.
        _rollAndSnapshot(2, bytes32(uint256(0xBB)));
        bytes32[] memory signers = new bytes32[](2);
        signers[0] = ids[0];
        signers[1] = ids[1];
        assertEq(v.validate(keccak256("op"), _payload(ACCOUNT, signers)), 1, "missing setRoot[e-1] => fail-closed");
    }

    function test_validate_rejects_unregistered_signer() public {
        bytes32[] memory ids = _registerNodes(3);
        _rollAndSnapshot(1, bytes32(uint256(0xAA)));
        _rollAndSnapshot(2, bytes32(uint256(0xBB)));

        // Build a valid 2-signer payload, then revoke one signer AFTER proof generation.
        bytes32[] memory signers = new bytes32[](2);
        signers[0] = ids[0];
        signers[1] = ids[1];
        bytes memory payload = _payload(ACCOUNT, signers);
        v.revokePublicKey(ids[0]);
        assertEq(v.validate(keccak256("op"), payload), 1, "unregistered signer must fail");
    }

    function test_validate_rejects_non_increasing_nodeids() public {
        bytes32[] memory ids = _registerNodes(3);
        _rollAndSnapshot(1, bytes32(uint256(0xAA)));
        _rollAndSnapshot(2, bytes32(uint256(0xBB)));

        // Descending order (ids sorted asc => [1],[0] is descending).
        bytes32[] memory signers = new bytes32[](2);
        signers[0] = ids[1];
        signers[1] = ids[0];
        assertEq(v.validate(keccak256("op"), _payload(ACCOUNT, signers)), 1, "non-increasing ids must fail");
    }

    function test_validate_rejects_tampered_proof() public {
        bytes32[] memory ids = _registerNodes(3);
        _rollAndSnapshot(1, bytes32(uint256(0xAA)));
        _rollAndSnapshot(2, bytes32(uint256(0xBB)));

        bytes32[] memory signers = new bytes32[](2);
        signers[0] = ids[0];
        signers[1] = ids[1];
        bytes memory payload = _payload(ACCOUNT, signers);
        // Corrupt one byte inside the first signer's Merkle proof (offset: 32 accountId + 32 nodeId + 32 slot).
        payload[96] = bytes1(uint8(payload[96]) ^ 0xFF);
        assertEq(v.validate(keccak256("op"), payload), 1, "tampered proof must fail");
    }

    /// @dev Sortition draw for `account`/`nid` matching the contract exactly.
    function _draw(address account, bytes32 nid, bytes32 seed) internal pure returns (uint256) {
        return uint256(keccak256(abi.encode(keccak256("CMT_SELECT"), seed, bytes32(uint256(uint160(account))), nid)));
    }

    /// @dev Partition a registered pool into ACCOUNT's committee vs the rest, for a partial-sampling pool.
    function _partition(bytes32[] memory ids, address account, bytes32 seed, uint256 T)
        internal
        pure
        returns (bytes32[] memory sel, bytes32[] memory non)
    {
        sel = new bytes32[](ids.length);
        non = new bytes32[](ids.length);
        uint256 ns;
        uint256 nn;
        for (uint256 i = 0; i < ids.length; i++) {
            if (_draw(account, ids[i], seed) < T) sel[ns++] = ids[i];
            else non[nn++] = ids[i];
        }
        assembly {
            mstore(sel, ns)
            mstore(non, nn)
        }
    }

    // pr-daemon round-3: the CORE mechanism must have a discriminating regression test. n=100 => m=30,
    // T with oversample 1.25 => ~38% selected, a clean partial split. Baseline of `required` committee
    // members validates; swapping ONE for a non-committee node (still registered + Merkle-valid) must be
    // rejected BY SORTITION. Deleting the draw check flips the second assert 1->0 (verified by mutation).
    function test_validate_sortition_rejects_noncommittee_signer() public {
        bytes32[] memory ids = _registerNodes(100);
        _rollAndSnapshot(1, bytes32(uint256(0xAA)));
        _rollAndSnapshot(2, bytes32(uint256(0xBB)));
        bytes32 seed = v.epochSeed(2);
        uint256 m = v.expectedCommittee(v.epochSetCount(1));
        uint256 T = v.exposedThreshold(v.epochSetCount(1), m);
        uint256 required = (2 * m + 2) / 3;
        assertLt(T, type(uint256).max, "pool must be in partial-sampling regime");

        (bytes32[] memory sel, bytes32[] memory non) = _partition(ids, ACCOUNT, seed, T);
        require(sel.length >= required && non.length >= 1, "setup: need selected + a non-selected node");

        // Baseline: `required` committee members validate.
        bytes32[] memory good = new bytes32[](required);
        for (uint256 i = 0; i < required; i++) {
            good[i] = sel[i];
        }
        _sortAsc(good);
        assertEq(v.validate(keccak256("op"), _payload(ACCOUNT, good)), 0, "all-committee signers valid");

        // Discriminator: replace one member with a NON-committee node -> sortition must reject.
        bytes32[] memory mixed = new bytes32[](required);
        for (uint256 i = 0; i < required - 1; i++) {
            mixed[i] = sel[i];
        }
        mixed[required - 1] = non[0];
        _sortAsc(mixed);
        assertEq(
            v.validate(keccak256("op"), _payload(ACCOUNT, mixed)),
            1,
            "a non-committee signer must be rejected by sortition"
        );
    }

    // Account-binding: the SAME committee members that pass for ACCOUNT must be rejected for a different
    // account (different draw). Asserts unconditionally (the prior version guarded the assert behind an
    // `if (someExcluded)` that was always false — pr-daemon round-3).
    function test_validate_committee_is_account_bound() public {
        bytes32[] memory ids = _registerNodes(100);
        _rollAndSnapshot(1, bytes32(uint256(0xAA)));
        _rollAndSnapshot(2, bytes32(uint256(0xBB)));
        bytes32 seed = v.epochSeed(2);
        uint256 m = v.expectedCommittee(v.epochSetCount(1));
        uint256 T = v.exposedThreshold(v.epochSetCount(1), m);
        uint256 required = (2 * m + 2) / 3;

        (bytes32[] memory sel,) = _partition(ids, ACCOUNT, seed, T);
        require(sel.length >= required, "setup: need enough ACCOUNT committee members");
        bytes32[] memory chosen = new bytes32[](required);
        for (uint256 i = 0; i < required; i++) {
            chosen[i] = sel[i];
        }
        _sortAsc(chosen);
        assertEq(v.validate(keccak256("op"), _payload(ACCOUNT, chosen)), 0, "valid for its own account");

        address other = address(0xB0B);
        vm.prank(other);
        v.enroll();
        // At least one of `chosen` must be outside `other`'s committee (draw >= T) — assert it, don't skip.
        bool someExcluded;
        for (uint256 i = 0; i < chosen.length; i++) {
            if (_draw(other, chosen[i], seed) >= T) someExcluded = true;
        }
        require(someExcluded, "setup: chosen must not be a full committee for other too");
        assertEq(v.validate(keccak256("op"), _payload(other, chosen)), 1, "committee is account-bound");
    }

    function test_requiredQuorum_view_tracks_lookahead() public {
        _registerNodes(3);
        _rollAndSnapshot(1, bytes32(uint256(0xAA)));
        _rollAndSnapshot(2, bytes32(uint256(0xBB)));
        // epoch 2 committees use setRoot[1] (count 3) => m=3 => quorum 2.
        assertEq(v.requiredQuorum(), 2);
    }

    function test_epochLength_zero_falls_back_to_wholeset() public {
        MockCommitteeValidator w = new MockCommitteeValidator();
        // epochLength stays 0 => legacy whole-set path.
        bytes32 nid = keccak256(abi.encode("node", uint256(0)));
        w.registerPublicKey(nid, DUMMY_KEY);
        bytes32[] memory one = new bytes32[](1);
        one[0] = nid;
        // legacy format: [nodeId][blsSig]
        bytes memory legacy = abi.encodePacked(nid, DUMMY_SIG);
        assertEq(w.validate(keccak256("op"), legacy), 0, "epochLength=0 => whole-set path validates");
    }

    // ---- Codex-round fixes ---------------------------------------------------------------------

    // epochLength must be 0 or >= 64 (window min(256, epochLength-1) must be usable; 1 is unpinnable).
    function test_setEpochLength_bounds() public {
        MockCommitteeValidator w = new MockCommitteeValidator();
        vm.expectRevert("epochLength must be 0 or >= 64");
        w.setEpochLength(1);
        vm.expectRevert("epochLength must be 0 or >= 64");
        w.setEpochLength(63);
        w.setEpochLength(0); // disable allowed
        w.setEpochLength(64); // >= 64 allowed
    }

    // pr-daemon Medium (coverage): the discriminating look-ahead test. A node registered AFTER the
    // set was frozen for the epoch (i.e. not in setRoot[e-1]) must be rejected even though it is
    // currently registered and would pass sortition. Deleting the look-ahead (using setRoot[e]) flips
    // this to accept. Uses getMerkleProof against the CURRENT tree, so the frozen vs live divergence
    // is genuinely exercised.
    function test_validate_lookahead_rejects_post_freeze_registrant() public {
        bytes32[] memory ids = _registerNodes(3);
        _rollAndSnapshot(1, bytes32(uint256(0xAA))); // setRoot[1] frozen with exactly these 3 nodes

        // Capture a valid frozen-member payload NOW, while the live tree still equals setRoot[1].
        bytes32[] memory frozen = new bytes32[](2);
        frozen[0] = ids[0];
        frozen[1] = ids[1];
        bytes memory frozenPayload = _payload(ACCOUNT, frozen);

        // Register a 4th node AFTER the freeze: it enters the live tree (root changes) but NOT setRoot[1].
        vm.roll(EPOCH_LEN + 5);
        bytes32 late = keccak256("late-node");
        v.registerPublicKey(late, DUMMY_KEY);
        _rollAndSnapshot(2, bytes32(uint256(0xBB))); // seed[2]; epoch-2 committees use setRoot[1]

        // The pre-captured frozen payload still validates (setRoot[1] is immutable).
        assertEq(v.validate(keccak256("op"), frozenPayload), 0, "frozen members remain valid");

        // The late node is currently registered and passes whole-set sortition, but ANY proof for it
        // (built against the live root) cannot match setRoot[1] -> rejected. This is the discriminator:
        // deleting the look-ahead (validating against setRoot[e]) would ACCEPT it.
        bytes32[] memory withLate = new bytes32[](2);
        withLate[0] = ids[0] < late ? ids[0] : late;
        withLate[1] = ids[0] < late ? late : ids[0];
        assertEq(
            v.validate(keccak256("op"), _payload(ACCOUNT, withLate)),
            1,
            "post-freeze registrant must not be a valid committee member"
        );
    }

    // pr-daemon B2 (defense-in-depth): committeeActive view + self-enroll + unenrolled fail-closed.
    function test_committeeActive_view() public {
        assertTrue(v.committeeActive(), "epochLength set => active");
        MockCommitteeValidator w = new MockCommitteeValidator();
        assertFalse(w.committeeActive(), "epochLength 0 => inactive");
    }

    function test_enroll_selfproving() public {
        assertFalse(v.enrolledAccount(address(0xBEEF)));
        vm.prank(address(0xBEEF));
        v.enroll();
        assertTrue(v.enrolledAccount(address(0xBEEF)), "enroll sets caller");
        vm.prank(address(0xBEEF));
        v.unenroll();
        assertFalse(v.enrolledAccount(address(0xBEEF)), "unenroll clears caller");
    }

    function test_validate_rejects_unenrolled_account() public {
        bytes32[] memory ids = _registerNodes(3);
        _rollAndSnapshot(1, bytes32(uint256(0xAA)));
        _rollAndSnapshot(2, bytes32(uint256(0xBB)));
        bytes32[] memory signers = new bytes32[](2);
        signers[0] = ids[0];
        signers[1] = ids[1];
        // ACCOUNT is enrolled (setUp) -> valid.
        assertEq(v.validate(keccak256("op"), _payload(ACCOUNT, signers)), 0, "enrolled account valid");
        // An un-enrolled accountId (e.g. a flip-order fabricated prefix) fails closed regardless of the
        // committee/sortition — this blocks the B2 shape-collision path on-chain.
        assertEq(v.validate(keccak256("op"), _payload(address(0xDEAD), signers)), 1, "unenrolled => fail-closed");
    }

    // pr-daemon round-3 regression: a short signature must fail closed (return 1), NOT revert on an
    // out-of-bounds calldata slice. Committee mode on, snapshots present so the length guard is reached.
    function test_validate_short_signature_fails_closed() public {
        _registerNodes(3);
        _rollAndSnapshot(1, bytes32(uint256(0xAA)));
        _rollAndSnapshot(2, bytes32(uint256(0xBB)));
        assertEq(v.validate(keccak256("op"), hex""), 1, "empty sig => return 1");
        assertEq(v.validate(keccak256("op"), hex"01020304"), 1, "4-byte sig => return 1");
        bytes memory b31 = new bytes(31);
        assertEq(v.validate(keccak256("op"), b31), 1, "31-byte sig => return 1 (no accountId slice revert)");
    }

    // pr-daemon B4: accountId must be canonical (high 96 bits zero). The enrollment gate reads the low
    // 160 bits but the draw consumes all 256, so a set high bit would be a free grind surface.
    function test_validate_rejects_noncanonical_accountId() public {
        bytes32[] memory ids = _registerNodes(3);
        _rollAndSnapshot(1, bytes32(uint256(0xAA)));
        _rollAndSnapshot(2, bytes32(uint256(0xBB)));
        bytes32[] memory signers = new bytes32[](2);
        signers[0] = ids[0];
        signers[1] = ids[1];
        // Canonical accountId (== ACCOUNT, enrolled) validates.
        bytes memory good = _payload(ACCOUNT, signers);
        assertEq(v.validate(keccak256("op"), good), 0, "canonical accountId valid");
        // Same low 160 bits (ACCOUNT, enrolled) but a high bit set -> must be rejected, not accepted via
        // the low-160 enrollment match.
        bytes memory bad = good;
        uint256 highBit = 1 << 160;
        bytes32 tainted = bytes32(uint256(uint160(ACCOUNT)) | highBit);
        for (uint256 b = 0; b < 32; b++) {
            bad[b] = tainted[b];
        }
        assertEq(v.validate(keccak256("op"), bad), 1, "non-canonical accountId must fail");
    }

    // Bounded grind on the high 96 bits: none may be accepted (the probe found a low-160 collision fast).
    function test_validate_highbits_grind_all_rejected() public {
        bytes32[] memory ids = _registerNodes(3);
        _rollAndSnapshot(1, bytes32(uint256(0xAA)));
        _rollAndSnapshot(2, bytes32(uint256(0xBB)));
        bytes32[] memory signers = new bytes32[](2);
        signers[0] = ids[0];
        signers[1] = ids[1];
        bytes memory p = _payload(ACCOUNT, signers);
        uint256 base = uint256(uint160(ACCOUNT));
        for (uint256 g = 1; g <= 300; g++) {
            bytes32 tainted = bytes32(base | (g << 160)); // vary only the high 96 bits
            for (uint256 b = 0; b < 32; b++) {
                p[b] = tainted[b];
            }
            assertEq(v.validate(keccak256("op"), p), 1, "no high-bit grind may be accepted");
        }
    }

    // pr-daemon Low: pin the requiredQuorum sentinel (max, NOT 0 which would be fail-open) + the
    // constructor oversample default (the whole B1 argument rests on it).
    function test_requiredQuorum_sentinel_is_max_not_zero() public {
        MockCommitteeValidator w = new MockCommitteeValidator(); // epochLength 0
        assertEq(w.requiredQuorum(), type(uint256).max, "sentinel must be max (fail-closed), never 0");
    }

    // pr-daemon B3: setOversample must bump configVersion so it cannot retroactively relax the
    // sortition gate on an already-pinned epoch (setOversample(5,1) collapses T to max otherwise).
    function test_setOversample_invalidates_pinned_epochs() public {
        bytes32[] memory ids = _registerNodes(3);
        _rollAndSnapshot(1, bytes32(uint256(0xAA)));
        _rollAndSnapshot(2, bytes32(uint256(0xBB)));
        bytes32[] memory signers = new bytes32[](2);
        signers[0] = ids[0];
        signers[1] = ids[1];
        bytes memory payload = _payload(ACCOUNT, signers);
        assertEq(v.validate(keccak256("op"), payload), 0, "valid before oversample change");

        v.setOversample(5, 1); // would collapse the gate — must instead invalidate pinned epochs
        assertEq(v.validate(keccak256("op"), payload), 1, "pinned epochs fail-closed after oversample change");
    }

    // pr-daemon round-2 High: snapshotEpoch no longer reverts on a same-block mutation (that revert was
    // a migration-boundary DoS). Instead it freezes the BLOCK-START state, so an atomic evict-then-freeze
    // cannot depress epochSetCount. Here: 3 nodes, then a same-block registration, then freeze in that
    // block -> the snapshot must pin count 3 (pre-mutation), not 4, and NOT revert.
    function test_snapshot_freezes_block_start_state() public {
        _registerNodes(3);
        bytes32 rootBefore = v.runningRoot();
        vm.roll(EPOCH_LEN + 1);
        vm.setBlockhash(EPOCH_LEN, bytes32(uint256(0xAA)));
        v.registerPublicKey(keccak256("same-block"), DUMMY_KEY); // mutate in the freeze block
        v.snapshotEpoch(); // must NOT revert
        assertEq(v.epochSetCount(1), 3, "freezes pre-mutation (block-start) count, not 4");
        assertEq(v.epochSetRoot(1), rootBefore, "freezes pre-mutation root");
    }

    // A mutation in an EARLIER block than the freeze is included normally (block-start == current).
    function test_snapshot_includes_prior_block_mutation() public {
        _registerNodes(3);
        vm.roll(EPOCH_LEN - 1);
        v.registerPublicKey(keccak256("prior-block"), DUMMY_KEY); // 4th node, earlier block
        vm.roll(EPOCH_LEN + 1);
        vm.setBlockhash(EPOCH_LEN, bytes32(uint256(0xAA)));
        v.snapshotEpoch();
        assertEq(v.epochSetCount(1), 4, "prior-block mutation included");
    }

    // Medium: unbounded oversample would overflow _thresholdOf and turn fail-closed into a revert.
    function test_setOversample_bounds() public {
        vm.expectRevert("oversample must be in [1, 8]");
        v.setOversample(type(uint256).max, 1);
        vm.expectRevert("oversample must be in [1, 8]");
        v.setOversample(1, 2); // num < den
        vm.expectRevert("den out of range");
        v.setOversample(2e9, 2e9);
        v.setOversample(2, 1); // ok (2x)
    }

    // Medium: the submitted slot is authenticated by the proof — a wrong slot must fail.
    function test_validate_rejects_wrong_slot() public {
        bytes32[] memory ids = _registerNodes(3);
        _rollAndSnapshot(1, bytes32(uint256(0xAA)));
        _rollAndSnapshot(2, bytes32(uint256(0xBB)));
        bytes32[] memory signers = new bytes32[](2);
        signers[0] = ids[0];
        signers[1] = ids[1];
        bytes memory payload = _payload(ACCOUNT, signers);
        // Slot word for signer 0 is at offset 32(accountId)+32(nodeId) = 64; flip its low byte.
        payload[95] = bytes1(uint8(payload[95]) ^ 0x01);
        assertEq(v.validate(keccak256("op"), payload), 1, "wrong slot must fail Merkle");
    }

    // Low: changing epochLength must invalidate snapshots taken under the old schedule (fail-closed).
    function test_configVersion_invalidates_snapshots() public {
        bytes32[] memory ids = _registerNodes(3);
        _rollAndSnapshot(1, bytes32(uint256(0xAA)));
        _rollAndSnapshot(2, bytes32(uint256(0xBB)));
        bytes32[] memory signers = new bytes32[](2);
        signers[0] = ids[0];
        signers[1] = ids[1];
        bytes memory payload = _payload(ACCOUNT, signers);
        assertEq(v.validate(keccak256("op"), payload), 0, "valid before reconfig");

        // Reconfigure epoch schedule -> configVersion bumps -> old snapshots become stale.
        v.setEpochLength(EPOCH_LEN);
        assertEq(v.validate(keccak256("op"), payload), 1, "stale snapshots => fail-closed after reconfig");
        assertEq(v.requiredQuorum(), type(uint256).max, "requiredQuorum unusable until re-pinned");
    }

    // Round-2 High: after a configVersion bump, an epoch pinned under the OLD version must be
    // re-pinnable under the new one (else colliding epoch numbers strand committee mode forever).
    function test_snapshot_repin_after_reconfig() public {
        _registerNodes(3);
        vm.roll(3 * EPOCH_LEN + 1);
        vm.setBlockhash(3 * EPOCH_LEN, bytes32(uint256(0xCC)));
        v.snapshotEpoch(); // pinned under configVersion 1
        assertEq(v.epochConfigVersion(3), 1);

        v.setEpochLength(EPOCH_LEN); // configVersion -> 2
        // Same epoch/block: the stale pin must be replaceable, not rejected as "already pinned".
        v.snapshotEpoch();
        assertEq(v.epochConfigVersion(3), 2, "epoch re-pinned under new configVersion");
    }

    // Round-2 Low: a non-canonical slot (slot + 2^TREE_DEPTH) must be rejected, not aliased.
    function test_validate_rejects_noncanonical_slot() public {
        bytes32[] memory ids = _registerNodes(3);
        _rollAndSnapshot(1, bytes32(uint256(0xAA)));
        _rollAndSnapshot(2, bytes32(uint256(0xBB)));
        bytes32[] memory signers = new bytes32[](2);
        signers[0] = ids[0];
        signers[1] = ids[1];
        bytes memory payload = _payload(ACCOUNT, signers);
        // Add 2^TREE_DEPTH to signer 0's slot word (offset 64) — same low bits, must be rejected.
        uint256 aliased = (1 << v.TREE_DEPTH()); // canonical slot is 0 or 1 here; +2^depth aliases it
        bytes32 slotWord = bytes32(uint256(bytes32(_slice(payload, 64, 32))) + aliased);
        for (uint256 b = 0; b < 32; b++) {
            payload[64 + b] = slotWord[b];
        }
        assertEq(v.validate(keccak256("op"), payload), 1, "non-canonical slot must be rejected");
    }

    function _slice(bytes memory data, uint256 start, uint256 len) internal pure returns (bytes memory out) {
        out = new bytes(len);
        for (uint256 i = 0; i < len; i++) {
            out[i] = data[start + i];
        }
    }
}
