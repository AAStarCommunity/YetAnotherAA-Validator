// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import "../src/AAStarCommitteeValidator.sol";

/// @dev SuperPaymaster Registry stand-in: ROLE_DVT membership + locked stake.
contract StakeRegistry is IDVTRegistry {
    mapping(bytes32 => mapping(address => bool)) internal roles;
    mapping(address => uint256) public stake;
    /// @dev Mirrors SP Registry.sol:33 — the authoritative pointer the validator binds to.
    address public blsAggregator;

    function setBLSAggregator(address a) external {
        blsAggregator = a;
    }

    function setRole(bytes32 r, address u, bool ok) external {
        roles[r][u] = ok;
    }

    function setStake(address u, uint256 amount) external {
        stake[u] = amount;
    }

    function hasRole(bytes32 r, address u) external view returns (bool) {
        return roles[r][u];
    }

    function getEffectiveStake(address u, bytes32) external view returns (uint256) {
        return stake[u];
    }
}

/// @dev SP BLSAggregator stand-in: only the ROLE_DVT exit-notice ledger the snapshot reads.
contract ExitNoticeAggregator {
    mapping(address => uint64) internal readyAt;

    function setExitNotice(address guardian, uint64 ready) external {
        readyAt[guardian] = ready;
    }

    function guardianExitRequests(address guardian) external view returns (uint64, uint64) {
        uint64 r = readyAt[guardian];
        if (r == 0) return (0, 0);
        // SP's GUARDIAN_EXIT_WINDOW is 1 day; saturate rather than overflow at uint64 extremes.
        uint64 expires = r > type(uint64).max - uint64(1 days) ? type(uint64).max : r + uint64(1 days);
        return (r, expires);
    }
}

/// @dev An aggregator address that does NOT expose the exit-notice getter.
contract NotAnAggregator {
    function version() external pure returns (string memory) {
        return "nope";
    }
}

contract StakeAwareMock is AAStarCommitteeValidator {
    function _validateBLSSignatureMem(bytes32[] memory, bytes memory, bytes memory)
        internal
        pure
        override
        returns (bool)
    {
        return true;
    }

    /// @dev Test seam. `requiredQuorum()` cannot express these assertions on a 2-node fixture: it
    ///      returns the sentinel whenever the pool is under `minCommittee` (hard floor 3), which would
    ///      make every "fails closed" assertion pass for the wrong reason.
    function exposedEpochUsable(uint256 e) external view returns (bool) {
        return _epochUsable(e);
    }
}

/// @notice CC-112 D2 (pillars P3 + P8): the frozen committee set must be the ELIGIBLE set — currently
///         staked, holding ROLE_DVT, and with no ROLE_DVT exit notice in flight — verified in the
///         permissionless keeper's snapshot tx so that validate() keeps reading only its own storage
///         (ERC-7562 clean).
contract CommitteeStakeAwareSnapshotTest is Test {
    StakeAwareMock v;
    StakeRegistry reg;
    ExitNoticeAggregator agg;

    uint256 constant EPOCH_LEN = 64;
    bytes32 constant ROLE_DVT = keccak256("DVT");
    uint256 constant MIN_STAKE = 100 ether;

    address constant OP_A = address(0xA11CE);
    address constant OP_B = address(0xB0B);

    // Real BLS12-381 PoP vectors (shared with AAStarValidatorStakeBinding.t.sol) so registration goes
    // through the genuine staked path — no test seam over the PoP pairing.
    bytes V1_PUB = hex"000000000000000000000000000000001928f3beb93519eecf0145da903b40a4c97dca00b21f12ac0df3be9116ef2ef27b2ae6bcd4c5bc2d54ef5a70627efcb700000000000000000000000000000000108dadbaa4b636445639d5ae3089b3c43a8a1d47818edd1839d7383959a41c10fdc66849cfa1b08c5a11ec7e28981a1c";
    bytes V1_POP_POINT = hex"00000000000000000000000000000000086f6d0cdf889dc6d987ee9c5446c45b206775fcf7c60ebde4e1e0250fb04be1a86a296bae0bad3bc81f27a76ada86d50000000000000000000000000000000007906cd1575d26570463bee46945d8ef77539df93d13e22aef436f0d538bb28d916d581fe1d71bbc0d62c7ba4b8edccb000000000000000000000000000000000389f33b01cdf1a04f541764ddf51ec2dbed718f2398f75f3fce7725c072d9340263ae52e06b7bf52eb3ab7ec72ca92000000000000000000000000000000000137ab9e24a3c0f637ae65f212458ed1a10250d85da32ae5bf72842062c6819149945d2c7091607690f3c61f53e52c8b9";
    bytes V1_POP_SIG = hex"00000000000000000000000000000000022bd720bb56d00b92f4995e3e4342b2cb7fb8ca8d54e58ff20adc76760c2340c2b1e119a19db8640cffad3f0e41c850000000000000000000000000000000000eafa2b92b141289b6e189c9a0a4d3b1b9a9cd0e5d51b43482b7a1b261134049a601bda9fabb054c36e790fb6b6ca3e7000000000000000000000000000000000b6232777504abec794edddee6bb8b38b9fa3292d2376a3ddaed676bf0b5406c981292eb50ec1b2d8dffec72f1f9aab400000000000000000000000000000000019da6fdf9a09dd3b32c75176c36426118bab60496b3583c817dde359dadf72fc87ddd09a192bd32766938a92cf4ff5c";
    bytes V2_PUB = hex"0000000000000000000000000000000019cdf3807146e68e041314ca93e1fee0991224ec2a74beb2866816fd0826ce7b6263ee31e953a86d1b72cc2215a577930000000000000000000000000000000007481b1f261aabacf45c6e4fc278055441bfaf99f604d1f835c0752ac9742b4522c9f5c77db40989e7da608505d48616";
    bytes V2_POP_POINT = hex"000000000000000000000000000000000f73f219e773dd1ef6fe2d10a5c49921d8cdd723b33b34087a52617d067a2de251e945553c8bd9734ad664fb6f345fce00000000000000000000000000000000123a13ec0543aeed2afad244f7e4c9bc20ee778d6354947cbea7410820f8d907f5c025bb8e8598cbf5902a7982e1b323000000000000000000000000000000000c02e3e68f26c168a018698ba779272abe9ff0279d6f5280afc9fb3ab0160c06ecbddf2d33d0423b79a2751695f51a11000000000000000000000000000000000eaaecfea4c6ce69a92154ca4b2804d2f7017d468be09aeb0de61c4dbe2c2553afe4193e20a948afc382b97a2d36e8e4";
    bytes V2_POP_SIG = hex"000000000000000000000000000000000142a94144f05fff297d81f022f4a81023db248cd04b17530e474c0a264a4a1970f53d0fdd2c75eb40767f198461e08e0000000000000000000000000000000004dfd312738238f2004bde8c5376d6262f6ae91ff8ba8d94fa4c840b1682fcfb1994738cf7a861f34411f0d3eead6f79000000000000000000000000000000000f0db21327df7234d3dab4e226caadea2f1447fa9ea5969db23d84dcf0b985c93de4dcf45041cb8c23ea8e276d0a60350000000000000000000000000000000000c933d07622ca99f9f8d9648354c07ab2d41fb7804d43f605adea83f6e4713e2d66e3ad0790ec39bf193ef3529c6693";

    function setUp() public {
        v = new StakeAwareMock();
        reg = new StakeRegistry();
        agg = new ExitNoticeAggregator();
        v.setRegistry(address(reg));
        v.setMinStake(MIN_STAKE);
        v.setRequireStake(true);
        reg.setBLSAggregator(address(agg));
        v.setBlsAggregator(address(agg));
        v.setEpochLength(EPOCH_LEN);
        _stake(OP_A);
        _stake(OP_B);
        vm.prank(OP_A);
        v.registerWithProof(V1_PUB, V1_POP_POINT, V1_POP_SIG);
        vm.prank(OP_B);
        v.registerWithProof(V2_PUB, V2_POP_POINT, V2_POP_SIG);
    }

    function _stake(address op) internal {
        reg.setRole(ROLE_DVT, op, true);
        reg.setStake(op, MIN_STAKE);
    }

    function _snap(uint256 epoch) internal {
        vm.roll(epoch * EPOCH_LEN + 1);
        vm.setBlockhash(epoch * EPOCH_LEN, bytes32(uint256(0xAA + epoch)));
        v.snapshotEpoch(v.activeNodeIdsSorted());
    }

    function _expectSnapRevert(uint256 epoch, bytes memory reason) internal {
        vm.roll(epoch * EPOCH_LEN + 1);
        vm.setBlockhash(epoch * EPOCH_LEN, bytes32(uint256(0xAA + epoch)));
        bytes32[] memory ids = v.activeNodeIdsSorted();
        vm.expectRevert(reason);
        v.snapshotEpoch(ids);
    }

    function _nodeOf(address op) internal view returns (bytes32) {
        return v.operatorNode(op);
    }

    // --- happy path -------------------------------------------------------------------------------

    function test_snapshot_accepts_a_fully_eligible_set() public {
        _snap(1);
        assertEq(v.epochSetCount(1), 2, "both eligible nodes are frozen");
        assertEq(v.epochSetRoot(1), v.runningRoot(), "root pinned live");
    }

    // --- P8: currently staked ---------------------------------------------------------------------

    /// @notice CC-112 named case: a node whose operator dropped below minStake must not be frozen.
    function test_snapshot_rejects_a_node_below_minStake() public {
        reg.setStake(OP_B, MIN_STAKE - 1);
        _expectSnapRevert(1, "ineligible node in set: syncNode it first");
    }

    /// @notice ...and the eviction path unblocks it, with the count reduced accordingly.
    function test_syncNode_then_snapshot_succeeds_with_a_smaller_set() public {
        reg.setStake(OP_B, MIN_STAKE - 1);
        v.syncNode(_nodeOf(OP_B));
        _snap(1);
        assertEq(v.epochSetCount(1), 1, "the unstaked node is gone from the frozen set");
    }

    function test_snapshot_rejects_a_node_whose_operator_lost_ROLE_DVT() public {
        reg.setRole(ROLE_DVT, OP_B, false);
        _expectSnapRevert(1, "ineligible node in set: syncNode it first");
    }

    // --- CC-112 boundary 1: exit notice in flight --------------------------------------------------

    /// @notice THE case SP raised (BLSAggregator.sol:1235): once a guardian's notice matures, SP stops
    ///         accepting it in a BLS quorum even though its stake is still locked. A set frozen before
    ///         that moment would contain a member that cannot sign for part of the epoch.
    function test_snapshot_rejects_a_node_with_an_exit_notice_in_flight() public {
        agg.setExitNotice(OP_A, uint64(block.timestamp + 2 days));
        _expectSnapRevert(1, "ineligible node in set: syncNode it first");
    }

    /// @notice Stricter than SP's suggested `readyAt > snapshotTime + epochLength` ON PURPOSE: readyAt
    ///         is SECONDS and epochLength is BLOCKS, and converting would weld a block-time assumption
    ///         into a non-upgradeable validator. Even a notice maturing far beyond this epoch is refused.
    function test_snapshot_rejects_an_exit_notice_maturing_far_in_the_future() public {
        agg.setExitNotice(OP_A, type(uint64).max);
        _expectSnapRevert(1, "ineligible node in set: syncNode it first");
    }

    /// @notice ...and cancelling the notice restores eligibility at the NEXT snapshot.
    function test_cancelled_exit_notice_restores_eligibility() public {
        agg.setExitNotice(OP_A, uint64(block.timestamp + 2 days));
        _expectSnapRevert(1, "ineligible node in set: syncNode it first");
        agg.setExitNotice(OP_A, 0);
        _snap(1);
        assertEq(v.epochSetCount(1), 2, "both eligible again");
    }

    // --- H1: an exit notice must be permissionlessly resolvable, or the snapshot deadlocks ---------

    /// @notice THE deadlock this path exists to break. SP keeps role AND stake intact for the whole
    ///         2-day notice, so `syncNode` refuses ("Node still active") while `snapshotEpoch` refuses
    ///         ("ineligible node"). Without a third path, one ORDINARY exit halts committee mode for
    ///         two days.
    function test_syncNode_cannot_clear_an_exit_notice() public {
        agg.setExitNotice(OP_A, uint64(block.timestamp + 2 days));
        bytes32 nid = _nodeOf(OP_A);
        vm.expectRevert("Node still active");
        v.syncNode(nid);
    }

    function test_syncExitNotice_breaks_the_deadlock_and_unblocks_the_snapshot() public {
        agg.setExitNotice(OP_A, uint64(block.timestamp + 2 days));
        _expectSnapRevert(1, "ineligible node in set: syncNode it first");

        // Permissionless: any address, not just the owner or the operator.
        bytes32 nid = _nodeOf(OP_A); // capture BEFORE deactivation clears operatorNode[op]
        vm.prank(address(0xDEADBEEF));
        v.syncExitNotice(nid);

        assertFalse(v.isRegistered(nid), "the exiting node is retired");
        _snap(1);
        assertEq(v.epochSetCount(1), 1, "the snapshot proceeds without it");
    }

    /// @notice The eviction and the pin may happen in the SAME block — the earlier same-block revert
    ///         was removed (it could deny a whole 63-block window at L=64 for the price of registering
    ///         one node per block). The completeness check is what keeps the list honest.
    function test_syncExitNotice_and_snapshot_in_the_same_block() public {
        agg.setExitNotice(OP_A, uint64(block.timestamp + 2 days));
        vm.roll(EPOCH_LEN + 1);
        vm.setBlockhash(EPOCH_LEN, bytes32(uint256(0xAB)));
        v.syncExitNotice(_nodeOf(OP_A));
        v.snapshotEpoch(v.activeNodeIdsSorted()); // same block, must NOT revert
        assertEq(v.epochSetCount(1), 1, "freezes the live post-eviction set");
    }

    /// @notice The predicate is narrow ON PURPOSE. Reusing `!_isEligibleForSnapshot` would let anyone
    ///         empty the entire set whenever `blsAggregator` is unset, since it returns false for every
    ///         staked node in that state.
    function test_syncExitNotice_rejects_a_node_without_a_notice() public {
        bytes32 nid = _nodeOf(OP_A);
        vm.expectRevert("No exit notice filed");
        v.syncExitNotice(nid);
    }

    function test_syncExitNotice_rejects_an_unstaked_but_notice_free_node() public {
        reg.setStake(OP_A, 0); // ineligible for the snapshot, but NOT via an exit notice
        bytes32 nid = _nodeOf(OP_A);
        vm.expectRevert("No exit notice filed");
        v.syncExitNotice(nid);
        // syncNode is the right tool for that case, and it works.
        v.syncNode(nid);
        assertFalse(v.isRegistered(nid), "stake loss is syncNode's job");
    }

    function test_syncExitNotice_rejects_an_unregistered_node() public {
        vm.expectRevert("Node not registered");
        v.syncExitNotice(keccak256("nope"));
    }

    /// @notice M2: during a Registry rotation a LEFTOVER notice on the OLD ledger no longer governs
    ///         `Registry.exitRole`, so it must not be usable to evict a node that still holds its role
    ///         and stake — that would drop it from the frozen committee it is currently serving.
    function test_syncExitNotice_refuses_a_stale_aggregator_after_rotation() public {
        agg.setExitNotice(OP_A, uint64(block.timestamp + 2 days));
        ExitNoticeAggregator successor = new ExitNoticeAggregator();
        reg.setBLSAggregator(address(successor)); // SP rotated; validator not re-pointed yet
        bytes32 nid = _nodeOf(OP_A);
        vm.expectRevert("aggregator stale: re-run setBlsAggregator");
        v.syncExitNotice(nid);
    }

    // --- CC-112 boundary 2: in-epoch slash is an EXPLICIT NON-CLAIM --------------------------------

    /// @notice What IS claimed: every frozen signer held bonded, slashable stake at freeze time, and
    ///         cannot have withdrawn it while the snapshot is still usable (the bond window is enforced
    ///         on the clock — see the epochSetValidUntil tests).
    ///
    ///         What is NOT claimed, and an earlier revision of the design doc wrongly did claim: that a
    ///         slashed node "stays in the frozen set and keeps signing". It does not. Slashing makes it
    ///         `syncNode`-able immediately, and `_deactivate` clears `isRegistered`, which
    ///         `_verifyCommitteeSigners` reads live — so it stops being able to sign at once. The
    ///         frozen DENOMINATOR is what survives, which makes an in-epoch slash a LIVENESS cost (the
    ///         quorum still asks for ⌈2m/3⌉ of the frozen population) rather than a safety one.
    ///         The validate-level proof of that is
    ///         `test_a_node_removed_mid_epoch_cannot_sign_while_the_frozen_denominator_stays`
    ///         in AAStarCommitteeValidator.t.sol, where a 3-node fixture is available.
    function test_in_epoch_slash_evicts_the_node_but_never_rewrites_the_frozen_set() public {
        _snap(1);
        bytes32 frozenRoot = v.epochSetRoot(1);
        uint256 frozenCount = v.epochSetCount(1);

        // Mid-epoch slash: stake drops with no exit flow, exactly as SP's slashByDVT does.
        vm.roll(EPOCH_LEN + 10);
        reg.setStake(OP_B, 0);

        // The node is immediately evictable, and eviction is permissionless.
        assertFalse(v.isEligibleForSnapshot(_nodeOf(OP_B)), "slashed node is no longer eligible");
        bytes32 nidB = _nodeOf(OP_B); // capture BEFORE deactivation clears operatorNode[op]
        vm.prank(address(0xFEE));
        v.syncNode(nidB);
        assertFalse(v.isRegistered(nidB), "and it is retired at once, not at the epoch end");

        // The pinned snapshot is immutable: the denominator does not shrink to match.
        assertEq(v.epochSetRoot(1), frozenRoot, "frozen root is immutable once pinned");
        assertEq(v.epochSetCount(1), frozenCount, "frozen count is immutable once pinned");

        // The NEXT snapshot is where the smaller set takes effect.
        _snap(2);
        assertEq(v.epochSetCount(2), frozenCount - 1, "the next epoch's set excludes it");
    }

    // --- completeness of the supplied list ---------------------------------------------------------

    function test_snapshot_rejects_a_short_list() public {
        vm.roll(EPOCH_LEN + 1);
        vm.setBlockhash(EPOCH_LEN, bytes32(uint256(0xAA)));
        bytes32[] memory ids = new bytes32[](1);
        bytes32[] memory all = v.activeNodeIdsSorted();
        ids[0] = all[0];
        vm.expectRevert("activeNodeIds length != activeCount");
        v.snapshotEpoch(ids);
    }

    function test_snapshot_rejects_duplicates_padding_the_list() public {
        vm.roll(EPOCH_LEN + 1);
        vm.setBlockhash(EPOCH_LEN, bytes32(uint256(0xAA)));
        bytes32[] memory all = v.activeNodeIdsSorted();
        bytes32[] memory ids = new bytes32[](2);
        ids[0] = all[0];
        ids[1] = all[0]; // a duplicate would hide an ineligible member
        vm.expectRevert("activeNodeIds must be strictly increasing");
        v.snapshotEpoch(ids);
    }

    function test_snapshot_rejects_an_unsorted_list() public {
        vm.roll(EPOCH_LEN + 1);
        vm.setBlockhash(EPOCH_LEN, bytes32(uint256(0xAA)));
        bytes32[] memory all = v.activeNodeIdsSorted();
        bytes32[] memory ids = new bytes32[](2);
        ids[0] = all[1];
        ids[1] = all[0];
        vm.expectRevert("activeNodeIds must be strictly increasing");
        v.snapshotEpoch(ids);
    }

    function test_snapshot_rejects_a_non_member_in_the_list() public {
        vm.roll(EPOCH_LEN + 1);
        vm.setBlockhash(EPOCH_LEN, bytes32(uint256(0xAA)));
        bytes32[] memory all = v.activeNodeIdsSorted();
        bytes32[] memory ids = new bytes32[](2);
        ids[0] = all[0];
        ids[1] = bytes32(type(uint256).max); // sorts last, is not a member
        vm.expectRevert("activeNodeIds contains a non-member");
        v.snapshotEpoch(ids);
    }

    // --- aggregator wiring --------------------------------------------------------------------------

    /// @notice No silent downgrade: with no aggregator wired there is no way to read exit notices, so a
    ///         staked set cannot be judged and the snapshot fails closed.
    function test_snapshot_fails_closed_when_no_aggregator_is_wired() public {
        StakeAwareMock w = new StakeAwareMock();
        w.setRegistry(address(reg));
        w.setMinStake(MIN_STAKE);
        w.setRequireStake(true);
        // deliberately NOT calling w.setBlsAggregator
        w.setEpochLength(EPOCH_LEN);
        vm.prank(OP_A);
        w.registerWithProof(V1_PUB, V1_POP_POINT, V1_POP_SIG);
        vm.roll(EPOCH_LEN + 1);
        vm.setBlockhash(EPOCH_LEN, bytes32(uint256(0xAA)));
        bytes32[] memory ids = w.activeNodeIdsSorted();
        // Fails closed on the authority check before it even reaches eligibility — a validator that
        // was never pointed at an aggregator cannot judge exit notices at all.
        vm.expectRevert("aggregator stale: re-run setBlsAggregator");
        w.snapshotEpoch(ids);
    }

    function test_setBlsAggregator_rejects_zero_and_codeless_and_wrong_surface() public {
        vm.expectRevert("aggregator must be non-zero");
        v.setBlsAggregator(address(0));
        vm.expectRevert("aggregator has no code");
        v.setBlsAggregator(address(0xDEAD));
    }

    /// @notice The ABI sanity check is reachable only AFTER identity passes, so exercise it with an
    ///         address the Registry really does publish but which does not implement the ledger.
    function test_setBlsAggregator_rejects_a_published_address_without_the_getter() public {
        NotAnAggregator bad = new NotAnAggregator();
        reg.setBLSAggregator(address(bad)); // Registry publishes it, so identity passes
        vm.expectRevert("aggregator has no guardianExitRequests(address)");
        v.setBlsAggregator(address(bad));
    }

    /// @notice Identity comes from the Registry, not from an ABI probe: a contract with a fallback
    ///         returning 64 zero bytes passes the probe while implementing none of the ledger
    ///         semantics. Only the address the Registry publishes is accepted.
    function test_setBlsAggregator_rejects_an_address_the_Registry_does_not_publish() public {
        ExitNoticeAggregator impostor = new ExitNoticeAggregator(); // perfect ABI, wrong identity
        vm.expectRevert("aggregator != Registry.blsAggregator()");
        v.setBlsAggregator(address(impostor));
    }

    /// @notice And once SP rotates, the snapshot fails CLOSED until the owner re-points the validator —
    ///         rather than silently reading a stale ledger that reports no exit notices.
    function test_snapshot_fails_closed_when_the_Registry_aggregator_moved_ahead() public {
        ExitNoticeAggregator successor = new ExitNoticeAggregator();
        reg.setBLSAggregator(address(successor)); // SP rotated; validator not re-pointed yet
        _expectSnapRevert(1, "aggregator stale: re-run setBlsAggregator");

        v.setBlsAggregator(address(successor));
        _snap(1);
        assertEq(v.epochSetCount(1), 2, "works again once re-pointed");
    }

    /// @notice Rotation is expected (SP queues/applies a new aggregator; CC-115 B3 is a successor
    ///         deployment), so a change must invalidate snapshots judged against the OLD one.
    function test_rotating_the_aggregator_bumps_configVersion_and_fails_old_snapshots_closed() public {
        _snap(1);
        vm.roll(EPOCH_LEN + 5);
        assertTrue(v.exposedEpochUsable(1), "usable before rotation (so the assertion below is not vacuous)");
        uint256 cv = v.configVersion();
        assertTrue(v.epochPinned(1), "epoch 1 pinned");
        assertEq(v.epochConfigVersion(1), cv, "pinned under the current config");

        ExitNoticeAggregator successor = new ExitNoticeAggregator();
        reg.setBLSAggregator(address(successor)); // SP rotates first
        v.setBlsAggregator(address(successor));
        assertEq(v.configVersion(), cv + 1, "rotation bumps configVersion");
        assertTrue(v.epochPinned(1), "the pin record survives...");
        assertTrue(v.epochConfigVersion(1) != v.configVersion(), "...but no longer matches, so it is unusable");
        // Asserting the quorum sentinel here would be vacuous on a 2-node fixture (it is already the
        // sentinel because the pool is under minCommittee). Assert usability directly instead.
        assertFalse(v.exposedEpochUsable(1), "the old snapshot is no longer usable after rotation");
    }

    // --- epochLength bound vs SP's 2-day exit notice ------------------------------------------------

    // --- H3: the bond is enforced on the CLOCK, not on a block count -------------------------------

    /// @notice A frozen set is usable only while SP still guarantees its members are bonded. An earlier
    ///         revision tried to get this from a block count with a MINIMUM block time, which is the
    ///         wrong direction — bounding how long 2L blocks take needs an UPPER bound, and at 12s/block
    ///         the accepted L spanned ~24 days. Recording a wall-clock deadline makes the guarantee hold
    ///         at any block time, and survive a chain halt.
    function test_frozen_set_expires_after_the_exit_notice_window() public {
        _snap(1);
        _snap(2);
        vm.roll(2 * EPOCH_LEN + 5);
        assertTrue(v.exposedEpochUsable(1), "usable inside the bond window");

        uint256 deadline = v.epochSetValidUntil(1);
        assertEq(deadline, block.timestamp + 2 days, "deadline is freeze time + GUARDIAN_EXIT_DELAY");

        vm.warp(deadline + 1);
        assertFalse(v.exposedEpochUsable(1), "past the bond window the snapshot stops being usable");
        assertEq(v.requiredQuorum(), type(uint256).max, "...and the quorum sentinel follows");
    }

    /// @notice The boundary is STRICT. SP admits an exit at `block.timestamp == readyAt`, and a node
    ///         that was clean at freeze time (readyAt == 0 is required) and filed in that same second
    ///         matures at exactly `freezeTime + GUARDIAN_EXIT_DELAY` — which is this deadline. So at
    ///         the deadline itself the stake may already be gone, and the snapshot must be unusable.
    function test_frozen_set_is_unusable_AT_the_deadline_not_just_after() public {
        _snap(1);
        _snap(2);
        vm.roll(2 * EPOCH_LEN + 5);
        uint256 deadline = v.epochSetValidUntil(1);
        vm.warp(deadline - 1);
        assertTrue(v.exposedEpochUsable(1), "usable one second before the deadline");
        vm.warp(deadline);
        assertFalse(v.exposedEpochUsable(1), "NOT usable at the deadline itself");
    }

    /// @notice A chain halt longer than the window expires the set rather than letting it outlive the
    ///         guarantee — the case a block-count bound cannot express at all.
    function test_a_chain_halt_expires_the_frozen_set() public {
        _snap(1);
        _snap(2);
        vm.roll(2 * EPOCH_LEN + 5);
        vm.warp(block.timestamp + 3 days); // blocks barely advanced; wall clock did
        assertFalse(v.exposedEpochUsable(1), "fail-closed after the halt");
        assertFalse(v.exposedEpochUsable(2), "both snapshots expire on the clock");
    }

    /// @notice The removed bound must NOT come back: a large epochLength is accepted, because safety no
    ///         longer depends on how many blocks fit in two days.
    function test_setEpochLength_no_longer_imposes_a_block_count_bound() public {
        v.setEpochLength(200000);
        assertEq(v.epochLength(), 200000, "no block-count ceiling");
    }

    function test_setEpochLength_still_allows_disabling_and_the_floor() public {
        v.setEpochLength(0);
        assertEq(v.epochLength(), 0, "committee mode can still be switched off");
        vm.expectRevert("epochLength must be 0 or >= 64");
        v.setEpochLength(63);
    }
}
