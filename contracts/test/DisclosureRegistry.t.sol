// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {DisclosureRegistry} from "../src/disclosure/DisclosureRegistry.sol";

/// @dev Stands in for SuperPaymaster's BLSAggregator. It computes the signer commitment the way SP
///      does — signers resolved from `signerMask` through a slot table, then insertion-sorted — so
///      the registry (which takes a caller-supplied sorted list) is checked against an independent
///      derivation, not against its own code. Key and tuple follow SP's stated rc.8 intent; when SP
///      lands the implemented tuple, this mock and DisclosureRegistry change together.
contract MockAggregator {
    bytes32 public constant DOMAIN_NAME = keccak256("SuperPaymaster.BLSConsensus.v1");
    bytes32 public constant TAG_SIGNERS_COMMITMENT = keccak256("SuperPaymaster.BLS.SignersCommitment.v1");
    address public immutable REGISTRY;
    mapping(uint8 => address) public validatorAtSlot;
    mapping(uint256 => bytes32) public proposalSignersCommitment;

    constructor(address registry) {
        REGISTRY = registry;
    }

    function domainSeparator() public view returns (bytes32) {
        return keccak256(abi.encode(DOMAIN_NAME, block.chainid, address(this), REGISTRY));
    }

    function setSlot(uint8 slot, address v) external {
        validatorAtSlot[slot] = v;
    }

    /// @notice Record what SP's aggregator would store after a successful execution.
    function record(uint256 key, bytes32 messageHash, uint256 signerMask, bytes32 anchor) external {
        uint256 n;
        for (uint256 m = signerMask; m != 0; m &= m - 1) {
            n++;
        }
        address[] memory signers = new address[](n);
        uint256 k;
        for (uint16 slot = 1; slot <= 255; slot++) {
            if ((signerMask >> (slot - 1)) & 1 == 1) signers[k++] = validatorAtSlot[uint8(slot)];
        }
        for (uint256 i = 1; i < n; i++) {
            address key_ = signers[i];
            uint256 j = i;
            while (j > 0 && uint160(signers[j - 1]) > uint160(key_)) {
                signers[j] = signers[j - 1];
                j--;
            }
            signers[j] = key_;
        }
        proposalSignersCommitment[key] = keccak256(
            abi.encode(domainSeparator(), TAG_SIGNERS_COMMITMENT, key, messageHash, signerMask, signers, anchor)
        );
    }
}

/// @dev EIP-2935 stand-in etched at the history address: returns a stored hash for an input block.
contract MockHistory {
    mapping(uint256 => bytes32) public h;

    function set(uint256 n, bytes32 v) external {
        h[n] = v;
    }

    fallback(bytes calldata data) external returns (bytes memory) {
        uint256 n = abi.decode(data, (uint256));
        bytes32 v = h[n];
        require(v != bytes32(0), "no history");
        return abi.encode(v);
    }
}

contract CommunityToken {
    address public communityOwner;

    constructor(address o) {
        communityOwner = o;
    }
}

contract DisclosureRegistryTest is Test {
    address constant HISTORY = 0x0000F90827F1C53a10cb7A02335B175320002935;

    DisclosureRegistry reg;
    MockAggregator agg;
    address writer = makeAddr("watcher");
    address[] guardians; // slot i+1 -> guardians[i]

    bytes32 constant ANCHOR = keccak256("parent-block");
    uint64 constant EXEC_BLOCK = 1_000_000;

    function setUp() public {
        agg = new MockAggregator(makeAddr("spRegistry"));
        reg = new DisclosureRegistry(writer, address(agg));
        for (uint8 i = 0; i < 5; i++) {
            address g = address(uint160(uint256(keccak256(abi.encode("guardian", i)))));
            guardians.push(g);
            agg.setSlot(i + 1, g);
        }
        MockHistory hist = new MockHistory();
        vm.etch(HISTORY, address(hist).code);
        MockHistory(HISTORY).set(EXEC_BLOCK - 1, ANCHOR);
        vm.roll(EXEC_BLOCK + 10);
    }

    // ---------------------------------------------------------------- helpers

    /// signers for a mask, sorted ascending (what the watcher derives off-chain)
    function _signers(uint256 mask) internal view returns (address[] memory s) {
        uint256 n;
        for (uint256 m = mask; m != 0; m &= m - 1) {
            n++;
        }
        s = new address[](n);
        uint256 k;
        for (uint256 i = 0; i < guardians.length; i++) {
            if ((mask >> i) & 1 == 1) s[k++] = guardians[i];
        }
        for (uint256 i = 1; i < n; i++) {
            address x = s[i];
            uint256 j = i;
            while (j > 0 && uint160(s[j - 1]) > uint160(x)) {
                s[j] = s[j - 1];
                j--;
            }
            s[j] = x;
        }
    }

    function _signed(DisclosureRegistry.Kind kind, uint256 id, bytes memory inputs, uint256 mask)
        internal
        view
        returns (DisclosureRegistry.Signed memory s)
    {
        s.kind = kind;
        s.proposalId = id;
        s.messageInputs = inputs;
        s.signerMask = mask;
        s.signers = _signers(mask);
        s.anchor = ANCHOR;
    }

    /// Execute on the mock aggregator (records the commitment) and return the matching Signed.
    /// The message hash and storage key are computed HERE, from SP's source, not from the
    /// registry — otherwise a registry bug would be mirrored into the expected commitment.
    function _executed(DisclosureRegistry.Kind kind, uint256 id, bytes memory inputs, uint256 mask)
        internal
        returns (DisclosureRegistry.Signed memory s)
    {
        s = _signed(kind, id, inputs, mask);
        bytes32 mh = _spMessageHash(kind, id, inputs);
        agg.record(_spKey(kind, id, mh), mh, mask, ANCHOR);
    }

    /// SuperPaymaster BLSAggregator message preimages (origin/main 20617a9c:
    /// verifyAndExecute slash branch, _reputationMessageHash, executeProposal, queueSlashWithConsensus).
    function _spMessageHash(DisclosureRegistry.Kind kind, uint256 id, bytes memory inputs)
        internal
        view
        returns (bytes32)
    {
        bytes32 ds = agg.domainSeparator();
        if (kind == DisclosureRegistry.Kind.SLASH) {
            (address op, uint8 lvl, uint256 ep, bytes32 ev) = abi.decode(inputs, (address, uint8, uint256, bytes32));
            return keccak256(abi.encode(ds, keccak256("SuperPaymaster.BLS.ExecuteSlash.v1"), id, op, lvl, ep, ev));
        }
        if (kind == DisclosureRegistry.Kind.GENERIC) {
            (address t, bytes32 ch, uint256 th) = abi.decode(inputs, (address, bytes32, uint256));
            return keccak256(abi.encode(ds, keccak256("SuperPaymaster.BLS.Proposal.v1"), id, t, ch, th));
        }
        if (kind == DisclosureRegistry.Kind.QUEUE) {
            (address op, uint8 lvl, uint256 ep) = abi.decode(inputs, (address, uint8, uint256));
            return keccak256(abi.encode(ds, keccak256("SuperPaymaster.BLS.QueueSlash.v1"), op, lvl, ep));
        }
        (address[] memory u, uint256[] memory sc, uint256 e) = abi.decode(inputs, (address[], uint256[], uint256));
        return keccak256(abi.encode(ds, keccak256("SuperPaymaster.BLS.Reputation.v1"), id, u, sc, e));
    }

    /// Storage key per path — BLSAggregator-4.13.0 r3b as SP reported it from code
    /// (PENDING re-check against SP's committed SHA).
    function _spKey(DisclosureRegistry.Kind kind, uint256 id, bytes32 mh) internal pure returns (uint256) {
        if (kind == DisclosureRegistry.Kind.GENERIC) {
            return uint256(keccak256(abi.encode(keccak256("SuperPaymaster.BLS.Proposal.v1"), id)));
        }
        if (kind == DisclosureRegistry.Kind.QUEUE) return uint256(mh);
        return id; // slash and reputation: raw id, < 2^128
    }

    function _slashInputs() internal returns (bytes memory) {
        return abi.encode(makeAddr("operator"), uint8(1), uint256(42), keccak256("evidence"));
    }

    function _genericInputs() internal returns (bytes memory) {
        return abi.encode(makeAddr("target"), keccak256("calldata"), uint256(3));
    }

    function _queueInputs() internal returns (bytes memory) {
        return abi.encode(makeAddr("operator"), uint8(1), uint256(42));
    }

    function _repInputs() internal returns (bytes memory) {
        address[] memory u = new address[](2);
        u[0] = makeAddr("u0");
        u[1] = makeAddr("u1");
        uint256[] memory sc = new uint256[](2);
        sc[0] = 10;
        sc[1] = 20;
        return abi.encode(u, sc, uint256(7));
    }

    function _disclose(DisclosureRegistry.Signed memory s) internal returns (uint256) {
        vm.prank(writer);
        return reg.disclose(s, address(0), keccak256("tx"), EXEC_BLOCK, bytes20(uint160(0xabc)), "repo://r", bytes32(0));
    }

    // ---------------------------------------------------------------- accepted, every kind

    function test_acceptsCorrectSet_allKinds() public {
        assertEq(_disclose(_executed(DisclosureRegistry.Kind.SLASH, 11, _slashInputs(), 0x7)), 1);
        assertEq(_disclose(_executed(DisclosureRegistry.Kind.GENERIC, 11, _genericInputs(), 0x7)), 2);
        assertEq(_disclose(_executed(DisclosureRegistry.Kind.QUEUE, 0, _queueInputs(), 0x3)), 3);
        assertEq(_disclose(_executed(DisclosureRegistry.Kind.REPUTATION, 12, _repInputs(), 0x1f)), 4);
        assertEq(reg.entryCount(), 4);
    }

    function test_emitsBlockVerifiedTrueInsideWindow() public {
        DisclosureRegistry.Signed memory s = _executed(DisclosureRegistry.Kind.GENERIC, 5, _genericInputs(), 0x7);
        vm.recordLogs();
        _disclose(s);
        Vm.Log[] memory logs = vm.getRecordedLogs();
        // non-indexed data: proposalId, messageHash, signers, subjectToken, txHash, blockNumber,
        // blockVerified, rulesetCommit, recordURI, recordHash
        (uint256 pid, bytes32 mh, address[] memory sg, address subj, bytes32 txh, uint64 bn, bool bv,,,) = abi.decode(
            logs[0].data, (uint256, bytes32, address[], address, bytes32, uint64, bool, bytes20, string, bytes32)
        );
        assertEq(pid, 5);
        assertTrue(mh != bytes32(0));
        assertEq(sg.length, 3);
        assertEq(subj, address(0));
        assertEq(txh, keccak256("tx"));
        assertEq(bn, EXEC_BLOCK);
        assertTrue(bv, "block inside window and anchor matches");
    }

    // ---------------------------------------------------------------- signer set

    function test_revertsOnSwappedSigner() public {
        DisclosureRegistry.Signed memory s = _executed(DisclosureRegistry.Kind.SLASH, 11, _slashInputs(), 0x7);
        // replace one signer with a non-signer, keep sorted order
        address[] memory alt = _signers(0xb); // slots 1,2,4 instead of 1,2,3
        s.signers = alt;
        vm.prank(writer);
        vm.expectRevert(DisclosureRegistry.CommitmentMismatch.selector);
        reg.disclose(s, address(0), bytes32(0), EXEC_BLOCK, bytes20(0), "", bytes32(0));
    }

    function test_revertsOnMaskNotMatchingCommitment() public {
        DisclosureRegistry.Signed memory s = _executed(DisclosureRegistry.Kind.SLASH, 11, _slashInputs(), 0x7);
        s.signerMask = 0xb; // same popcount, different slots
        vm.prank(writer);
        vm.expectRevert(DisclosureRegistry.CommitmentMismatch.selector);
        reg.disclose(s, address(0), bytes32(0), EXEC_BLOCK, bytes20(0), "", bytes32(0));
    }

    function test_revertsOnUnsortedOrDuplicateOrCountMismatch() public {
        DisclosureRegistry.Signed memory s = _executed(DisclosureRegistry.Kind.SLASH, 11, _slashInputs(), 0x7);
        address[] memory sg = s.signers;
        (sg[0], sg[1]) = (sg[1], sg[0]);
        vm.prank(writer);
        vm.expectRevert(DisclosureRegistry.BadSigners.selector);
        reg.disclose(s, address(0), bytes32(0), EXEC_BLOCK, bytes20(0), "", bytes32(0));

        s = _executed(DisclosureRegistry.Kind.SLASH, 11, _slashInputs(), 0x7);
        s.signers[1] = s.signers[0];
        vm.prank(writer);
        vm.expectRevert(DisclosureRegistry.BadSigners.selector);
        reg.disclose(s, address(0), bytes32(0), EXEC_BLOCK, bytes20(0), "", bytes32(0));

        s = _executed(DisclosureRegistry.Kind.SLASH, 11, _slashInputs(), 0x7);
        s.signerMask = 0xf; // 4 bits, 3 signers
        vm.prank(writer);
        vm.expectRevert(DisclosureRegistry.BadSigners.selector);
        reg.disclose(s, address(0), bytes32(0), EXEC_BLOCK, bytes20(0), "", bytes32(0));
    }

    // ---------------------------------------------------------------- message fields are verified

    function test_revertsOnWrongMessageFields() public {
        DisclosureRegistry.Signed memory s = _executed(DisclosureRegistry.Kind.GENERIC, 11, _genericInputs(), 0x7);
        s.messageInputs = abi.encode(makeAddr("otherTarget"), keccak256("calldata"), uint256(3));
        vm.prank(writer);
        vm.expectRevert(DisclosureRegistry.CommitmentMismatch.selector);
        reg.disclose(s, address(0), bytes32(0), EXEC_BLOCK, bytes20(0), "", bytes32(0));

        s.messageInputs = abi.encode(makeAddr("target"), keccak256("other calldata"), uint256(3));
        vm.prank(writer);
        vm.expectRevert(DisclosureRegistry.CommitmentMismatch.selector);
        reg.disclose(s, address(0), bytes32(0), EXEC_BLOCK, bytes20(0), "", bytes32(0));

        DisclosureRegistry.Signed memory q = _executed(DisclosureRegistry.Kind.SLASH, 11, _slashInputs(), 0x7);
        q.messageInputs = abi.encode(makeAddr("operator"), uint8(2), uint256(42), keccak256("evidence"));
        vm.prank(writer);
        vm.expectRevert(DisclosureRegistry.CommitmentMismatch.selector);
        reg.disclose(q, address(0), bytes32(0), EXEC_BLOCK, bytes20(0), "", bytes32(0));
    }

    function test_revertsOnWrongAnchor() public {
        DisclosureRegistry.Signed memory s = _executed(DisclosureRegistry.Kind.SLASH, 11, _slashInputs(), 0x7);
        s.anchor = keccak256("other");
        vm.prank(writer);
        vm.expectRevert(DisclosureRegistry.CommitmentMismatch.selector);
        reg.disclose(s, address(0), bytes32(0), EXEC_BLOCK, bytes20(0), "", bytes32(0));
    }

    function test_revertsOnUnexecutedProposal() public {
        DisclosureRegistry.Signed memory s = _signed(DisclosureRegistry.Kind.SLASH, 99, _slashInputs(), 0x7);
        vm.prank(writer);
        vm.expectRevert(DisclosureRegistry.CommitmentMismatch.selector);
        reg.disclose(s, address(0), bytes32(0), EXEC_BLOCK, bytes20(0), "", bytes32(0));
    }

    /// A commitment recorded on one path cannot be disclosed as another path's action.
    function test_noCrossPathReuse() public {
        DisclosureRegistry.Signed memory s = _executed(DisclosureRegistry.Kind.GENERIC, 11, _genericInputs(), 0x7);
        s.kind = DisclosureRegistry.Kind.SLASH;
        s.messageInputs = _slashInputs();
        vm.prank(writer);
        vm.expectRevert(DisclosureRegistry.CommitmentMismatch.selector);
        reg.disclose(s, address(0), bytes32(0), EXEC_BLOCK, bytes20(0), "", bytes32(0));
    }

    function test_proposalIdRules() public {
        DisclosureRegistry.Signed memory q = _executed(DisclosureRegistry.Kind.QUEUE, 0, _queueInputs(), 0x3);
        q.proposalId = 1;
        vm.prank(writer);
        vm.expectRevert(DisclosureRegistry.BadProposalId.selector);
        reg.disclose(q, address(0), bytes32(0), EXEC_BLOCK, bytes20(0), "", bytes32(0));

        DisclosureRegistry.Signed memory s = _signed(DisclosureRegistry.Kind.SLASH, 0, _slashInputs(), 0x7);
        vm.prank(writer);
        vm.expectRevert(DisclosureRegistry.BadProposalId.selector);
        reg.disclose(s, address(0), bytes32(0), EXEC_BLOCK, bytes20(0), "", bytes32(0));
    }

    /// A raw slash/reputation id >= 2^128 is rejected even when a commitment sits at that key —
    /// e.g. a generic action's typed key, which a reputation id must never be able to claim.
    function test_rawIdBoundRejectsCrossPathKey() public {
        DisclosureRegistry.Signed memory g = _executed(DisclosureRegistry.Kind.GENERIC, 5, _genericInputs(), 0x7);
        uint256 genericKey = _spKey(DisclosureRegistry.Kind.GENERIC, 5, bytes32(0));
        assertGe(genericKey, uint256(1) << 128);

        DisclosureRegistry.Signed memory s = _executed(DisclosureRegistry.Kind.SLASH, genericKey, _slashInputs(), 0x7);
        vm.prank(writer);
        vm.expectRevert(DisclosureRegistry.BadProposalId.selector);
        reg.disclose(s, address(0), bytes32(0), EXEC_BLOCK, bytes20(0), "", bytes32(0));

        // boundary: 2^128 - 1 is a valid raw id; 2^128 is not
        DisclosureRegistry.Signed memory ok =
            _executed(DisclosureRegistry.Kind.SLASH, (uint256(1) << 128) - 1, _slashInputs(), 0x7);
        vm.prank(writer);
        reg.disclose(ok, address(0), bytes32(0), EXEC_BLOCK, bytes20(0), "", bytes32(0));
        DisclosureRegistry.Signed memory bad =
            _executed(DisclosureRegistry.Kind.SLASH, uint256(1) << 128, _slashInputs(), 0x7);
        vm.prank(writer);
        vm.expectRevert(DisclosureRegistry.BadProposalId.selector);
        reg.disclose(bad, address(0), bytes32(0), EXEC_BLOCK, bytes20(0), "", bytes32(0));
        g; // generic entry executed only to place a commitment at genericKey
    }

    // ---------------------------------------------------------------- writer

    function test_onlyConstructorWriterMayDisclose() public {
        assertEq(reg.WRITER(), writer);
        DisclosureRegistry.Signed memory s = _executed(DisclosureRegistry.Kind.SLASH, 11, _slashInputs(), 0x7);
        vm.prank(makeAddr("stranger"));
        vm.expectRevert(DisclosureRegistry.NotWriter.selector);
        reg.disclose(s, address(0), bytes32(0), EXEC_BLOCK, bytes20(0), "", bytes32(0));
        vm.prank(guardians[0]);
        vm.expectRevert(DisclosureRegistry.NotWriter.selector);
        reg.disclose(s, address(0), bytes32(0), EXEC_BLOCK, bytes20(0), "", bytes32(0));
    }

    function test_constructorRejectsZero() public {
        vm.expectRevert(DisclosureRegistry.ZeroAddress.selector);
        new DisclosureRegistry(address(0), address(agg));
        vm.expectRevert(DisclosureRegistry.ZeroAddress.selector);
        new DisclosureRegistry(writer, address(0));
    }

    // ---------------------------------------------------------------- block binding

    function test_blockOutsideWindowIsUnverifiedNotReverted() public {
        DisclosureRegistry.Signed memory s = _executed(DisclosureRegistry.Kind.SLASH, 11, _slashInputs(), 0x7);
        vm.roll(EXEC_BLOCK + 9000);
        vm.recordLogs();
        _disclose(s);
        Vm.Log[] memory logs = vm.getRecordedLogs();
        (,,,,,, bool bv,,,) = abi.decode(
            logs[0].data, (uint256, bytes32, address[], address, bytes32, uint64, bool, bytes20, string, bytes32)
        );
        assertFalse(bv);
    }

    function test_blockInsideWindowWithWrongNumberReverts() public {
        DisclosureRegistry.Signed memory s = _executed(DisclosureRegistry.Kind.SLASH, 11, _slashInputs(), 0x7);
        MockHistory(HISTORY).set(EXEC_BLOCK, keccak256("a different block"));
        vm.prank(writer);
        vm.expectRevert(DisclosureRegistry.AnchorMismatch.selector);
        reg.disclose(s, address(0), bytes32(0), EXEC_BLOCK + 1, bytes20(0), "", bytes32(0));
    }

    // ---------------------------------------------------------------- right of reply

    function test_replyByAccusedSigner() public {
        DisclosureRegistry.Signed memory s = _executed(DisclosureRegistry.Kind.SLASH, 11, _slashInputs(), 0x7);
        uint256 id = _disclose(s);
        vm.prank(s.signers[1]);
        vm.expectEmit(true, true, false, true, address(reg));
        emit DisclosureRegistry.Replied(id, s.signers[1], "repo://reply", keccak256("r"));
        reg.reply(id, s, address(0), "repo://reply", keccak256("r"));
    }

    function test_replyByCommunityOwner() public {
        address owner_ = makeAddr("communityOwner");
        CommunityToken tok = new CommunityToken(owner_);
        DisclosureRegistry.Signed memory s = _executed(DisclosureRegistry.Kind.SLASH, 11, _slashInputs(), 0x7);
        vm.prank(writer);
        uint256 id = reg.disclose(s, address(tok), bytes32(0), EXEC_BLOCK, bytes20(0), "", bytes32(0));
        vm.prank(owner_);
        reg.reply(id, s, address(tok), "repo://reply", bytes32(0));
    }

    /// An entry that names a community token: only that community's owner (or a proven signer)
    /// may reply — a stranger, or the owner of a different community, may not.
    function test_replyOnCommunityEntryByNonOwnerReverts() public {
        CommunityToken tok = new CommunityToken(makeAddr("communityOwner"));
        DisclosureRegistry.Signed memory s = _executed(DisclosureRegistry.Kind.SLASH, 11, _slashInputs(), 0x7);
        vm.prank(writer);
        uint256 id = reg.disclose(s, address(tok), bytes32(0), EXEC_BLOCK, bytes20(0), "", bytes32(0));
        vm.prank(makeAddr("stranger"));
        vm.expectRevert(DisclosureRegistry.NotAccused.selector);
        reg.reply(id, s, address(tok), "", bytes32(0));

        CommunityToken otherTok = new CommunityToken(makeAddr("otherOwner"));
        vm.prank(makeAddr("otherOwner"));
        vm.expectRevert(DisclosureRegistry.BindingMismatch.selector);
        reg.reply(id, s, address(otherTok), "", bytes32(0));
    }

    function test_replyByStrangerReverts() public {
        DisclosureRegistry.Signed memory s = _executed(DisclosureRegistry.Kind.SLASH, 11, _slashInputs(), 0x7);
        uint256 id = _disclose(s);
        vm.prank(guardians[4]); // a guardian, but not a signer of this action
        vm.expectRevert(DisclosureRegistry.NotAccused.selector);
        reg.reply(id, s, address(0), "", bytes32(0));
    }

    function test_replyToMissingEntryOrOtherActionReverts() public {
        DisclosureRegistry.Signed memory s = _executed(DisclosureRegistry.Kind.SLASH, 11, _slashInputs(), 0x7);
        vm.prank(s.signers[0]);
        vm.expectRevert(DisclosureRegistry.UnknownEntry.selector);
        reg.reply(1, s, address(0), "", bytes32(0));

        uint256 id = _disclose(s);
        // a signer of a DIFFERENT executed action cannot reply under this entry
        DisclosureRegistry.Signed memory other = _executed(DisclosureRegistry.Kind.SLASH, 12, _slashInputs(), 0x18);
        vm.prank(other.signers[0]);
        vm.expectRevert(DisclosureRegistry.BindingMismatch.selector);
        reg.reply(id, other, address(0), "", bytes32(0));
    }

    function test_replyCannotForgeSignerSet() public {
        DisclosureRegistry.Signed memory s = _executed(DisclosureRegistry.Kind.SLASH, 11, _slashInputs(), 0x7);
        uint256 id = _disclose(s);
        // stranger inserts themself into the list: commitment no longer matches
        address stranger = address(1);
        s.signers[0] = stranger;
        vm.prank(stranger);
        vm.expectRevert();
        reg.reply(id, s, address(0), "", bytes32(0));
    }
}
