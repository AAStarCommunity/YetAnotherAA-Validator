// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

/// @dev The parts of SuperPaymaster's BLSAggregator this registry reads.
interface IBLSAggregatorView {
    function domainSeparator() external view returns (bytes32);
    function proposalSignersCommitment(uint256 key) external view returns (bytes32);
}

/// @dev xPNTs community token: who may reply on a community's behalf.
interface ICommunityToken {
    function communityOwner() external view returns (address);
}

/**
 * @title DisclosureRegistry
 * @notice Append-only, on-chain record of guardian-quorum actions that the DVT watcher discloses
 *         (SuperPaymaster 5.5.0 guardian accountability: disclosure, no on-chain slashing; see
 *         docs/design/guardian-accountability-5.5.0.md §4).
 *
 *         What is VERIFIED on-chain at write time, against the aggregator's BLS signer commitment:
 *           - the message the guardians signed, recomputed from the supplied inputs exactly as the
 *             aggregator builds it for that path (so target, calldata hash, threshold, operator,
 *             level, epoch, evidence hash, reputation batch are facts, not claims);
 *           - the signer set (addresses + mask) that produced the commitment;
 *           - the execution block, when its parent is still inside the EIP-2935 history window and
 *             the commitment carries the parent-block anchor.
 *         What stays a CLAIM: the transaction hash, the block when `blockVerified == false`, the
 *         off-chain record behind `recordURI`, and the interpretation of why the action is
 *         misbehaviour. Readers must treat every entry as a claim to recheck.
 *
 *         No admin, no owner, no upgrade, no delete, no edit. A lost writer key or a new aggregator
 *         means a new registry; the release manifest pins the current one.
 *
 * @dev PENDING SP rc.8 r3a/r3b — the commitment storage KEY per path and the exact commitment
 *      TUPLE (anchor position) are taken from SP's stated intent and MUST be re-checked against the
 *      implemented BLSAggregator before this contract is frozen. They live only in `commitmentKey`
 *      and `expectedCommitment`.
 */
contract DisclosureRegistry {
    // ---- aggregator constants (byte-identical to SuperPaymaster BLSAggregator) ----
    bytes32 internal constant TAG_QUEUE_SLASH = keccak256("SuperPaymaster.BLS.QueueSlash.v1");
    bytes32 internal constant TAG_EXECUTE_SLASH = keccak256("SuperPaymaster.BLS.ExecuteSlash.v1");
    bytes32 internal constant TAG_REPUTATION = keccak256("SuperPaymaster.BLS.Reputation.v1");
    bytes32 internal constant TAG_PROPOSAL = keccak256("SuperPaymaster.BLS.Proposal.v1");
    bytes32 internal constant TAG_SIGNERS_COMMITMENT = keccak256("SuperPaymaster.BLS.SignersCommitment.v1");
    /// @dev PENDING SP: typed slash key (byte priority 4). If SP ships the raw slash id instead,
    ///      `commitmentKey` changes for SLASH/REPUTATION.
    bytes32 internal constant TAG_SLASH = keccak256("SuperPaymaster.BLS.Slash.v1");

    /// @dev EIP-2935 history contract; same address and code on OP Mainnet, OP Sepolia, Sepolia.
    address internal constant HISTORY = 0x0000F90827F1C53a10cb7A02335B175320002935;
    uint256 internal constant HISTORY_WINDOW = 8191;

    uint256 internal constant MAX_SIGNERS = 256; // signerMask is a uint256

    enum Kind {
        SLASH, // verifyAndExecute, slash-only branch
        GENERIC, // executeProposal
        QUEUE, // queueSlashWithConsensus
        REPUTATION // verifyAndExecute, reputation branch
    }

    address public immutable WRITER;
    IBLSAggregatorView public immutable AGGREGATOR;

    /// @notice Number of primary entries written so far (entry ids are 1-based).
    uint256 public entryCount;
    /// @notice keccak256(abi.encode(kind, key, subjectToken)) per entry; a reply must match it.
    mapping(uint256 => bytes32) public entryBinding;

    struct Signed {
        Kind kind;
        uint256 proposalId; // ignored (must be 0) for QUEUE
        bytes messageInputs; // per-kind, see messageHashOf
        uint256 signerMask;
        address[] signers; // strictly ascending by uint160
        bytes32 anchor; // blockhash(executionBlock - 1) as committed by the aggregator
    }

    event Disclosed(
        uint256 indexed entryId,
        Kind indexed kind,
        uint256 indexed key,
        uint256 proposalId,
        bytes32 messageHash,
        address[] signers,
        address subjectToken,
        bytes32 txHash,
        uint64 blockNumber,
        bool blockVerified,
        bytes20 rulesetCommit,
        string recordURI,
        bytes32 recordHash
    );

    event Replied(uint256 indexed entryId, address indexed replier, string replyURI, bytes32 replyHash);

    error NotWriter();
    error ZeroAddress();
    error BadKind();
    error BadProposalId();
    error BadSigners();
    error CommitmentMismatch();
    error AnchorMismatch();
    error UnknownEntry();
    error BindingMismatch();
    error NotAccused();

    constructor(address writer, address aggregator) {
        if (writer == address(0) || aggregator == address(0)) revert ZeroAddress();
        WRITER = writer;
        AGGREGATOR = IBLSAggregatorView(aggregator);
    }

    // ------------------------------------------------------------------------------------------
    //                                     write paths
    // ------------------------------------------------------------------------------------------

    /// @notice Append a primary entry. Only the watcher (WRITER). Reverts unless the signer set and
    ///         message reproduce the aggregator's commitment for this path.
    function disclose(
        Signed calldata s,
        address subjectToken,
        bytes32 txHash,
        uint64 blockNumber,
        bytes20 rulesetCommit,
        string calldata recordURI,
        bytes32 recordHash
    ) external returns (uint256 entryId) {
        if (msg.sender != WRITER) revert NotWriter();
        (uint256 key, bytes32 messageHash) = _verifySigned(s);
        bool blockVerified = _verifyBlock(blockNumber, s.anchor);

        entryId = ++entryCount;
        entryBinding[entryId] = keccak256(abi.encode(s.kind, key, subjectToken));
        emit Disclosed(
            entryId,
            s.kind,
            key,
            s.proposalId,
            messageHash,
            s.signers,
            subjectToken,
            txHash,
            blockNumber,
            blockVerified,
            rulesetCommit,
            recordURI,
            recordHash
        );
    }

    /// @notice Right of reply. The caller must be one of the proven signers of the entry's action,
    ///         or the community owner of the entry's subject token. Appends only.
    function reply(
        uint256 entryId,
        Signed calldata s,
        address subjectToken,
        string calldata replyURI,
        bytes32 replyHash
    ) external {
        bytes32 binding = entryBinding[entryId];
        if (binding == bytes32(0)) revert UnknownEntry();
        (uint256 key,) = _verifySigned(s);
        if (keccak256(abi.encode(s.kind, key, subjectToken)) != binding) revert BindingMismatch();

        bool accused;
        for (uint256 i = 0; i < s.signers.length; i++) {
            if (s.signers[i] == msg.sender) {
                accused = true;
                break;
            }
        }
        if (!accused && subjectToken != address(0) && subjectToken.code.length != 0) {
            try ICommunityToken(subjectToken).communityOwner() returns (address owner_) {
                accused = owner_ == msg.sender && owner_ != address(0);
            } catch {}
        }
        if (!accused) revert NotAccused();
        emit Replied(entryId, msg.sender, replyURI, replyHash);
    }

    // ------------------------------------------------------------------------------------------
    //                                   verification
    // ------------------------------------------------------------------------------------------

    function _verifySigned(Signed calldata s) internal view returns (uint256 key, bytes32 messageHash) {
        bytes32 ds = AGGREGATOR.domainSeparator();
        if (s.kind == Kind.QUEUE) {
            if (s.proposalId != 0) revert BadProposalId();
        } else if (s.proposalId == 0) {
            revert BadProposalId();
        }
        messageHash = messageHashOf(ds, s.kind, s.proposalId, s.messageInputs);
        key = commitmentKey(s.kind, s.proposalId, messageHash);

        _checkSigners(s.signerMask, s.signers);
        bytes32 onchain = AGGREGATOR.proposalSignersCommitment(key);
        if (
            onchain == bytes32(0)
                || onchain != expectedCommitment(ds, key, messageHash, s.signerMask, s.signers, s.anchor)
        ) {
            revert CommitmentMismatch();
        }
    }

    /// @dev Non-empty, strictly ascending, no zero address, length == popcount(mask) <= 256.
    function _checkSigners(uint256 mask, address[] calldata signers) internal pure {
        uint256 n = signers.length;
        if (n == 0 || n > MAX_SIGNERS) revert BadSigners();
        uint256 bits;
        uint256 m = mask;
        while (m != 0) {
            m &= m - 1;
            bits++;
        }
        if (bits != n) revert BadSigners();
        uint160 prev;
        for (uint256 i = 0; i < n; i++) {
            uint160 a = uint160(signers[i]);
            if (a <= prev) revert BadSigners(); // also rejects address(0) at i == 0
            prev = a;
        }
    }

    /// @dev True when `blockNumber - 1` is inside the EIP-2935 window and its hash equals `anchor`.
    ///      Outside the window: false (no revert). Inside the window with a different hash: revert,
    ///      because the commitment's anchor proves the execution was not at `blockNumber`.
    function _verifyBlock(uint64 blockNumber, bytes32 anchor) internal view returns (bool) {
        if (anchor == bytes32(0) || blockNumber == 0) return false;
        uint256 parent = uint256(blockNumber) - 1;
        if (parent >= block.number || block.number - parent > HISTORY_WINDOW) return false;
        (bool ok, bytes memory ret) = HISTORY.staticcall(abi.encode(parent));
        if (!ok || ret.length != 32) return false;
        if (abi.decode(ret, (bytes32)) != anchor) revert AnchorMismatch();
        return true;
    }

    // ------------------------------------------------------------------------------------------
    //                       aggregator mirrors (byte-identical; see PENDING above)
    // ------------------------------------------------------------------------------------------

    /// @notice The message the guardians signed on each path, as BLSAggregator builds it.
    ///   SLASH      inputs = abi.encode(address operator, uint8 slashLevel, uint256 epoch, bytes32 evidenceHash)
    ///   GENERIC    inputs = abi.encode(address target, bytes32 callDataHash, uint256 requiredThreshold)
    ///   QUEUE      inputs = abi.encode(address operator, uint8 slashLevel, uint256 epoch)
    ///   REPUTATION inputs = abi.encode(address[] users, uint256[] newScores, uint256 epoch)
    function messageHashOf(bytes32 ds, Kind kind, uint256 proposalId, bytes calldata inputs)
        public
        pure
        returns (bytes32)
    {
        if (kind == Kind.SLASH) {
            (address operator, uint8 level, uint256 epoch, bytes32 evidenceHash) =
                abi.decode(inputs, (address, uint8, uint256, bytes32));
            return keccak256(abi.encode(ds, TAG_EXECUTE_SLASH, proposalId, operator, level, epoch, evidenceHash));
        }
        if (kind == Kind.GENERIC) {
            (address target, bytes32 callDataHash, uint256 threshold) = abi.decode(inputs, (address, bytes32, uint256));
            return keccak256(abi.encode(ds, TAG_PROPOSAL, proposalId, target, callDataHash, threshold));
        }
        if (kind == Kind.QUEUE) {
            (address operator, uint8 level, uint256 epoch) = abi.decode(inputs, (address, uint8, uint256));
            return keccak256(abi.encode(ds, TAG_QUEUE_SLASH, operator, level, epoch));
        }
        if (kind == Kind.REPUTATION) {
            (address[] memory users, uint256[] memory scores, uint256 epoch) =
                abi.decode(inputs, (address[], uint256[], uint256));
            return keccak256(abi.encode(ds, TAG_REPUTATION, proposalId, users, scores, epoch));
        }
        revert BadKind();
    }

    /// @notice Storage key of `proposalSignersCommitment` per path. PENDING SP final scheme.
    function commitmentKey(Kind kind, uint256 proposalId, bytes32 messageHash) public pure returns (uint256) {
        if (kind == Kind.GENERIC) return uint256(keccak256(abi.encode(TAG_PROPOSAL, proposalId)));
        if (kind == Kind.QUEUE) return uint256(messageHash);
        return uint256(keccak256(abi.encode(TAG_SLASH, proposalId))); // SLASH and REPUTATION
    }

    /// @notice The commitment tuple. PENDING SP final tuple (storage key in the id position,
    ///         parent-block anchor appended).
    function expectedCommitment(
        bytes32 ds,
        uint256 key,
        bytes32 messageHash,
        uint256 signerMask,
        address[] calldata signers,
        bytes32 anchor
    ) public pure returns (bytes32) {
        return keccak256(abi.encode(ds, TAG_SIGNERS_COMMITMENT, key, messageHash, signerMask, signers, anchor));
    }
}
