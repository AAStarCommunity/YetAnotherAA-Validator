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
 * @dev Key scheme and commitment tuple are BLSAggregator-4.13.0 (rc.8 r3b), checked line by line
 *      against SuperPaymaster cc125/rc8-bls @ f00be60374c5cc1d2c4c928a73cee90cf0e12e6c
 *      (contracts/src/modules/monitoring/BLSAggregator.sol: tuple :1376-1386, single write/emit in
 *      _commitSigners :1389-1391, keys :987 / :1072 / :1135, id bound :1006-1009, mask :1267/:1359).
 *      They live only in `commitmentKey` and `expectedCommitment`.
 */
contract DisclosureRegistry {
    // ---- aggregator constants (byte-identical to SuperPaymaster BLSAggregator) ----
    bytes32 internal constant TAG_QUEUE_SLASH = keccak256("SuperPaymaster.BLS.QueueSlash.v1");
    bytes32 internal constant TAG_EXECUTE_SLASH = keccak256("SuperPaymaster.BLS.ExecuteSlash.v1");
    bytes32 internal constant TAG_REPUTATION = keccak256("SuperPaymaster.BLS.Reputation.v1");
    bytes32 internal constant TAG_PROPOSAL = keccak256("SuperPaymaster.BLS.Proposal.v1");
    bytes32 internal constant TAG_SIGNERS_COMMITMENT = keccak256("SuperPaymaster.BLS.SignersCommitment.v1");
    /// @dev verifyAndExecute keys its commitment at the RAW proposalId and requires id < 2^128, so a
    ///      slash/reputation id can never equal a generic typed key or a queue message hash.
    uint256 internal constant RAW_ID_BOUND = 1 << 128;

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
    /// @notice The one primary entry of an action: keccak256(abi.encode(kind, key)) -> entryId (0 =
    ///         none). A guardian action is disclosed at most once, whatever the writer does; its
    ///         claim fields can only be corrected by `amend`, never by a second primary entry.
    mapping(bytes32 => uint256) public entryOf;

    struct Signed {
        Kind kind;
        uint256 proposalId; // ignored (must be 0) for QUEUE
        bytes messageInputs; // per-kind, see messageHashOf
        uint256 signerMask;
        address[] signers; // strictly ascending by uint160
        bytes32 anchor; // blockhash(executionBlock - 1) as committed by the aggregator
    }

    /// @dev The entry's context. `blockVerified` is checked on chain (EIP-2935); the other fields
    ///      are the writer's claims (see the recheck tool). Grouped so the event stays compilable
    ///      without viaIR (forge coverage).
    struct Record {
        address subjectToken;
        bytes32 txHash;
        uint64 blockNumber;
        bool blockVerified;
        bytes20 rulesetCommit;
        string recordURI;
        bytes32 recordHash;
    }

    event Disclosed(
        uint256 indexed entryId,
        Kind indexed kind,
        uint256 indexed key,
        uint256 proposalId,
        bytes32 messageHash,
        address[] signers,
        Record record
    );

    event Replied(uint256 indexed entryId, address indexed replier, string replyURI, bytes32 replyHash);

    /// @notice The writer's correction of an entry's CLAIM fields (record location and hash). It
    ///         never edits the primary entry; readers apply amendments in order. `reasonHash`
    ///         commits to a public explanation.
    event Amended(uint256 indexed entryId, string recordURI, bytes32 recordHash, bytes32 reasonHash);

    error NotWriter();
    error ZeroAddress();
    error BadKind();
    error NonCanonicalInputs();
    error BadProposalId();
    error BadSigners();
    error CommitmentMismatch();
    error AnchorMismatch();
    error UnknownEntry();
    error BindingMismatch();
    error NotAccused();
    error AlreadyDisclosed(uint256 entryId);

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
        entryId = _append(
            s,
            Record({
                subjectToken: subjectToken,
                txHash: txHash,
                blockNumber: blockNumber,
                blockVerified: false, // set in _append, after the signer check
                rulesetCommit: rulesetCommit,
                recordURI: recordURI,
                recordHash: recordHash
            })
        );
    }

    /// @dev Signer/message check first, then block binding, then append + emit. Split out of
    ///      `disclose` only to keep the stack shallow without viaIR.
    function _append(Signed calldata s, Record memory r) internal returns (uint256 entryId) {
        (uint256 key, bytes32 messageHash) = _verifySigned(s);
        r.blockVerified = _verifyBlock(r.blockNumber, s.anchor);
        bytes32 action = keccak256(abi.encode(s.kind, key));
        uint256 existing = entryOf[action];
        if (existing != 0) revert AlreadyDisclosed(existing);
        entryId = ++entryCount;
        entryOf[action] = entryId;
        entryBinding[entryId] = keccak256(abi.encode(s.kind, key, r.subjectToken));
        emit Disclosed(entryId, s.kind, key, s.proposalId, messageHash, s.signers, r);
    }

    /// @notice Correct the record location/hash of an existing entry (WRITER only, append-only).
    function amend(uint256 entryId, string calldata recordURI, bytes32 recordHash, bytes32 reasonHash) external {
        if (msg.sender != WRITER) revert NotWriter();
        if (entryBinding[entryId] == bytes32(0)) revert UnknownEntry();
        emit Amended(entryId, recordURI, recordHash, reasonHash);
    }

    /// @notice Right of reply. Appends only. The caller must be one of:
    ///         - a proven signer of the entry's action;
    ///         - a party the SIGNED message names, verified through the commitment: the operator of
    ///           a SLASH or QUEUE action, or a user of a REPUTATION batch;
    ///         - the `communityOwner()` of the entry's `subjectToken`. `subjectToken` is the writer's
    ///           CLAIM (no commitment covers it), so this route is only as good as the watcher.
    ///         For SLASH, QUEUE and REPUTATION the second route does not depend on the writer, so a
    ///         wrongly attributed entry cannot shut out the party the action named. A GENERIC action
    ///         commits only to `callDataHash`, so the parties its calldata affects are not
    ///         identifiable on chain; for GENERIC entries a non-signer can reply only through the
    ///         claimed `subjectToken` route.
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
        if (!accused) accused = _namedBySignedMessage(s.kind, s.messageInputs, msg.sender);
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
        } else if (s.kind != Kind.GENERIC && s.proposalId >= RAW_ID_BOUND) {
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

    /// @dev Whether `who` is a party the signed message itself names. Only called after `_verifySigned`
    ///      accepted `inputs`, so the names are covered by the guardians' commitment.
    function _namedBySignedMessage(Kind kind, bytes calldata inputs, address who) internal pure returns (bool) {
        if (kind == Kind.SLASH || kind == Kind.QUEUE) {
            // SLASH (operator, level, epoch, evidenceHash) and QUEUE (operator, level, epoch) both
            // lead with the operator.
            return abi.decode(inputs[:32], (address)) == who;
        }
        if (kind == Kind.REPUTATION) {
            (address[] memory users,,) = abi.decode(inputs, (address[], uint256[], uint256));
            for (uint256 i = 0; i < users.length; i++) {
                if (users[i] == who) return true;
            }
        }
        return false;
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
    //                       aggregator mirrors (byte-identical; see @dev above)
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
        // Each branch also requires `inputs` to be the canonical encoding of what it decoded
        // (abi.decode alone accepts trailing bytes and non-canonical offsets), so an accepted entry
        // carries exactly the bytes an independent re-encoding produces.
        if (kind == Kind.SLASH) {
            (address operator, uint8 level, uint256 epoch, bytes32 evidenceHash) =
                abi.decode(inputs, (address, uint8, uint256, bytes32));
            _requireCanonical(inputs, abi.encode(operator, level, epoch, evidenceHash));
            return keccak256(abi.encode(ds, TAG_EXECUTE_SLASH, proposalId, operator, level, epoch, evidenceHash));
        }
        if (kind == Kind.GENERIC) {
            (address target, bytes32 callDataHash, uint256 threshold) = abi.decode(inputs, (address, bytes32, uint256));
            _requireCanonical(inputs, abi.encode(target, callDataHash, threshold));
            return keccak256(abi.encode(ds, TAG_PROPOSAL, proposalId, target, callDataHash, threshold));
        }
        if (kind == Kind.QUEUE) {
            (address operator, uint8 level, uint256 epoch) = abi.decode(inputs, (address, uint8, uint256));
            _requireCanonical(inputs, abi.encode(operator, level, epoch));
            return keccak256(abi.encode(ds, TAG_QUEUE_SLASH, operator, level, epoch));
        }
        if (kind == Kind.REPUTATION) {
            (address[] memory users, uint256[] memory scores, uint256 epoch) =
                abi.decode(inputs, (address[], uint256[], uint256));
            _requireCanonical(inputs, abi.encode(users, scores, epoch));
            return keccak256(abi.encode(ds, TAG_REPUTATION, proposalId, users, scores, epoch));
        }
        revert BadKind();
    }

    function _requireCanonical(bytes calldata inputs, bytes memory canonical) private pure {
        if (keccak256(inputs) != keccak256(canonical)) revert NonCanonicalInputs();
    }

    /// @notice Storage key of `proposalSignersCommitment` per path (BLSAggregator-4.13.0 r3b):
    ///   GENERIC    uint256(keccak256(abi.encode(TAG_PROPOSAL, proposalId)))  (= its replay slot)
    ///   QUEUE      uint256(messageHash)
    ///   SLASH/REP  proposalId (raw, < 2^128)
    function commitmentKey(Kind kind, uint256 proposalId, bytes32 messageHash) public pure returns (uint256) {
        if (kind == Kind.GENERIC) return uint256(keccak256(abi.encode(TAG_PROPOSAL, proposalId)));
        if (kind == Kind.QUEUE) return uint256(messageHash);
        return proposalId;
    }

    /// @notice The commitment tuple, identical on all paths: storage key in the id position, signers
    ///         ascending by uint160, parent-block hash `blockhash(N-1)` appended.
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
