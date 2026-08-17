// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.19;

import "./AAStarValidator.sol";

/// @title AAStarCommitteeValidator — CC-98 per-proposal random-committee BLS validator (production)
/// @notice Replaces CC-97's global ⌈2N/3⌉ (which does not scale: registry unbounded ⇒ quorum exceeds
///         the single-call node cap ⇒ network-wide fail-close). Each operation is validated against a
///         PER-PROPOSAL committee the submitter cannot choose:
///
///           node ∈ committee(account A, epoch e)  ⟺  H("CMT_SELECT", seed[e], A, nodeId) < T
///
///         Security rests on THREE inputs, each un-choosable by the submitter:
///           1. seed[e]     = blockhash(firstBlockOf(e)), pinned by a permissionless keeper.
///           2. the SET     the node must belong to is committed by an on-chain incremental Merkle root
///                          FROZEN ONE EPOCH AHEAD of the seed reveal (look-ahead) — see below.
///           3. accountId A = the account injects address(this); never taken from submitter calldata.
///
///         LOOK-AHEAD (the register-to-order fix, dvt CC-98 comment 7322c647): a committee used DURING
///         epoch e samples over setRoot[e-1] (frozen while e-1 was current, strictly BEFORE seed[e]
///         became knowable) with seed[e] (revealed at the start of e). An attacker cannot grind a
///         pubkey → nodeId into a victim's committee: during e-1 they don't know seed[e]; during e the
///         set is already frozen. This reduces the attack to holding a β-fraction of ALL stake (the
///         honest-majority assumption the DSR tail bound is built on).
///
///         Per signer, validate() does zero extra pairings: a Merkle proof that nodeId ∈ setRoot[e-1]
///         (O(depth) keccak) + the sortition inequality (1 keccak) + the existing registration/stake
///         gate, then the SAME aggregate BLS verify as the base contract. Committee membership is NOT
///         transmitted; it is recomputed. Threshold ⌈2·m_e/3⌉ is computed by the validator (never
///         accepted from calldata), m_e follows the DSR curve over the committed node count.
///
///         Wire format of `signature` (the account prepends accountId; the submitter provides the rest):
///           [ accountId(32) ] [ per signer: nodeId(32) ‖ merkleProof(TREE_DEPTH×32) ]... [ blsSig(256) ]
contract AAStarCommitteeValidator is AAStarValidator {
    // Base declares these as private constants; re-declare the two lengths the committee path needs.
    uint256 private constant G1_LEN = 128;
    uint256 private constant G2_LEN = 256;
    /// @dev Mirrors the base's private MAX_NODE_COUNT: upper bound on signers parsed in one validate().
    uint256 private constant MAX_NODE_COUNT = 100;

    /// @dev Sortition domain separator (DSR: distinct keccak domain, disjoint from any BLS DST).
    bytes32 private constant CMT_DOMAIN = keccak256("CMT_SELECT");

    /// @dev Incremental sparse-Merkle-tree depth over slot indices. 2^14 = 16,384 concurrent nodes.
    ///      Slots are reused on deactivation (free list), so this bounds CONCURRENT nodes, not lifetime.
    uint256 public constant TREE_DEPTH = 14;

    // ---------------------------------------------------------------------------------------------
    //                          COMMITTEE / EPOCH CONFIGURATION (owner-set)
    // ---------------------------------------------------------------------------------------------

    /// @dev Blocks per epoch. 0 ⇒ committee mode OFF (validate() falls back to the base whole-set path).
    uint256 public epochLength;
    /// @dev Oversampling numerator/denominator applied to the expected committee size m_e when deriving
    ///      the sortition threshold T (DSR: E[selected] ≈ 1.15·m_e buys liveness margin). Default 115/100.
    uint256 public oversampleNum;
    uint256 public oversampleDen;

    event EpochSnapshotted(uint256 indexed epoch, bytes32 seed, bytes32 setRoot, uint256 setCount);
    event EpochLengthSet(uint256 epochLength);
    event OversampleSet(uint256 num, uint256 den);

    // ---------------------------------------------------------------------------------------------
    //                          INCREMENTAL SPARSE MERKLE TREE (active-set commitment)
    // ---------------------------------------------------------------------------------------------

    /// @dev nodeId → (slot + 1). 0 means "no slot" (unregistered). Stored +1 so slot 0 is representable.
    mapping(bytes32 => uint256) public slotPlusOne;
    /// @dev Monotonic slot allocator; `freeSlots` recycles slots freed on deactivation to stay compact.
    uint256 public nextSlot;
    uint256[] public freeSlots;
    /// @dev Count of currently active leaves (slots occupied). Feeds the m_e curve.
    uint256 public activeCount;

    /// @dev SMT internal nodes: node[level][index]. Level 0 = leaves (leaf = nodeId, or 0 if empty).
    ///      Unset entries read as the empty-subtree hash `zeros[level]`.
    mapping(uint256 => mapping(uint256 => bytes32)) internal smt;
    /// @dev Precomputed empty-subtree hashes per level (zeros[0]=0, zeros[l]=H(zeros[l-1],zeros[l-1])).
    bytes32[TREE_DEPTH + 1] public zeros;
    /// @dev Current Merkle root of the active set (level TREE_DEPTH). Updated O(depth) per mutation.
    bytes32 public runningRoot;

    // ---------------------------------------------------------------------------------------------
    //                          PER-EPOCH SNAPSHOTS (double-snapshot, look-ahead)
    // ---------------------------------------------------------------------------------------------

    /// @dev epoch → pinned seed = blockhash(firstBlockOf(epoch)). Used by committees DURING this epoch.
    mapping(uint256 => bytes32) public epochSeed;
    /// @dev epoch → active-set Merkle root frozen while this epoch was current. Used by committees
    ///      DURING epoch+1 (the look-ahead: set frozen strictly before the next seed is revealed).
    mapping(uint256 => bytes32) public epochSetRoot;
    /// @dev epoch → active node count at the freeze. Feeds requiredQuorum for epoch+1.
    mapping(uint256 => uint256) public epochSetCount;
    /// @dev epoch → whether snapshotEpoch() has run for it (both seed and setRoot are then final).
    mapping(uint256 => bool) public epochPinned;

    constructor() AAStarValidator() {
        // Empty-subtree hashes + empty-tree root.
        for (uint256 i = 0; i < TREE_DEPTH; i++) {
            zeros[i + 1] = keccak256(abi.encode(zeros[i], zeros[i]));
        }
        runningRoot = zeros[TREE_DEPTH];
        oversampleNum = 115;
        oversampleDen = 100;
    }

    // ---------------------------------------------------------------------------------------------
    //                          ADMIN
    // ---------------------------------------------------------------------------------------------

    function setEpochLength(uint256 _epochLength) external onlyOwner {
        epochLength = _epochLength;
        emit EpochLengthSet(_epochLength);
    }

    function setOversample(uint256 num, uint256 den) external onlyOwner {
        require(den != 0 && num >= den, "oversample must be >= 1");
        oversampleNum = num;
        oversampleDen = den;
        emit OversampleSet(num, den);
    }

    // ---------------------------------------------------------------------------------------------
    //                          SET-MUTATION HOOKS (maintain the SMT in lock-step with isRegistered[])
    // ---------------------------------------------------------------------------------------------

    function _onNodeActivated(bytes32 nodeId) internal override {
        // base already guaranteed !isRegistered before this; defensively no-op on a double-activate.
        if (slotPlusOne[nodeId] != 0) return;
        uint256 slot;
        uint256 free = freeSlots.length;
        if (free != 0) {
            slot = freeSlots[free - 1];
            freeSlots.pop();
        } else {
            slot = nextSlot;
            require(slot < (1 << TREE_DEPTH), "committee tree full");
            nextSlot = slot + 1;
        }
        slotPlusOne[nodeId] = slot + 1;
        activeCount += 1;
        _smtSet(slot, nodeId);
    }

    function _onNodeDeactivated(bytes32 nodeId) internal override {
        uint256 sp = slotPlusOne[nodeId];
        if (sp == 0) return; // defensive: never activated in committee accounting
        uint256 slot = sp - 1;
        delete slotPlusOne[nodeId];
        freeSlots.push(slot);
        activeCount -= 1;
        _smtSet(slot, bytes32(0));
    }

    /// @dev Set leaf `slot` to `leaf` and fold the change up to the root: O(TREE_DEPTH) hashes + SSTOREs.
    function _smtSet(uint256 slot, bytes32 leaf) internal {
        uint256 idx = slot;
        smt[0][idx] = leaf;
        bytes32 cur = leaf;
        for (uint256 level = 0; level < TREE_DEPTH; level++) {
            uint256 sibIdx = idx ^ 1;
            bytes32 sib = smt[level][sibIdx];
            if (sib == bytes32(0)) sib = zeros[level]; // unset ⇒ empty subtree
            cur = (idx & 1) == 0 ? keccak256(abi.encode(cur, sib)) : keccak256(abi.encode(sib, cur));
            idx >>= 1;
            smt[level + 1][idx] = cur;
        }
        runningRoot = cur;
    }

    // ---------------------------------------------------------------------------------------------
    //                          EPOCH SNAPSHOT (permissionless keeper)
    // ---------------------------------------------------------------------------------------------

    /// @notice Pin epoch `e`: seed[e] = blockhash(firstBlockOf(e)) (used by committees during e) and
    ///         setRoot[e] = current active-set root (used by committees during e+1). Callable by anyone
    ///         within the 256-block window after the epoch's first block (blockhash availability), once.
    /// @dev The seed source is a FIXED past block (the epoch's first block), so no caller can grind it by
    ///      choosing when to call — only the block proposer has the standard bounded ~1-bit RANDAO bias.
    function snapshotEpoch() external {
        require(epochLength != 0, "committee mode off");
        uint256 e = block.number / epochLength;
        require(!epochPinned[e], "epoch already pinned");
        uint256 startBlock = e * epochLength;
        require(block.number > startBlock, "wait for epoch start block");
        require(block.number <= startBlock + 256, "pin window elapsed");
        bytes32 bh = blockhash(startBlock);
        require(bh != bytes32(0), "blockhash unavailable");

        epochSeed[e] = bh;
        epochSetRoot[e] = runningRoot;
        epochSetCount[e] = activeCount;
        epochPinned[e] = true;
        emit EpochSnapshotted(e, bh, runningRoot, activeCount);
    }

    function currentEpoch() public view returns (uint256) {
        require(epochLength != 0, "committee mode off");
        return block.number / epochLength;
    }

    // ---------------------------------------------------------------------------------------------
    //                          COMMITTEE MATH (m_e curve + threshold)
    // ---------------------------------------------------------------------------------------------

    /// @dev DSR expected-committee curve over committed pool size n:
    ///      n ≤ 8 → whole set (bootstrap); else m_e = min(110, max(16, n/5)).
    ///      CAPPED AT n: the expected committee can never exceed the pool. Without this, a pool of
    ///      9..15 nodes gets m_e = 16 (the floor) and requiredQuorum = ceil(2*16/3) = 11 > n, making
    ///      every op unsatisfiable (liveness DoS). Capping degrades such pools to the whole set, so
    ///      requiredQuorum = ceil(2n/3) <= n always holds.
    function expectedCommittee(uint256 n) public pure returns (uint256) {
        if (n <= 8) return n;
        uint256 m = n / 5;
        if (m < 16) m = 16;
        if (m > 110) m = 110;
        if (m > n) m = n; // never sample more than the pool
        return m;
    }

    /// @dev ⌈2·m/3⌉ with m ≥ 1 (base of the whole scheme). Division-free ceil.
    function _quorumOf(uint256 m) internal pure returns (uint256) {
        return (2 * m + 2) / 3;
    }

    /// @dev Sortition threshold T for pool n, expected committee m: a node is selected iff its 256-bit
    ///      draw < T. Target selection probability = oversample·m/n, capped at "whole set" (T = max).
    function _thresholdOf(uint256 n, uint256 m) internal view returns (uint256) {
        if (n == 0) return 0;
        uint256 target = (oversampleNum * m + oversampleDen - 1) / oversampleDen; // ceil(over·m)
        if (target >= n) return type(uint256).max; // whole set (bootstrap / tiny pool)
        return (type(uint256).max / n) * target;
    }

    /// @notice Required signer count ⌈2·m_e/3⌉ for committees active in `e`, i.e. over setRoot[e-1].
    ///         Returns type(uint256).max when the prerequisite snapshot is missing (nothing can satisfy
    ///         it — the account's mirror check then fails closed too).
    function requiredQuorum() public view returns (uint256) {
        uint256 e = currentEpoch();
        if (e == 0 || !epochPinned[e - 1]) return type(uint256).max;
        uint256 m = expectedCommittee(epochSetCount[e - 1]);
        return _quorumOf(m);
    }

    // ---------------------------------------------------------------------------------------------
    //                          VALIDATE (committee path; overrides the base whole-set path)
    // ---------------------------------------------------------------------------------------------

    function validate(bytes32 hash, bytes calldata signature) external view override returns (uint256) {
        // Committee mode disabled → behave exactly like the base contract (whole-set aggregate verify).
        if (epochLength == 0) return _validateWholeSet(hash, signature);

        uint256 e = block.number / epochLength;
        // Need seed[e] (this epoch) and setRoot[e-1] (frozen last epoch, the look-ahead set). Fail-closed
        // if either is missing: the permissionless keeper must snapshot each epoch inside its window.
        if (e == 0 || !epochPinned[e] || !epochPinned[e - 1]) return 1;
        bytes32 seed = epochSeed[e];
        bytes32 setRoot = epochSetRoot[e - 1];
        uint256 committedCount = epochSetCount[e - 1];

        // ---- parse layout: accountId(32) ‖ k×(nodeId(32) ‖ proof(TREE_DEPTH*32)) ‖ blsSig(256) ----
        uint256 perSigner = 32 + TREE_DEPTH * 32;
        if (signature.length < 32 + G2_LEN) return 1;
        uint256 body = signature.length - 32 - G2_LEN;
        if (body == 0 || body % perSigner != 0) return 1;
        uint256 k = body / perSigner;
        if (k > MAX_NODE_COUNT) return 1; // gas-griefing bound (shared with the base cap)

        // requiredQuorum for THIS epoch (over the look-ahead set).
        uint256 m = expectedCommittee(committedCount);
        uint256 required = _quorumOf(m);
        if (k < required) return 1;
        uint256 T = _thresholdOf(committedCount, m);

        bytes32 accountId = bytes32(signature[0:32]);

        bytes32[] memory nodeIds = new bytes32[](k);
        bytes32 prevId = bytes32(0);
        uint256 off = 32;
        for (uint256 i = 0; i < k; i++) {
            bytes32 nid = bytes32(signature[off:off + 32]);
            off += 32;
            // Distinct, strictly-increasing signers (blocks self-repetition inflating the aggregate).
            if (i != 0 && nid <= prevId) return 1;
            prevId = nid;
            // Still-active + economically backed (rejects retired bootstrap in staked mode).
            if (!isRegistered[nid]) return 1;
            if (requireStake && isBootstrap[nid]) return 1;
            // (a) Membership in the look-ahead set: Merkle proof at the node's slot against setRoot[e-1].
            uint256 sp = slotPlusOne[nid];
            if (sp == 0) return 1;
            if (!_verifyMerkle(setRoot, sp - 1, nid, signature[off:off + TREE_DEPTH * 32])) return 1;
            off += TREE_DEPTH * 32;
            // (b) Sortition: the committee membership the submitter cannot choose. When T == max the
            //     pool degrades to the whole set (bootstrap/tiny pool) — skip the draw so membership is
            //     truly universal (a draw == max, prob 2^-256, must not spuriously exclude a node).
            if (T != type(uint256).max) {
                uint256 draw = uint256(keccak256(abi.encode(CMT_DOMAIN, seed, accountId, nid)));
                if (draw >= T) return 1;
            }
            nodeIds[i] = nid;
        }

        bytes calldata blsSignature = signature[off:off + G2_LEN];
        if (_isG2InfinityCalldata(blsSignature)) return 1;

        bytes memory messagePoint = _hashToG2(hash);
        if (_isG2InfinityMemory(messagePoint)) return 1;

        bytes memory blsSigMem = blsSignature;
        bool valid = _validateBLSSignatureMem(nodeIds, blsSigMem, messagePoint);
        return valid ? 0 : 1;
    }

    /// @dev The base whole-set parse+verify, inlined for the epochLength==0 fallback. Kept byte-identical
    ///      to AAStarValidator.validate() so mounting this contract with committee mode off is a no-op
    ///      change vs. the legacy validator.
    function _validateWholeSet(bytes32 hash, bytes calldata signature) internal view returns (uint256) {
        if (signature.length <= G2_LEN) return 1;
        uint256 nodeIdsBytes = signature.length - G2_LEN;
        if (nodeIdsBytes == 0 || nodeIdsBytes % 32 != 0) return 1;
        uint256 nodeCount = nodeIdsBytes / 32;
        if (nodeCount > MAX_NODE_COUNT) return 1;

        bytes32[] memory nodeIds = new bytes32[](nodeCount);
        bytes32 prevId = bytes32(0);
        for (uint256 i = 0; i < nodeCount; i++) {
            bytes32 nid = bytes32(signature[i * 32:(i + 1) * 32]);
            if (i != 0 && nid <= prevId) return 1;
            prevId = nid;
            if (!isRegistered[nid]) return 1;
            if (requireStake && isBootstrap[nid]) return 1;
            nodeIds[i] = nid;
        }
        bytes calldata blsSignature = signature[nodeIdsBytes:nodeIdsBytes + G2_LEN];
        if (_isG2InfinityCalldata(blsSignature)) return 1;
        bytes memory messagePoint = _hashToG2(hash);
        if (_isG2InfinityMemory(messagePoint)) return 1;
        bytes memory blsSigMem = blsSignature;
        return _validateBLSSignatureMem(nodeIds, blsSigMem, messagePoint) ? 0 : 1;
    }

    /// @notice Build a Merkle proof for `nodeId` against the CURRENT active-set root. Convenience view
    ///         for off-chain aggregators (and tests). NOTE: production proofs must target the FROZEN
    ///         setRoot[e-1]; this returns a current-state proof, valid only while the set is unchanged
    ///         since that snapshot (aggregators otherwise reconstruct the frozen tree from events).
    /// @return slot The node's leaf slot. @return proof TREE_DEPTH sibling hashes (leaf→root order).
    function getMerkleProof(bytes32 nodeId) external view returns (uint256 slot, bytes32[] memory proof) {
        uint256 sp = slotPlusOne[nodeId];
        require(sp != 0, "node not active");
        slot = sp - 1;
        proof = new bytes32[](TREE_DEPTH);
        uint256 idx = slot;
        for (uint256 level = 0; level < TREE_DEPTH; level++) {
            bytes32 sib = smt[level][idx ^ 1];
            proof[level] = sib == bytes32(0) ? zeros[level] : sib;
            idx >>= 1;
        }
    }

    /// @dev Verify a fixed-depth Merkle proof: fold `leaf` at position `slot` up through `proof`
    ///      (TREE_DEPTH sibling words) and compare to `root`. Bit i of `slot` selects left/right.
    function _verifyMerkle(bytes32 root, uint256 slot, bytes32 leaf, bytes calldata proof)
        internal
        pure
        returns (bool)
    {
        if (proof.length != TREE_DEPTH * 32) return false;
        bytes32 cur = leaf;
        uint256 idx = slot;
        for (uint256 level = 0; level < TREE_DEPTH; level++) {
            bytes32 sib = bytes32(proof[level * 32:level * 32 + 32]);
            cur = (idx & 1) == 0 ? keccak256(abi.encode(cur, sib)) : keccak256(abi.encode(sib, cur));
            idx >>= 1;
        }
        return cur == root;
    }
}
