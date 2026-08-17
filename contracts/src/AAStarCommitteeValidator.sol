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
///           [ accountId(32) ] [ per signer: nodeId(32) | slot(32) | merkleProof(TREE_DEPTH*32) ]... [ blsSig(256) ]
///         (slot is the node's leaf index in the FROZEN setRoot[e-1]; it is authenticated by the proof.)
///
///         SECURITY ASSUMPTIONS (residuals from adversarial review — read before mounting):
///         - accountId is SECURITY-CRITICAL, not formatting. This contract cannot bind it to msg.sender
///           because a ValidatorRouter sits between account and validator. The account MUST inject its own
///           address(this) and MUST NOT forward any submitter-supplied accountId. If that account-side rule
///           is violated/bypassed, a submitter can shop accountId after seed[e] is known and place its own
///           nodes into the committee -> forgery. Enforcement is the account's responsibility (airaccount).
///         - LIVENESS (not safety): quorum is over the frozen count epochSetCount[e-1] but signers must be
///           currently registered. If more than ~1/3 of an account's frozen committee unregisters mid-epoch
///           (unstake/syncNode/revoke), ops for that account fail until the next epoch's fresh set. This is
///           the standard BFT liveness bound; mitigated by DSR oversampling (E[selected] ~ 1.15*m), the SP
///           unbonding delay (bounds mass-exit), and per-epoch retry. Lowering quorum on churn would break
///           safety, so it is intentionally NOT done.
///         - LIVENESS: if a keeper misses the 256-block pin window for an epoch, committee ops fail for that
///           epoch (no seed) and the next (no setRoot), then self-heal. No late seed fallback exists because
///           a caller-chosen late seed would be grindable. Run redundant permissionless keepers.
///         - The active-set freeze time within the pin window is caller-chosen (first call wins); this cannot
///           reopen register-to-order (seed still unknowable at freeze) but lets a griefer exclude
///           registrations made between the epoch boundary and the pin. Minor fairness, not safety.
contract AAStarCommitteeValidator is AAStarValidator {
    // Base declares these as private constants; re-declare the length the committee path needs.
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
    /// @dev Emitted on every SMT leaf mutation so off-chain aggregators can reconstruct any historical
    ///      (frozen) tree from logs alone, without re-deriving the slot allocator (pr-daemon Low).
    event SlotAssigned(bytes32 indexed nodeId, uint256 slot);
    event SlotCleared(bytes32 indexed nodeId, uint256 slot);

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
    /// @dev Block of the most recent set mutation (activate/deactivate). snapshotEpoch requires this to
    ///      be strictly in the past, so a keeper cannot atomically evict nodes (syncNode is permissionless
    ///      and owner-free) and freeze the shrunken count in the SAME tx to depress m/quorum (pr-daemon
    ///      Medium — this manipulation feeds the B1 forgery budget).
    uint256 public lastSetMutationBlock;

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
    /// @dev epoch → the config version in force when it was pinned. A snapshot is only usable while it
    ///      matches the CURRENT configVersion, so changing epochLength cannot silently reuse a seed/root
    ///      that belonged to a different epoch schedule (Codex Low: reconfiguration provenance).
    mapping(uint256 => uint256) public epochConfigVersion;
    /// @dev Bumped on every epochLength change; namespaces all epoch snapshots to their schedule.
    uint256 public configVersion;

    /// @dev Accounts that have self-enrolled for committee validation. validate() fails closed unless the
    ///      injected accountId maps to an enrolled account. This is DEFENSE-IN-DEPTH for the accountId
    ///      trust (pr-daemon B2, agreed with airaccount f444db89): the MANDATORY fix is the account
    ///      injecting address(this). Enrollment blocks the flip-order shape collision — a legacy-shaped
    ///      payload's fabricated accountId maps to a non-enrolled address → reject. Combined with the
    ///      canonical-accountId check in validate() (high 96 bits must be zero, pr-daemon B4), the value
    ///      the gate reads (low 160) equals the value the draw consumes (all 256), so an enrolled
    ///      address's committee cannot be shifted by grinding unused bits. It does NOT replace injection:
    ///      an attacker can still enroll its own accounts, so accountId==address(this) at the account
    ///      remains the primary guarantee.
    mapping(address => bool) public enrolledAccount;

    event AccountEnrolled(address indexed account);
    event AccountUnenrolled(address indexed account);

    constructor() AAStarValidator() {
        // Empty-subtree hashes + empty-tree root.
        for (uint256 i = 0; i < TREE_DEPTH; i++) {
            zeros[i + 1] = keccak256(abi.encode(zeros[i], zeros[i]));
        }
        runningRoot = zeros[TREE_DEPTH];
        // oversample = 1.0: DSR's B1 security calc assumes E[committee] = m_e (λ = β*m_e). Any value > 1
        // inflates the attacker's expected selections and breaks the N>=430 β=1/3 guarantee, so the
        // default matches the security model exactly. setOversample can raise it (trading the DSR margin
        // for honest-liveness headroom) but that is an explicit, configVersion-bumping deviation.
        oversampleNum = 1;
        oversampleDen = 1;
    }

    // ---------------------------------------------------------------------------------------------
    //                          ADMIN
    // ---------------------------------------------------------------------------------------------

    /// @dev 0 disables committee mode. Must be >= 2: with epochLength == 1, startBlock == block.number
    ///      for every block, so `block.number > startBlock` in snapshotEpoch is never true and committee
    ///      mode is permanently unpinnable (Codex High). Bumps configVersion so snapshots taken under a
    ///      previous schedule are not reused under the new one (Codex Low).
    /// @dev 0 disables committee mode; otherwise >= 64. The real pin window is min(256, epochLength-1)
    ///      blocks (blockhash availability vs epoch span), so epochLength == 1 is unpinnable and tiny
    ///      values leave a window too small for a keeper; 64 keeps a usable window (pr-daemon Low).
    ///      Bumps configVersion so snapshots taken under a previous schedule are not reused (Codex Low).
    ///      MIGRATION INTERLOCK (pr-daemon B2, airaccount f444db89): committee mode MUST NOT be enabled
    ///      before the accountId-injecting v0.30.0 accounts are deployed, mounted, and (defense-in-depth)
    ///      enrolled. Flipping this on early would fail-close honest legacy traffic while an attacker's
    ///      legacy-shaped payload parses as a committee op — but enrollment blocks that path on-chain
    ///      (non-enrolled accountId => reject), so the residual is an owner/Safe process ordering:
    ///      deploy+mount+enroll accounts first, THEN setEpochLength.
    function setEpochLength(uint256 _epochLength) external onlyOwner {
        require(_epochLength == 0 || _epochLength >= 64, "epochLength must be 0 or >= 64");
        epochLength = _epochLength;
        configVersion += 1;
        emit EpochLengthSet(_epochLength);
    }

    /// @dev The threshold `oversample` scales the OTHER half of the committee definition, so — exactly
    ///      like setEpochLength — it bumps configVersion. Without this, setOversample RETROACTIVELY
    ///      relaxes the sortition gate on ALREADY-PINNED epochs (e.g. setOversample(5,1) collapses
    ///      _thresholdOf to type(uint256).max, admitting nodes that were out of committee), which is a
    ///      committee-definition mutation on a frozen epoch (pr-daemon B3). Bumping fails those epochs
    ///      closed until re-pinned. Bounds also keep `oversampleNum * m` from overflowing (num/den in
    ///      [1,8], den in [1,1e9]).
    function setOversample(uint256 num, uint256 den) external onlyOwner {
        require(den != 0 && den <= 1e9, "den out of range");
        require(num >= den && num <= 8 * den, "oversample must be in [1, 8]");
        oversampleNum = num;
        oversampleDen = den;
        configVersion += 1;
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
        lastSetMutationBlock = block.number;
        _smtSet(slot, nodeId);
        emit SlotAssigned(nodeId, slot);
    }

    function _onNodeDeactivated(bytes32 nodeId) internal override {
        uint256 sp = slotPlusOne[nodeId];
        if (sp == 0) return; // defensive: never activated in committee accounting
        uint256 slot = sp - 1;
        delete slotPlusOne[nodeId];
        freeSlots.push(slot);
        activeCount -= 1;
        lastSetMutationBlock = block.number;
        _smtSet(slot, bytes32(0));
        emit SlotCleared(nodeId, slot);
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
        // Re-pinning is allowed only when the existing pin belongs to a PREVIOUS epoch schedule
        // (configVersion). Otherwise, after an epochLength change, new-schedule epoch numbers that
        // collide with old pinned IDs could never be re-snapshotted under the current version, stranding
        // committee mode until the epoch counter passed every colliding old ID (Codex round-2 High).
        require(!epochPinned[e] || epochConfigVersion[e] != configVersion, "epoch already pinned");
        uint256 startBlock = e * epochLength;
        require(block.number > startBlock, "wait for epoch start block");
        require(block.number <= startBlock + 256, "pin window elapsed");
        bytes32 bh = blockhash(startBlock);
        require(bh != bytes32(0), "blockhash unavailable");
        // No set mutation in THIS block: forces any set change (esp. permissionless syncNode evictions)
        // to land in an earlier block than the freeze, turning an atomic "evict-then-freeze" depression
        // of epochSetCount into a race an honest keeper can win (pr-daemon Medium).
        require(lastSetMutationBlock < block.number, "set mutated this block");

        epochSeed[e] = bh;
        epochSetRoot[e] = runningRoot;
        epochSetCount[e] = activeCount;
        epochConfigVersion[e] = configVersion;
        epochPinned[e] = true;
        emit EpochSnapshotted(e, bh, runningRoot, activeCount);
    }

    function currentEpoch() public view returns (uint256) {
        require(epochLength != 0, "committee mode off");
        return block.number / epochLength;
    }

    /// @notice Whether committee mode is active. The ACCOUNT reads this to choose its signature framing
    ///         (inject accountId + committee layout) rather than guessing from the payload shape — the
    ///         shape-collision root of the flip-order attack (pr-daemon B2, airaccount f444db89). Same
    ///         validator state drives both the validator's parse and the account's framing → no desync.
    function committeeActive() external view returns (bool) {
        return epochLength != 0;
    }

    /// @notice Self-enroll the caller for committee validation. msg.sender IS the account, so enrollment
    ///         is self-proving — no trusted external input. Required before an account's committee ops
    ///         validate (defense-in-depth for accountId; see enrolledAccount).
    function enroll() external {
        enrolledAccount[msg.sender] = true;
        emit AccountEnrolled(msg.sender);
    }

    /// @notice Un-enroll the caller (e.g. before migrating away). Only the account itself can.
    function unenroll() external {
        enrolledAccount[msg.sender] = false;
        emit AccountUnenrolled(msg.sender);
    }

    // ---------------------------------------------------------------------------------------------
    //                          COMMITTEE MATH (m_e curve + threshold)
    // ---------------------------------------------------------------------------------------------

    /// @dev DSR expected-committee curve over committed pool size n:
    ///      n ≤ 8 → whole set (bootstrap); else m_e = min(110, max(16, n/5)).
    ///      DSR-locked curve (CC-98 comment 9a9f47c9, Jason-adjudicated target): m_e(N) = N for N<=8
    ///      (bootstrap whole set); else clamp(ceil(N/5), 17, 86). Security target: forgery probability
    ///      ε = P(Poisson(β*m_e) >= ceil(2*m_e/3)) <= 1e-6 per (account, epoch) under the explicit
    ///      assumption β <= 10% malicious stake. floor 17 hits ε=2.6e-7 @ β=10% (floor 16 was 1.02e-6,
    ///      just over); cap 86 is the β=1/3 1e-6 point, so pools of N>=430 meet 1e-6 even at worst-case
    ///      β=1/3 for free. This methodology REQUIRES E[committee] = m_e, i.e. oversample = 1.0 (see the
    ///      constructor) — any oversample > 1 inflates λ and breaks the N>=430 worst-case guarantee.
    ///      CAPPED AT n keeps requiredQuorum = ceil(2*m_e/3) <= n for the 9..16 bootstrap band (where the
    ///      floor 17 would otherwise exceed the pool); airaccount gates committee mode on N >= N0 to keep
    ///      such small pools off the sampling path (bootstrap-cliff avoidance).
    function expectedCommittee(uint256 n) public pure returns (uint256) {
        if (n <= 8) return n;
        uint256 m = (n + 4) / 5; // ceil(n/5)
        if (m < 17) m = 17;
        if (m > 86) m = 86;
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
        // Read epochLength directly — do NOT go through currentEpoch(), which reverts when epochLength
        // == 0 (the DEFAULT/committee-off config). Returning the sentinel keeps this view fail-closed
        // and consistent with validate()'s "return 1" for the same state (pr-daemon Medium).
        if (epochLength == 0) return type(uint256).max;
        uint256 e = block.number / epochLength;
        if (e == 0 || !_epochUsable(e - 1)) return type(uint256).max;
        uint256 m = expectedCommittee(epochSetCount[e - 1]);
        return _quorumOf(m);
    }

    /// @dev An epoch's snapshot is usable only if it was pinned AND under the current epoch schedule
    ///      (configVersion). This makes a post-reconfiguration seed/root fail-closed rather than being
    ///      combined across incompatible schedules.
    function _epochUsable(uint256 e) internal view returns (bool) {
        return epochPinned[e] && epochConfigVersion[e] == configVersion;
    }

    // ---------------------------------------------------------------------------------------------
    //                          VALIDATE (committee path; overrides the base whole-set path)
    // ---------------------------------------------------------------------------------------------

    function validate(bytes32 hash, bytes calldata signature) external view override returns (uint256) {
        // Committee mode disabled → behave exactly like the base contract (whole-set aggregate verify).
        if (epochLength == 0) return _validateWholeSet(hash, signature);

        uint256 e = block.number / epochLength;
        // Need seed[e] (this epoch) and setRoot[e-1] (frozen last epoch, the look-ahead set), both under
        // the current epoch schedule. Fail-closed if either is missing/stale: the permissionless keeper
        // must snapshot each epoch inside its window.
        if (e == 0 || !_epochUsable(e) || !_epochUsable(e - 1)) return 1;
        bytes32 seed = epochSeed[e];
        bytes32 setRoot = epochSetRoot[e - 1];
        uint256 committedCount = epochSetCount[e - 1];

        // ---- parse layout: accountId(32) || k×(nodeId(32) || slot(32) || proof(TREE_DEPTH*32)) || blsSig(256)
        //      The slot is submitter-provided and authenticated by the Merkle proof against setRoot[e-1]:
        //      each nodeId sits at exactly one slot in the frozen tree, so a wrong slot cannot verify. This
        //      binds membership to the node's HISTORICAL slot in the frozen set, so a node whose live slot
        //      was recycled+reassigned after the snapshot is still provable (Codex Medium: slot-reuse).
        uint256 perSigner = 64 + TREE_DEPTH * 32;
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
        // accountId MUST be the canonical zero-extension of a 160-bit address. The enrollment gate below
        // reads the low 160 bits, but the sortition draw consumes all 256 — so a set high bit is a free
        // offline grind surface on committee membership (pr-daemon B4). Reject non-canonical, symmetric
        // to the canonical-slot check below. (The account injecting address(this) always has zero high
        // bits, so this never rejects an honest op.)
        if (uint256(accountId) >> 160 != 0) return 1;
        // Defense-in-depth for the account-injected accountId (pr-daemon B2): the account must have
        // self-enrolled. A flip-order legacy-shaped payload whose fabricated accountId maps to a
        // non-enrolled address fails closed here.
        if (!enrolledAccount[address(uint160(uint256(accountId)))]) return 1;

        bytes32[] memory nodeIds = new bytes32[](k);
        bytes32 prevId = bytes32(0);
        uint256 off = 32;
        for (uint256 i = 0; i < k; i++) {
            bytes32 nid = bytes32(signature[off:off + 32]);
            uint256 slot = uint256(bytes32(signature[off + 32:off + 64]));
            off += 64;
            // Canonical slot only: _verifyMerkle folds just the low TREE_DEPTH bits, so slot and
            // slot + q*2^TREE_DEPTH would share a path. Reject non-canonical aliases (Codex round-2 Low).
            if (slot >= (1 << TREE_DEPTH)) return 1;
            // Distinct, strictly-increasing signers (blocks self-repetition inflating the aggregate).
            if (i != 0 && nid <= prevId) return 1;
            prevId = nid;
            // Still-active + economically backed (rejects retired bootstrap in staked mode).
            if (!isRegistered[nid]) return 1;
            if (requireStake && isBootstrap[nid]) return 1;
            // (a) Membership in the look-ahead set: Merkle proof at the submitted (authenticated) slot.
            if (!_verifyMerkle(setRoot, slot, nid, signature[off:off + TREE_DEPTH * 32])) return 1;
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
