// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.19;

import "./AAStarValidator.sol";

/// @dev SuperPaymaster BLSAggregator's ROLE_DVT exit-notice ledger (public mapping getter).
///      Read ONLY from the permissionless keeper's snapshot tx — never from validate(), which must stay
///      within ERC-7562 validation-phase storage rules.
/// @dev SP Registry's authoritative pointer to the live BLSAggregator (Registry.sol:33).
interface IRegistryAggregator {
    function blsAggregator() external view returns (address);
}

interface IGuardianExitSource {
    function guardianExitRequests(address guardian) external view returns (uint64 readyAt, uint64 expiresAt);
}

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
    /// @dev Oversampling numerator/denominator applied to m_e when deriving the sortition threshold T:
    ///      E[committee] = oversample·m_e, which pulls the liveness tail below its 1e-3 target. Default
    ///      5/4 = 1.25 (pr-daemon B5 two-tail operating point; see the constructor).
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
    /// @dev epoch → wall-clock deadline past which its snapshot is no longer usable. Set at freeze to
    ///      `block.timestamp + GUARDIAN_EXIT_DELAY`: SP guarantees a member staked at freeze time
    ///      cannot have withdrawn within that window, so this is exactly how long "frozen ⟹ still
    ///      bonded" holds. Enforcing it on the CLOCK rather than on a block count makes the guarantee
    ///      independent of block time and safe across a chain halt.
    mapping(uint256 => uint64) public epochSetValidUntil;

    /// @dev Minimum FROZEN committee pool size (epochSetCount[e-1]) for committee mode to accept a
    ///      tier-2/3 op. Below it, requiredQuorum() returns the unsatisfiable sentinel and validate()
    ///      fails closed — the ⌈2m/3⌉ ratio alone is meaningless at tiny N (N=1 ⇒ quorum 1, a single
    ///      node passes). Restores the agreed floor (CC-97) lost when the global-N model was rewritten
    ///      per-proposal (#237). Owner-adjustable via setMinCommittee but with a HARD FLOOR of 3 (it may be
///      raised above 3 and lowered back down to 3, never below); a change bumps configVersion.
    uint256 public minCommittee;

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
        // oversample = 1.25 (pr-daemon B5): raises E[committee] to 1.25*m_e so the actual committee clears
        // requiredQuorum with margin (liveness tail <=1.65e-4), while floor 30's forgery headroom keeps
        // P(forge) <= ~4.4e-9 @ β=10%. This is the two-tail operating point; it gives up the old β=1/3
        // "free gift" (out of scope under the β<=10% assumption). Pinned by test_constructor_oversample.
        oversampleNum = 5;
        oversampleDen = 4;
        // CC-97 floor: a committee of fewer than 3 nodes cannot carry BFT security; the ⌈2m/3⌉ ratio
        // degenerates at tiny N (N=1 ⇒ quorum 1). Owner may raise it; the hard floor 3 is not settable away.
        minCommittee = 3;
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
        // TWO DIRECTIONS, and only one of them was wrong. An earlier revision required
        // `2*L*MIN_BLOCK_SECONDS <= GUARDIAN_EXIT_DELAY`, calling 1s/block conservative; that proved
        // nothing, because bounding how long 2L blocks TAKE needs an upper bound on block time. It was
        // removed and SAFETY moved onto the clock (epochSetValidUntil, below).
        //
        // But LIVENESS needs the same inequality with the direction fixed, and deleting the broken
        // bound deleted that too. `validate` requires BOTH `_epochUsable(e)` and `_epochUsable(e-1)`,
        // so setRoot[e-1] must still be unexpired throughout e. If one epoch's wall-clock length
        // approaches the bond window, the look-ahead set is already expired every time it is needed
        // and committee mode fails closed FOREVER — from a governance call that looks legitimate, on
        // a contract that cannot be upgraded.
        //
        // Here OVER-estimating block time is the conservative direction: it makes the accepted
        // epochLength SHORTER. 24s allows for sustained missed slots at Ethereum's 12s cadence, and
        // caps L at 3599 (~12h per epoch at 12s). Being wrong about it costs liveness, which fails
        // closed and is visible — never a silent relaxation, which is how the previous bound failed.
        require(
            _epochLength == 0 || 2 * _epochLength * MAX_BLOCK_SECONDS < GUARDIAN_EXIT_DELAY,
            "epochLength too long: setRoot[e-1] would expire during e"
        );
        epochLength = _epochLength;
        configVersion += 1;
        emit EpochLengthSet(_epochLength);
    }

    event BlsAggregatorSet(address indexed aggregator);

    /// @notice SP's BLSAggregator, read at snapshot time for each operator's ROLE_DVT exit notice.
    address public blsAggregator;

    /// @dev Upper bound on block time, used ONLY to bound epochLength for liveness. Note the
    ///      direction — a MINIMUM here proves nothing, which is why the earlier bound was removed.
    uint256 internal constant MAX_BLOCK_SECONDS = 24;

    /// @dev SP's `GUARDIAN_EXIT_DELAY` (BLSAggregator.sol:387) — a constant, not governable. A frozen
    ///      set stays usable for exactly this long, which is the window inside which SP guarantees a
    ///      member that was staked at freeze time still has stake that can be slashed.
    uint256 internal constant GUARDIAN_EXIT_DELAY = 2 days;

    /// @notice Point the validator at SP's BLSAggregator.
    /// @dev Rotatable BY DESIGN: SP exposes `Registry.setBLSAggregator` and
    ///      `queueBLSAggregator`/`applyBLSAggregator`, and CC-115 B3 is explicitly a SUCCESSOR
    ///      deployment — so the address WILL change within this validator's lifetime (dsr b726b6a0).
    ///      A change bumps configVersion, which fails every already-pinned snapshot closed: a set whose
    ///      exit notices were judged against the OLD aggregator must not keep serving committees.
    function setBlsAggregator(address _aggregator) external onlyOwner {
        require(_aggregator != address(0), "aggregator must be non-zero");
        require(_aggregator.code.length > 0, "aggregator has no code");
        // POSITIVE IDENTITY, not a surface probe. An earlier revision only try/catch'd
        // `guardianExitRequests(address)`, which any contract with a fallback returning 64 zero bytes
        // passes while implementing none of the ledger semantics. The Registry publishes the live
        // aggregator, so bind to that instead and let the ABI probe be a mere sanity check.
        require(_aggregator == _registryAggregator(), "aggregator != Registry.blsAggregator()");
        try IGuardianExitSource(_aggregator).guardianExitRequests(address(0)) returns (uint64, uint64) {
            // ok — ABI sanity only; identity comes from the Registry check above.
        } catch {
            revert("aggregator has no guardianExitRequests(address)");
        }
        blsAggregator = _aggregator;
        configVersion += 1;
        emit BlsAggregatorSet(_aggregator);
    }

    event MinCommitteeSet(uint256 minCommittee);

    /// @dev Committee floor with a HARD MINIMUM of 3 (the agreed CC-97 floor). The owner may raise it and
    ///      may lower it back to — but never below — 3; keeping the lower bound settable back to 3 is the
    ///      escape hatch for an over-raised floor (an accidental setMinCommittee(30) would otherwise halt
    ///      tier-2/3 until the pool grew that large). Bumps configVersion so snapshots frozen under a
    ///      different floor are not reused (same rationale as setEpochLength).
    function setMinCommittee(uint256 _minCommittee) external onlyOwner {
        require(_minCommittee >= 3, "minCommittee floor is 3");
        minCommittee = _minCommittee;
        configVersion += 1;
        emit MinCommitteeSet(_minCommittee);
    }

    /// @dev requireStake / registry / minStake all change which frozen nodes still qualify as eligible
    ///      signers. Bump configVersion so a snapshot pinned under the old eligibility policy is not reused
    ///      under a new one (fails closed until re-pinned) — same rationale as setEpochLength/setOversample.
    function _onEligibilityConfigChanged() internal override {
        configVersion += 1;
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
    /// @dev KNOWN OPERATIONAL CEILING, measured rather than assumed. This call is linear in the
    ///      active-set size and the set has no on-chain cap: TREE_DEPTH = 14 allows 16,384 slots.
    ///      Measured on the bootstrap path (a LOWER bound — it makes no external calls):
    ///      N=10 -> 153,738 gas; 50 -> 202,109; 100 -> 263,163; 200 -> 387,231, i.e. ~1,229 gas/node.
    ///      The staked path additionally makes two external view calls per node, so its slope is
    ///      materially steeper (estimated 8-15k/node; NOT measured). At that slope a few thousand
    ///      nodes push the pin past a 30M block limit — and a pin that cannot land fails the whole
    ///      network closed for that epoch.
    ///
    ///      No N cap is imposed here on purpose: the committee curve is designed for pools up to
    ///      20,000, so a hard limit would contradict the sizing this validator exists to implement.
    ///      The real fix is a batched snapshot, which is future work. Until then this is an operating
    ///      limit to be watched, not a guarantee — see docs/DVT_OPERATIONS.md.
    /// @param activeNodeIds The COMPLETE current active set, strictly increasing by nodeId. Supplying
    ///        it lets the snapshot verify eligibility for every member; the contract proves the list is
    ///        complete rather than trusting the caller (see below).
    function snapshotEpoch(bytes32[] calldata activeNodeIds) external {
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

        // CC-112 D2 (P3+P8). The frozen set must be the ELIGIBLE set, not merely the registered one:
        // the CC-97 floor and the ⌈2m/3⌉ denominator are both computed over epochSetCount, so counting a
        // node whose operator has no stake defeats the minimum-population predicate outright.
        //
        // WHY THE BLOCK-START LATCH IS GONE. The freeze used to pin the PRE-mutation root/count when
        // the set changed in the same block, so a permissionless syncNode could not be atomically
        // composed with the freeze to depress epochSetCount. That defence is obsolete: eviction can
        // only remove a node the Registry itself judges stale, so depressing the count is now the
        // CORRECT outcome, not an attack — the frozen set is supposed to be the eligible set.
        //
        // An earlier revision of this pillar reverted on any same-block mutation instead. That was
        // both unnecessary and harmful: the real pin window is min(256, epochLength - 1) blocks — only
        // 63 at L=64, not 256 — so an attacker holding that many staked operators could register one
        // per block and deny every keeper for the whole window. Stake is locked, not spent, so the
        // "ammunition is finite" argument did not hold either. The set is simply frozen as it stands
        // when the transaction executes, and the completeness check below rejects any list that no
        // longer matches it.
        uint256 n = activeCount;
        require(activeNodeIds.length == n, "activeNodeIds length != activeCount");

        // COMPLETENESS PROOF, not trust. Strictly increasing (so no duplicates) + every entry currently
        // holds a slot + exactly `activeCount` entries ⟹ the list is precisely the active set. Any
        // omission would have to be replaced by a duplicate or a non-member, and both are rejected.
        bytes32 prev = bytes32(0);
        bool aggregatorChecked;
        for (uint256 i = 0; i < n; i++) {
            bytes32 nid = activeNodeIds[i];
            require(i == 0 || nid > prev, "activeNodeIds must be strictly increasing");
            prev = nid;
            require(slotPlusOne[nid] != 0, "activeNodeIds contains a non-member");
            // Only a STAKED node has an exit notice to read, so an all-bootstrap set needs no
            // aggregator at all. Checked once, on first encountering one, so bootstrap-only
            // deployments are unaffected and the Registry read is not repeated per node.
            //
            // SP can rotate its aggregator (Registry.setBLSAggregator; CC-115 B3 is a successor
            // deployment). Without this the validator keeps reading the OLD ledger, which reports no
            // notice for one filed on the new one — a SILENT fail-open that admits a guardian on its
            // way out. Fail closed until the owner re-points the validator.
            if (!isBootstrap[nid] && !aggregatorChecked) {
                require(blsAggregator == _registryAggregator(), "aggregator stale: re-run setBlsAggregator");
                aggregatorChecked = true;
            }
            require(_isEligibleForSnapshot(nid), "ineligible node in set: syncNode it first");
        }

        epochSeed[e] = bh;
        epochSetRoot[e] = runningRoot;
        epochSetCount[e] = n;
        epochConfigVersion[e] = configVersion;
        epochSetValidUntil[e] = uint64(block.timestamp + GUARDIAN_EXIT_DELAY);
        epochPinned[e] = true;
        emit EpochSnapshotted(e, bh, runningRoot, n);
    }

    /// @dev Eligibility AT FREEZE TIME. Mirrors `syncNode`'s predicate exactly for the registered/staked
    ///      halves — inventing a second notion of "eligible" is how the two drift apart — and adds SP's
    ///      exit-notice condition on top.
    ///
    ///      WHY `readyAt == 0` AND NOT SP's SUGGESTED `readyAt > snapshotTime + epochLength`. `readyAt`
    ///      is SECONDS; `epochLength` is BLOCKS. Writing SP's condition on-chain would weld a block-time
    ///      assumption into a NON-UPGRADEABLE validator, and a block-time change would loosen it
    ///      SILENTLY rather than fail closed. The stricter rule needs no conversion and is a subset of
    ///      SP's. It also matches SP's own look-ahead accounting, which already excludes any guardian
    ///      with `readyAt != 0` (dsr b726b6a0). Cost, accepted and documented: a guardian that filed and
    ///      then cancelled an exit waits for the next snapshot to rejoin — and SP already imposes a
    ///      1-day cooldown on that cancel, so this adds nothing material.
    function _isEligibleForSnapshot(bytes32 nodeId) internal view returns (bool) {
        // Bootstrap nodes carry no stake by construction; `requireStake` is what retires them.
        if (isBootstrap[nodeId]) return !requireStake;
        address op = nodeOperator[nodeId];
        if (!_isStaked(op)) return false;
        address agg = blsAggregator;
        // Fail-closed rather than "skip the check when unset": a silent downgrade would turn a security
        // predicate into an optional one exactly when it is most needed.
        if (agg == address(0)) return false;
        (uint64 readyAt,) = IGuardianExitSource(agg).guardianExitRequests(op);
        return readyAt == 0;
    }

    /// @dev The Registry's current aggregator. Fails closed if the Registry does not publish one:
    ///      without it there is no authority to bind to, and guessing is what this replaced.
    function _registryAggregator() internal view returns (address) {
        require(registry != address(0), "registry not set");
        try IRegistryAggregator(registry).blsAggregator() returns (address a) {
            require(a != address(0), "Registry.blsAggregator() == 0");
            return a;
        } catch {
            revert("registry does not publish blsAggregator()");
        }
    }

    /// @notice The complete active set, sorted ascending — exactly the argument `snapshotEpoch` wants.
    /// @dev    OFF-CHAIN CONVENIENCE ONLY (keepers, tests). It scans `registeredNodes` (which retains
    ///         stale ids by design) and insertion-sorts, so it is O(n^2) and must never be called from
    ///         a transaction. A production keeper should rebuild the set from SlotAssigned/SlotCleared
    ///         events instead; this exists so that doing the simple thing is still correct.
    function activeNodeIdsSorted() public view returns (bytes32[] memory out) {
        uint256 total = registeredNodes.length;
        out = new bytes32[](activeCount);
        uint256 k;
        for (uint256 i = 0; i < total && k < out.length; i++) {
            bytes32 id = registeredNodes[i];
            if (slotPlusOne[id] == 0) continue;
            // `registeredNodes` can hold the same id twice (revoke then re-register), so de-duplicate.
            bool seen;
            for (uint256 j = 0; j < k; j++) {
                if (out[j] == id) {
                    seen = true;
                    break;
                }
            }
            if (seen) continue;
            // Insertion sort in place: snapshotEpoch requires strictly increasing ids.
            uint256 pos = k;
            while (pos > 0 && out[pos - 1] > id) {
                out[pos] = out[pos - 1];
                pos--;
            }
            out[pos] = id;
            k++;
        }
    }

    event NodeExitNoticeSynced(bytes32 indexed nodeId, address indexed operator, uint64 readyAt);

    /// @notice Permissionlessly retire a node whose operator has filed a ROLE_DVT exit notice.
    /// @dev    WITHOUT THIS THE SNAPSHOT DEADLOCKS. `snapshotEpoch` refuses a set containing a node
    ///         with `readyAt != 0`, but the base `syncNode` only knows about role/stake/bootstrap — and
    ///         SP deliberately keeps BOTH role and stake intact for the whole 2-day notice. So
    ///         `syncNode` reverts "Node still active" while `snapshotEpoch` reverts "ineligible node",
    ///         and no permissionless action can break the tie: every pin fails until the guardian
    ///         cancels or two days elapse. A single ORDINARY exit would halt committee mode.
    ///
    ///         The predicate is deliberately NARROW — an in-flight exit notice, nothing else — rather
    ///         than `!_isEligibleForSnapshot`. Reusing the snapshot predicate would let anyone empty
    ///         the whole set whenever `blsAggregator` is unset, since it returns false for every staked
    ///         node in that state.
    function syncExitNotice(bytes32 nodeId) external {
        require(isRegistered[nodeId], "Node not registered");
        require(!isBootstrap[nodeId], "Bootstrap node: use syncNode");
        address agg = blsAggregator;
        require(agg != address(0), "bls aggregator not set");
        // Same authority binding as snapshotEpoch. Without it, during a Registry rotation a LEFTOVER
        // notice on the OLD ledger — which no longer governs `Registry.exitRole` — would let anyone
        // evict a node that still holds its role and stake, dropping it from the frozen committee it
        // is currently serving.
        require(agg == _registryAggregator(), "aggregator stale: re-run setBlsAggregator");
        address op = nodeOperator[nodeId];
        (uint64 readyAt,) = IGuardianExitSource(agg).guardianExitRequests(op);
        require(readyAt != 0, "No exit notice filed");
        _deactivate(nodeId);
        emit NodeExitNoticeSynced(nodeId, op, readyAt);
        emit NodeDeactivated(nodeId, op);
    }

    /// @notice Whether `nodeId` would be accepted into the next snapshot. For keepers: call this to find
    ///         which nodes need `syncNode` before `snapshotEpoch` will succeed.
    function isEligibleForSnapshot(bytes32 nodeId) external view returns (bool) {
        return _isEligibleForSnapshot(nodeId);
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

    /// @notice Un-enroll the caller. Only the account itself can. WARNING: while this validator is the
    ///         mounted one and committee mode is on, an account has to pass validate() to send ANY tx, and
    ///         validate() requires enrollment — so unenrolling first is self-bricking. Un-enroll only
    ///         AFTER unmounting this validator (or via owner disabling committee mode).
    function unenroll() external {
        enrolledAccount[msg.sender] = false;
        emit AccountUnenrolled(msg.sender);
    }

    // ---------------------------------------------------------------------------------------------
    //                          COMMITTEE MATH (m_e curve + threshold)
    // ---------------------------------------------------------------------------------------------

    /// @dev DSR expected-committee curve over committed pool size n:
    ///      n ≤ 8 → whole set (bootstrap); else m_e = min(110, max(16, n/5)).
    ///      Curve: m_e(N) = N for N<=8 (bootstrap whole set); else clamp(ceil(N/5), 30, 86).
    ///
    ///      TWO tails must both hold (pr-daemon round-2 B5 — B1's original single-tail floor-17/o-1.0
    ///      curve left a 6.3% honest-liveness failure). With committee K ~ Binom(n, oversample*m_e/n) and
    ///      requiredQuorum = ceil(2*m_e/3):
    ///        - forgery : P(Poisson(β*oversample*m_e) >= requiredQuorum) <= 1e-6, β <= 10% (unchanged).
    ///        - liveness: P(K < requiredQuorum) <= 1e-3 (LOOSER target, Jason-adjudicated) — a liveness
    ///          miss is a retryable one-epoch stall (seed re-draws each epoch: two-in-a-row ~5.9e-7),
    ///          not fund loss, so it is not held to the 1e-6 forgery bar.
    ///      floor 30 (up from 17) gives the forgery tail enough headroom (~4.4e-9 @ β=10% in the sampling
    ///      regime) to afford oversample = 1.25 (see constructor), which pulls the liveness tail to
    ///      <=1.65e-4 (100% online) / <=5.9e-4 (95% online) — verified by an exact Binom/Poisson scan over
    ///      n in [9,20000]. floor 17 could NOT afford any oversample (its forgery tail was 4.6e-7, razor
    ///      thin). Cost: requiredQuorum in [20,58], ~10KB (typical N<=150) to ~29KB (N>=430) calldata/op.
    ///      CAPPED AT n keeps requiredQuorum <= n in the bootstrap band; airaccount gates committee mode
    ///      on N >= N0 (>= ~39, where sampling begins) to keep small pools off the sampling path.
    function expectedCommittee(uint256 n) public pure returns (uint256) {
        if (n <= 8) return n;
        uint256 m = (n + 4) / 5; // ceil(n/5)
        if (m < 30) m = 30;
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
        // Mirror validate()'s readiness exactly: it needs seed[e] AND setRoot[e-1]. Checking only e-1 here
        // made the view report a satisfiable quorum right after an epoch boundary while every payload was
        // still rejected for the missing current seed — unreliable for the account-side mirror and for
        // monitoring (Codex round-1 Low). Fail-closed either way; this only aligns the two answers.
        if (e == 0 || !_epochUsable(e) || !_epochUsable(e - 1)) return type(uint256).max;
        uint256 n = epochSetCount[e - 1];
        if (n < minCommittee) return type(uint256).max; // below floor ⇒ unsatisfiable (mirrors validate)
        return _quorumOf(expectedCommittee(n));
    }

    /// @dev An epoch's snapshot is usable only if it was pinned AND under the current epoch schedule
    ///      (configVersion). This makes a post-reconfiguration seed/root fail-closed rather than being
    ///      combined across incompatible schedules.
    function _epochUsable(uint256 e) internal view returns (bool) {
        return epochPinned[e] && epochConfigVersion[e] == configVersion
        // STRICTLY less than, not <=. SP's `consumeGuardianExit` admits an exit at
        // `block.timestamp == readyAt` (BLSAggregator.sol:1803). A node that was clean at freeze time
        // (readyAt == 0 is required) and filed in that same second matures at exactly
        // freezeTime + GUARDIAN_EXIT_DELAY == epochSetValidUntil — so at that instant it can already
        // have withdrawn, while `validate` never re-reads the Registry. Reads only this contract's own
        // storage, so validate() stays ERC-7562 clean.
        && block.timestamp < epochSetValidUntil[e];
    }

    // ---------------------------------------------------------------------------------------------
    //                          VALIDATE (committee path; overrides the base whole-set path)
    // ---------------------------------------------------------------------------------------------

    function validate(bytes32 hash, bytes calldata signature) external view override returns (uint256) {
        // Committee mode disabled → behave exactly like the base contract (whole-set aggregate verify).
        if (epochLength == 0) return _validateWholeSet(hash, signature);

        // Length guard FIRST — before any calldata slice — so a short signature fails closed (return 1)
        // instead of reverting on an out-of-bounds slice. Uniform fail-closed is the base contract's
        // contract (pr-daemon round-3 regression: an earlier accountId slice moved ahead of this check).
        if (signature.length < 32 + G2_LEN) return 1;

        bytes32 seed;
        bytes32 setRoot;
        uint256 committedCount;
        {
            uint256 e = block.number / epochLength;
            // Need seed[e] (this epoch) and setRoot[e-1] (frozen last epoch, the look-ahead set), both
            // under the current epoch schedule. Fail-closed if either is missing/stale (keeper must
            // snapshot each epoch inside its window).
            if (e == 0 || !_epochUsable(e) || !_epochUsable(e - 1)) return 1;
            seed = epochSeed[e];
            setRoot = epochSetRoot[e - 1];
            committedCount = epochSetCount[e - 1];
        }

        // CC-97 FLOOR: a frozen pool below minCommittee can never carry committee security (the ⌈2m/3⌉
        // ratio degenerates at tiny N). Fail closed, consistent with requiredQuorum()'s sentinel.
        if (committedCount < minCommittee) return 1;

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

        // ---- parse layout: accountId(32) || k×(nodeId(32) || slot(32) || proof(TREE_DEPTH*32)) || blsSig
        //      The slot is submitter-provided and authenticated by the Merkle proof against setRoot[e-1];
        //      a wrong slot cannot verify, so membership binds to the node's HISTORICAL slot (Codex Medium).
        //      Intermediate parse/quorum locals are block-scoped so validate()'s live stack stays within
        //      the non-via-IR limit that `forge coverage` compiles under.
        uint256 k;
        uint256 T;
        {
            uint256 perSigner = 64 + TREE_DEPTH * 32;
            uint256 body = signature.length - 32 - G2_LEN; // safe: length >= 32 + G2_LEN checked above
            if (body == 0 || body % perSigner != 0) return 1;
            k = body / perSigner;
            if (k > MAX_NODE_COUNT) return 1; // gas-griefing bound (shared with the base cap)
            uint256 m = expectedCommittee(committedCount);
            if (k < _quorumOf(m)) return 1; // requiredQuorum for THIS epoch (over the look-ahead set)
            T = _thresholdOf(committedCount, m);
        }

        // Per-signer membership + sortition is factored into a helper (params packed into a memory struct
        // = one stack slot) so validate()'s own stack stays within the non-via-IR limit `forge coverage`
        // compiles under. ok=false means some check failed (fail-closed).
        (bool ok, bytes32[] memory nodeIds) = _verifyCommitteeSigners(signature, k, _Ctx(seed, setRoot, accountId, T));
        if (!ok) return 1;

        // blsSig is the trailing G2_LEN bytes: off after k signers is exactly signature.length - G2_LEN.
        bytes calldata blsSignature = signature[signature.length - G2_LEN:];
        if (_isG2InfinityCalldata(blsSignature)) return 1;

        bytes memory messagePoint = _hashToG2(hash);
        if (_isG2InfinityMemory(messagePoint)) return 1;

        bytes memory blsSigMem = blsSignature;
        return _validateBLSSignatureMem(nodeIds, blsSigMem, messagePoint) ? 0 : 1;
    }

    /// @dev Parse and verify the k committee signers: canonical slot, strictly-increasing distinct
    ///      nodeIds, still-registered + staked, Merkle membership in the look-ahead setRoot, and the
    ///      sortition draw. Returns (true, nodeIds) on full success; (false, []) the moment any check
    ///      fails. Split out of validate() to keep that frame within the non-via-IR stack limit.
    /// @dev Committee-verification parameters, packed so the helper takes one memory pointer instead of
    ///      four stack words (keeps both frames within the non-via-IR limit for `forge coverage`).
    struct _Ctx {
        bytes32 seed;
        bytes32 setRoot;
        bytes32 accountId;
        uint256 T;
    }

    function _verifyCommitteeSigners(bytes calldata signature, uint256 k, _Ctx memory ctx)
        internal
        view
        returns (bool, bytes32[] memory)
    {
        bytes32[] memory nodeIds = new bytes32[](k);
        bytes32 prevId = bytes32(0);
        uint256 off = 32;
        for (uint256 i = 0; i < k; i++) {
            bytes32 nid = bytes32(signature[off:off + 32]);
            uint256 slot = uint256(bytes32(signature[off + 32:off + 64]));
            off += 64;
            // Canonical slot only: _verifyMerkle folds just the low TREE_DEPTH bits, so slot and
            // slot + q*2^TREE_DEPTH would share a path. Reject non-canonical aliases (Codex round-2 Low).
            if (slot >= (1 << TREE_DEPTH)) return (false, nodeIds);
            // Distinct, strictly-increasing signers (blocks self-repetition inflating the aggregate).
            if (i != 0 && nid <= prevId) return (false, nodeIds);
            prevId = nid;
            // Still-active + economically backed (rejects retired bootstrap in staked mode).
            if (!isRegistered[nid]) return (false, nodeIds);
            if (requireStake && isBootstrap[nid]) return (false, nodeIds);
            // (a) Membership in the look-ahead set: Merkle proof at the submitted (authenticated) slot.
            if (!_verifyMerkle(ctx.setRoot, slot, nid, signature[off:off + TREE_DEPTH * 32])) {
                return (false, nodeIds);
            }
            off += TREE_DEPTH * 32;
            // (b) Sortition: the committee membership the submitter cannot choose. When T == max the pool
            //     degrades to the whole set — skip the draw so membership is truly universal.
            if (ctx.T != type(uint256).max) {
                if (uint256(keccak256(abi.encode(CMT_DOMAIN, ctx.seed, ctx.accountId, nid))) >= ctx.T) {
                    return (false, nodeIds);
                }
            }
            nodeIds[i] = nid;
        }
        return (true, nodeIds);
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
