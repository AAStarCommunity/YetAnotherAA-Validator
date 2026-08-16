// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import "forge-std/console2.sol";

/// @title CC-98 hash-sortition + Merkle committee gas microbenchmark (PROTOTYPE, not production)
/// @notice Follow-up to CommitteeSelectionGasProto (proto/cc98-committee-gas), which decided
///         SAMPLING beats BLS-VRF 6-25x. This measures the CONVERGED committed-root variant the
///         three parties (airaccount-contract + dvt + DSR) locked in CC-98:
///
///         Per-proposal committee selection with NO on-chain enumeration of the pool. A node is in
///         account A's committee for an epoch iff
///             H("CMT_SELECT", epochSeed, accountId, nodeId) < T          (hash-sortition)
///         and validate() authenticates each SUBMITTED signer against the epoch-snapshot commitment
///         with a per-signer Merkle proof:
///             (a) verify proof(nodeId) ∈ committedRoot                    (O(log N) keccak)
///             (b) check the sortition inequality above                   (1 keccak)
///         Zero extra pairings; cost is O(k·log N) where k = #signers, N = pool size.
///
///         Two numbers this prototype pins down:
///
///         1. VALIDATE() MEMBERSHIP HOT PATH (per op, the number airaccount needs to size the payload
///            and DSR needs for the paper): k signers × (Merkle-verify(depth d) + sortition keccak).
///            This is ON TOP of the existing per-signer registered-key lookup (~16,620/signer, measured
///            in AAStarValidatorNScanGas / PR #236) and the constant k=2 aggregate pairing (~102,900,
///            measured in AAStarValidatorGasProfile) — both orthogonal and unchanged by this model.
///
///         2. RUNNING-COMMITMENT UPDATE (per register, amortized off the op path): incremental
///            fixed-depth Merkle insert. HONEST FINDING the prototype surfaces: the discussion loosely
///            said "O(1) running commitment", but a commitment that ALSO supports membership proofs is
///            a Merkle root, whose incremental update is O(log N) hashes + O(log N) SSTORE, NOT O(1).
///            You cannot have both O(1) update and Merkle membership proofs — pick O(log N). The epoch
///            snapshot itself is O(1) (just read the current root); the per-register fold is O(log N).
///
///         Run: forge test --match-contract CommitteeSortitionMerkleGasProto -vv
contract CommitteeSortitionMerkleGasProto is Test {
    bytes32 constant DOMAIN = keccak256("CMT_SELECT"); // DSR's domain prefix (anti keccak-domain-collision)

    // ---------------------------------------------------------------------------------------------
    // Fixed-depth Merkle helpers (in-memory; proof GENERATION is not measured, only VERIFY is)
    // ---------------------------------------------------------------------------------------------

    /// @dev Build a full fixed-depth Merkle tree over `leaves` (padded with bytes32(0)) and return the
    ///      root plus a membership proof for each requested leaf index. depth d ⇒ capacity 2^d.
    function _buildTreeAndProofs(bytes32[] memory leaves, uint256 d, uint256[] memory wantIdx)
        internal
        pure
        returns (bytes32 root, bytes32[][] memory proofs)
    {
        uint256 width = 1 << d;
        // level 0 = padded leaves
        bytes32[] memory level = new bytes32[](width);
        for (uint256 i = 0; i < width; i++) {
            level[i] = i < leaves.length ? leaves[i] : bytes32(0);
        }
        // keep every level so we can pull sibling paths for the proofs
        bytes32[][] memory levels = new bytes32[][](d + 1);
        levels[0] = level;
        for (uint256 lvl = 0; lvl < d; lvl++) {
            uint256 w = level.length / 2;
            bytes32[] memory next = new bytes32[](w);
            for (uint256 i = 0; i < w; i++) {
                next[i] = keccak256(abi.encode(level[2 * i], level[2 * i + 1]));
            }
            levels[lvl + 1] = next;
            level = next;
        }
        root = level[0];

        proofs = new bytes32[][](wantIdx.length);
        for (uint256 q = 0; q < wantIdx.length; q++) {
            uint256 idx = wantIdx[q];
            bytes32[] memory proof = new bytes32[](d);
            for (uint256 lvl = 0; lvl < d; lvl++) {
                uint256 sib = idx ^ 1; // sibling at this level
                proof[lvl] = levels[lvl][sib];
                idx >>= 1;
            }
            proofs[q] = proof;
        }
    }

    // ---------------------------------------------------------------------------------------------
    // 1) VALIDATE() MEMBERSHIP HOT PATH — k signers × (Merkle verify + sortition), zero pairing
    // ---------------------------------------------------------------------------------------------

    function test_membership_hotpath_gas() public view {
        address account = address(0xA11CE);
        bytes32 epochSeed = keccak256("epoch-seed-42");
        // T = max ⇒ every candidate passes the inequality (keeps the check on the hot path while the
        //           k real members verify against the root); the keccak cost is identical for any T.
        uint256 T = type(uint256).max;

        _bench_membership(100, 7, 6, account, epochSeed, T); // N=100  depth ceil(log2)=7 (cap 128)
        _bench_membership(100, 7, 14, account, epochSeed, T);
        _bench_membership(500, 9, 6, account, epochSeed, T); // N=500  depth 9 (cap 512)
        _bench_membership(500, 9, 14, account, epochSeed, T);
        _bench_membership(1000, 10, 6, account, epochSeed, T); // N=1000 depth 10 (cap 1024)
        _bench_membership(1000, 10, 14, account, epochSeed, T);
    }

    function _bench_membership(
        uint256 N,
        uint256 d,
        uint256 k,
        address account,
        bytes32 epochSeed,
        uint256 T
    ) internal view {
        // registered pool: N distinct nodeIds (= keccak(pubkey) in production)
        bytes32[] memory pool = new bytes32[](N);
        for (uint256 i = 0; i < N; i++) pool[i] = keccak256(abi.encode("node", i));

        // pick k signers spread across the pool, build their Merkle proofs (generation NOT measured)
        uint256[] memory idx = new uint256[](k);
        for (uint256 s = 0; s < k; s++) idx[s] = (s * (N / k)) % N;
        (bytes32 root, bytes32[][] memory proofs) = _buildTreeAndProofs(pool, d, idx);

        // pull the signer leaves into a flat array so the measured loop only does verify work
        bytes32[] memory signerIds = new bytes32[](k);
        for (uint256 s = 0; s < k; s++) signerIds[s] = pool[idx[s]];

        uint256 g = gasleft();
        uint256 selected = _verifyCommittee(root, epochSeed, account, T, signerIds, idx, proofs, d);
        uint256 used = g - gasleft();

        require(selected == k, "all signers must verify + pass sortition at T=max");
        // HONEST CALLDATA CAVEAT: the measured `used` is COMPUTE only (proofs read from memory). In
        // production each signer's Merkle proof is d words = d*32 bytes of CALLDATA. Worst case (all
        // nonzero) ~16 gas/byte. This is the payload-size cost airaccount must budget on top.
        uint256 proofBytesPerSigner = d * 32;
        uint256 calldataGasEst = k * proofBytesPerSigner * 16; // upper bound (16 gas/nonzero byte)
        console2.log("MEMBERSHIP  N / depth / k:", N, d, k);
        console2.log("  committee-membership COMPUTE gas     :", used);
        console2.log("  per-signer compute (Merkle d + sort) :", used / k);
        console2.log("  proof calldata bytes/signer (d*32)   :", proofBytesPerSigner);
        console2.log("  proof calldata gas est (k, ub 16/B)  :", calldataGasEst);
        console2.log("  membership total est (compute+cd)    :", used + calldataGasEst);
    }

    /// @dev The exact per-signer work validate() would run: Merkle-verify(depth d) + sortition keccak.
    function _verifyCommittee(
        bytes32 root,
        bytes32 epochSeed,
        address account,
        uint256 T,
        bytes32[] memory signerIds,
        uint256[] memory idx,
        bytes32[][] memory proofs,
        uint256 d
    ) internal pure returns (uint256 selected) {
        for (uint256 s = 0; s < signerIds.length; s++) {
            // (a) Merkle membership against the epoch-snapshot committedRoot
            bytes32 h = signerIds[s];
            uint256 i = idx[s];
            bytes32[] memory proof = proofs[s];
            for (uint256 lvl = 0; lvl < d; lvl++) {
                bytes32 sib = proof[lvl];
                h = (i & 1) == 0 ? keccak256(abi.encode(h, sib)) : keccak256(abi.encode(sib, h));
                i >>= 1;
            }
            require(h == root, "merkle");
            // (b) hash-sortition inequality — committee membership the submitter cannot choose
            uint256 draw = uint256(keccak256(abi.encode(DOMAIN, epochSeed, account, signerIds[s])));
            if (draw < T) selected++;
        }
    }

    // ---------------------------------------------------------------------------------------------
    // 2) RUNNING-COMMITMENT UPDATE — incremental fixed-depth Merkle insert (per register)
    //    Storage-backed, Tornado-style zero-subtree caching. Measures the amortized register-side fold.
    // ---------------------------------------------------------------------------------------------

    uint256 constant TREE_DEPTH = 10; // supports 1024 nodes
    bytes32[TREE_DEPTH] filledSubtrees;
    bytes32[TREE_DEPTH] zeros;
    bytes32 committedRoot;
    uint256 nextIndex;

    function _initTree() internal {
        bytes32 z = bytes32(0);
        for (uint256 i = 0; i < TREE_DEPTH; i++) {
            zeros[i] = z;
            filledSubtrees[i] = z;
            z = keccak256(abi.encode(z, z));
        }
        committedRoot = z;
        nextIndex = 0;
    }

    /// @dev Standard incremental Merkle insert: O(depth) hashes + O(depth) SSTORE.
    function _insert(bytes32 leaf) internal {
        uint256 idx = nextIndex;
        bytes32 cur = leaf;
        for (uint256 lvl = 0; lvl < TREE_DEPTH; lvl++) {
            if (idx & 1 == 0) {
                filledSubtrees[lvl] = cur; // left child: cache, sibling is the zero subtree
                cur = keccak256(abi.encode(cur, zeros[lvl]));
            } else {
                cur = keccak256(abi.encode(filledSubtrees[lvl], cur)); // right child: fold with cached left
            }
            idx >>= 1;
        }
        committedRoot = cur;
        nextIndex += 1;
    }

    function test_running_root_update_gas() public {
        _initTree();
        // warm the tree with 200 inserts, then measure a representative insert (cold-ish frontier).
        for (uint256 i = 0; i < 200; i++) _insert(keccak256(abi.encode("seed-node", i)));

        bytes32 leaf = keccak256(abi.encode("seed-node", uint256(200)));
        uint256 g = gasleft();
        _insert(leaf);
        uint256 used = g - gasleft();

        console2.log("RUNNING-ROOT insert (depth 10):");
        console2.log("  per-register incremental fold gas    :", used);
        console2.log("  => amortized OFF the op path; O(log N), NOT O(1). epoch snapshot itself = O(1) root read.");
    }
}
