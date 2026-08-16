// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import "forge-std/console2.sol";

/// @title CC-98 committee-selection gas microbenchmark (PROTOTYPE, not production)
/// @notice Decides the sampling-vs-VRF question for the per-proposal committee model. Measures the
///         MARGINAL on-chain cost each mechanism adds to validate() for its committee-membership check
///         (on top of the identical aggregate co-sign verify, which both pay). Two mechanisms:
///
///         A) Deterministic SAMPLING: validate() recomputes committee = sample(seed, activeSet) via a
///            partial Fisher-Yates over a COMPACT active-node array, then checks signers ⊆ committee.
///            Cost driver: m array SLOADs + m keccaks. NO extra pairings.
///
///         B) BLS-VRF SORTITION: each signer proves selection with a BLS sig over the seed; selected
///            iff hash(vrfSig_i) < T. Because selection reads the INDIVIDUAL output, the k VRF sigs
///            CANNOT be aggregate-verified (an attacker could offset sig_i/sig_j keeping the sum valid
///            but changing each hash) — so each needs its own pairing check. Cost driver: k pairing
///            verifications.
///
///         Run: forge test --match-contract CommitteeSelectionGasProto -vv
contract CommitteeSelectionGasProto is Test {
    address constant PAIRING = 0x000000000000000000000000000000000000000F;

    // Valid EIP-2537 G1 (generator) + G2 (a golden hashToCurve output) — real subgroup points so the
    // pairing precompile actually executes and we measure real gas.
    bytes G1 =
        hex"0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1";
    bytes G2 =
        hex"0000000000000000000000000000000006ee78bc8f2dec556b1fc39b04afe2126b9817c06dc3a62eebea7015bc5e5f83209b3b632351b8b32442ea4df23425cb00000000000000000000000000000000160a054c6de9a3df5ba20bdb88a06e0af04e27fccf362e3469b11ba80243ad6e78fc020c8fc79cc26c489731f7be19590000000000000000000000000000000001e519a10826c01e6492cf454c3b4fe21103add791f18c950f4202ff9e4be43e8b15185d25e6ae64f23e1c861b5e1a8300000000000000000000000000000000134607d8f6cd2b673a9d3283ec12f593d3bcb787d5d6198f3ad472e680eff430e95c708d1d880ac65fa080e74ef5e36b";

    // Compact active-node arrays (no stale ids — the model requires this for unbiased sampling).
    bytes32[] active100;
    bytes32[] active500;

    function setUp() public {
        for (uint256 i = 0; i < 100; i++) active100.push(keccak256(abi.encode("node", i)));
        for (uint256 i = 0; i < 500; i++) active500.push(keccak256(abi.encode("node", i)));
    }

    // --- A) SAMPLING: partial Fisher-Yates picks m distinct indices from an R-array, then a
    //        membership check that the k submitted signers are all in the sampled committee. ---
    function _sampleAndCheck(bytes32[] storage set, bytes32 seed, uint256 m, uint256 k)
        internal
        view
        returns (bool)
    {
        uint256 n = set.length;
        // Partial Fisher-Yates over an in-memory index array: m random swaps → committee = first m.
        uint256[] memory idx = new uint256[](n);
        for (uint256 i = 0; i < n; i++) idx[i] = i;
        bytes32[] memory committee = new bytes32[](m);
        for (uint256 i = 0; i < m; i++) {
            uint256 j = i + (uint256(keccak256(abi.encode(seed, i))) % (n - i));
            (idx[i], idx[j]) = (idx[j], idx[i]);
            committee[i] = set[idx[i]]; // the SLOAD — reading the sampled member
        }
        // Membership: the k submitted signers (here: the first k committee members) must be ⊆ committee.
        // In production the signers come from calldata; using committee members bounds the check cost.
        uint256 found;
        for (uint256 s = 0; s < k; s++) {
            bytes32 signer = committee[s];
            for (uint256 c = 0; c < m; c++) {
                if (committee[c] == signer) {
                    found++;
                    break;
                }
            }
        }
        return found == k;
    }

    function test_A_sampling_gas() public view {
        bytes32 seed = keccak256("epoch-seed");
        _bench_sampling(active100, 100, 10, 6, seed);
        _bench_sampling(active100, 100, 20, 14, seed);
        _bench_sampling(active500, 500, 10, 6, seed);
    }

    function _bench_sampling(bytes32[] storage set, uint256 R, uint256 m, uint256 k, bytes32 seed) internal view {
        uint256 g = gasleft();
        bool ok = _sampleAndCheck(set, seed, m, k);
        uint256 used = g - gasleft();
        require(ok, "membership");
        console2.log("SAMPLING  R / m / k:", R, m, k);
        console2.log("  committee-membership gas             :", used);
    }

    // --- B) BLS-VRF: k individual pairing verifications (cannot be aggregated, see header). ---
    function _pairingOnce() internal view returns (uint256 gasUsed) {
        // 2-pair input (as a per-signer VRF verify would be: e(g,sig)·e(-pk,H)==1): [G1][G2][G1][G2].
        bytes memory input = bytes.concat(G1, G2, G1, G2);
        uint256 g = gasleft();
        (bool ok, ) = PAIRING.staticcall(input);
        gasUsed = g - gasleft();
        ok; // gas is charged regardless of the boolean result
    }

    function test_B_vrf_gas() public view {
        _bench_vrf(6);
        _bench_vrf(14);
    }

    function _bench_vrf(uint256 k) internal view {
        uint256 total;
        for (uint256 i = 0; i < k; i++) total += _pairingOnce();
        console2.log("VRF k signers:", k);
        console2.log("  per-signer pairing verify gas        :", total / k);
        console2.log("  k individual VRF-verify gas (total)  :", total);
    }
}
