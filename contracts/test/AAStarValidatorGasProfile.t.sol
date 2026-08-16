// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import "forge-std/console2.sol";
import "../src/AAStarValidator.sol";

/// @title AAStarValidator.validate() gas profile — reproducible cost decomposition
/// @notice Regenerates the on-chain BLS-verification cost table used by the DSR "Onion" paper
///         (§5.1, tier-BLS gas). Run:
///
///             forge test --match-test test_validate_gas_profile -vv
///
///         It prints a per-bucket decomposition of `validate()` over the cross-repo golden
///         vector (same 2-node aggregate that `AAStarValidatorRouterTest` verifies == 0), and
///         asserts the totals as a regression baseline.
///
///         Cost model — validate() = crypto precompile floor + implementation overhead:
///           • crypto floor    = deterministic EIP-2537 schedule (confirmed by the `-vvvv`
///                               staticcall trace): hash-to-curve (RFC-9380) + pairing(k=2) +
///                               G1 aggregation. FIXED by the protocol — not implementation.
///           • impl overhead   = total − floor. Pure EVM: calldata parse, EIP-2537 G1/G2 point
///                               decode + subgroup checks, RFC-9380 Solidity glue (expand_message
///                               loop, Fp field-reduction memory marshalling), memory copies, and
///                               per-node registration/stake SLOADs.
///
///         The cold−warm differential isolates the per-node registration/state SLOAD sub-bucket
///         (the price of verifying against a *decentralized staked committee* rather than a
///         curated pubkey list) from the generic EVM glue. Finding: on this design the impl
///         overhead is the ~2/3 majority and is near a structural floor — two independently
///         written assembly-optimised validators (this one + airaccount's AAStarBLSKeyRegistry)
///         both land at ~300k+ — not a low-hanging optimisation. See CC-95 / evidence/04_gas.md.
contract AAStarValidatorGasProfileTest is Test {
    AAStarValidator validator;

    // Cross-repo golden input (matches AAStarValidatorRouterTest + hash-to-g2.golden.spec.ts).
    bytes32 constant USER_OP_HASH =
        bytes32(uint256(0x1111111111111111111111111111111111111111111111111111111111111111));

    bytes[2] PUB;

    // Aggregate of the two node signatures over hashToCurve(USER_OP_HASH, DST) (@noble, verify == true).
    bytes AGG_SIG =
        hex"000000000000000000000000000000000b9f176f5113c4ccad075895d342d551ab705281d3a134902b8f6f0eb172a02b476efe18a58791bb5308a721bd87a417000000000000000000000000000000000f28139976fdab5e48503ad8d94c08ed65ef56219e423aa5942ae4b1926545ecabd48cde24179509a99ccac4b958499e000000000000000000000000000000000b7f5bcdb9f61925e00695c3a8c04dfe93258e7db5b923f6dd9b18a620e86ad45df02f23039a3ece1a09ea58e0e1677b0000000000000000000000000000000009ccf8330835ca4660012e0f587a6e0727241c3ac771858cc6d3b01d8659e3bf8a4582015610cacb9bee5f10945887af";

    // --- Deterministic EIP-2537 schedule (the crypto precompile floor; confirmed by -vvvv trace) ---
    uint256 constant SHA256_EXPAND = 888; // expand_message_xmd: 9 SHA-256 rounds over the golden msg
    uint256 constant MODEXP_REDUCE = 4 * 500; // 4× Fp field reduction (2 Fp2 = 4 Fp)
    uint256 constant MAP_FP2_TO_G2 = 2 * 23_800; // hash_to_field → two G2 points
    uint256 constant G2ADD = 600; // sum the two mapped points
    uint256 constant HASH_TO_CURVE_FLOOR = SHA256_EXPAND + MODEXP_REDUCE + MAP_FP2_TO_G2 + G2ADD; // 51,088
    uint256 constant PAIRING_FLOOR = 102_900; // PAIRING_CHECK, k=2 (= 32,600·2 + 37,700)
    uint256 constant G1_AGG_FLOOR = 375; // 1× G1ADD to aggregate two pubkeys
    uint256 constant CRYPTO_FLOOR = HASH_TO_CURVE_FLOOR + PAIRING_FLOOR + G1_AGG_FLOOR; // 154,363

    function setUp() public {
        validator = new AAStarValidator();
        PUB[0] =
            hex"000000000000000000000000000000001928f3beb93519eecf0145da903b40a4c97dca00b21f12ac0df3be9116ef2ef27b2ae6bcd4c5bc2d54ef5a70627efcb700000000000000000000000000000000108dadbaa4b636445639d5ae3089b3c43a8a1d47818edd1839d7383959a41c10fdc66849cfa1b08c5a11ec7e28981a1c";
        PUB[1] =
            hex"0000000000000000000000000000000000fd75ebcc0a21649e3177bcce15426da0e4f25d6828fbf4038d4d7ed3bd4421de3ef61d70f794687b12b2d571971a550000000000000000000000000000000004523f5a3915fc57ee889cdb057e3e76109112d125217546ccfe26810c99b130d1b27820595ad61c7527dc5bbb132a90";
        // Register in setUp() so the first validate() in the test sees COLD registration storage
        // (the realistic on-chain single-call scenario).
        validator.registerPublicKey(keccak256(PUB[0]), PUB[0]);
        validator.registerPublicKey(keccak256(PUB[1]), PUB[1]);
    }

    function _sortedIds() internal view returns (bytes32 lo, bytes32 hi) {
        bytes32 a = keccak256(PUB[0]);
        bytes32 b = keccak256(PUB[1]);
        (lo, hi) = a < b ? (a, b) : (b, a);
    }

    function test_validate_gas_profile() public {
        (bytes32 lo, bytes32 hi) = _sortedIds();
        bytes memory sig = abi.encodePacked(lo, hi, AGG_SIG);

        // 1. Cold call — realistic single on-chain validate() (registration SLOADs cold).
        uint256 g0 = gasleft();
        uint256 ret = validator.validate(USER_OP_HASH, sig);
        uint256 coldGas = g0 - gasleft();
        assertEq(ret, 0, "golden aggregate must verify (return 0)");

        // 2. Warm call — same nodeIds/keys, different userOpHash. Runs the full hash-to-curve +
        //    G1 aggregation + pairing again; only the per-node registration slots are now warm.
        //    cold − warm isolates the registration/state SLOAD sub-bucket.
        bytes32 otherHash = bytes32(uint256(USER_OP_HASH) ^ 1);
        bytes memory sig2 = abi.encodePacked(lo, hi, AGG_SIG);
        uint256 g1 = gasleft();
        validator.validate(otherHash, sig2); // wrong messagePoint ⇒ returns 1, same storage path
        uint256 warmGas = g1 - gasleft();

        uint256 sloadBucket = coldGas > warmGas ? coldGas - warmGas : 0;
        uint256 implOverhead = coldGas - CRYPTO_FLOOR;
        uint256 genericGlue = implOverhead > sloadBucket ? implOverhead - sloadBucket : 0;

        console2.log("=== AAStarValidator.validate() gas profile (golden 2-node bootstrap) ===");
        console2.log("validate() total (cold)                 :", coldGas);
        console2.log("--- crypto precompile floor (EIP-2537, fixed) ---");
        console2.log("  hash-to-curve (RFC-9380)              :", HASH_TO_CURVE_FLOOR);
        console2.log("  pairing check (k=2)                   :", PAIRING_FLOOR);
        console2.log("  G1 pubkey aggregation                 :", G1_AGG_FLOOR);
        console2.log("  crypto floor subtotal                 :", CRYPTO_FLOOR);
        console2.log("--- implementation overhead (EVM, total - floor) ---");
        console2.log("  impl overhead subtotal                :", implOverhead);
        console2.log("    registration/state SLOAD (cold-warm):", sloadBucket);
        console2.log("    generic glue (decode/subgroup/glue) :", genericGlue);

        // Regression baseline (this cold single-call profile @ HEAD): total ~490k. This is the
        // realistic on-chain scenario (registration slots cold). NB the `-vvvv` router trace shows
        // ~458k because there registration ran in the same call frame (slots already warm); the
        // ~31k gap IS the cold registration/state SLOAD premium this test isolates below. The live
        // 0x539B (requireStake=true) adds a further per-node stake-state read on top. Wide
        // tolerance so a compiler/opt bump nudging the glue does not red the whole run.
        assertApproxEqAbs(coldGas, 490_000, 15_000, "validate() total gas drifted from baseline");
        assertLt(CRYPTO_FLOOR, coldGas, "crypto floor must be below total");
        assertGt(implOverhead, PAIRING_FLOOR, "impl overhead should exceed a single pairing (the 5x finding)");
        assertGt(sloadBucket, 10_000, "cold registration/state SLOAD premium should be measurable");
    }
}
