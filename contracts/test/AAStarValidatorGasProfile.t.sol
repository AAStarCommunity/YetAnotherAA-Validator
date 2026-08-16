// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import "forge-std/console2.sol";
import "../src/AAStarValidator.sol";

/// @title AAStarValidator.validate() gas profile — reproducible ABSOLUTE cost attribution
/// @notice Regenerates the on-chain BLS-verification cost table used by the DSR "Onion" paper
///         (§5.1 two-implementation table, appendix-C reproducibility). Run:
///
///             forge test --match-test test_validate_gas_profile -vv
///
///         Methodology (per CC-95 review): every bucket is reported as an ABSOLUTE number that is
///         either (a) directly measured in this harness, or (b) fixed by the EIP-2537 precompile
///         schedule. We do NOT report "path A − path B" differences where both paths pay the same
///         amount (that subtraction cancels the very quantity it claims to isolate — the failure
///         mode CC-95 flagged). The only subtractions here are `measured_total − spec_floor`, where
///         each term is independently grounded (this is exactly the decomposition DSR uses in-paper).
///
///         Buckets:
///           • crypto floor  — deterministic EIP-2537 schedule (also cross-checked below by a direct
///                             hashToG2() measurement): hash-to-curve (RFC-9380) + pairing(k=2) +
///                             G1 aggregation. FIXED by the protocol, not by this implementation.
///           • RFC-9380 glue — hashToG2() measured − hash-to-curve crypto floor. The Solidity
///                             expand_message_xmd loop + Fp field-reduction marshalling. MEASURED.
///           • remainder     — total − hashToG2() − pairing − G1 agg. Calldata parse, EIP-2537 G1/G2
///                             point decode + subgroup checks, pairing-path memory marshalling, and
///                             per-node registration/state SLOADs. Still a bundle; isolating the
///                             stake/registration SLOAD sub-bucket cleanly needs a same-harness
///                             requireStake on/off two-arm run — the paper's §6.5 remaining work,
///                             NOT claimed here.
///
///         Second data point (CC-95, airaccount-contract profiled its own AAStarBLSKeyRegistry):
///         two independently assembly-optimised validators doing the SAME BLS aggregate verification
///         do NOT share a ~300k floor. Safe-curated / no-stake ≈ 220k vs stake-bound decentralised
///         ≈ 458k (≈2×). Crypto floors agree within 8% (same cryptography); the whole spread is in
///         the non-precompile EVM layer (impl overhead ≈52k vs ≈304k, ≈6×) ⇒ implementation-dependent
///         variance, NOT a structural floor. The ≈238k gap is a mix of the decentralised-staking
///         machinery (which curated designs simply do not have) and implementation-efficiency
///         difference; it is an UPPER BOUND on the price of binding verification to a staked
///         committee rather than a curated key list — a ceiling, not an attribution. See
///         evidence/04_gas.md.
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

    // --- Second data point (CC-95, airaccount-contract AAStarBLSKeyRegistry, forge golden 3-node) ---
    uint256 constant CURATED_TOTAL = 219_963; // Safe-curated / no-stake validator.validate()
    uint256 constant CURATED_CRYPTO_FLOOR = 167_530; // ≈ h2c 63,880 + pairing 102,900 + 2×G1ADD 750

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

        // --- Measurement 1: full validate(), cold registration storage (realistic single on-chain call).
        uint256 g0 = gasleft();
        uint256 ret = validator.validate(USER_OP_HASH, sig);
        uint256 total = g0 - gasleft();
        assertEq(ret, 0, "golden aggregate must verify (return 0)");

        // --- Measurement 2: hashToG2() directly, code warm. This ABSOLUTELY measures the entire
        //     hash-to-curve phase as executed in-contract (RFC-9380 Solidity glue + its EIP-2537
        //     precompiles), independent of the pairing/registration path. Warm the code once so the
        //     number reflects steady-state execution, not first-touch code loading.
        validator.hashToG2(USER_OP_HASH);
        uint256 h1 = gasleft();
        validator.hashToG2(USER_OP_HASH);
        uint256 h2cMeasured = h1 - gasleft();

        // Grounded splits — each subtrahend is either measured (total, h2cMeasured) or a fixed
        // EIP-2537 schedule constant. No "both-sides-pay-full" cancellation.
        uint256 rfc9380Glue = h2cMeasured > HASH_TO_CURVE_FLOOR ? h2cMeasured - HASH_TO_CURVE_FLOOR : 0;
        uint256 cryptoInValidate = h2cMeasured + PAIRING_FLOOR + G1_AGG_FLOOR;
        uint256 remainder = total > cryptoInValidate ? total - cryptoInValidate : 0;
        uint256 implOverhead = total > CRYPTO_FLOOR ? total - CRYPTO_FLOOR : 0;

        console2.log("=== AAStarValidator.validate() ABSOLUTE gas attribution (golden 2-node) ===");
        console2.log("validate() total (cold storage)         :", total);
        console2.log("--- crypto precompile floor (EIP-2537 schedule, fixed) ---");
        console2.log("  hash-to-curve floor (RFC-9380)        :", HASH_TO_CURVE_FLOOR);
        console2.log("  pairing check (k=2)                   :", PAIRING_FLOOR);
        console2.log("  G1 pubkey aggregation                 :", G1_AGG_FLOOR);
        console2.log("  crypto floor subtotal                 :", CRYPTO_FLOOR);
        console2.log("--- measured phase (direct hashToG2 call) ---");
        console2.log("  hashToG2() measured (glue+precompile) :", h2cMeasured);
        console2.log("  of which RFC-9380 Solidity glue       :", rfc9380Glue);
        console2.log("--- non-crypto EVM cost ---");
        console2.log("  impl overhead (total - crypto floor)  :", implOverhead);
        console2.log("  remainder after hashToG2+pairing+G1   :", remainder);
        console2.log("    (= calldata parse + point decode + subgroup + pairing-path");
        console2.log("       marshalling + per-node registration/state SLOADs; the");
        console2.log("       stake-SLOAD sub-split is paper's 6.5 remaining work)");
        console2.log("--- second data point (airaccount AAStarBLSKeyRegistry, curated/no-stake) ---");
        console2.log("  curated validate() total              :", CURATED_TOTAL);
        console2.log("  curated impl overhead (- crypto floor):", CURATED_TOTAL - CURATED_CRYPTO_FLOOR);
        // Deliberately NOT printing a single staked-vs-curated subtraction here: this test's staked
        // number is the COLD single-call (489,626) while the paper's canonical ceiling of ~238,417 is
        // computed from the warm -vvvv trace figure (458,380) against curated 219,963. Mixing the two
        // harnesses would manufacture a false-precision gap — exactly the cross-method error CC-95
        // polices. The published ceiling and its harness caveats (2-node vs 3-node, forge --isolate)
        // live in the paper §5.1 / evidence/04_gas.md; this test only supplies the absolute buckets.

        // Regression baseline (cold single-call profile @ HEAD): total ~490k. NB the paper's canonical
        // staked figure is 458,380 — that comes from the `-vvvv` router trace where validate() ran with
        // registration slots already warm in the same call frame; this test's cold single call reads
        // higher by the EIP-2929 first-touch surcharge. We report the cold number as the realistic
        // standalone on-chain cost and do NOT build a bucket-size argument on the cold−warm gap.
        // Wide tolerance so a compiler/opt bump nudging the glue does not red the whole run.
        assertApproxEqAbs(total, 490_000, 15_000, "validate() total gas drifted from baseline");
        assertLt(CRYPTO_FLOOR, total, "crypto floor must be below total");
        // Measured cross-check: hashToG2 sits just above its schedule floor (glue is small, ~15k),
        // and well under a full pairing — the crypto floor constants are not fabricated.
        assertGt(h2cMeasured, HASH_TO_CURVE_FLOOR, "hashToG2 must exceed its own crypto floor (has glue)");
        assertLt(h2cMeasured, HASH_TO_CURVE_FLOOR + 30_000, "hashToG2 glue should be modest, not dominant");
        // Measured fact (NOT a claimed floor): on THIS design the non-crypto EVM cost is the majority.
        // The second data point shows this is implementation-dependent, not structural.
        assertGt(implOverhead, CRYPTO_FLOOR, "on this design non-crypto EVM cost exceeds the crypto floor");
    }
}
