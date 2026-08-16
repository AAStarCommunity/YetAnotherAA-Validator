// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import "forge-std/console2.sol";
import {VmSafe} from "forge-std/Vm.sol";
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
///           • crypto floor  — deterministic EIP-2537 schedule: hash-to-curve (RFC-9380) +
///                             pairing(k=2) + G1 aggregation. FIXED by the protocol, not by this
///                             implementation. NB the schedule is pinned to evm_version = "osaka"
///                             (foundry.toml). One term is NOT EIP-2537 and IS fork-sensitive: the
///                             Fp modular reduction runs on MODEXP (precompile 0x05), repriced by
///                             EIP-2565 → EIP-7883; under a different fork the RFC-9380 glue below
///                             shifts by ~1.2k. See MODEXP_REDUCE.
///           • RFC-9380 glue — hashToG2() measured − hash-to-curve schedule floor. The Solidity
///                             expand_message_xmd loop + Fp field-reduction marshalling. This is a
///                             DEFINITION (measured minus schedule), not an independent check of the
///                             floor — it just names the non-precompile remainder of hash-to-curve.
///           • remainder     — total − hashToG2() − pairing − G1 agg. Calldata parse, EIP-2537 G1/G2
///                             point decode + subgroup checks, pairing-path memory marshalling, and
///                             per-node registration/state SLOADs. Still a bundle; the requireStake
///                             gate sub-cost is isolated cleanly by the same-method two-arm test in
///                             this file (test_requireStake_gate_gas_two_arm) — measured at 5,030 gas
///                             per verify, NOT claimed from this bundle.
///
///         Second data point / two-implementation comparison lives in the paper (§5.1) and CC-95,
///         NOT hardcoded here. It is deliberately not reproduced as constants in this test for two
///         reasons: (1) airaccount's curated AAStarBLSKeyRegistry numbers cannot be regenerated in
///         THIS repo, so pinning them here would be an un-runnable citation; (2) an earlier version
///         of this file did hardcode them and mixed bucket definitions — comparing our schedule-floor
///         impl-overhead (glue INCLUDED) against a curated measured-floor overhead (glue EXCLUDED)
///         and reading the ~13k difference as "crypto floors agree within 8%". That was a bucket
///         mismatch, not a physical agreement. The cross-implementation claim belongs in the paper,
///         where both sides can be put on ONE bucket definition; this test only supplies THIS
///         validator's own absolute buckets. See evidence/04_gas.md.
contract AAStarValidatorGasProfileTest is Test {
    AAStarValidator validator;

    // Cross-repo golden input (matches AAStarValidatorRouterTest + hash-to-g2.golden.spec.ts).
    bytes32 constant USER_OP_HASH =
        bytes32(uint256(0x1111111111111111111111111111111111111111111111111111111111111111));

    bytes[2] PUB;

    // Aggregate of the two node signatures over hashToCurve(USER_OP_HASH, DST) (@noble, verify == true).
    bytes AGG_SIG =
        hex"000000000000000000000000000000000b9f176f5113c4ccad075895d342d551ab705281d3a134902b8f6f0eb172a02b476efe18a58791bb5308a721bd87a417000000000000000000000000000000000f28139976fdab5e48503ad8d94c08ed65ef56219e423aa5942ae4b1926545ecabd48cde24179509a99ccac4b958499e000000000000000000000000000000000b7f5bcdb9f61925e00695c3a8c04dfe93258e7db5b923f6dd9b18a620e86ad45df02f23039a3ece1a09ea58e0e1677b0000000000000000000000000000000009ccf8330835ca4660012e0f587a6e0727241c3ac771858cc6d3b01d8659e3bf8a4582015610cacb9bee5f10945887af";

    // --- Crypto precompile floor. The EIP-2537 terms — MAP_FP2_TO_G2 + G2ADD + PAIRING + G1ADD —
    //     are protocol-fixed and legitimately hardcoded. Two terms are NOT EIP-2537: SHA256_EXPAND
    //     (SHA-256, precompile 0x02) and MODEXP_REDUCE (0x05). Of those, MODEXP is the one
    //     FORK-SENSITIVE term (repriced EIP-2565 → EIP-7883); everything else is fork-invariant.
    uint256 constant SHA256_EXPAND = 888; // expand_message_xmd: 9 SHA-256 rounds over the golden msg
    // MODEXP (precompile 0x05) — NOT EIP-2537, and the one fork-sensitive term. 500/op is the
    // EIP-7883 (osaka) price; EIP-2565 (pre-osaka) charged less, so this line — and the RFC-9380
    // glue derived from it — is only exact under evm_version = "osaka" (pinned in foundry.toml).
    uint256 constant MODEXP_REDUCE = 4 * 500; // 4× Fp field reduction (2 Fp2 = 4 Fp) @ osaka
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
        console2.log("--- crypto precompile floor (EIP-2537 schedule @ evm_version=osaka) ---");
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
        console2.log("       marshalling + per-node registration/state SLOADs).");
        console2.log("    NB the requireStake gate is NOT in this remainder -- this profile runs the");
        console2.log("       requireStake=false path (the gate's per-node isBootstrap SLOAD short-");
        console2.log("       circuits and never executes here). Its per-verify cost (5,030) is a");
        console2.log("       SEPARATE add-on, measured by the two-arm test, not a slice of 320k.");
        // The curated (airaccount) second data point and the two-implementation comparison are NOT
        // printed here: they cannot be regenerated in this repo, and putting our schedule-floor buckets
        // beside their measured-floor buckets is apples-to-oranges. That comparison lives in the paper
        // §5.1 / CC-95, on one unified bucket definition. This test reports only THIS validator.

        // Correctness is asserted in every context. The golden aggregate must verify regardless of
        // how gas is metered.
        assertLt(CRYPTO_FLOOR, total, "crypto floor must be below total");
        assertGt(h2cMeasured, HASH_TO_CURVE_FLOOR, "hashToG2 must exceed its own crypto floor (has glue)");
        assertGt(implOverhead, CRYPTO_FLOOR, "on this design non-crypto EVM cost exceeds the crypto floor");

        // Gas-MAGNITUDE regression baselines only hold under the production build. `forge coverage`
        // compiles with the optimizer disabled + source instrumentation, which inflates every number
        // (e.g. total ~490k → ~567k), so pinning an absolute baseline there is meaningless and would
        // red the coverage run. Gate the magnitude asserts to the real `forge test` build; the console
        // profile above (the paper's appendix-C artifact) still prints in all contexts.
        if (vm.isContext(VmSafe.ForgeContext.Coverage)) return;

        // Regression baseline: total = 489,625 at HEAD, deterministic across solc 0.8.28/31/33.
        // Tight tolerance: the only measurable drift source is the MODEXP fork term (~1,200), and the
        // assertEq below locks the fork, so a real code regression can't hide inside a wide band.
        // NB the paper §5.1 "staked" figure 458,380 is close to this file's requireStake=FALSE arm
        // (gate-OFF 458,853 in the two-arm test), not the gate-ON arm (463,883) — i.e. that paper
        // number is very likely a requireStake=false measurement. Different harness (trace vs this
        // cold call), so not proof; flagged for the paper to reconcile, not asserted here.
        assertApproxEqAbs(total, 489_625, 2_000, "validate() total gas drifted from baseline");
        // Fork lock (replaces the old circular "cross-check"). The RFC-9380 glue is fork-sensitive via
        // MODEXP (0x05): ~15,075 under evm_version=osaka vs ~13,875 under prague — a stable 1,200 gap.
        // Pinning it to the osaka band (±300 absorbs the few-gas harness-layout jitter, far under the
        // 1,200 fork gap) makes a wrong-fork run fail HERE instead of silently printing "@osaka" with
        // every number ~1,200 low.
        assertApproxEqAbs(rfc9380Glue, 15_075, 300, "RFC-9380 glue outside osaka band; wrong evm_version?");
    }
}

/// SuperPaymaster Registry stand-in (IDVTRegistry): role + locked stake. Named to avoid a
/// collision with the identical helper in AAStarValidatorStakeBinding.t.sol.
contract GasProfileStakeRegistry is IDVTRegistry {
    mapping(bytes32 => mapping(address => bool)) public roles;
    mapping(address => uint256) public stake;

    function setRole(bytes32 roleId, address user, bool v) external { roles[roleId][user] = v; }
    function setStake(address user, uint256 amount) external { stake[user] = amount; }

    function hasRole(bytes32 roleId, address user) external view returns (bool) { return roles[roleId][user]; }
    function getEffectiveStake(address user, bytes32) external view returns (uint256) { return stake[user]; }
}

/// @title requireStake gate — SAME-METHOD two-arm isolation (CC-96 §6.5 open item)
/// @notice DSR's paper §6.2 previously stated the per-verify price of binding validation to a
///         decentralised staked committee as ≈24,363 gas (< 5% of validate()). That number is a
///         CROSS-METHOD subtraction — 514,000 (on-chain eth_estimateGas, requireStake=true) minus
///         489,637 (forge harness, requireStake=false) — which conflates the gate cost with the
///         ~21k base-tx + calldata that estimateGas includes and the forge gasleft() reading does
///         not. DSR flagged (and requested) that this be re-measured with ONE method.
///
///         This test does exactly that: two fresh AAStarValidator deployments, identical keys /
///         nodeIds / signature / userOpHash, each a first `validate()` in the same forge harness,
///         differing ONLY in whether the requireStake gate is active. Registration happens in the
///         test body (not setUp), so the measured slots are WARM — absolute totals here (458,824 /
///         463,854) are ~26k below the `--isolate` cold totals (484,824 / 489,854); the 5,030 DELTA
///         is identical in both modes (it is what we report), only the absolute base differs:
///           • Arm OFF — bootstrap nodes (owner registerPublicKey), requireStake = false.
///           • Arm ON  — staked nodes (permissionless registerWithProof + mock staked Registry),
///                       requireStake = true.
///         The crypto path (hash-to-curve + pairing) is byte-identical and runs fully in both arms
///         regardless of whether the aggregate verifies, so the difference is EXACTLY the storage
///         reads the requireStake gate adds to validate() (the per-node isBootstrap migration check
///         + the flag). This replaces DSR's cross-method ≈24k with a clean same-method figure; the
///         expectation is that the true per-verify gate cost is far below 24k (most of that 24k is
///         the estimateGas base-tx artifact), which only sharpens §6.2's "the most expensive part
///         of this design is not the reason it exists." Absolute number printed; see evidence/04_gas.md.
contract AAStarValidatorStakeGateGasTest is Test {
    bytes32 constant ROLE_DVT = keccak256("DVT");
    uint256 constant MIN_STAKE = 30 ether;
    address operator1 = address(0xA1);
    address operator2 = address(0xA2);

    bytes32 constant USER_OP_HASH =
        bytes32(uint256(0x1111111111111111111111111111111111111111111111111111111111111111));

    // Known-answer PoP vectors (same fixtures as AAStarValidatorStakeBinding.t.sol; noble @noble/curves).
    bytes V1_PUB = hex"000000000000000000000000000000001928f3beb93519eecf0145da903b40a4c97dca00b21f12ac0df3be9116ef2ef27b2ae6bcd4c5bc2d54ef5a70627efcb700000000000000000000000000000000108dadbaa4b636445639d5ae3089b3c43a8a1d47818edd1839d7383959a41c10fdc66849cfa1b08c5a11ec7e28981a1c";
    bytes V1_POP_POINT = hex"00000000000000000000000000000000086f6d0cdf889dc6d987ee9c5446c45b206775fcf7c60ebde4e1e0250fb04be1a86a296bae0bad3bc81f27a76ada86d50000000000000000000000000000000007906cd1575d26570463bee46945d8ef77539df93d13e22aef436f0d538bb28d916d581fe1d71bbc0d62c7ba4b8edccb000000000000000000000000000000000389f33b01cdf1a04f541764ddf51ec2dbed718f2398f75f3fce7725c072d9340263ae52e06b7bf52eb3ab7ec72ca92000000000000000000000000000000000137ab9e24a3c0f637ae65f212458ed1a10250d85da32ae5bf72842062c6819149945d2c7091607690f3c61f53e52c8b9";
    bytes V1_POP_SIG = hex"00000000000000000000000000000000022bd720bb56d00b92f4995e3e4342b2cb7fb8ca8d54e58ff20adc76760c2340c2b1e119a19db8640cffad3f0e41c850000000000000000000000000000000000eafa2b92b141289b6e189c9a0a4d3b1b9a9cd0e5d51b43482b7a1b261134049a601bda9fabb054c36e790fb6b6ca3e7000000000000000000000000000000000b6232777504abec794edddee6bb8b38b9fa3292d2376a3ddaed676bf0b5406c981292eb50ec1b2d8dffec72f1f9aab400000000000000000000000000000000019da6fdf9a09dd3b32c75176c36426118bab60496b3583c817dde359dadf72fc87ddd09a192bd32766938a92cf4ff5c";

    bytes V2_PUB = hex"0000000000000000000000000000000019cdf3807146e68e041314ca93e1fee0991224ec2a74beb2866816fd0826ce7b6263ee31e953a86d1b72cc2215a577930000000000000000000000000000000007481b1f261aabacf45c6e4fc278055441bfaf99f604d1f835c0752ac9742b4522c9f5c77db40989e7da608505d48616";
    bytes V2_POP_POINT = hex"000000000000000000000000000000000f73f219e773dd1ef6fe2d10a5c49921d8cdd723b33b34087a52617d067a2de251e945553c8bd9734ad664fb6f345fce00000000000000000000000000000000123a13ec0543aeed2afad244f7e4c9bc20ee778d6354947cbea7410820f8d907f5c025bb8e8598cbf5902a7982e1b323000000000000000000000000000000000c02e3e68f26c168a018698ba779272abe9ff0279d6f5280afc9fb3ab0160c06ecbddf2d33d0423b79a2751695f51a11000000000000000000000000000000000eaaecfea4c6ce69a92154ca4b2804d2f7017d468be09aeb0de61c4dbe2c2553afe4193e20a948afc382b97a2d36e8e4";
    bytes V2_POP_SIG = hex"000000000000000000000000000000000142a94144f05fff297d81f022f4a81023db248cd04b17530e474c0a264a4a1970f53d0fdd2c75eb40767f198461e08e0000000000000000000000000000000004dfd312738238f2004bde8c5376d6262f6ae91ff8ba8d94fa4c840b1682fcfb1994738cf7a861f34411f0d3eead6f79000000000000000000000000000000000f0db21327df7234d3dab4e226caadea2f1447fa9ea5969db23d84dcf0b985c93de4dcf45041cb8c23ea8e276d0a60350000000000000000000000000000000000c933d07622ca99f9f8d9648354c07ab2d41fb7804d43f605adea83f6e4713e2d66e3ad0790ec39bf193ef3529c6693";

    // A valid-format (non-infinity) 256-byte G2 for the sig slice. validate() runs the full crypto
    // path on it and returns 1 (these keys do not aggregate to it) — irrelevant here: both arms run
    // the identical path, so the gas difference is purely the requireStake gate, not the verdict.
    bytes SIG_G2 =
        hex"000000000000000000000000000000000b9f176f5113c4ccad075895d342d551ab705281d3a134902b8f6f0eb172a02b476efe18a58791bb5308a721bd87a417000000000000000000000000000000000f28139976fdab5e48503ad8d94c08ed65ef56219e423aa5942ae4b1926545ecabd48cde24179509a99ccac4b958499e000000000000000000000000000000000b7f5bcdb9f61925e00695c3a8c04dfe93258e7db5b923f6dd9b18a620e86ad45df02f23039a3ece1a09ea58e0e1677b0000000000000000000000000000000009ccf8330835ca4660012e0f587a6e0727241c3ac771858cc6d3b01d8659e3bf8a4582015610cacb9bee5f10945887af";

    function _sig() internal view returns (bytes memory) {
        bytes32 a = keccak256(V1_PUB);
        bytes32 b = keccak256(V2_PUB);
        (bytes32 lo, bytes32 hi) = a < b ? (a, b) : (b, a);
        return abi.encodePacked(lo, hi, SIG_G2);
    }

    function test_requireStake_gate_gas_two_arm() public {
        bytes memory sig = _sig();

        // --- Arm OFF: bootstrap nodes, requireStake = false. Fresh deploy; registration in-body ⇒
        AAStarValidator off = new AAStarValidator();
        off.registerPublicKey(keccak256(V1_PUB), V1_PUB);
        off.registerPublicKey(keccak256(V2_PUB), V2_PUB);
        uint256 g0 = gasleft();
        off.validate(USER_OP_HASH, sig);
        uint256 offGas = g0 - gasleft();

        // --- Arm ON: staked nodes, requireStake = true. Fresh deploy; registration in-body ⇒ warm slots.
        AAStarValidator on = new AAStarValidator();
        GasProfileStakeRegistry reg = new GasProfileStakeRegistry();
        on.setRegistry(address(reg));
        on.setMinStake(MIN_STAKE);
        on.setRequireStake(true);
        reg.setRole(ROLE_DVT, operator1, true);
        reg.setStake(operator1, MIN_STAKE);
        reg.setRole(ROLE_DVT, operator2, true);
        reg.setStake(operator2, MIN_STAKE);
        vm.prank(operator1);
        on.registerWithProof(V1_PUB, V1_POP_POINT, V1_POP_SIG);
        vm.prank(operator2);
        on.registerWithProof(V2_PUB, V2_POP_POINT, V2_POP_SIG);
        uint256 g1 = gasleft();
        on.validate(USER_OP_HASH, sig);
        uint256 onGas = g1 - gasleft();

        uint256 gateCost = onGas > offGas ? onGas - offGas : 0;

        console2.log("=== requireStake gate: SAME-METHOD two-arm (2 nodes, warm slots; delta invariant) ===");
        console2.log("validate() gate OFF (bootstrap)          :", offGas);
        console2.log("validate() gate ON  (staked)             :", onGas);
        console2.log("per-verify stake-gate cost (same-method) :", gateCost);
        console2.log("  (paper's prior cross-method figure was ~24,363 = 514k estimateGas - 489,637");
        console2.log("   forge; that spread is dominated by the ~21k base-tx cost estimateGas");
        console2.log("   includes and forge gasleft() does not -- this same-method delta is the");
        console2.log("   clean per-verify price of the decentralised-staking gate in validate())");

        // Correctness-shaped invariants (hold in every context): the gate costs SOMETHING (it does
        // extra per-node reads) but is nowhere near the crypto floor — decentralisation is cheap
        // per-verify. Gate the magnitude bound under coverage (optimizer-off inflation).
        assertGt(onGas, offGas, "staked mode must read at least the per-node isBootstrap gate");
        if (vm.isContext(VmSafe.ForgeContext.Coverage)) return;
        // The whole point of §6.2: this is a small number, an order of magnitude under the ~24k the
        // cross-method subtraction implied, and trivially under one validate(). Loose upper bound so
        // a schedule tweak does not red the run.
        assertLt(gateCost, 20_000, "same-method gate cost should be well under the cross-method ~24k");
    }
}
