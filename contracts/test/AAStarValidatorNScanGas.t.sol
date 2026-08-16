// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import "forge-std/console2.sol";
import "../src/AAStarValidator.sol";

/// @title validate() committee-size (n) scan — marginal per-signer cost (CC-99 需求 3)
/// @notice The Onion reviewers asked to correct the "O(1)" claim: validate() is O(1) in PAIRING
///         (always k=2, message vs aggregate) but LINEAR in per-signer work — each extra signer costs
///         a registry lookup (isRegistered + registeredKeys SLOAD) + one G1ADD + 32 bytes calldata.
///         This measures validate() at n = 2 / 3 / 5 and prints the marginal per-signer gas.
///
///         Method: register n bootstrap nodes whose keys are all the EIP-2537 GENERATOR (a valid
///         subgroup G1 point) so the full parse → per-node lookup → G1 aggregation → pairing path
///         executes for real (validate returns 1 because the dummy G2 sig does not verify, but the
///         VERDICT does not change the per-signer COST — the linear work all runs before the pairing
///         result is known). Δgas / Δn isolates the per-signer marginal.
///
///         Run: forge test --match-test test_validate_nscan -vv
contract AAStarValidatorNScanGas is Test {
    AAStarValidator validator;

    bytes32 constant USER_OP_HASH =
        bytes32(uint256(0x1111111111111111111111111111111111111111111111111111111111111111));

    // Valid EIP-2537 G1 generator — a real subgroup point, so G1 aggregation runs (no revert).
    bytes G1 =
        hex"0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1";
    // A valid G2 (golden hashToCurve output) as the 256-byte aggregate-sig slice — non-infinity so the
    // pairing runs; it will not verify (returns 1), which does not affect the per-signer cost.
    bytes SIG_G2 =
        hex"0000000000000000000000000000000006ee78bc8f2dec556b1fc39b04afe2126b9817c06dc3a62eebea7015bc5e5f83209b3b632351b8b32442ea4df23425cb00000000000000000000000000000000160a054c6de9a3df5ba20bdb88a06e0af04e27fccf362e3469b11ba80243ad6e78fc020c8fc79cc26c489731f7be19590000000000000000000000000000000001e519a10826c01e6492cf454c3b4fe21103add791f18c950f4202ff9e4be43e8b15185d25e6ae64f23e1c861b5e1a8300000000000000000000000000000000134607d8f6cd2b673a9d3283ec12f593d3bcb787d5d6198f3ad472e680eff430e95c708d1d880ac65fa080e74ef5e36b";

    // One validator per committee size, each populated in setUp() so the first validate() in the
    // test sees COLD registration storage (the realistic on-chain scenario — registration happened
    // in a PAST transaction). Forge resets the access list at the setUp→test boundary.
    AAStarValidator v2;
    AAStarValidator v3;
    AAStarValidator v5;
    bytes32[] ids2;
    bytes32[] ids3;
    bytes32[] ids5;

    function setUp() public {
        v2 = new AAStarValidator();
        v3 = new AAStarValidator();
        v5 = new AAStarValidator();
        ids2 = _register(v2, 2);
        ids3 = _register(v3, 3);
        ids5 = _register(v5, 5);
    }

    function _register(AAStarValidator v, uint256 n) internal returns (bytes32[] memory ids) {
        ids = new bytes32[](n);
        for (uint256 i = 0; i < n; i++) {
            bytes32 id = keccak256(abi.encode("nscan", i));
            v.registerPublicKey(id, G1);
            ids[i] = id;
        }
        for (uint256 a = 1; a < n; a++) {
            bytes32 key = ids[a];
            uint256 b = a;
            while (b > 0 && ids[b - 1] > key) {
                ids[b] = ids[b - 1];
                b--;
            }
            ids[b] = key;
        }
    }

    function _measureCold(AAStarValidator v, bytes32[] storage ids) internal view returns (uint256 gasUsed) {
        bytes memory sig = abi.encodePacked(abi.encodePacked(ids), SIG_G2);
        uint256 g = gasleft();
        v.validate(USER_OP_HASH, sig);
        gasUsed = g - gasleft();
    }

    function test_validate_nscan() public view {
        uint256 g2 = _measureCold(v2, ids2);
        uint256 g3 = _measureCold(v3, ids3);
        uint256 g5 = _measureCold(v5, ids5);

        console2.log("=== validate() committee-size scan (all-generator keys, cold) ===");
        console2.log("n=2 total gas :", g2);
        console2.log("n=3 total gas :", g3);
        console2.log("n=5 total gas :", g5);
        console2.log("--- marginal per-signer ---");
        console2.log("  (n3 - n2)          :", g3 - g2);
        console2.log("  (n5 - n3) / 2      :", (g5 - g3) / 2);
        console2.log("NB pairing is CONSTANT (k=2) at every n; the marginal above = registry lookup");
        console2.log("   (isRegistered + registeredKeys SLOAD) + 1 G1ADD + 32B calldata per signer.");

        // Linear, not O(1): each added signer costs a measurable, roughly-constant marginal.
        assertGt(g3, g2, "n=3 must cost more than n=2 (per-signer work is not free)");
        assertGt(g5, g3, "n=5 must cost more than n=3");
        // The per-signer marginal is dominated by the registry SLOADs (~a few k), NOT the 375 G1ADD —
        // so it must be well above 375 (the reviewers' point that 'third key adds only 375' is wrong).
        assertGt(g3 - g2, 375, "per-signer marginal exceeds the G1ADD-only 375 (lookups dominate)");
    }
}
