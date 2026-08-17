// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title DeployCommitteeValidator
 * @dev Deploy the CC-98 AAStarCommitteeValidator (per-proposal random-committee BLS validator, PR #237)
 *      and wire it to the SuperPaymaster Registry (stake source of truth), same as the Plan A v3 deploy.
 *
 *      DEPLOYS IN LEGACY MODE (committee mode OFF): the constructor leaves epochLength == 0, so validate()
 *      behaves exactly like the base AAStarValidator (whole-set aggregate verify) — a safe drop-in for the
 *      current 0x539B. This script INTENTIONALLY does NOT call setEpochLength.
 *
 *      MIGRATION INTERLOCK (pr-daemon B2 — do NOT skip): committee mode MUST NOT be enabled until the
 *      accountId-injecting airaccount v0.31.0 accounts are deployed, mounted on this validator, and have
 *      called enroll(). Flipping setEpochLength early would fail-close honest legacy traffic; an attacker's
 *      legacy-shaped payload is blocked on-chain by the enrollment gate, but the correct order is still:
 *        1) deploy this validator (epochLength == 0, legacy)             ← this script
 *        2) airaccount deploys v0.31.0 accounts that inject address(this) + call enroll()
 *        3) mount + testnet e2e
 *        4) ONLY THEN: owner(Safe) calls setEpochLength(L) to turn committee mode on (L >= 64; N >= ~39)
 *
 *  SP_REGISTRY   = SuperPaymaster Registry (default: Sepolia deploy)
 *  MIN_STAKE     = ROLE_DVT floor (default 30 ether GToken)
 *  REQUIRE_STAKE = "true" to enable permissionless-but-staked immediately (default false = bootstrap)
 *
 *  forge script script/DeployCommitteeValidator.s.sol --rpc-url <RPC> --private-key <KEY> --broadcast --legacy
 */

import "forge-std/Script.sol";
import "../src/AAStarCommitteeValidator.sol";

contract DeployCommitteeValidator is Script {
    // SuperPaymaster Sepolia (same source of truth as DeployStakeBoundValidator).
    address constant SP_REGISTRY_SEPOLIA = 0xf5Bf37ca83AfdAab73691bA7eCcDfA69b8708E71;

    function run() external {
        address registry = vm.envOr("SP_REGISTRY", SP_REGISTRY_SEPOLIA);
        uint256 minStake = vm.envOr("MIN_STAKE", uint256(30 ether));
        bool requireStake = vm.envOr("REQUIRE_STAKE", false);

        vm.startBroadcast();

        AAStarCommitteeValidator validator = new AAStarCommitteeValidator();
        validator.setRegistry(registry);
        validator.setMinStake(minStake);
        if (requireStake) validator.setRequireStake(true);
        // NOTE: epochLength is deliberately left at 0 (committee mode OFF). See the migration interlock.

        vm.stopBroadcast();

        console.log("=== CC-98 AAStarCommitteeValidator deployed (LEGACY MODE, committee OFF) ===");
        console.log("validator:     ", address(validator));
        console.log("registry:      ", registry);
        console.log("minStake:      ", minStake);
        console.log("requireStake:  ", requireStake);
        console.log("epochLength:   ", validator.epochLength(), "(0 = committee mode OFF)");
        console.log("committeeActive:", validator.committeeActive());
        console.log("oversample:    ", validator.oversampleNum(), "/", validator.oversampleDen());
        console.log("owner:         ", validator.owner());
        console.log("");
        console.log("Next (migration interlock - in order):");
        console.log(" 1. transfer owner to a Gnosis Safe");
        console.log(" 2. airaccount deploys v0.31.0 accounts (inject address(this) + call enroll())");
        console.log(" 3. mount + testnet e2e");
        console.log(" 4. ONLY THEN owner(Safe) setEpochLength(L>=64) to enable committee mode (N>=~39)");
    }
}
