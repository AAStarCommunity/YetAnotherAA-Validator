// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title DeployStakeBoundValidator
 * @dev Deploy the Plan A v3 AAStarValidator (#163) and wire it to the SuperPaymaster
 *      Registry (stake source of truth). SuperPaymaster registry/staking/GToken are
 *      already deployed — this only deploys the DVT validator and points it at them.
 *
 *  SP_REGISTRY  = SuperPaymaster Registry (default: Sepolia deploy)
 *  MIN_STAKE    = ROLE_DVT floor (default 30 ether GToken)
 *  REQUIRE_STAKE= "true" to enable permissionless-but-staked immediately (default false =
 *                 bootstrap; toggle on after nodes re-register via registerWithProof)
 *
 *  forge script script/DeployStakeBoundValidator.s.sol --rpc-url <RPC> --private-key <KEY> --broadcast
 */

import "forge-std/Script.sol";
import "../src/AAStarValidator.sol";

contract DeployStakeBoundValidator is Script {
    // SuperPaymaster Sepolia (deployments/config.sepolia.json)
    address constant SP_REGISTRY_SEPOLIA = 0xf5Bf37ca83AfdAab73691bA7eCcDfA69b8708E71;

    function run() external {
        address registry = vm.envOr("SP_REGISTRY", SP_REGISTRY_SEPOLIA);
        uint256 minStake = vm.envOr("MIN_STAKE", uint256(30 ether));
        bool requireStake = vm.envOr("REQUIRE_STAKE", false);

        vm.startBroadcast();

        AAStarValidator validator = new AAStarValidator();
        validator.setRegistry(registry);
        validator.setMinStake(minStake);
        if (requireStake) validator.setRequireStake(true);

        vm.stopBroadcast();

        console.log("=== Plan A v3 AAStarValidator deployed ===");
        console.log("validator:    ", address(validator));
        console.log("registry:     ", registry);
        console.log("minStake:     ", minStake);
        console.log("requireStake: ", requireStake);
        console.log("owner:        ", validator.owner());
        console.log("");
        console.log("Next: transfer owner to a Gnosis Safe; nodes stake+registerRole on SP");
        console.log("then registerWithProof (deploy/onboarding/onboard.mjs pop <operator>).");
    }
}
