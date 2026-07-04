// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import "../src/AAStarValidator.sol";

/// SuperPaymaster Registry stand-in for the stake gate (IDVTRegistry): role + locked stake.
contract StakeRegistry is IDVTRegistry {
    mapping(bytes32 => mapping(address => bool)) public roles;
    mapping(address => uint256) public stake;

    function setRole(bytes32 roleId, address user, bool v) external { roles[roleId][user] = v; }
    function setStake(address user, uint256 amount) external { stake[user] = amount; }

    function hasRole(bytes32 roleId, address user) external view returns (bool) { return roles[roleId][user]; }
    function getEffectiveStake(address user, bytes32) external view returns (uint256) { return stake[user]; }
}

contract AAStarValidatorStakeBindingTest is Test {
    AAStarValidator validator;
    StakeRegistry registry;

    bytes32 constant ROLE_DVT = keccak256("DVT");
    uint256 constant MIN_STAKE = 30 ether;
    // 128-byte G1 keys (content irrelevant for the binding logic under test).
    bytes KEY_A = new bytes(128);
    bytes KEY_B = new bytes(128);
    bytes32 constant NODE_A = keccak256("nodeA");
    bytes32 constant NODE_B = keccak256("nodeB");

    address operator1 = address(0xA1);
    address operator2 = address(0xA2);

    function setUp() public {
        validator = new AAStarValidator(); // deployer (this) = owner
        registry = new StakeRegistry();
        validator.setRegistry(address(registry));
        validator.setMinStake(MIN_STAKE);
        KEY_A[0] = 0x01;
        KEY_B[0] = 0x02;
    }

    function _stake(address op, uint256 amount) internal {
        registry.setRole(ROLE_DVT, op, true);
        registry.setStake(op, amount);
    }

    // --- staked mode: permissionless-but-staked ---------------------------------
    function test_StakedMode_operatorRegisters() public {
        validator.setRequireStake(true);
        _stake(operator1, MIN_STAKE);

        vm.prank(operator1);
        validator.registerPublicKey(NODE_A, KEY_A);

        assertTrue(validator.isRegistered(NODE_A));
        assertEq(validator.nodeOperator(NODE_A), operator1);
        assertEq(validator.operatorNode(operator1), NODE_A);
        assertFalse(validator.isBootstrap(NODE_A));
    }

    function test_StakedMode_rejectsUnstaked() public {
        validator.setRequireStake(true);
        // operator1 has no role/stake
        vm.prank(operator1);
        vm.expectRevert("Operator not staked for ROLE_DVT");
        validator.registerPublicKey(NODE_A, KEY_A);
    }

    function test_StakedMode_rejectsBelowMinStake() public {
        validator.setRequireStake(true);
        _stake(operator1, MIN_STAKE - 1);
        vm.prank(operator1);
        vm.expectRevert("Operator not staked for ROLE_DVT");
        validator.registerPublicKey(NODE_A, KEY_A);
    }

    function test_StakedMode_oneNodePerOperator() public {
        validator.setRequireStake(true);
        _stake(operator1, MIN_STAKE);
        vm.startPrank(operator1);
        validator.registerPublicKey(NODE_A, KEY_A);
        vm.expectRevert("Operator already has a node"); // anti-Sybil: 1 stake -> 1 node
        validator.registerPublicKey(NODE_B, KEY_B);
        vm.stopPrank();
    }

    // --- syncNode: deactivate stale nodes ---------------------------------------
    function test_syncNode_deactivatesUnstakedOperator() public {
        validator.setRequireStake(true);
        _stake(operator1, MIN_STAKE);
        vm.prank(operator1);
        validator.registerPublicKey(NODE_A, KEY_A);

        // operator exits stake
        registry.setStake(operator1, 0);
        registry.setRole(ROLE_DVT, operator1, false);

        validator.syncNode(NODE_A); // anyone can call
        assertFalse(validator.isRegistered(NODE_A), "deactivated");
        assertEq(validator.operatorNode(operator1), bytes32(0), "binding cleared -> can re-stake+register");
    }

    function test_syncNode_revertsWhenStillActive() public {
        validator.setRequireStake(true);
        _stake(operator1, MIN_STAKE);
        vm.prank(operator1);
        validator.registerPublicKey(NODE_A, KEY_A);
        vm.expectRevert("Node still active");
        validator.syncNode(NODE_A);
    }

    // --- migration boundary: bootstrap nodes retire when staking turns on -------
    function test_migrationBoundary_bootstrapRetiredOnToggle() public {
        // bootstrap register (owner, requireStake=false)
        validator.registerPublicKey(NODE_A, KEY_A);
        assertTrue(validator.isBootstrap(NODE_A));

        // turn staking on -> bootstrap node can be synced out
        validator.setRequireStake(true);
        validator.syncNode(NODE_A);
        assertFalse(validator.isRegistered(NODE_A), "bootstrap node retired");
    }

    function test_onlyOwner_setters() public {
        vm.prank(operator1);
        vm.expectRevert("Only owner can call this function");
        validator.setRequireStake(true);
    }
}
