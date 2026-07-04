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
    address operator1 = address(0xA1);
    address operator2 = address(0xA2);

    // Known-answer PoP vectors (noble @noble/curves, DST AASTAR_DVT_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_).
    // e(g1, POP_SIG) == e(PUB, POP_POINT) holds (noble verify=true).
    bytes V1_PUB = hex"000000000000000000000000000000001928f3beb93519eecf0145da903b40a4c97dca00b21f12ac0df3be9116ef2ef27b2ae6bcd4c5bc2d54ef5a70627efcb700000000000000000000000000000000108dadbaa4b636445639d5ae3089b3c43a8a1d47818edd1839d7383959a41c10fdc66849cfa1b08c5a11ec7e28981a1c";
    bytes V1_POP_POINT = hex"00000000000000000000000000000000086f6d0cdf889dc6d987ee9c5446c45b206775fcf7c60ebde4e1e0250fb04be1a86a296bae0bad3bc81f27a76ada86d50000000000000000000000000000000007906cd1575d26570463bee46945d8ef77539df93d13e22aef436f0d538bb28d916d581fe1d71bbc0d62c7ba4b8edccb000000000000000000000000000000000389f33b01cdf1a04f541764ddf51ec2dbed718f2398f75f3fce7725c072d9340263ae52e06b7bf52eb3ab7ec72ca92000000000000000000000000000000000137ab9e24a3c0f637ae65f212458ed1a10250d85da32ae5bf72842062c6819149945d2c7091607690f3c61f53e52c8b9";
    bytes V1_POP_SIG = hex"00000000000000000000000000000000022bd720bb56d00b92f4995e3e4342b2cb7fb8ca8d54e58ff20adc76760c2340c2b1e119a19db8640cffad3f0e41c850000000000000000000000000000000000eafa2b92b141289b6e189c9a0a4d3b1b9a9cd0e5d51b43482b7a1b261134049a601bda9fabb054c36e790fb6b6ca3e7000000000000000000000000000000000b6232777504abec794edddee6bb8b38b9fa3292d2376a3ddaed676bf0b5406c981292eb50ec1b2d8dffec72f1f9aab400000000000000000000000000000000019da6fdf9a09dd3b32c75176c36426118bab60496b3583c817dde359dadf72fc87ddd09a192bd32766938a92cf4ff5c";

    bytes V2_PUB = hex"0000000000000000000000000000000019cdf3807146e68e041314ca93e1fee0991224ec2a74beb2866816fd0826ce7b6263ee31e953a86d1b72cc2215a577930000000000000000000000000000000007481b1f261aabacf45c6e4fc278055441bfaf99f604d1f835c0752ac9742b4522c9f5c77db40989e7da608505d48616";
    bytes V2_POP_POINT = hex"000000000000000000000000000000000f73f219e773dd1ef6fe2d10a5c49921d8cdd723b33b34087a52617d067a2de251e945553c8bd9734ad664fb6f345fce00000000000000000000000000000000123a13ec0543aeed2afad244f7e4c9bc20ee778d6354947cbea7410820f8d907f5c025bb8e8598cbf5902a7982e1b323000000000000000000000000000000000c02e3e68f26c168a018698ba779272abe9ff0279d6f5280afc9fb3ab0160c06ecbddf2d33d0423b79a2751695f51a11000000000000000000000000000000000eaaecfea4c6ce69a92154ca4b2804d2f7017d468be09aeb0de61c4dbe2c2553afe4193e20a948afc382b97a2d36e8e4";
    bytes V2_POP_SIG = hex"000000000000000000000000000000000142a94144f05fff297d81f022f4a81023db248cd04b17530e474c0a264a4a1970f53d0fdd2c75eb40767f198461e08e0000000000000000000000000000000004dfd312738238f2004bde8c5376d6262f6ae91ff8ba8d94fa4c840b1682fcfb1994738cf7a861f34411f0d3eead6f79000000000000000000000000000000000f0db21327df7234d3dab4e226caadea2f1447fa9ea5969db23d84dcf0b985c93de4dcf45041cb8c23ea8e276d0a60350000000000000000000000000000000000c933d07622ca99f9f8d9648354c07ab2d41fb7804d43f605adea83f6e4713e2d66e3ad0790ec39bf193ef3529c6693";

    function setUp() public {
        validator = new AAStarValidator(); // deployer (this) = owner
        registry = new StakeRegistry();
        validator.setRegistry(address(registry));
        validator.setMinStake(MIN_STAKE);
    }

    function _stake(address op, uint256 amount) internal {
        registry.setRole(ROLE_DVT, op, true);
        registry.setStake(op, amount);
    }

    // --- staked registration with PoP -------------------------------------------
    function test_registerWithProof_success() public {
        validator.setRequireStake(true);
        _stake(operator1, MIN_STAKE);

        vm.prank(operator1);
        validator.registerWithProof(V1_PUB, V1_POP_POINT, V1_POP_SIG);

        bytes32 nodeId = keccak256(V1_PUB);
        assertTrue(validator.isRegistered(nodeId));
        assertEq(validator.nodeOperator(nodeId), operator1);
        assertEq(validator.operatorNode(operator1), nodeId);
        assertFalse(validator.isBootstrap(nodeId));
    }

    function test_registerWithProof_rejectsBadPoP() public {
        validator.setRequireStake(true);
        _stake(operator1, MIN_STAKE);
        // V1 pubkey with V2's signature/point → pairing fails.
        vm.prank(operator1);
        vm.expectRevert("Invalid proof-of-possession");
        validator.registerWithProof(V1_PUB, V2_POP_POINT, V2_POP_SIG);
    }

    function test_registerWithProof_rejectsUnstaked() public {
        validator.setRequireStake(true);
        vm.prank(operator1);
        vm.expectRevert("Operator not staked for ROLE_DVT");
        validator.registerWithProof(V1_PUB, V1_POP_POINT, V1_POP_SIG);
    }

    function test_registerWithProof_rejectsBelowMinStake() public {
        validator.setRequireStake(true);
        _stake(operator1, MIN_STAKE - 1);
        vm.prank(operator1);
        vm.expectRevert("Operator not staked for ROLE_DVT");
        validator.registerWithProof(V1_PUB, V1_POP_POINT, V1_POP_SIG);
    }

    function test_registerWithProof_oneNodePerOperator() public {
        validator.setRequireStake(true);
        _stake(operator1, MIN_STAKE);
        vm.startPrank(operator1);
        validator.registerWithProof(V1_PUB, V1_POP_POINT, V1_POP_SIG);
        vm.expectRevert("Operator already has a node"); // anti-Sybil: 1 stake -> 1 node
        validator.registerWithProof(V2_PUB, V2_POP_POINT, V2_POP_SIG);
        vm.stopPrank();
    }

    function test_registerPublicKey_revertsWhenStaking() public {
        validator.setRequireStake(true);
        vm.expectRevert("Staking on: use registerWithProof");
        validator.registerPublicKey(keccak256("x"), V1_PUB);
    }

    // --- syncNode: deactivate stale nodes ---------------------------------------
    function test_syncNode_deactivatesUnstakedOperator() public {
        validator.setRequireStake(true);
        _stake(operator1, MIN_STAKE);
        vm.prank(operator1);
        validator.registerWithProof(V1_PUB, V1_POP_POINT, V1_POP_SIG);
        bytes32 nodeId = keccak256(V1_PUB);

        registry.setStake(operator1, 0);
        registry.setRole(ROLE_DVT, operator1, false);

        validator.syncNode(nodeId); // anyone can call
        assertFalse(validator.isRegistered(nodeId), "deactivated");
        assertEq(validator.operatorNode(operator1), bytes32(0), "binding cleared -> can re-stake");
    }

    function test_syncNode_revertsWhenStillActive() public {
        validator.setRequireStake(true);
        _stake(operator1, MIN_STAKE);
        vm.prank(operator1);
        validator.registerWithProof(V1_PUB, V1_POP_POINT, V1_POP_SIG);
        vm.expectRevert("Node still active");
        validator.syncNode(keccak256(V1_PUB));
    }

    // --- migration boundary: bootstrap nodes retire when staking turns on -------
    function test_migrationBoundary_bootstrapRetiredOnToggle() public {
        bytes32 nodeId = keccak256("bootnode");
        validator.registerPublicKey(nodeId, V1_PUB); // bootstrap (owner, requireStake=false)
        assertTrue(validator.isBootstrap(nodeId));

        validator.setRequireStake(true);
        validator.syncNode(nodeId);
        assertFalse(validator.isRegistered(nodeId), "bootstrap node retired");
    }

    function test_onlyOwner_setters() public {
        vm.prank(operator1);
        vm.expectRevert("Only owner can call this function");
        validator.setRequireStake(true);
    }

    // --- Codex fixes: infinity-point PoP bypass (was a critical hole) ------------
    function test_PoP_rejectsInfinityPopPointAndSig() public {
        validator.setRequireStake(true);
        _stake(operator1, MIN_STAKE);
        bytes memory zeroG2 = new bytes(256); // EIP-2537 infinity = all-zero
        vm.prank(operator1);
        // Without the fix this passed for ANY pubkey with no secret known.
        vm.expectRevert("Invalid proof-of-possession");
        validator.registerWithProof(V1_PUB, zeroG2, zeroG2);
    }

    function test_registerWithProof_rejectsInfinityPubkey() public {
        validator.setRequireStake(true);
        _stake(operator1, MIN_STAKE);
        bytes memory zeroG1 = new bytes(128);
        bytes memory zeroG2 = new bytes(256);
        vm.prank(operator1);
        vm.expectRevert("pubkey is infinity");
        validator.registerWithProof(zeroG1, zeroG2, zeroG2);
    }

    function test_bootstrap_rejectsInfinityPubkey() public {
        bytes memory zeroG1 = new bytes(128);
        vm.expectRevert("pubkey is infinity");
        validator.registerPublicKey(keccak256("x"), zeroG1);
    }

    // --- Codex fixes: revoke clears the 1:1 binding -----------------------------
    function test_revoke_clearsOperatorBinding() public {
        validator.setRequireStake(true);
        _stake(operator1, MIN_STAKE);
        vm.prank(operator1);
        validator.registerWithProof(V1_PUB, V1_POP_POINT, V1_POP_SIG);
        bytes32 nodeId = keccak256(V1_PUB);

        validator.revokePublicKey(nodeId); // owner revokes
        assertEq(validator.operatorNode(operator1), bytes32(0), "1:1 slot freed");

        // operator can now register a fresh node (V2) — not stranded
        vm.prank(operator1);
        validator.registerWithProof(V2_PUB, V2_POP_POINT, V2_POP_SIG);
        assertTrue(validator.isRegistered(keccak256(V2_PUB)));
    }

    // --- Codex fixes: owner bootstrap paths disabled once staking is on ---------
    function test_batchRegister_revertsWhenStaking() public {
        validator.setRequireStake(true);
        bytes32[] memory ids = new bytes32[](1);
        bytes[] memory keys = new bytes[](1);
        ids[0] = keccak256("n");
        keys[0] = V1_PUB;
        vm.expectRevert("Staking on: use registerWithProof");
        validator.batchRegisterPublicKeys(ids, keys);
    }

    function test_updatePublicKey_bootstrapNodeRevertsWhenStaking() public {
        bytes32 nodeId = keccak256("boot");
        validator.registerPublicKey(nodeId, V1_PUB); // bootstrap node (requireStake=false)
        validator.setRequireStake(true);
        vm.expectRevert("Staking on: re-register via registerWithProof");
        validator.updatePublicKey(nodeId, V2_PUB);
    }

    // Codex #163 verification pass: owner cannot toggle staking off, mutate a STAKED
    // (non-bootstrap) node's key to a PoP-less one, and toggle back on.
    function test_updatePublicKey_cannotMutateStakedNode() public {
        validator.setRequireStake(true);
        _stake(operator1, MIN_STAKE);
        vm.prank(operator1);
        validator.registerWithProof(V1_PUB, V1_POP_POINT, V1_POP_SIG);
        bytes32 stakedNode = keccak256(V1_PUB);

        validator.setRequireStake(false); // owner toggles staking off
        vm.expectRevert("Not a bootstrap node"); // staked node key is immutable
        validator.updatePublicKey(stakedNode, V2_PUB);
    }
}
