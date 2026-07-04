// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import "../src/AAStarValidator.sol";

/// SuperPaymaster Registry stand-in (stake stays in SuperPaymaster; validator only reads).
contract StakeRegistry is IDVTRegistry {
    mapping(bytes32 => mapping(address => bool)) public roles;
    mapping(address => uint256) public stake;
    function setRole(bytes32 r, address u, bool v) external { roles[r][u] = v; }
    function setStake(address u, uint256 a) external { stake[u] = a; }
    function hasRole(bytes32 r, address u) external view returns (bool) { return roles[r][u]; }
    function getEffectiveStake(address u, bytes32) external view returns (uint256) { return stake[u]; }
}

/// Full local E2E (Plan A v3, #163): three community operators stake → registerWithProof
/// (BLS PoP) → the DVT co-signs a userOpHash → on-chain aggregate verification passes.
/// All BLS material generated from noble curves (aggregate verify=true off-chain).
contract DvtStakeE2ETest is Test {
    AAStarValidator validator;
    StakeRegistry registry;
    bytes32 constant ROLE_DVT = keccak256("DVT");
    uint256 constant MIN_STAKE = 30 ether;

    address[3] OP = [
        0x00000000000000000000000000000000000000A1,
        0x00000000000000000000000000000000000000A2,
        0x00000000000000000000000000000000000000A3
    ];
    bytes[3] PUB;
    bytes[3] POPPOINT;
    bytes[3] POPSIG;

    // The DVT co-signs hashToCurve(userOpHash) — messagePoint — and the 3 node sigs
    // aggregate to AGG_SIG.
    bytes MESSAGE_POINT = hex"0000000000000000000000000000000008ecb047898685515ad76c4ed47ca143e91e1e8f71f659e5c346ee4b532c8bbf5c3f376252faf0fa8b9f46bf4523c12b0000000000000000000000000000000008531197560a096eeaec90e9c0eb6093bc010b7460745354c3c146589d7961cb15640b0d8c55b436871d5c0e2d9b7c320000000000000000000000000000000007ccd070ad13a66af87038b017ea84cab71c9cc4f19fa2406d58e2b46c430584e049e617270778e386a11ffee28f81880000000000000000000000000000000008633c44f58a9feb8c43e5ad4b30b9b4aa7102c4fb75c97f11ec7e52027cda8d0ee58a1b0293865ba15d18dbbaa2c165";
    bytes AGG_SIG = hex"0000000000000000000000000000000018b0c216f1be802c7e1fccda89a05530fbe0c2e1c919c1f4f984b2c3d095b0bc68ae96e38c45e6b691cc4e90e30798290000000000000000000000000000000012967a789574c4caf38636eb31aaf83143a72f61f73d24da3acf69001d55da42bb19832dfde25099f6b29fb2f75a076b00000000000000000000000000000000121cc802d46cadd95dc86eb922155fe9faba6d8d16423aea27445c2dcc1434cb53ef09e37ed7043efbf79a2e2768371d0000000000000000000000000000000010af3fd56f9a3f8415706f863c6be1a9003d357e9f2d86397a18dc39b8595e553917edabd377d44ae536751c7dbbb727";

    function setUp() public {
        validator = new AAStarValidator();
        registry = new StakeRegistry();
        validator.setRegistry(address(registry));
        validator.setMinStake(MIN_STAKE);
        validator.setRequireStake(true); // permissionless-but-staked mode

        PUB[0] = hex"000000000000000000000000000000000572cbea904d67468808c8eb50a9450c9721db309128012543902d0ac358a62ae28f75bb8f1c7c42c39a8c5529bf0f4e00000000000000000000000000000000166a9d8cabc673a322fda673779d8e3822ba3ecb8670e461f73bb9021d5fd76a4c56d9d4cd16bd1bba86881979749d28";
        POPPOINT[0] = hex"00000000000000000000000000000000086f6d0cdf889dc6d987ee9c5446c45b206775fcf7c60ebde4e1e0250fb04be1a86a296bae0bad3bc81f27a76ada86d50000000000000000000000000000000007906cd1575d26570463bee46945d8ef77539df93d13e22aef436f0d538bb28d916d581fe1d71bbc0d62c7ba4b8edccb000000000000000000000000000000000389f33b01cdf1a04f541764ddf51ec2dbed718f2398f75f3fce7725c072d9340263ae52e06b7bf52eb3ab7ec72ca92000000000000000000000000000000000137ab9e24a3c0f637ae65f212458ed1a10250d85da32ae5bf72842062c6819149945d2c7091607690f3c61f53e52c8b9";
        POPSIG[0] = hex"000000000000000000000000000000000fe44ee30a237243f9b73052610d1f18c059c444c64a3976167a1d56c93be382c89bf86c6885a2dc17225c108ff983a70000000000000000000000000000000018f07e274f307f104fa98bc723ab4197d86d68c7ef2c3acdc833674daebdf73ed300b62ba4ead3fbd8f78100074705e400000000000000000000000000000000028f4c1f1d45fb86c899a0dfb0b475b061cfb46a38e02211953a0b743203128d9bb661bc22cf2ca5aa2a2182599cad90000000000000000000000000000000000391964381d36a7461f20edb95daa77a328ff7a999d002abdbc5643d89b733cb9a22174c7be126204b505d9d0beb88d4";

        PUB[1] = hex"0000000000000000000000000000000009ece308f9d1f0131765212deca99697b112d61f9be9a5f1f3780a51335b3ff981747a0b2ca2179b96d2c0c9024e522400000000000000000000000000000000032b80d3a6f5b09f8a84623389c5f80ca69a0cddabc3097f9d9c27310fd43be6e745256c634af45ca3473b0590ae30d1";
        POPPOINT[1] = hex"000000000000000000000000000000000f73f219e773dd1ef6fe2d10a5c49921d8cdd723b33b34087a52617d067a2de251e945553c8bd9734ad664fb6f345fce00000000000000000000000000000000123a13ec0543aeed2afad244f7e4c9bc20ee778d6354947cbea7410820f8d907f5c025bb8e8598cbf5902a7982e1b323000000000000000000000000000000000c02e3e68f26c168a018698ba779272abe9ff0279d6f5280afc9fb3ab0160c06ecbddf2d33d0423b79a2751695f51a11000000000000000000000000000000000eaaecfea4c6ce69a92154ca4b2804d2f7017d468be09aeb0de61c4dbe2c2553afe4193e20a948afc382b97a2d36e8e4";
        POPSIG[1] = hex"00000000000000000000000000000000112fb50bdf3fc8bb65efd70651b8df399f9a98139efd7138eb4c257e446ba19b86a57e68fe5750434919dafc1bd819d20000000000000000000000000000000016ce085bf473462d09925538b981b344b5db363169376cea315a4368790a2db271e5fd15abc4907720cb1502667afec9000000000000000000000000000000001693bcda1b0fc6242d3e5f1c6789078ef5515f4d15770985693cc76306862c53fc2bca4d2a3d699b49a30b053dc992940000000000000000000000000000000018a48af2fbdbc3f63e38b131b986938d4ab6a01b237ca9a61ff6c85547104e75d5772c47c1eeca8a3475560990474a6a";

        PUB[2] = hex"0000000000000000000000000000000010e7791fb972fe014159aa33a98622da3cdc98ff707965e536d8636b5fcc5ac7a91a8c46e59a00dca575af0f18fb13dc0000000000000000000000000000000016ba437edcc6551e30c10512367494bfb6b01cc6681e8a4c3cd2501832ab5c4abc40b4578b85cbaffbf0bcd70d67c6e2";
        POPPOINT[2] = hex"0000000000000000000000000000000001995c8b9763e2615565bc7f77b85424f88a76d3f6bc3c766011ede90ad5d19ad97c82f9f777fb88a9108b64e9f6dc36000000000000000000000000000000000d653750a796742eb4db97caed3419a91715230a11922b7bf8c22791a9b69a10ca3072e6292fdaf6d9e18ff258d6b6cd00000000000000000000000000000000024cc0cddd0a4e94119195861ff96783506ba3907a42e73690f50647b55cac6bba1abdb5360f4f5c1778b81b71c0938c0000000000000000000000000000000005a33a032fa529c8d2dd092ea4ad767b98573edb199de0820c10e337b1a602bb58c5188e55992bbecd615d59bf7850c1";
        POPSIG[2] = hex"0000000000000000000000000000000005e4240a50ec6846c376579ce2ed8c0cc6f161a5efb064a4c0d84086f9c847374f5c349a62c9598f3f764d75691f103200000000000000000000000000000000072d7492acac18a661b1797e81441ded455126cab92818e348bf6dfa7f8748958ca074a2ac487e9215f147fe1f3012f5000000000000000000000000000000001799abf4b69e9fde5810794f5d80919af5e9b0dfd67c70d55d7b9250c909b67fca7b724ae56538fe7c9fc0d84fc2632a000000000000000000000000000000000e4b34edcc72336743f262537655fe24d6c02858d450ee4b1cf5e563bd057814313dd59dfcea13b88c71ab8e49f124e5";
    }

    function test_e2e_stake_pop_register_cosign_verify() public {
        bytes32[] memory nodeIds = new bytes32[](3);

        for (uint256 i = 0; i < 3; i++) {
            // (1) operator stakes GToken for ROLE_DVT in the SuperPaymaster Registry
            registry.setRole(ROLE_DVT, OP[i], true);
            registry.setStake(OP[i], MIN_STAKE);

            // (2) operator self-registers on the DVT validator with a BLS PoP
            vm.prank(OP[i]);
            validator.registerWithProof(PUB[i], POPPOINT[i], POPSIG[i]);

            nodeIds[i] = keccak256(PUB[i]); // derived nodeId
            assertTrue(validator.isRegistered(nodeIds[i]), "node registered");
            assertEq(validator.nodeOperator(nodeIds[i]), OP[i], "bound to operator");
        }

        // (3) the DVT has co-signed the userOpHash; verify the aggregate on-chain.
        bool ok = validator.validateAggregateSignature(nodeIds, AGG_SIG, MESSAGE_POINT);
        assertTrue(ok, "aggregate co-signature verifies (validate == 0 equivalent)");
    }

    function test_e2e_unstakedNodeCannotJoinQuorum() public {
        // node 0 + 1 stake & register; node 2 does NOT stake → cannot register → its
        // signature can't be part of a verifiable quorum.
        for (uint256 i = 0; i < 2; i++) {
            registry.setRole(ROLE_DVT, OP[i], true);
            registry.setStake(OP[i], MIN_STAKE);
            vm.prank(OP[i]);
            validator.registerWithProof(PUB[i], POPPOINT[i], POPSIG[i]);
        }
        vm.prank(OP[2]);
        vm.expectRevert("Operator not staked for ROLE_DVT");
        validator.registerWithProof(PUB[2], POPPOINT[2], POPSIG[2]);
    }
}
