// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import "../src/AAStarValidator.sol";

// Router-mount golden vector (issue #45 port from airaccount AAStarBLSAlgorithm).
//
// Proves the ported validate() + on-chain RFC-9380 hashToG2() are byte-wire-compatible with the
// DVT signer + airaccount. All BLS material generated from @noble/curves under DST
// BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_ (off-chain aggregate verify = true):
//
//   USER_OP_HASH  = 0x11 * 32   (fixed cross-repo golden input, matches
//                   src/modules/bls/hash-to-g2.golden.spec.ts)
//   MESSAGE_POINT = hashToCurve(USER_OP_HASH, DST)   -- byte-identical golden vector
//   PUB0/PUB1     = two node G1 pubkeys (sk = 0x..07, 0x..0b)
//   AGG_SIG       = aggregateSignatures([sign(MESSAGE_POINT, sk0), sign(MESSAGE_POINT, sk1)])
//   nodeId_i      = keccak256(PUB_i)
contract AAStarValidatorRouterTest is Test {
    AAStarValidator validator;

    // Fixed cross-repo golden input (same as the off-chain hash-to-g2.golden.spec.ts).
    bytes32 constant USER_OP_HASH = bytes32(uint256(0x1111111111111111111111111111111111111111111111111111111111111111));

    // Golden EIP-2537 G2 encoding (256 bytes) of hashToCurve(USER_OP_HASH, DST). MUST equal both
    // the off-chain noble vector and the on-chain validator.hashToG2(USER_OP_HASH).
    bytes MESSAGE_POINT = hex"0000000000000000000000000000000006ee78bc8f2dec556b1fc39b04afe2126b9817c06dc3a62eebea7015bc5e5f83209b3b632351b8b32442ea4df23425cb00000000000000000000000000000000160a054c6de9a3df5ba20bdb88a06e0af04e27fccf362e3469b11ba80243ad6e78fc020c8fc79cc26c489731f7be19590000000000000000000000000000000001e519a10826c01e6492cf454c3b4fe21103add791f18c950f4202ff9e4be43e8b15185d25e6ae64f23e1c861b5e1a8300000000000000000000000000000000134607d8f6cd2b673a9d3283ec12f593d3bcb787d5d6198f3ad472e680eff430e95c708d1d880ac65fa080e74ef5e36b";

    bytes[2] PUB;

    // aggregate of the two node signatures over MESSAGE_POINT (@noble, verify == true).
    bytes AGG_SIG = hex"000000000000000000000000000000000b9f176f5113c4ccad075895d342d551ab705281d3a134902b8f6f0eb172a02b476efe18a58791bb5308a721bd87a417000000000000000000000000000000000f28139976fdab5e48503ad8d94c08ed65ef56219e423aa5942ae4b1926545ecabd48cde24179509a99ccac4b958499e000000000000000000000000000000000b7f5bcdb9f61925e00695c3a8c04dfe93258e7db5b923f6dd9b18a620e86ad45df02f23039a3ece1a09ea58e0e1677b0000000000000000000000000000000009ccf8330835ca4660012e0f587a6e0727241c3ac771858cc6d3b01d8659e3bf8a4582015610cacb9bee5f10945887af";

    function setUp() public {
        validator = new AAStarValidator();

        PUB[0] = hex"000000000000000000000000000000001928f3beb93519eecf0145da903b40a4c97dca00b21f12ac0df3be9116ef2ef27b2ae6bcd4c5bc2d54ef5a70627efcb700000000000000000000000000000000108dadbaa4b636445639d5ae3089b3c43a8a1d47818edd1839d7383959a41c10fdc66849cfa1b08c5a11ec7e28981a1c";
        PUB[1] = hex"0000000000000000000000000000000000fd75ebcc0a21649e3177bcce15426da0e4f25d6828fbf4038d4d7ed3bd4421de3ef61d70f794687b12b2d571971a550000000000000000000000000000000004523f5a3915fc57ee889cdb057e3e76109112d125217546ccfe26810c99b130d1b27820595ad61c7527dc5bbb132a90";
    }

    /// Register both nodes via the bootstrap path (requireStake off), then assert validate() ==
    /// 0 for the valid aggregate and non-zero for a tampered signature.
    function test_router_validate_valid_and_tampered_bootstrap() public {
        validator.registerPublicKey(keccak256(PUB[0]), PUB[0]);
        validator.registerPublicKey(keccak256(PUB[1]), PUB[1]);

        bytes memory sig = abi.encodePacked(keccak256(PUB[0]), keccak256(PUB[1]), AGG_SIG);
        assertEq(validator.validate(USER_OP_HASH, sig), 0, "valid aggregate must pass (return 0)");

        // Tamper the last byte of the aggregate signature to verification must fail (non-zero).
        bytes memory tampered = abi.encodePacked(keccak256(PUB[0]), keccak256(PUB[1]), AGG_SIG);
        tampered[tampered.length - 1] = bytes1(uint8(tampered[tampered.length - 1]) ^ 0x01);
        assertTrue(validator.validate(USER_OP_HASH, tampered) != 0, "tampered signature must fail (non-zero)");

        // A wrong userOpHash (message-point re-derivation binds to it) must also fail.
        bytes32 wrongHash = bytes32(uint256(USER_OP_HASH) ^ 1);
        assertTrue(validator.validate(wrongHash, sig) != 0, "wrong userOpHash must fail (op-binding)");
    }

    /// Same golden vector, but through the permissionless-but-staked path (Plan A v3): PoP-less
    /// bootstrap not used; here we exercise validate() after the staked-mode registration too by
    /// registering bootstrap then flipping requireStake would retire them — so instead just prove
    /// validate() reads only this validator's storage and returns 1 on unregistered nodes' malformed
    /// input without an external call.
    function test_router_validate_malformed_returns_one_no_revert() public {
        // No nodes registered. Malformed layouts must return 1 (never revert).
        assertEq(validator.validate(USER_OP_HASH, hex""), 1, "empty sig to 1");
        assertEq(validator.validate(USER_OP_HASH, new bytes(256)), 1, "only 256 bytes (no nodeIds) to 1");
        // 256 + 16 bytes: nodeIds region not a multiple of 32 to 1.
        assertEq(validator.validate(USER_OP_HASH, new bytes(272)), 1, "nodeIds not %32 to 1");
        // All-zero (infinity) blsSignature with a valid-length nodeIds region to 1.
        bytes memory infSig = abi.encodePacked(keccak256(PUB[0]), new bytes(256));
        assertEq(validator.validate(USER_OP_HASH, infSig), 1, "infinity blsSignature to 1");
    }

    /// The crux golden assertion: on-chain hashToG2(userOpHash) is byte-identical to the noble
    /// vector (== off-chain hash-to-g2.golden.spec.ts EXPECTED_MESSAGE_POINT). This proves the
    /// on-chain message-point recomputation is wire-compatible with the DVT signer + airaccount.
    function test_router_hashToG2_matches_noble_golden_vector() public view {
        bytes memory onchain = validator.hashToG2(USER_OP_HASH);
        assertEq(onchain.length, 256, "G2 point is 256 bytes");
        assertEq(keccak256(onchain), keccak256(MESSAGE_POINT), "on-chain hashToG2 == noble golden vector");
    }

    /// validate() must agree with the legacy calldata path validateAggregateSignature over the same
    /// (nodeIds, sig, messagePoint) — the two chains are equivalent for a registered quorum.
    function test_router_validate_agrees_with_legacy_calldata_path() public {
        validator.registerPublicKey(keccak256(PUB[0]), PUB[0]);
        validator.registerPublicKey(keccak256(PUB[1]), PUB[1]);

        bytes32[] memory nodeIds = new bytes32[](2);
        nodeIds[0] = keccak256(PUB[0]);
        nodeIds[1] = keccak256(PUB[1]);

        bool legacy = validator.validateAggregateSignature(nodeIds, AGG_SIG, MESSAGE_POINT);
        assertTrue(legacy, "legacy calldata path verifies");

        bytes memory sig = abi.encodePacked(nodeIds[0], nodeIds[1], AGG_SIG);
        assertEq(validator.validate(USER_OP_HASH, sig), 0, "router path agrees with legacy path");
    }
}
