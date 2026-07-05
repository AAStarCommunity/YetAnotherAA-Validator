// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.19;

/**
 * @title AAStarValidator
 * @dev Integrated BLS aggregate signature validator with public key management
 *
 * This contract integrates the functionality of AggregateSignatureValidator and BLS12381AggregateNegation,
 * and adds public key management functionality with the following features:
 *
 * Core verification workflow:
 * 1. Accept G2-encoded message, aggregated signature, and participating public keys array or node identifiers
 * 2. Aggregate public key array through G1Add
 * 3. Negate the aggregated public key
 * 4. Perform pairing verification
 * 5. Output whether signature verification is successful
 *
 * Public key management functionality:
 * - Support mapping management between node identifiers and public keys
 * - Support registration, update, and revocation of public keys
 * - Support batch operations
 * - Support signature verification through node identifiers
 */
/// @dev Minimal read-interface into the SuperPaymaster Registry (economic single source
///      of truth). AAStarValidator READS role+stake; it never manages stake itself.
///      Matches Registry.hasRole (public mapping getter) + getEffectiveStake view.
interface IDVTRegistry {
    function hasRole(bytes32 roleId, address user) external view returns (bool);
    function getEffectiveStake(address user, bytes32 roleId) external view returns (uint256);
}

/// @dev Router-mountable algorithm interface (ported from airaccount-contract). A router can
///      dispatch to any validator implementing this: `validate(hash, signature)` recomputes the
///      message point on-chain from `hash` (the ERC-4337 userOpHash) and verifies the aggregate
///      BLS signature against it. Returns 0 on success, non-zero on failure; MUST NOT revert on
///      malformed signature input (returns 1) so a router can treat all validators uniformly.
interface IAAStarAlgorithm {
    function validate(bytes32 hash, bytes calldata signature) external view returns (uint256);
}

contract AAStarValidator is IAAStarAlgorithm {
    // =============================================================
    //                           STORAGE
    // =============================================================

    /// @dev Mapping from node identifier to registered public key
    mapping(bytes32 => bytes) public registeredKeys;

    /// @dev Mapping to check if a node identifier is registered
    mapping(bytes32 => bool) public isRegistered;

    /// @dev Array of all registered node identifiers for enumeration
    bytes32[] public registeredNodes;

    /// @dev Contract owner for administrative functions
    address public owner;

    // --- Stake-binding (issue #163, Plan A v3) -----------------------------------
    /// @dev The operator (EOA / Safe) that owns a nodeId — the slashing/economic anchor.
    mapping(bytes32 => address) public nodeOperator;
    /// @dev Reverse 1:1 lock — one active nodeId per operator in staked mode (anti-Sybil:
    ///      one GToken stake cannot back many signing identities).
    mapping(address => bytes32) public operatorNode;
    /// @dev Nodes registered by the owner during bootstrap (no stake). Retired once
    ///      requireStake is turned on (migration boundary — no permanent bypass).
    mapping(bytes32 => bool) public isBootstrap;

    /// @dev SuperPaymaster Registry (stake source of truth). Owner/Safe-settable.
    address public registry;
    /// @dev When true, registerPublicKey is permissionless-but-staked and bootstrap nodes
    ///      stop being accepted in verification. When false, owner-only bootstrap (default).
    bool public requireStake;
    /// @dev Minimum locked GToken stake under ROLE_DVT to register/stay active.
    uint256 public minStake;
    /// @dev DVT role id in the SuperPaymaster Registry.
    bytes32 public constant ROLE_DVT = keccak256("DVT");

    /// @dev Modifier to restrict access to owner only
    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can call this function");
        _;
    }

    // =============================================================
    //                           CONSTANTS
    // =============================================================

    /// @dev EIP-2537 pairing precompile address
    address private constant PAIRING_PRECOMPILE = 0x000000000000000000000000000000000000000F;

    /// @dev Standard encoded lengths for cryptographic points
    uint256 private constant G1_POINT_LENGTH = 128;
    uint256 private constant G2_POINT_LENGTH = 256;
    uint256 private constant PAIRING_LENGTH = 384; // G1 + G2

    /// @dev Generator point for the cryptographic group (EIP-2537 encoded format)
    bytes private constant GENERATOR_POINT =
        hex"0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1";

    // =============================================================
    //                           CONSTRUCTOR
    // =============================================================

    constructor() {
        owner = msg.sender;
        emit OwnershipTransferred(address(0), msg.sender);
    }

    // =============================================================
    //                           CONSTANTS
    // =============================================================

    /// @dev BLS12-381 field modulus (381 bits)
    /// p = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    uint256 private constant P_HIGH = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f624;
    uint256 private constant P_LOW = 0x1eabfffeb153ffffb9feffffffffaaab;

    // --- RFC 9380 hash_to_curve constants (ported from airaccount AAStarBLSAlgorithm) --------
    /// @dev Domain separation tag for suite BLS12381G2_XMD:SHA-256_SSWU_RO_ with the POP suffix.
    ///      MUST byte-match the off-chain DVT signer (src/utils/bls.util.ts BLS_DST) so the
    ///      on-chain message point equals `bls12_381.G2.hashToCurve(userOpHash, {DST})` (43 bytes).
    bytes private constant DST = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

    /// @dev BLS12-381 base field modulus p as 48-byte big-endian (= P_HIGH‖P_LOW); MODEXP modulus.
    bytes private constant FIELD_MODULUS =
        hex"1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab";

    /// @dev EIP-2537 MAP_FP2_TO_G2 input length (an Fp2 element = two 64-byte Fp coordinates).
    uint256 private constant FP2_INPUT_LENGTH = 128;
    /// @dev expand_message_xmd output length for G2: count(2)×m(2)×L(64) = 256 → ell = 8 SHA-256 blocks.
    uint256 private constant XMD_LEN = 256;
    uint256 private constant XMD_ELL = 8;

    /// @dev Upper bound on nodeIds in a single `validate()` call — bounds the router entry point's
    ///      pre-pairing work (parse + storage reads + G1 aggregation) so a large payload cannot
    ///      gas-grief the bundler. Matches the legacy account parser's cap.
    uint256 private constant MAX_NODE_COUNT = 100;

    // =============================================================
    //                           EVENTS
    // =============================================================

    event SignatureValidated(bytes32 indexed messageHash, uint256 publicKeysCount, bool isValid, uint256 gasUsed);

    event PublicKeyRegistered(bytes32 indexed nodeId, bytes publicKey);

    event PublicKeyUpdated(bytes32 indexed nodeId, bytes oldKey, bytes newKey);

    event PublicKeyRevoked(bytes32 indexed nodeId);

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    // --- Stake-binding (Plan A v3) ---
    event NodeBound(bytes32 indexed nodeId, address indexed operator);
    event NodeDeactivated(bytes32 indexed nodeId, address indexed operator);
    event RegistrySet(address indexed registry);
    event RequireStakeSet(bool requireStake);
    event MinStakeSet(uint256 minStake);

    function validateAggregateSignature(
        bytes32[] calldata nodeIds,
        bytes calldata signature,
        bytes calldata messagePoint
    ) external view returns (bool isValid) {
        require(nodeIds.length > 0, "No node IDs provided");
        require(signature.length == G2_POINT_LENGTH, "Invalid signature length");
        require(messagePoint.length == G2_POINT_LENGTH, "Invalid message length");

        return _validateBLSSignature(nodeIds, signature, messagePoint);
    }

    /**
     * @dev Verify aggregate BLS signature using node identifiers (emits events)
     * Note: Both BLS nodes and AA account owner sign the same original message
     *
     * @param nodeIds Array of node identifiers participating in signature
     * @param signature Aggregated BLS signature (256 bytes, G2 point)
     * @param messagePoint G2-encoded message point (256 bytes)
     * @return isValid Whether signature verification is successful
     */
    function verifyAggregateSignature(
        bytes32[] calldata nodeIds,
        bytes calldata signature,
        bytes calldata messagePoint
    ) external returns (bool isValid) {
        require(nodeIds.length > 0, "No node IDs provided");
        require(signature.length == G2_POINT_LENGTH, "Invalid signature length");
        require(messagePoint.length == G2_POINT_LENGTH, "Invalid message length");

        uint256 gasStart = gasleft();

        // Perform validation and get result
        isValid = _validateBLSSignature(nodeIds, signature, messagePoint);

        uint256 gasUsed = gasStart - gasleft();
        emit SignatureValidated(
            keccak256(abi.encode(nodeIds, signature, messagePoint)),
            nodeIds.length,
            isValid,
            gasUsed
        );
    }

    // =============================================================
    //           ROUTER ENTRY POINT (IAAStarAlgorithm.validate)
    // =============================================================

    /// @inheritdoc IAAStarAlgorithm
    /// @dev Ported from airaccount-contract AAStarBLSAlgorithm.validate (issue #45 Fix 1, Option B).
    ///      Signature layout is `[nodeIds...][blsSignature(256)]` — NO caller-supplied messagePoint.
    ///      The message point is recomputed on-chain from `hash` (the ERC-4337 userOpHash) via RFC
    ///      9380 hash_to_curve and the pairing is verified against THAT, binding the aggregate to
    ///      this exact operation (a (messagePoint, aggSig) produced for userOpHash_A cannot be
    ///      replayed against userOpHash_B). nodeCount = (signature.length - 256) / 32.
    ///
    ///      ERC-7562: this is `view` and reads ONLY this validator's own `registeredKeys` /
    ///      `isRegistered` / `isBootstrap` storage — no external calls. It is uniformly
    ///      fail-closed: EVERY malformed / unregistered / retired-bootstrap / non-quorum input
    ///      returns 1 rather than reverting (the account calls it under try/catch, treating a
    ///      revert as fail; returning 1 keeps the failure signal uniform).
    function validate(bytes32 hash, bytes calldata signature) external view override returns (uint256) {
        // Parse: variable-length nodeIds + 256-byte BLS sig (messagePoint dropped — see above).
        uint256 fixedLen = G2_POINT_LENGTH; // 256
        if (signature.length <= fixedLen) return 1;

        uint256 nodeIdsBytes = signature.length - fixedLen;
        if (nodeIdsBytes == 0 || nodeIdsBytes % 32 != 0) return 1;

        uint256 nodeCount = nodeIdsBytes / 32;
        if (nodeCount > MAX_NODE_COUNT) return 1; // gas-griefing bound

        bytes32[] memory nodeIds = new bytes32[](nodeCount);
        bytes32 prevId = bytes32(0);
        for (uint256 i = 0; i < nodeCount; i++) {
            bytes32 nid = bytes32(signature[i * 32:(i + 1) * 32]);
            // Strictly-increasing nodeIds ⇒ distinct participants. Blocks a single node inflating
            // the aggregate by repeating itself (`[nid,nid,…]` with the self-aggregated `k·sig`) to
            // fake an M-of-N quorum: the pairing is valid for the multiset, but only one distinct
            // node signed. Requires the caller to send nodeIds ascending — the same ordered-signer
            // discipline SP BLSAggregator enforces via its signerMask; it is the router wire
            // contract (the off-chain aggregator sorts before submitting).
            if (i != 0 && nid <= prevId) return 1;
            prevId = nid;
            // Fail-closed (not revert) on an unregistered or retired-bootstrap node.
            if (!isRegistered[nid]) return 1;
            if (requireStake && isBootstrap[nid]) return 1;
            nodeIds[i] = nid;
        }

        bytes calldata blsSignature = signature[nodeIdsBytes:nodeIdsBytes + G2_POINT_LENGTH];

        // Reject point-at-infinity: pairings with infinity evaluate to the identity in GT and
        // would let a zero signature satisfy the BLS factor.
        if (_isG2InfinityCalldata(blsSignature)) return 1;

        // issue #45 Fix 1: recompute the message point from userOpHash (same DST/suite as the DVT).
        bytes memory messagePoint = _hashToG2(hash);
        // Defensive: hash_to_curve never returns infinity, but assert it (keeps the prior invariant).
        if (_isG2InfinityMemory(messagePoint)) return 1;

        // Copy the calldata sig slice into memory for the memory-based pairing path used by validate().
        bytes memory blsSigMem = blsSignature;

        bool valid = _validateBLSSignatureMem(nodeIds, blsSigMem, messagePoint);
        return valid ? 0 : 1;
    }

    // =============================================================
    //             RFC 9380 hash_to_curve (issue #45 Fix 1)
    // =============================================================

    /// @notice Map a 32-byte message (the userOpHash) to a BLS12-381 G2 point, byte-identical to
    ///         `bls12_381.G2.hashToCurve(getBytes(message), { DST })` in noble-curves (the DVT).
    /// @dev Exposed as an external view for golden-vector testing / off-chain cross-checking.
    ///      No security impact: it is a pure function of `message` (no storage, no msg.sender).
    function hashToG2(bytes32 message) external view returns (bytes memory) {
        return _hashToG2(message);
    }

    /// @dev RFC 9380 `hash_to_curve` for suite BLS12381G2_XMD:SHA-256_SSWU_RO_.
    ///      1. expand_message_xmd(message, DST, 256) → 256 uniform bytes.
    ///      2. hash_to_field → two Fp2 elements u0,u1 (four 64-byte chunks reduced mod p).
    ///      3. MAP_FP2_TO_G2(u0), MAP_FP2_TO_G2(u1)   (EIP-2537 0x11; isogeny + cofactor clearing).
    ///      4. G2ADD(q0, q1)                          (EIP-2537 0x0d).
    ///      Step 4 equals RFC's clear_cofactor(map(u0)+map(u1)) because cofactor clearing is a
    ///      scalar multiplication and therefore distributes over point addition.
    function _hashToG2(bytes32 message) internal view returns (bytes memory point) {
        bytes memory uniform = _expandMessageXmd(message); // 256 bytes

        // RFC 9380 §5.3 ordering: u0 = (chunk0, chunk1), u1 = (chunk2, chunk3); each chunk mod p
        // is the c0/c1 coordinate of the Fp2 element, encoded EIP-2537-style (16-byte left pad).
        bytes memory map0 = new bytes(FP2_INPUT_LENGTH);
        bytes memory map1 = new bytes(FP2_INPUT_LENGTH);
        _placeFieldElement(map0, 0, uniform, 0); // u0.c0
        _placeFieldElement(map0, 1, uniform, 1); // u0.c1
        _placeFieldElement(map1, 0, uniform, 2); // u1.c0
        _placeFieldElement(map1, 1, uniform, 3); // u1.c1

        bytes memory q0 = _mapFp2ToG2(map0);
        bytes memory q1 = _mapFp2ToG2(map1);
        point = _g2AddPoints(q0, q1);
    }

    /// @dev RFC 9380 §5.3.1 expand_message_xmd with SHA-256, len_in_bytes = 256, ell = 8.
    function _expandMessageXmd(bytes32 message) internal view returns (bytes memory uniform) {
        // DST_prime = DST || I2OSP(len(DST), 1)
        bytes memory dstPrime = abi.encodePacked(DST, uint8(DST.length));
        // msg_prime = Z_pad(s_in_bytes=64) || msg || I2OSP(len_in_bytes,2) || I2OSP(0,1) || DST_prime
        bytes memory msgPrime = abi.encodePacked(
            new bytes(64), // Z_pad
            message,
            uint16(XMD_LEN), // l_i_b_str = I2OSP(256,2) = 0x0100
            uint8(0),
            dstPrime
        );
        bytes32 b0 = sha256(msgPrime);
        bytes32 b1 = sha256(abi.encodePacked(b0, uint8(1), dstPrime));

        uniform = new bytes(XMD_LEN);
        _writeWord(uniform, 0, b1);
        bytes32 prev = b1;
        for (uint256 i = 2; i <= XMD_ELL; i++) {
            bytes32 bi = sha256(abi.encodePacked(b0 ^ prev, uint8(i), dstPrime));
            _writeWord(uniform, (i - 1) * 32, bi);
            prev = bi;
        }
    }

    /// @dev Reduce the `chunkIndex`-th 64-byte chunk of `uniform` mod p (via MODEXP, exp = 1) and
    ///      write the 48-byte result into `mapInput` at the EIP-2537 Fp slot (`slot` ∈ {0,1}).
    function _placeFieldElement(
        bytes memory mapInput,
        uint256 slot,
        bytes memory uniform,
        uint256 chunkIndex
    ) internal view {
        // MODEXP input (EIP-198): Blen(32)|Elen(32)|Mlen(32)|B(64)|E(1)|M(48) = 209 bytes.
        bytes memory input = new bytes(209);
        bytes memory modulus = FIELD_MODULUS;
        // out is the Fp slot inside mapInput: slot 0 → bytes[16:64], slot 1 → bytes[80:128].
        uint256 dstOff = slot == 0 ? 16 : 80;
        assembly {
            let p := add(input, 0x20)
            mstore(p, 64) // Blen
            mstore(add(p, 32), 1) // Elen
            mstore(add(p, 64), 48) // Mlen
            // B: 64 bytes from uniform[chunkIndex*64 :]
            mcopy(add(p, 96), add(add(uniform, 0x20), mul(chunkIndex, 64)), 64)
            mstore8(add(p, 160), 1) // E = 0x01
            mcopy(add(p, 161), add(modulus, 0x20), 48) // M = p
            // MODEXP (0x05) → 48-byte reduced value written straight into the map slot.
            let ok := staticcall(gas(), 0x05, p, 209, add(add(mapInput, 0x20), dstOff), 48)
            if iszero(ok) { revert(0, 0) }
        }
    }

    /// @dev EIP-2537 BLS12_MAP_FP2_TO_G2 (0x11): Fp2 (128 bytes) → G2 point (256 bytes).
    function _mapFp2ToG2(bytes memory fp2) internal view returns (bytes memory out) {
        out = new bytes(G2_POINT_LENGTH);
        assembly {
            // MAP_FP2_TO_G2 (0x11)
            let ok := staticcall(gas(), 0x11, add(fp2, 0x20), FP2_INPUT_LENGTH, add(out, 0x20), 256)
            if iszero(ok) { revert(0, 0) }
        }
    }

    /// @dev EIP-2537 BLS12_G2ADD (0x0d): add two G2 points (memory operands).
    function _g2AddPoints(bytes memory a, bytes memory b) internal view returns (bytes memory out) {
        out = new bytes(G2_POINT_LENGTH);
        assembly {
            let input := mload(0x40)
            mstore(0x40, add(input, 512))
            mcopy(input, add(a, 0x20), 256)
            mcopy(add(input, 256), add(b, 0x20), 256)
            // G2ADD (0x0d)
            let ok := staticcall(gas(), 0x0d, input, 512, add(out, 0x20), 256)
            if iszero(ok) { revert(0, 0) }
        }
    }

    /// @dev Write a 32-byte word into `buf` at byte offset `off`.
    function _writeWord(bytes memory buf, uint256 off, bytes32 val) internal pure {
        assembly {
            mstore(add(add(buf, 0x20), off), val)
        }
    }

    /// @dev Returns true if a G2 point (256-byte EIP-2537 format) in calldata is the point at infinity.
    function _isG2InfinityCalldata(bytes calldata point) internal pure returns (bool) {
        if (point.length != G2_POINT_LENGTH) return false;
        for (uint256 i = 0; i < G2_POINT_LENGTH; i++) {
            if (point[i] != 0) return false;
        }
        return true;
    }

    /// @dev Returns true if a G2 point (256-byte EIP-2537 format) in memory is the point at infinity.
    function _isG2InfinityMemory(bytes memory point) internal pure returns (bool) {
        if (point.length != G2_POINT_LENGTH) return false;
        for (uint256 i = 0; i < G2_POINT_LENGTH; i++) {
            if (point[i] != 0) return false;
        }
        return true;
    }

    // =============================================================
    //      MEMORY-BASED BLS VERIFICATION (used only by validate())
    // =============================================================
    // These mirror the calldata-based chain
    // (_validateBLSSignature/_getPublicKeysByNodes/_validateWithNegatedKey/
    //  _buildPairingDataFromComponents) but take `bytes memory` operands, because validate()
    // produces messagePoint and the BLS sig in memory. The calldata chain is left byte-for-byte
    // unchanged (it backs validateAggregateSignature / verifyAggregateSignature / Plan-A-v3).

    /// @dev Memory sibling of _getPublicKeysByNodes. Preserves BOTH invariants: node must be
    ///      registered, and a retired bootstrap node is rejected once requireStake is on.
    function _getPublicKeysByNodesMem(bytes32[] memory nodeIds) internal view returns (bytes[] memory publicKeys) {
        publicKeys = new bytes[](nodeIds.length);

        for (uint256 i = 0; i < nodeIds.length; i++) {
            require(isRegistered[nodeIds[i]], "Node not registered");
            // Migration boundary (Plan A v3): once staking is mandatory, bootstrap-era nodes are
            // no longer accepted until they re-register via the staked path.
            require(!(requireStake && isBootstrap[nodeIds[i]]), "Bootstrap node retired");
            publicKeys[i] = registeredKeys[nodeIds[i]];
        }
    }

    /// @dev Memory sibling of _validateBLSSignature. Reuses the existing memory helpers
    ///      _aggregatePublicKeysFromMemory and _negateG1Point.
    function _validateBLSSignatureMem(
        bytes32[] memory nodeIds,
        bytes memory signature,
        bytes memory messagePoint
    ) internal view returns (bool isValid) {
        bytes[] memory publicKeys = _getPublicKeysByNodesMem(nodeIds);
        bytes memory aggregatedKey = _aggregatePublicKeysFromMemory(publicKeys);
        bytes memory negatedAggregatedKey = _negateG1Point(aggregatedKey);
        return _validateWithNegatedKeyMem(negatedAggregatedKey, signature, messagePoint, nodeIds.length);
    }

    /// @dev Memory sibling of _validateWithNegatedKey.
    function _validateWithNegatedKeyMem(
        bytes memory negatedAggregatedKey,
        bytes memory signature,
        bytes memory messagePoint,
        uint256 nodeCount
    ) internal view returns (bool isValid) {
        bytes memory pairingData = _buildPairingDataMem(negatedAggregatedKey, signature, messagePoint);
        uint256 requiredGas = _calculateRequiredGas(nodeCount);

        (bool callSuccess, bytes memory result) = PAIRING_PRECOMPILE.staticcall{ gas: requiredGas }(pairingData);
        if (!callSuccess) {
            return false;
        }
        isValid = result.length == 32 && bytes32(result) == bytes32(uint256(1));
    }

    /// @dev Memory sibling of _buildPairingDataFromComponents. Identical byte layout:
    ///      [generator(128) | signature(256) | aggregatedKey(128) | messagePoint(256)] = 768 bytes.
    function _buildPairingDataMem(
        bytes memory aggregatedKey,
        bytes memory signature,
        bytes memory messagePoint
    ) internal pure returns (bytes memory pairingData) {
        pairingData = new bytes(768);

        // First pairing: (generator, signature)
        for (uint256 i = 0; i < G1_POINT_LENGTH; i++) {
            pairingData[i] = GENERATOR_POINT[i];
        }
        for (uint256 i = 0; i < G2_POINT_LENGTH; i++) {
            pairingData[G1_POINT_LENGTH + i] = signature[i];
        }

        // Second pairing: (aggregated key, message point)
        uint256 secondPairingOffset = PAIRING_LENGTH;
        for (uint256 i = 0; i < G1_POINT_LENGTH; i++) {
            pairingData[secondPairingOffset + i] = aggregatedKey[i];
        }
        for (uint256 i = 0; i < G2_POINT_LENGTH; i++) {
            pairingData[secondPairingOffset + G1_POINT_LENGTH + i] = messagePoint[i];
        }
    }

    // =============================================================
    //                      AGGREGATION FUNCTIONS
    // =============================================================

    /**
     * @dev Aggregates multiple G1 public keys using G1Add precompile
     *
     * @param publicKeys Array of individual G1 public keys to aggregate
     * @return aggregatedKey The resulting aggregated public key
     */
    function _aggregatePublicKeys(bytes[] calldata publicKeys) internal view returns (bytes memory aggregatedKey) {
        require(publicKeys.length > 0, "No public keys provided");

        // Start with the first public key
        aggregatedKey = publicKeys[0];
        require(aggregatedKey.length == G1_POINT_LENGTH, "Invalid first key length");

        // Add each subsequent public key
        for (uint256 i = 1; i < publicKeys.length; i++) {
            require(publicKeys[i].length == G1_POINT_LENGTH, "Invalid key length");
            aggregatedKey = _addG1Points(aggregatedKey, publicKeys[i]);
        }
    }

    /**
     * @dev Aggregates multiple G1 public keys using G1Add precompile (memory version)
     *
     * @param publicKeys Array of individual G1 public keys to aggregate
     * @return aggregatedKey The resulting aggregated public key
     */
    function _aggregatePublicKeysFromMemory(
        bytes[] memory publicKeys
    ) internal view returns (bytes memory aggregatedKey) {
        require(publicKeys.length > 0, "No public keys provided");

        // Start with the first public key
        aggregatedKey = publicKeys[0];
        require(aggregatedKey.length == G1_POINT_LENGTH, "Invalid first key length");

        // Add each subsequent public key
        for (uint256 i = 1; i < publicKeys.length; i++) {
            require(publicKeys[i].length == G1_POINT_LENGTH, "Invalid key length");
            aggregatedKey = _addG1PointsFromMemory(aggregatedKey, publicKeys[i]);
        }
    }

    /**
     * @dev Get corresponding public key array based on node identifier array
     *
     * @param nodeIds Array of node identifiers
     * @return publicKeys Corresponding public key array
     */
    function _getPublicKeysByNodes(bytes32[] calldata nodeIds) internal view returns (bytes[] memory publicKeys) {
        publicKeys = new bytes[](nodeIds.length);

        for (uint256 i = 0; i < nodeIds.length; i++) {
            require(isRegistered[nodeIds[i]], "Node not registered");
            // Migration boundary (Plan A v3): once staking is mandatory, bootstrap-era
            // nodes are no longer accepted until they re-register via the staked path.
            // Cheap per-node read; NOT a full per-verify stake re-check (that's syncNode).
            require(!(requireStake && isBootstrap[nodeIds[i]]), "Bootstrap node retired");
            publicKeys[i] = registeredKeys[nodeIds[i]];
        }
    }

    /**
     * @dev Validate BLS signature only
     *
     * @param nodeIds Array of node identifiers
     * @param signature Aggregated BLS signature
     * @param messagePoint G2-encoded message point
     * @return isValid Whether BLS signature is valid
     */
    function _validateBLSSignature(
        bytes32[] calldata nodeIds,
        bytes calldata signature,
        bytes calldata messagePoint
    ) internal view returns (bool isValid) {
        // Get public keys corresponding to nodes
        bytes[] memory publicKeys = _getPublicKeysByNodes(nodeIds);

        // Aggregate public key array
        bytes memory aggregatedKey = _aggregatePublicKeysFromMemory(publicKeys);

        // Negate the aggregated public key
        bytes memory negatedAggregatedKey = _negateG1Point(aggregatedKey);

        // Verify signature with dynamic gas calculation
        return _validateWithNegatedKey(negatedAggregatedKey, signature, messagePoint, nodeIds.length);
    }

    /**
     * @dev Perform pairing verification using negated public key with dynamic gas calculation
     *
     * @param negatedAggregatedKey Negated aggregated public key
     * @param signature Aggregate signature
     * @param messagePoint Message point
     * @param nodeCount Number of nodes participating (for dynamic gas calculation)
     * @return isValid Whether verification is successful
     */
    function _validateWithNegatedKey(
        bytes memory negatedAggregatedKey,
        bytes calldata signature,
        bytes calldata messagePoint,
        uint256 nodeCount
    ) internal view returns (bool isValid) {
        bytes memory pairingData = _buildPairingDataFromComponents(negatedAggregatedKey, signature, messagePoint);

        // Calculate required gas dynamically based on operation complexity
        uint256 requiredGas = _calculateRequiredGas(nodeCount);

        (bool callSuccess, bytes memory result) = PAIRING_PRECOMPILE.staticcall{ gas: requiredGas }(pairingData);

        if (!callSuccess) {
            return false;
        }

        isValid = result.length == 32 && bytes32(result) == bytes32(uint256(1));
    }

    /**
     * @dev Build pairing verification data from components
     *
     * @param aggregatedKey Aggregated public key
     * @param signature Signature
     * @param messagePoint Message point
     * @return pairingData Pairing data
     */
    function _buildPairingDataFromComponents(
        bytes memory aggregatedKey,
        bytes calldata signature,
        bytes calldata messagePoint
    ) internal pure returns (bytes memory pairingData) {
        pairingData = new bytes(768);

        // First pairing: (generator, signature)
        // Copy generator point (128 bytes)
        for (uint256 i = 0; i < G1_POINT_LENGTH; i++) {
            pairingData[i] = GENERATOR_POINT[i];
        }

        // Copy signature (256 bytes)
        for (uint256 i = 0; i < G2_POINT_LENGTH; i++) {
            pairingData[G1_POINT_LENGTH + i] = signature[i];
        }

        // Second pairing: (aggregated key, message point)
        uint256 secondPairingOffset = PAIRING_LENGTH;

        // Copy aggregated key (128 bytes)
        for (uint256 i = 0; i < G1_POINT_LENGTH; i++) {
            pairingData[secondPairingOffset + i] = aggregatedKey[i];
        }

        // Copy message point (256 bytes)
        for (uint256 i = 0; i < G2_POINT_LENGTH; i++) {
            pairingData[secondPairingOffset + G1_POINT_LENGTH + i] = messagePoint[i];
        }
    }

    /**
     * @dev Adds two G1 points using the EIP-2537 precompile
     *
     * @param point1 First G1 point (128 bytes)
     * @param point2 Second G1 point (128 bytes)
     * @return result Sum of the two G1 points
     */
    function _addG1Points(bytes memory point1, bytes calldata point2) internal view returns (bytes memory result) {
        require(point1.length == G1_POINT_LENGTH, "Invalid point1 length");
        require(point2.length == G1_POINT_LENGTH, "Invalid point2 length");

        // Create input: concatenate point1 and point2 (256 bytes total)
        bytes memory input = abi.encodePacked(point1, point2);
        require(input.length == 256, "Invalid input length");

        // Use assembly for precompile call (staticcall doesn't work properly for EIP-2537 on Sepolia)
        result = new bytes(G1_POINT_LENGTH);

        assembly {
            let success := staticcall(gas(), 0x0b, add(input, 0x20), mload(input), add(result, 0x20), 128)
            if eq(success, 0) {
                revert(0, 0)
            }
        }
    }

    /**
     * @dev Adds two G1 points using the EIP-2537 precompile (memory version)
     *
     * @param point1 First G1 point (128 bytes)
     * @param point2 Second G1 point (128 bytes)
     * @return result Sum of the two G1 points
     */
    function _addG1PointsFromMemory(
        bytes memory point1,
        bytes memory point2
    ) internal view returns (bytes memory result) {
        require(point1.length == G1_POINT_LENGTH, "Invalid point1 length");
        require(point2.length == G1_POINT_LENGTH, "Invalid point2 length");

        // Create input: concatenate point1 and point2 (256 bytes total)
        bytes memory input = abi.encodePacked(point1, point2);
        require(input.length == 256, "Invalid input length");

        // Use assembly for precompile call (staticcall doesn't work properly for EIP-2537 on Sepolia)
        result = new bytes(G1_POINT_LENGTH);

        assembly {
            let success := staticcall(gas(), 0x0b, add(input, 0x20), mload(input), add(result, 0x20), 128)
            if eq(success, 0) {
                revert(0, 0)
            }
        }
    }

    // =============================================================
    //                      NEGATION FUNCTION
    // =============================================================

    /**
     * @dev Negates a G1 point by computing -P = (x, -y mod p)
     *
     * @param point G1 point in EIP-2537 format (128 bytes)
     * @return negatedPoint The negated G1 point (-P)
     */
    function _negateG1Point(bytes memory point) internal pure returns (bytes memory negatedPoint) {
        require(point.length == G1_POINT_LENGTH, "Invalid G1 point length");

        negatedPoint = new bytes(G1_POINT_LENGTH);

        // Copy x coordinate unchanged (first 64 bytes)
        for (uint256 i = 0; i < 64; i++) {
            negatedPoint[i] = point[i];
        }

        // Handle point at infinity (all zeros)
        bool isInfinity = true;
        for (uint256 i = 0; i < G1_POINT_LENGTH; i++) {
            if (point[i] != 0) {
                isInfinity = false;
                break;
            }
        }

        if (isInfinity) {
            // Point at infinity remains unchanged
            return negatedPoint; // Already all zeros
        }

        // Negate y coordinate: compute p - y
        _negateYCoordinate(point, negatedPoint);
    }
    // =============================================================
    //                      INTERNAL FUNCTIONS
    // =============================================================

    /**
     * @dev Negates the y coordinate by computing p - y
     * Uses the BLS12-381 field modulus for correct negation
     */
    function _negateYCoordinate(bytes memory point, bytes memory result) internal pure {
        // Extract y coordinate (bytes 64-127 in EIP-2537 format)
        // EIP-2537: [16 zero bytes][48 bytes x][16 zero bytes][48 bytes y]

        // For BLS12-381, coordinates are 48 bytes (384 bits) each
        // In the 64-byte encoding, the actual coordinate starts at byte 16 of each 64-byte chunk

        // Y coordinate: bytes 64+16 = 80 to 127 (48 bytes)
        // We need to compute p - y where both p and y are 381-bit numbers

        // Extract the full 48-byte y coordinate from the 64-byte encoding
        // EIP-2537 format: [16 zero bytes][48 bytes coordinate]
        uint256 y_high = 0;
        uint256 y_low = 0;

        assembly {
            // point points to the start of the bytes struct in memory; data starts at point + 32
            let dataPtr := add(point, 32)
            let yPtr := add(dataPtr, 80)
            // Load first 32 bytes of the 48-byte y coordinate
            y_high := mload(yPtr)
            // Load remaining 16 bytes of y coordinate (shift to align properly)
            let temp := mload(add(yPtr, 32))
            y_low := shr(128, temp) // Shift right by 16 bytes to get the 16-byte portion
        }

        // Compute p - y
        uint256 neg_y_high;
        uint256 neg_y_low;

        if (P_LOW >= y_low) {
            neg_y_low = P_LOW - y_low;
            neg_y_high = P_HIGH - y_high;
        } else {
            // Need to borrow
            unchecked {
                neg_y_low = P_LOW - y_low + type(uint256).max + 1;
                neg_y_high = P_HIGH - y_high - 1;
            }
        }

        // Store the negated y coordinate back to result in EIP-2537 format
        // Set y coordinate padding (16 zero bytes at offset 64-79)
        for (uint256 i = 64; i < 80; i++) {
            result[i] = 0;
        }

        // Store negated y coordinate (48 bytes starting at offset 80)
        assembly {
            let resultPtr := add(result, 0x20) // Skip length prefix
            // Store first 32 bytes of negated y
            mstore(add(resultPtr, 80), neg_y_high)
            // Store remaining 16 bytes of negated y in the correct position
            let temp := shl(128, neg_y_low) // Shift left to align the 16 bytes correctly
            mstore(add(resultPtr, 112), temp)
        }
    }

    // =============================================================
    //                      KEY MANAGEMENT FUNCTIONS
    // =============================================================

    /**
     * @dev Register a node's BLS public key, binding it to a staked operator (Plan A v3).
     *
     * Two modes, controlled by `requireStake`:
     *  - requireStake == false (bootstrap, default): owner-only, records nodeId->pubkey and
     *    marks it `isBootstrap` (retired once staking is turned on). Preserves the initial
     *    permissioned launch where the owner grows the quorum.
     *  - requireStake == true (permissionless-but-staked): the OPERATOR (msg.sender) calls;
     *    they must hold ROLE_DVT and >= minStake locked GToken in the SuperPaymaster
     *    Registry, and one operator may back only ONE active nodeId (anti-Sybil).
     *
     * NOTE (increment 1): does NOT yet enforce BLS proof-of-possession. Because the
     * aggregate verifier sums pubkeys (rogue-key vulnerable), PoP MUST be added before
     * relying on requireStake=true in production. Tracked in #163.
     *
     * @param nodeId Unique node identifier
     * @param publicKey G1 public key (128 bytes)
     */
    function registerPublicKey(bytes32 nodeId, bytes calldata publicKey) external {
        require(nodeId != bytes32(0), "Invalid node ID");
        require(publicKey.length == G1_POINT_LENGTH, "Invalid public key length");
        require(!_isInfinity(publicKey), "pubkey is infinity");
        require(!isRegistered[nodeId], "Node already registered");

        // Bootstrap-only path: owner registers (permissioned launch). Once staking is
        // mandatory, the staked path (registerWithProof) is the only way in — this keeps
        // the rogue-key-vulnerable no-PoP registration off the permissionless surface.
        require(!requireStake, "Staking on: use registerWithProof");
        require(msg.sender == owner, "Bootstrap: only owner");
        nodeOperator[nodeId] = owner;
        isBootstrap[nodeId] = true;

        registeredKeys[nodeId] = publicKey;
        isRegistered[nodeId] = true;
        registeredNodes.push(nodeId);

        emit PublicKeyRegistered(nodeId, publicKey);
    }

    /**
     * @dev Permissionless-but-staked registration (Plan A v3). The OPERATOR (msg.sender)
     * registers their own node: stake-gated, one node per operator, nodeId derived from
     * the pubkey (no squatting), and a BLS proof-of-possession that closes the rogue-key
     * hole in the aggregate verifier (you cannot PoP a key whose secret you don't hold).
     *
     * PoP: prove e(g1, popSig) == e(pubkey, popPoint). popPoint is the caller-provided G2
     * message point their BLS key signed; soundness of possession holds for ANY popPoint
     * (forging needs the pubkey's secret), so no on-chain hash-to-curve is required.
     *
     * @param publicKey  G1 public key (128 bytes, EIP-2537)
     * @param popPoint   G2 message point the key signed (256 bytes)
     * @param popSig     G2 BLS signature over popPoint by `publicKey` (256 bytes)
     */
    function registerWithProof(
        bytes calldata publicKey,
        bytes calldata popPoint,
        bytes calldata popSig
    ) external {
        require(requireStake, "Staked registration disabled");
        require(publicKey.length == G1_POINT_LENGTH, "Invalid public key length");
        // Reject the point-at-infinity encoding (all-zero). e(_, infinity)=1, so an
        // infinity pubkey/popPoint/popSig would make the PoP pairing trivially pass with
        // NO secret known — the rogue-key bypass this check exists to close. Non-infinity
        // but off-subgroup points are rejected by the pairing precompile's subgroup check.
        require(!_isInfinity(publicKey), "pubkey is infinity");
        bytes32 nodeId = keccak256(publicKey); // derived — not caller-chosen (no squatting)
        require(!isRegistered[nodeId], "Node already registered");
        require(operatorNode[msg.sender] == bytes32(0), "Operator already has a node");
        require(_isStaked(msg.sender), "Operator not staked for ROLE_DVT");
        require(_verifyPoP(publicKey, popPoint, popSig), "Invalid proof-of-possession");

        nodeOperator[nodeId] = msg.sender;
        operatorNode[msg.sender] = nodeId;
        registeredKeys[nodeId] = publicKey;
        isRegistered[nodeId] = true;
        registeredNodes.push(nodeId);

        emit NodeBound(nodeId, msg.sender);
        emit PublicKeyRegistered(nodeId, publicKey);
    }

    /// @dev BLS proof-of-possession: e(g1, popSig) == e(pubkey, popPoint). Reuses the same
    ///      pairing construction as aggregate verification (generator, sig | -pubkey, point).
    function _verifyPoP(
        bytes calldata pubkey,
        bytes calldata popPoint,
        bytes calldata popSig
    ) internal view returns (bool) {
        if (popPoint.length != G2_POINT_LENGTH || popSig.length != G2_POINT_LENGTH) return false;
        // Defence in depth: infinity in any pairing operand makes e(...)=1 trivially.
        if (_isInfinity(pubkey) || _isInfinity(popPoint) || _isInfinity(popSig)) return false;
        bytes memory negPk = _negateG1Point(pubkey);
        bytes memory pairingData = _buildPairingDataFromComponents(negPk, popSig, popPoint);
        (bool ok, bytes memory result) = PAIRING_PRECOMPILE.staticcall{ gas: _calculateRequiredGas(1) }(
            pairingData
        );
        return ok && result.length == 32 && bytes32(result) == bytes32(uint256(1));
    }

    /// @dev EIP-2537 encodes the point at infinity as all-zero bytes. Reject it wherever a
    ///      non-degenerate point is required (a pairing with infinity is the identity in GT).
    function _isInfinity(bytes calldata point) internal pure returns (bool) {
        for (uint256 i = 0; i < point.length; i++) {
            if (point[i] != 0) return false;
        }
        return true;
    }

    /**
     * @dev Permissionless re-validation: deactivate a node whose economic backing is gone.
     *  - a staked node whose operator lost ROLE_DVT or dropped below minStake, or
     *  - a bootstrap node once requireStake has been turned on (migration boundary).
     * Anyone (a keeper) may call it — the check is authoritative, not the caller.
     */
    function syncNode(bytes32 nodeId) external {
        require(isRegistered[nodeId], "Node not registered");
        address op = nodeOperator[nodeId]; // capture before _deactivate clears it
        bool stale = isBootstrap[nodeId] ? requireStake : !_isStaked(op);
        require(stale, "Node still active");
        _deactivate(nodeId);
        emit NodeDeactivated(nodeId, op);
    }

    /// @dev True if `op` holds ROLE_DVT and >= minStake locked GToken in the Registry.
    function _isStaked(address op) internal view returns (bool) {
        if (registry == address(0) || op == address(0)) return false;
        IDVTRegistry r = IDVTRegistry(registry);
        return r.hasRole(ROLE_DVT, op) && r.getEffectiveStake(op, ROLE_DVT) >= minStake;
    }

    /// @dev Remove a node from the active set + clear its operator binding.
    function _deactivate(bytes32 nodeId) internal {
        address op = nodeOperator[nodeId];
        isRegistered[nodeId] = false;
        delete registeredKeys[nodeId];
        delete nodeOperator[nodeId];
        delete isBootstrap[nodeId];
        if (op != address(0) && operatorNode[op] == nodeId) delete operatorNode[op];
        // registeredNodes[] is an unordered enumeration; leave the stale id (isRegistered
        // gates all reads). Compaction is a gas trade-off deferred to a later pass.
    }

    // --- Owner/Safe governance (transfer owner to a Gnosis Safe after init) --------
    function setRegistry(address _registry) external onlyOwner {
        registry = _registry;
        emit RegistrySet(_registry);
    }

    function setRequireStake(bool _v) external onlyOwner {
        requireStake = _v;
        emit RequireStakeSet(_v);
    }

    function setMinStake(uint256 _v) external onlyOwner {
        minStake = _v;
        emit MinStakeSet(_v);
    }

    /**
     * @dev Update public key for registered node
     *
     * @param nodeId Unique node identifier
     * @param newPublicKey New G1 public key (128 bytes)
     */
    function updatePublicKey(bytes32 nodeId, bytes calldata newPublicKey) external onlyOwner {
        // Only bootstrap nodes' keys are owner-mutable. A staked node is immutable-key
        // (nodeId == keccak(pubkey), PoP-bound); to change it, re-register via
        // registerWithProof. Otherwise the owner could toggle staking off, swap a staked
        // node to a rogue/PoP-less key, and toggle back on — injecting an unbacked signer
        // (the exact owner-injection this design removes). Codex #163 review.
        require(isRegistered[nodeId], "Node not registered");
        require(isBootstrap[nodeId], "Not a bootstrap node");
        require(!requireStake, "Staking on: re-register via registerWithProof");
        require(newPublicKey.length == G1_POINT_LENGTH, "Invalid public key length");
        require(!_isInfinity(newPublicKey), "pubkey is infinity");

        bytes memory oldKey = registeredKeys[nodeId];
        registeredKeys[nodeId] = newPublicKey;

        emit PublicKeyUpdated(nodeId, oldKey, newPublicKey);
    }

    /**
     * @dev Revoke public key registration for node
     *
     * @param nodeId Unique node identifier
     */
    function revokePublicKey(bytes32 nodeId) external onlyOwner {
        require(isRegistered[nodeId], "Node not registered");

        // Clear the operator binding too, or operatorNode[op] would stay pointing at a
        // revoked node and strand the operator's 1:1 slot forever (syncNode can't fix it
        // once isRegistered is false).
        address op = nodeOperator[nodeId];
        if (op != address(0) && operatorNode[op] == nodeId) delete operatorNode[op];
        delete nodeOperator[nodeId];
        delete isBootstrap[nodeId];
        delete registeredKeys[nodeId];
        isRegistered[nodeId] = false;

        // Remove node ID from array
        for (uint256 i = 0; i < registeredNodes.length; i++) {
            if (registeredNodes[i] == nodeId) {
                registeredNodes[i] = registeredNodes[registeredNodes.length - 1];
                registeredNodes.pop();
                break;
            }
        }

        emit PublicKeyRevoked(nodeId);
    }

    /**
     * @dev Batch register public keys for multiple nodes
     *
     * @param nodeIds Array of node identifiers
     * @param publicKeys Corresponding public key array
     */
    function batchRegisterPublicKeys(bytes32[] calldata nodeIds, bytes[] calldata publicKeys) external onlyOwner {
        // Bootstrap-only, same as registerPublicKey: once staking is mandatory this owner
        // path would let stake-less/PoP-less nodes into the active set.
        require(!requireStake, "Staking on: use registerWithProof");
        require(nodeIds.length == publicKeys.length, "Array length mismatch");
        require(nodeIds.length > 0, "Empty arrays");

        for (uint256 i = 0; i < nodeIds.length; i++) {
            require(nodeIds[i] != bytes32(0), "Invalid node ID");
            require(publicKeys[i].length == G1_POINT_LENGTH, "Invalid public key length");
            require(!_isInfinity(publicKeys[i]), "pubkey is infinity");
            require(!isRegistered[nodeIds[i]], "Node already registered");

            // Mark bootstrap + bind operator=owner so these nodes are consistent with the
            // registerPublicKey bootstrap path (and retire when requireStake turns on).
            nodeOperator[nodeIds[i]] = owner;
            isBootstrap[nodeIds[i]] = true;
            registeredKeys[nodeIds[i]] = publicKeys[i];
            isRegistered[nodeIds[i]] = true;
            registeredNodes.push(nodeIds[i]);

            emit PublicKeyRegistered(nodeIds[i], publicKeys[i]);
        }
    }

    /**
     * @dev Transfer contract ownership
     *
     * @param newOwner Address of new owner
     */
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Invalid new owner");
        require(newOwner != owner, "Same owner");

        address previousOwner = owner;
        owner = newOwner;

        emit OwnershipTransferred(previousOwner, newOwner);
    }

    /**
     * @dev Get number of registered nodes
     *
     * @return count Number of registered nodes
     */
    function getRegisteredNodeCount() external view returns (uint256 count) {
        return registeredNodes.length;
    }

    /**
     * @dev Get registered nodes within specified range
     *
     * @param offset Starting position
     * @param limit Return count limit
     * @return nodeIds Array of node identifiers
     * @return publicKeys Corresponding public key array
     */
    function getRegisteredNodes(
        uint256 offset,
        uint256 limit
    ) external view returns (bytes32[] memory nodeIds, bytes[] memory publicKeys) {
        require(offset < registeredNodes.length, "Offset out of bounds");

        uint256 end = offset + limit;
        if (end > registeredNodes.length) {
            end = registeredNodes.length;
        }

        uint256 length = end - offset;
        nodeIds = new bytes32[](length);
        publicKeys = new bytes[](length);

        for (uint256 i = 0; i < length; i++) {
            bytes32 nodeId = registeredNodes[offset + i];
            nodeIds[i] = nodeId;
            publicKeys[i] = registeredKeys[nodeId];
        }
    }

    // =============================================================
    //                      UTILITY FUNCTIONS
    // =============================================================

    /**
     * @dev Calculate required gas for BLS validation based on EIP-2537 and operational complexity
     *
     * @param nodeCount Number of nodes participating in the signature
     * @return requiredGas Calculated gas requirement
     */
    function _calculateRequiredGas(uint256 nodeCount) internal pure returns (uint256 requiredGas) {
        if (nodeCount == 0) return 0;

        // EIP-2537 pairing check: 32600 * k + 37700, where k = 2 (two pairings)
        uint256 pairingBaseCost = 32600 * 2 + 37700; // 102,900

        // G1 point addition cost: (nodeCount - 1) * 500 (EIP-2537 G1 addition)
        // Each additional node requires one G1 point addition for aggregation
        uint256 g1AdditionCost = (nodeCount - 1) * 500;

        // Storage read cost: nodeCount * 2100 (cold SLOAD for public keys)
        // Each node requires reading its public key from storage
        uint256 storageReadCost = nodeCount * 2100;

        // EVM execution overhead: data preparation, memory operations, loops
        // Includes: memory allocation, data copying, point negation, validation checks
        uint256 evmExecutionCost = 50000 + (nodeCount * 1000); // Base + per-node overhead

        // Calculate total with components breakdown
        uint256 totalBaseCost = pairingBaseCost + g1AdditionCost + storageReadCost + evmExecutionCost;

        // Safety margin: 25% buffer to handle network variations and unexpected costs
        requiredGas = (totalBaseCost * 125) / 100;

        // Minimum gas floor: ensure at least the proven working amount for small node counts
        if (requiredGas < 150000) {
            requiredGas = 150000;
        }

        // Maximum gas cap: prevent excessive gas usage for very large node counts
        if (requiredGas > 2000000) {
            requiredGas = 2000000;
        }
    }

    /**
     * @dev Get gas estimation (public interface for external callers)
     *
     * @param nodeCount Number of nodes participating in signature
     * @return gasEstimate Estimated gas consumption
     */
    function getGasEstimate(uint256 nodeCount) external pure returns (uint256 gasEstimate) {
        return _calculateRequiredGas(nodeCount);
    }

    /**
     * @dev Get supported signature format description
     *
     * @return format Signature format description
     */
    function getSignatureFormat() external pure returns (string memory format) {
        return "BLS aggregate signature: publicKeys[] + G2_signature + G2_messagePoint";
    }
}
