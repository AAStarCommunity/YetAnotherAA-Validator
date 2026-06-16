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
contract AAStarValidator {
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

    // =============================================================
    //                           EVENTS
    // =============================================================

    event SignatureValidated(bytes32 indexed messageHash, uint256 publicKeysCount, bool isValid, uint256 gasUsed);

    event PublicKeyRegistered(bytes32 indexed nodeId, bytes publicKey);

    event PublicKeyUpdated(bytes32 indexed nodeId, bytes oldKey, bytes newKey);

    event PublicKeyRevoked(bytes32 indexed nodeId);

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

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
     * @dev Register public key for new node
     * Anyone can register, but in the future must verify PNT token staking
     *
     * @param nodeId Unique node identifier
     * @param publicKey G1 public key (128 bytes)
     */
    function registerPublicKey(bytes32 nodeId, bytes calldata publicKey) external {
        require(nodeId != bytes32(0), "Invalid node ID");
        require(publicKey.length == G1_POINT_LENGTH, "Invalid public key length");
        require(!isRegistered[nodeId], "Node already registered");

        // TODO: Verify that msg.sender has staked PNT tokens before allowing registration
        // Example implementation:
        // IPNTToken pntToken = IPNTToken(pntTokenAddress);
        // require(pntToken.getStakedAmount(msg.sender) >= minimumStakeAmount, "Insufficient PNT stake");

        registeredKeys[nodeId] = publicKey;
        isRegistered[nodeId] = true;
        registeredNodes.push(nodeId);

        emit PublicKeyRegistered(nodeId, publicKey);
    }

    /**
     * @dev Update public key for registered node
     *
     * @param nodeId Unique node identifier
     * @param newPublicKey New G1 public key (128 bytes)
     */
    function updatePublicKey(bytes32 nodeId, bytes calldata newPublicKey) external onlyOwner {
        require(isRegistered[nodeId], "Node not registered");
        require(newPublicKey.length == G1_POINT_LENGTH, "Invalid public key length");

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
        require(nodeIds.length == publicKeys.length, "Array length mismatch");
        require(nodeIds.length > 0, "Empty arrays");

        for (uint256 i = 0; i < nodeIds.length; i++) {
            require(nodeIds[i] != bytes32(0), "Invalid node ID");
            require(publicKeys[i].length == G1_POINT_LENGTH, "Invalid public key length");
            require(!isRegistered[nodeIds[i]], "Node already registered");

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
