// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.19;

import {Script, console2} from "forge-std/Script.sol";
import {DisclosureRegistry} from "../src/disclosure/DisclosureRegistry.sol";

interface IOwnableView {
    function owner() external view returns (address);
}

/// @dev BLSAggregator's registered validator (guardian) slots, 1-indexed (SP BLSAggregator.sol
///      `validatorAtSlot` :204, `MAX_VALIDATORS` :219 — 13 on 4.11.0, 64 on 4.13.0).
interface IValidatorSetView {
    function MAX_VALIDATORS() external view returns (uint256);
    function validatorAtSlot(uint8 slot) external view returns (address);
}

/**
 * @title DeployDisclosureRegistry
 * @dev Deploys the guardian-watcher DisclosureRegistry (M0 §4) ONLY from the pinned release
 *      artifact (DSR, 2026-11-10). The guard is mechanical, not a convention to remember:
 *        1. the creation code compiled into this script must hash to CREATION_HASH and the
 *           artifact's runtime code (immutables zeroed) to RUNTIME_HASH. Both pins include the
 *           CBOR metadata, which commits to the compiler settings, so a build with any other
 *           evmVersion, optimizer setting or source is refused. The default profile (osaka, for
 *           the gas-profile test) fails here by construction;
 *        2. the artifact's metadata must report evmVersion "cancun" (SP's release profile,
 *           SuperPaymaster foundry.toml [profile.default]:12, all three 5.5.0 chains);
 *        3. the writer must not be the deployer, the aggregator's owner or any registered guardian
 *           (validatorAtSlot[1..MAX_VALIDATORS]) (M0 §5.5); the aggregator must be a contract
 *           whose owner and validator set read (fail closed);
 *        4. after deployment, the on-chain code must equal the pinned runtime with WRITER and
 *           AGGREGATOR written at their immutableReferences offsets, and both getters must read
 *           back the inputs.
 *
 *      Run: FOUNDRY_PROFILE=release WRITER=0x.. AGGREGATOR=0x.. forge script
 *           script/DeployDisclosureRegistry.s.sol:DeployDisclosureRegistry --rpc-url .. --broadcast
 *
 *      The pins are those of DisclosureRegistry at master fda7e425 (DVT #401), built with solc
 *      0.8.33+commit.64118f21, viaIR, optimizer 200 runs, evmVersion cancun. A source change to
 *      the registry requires a new release build, new pins here and a new DSR sign-off.
 */
contract DeployDisclosureRegistry is Script {
    bytes32 public constant CREATION_HASH = 0x1a4ff2084116fdaba2ad66e1417f34d251b67356dae9159d1a0fcb61d069dacc;
    bytes32 public constant RUNTIME_HASH = 0x92ad2cc5a985e348f602945570dc90d1382b4eeda2509440cadddb71ab5452ac;
    string public constant ARTIFACT = "out-release/DisclosureRegistry.sol/DisclosureRegistry.json";
    string public constant EVM_VERSION = "cancun";

    error WrongCreationCode(bytes32 got);
    error WrongRuntimeCode(bytes32 got);
    error WrongEvmVersion(string got);
    error WriterIsDeployer();
    error WriterIsAggregatorOwner();
    error AggregatorHasNoCode();
    error WriterIsGuardian(uint8 slot);
    error BadValidatorSetSize(uint256 max);
    error DeployedCodeMismatch(bytes32 got, bytes32 want);
    error GetterMismatch();

    /// @notice Steps 1 and 2: the artifact is the pinned release build.
    function checkArtifact(bytes memory creation, bytes memory runtimeZeroed) public view {
        bytes32 c = keccak256(creation);
        if (c != CREATION_HASH) revert WrongCreationCode(c);
        bytes32 r = keccak256(runtimeZeroed);
        if (r != RUNTIME_HASH) revert WrongRuntimeCode(r);
        string memory ev = vm.parseJsonString(
            vm.readFile(string.concat(vm.projectRoot(), "/", ARTIFACT)), ".metadata.settings.evmVersion"
        );
        if (keccak256(bytes(ev)) != keccak256(bytes(EVM_VERSION))) revert WrongEvmVersion(ev);
    }

    /// @notice Step 3: role separation.
    function checkRoles(address writer, address deployer, address aggregator) public view {
        if (writer == deployer) revert WriterIsDeployer();
        // Fail closed: the aggregator must be a contract whose owner can be read.
        if (aggregator.code.length == 0) revert AggregatorHasNoCode();
        if (IOwnableView(aggregator).owner() == writer) revert WriterIsAggregatorOwner();
        // Every registered guardian slot. Both views are called directly: an aggregator that
        // cannot answer them reverts here, so an unreadable set refuses the deploy.
        uint256 max = IValidatorSetView(aggregator).MAX_VALIDATORS();
        if (max == 0 || max > type(uint8).max) revert BadValidatorSetSize(max);
        for (uint256 slot = 1; slot <= max; ++slot) {
            if (IValidatorSetView(aggregator).validatorAtSlot(uint8(slot)) == writer) {
                revert WriterIsGuardian(uint8(slot));
            }
        }
    }

    /// @notice The expected on-chain runtime: the pinned code with both immutables written in.
    function expectedRuntime(bytes memory runtimeZeroed, address writer, address aggregator)
        public
        pure
        returns (bytes memory code)
    {
        code = runtimeZeroed;
        uint256[3] memory w = [uint256(1006), 1592, 2419];
        uint256[2] memory a = [uint256(849), 4568];
        for (uint256 i; i < 3; ++i) {
            _put(code, w[i], writer);
        }
        for (uint256 i; i < 2; ++i) {
            _put(code, a[i], aggregator);
        }
    }

    /// @notice Step 4: read-back of a deployment.
    function verifyDeployed(address reg, bytes memory runtimeZeroed, address writer, address aggregator) public view {
        bytes32 want = keccak256(expectedRuntime(runtimeZeroed, writer, aggregator));
        bytes32 got = keccak256(reg.code);
        if (got != want) revert DeployedCodeMismatch(got, want);
        if (DisclosureRegistry(reg).WRITER() != writer || address(DisclosureRegistry(reg).AGGREGATOR()) != aggregator) {
            revert GetterMismatch();
        }
    }

    function run() external returns (DisclosureRegistry reg) {
        address writer = vm.envAddress("WRITER");
        address aggregator = vm.envAddress("AGGREGATOR");
        bytes memory runtimeZeroed = vm.getDeployedCode("DisclosureRegistry.sol:DisclosureRegistry");
        checkArtifact(type(DisclosureRegistry).creationCode, runtimeZeroed);
        vm.startBroadcast();
        (, address deployer,) = vm.readCallers();
        checkRoles(writer, deployer, aggregator);
        reg = new DisclosureRegistry(writer, aggregator);
        vm.stopBroadcast();
        verifyDeployed(address(reg), runtimeZeroed, writer, aggregator);
        console2.log("DisclosureRegistry", address(reg));
        console2.log("block", block.number);
    }

    function _put(bytes memory code, uint256 off, address v) private pure {
        bytes32 word = bytes32(uint256(uint160(v)));
        assembly ("memory-safe") {
            mstore(add(add(code, 0x20), off), word)
        }
    }
}
