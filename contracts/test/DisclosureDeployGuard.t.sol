// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.19;

import {Test} from "forge-std/Test.sol";
import {DisclosureRegistry} from "../src/disclosure/DisclosureRegistry.sol";
import {DeployDisclosureRegistry} from "../script/DeployDisclosureRegistry.s.sol";

contract OwnedAgg {
    address public owner;
    uint256 public constant MAX_VALIDATORS = 13;
    mapping(uint8 => address) public validatorAtSlot;

    constructor(address o) {
        owner = o;
    }

    function setSlot(uint8 s, address v) external {
        validatorAtSlot[s] = v;
    }
}

/// @dev Has an owner but no validator-set views: must be refused (fail closed).
contract OwnerOnlyAgg {
    address public owner = address(1);
}

/// @dev DSR guard cells. CI runs this file under BOTH profiles: the default (osaka) run proves an
///      osaka-built artifact is refused; the release (cancun) run proves the pinned artifact is
///      accepted and the read-back, tamper and role checks bite. Each cell names the profile it
///      is for and is skipped (not passed) in the other.
contract DisclosureDeployGuardTest is Test {
    DeployDisclosureRegistry s;
    address writer = makeAddr("writer");
    address agg;

    function setUp() public {
        s = new DeployDisclosureRegistry();
        agg = address(new OwnedAgg(makeAddr("safe")));
    }

    function _release() internal view returns (bool) {
        return keccak256(bytes(vm.envOr("FOUNDRY_PROFILE", string("default")))) == keccak256("release");
    }

    /// Under the default profile out-release may not exist; the cells that reach the JSON are
    /// release-only, so the default cells pass an empty document.
    function _json() internal view returns (string memory) {
        return _release() ? s.artifactJson() : "{}";
    }

    function _runtime() internal view returns (bytes memory) {
        return vm.getDeployedCode("DisclosureRegistry.sol:DisclosureRegistry");
    }

    // ---- default profile (osaka): the non-release artifact is refused

    function test_default_osakaArtifactRefused() public {
        vm.skip(_release());
        bytes memory c = type(DisclosureRegistry).creationCode;
        vm.expectRevert(abi.encodeWithSelector(DeployDisclosureRegistry.WrongCreationCode.selector, keccak256(c)));
        s.checkArtifact(c, _runtime(), _json());
    }

    function test_default_osakaRuntimeDiffersFromPin() public {
        vm.skip(_release());
        // The runtime pin alone also refuses the osaka artifact (metadata differs).
        assertTrue(keccak256(_runtime()) != s.RUNTIME_HASH(), "osaka runtime must differ from the cancun pin");
    }

    // ---- release profile (cancun): accepted, and every other check bites

    function test_release_pinnedArtifactAccepted() public {
        vm.skip(!_release());
        s.checkArtifact(type(DisclosureRegistry).creationCode, _runtime(), _json());
    }

    function test_release_tamperedRuntimeRefused() public {
        vm.skip(!_release());
        bytes memory r = _runtime();
        r[100] = bytes1(uint8(r[100]) ^ 1);
        string memory j = _json(); // before expectRevert: _json() is itself an external call
        vm.expectRevert(abi.encodeWithSelector(DeployDisclosureRegistry.WrongRuntimeCode.selector, keccak256(r)));
        s.checkArtifact(type(DisclosureRegistry).creationCode, r, j);
    }

    /// L1: the evmVersion check fires on its own (code is identical across forks without metadata).
    function test_release_otherEvmVersionRefused() public {
        vm.skip(!_release());
        string memory j = vm.replace(_json(), '"evmVersion":"cancun"', '"evmVersion":"osaka"');
        assertTrue(keccak256(bytes(j)) != keccak256(bytes(_json())), "fixture edit applied");
        vm.expectRevert(abi.encodeWithSelector(DeployDisclosureRegistry.WrongEvmVersion.selector, "osaka"));
        s.checkArtifact(type(DisclosureRegistry).creationCode, _runtime(), j);
    }

    function test_release_otherCompilerRefused() public {
        vm.skip(!_release());
        string memory j =
            vm.replace(_json(), '"version":"0.8.33+commit.64118f21"', '"version":"0.8.34+commit.00000000"');
        assertTrue(keccak256(bytes(j)) != keccak256(bytes(_json())), "fixture edit applied");
        vm.expectRevert(
            abi.encodeWithSelector(DeployDisclosureRegistry.WrongCompiler.selector, "0.8.34+commit.00000000")
        );
        s.checkArtifact(type(DisclosureRegistry).creationCode, _runtime(), j);
    }

    /// L2: run() end to end (env in, broadcast, read-back), not only its parts.
    function test_release_runDeploysAndReadsBack() public {
        vm.skip(!_release());
        vm.setEnv("WRITER", vm.toString(writer));
        vm.setEnv("AGGREGATOR", vm.toString(agg));
        DisclosureRegistry reg = s.run();
        assertEq(reg.WRITER(), writer);
        assertEq(address(reg.AGGREGATOR()), agg);
    }

    function test_release_tamperedCreationRefused() public {
        vm.skip(!_release());
        bytes memory c = type(DisclosureRegistry).creationCode;
        c[10] = bytes1(uint8(c[10]) ^ 1);
        string memory j = _json();
        vm.expectRevert(abi.encodeWithSelector(DeployDisclosureRegistry.WrongCreationCode.selector, keccak256(c)));
        s.checkArtifact(c, _runtime(), j);
    }

    function test_release_readBackMatchesDeployment() public {
        vm.skip(!_release());
        DisclosureRegistry reg = new DisclosureRegistry(writer, agg);
        s.verifyDeployed(address(reg), _runtime(), writer, agg);
    }

    function test_release_readBackRefusesWrongImmutable() public {
        vm.skip(!_release());
        DisclosureRegistry reg = new DisclosureRegistry(writer, agg);
        vm.expectPartialRevert(DeployDisclosureRegistry.DeployedCodeMismatch.selector);
        s.verifyDeployed(address(reg), _runtime(), makeAddr("other"), agg);
    }

    function test_release_readBackRefusesAlteredCode() public {
        vm.skip(!_release());
        DisclosureRegistry reg = new DisclosureRegistry(writer, agg);
        bytes memory code = address(reg).code;
        code[200] = bytes1(uint8(code[200]) ^ 1);
        vm.etch(address(reg), code);
        vm.expectPartialRevert(DeployDisclosureRegistry.DeployedCodeMismatch.selector);
        s.verifyDeployed(address(reg), _runtime(), writer, agg);
    }

    // ---- profile-independent: role separation

    function test_writerIsDeployerRefused() public {
        vm.expectRevert(DeployDisclosureRegistry.WriterIsDeployer.selector);
        s.checkRoles(writer, writer, agg);
    }

    function test_writerIsAggregatorOwnerRefused() public {
        vm.expectRevert(DeployDisclosureRegistry.WriterIsAggregatorOwner.selector);
        s.checkRoles(makeAddr("safe"), makeAddr("deployer"), agg);
    }

    function test_writerIsGuardianRefused() public {
        OwnedAgg(agg).setSlot(1, makeAddr("g1"));
        OwnedAgg(agg).setSlot(13, writer); // the last slot: the scan must reach MAX_VALIDATORS
        vm.expectRevert(abi.encodeWithSelector(DeployDisclosureRegistry.WriterIsGuardian.selector, uint8(13)));
        s.checkRoles(writer, makeAddr("deployer"), agg);
    }

    function test_unreadableGuardianSetRefused() public {
        address a = address(new OwnerOnlyAgg());
        vm.expectRevert();
        s.checkRoles(writer, makeAddr("deployer"), a);
    }

    function test_aggregatorWithoutCodeRefused() public {
        vm.expectRevert(DeployDisclosureRegistry.AggregatorHasNoCode.selector);
        s.checkRoles(writer, makeAddr("deployer"), makeAddr("eoa"));
    }

    function test_dedicatedWriterAccepted() public {
        s.checkRoles(writer, makeAddr("deployer"), agg);
    }
}
