// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {DisclosureRegistry} from "../src/disclosure/DisclosureRegistry.sol";

/// @dev The off-chain recheck (scripts/disclosure/recheck-lib.mjs) is a second implementation of the
///      aggregator encoding. This pins it to the registry: both must produce the values in
///      test/fixtures/disclosure-vectors.json, which the JS side regenerates and CI diffs
///      (`npm run check:disclosure`). A drift in either implementation fails one of the two.
contract DisclosureRecheckParityTest is Test {
    DisclosureRegistry internal reg;

    function setUp() public {
        reg = new DisclosureRegistry(address(0xBEEF), address(0xA66));
    }

    function test_registryMatchesRecheckVectors() public view {
        string memory json = vm.readFile(string.concat(vm.projectRoot(), "/test/fixtures/disclosure-vectors.json"));
        bytes32 ds = vm.parseJsonBytes32(json, ".ds");
        uint256 mask = vm.parseJsonUint(json, ".signerMask");
        address[] memory signers = vm.parseJsonAddressArray(json, ".signers");
        bytes32 anchor = vm.parseJsonBytes32(json, ".anchor");

        for (uint256 i = 0; i < 4; i++) {
            string memory p = string.concat(".vectors[", vm.toString(i), "]");
            DisclosureRegistry.Kind kind = DisclosureRegistry.Kind(vm.parseJsonUint(json, string.concat(p, ".kind")));
            uint256 id = vm.parseJsonUint(json, string.concat(p, ".proposalId"));
            bytes memory inputs = vm.parseJsonBytes(json, string.concat(p, ".messageInputs"));

            bytes32 mh = reg.messageHashOf(ds, kind, id, inputs);
            assertEq(mh, vm.parseJsonBytes32(json, string.concat(p, ".messageHash")), "messageHash");
            uint256 key = reg.commitmentKey(kind, id, mh);
            assertEq(key, vm.parseJsonUint(json, string.concat(p, ".key")), "key");
            assertEq(
                reg.expectedCommitment(ds, key, mh, mask, signers, anchor),
                vm.parseJsonBytes32(json, string.concat(p, ".commitment")),
                "commitment"
            );
        }
    }
}
