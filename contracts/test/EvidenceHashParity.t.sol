// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "forge-std/Test.sol";

/// @dev M0 §3.1 evidence encoding, which SP's DVTValidator (0.8.0) checks at execute
///      (EvidenceHashMismatch). The off-chain side (scripts/evidence/evidence-lib.mjs) writes
///      test/fixtures/evidence-vectors.json; this test recomputes every vector with Solidity's own
///      abi.encode and keccak256, so a drift in either implementation fails one of the two
///      (`npm run check:evidence` diffs the JS side). SP's contract is checked against the same file
///      when its branch is available.
contract EvidenceHashParityTest is Test {
    bytes32 internal constant TAG_EVIDENCE = keccak256("SuperPaymaster.DVT.Evidence.v2");

    function _json() internal view returns (string memory) {
        return vm.readFile(string.concat(vm.projectRoot(), "/test/fixtures/evidence-vectors.json"));
    }

    function test_tagAndCategories() public view {
        string memory json = _json();
        assertEq(vm.parseJsonBytes32(json, ".tagEvidence"), TAG_EVIDENCE, "TAG_EVIDENCE");
        assertEq(
            vm.parseJsonBytes32(json, ".categories['DVT.Evidence.OverIssue.v1']"),
            keccak256("DVT.Evidence.OverIssue.v1"),
            "OverIssue category"
        );
        assertEq(
            vm.parseJsonBytes32(json, ".categories['DVT.Evidence.AuditSlash.v1']"),
            keccak256("DVT.Evidence.AuditSlash.v1"),
            "AuditSlash category"
        );
    }

    function test_evidenceVectors() public view {
        string memory json = _json();
        uint256 n;
        for (n = 0; vm.keyExistsJson(json, string.concat(".vectors[", vm.toString(n), "]")); n++) {
            string memory p = string.concat(".vectors[", vm.toString(n), "]");
            bytes32 category = vm.parseJsonBytes32(json, string.concat(p, ".category"));
            bytes memory body = vm.parseJsonBytes(json, string.concat(p, ".body"));
            bytes memory evidence = abi.encode(category, body);
            assertEq(evidence, vm.parseJsonBytes(json, string.concat(p, ".evidence")), "evidence");
            // the execute-side decode recovers the same category and body
            (bytes32 c2, bytes memory b2) = abi.decode(evidence, (bytes32, bytes));
            assertEq(c2, category, "decoded category");
            assertEq(b2, body, "decoded body");
            assertEq(
                keccak256(abi.encode(TAG_EVIDENCE, category, keccak256(body))),
                vm.parseJsonBytes32(json, string.concat(p, ".evidenceHash")),
                "evidenceHash"
            );
            // the packed blob is NOT the evidence: abi.encode carries the bytes offset and length
            bytes memory packed = abi.encodePacked(category, body);
            assertEq(packed, vm.parseJsonBytes(json, string.concat(p, ".packedEvidence")), "packedEvidence");
            assertTrue(keccak256(packed) != keccak256(evidence), "packed differs from abi.encode");
        }
        assertEq(n, 5, "vector count");
    }
}
