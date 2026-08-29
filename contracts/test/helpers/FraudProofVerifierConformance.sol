// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.19;

/// @notice DOCUMENTED PORT of SuperPaymaster's release-gate fixture
///         `contracts/test/helpers/FraudProofVerifierConformance.sol` (BLSAggregator 4.11.0), copied
///         into the DVT repo verbatim except for the pragma (SP pins 0.8.33; DVT is ^0.8.19 and uses
///         no 0.8.33-only feature here). SP owns the fixture; repo:dvt owns the verifier and runs it
///         against this port as the CC-115 B1 "SP real conformance" evidence. Keep in sync with SP.
///
///         Canonical selector under test: `verify(bytes32,uint256,address[],bytes)` = 0x61077735.

interface IFraudProofVerifierConformance {
    function verify(
        bytes32 domainDigest,
        uint256 fraudProofId,
        address[] calldata guiltyGuardians,
        bytes calldata fraudProof
    ) external view returns (bool);
}

interface IAggregatorFraudDigest {
    function fraudProofDigest(uint256 fraudProofId, address[] calldata guiltyGuardians)
        external
        view
        returns (bytes32);
    function domainSeparator() external view returns (bytes32);
}

/**
 * @title FraudProofVerifierConformance
 * @notice CC-48 fixture that decides whether a DVT-supplied fraud-proof verifier really BINDS
 *         `domainDigest` and the guilty SET, rather than merely accepting them as arguments.
 *
 * @dev Two release gates (both mandatory):
 *        assertDomainBound — accepts its own domain digest, rejects another aggregator's, rejects an
 *                            arbitrary one.
 *        assertSetBound    — accepts the exact committed set, rejects every strict subset, the
 *                            superset with one extra address, and an unrelated set of the same size.
 *      See SP's original for the full threat rationale (front-run-and-shrink burns the single-use
 *      fraudProofId FOR EVER).
 */
library FraudProofVerifierConformance {
    error VerifierRejectedItsOwnDomain(address verifier, bytes32 domainDigest);
    error VerifierIgnoresDomainDigest(address verifier, bytes32 foreignDigest);
    error VerifierAcceptsArbitraryDigest(address verifier, bytes32 arbitraryDigest);
    error AggregatorsShareADigest(address aggregatorA, address aggregatorB);
    error VerifierRejectedItsOwnGuardianSet(address verifier, bytes32 setHash);
    error VerifierAcceptsGuardianSubset(address verifier, address droppedGuardian);
    error VerifierAcceptsGuardianSuperset(address verifier, address addedGuardian);
    error VerifierAcceptsUnrelatedGuardianSet(address verifier, bytes32 unrelatedSetHash);
    error SetBoundNeedsAtLeastTwoGuardians(uint256 provided);

    function assertDomainBound(
        address verifier,
        address aggregatorA,
        address aggregatorB,
        uint256 fraudProofId,
        address[] memory guiltyGuardians,
        bytes memory fraudProof
    ) internal view {
        bytes32 digestA = IAggregatorFraudDigest(aggregatorA).fraudProofDigest(fraudProofId, guiltyGuardians);
        bytes32 digestB = IAggregatorFraudDigest(aggregatorB).fraudProofDigest(fraudProofId, guiltyGuardians);

        if (digestA == digestB) revert AggregatorsShareADigest(aggregatorA, aggregatorB);

        if (!_verify(verifier, digestA, fraudProofId, guiltyGuardians, fraudProof)) {
            revert VerifierRejectedItsOwnDomain(verifier, digestA);
        }
        if (_verify(verifier, digestB, fraudProofId, guiltyGuardians, fraudProof)) {
            revert VerifierIgnoresDomainDigest(verifier, digestB);
        }
        bytes32 arbitrary = keccak256("CC-48 conformance: not any aggregator's digest");
        if (_verify(verifier, arbitrary, fraudProofId, guiltyGuardians, fraudProof)) {
            revert VerifierAcceptsArbitraryDigest(verifier, arbitrary);
        }
    }

    function assertSetBound(
        address verifier,
        address aggregator,
        uint256 fraudProofId,
        address[] memory guiltyGuardians,
        bytes memory fraudProof
    ) internal view {
        uint256 n = guiltyGuardians.length;
        if (n < 2) revert SetBoundNeedsAtLeastTwoGuardians(n);

        if (!_verifyAgainst(verifier, aggregator, fraudProofId, guiltyGuardians, fraudProof)) {
            revert VerifierRejectedItsOwnGuardianSet(verifier, keccak256(abi.encode(guiltyGuardians)));
        }

        for (uint256 dropped = 0; dropped < n; ++dropped) {
            address[] memory subset = new address[](n - 1);
            uint256 k;
            for (uint256 i = 0; i < n; ++i) {
                if (i == dropped) continue;
                subset[k++] = guiltyGuardians[i];
            }
            if (_verifyAgainst(verifier, aggregator, fraudProofId, subset, fraudProof)) {
                revert VerifierAcceptsGuardianSubset(verifier, guiltyGuardians[dropped]);
            }
        }

        (address extra, address[] memory unrelated) = syntheticSets(guiltyGuardians, fraudProofId);

        address[] memory superset = new address[](n + 1);
        for (uint256 i = 0; i < n; ++i) {
            superset[i] = guiltyGuardians[i];
        }
        superset[n] = extra;
        if (_verifyAgainst(verifier, aggregator, fraudProofId, superset, fraudProof)) {
            revert VerifierAcceptsGuardianSuperset(verifier, extra);
        }

        if (_verifyAgainst(verifier, aggregator, fraudProofId, unrelated, fraudProof)) {
            revert VerifierAcceptsUnrelatedGuardianSet(verifier, keccak256(abi.encode(unrelated)));
        }
    }

    function syntheticSets(address[] memory guiltyGuardians, uint256 fraudProofId)
        internal
        pure
        returns (address extra, address[] memory unrelated)
    {
        uint256 n = guiltyGuardians.length;
        address[] memory excluded = new address[](2 * n + 1);
        uint256 len;
        for (uint256 i = 0; i < n; ++i) {
            excluded[len++] = guiltyGuardians[i];
        }

        extra = _syntheticGuardian(excluded, len, _setSalt(fraudProofId, 0));
        excluded[len++] = extra;

        unrelated = new address[](n);
        for (uint256 i = 0; i < n; ++i) {
            address pick = _syntheticGuardian(excluded, len, _setSalt(fraudProofId, i + 1));
            unrelated[i] = pick;
            excluded[len++] = pick;
        }
    }

    function _verifyAgainst(
        address verifier,
        address aggregator,
        uint256 fraudProofId,
        address[] memory candidate,
        bytes memory fraudProof
    ) private view returns (bool) {
        bytes32 digest = IAggregatorFraudDigest(aggregator).fraudProofDigest(fraudProofId, candidate);
        return _verify(verifier, digest, fraudProofId, candidate, fraudProof);
    }

    function _setSalt(uint256 fraudProofId, uint256 index) private pure returns (uint256) {
        return uint256(keccak256(abi.encode("CC-48 conformance set salt", fraudProofId, index)));
    }

    function _syntheticGuardian(address[] memory excluded, uint256 len, uint256 salt)
        private
        pure
        returns (address candidate)
    {
        bytes32 seed = keccak256(abi.encode("CC-48 conformance synthetic guardian", excluded, len, salt));
        while (true) {
            candidate = address(uint160(uint256(seed)));
            bool collides = candidate == address(0);
            for (uint256 i = 0; i < len && !collides; ++i) {
                if (excluded[i] == candidate) collides = true;
            }
            if (!collides) return candidate;
            seed = keccak256(abi.encode(seed));
        }
    }

    /// @notice Recompute the digest independently of the aggregator (byte-equality cross-check).
    function expectedFraudProofDigest(
        bytes32 domainName,
        uint256 chainId,
        address aggregator,
        address registry,
        bytes32 tagFraudProof,
        uint256 fraudProofId,
        address[] memory guiltyGuardians
    ) internal pure returns (bytes32) {
        bytes32 separator = keccak256(abi.encode(domainName, chainId, aggregator, registry));
        return keccak256(abi.encode(separator, tagFraudProof, fraudProofId, guiltyGuardians));
    }

    /// @dev A verifier that reverts (rather than returning false) is treated as rejecting.
    function _verify(
        address verifier,
        bytes32 domainDigest,
        uint256 fraudProofId,
        address[] memory guiltyGuardians,
        bytes memory fraudProof
    ) private view returns (bool) {
        (bool ok, bytes memory ret) = verifier.staticcall(
            abi.encodeWithSelector(
                IFraudProofVerifierConformance.verify.selector,
                domainDigest,
                fraudProofId,
                guiltyGuardians,
                fraudProof
            )
        );
        if (!ok || ret.length != 32) return false;
        return abi.decode(ret, (bool));
    }
}
