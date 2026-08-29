// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.19;

/**
 * @title DeployOverIssueVerifier
 * @dev CC-89 stage-2 joint-testnet prerequisite. Deploys the DVT `OverIssueFraudProofVerifier`
 *      (#223) and binds it to SuperPaymaster's A'-commitment `BLSAggregator` (≥ SP PR #371).
 *
 *      Deploy ORDER (chicken-egg — see CC-89 cf63e699):
 *        1. SP deploys the A' BLSAggregator to Sepolia → publishes its canonical address.
 *        2. Set CANONICAL_AGGREGATOR below to that address (or pass EXPECTED_AGGREGATOR); THIS
 *           script deploys the verifier bound to it → hand the verifier address to SP.
 *        3. SP calls setFraudProofVerifier(verifier).
 *
 *      The verifier binds `address(this)==AGGREGATOR` into every commitment recompute and reads
 *      `proposalSignersCommitment` from it — so a WRONG aggregator does NOT revert, it silently
 *      breaks all future verification. This script therefore ENFORCES a canonical-address identity
 *      match (not merely "some contract with code"), and refuses to deploy against an unverified
 *      address unless the operator explicitly acknowledges it.
 *
 *      Env:
 *        AGGREGATOR                  (REQUIRED) SP's on-chain BLSAggregator address.
 *        EXPECTED_AGGREGATOR         (optional) overrides the CANONICAL_AGGREGATOR constant for the
 *                                    identity match (use before the constant is filled in).
 *        ALLOW_UNVERIFIED_AGGREGATOR (optional) must be "true" to deploy when NO canonical/expected
 *                                    address is available yet — a conscious "I verified out-of-band".
 *        EXPECTED_CHAIN_ID           (optional, default 11155111 Sepolia) guards against a wrong RPC.
 *
 *      AGGREGATOR=0x... forge script script/DeployOverIssueVerifier.s.sol \
 *        --rpc-url <RPC> --private-key <KEY> --broadcast
 */

import "forge-std/Script.sol";
import "../src/verifiers/OverIssueFraudProofVerifier.sol";

/// @dev Positive-identity probe: getters only a real A' BLSAggregator exposes, plus the
///      domain-separator inputs CC-115 B1 binds into the verifier.
interface IAggregatorProbe {
    function proposalSignersCommitment(uint256 proposalId) external view returns (bytes32);
    function validatorAtSlot(uint8 slot) external view returns (address);
    function REGISTRY() external view returns (address);
    function fraudProofDigest(uint256 fraudProofId, address[] calldata guiltyGuardians)
        external
        view
        returns (bytes32);
}

contract DeployOverIssueVerifier is Script {
    /// @notice The canonical SP A' BLSAggregator on the target testnet. Fill in once SP publishes it
    ///         (CC-89) → the deploy then HARD-REQUIRES AGGREGATOR == this. address(0) = not yet known.
    address internal constant CANONICAL_AGGREGATOR = address(0);

    function run() external {
        // Wrong-RPC guard: default Sepolia, overridable for another testnet/local fork.
        uint256 expectedChainId = vm.envOr("EXPECTED_CHAIN_ID", uint256(11155111));
        require(block.chainid == expectedChainId, "wrong chain: set EXPECTED_CHAIN_ID for this RPC");

        // envAddress reverts if AGGREGATOR is unset — fail-closed rather than deploy against 0x0.
        address aggregator = vm.envAddress("AGGREGATOR");
        require(aggregator != address(0), "AGGREGATOR must be non-zero");
        require(aggregator.code.length > 0, "AGGREGATOR has no code (deploy the BLSAggregator first)");

        // MANDATORY canonical-identity match. Precedence: a NON-ZERO EXPECTED_AGGREGATOR env overrides
        // the CANONICAL constant; a zero/unset env falls THROUGH to the constant (so a zero env can
        // never clear a real canonical pin). If neither yields a nonzero address, the operator MUST
        // explicitly acknowledge deploying against an address verified out-of-band — never silent.
        address expectedEnv = vm.envOr("EXPECTED_AGGREGATOR", address(0));
        address expected = expectedEnv != address(0) ? expectedEnv : CANONICAL_AGGREGATOR;
        if (expected != address(0)) {
            require(aggregator == expected, "AGGREGATOR != canonical/expected aggregator");
        } else {
            require(
                vm.envOr("ALLOW_UNVERIFIED_AGGREGATOR", false),
                "no canonical aggregator known: set CANONICAL_AGGREGATOR/EXPECTED_AGGREGATOR, or ALLOW_UNVERIFIED_AGGREGATOR=true to accept"
            );
        }

        // Positive-identity probe (defense-in-depth): a wrong contract with bytecode passes
        // code.length>0, but won't expose BOTH aggregator getters — a missing selector reverts here,
        // before broadcast. Slot 1 (slots are 1-indexed; a real aggregator may range-check slot 0).
        try IAggregatorProbe(aggregator).proposalSignersCommitment(0) returns (bytes32) {
            // ok — exposes the A' commitment getter
        } catch {
            revert("AGGREGATOR is not an A' BLSAggregator (no proposalSignersCommitment)");
        }
        try IAggregatorProbe(aggregator).validatorAtSlot(1) returns (address) {
            // ok — exposes the slot registry getter
        } catch {
            revert("AGGREGATOR is not a BLSAggregator (no validatorAtSlot)");
        }

        // CC-115 B1: the verifier reconstructs SP's domain digest from (chainid, aggregator, REGISTRY),
        // so REGISTRY must be the SAME Registry the aggregator is wired to. Read it from the aggregator
        // itself (authoritative) rather than taking it as a hand-entered env — a mismatched Registry
        // would silently make every domain digest differ and reject all proofs.
        address registry;
        try IAggregatorProbe(aggregator).REGISTRY() returns (address r) {
            registry = r;
        } catch {
            revert("AGGREGATOR is not a domain-bound BLSAggregator (no REGISTRY)");
        }
        require(registry != address(0), "AGGREGATOR.REGISTRY() == 0");

        vm.startBroadcast();
        OverIssueFraudProofVerifier verifier = new OverIssueFraudProofVerifier(aggregator, registry);
        vm.stopBroadcast();

        // Byte-for-byte domain-conformance gate: the verifier's reconstructed digest MUST equal the
        // aggregator's own `fraudProofDigest` for a probe (id, guardians). If SP's schema and the
        // verifier's constants ever diverge, this fails HERE (post-deploy, pre-handoff) instead of
        // silently rejecting every real proof on-chain.
        //
        // LOW-4 (config-control, not an on-chain exploit): the probes above and this parity check
        // prove the target EXPOSES the expected getters and AGREES on the domain-digest schema — they
        // do NOT prove it is the genuine, honest SP aggregator. A malicious contract can implement all
        // these getters and return conformant values. The aggregator address AND its Registry MUST be
        // pinned to canonical, source-verified deployments out-of-band (CANONICAL_AGGREGATOR /
        // EXPECTED_AGGREGATOR above); do not treat passing these checks as identity proof.
        address[] memory probeGuardians = new address[](2);
        probeGuardians[0] = address(0x1111);
        probeGuardians[1] = address(0x2222);
        uint256 probeId = 42;
        require(
            verifier.expectedFraudProofDigest(probeId, probeGuardians)
                == IAggregatorProbe(aggregator).fraudProofDigest(probeId, probeGuardians),
            "domain digest mismatch: verifier not conformant with aggregator fraudProofDigest"
        );

        console.log("=== CC-89 / CC-115 B1 OverIssueFraudProofVerifier deployed ===");
        console.log("chainId:   ", block.chainid);
        console.log("verifier:  ", address(verifier));
        console.log("aggregator:", aggregator);
        console.log("registry:  ", registry);
        console.log("Next: SP calls setFraudProofVerifier(", address(verifier), ")");
    }
}
