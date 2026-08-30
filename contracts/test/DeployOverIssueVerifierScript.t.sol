// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.19;

import {Test} from "forge-std/Test.sol";
import {DeployOverIssueVerifier} from "../script/DeployOverIssueVerifier.s.sol";
import {OverIssueFraudProofVerifier} from "../src/verifiers/OverIssueFraudProofVerifier.sol";
import {MockAggregator} from "./OverIssueFraudProofVerifier.t.sol";

/// @dev A' BLSAggregator stand-in carrying the FULL surface the deploy script probes. It extends the
///      verifier suite's `MockAggregator` on purpose: the domain-separator / fraudProofDigest
///      encodings are the security-sensitive half, and they must stay pinned to the same independent
///      re-implementation of SP's published layout rather than being copied a second time here.
contract ScriptMockAggregator is MockAggregator {
    uint256 internal rotationDelay;
    string internal reportedVersion = "BLSAggregator-4.11.0";
    address public fraudProofVerifier;
    address public pendingFraudProofVerifier;
    uint64 public pendingFraudProofVerifierReadyAt;

    constructor(address registry, uint256 delay_) MockAggregator(registry) {
        rotationDelay = delay_;
    }

    function version() external view returns (string memory) {
        return reportedVersion;
    }

    function setVersion(string memory v) external {
        reportedVersion = v;
    }

    function VERIFIER_ROTATION_DELAY() external view returns (uint256) {
        return rotationDelay;
    }

    function validatorAtSlot(uint8) external pure returns (address) {
        return address(0xBEEF);
    }

    function setArmingState(address current, address pending, uint64 readyAt) external {
        fraudProofVerifier = current;
        pendingFraudProofVerifier = pending;
        pendingFraudProofVerifierReadyAt = readyAt;
    }
}

/// @dev A 4.11-shaped aggregator whose fraud-proof domain schema has DIVERGED from the one CC-115 B1
///      pinned (different DOMAIN_NAME). Deliberately standalone rather than inheriting `MockAggregator`
///      - this mock's whole job is to encode the digest WRONG, so it must not share the pinned
///      re-implementation. Exists to prove the script's post-deploy domain-parity gate actually fires.
contract DivergentDomainMockAggregator {
    mapping(uint256 => bytes32) public proposalSignersCommitment;
    address public immutable REGISTRY;
    address public fraudProofVerifier;
    address public pendingFraudProofVerifier;
    uint64 public pendingFraudProofVerifierReadyAt;

    constructor(address registry) {
        REGISTRY = registry;
    }

    function version() external pure returns (string memory) {
        return "BLSAggregator-4.11.0";
    }

    function VERIFIER_ROTATION_DELAY() external pure returns (uint256) {
        return 4 days;
    }

    function validatorAtSlot(uint8) external pure returns (address) {
        return address(0xBEEF);
    }

    function fraudProofDigest(uint256 fraudProofId, address[] calldata guiltyGuardians)
        external
        view
        returns (bytes32)
    {
        // NOTE the drifted domain name - everything else matches, which is exactly how a real schema
        // divergence would look: no revert anywhere, just a digest the verifier can never reproduce.
        bytes32 sep =
            keccak256(abi.encode(keccak256("SuperPaymaster.BLSConsensus.v2"), block.chainid, address(this), REGISTRY));
        return keccak256(abi.encode(sep, keccak256("SuperPaymaster.BLS.FraudProof.v1"), fraudProofId, guiltyGuardians));
    }
}

/// @dev A pre-rotation aggregator: exposes every legacy probe, reports an older release, and arms
///      through the one-shot `setFraudProofVerifier` setter with no `VERIFIER_ROTATION_DELAY` at all.
contract LegacyMockAggregator is MockAggregator {
    constructor(address registry) MockAggregator(registry) {}

    function version() external pure returns (string memory) {
        return "BLSAggregator-4.9.0";
    }

    function validatorAtSlot(uint8) external pure returns (address) {
        return address(0xBEEF);
    }

    /// @dev The removed setter, present here ONLY so this mock is a faithful pre-rotation target.
    function setFraudProofVerifier(address) external {}
}

/// @dev THE case a "does it expose VERIFIER_ROTATION_DELAY" gate cannot catch: a HYBRID that offers
///      the full two-step rotation surface with an honest 4-day delay AND keeps the instant, undelayed
///      `setFraudProofVerifier` setter. Every rotation-shaped probe passes; only the release-identity
///      check (`version()`) rejects it.
contract HybridSetterMockAggregator is MockAggregator {
    address public fraudProofVerifier;
    address public pendingFraudProofVerifier;
    uint64 public pendingFraudProofVerifierReadyAt;

    constructor(address registry) MockAggregator(registry) {}

    function version() external pure returns (string memory) {
        return "BLSAggregator-4.9.0-hybrid";
    }

    function VERIFIER_ROTATION_DELAY() external pure returns (uint256) {
        return 4 days;
    }

    function validatorAtSlot(uint8) external pure returns (address) {
        return address(0xBEEF);
    }

    /// @dev A faithful, working two-step rotation — so the mock really does offer everything the
    ///      delay-shaped probes look for, and its rejection can only come from the identity gate.
    function proposeFraudProofVerifier(address v) external {
        pendingFraudProofVerifier = v;
        pendingFraudProofVerifierReadyAt = uint64(block.timestamp + 4 days);
    }

    function applyFraudProofVerifier() external {
        require(block.timestamp >= pendingFraudProofVerifierReadyAt, "not ready");
        fraudProofVerifier = pendingFraudProofVerifier;
        delete pendingFraudProofVerifier;
        delete pendingFraudProofVerifierReadyAt;
    }

    /// @dev The bypass that disqualifies it: arms a verifier in one block, with none of the four days
    ///      of public notice. Nothing in the rotation surface above reveals that this exists.
    function setFraudProofVerifier(address v) external {
        fraudProofVerifier = v;
    }
}

/// @dev Exposes the whole rotation surface but no `version()` at all — an unidentifiable target.
contract VersionlessMockAggregator is MockAggregator {
    address public fraudProofVerifier;
    address public pendingFraudProofVerifier;
    uint64 public pendingFraudProofVerifierReadyAt;

    constructor(address registry) MockAggregator(registry) {}

    function VERIFIER_ROTATION_DELAY() external pure returns (uint256) {
        return 4 days;
    }

    function validatorAtSlot(uint8) external pure returns (address) {
        return address(0xBEEF);
    }
}

/// @notice CC-115 B3 / PR-D1: the deploy script must hand the verifier off through SP 4.11's two-step
///         `propose -> full VERIFIER_ROTATION_DELAY -> permissionless apply` rotation, and must refuse
///         any aggregator that would arm it faster or through the removed direct setter.
/// @dev    Drives `deploy(DeployConfig)` rather than the env-reading `run()`: forge executes test
///         functions in a suite concurrently, and `vm.setEnv` mutates process-global state, so an
///         env-driven variant of these cases is inherently racy. `run()` is a four-line env read on
///         top of this function, so every guard below is the one production exercises.
contract DeployOverIssueVerifierScriptTest is Test {
    DeployOverIssueVerifier internal deployScript;
    address internal constant REGISTRY = address(0xBEEF00);

    function setUp() public {
        deployScript = new DeployOverIssueVerifier();
    }

    /// @dev Default config: canonical-identity match satisfied, correct chain.
    function _config(address aggregator) internal view returns (DeployOverIssueVerifier.DeployConfig memory) {
        return DeployOverIssueVerifier.DeployConfig({
            expectedChainId: block.chainid,
            aggregator: aggregator,
            expectedAggregator: aggregator,
            allowUnverifiedAggregator: false,
            expectedAggregatorVersion: "" // falls through to SUPPORTED_AGGREGATOR_VERSION
        });
    }

    /// @notice Happy path: a 4.11 aggregator, dormant at deploy, is accepted — and the verifier that
    ///         comes back is bound to exactly that aggregator and the Registry read FROM it.
    function test_Deploy_AcceptsCompliantAggregatorAndBindsIt() public {
        ScriptMockAggregator agg = new ScriptMockAggregator(REGISTRY, 4 days);
        OverIssueFraudProofVerifier verifier = deployScript.deploy(_config(address(agg)));
        assertEq(verifier.AGGREGATOR(), address(agg), "verifier not bound to the probed aggregator");
        assertEq(verifier.REGISTRY(), REGISTRY, "verifier not bound to the aggregator's own Registry");
    }

    /// @notice The exact SP 4.11 constant (VERIFIER_ROTATION_DELAY == GUARDIAN_SLASH_CASE_WINDOW ==
    ///         4 days) is the boundary, and it is inclusive.
    function test_Deploy_AcceptsExactlyFourDayDelay() public {
        ScriptMockAggregator agg = new ScriptMockAggregator(REGISTRY, 4 days);
        deployScript.deploy(_config(address(agg)));
    }

    /// @notice One second under the window is refused — a shortened arming delay is a security
    ///         regression, not a knob, so there is deliberately no override for it.
    function test_Deploy_RevertsWhenRotationDelayIsOneSecondShort() public {
        ScriptMockAggregator agg = new ScriptMockAggregator(REGISTRY, 4 days - 1);
        vm.expectRevert(
            bytes("AGGREGATOR.VERIFIER_ROTATION_DELAY < 4 days: arming window too short to be publicly visible")
        );
        deployScript.deploy(_config(address(agg)));
    }

    /// @notice A zero delay (instant arming) is refused for the same reason.
    function test_Deploy_RevertsWhenRotationDelayIsZero() public {
        ScriptMockAggregator agg = new ScriptMockAggregator(REGISTRY, 0);
        vm.expectRevert(
            bytes("AGGREGATOR.VERIFIER_ROTATION_DELAY < 4 days: arming window too short to be publicly visible")
        );
        deployScript.deploy(_config(address(agg)));
    }

    /// @notice THE regression this PR exists to prevent: a pre-rotation aggregator, whose only arming
    ///         path is the removed `setFraudProofVerifier` setter, must be rejected before broadcast.
    function test_Deploy_RevertsOnPreRotationAggregatorWithDirectSetter() public {
        LegacyMockAggregator agg = new LegacyMockAggregator(REGISTRY);
        vm.expectRevert(
            bytes(
                "AGGREGATOR.version() != expected: re-verify the fraud-proof ABI and the arming path for that release, then set EXPECTED_AGGREGATOR_VERSION"
            )
        );
        deployScript.deploy(_config(address(agg)));
    }

    /// @notice THE case the earlier "does it expose VERIFIER_ROTATION_DELAY" predicate could not catch
    ///         (Codex High #1): a hybrid offering the full two-step rotation surface with an honest
    ///         4-day delay while ALSO keeping the instant `setFraudProofVerifier` bypass. Every
    ///         rotation-shaped probe passes; the release-identity check is what rejects it.
    function test_Deploy_RevertsOnHybridWithRotationSurfaceAndDirectSetter() public {
        HybridSetterMockAggregator agg = new HybridSetterMockAggregator(REGISTRY);
        // Preconditions: every delay-shaped probe this gate could have relied on genuinely passes, so
        // the rejection provably comes from the release-identity gate and nothing incidental.
        assertEq(agg.VERIFIER_ROTATION_DELAY(), 4 days, "hybrid must satisfy the delay floor");
        agg.proposeFraudProofVerifier(address(0xFEE));
        assertEq(agg.pendingFraudProofVerifier(), address(0xFEE), "hybrid must offer a real propose step");
        uint64 readyAt = agg.pendingFraudProofVerifierReadyAt();
        assertEq(readyAt, uint64(block.timestamp + 4 days), "hybrid must offer a real 4-day maturation");
        // The maturation is honoured, not just advertised: early apply reverts, and applying after the
        // full delay actually arms the verifier and clears the pending slot.
        vm.expectRevert(bytes("not ready"));
        agg.applyFraudProofVerifier();
        vm.warp(readyAt);
        agg.applyFraudProofVerifier();
        assertEq(agg.fraudProofVerifier(), address(0xFEE), "hybrid's apply step must actually arm");
        assertEq(agg.pendingFraudProofVerifier(), address(0), "hybrid's apply step must clear pending");
        assertEq(agg.pendingFraudProofVerifierReadyAt(), 0, "hybrid's apply step must clear readyAt");
        // ...and yet the instant bypass is right there, arming in a single call with no notice at all.
        agg.setFraudProofVerifier(address(0xBAD));
        assertEq(agg.fraudProofVerifier(), address(0xBAD), "hybrid must actually have the instant setter");
        vm.expectRevert(
            bytes(
                "AGGREGATOR.version() != expected: re-verify the fraud-proof ABI and the arming path for that release, then set EXPECTED_AGGREGATOR_VERSION"
            )
        );
        deployScript.deploy(_config(address(agg)));
    }

    /// @notice An aggregator that cannot identify its release at all is refused.
    function test_Deploy_RevertsOnAggregatorWithoutVersion() public {
        VersionlessMockAggregator agg = new VersionlessMockAggregator(REGISTRY);
        vm.expectRevert(bytes("AGGREGATOR exposes no version(): not a supported SuperPaymaster BLSAggregator"));
        deployScript.deploy(_config(address(agg)));
    }

    /// @notice A NEWER release is refused too: equality, not "at least". The verifier is immutable, so
    ///         an unreviewed release bump must be a conscious decision, never a silent pass.
    function test_Deploy_RevertsOnNewerUnreviewedVersion() public {
        ScriptMockAggregator agg = new ScriptMockAggregator(REGISTRY, 4 days);
        agg.setVersion("BLSAggregator-4.12.0");
        vm.expectRevert(
            bytes(
                "AGGREGATOR.version() != expected: re-verify the fraud-proof ABI and the arming path for that release, then set EXPECTED_AGGREGATOR_VERSION"
            )
        );
        deployScript.deploy(_config(address(agg)));
    }

    /// @notice ...and the operator can accept that newer release only by naming it explicitly.
    function test_Deploy_AcceptsNewerVersionWhenExplicitlyExpected() public {
        ScriptMockAggregator agg = new ScriptMockAggregator(REGISTRY, 4 days);
        agg.setVersion("BLSAggregator-4.12.0");
        DeployOverIssueVerifier.DeployConfig memory cfg = _config(address(agg));
        cfg.expectedAggregatorVersion = "BLSAggregator-4.12.0";
        deployScript.deploy(cfg);
    }

    /// @notice An empty override can never DISABLE the check — it falls through to the pinned default.
    function test_Deploy_EmptyExpectedVersionFallsThroughToPin() public {
        ScriptMockAggregator agg = new ScriptMockAggregator(REGISTRY, 4 days);
        agg.setVersion("");
        DeployOverIssueVerifier.DeployConfig memory cfg = _config(address(agg));
        cfg.expectedAggregatorVersion = "";
        vm.expectRevert(
            bytes(
                "AGGREGATOR.version() != expected: re-verify the fraud-proof ABI and the arming path for that release, then set EXPECTED_AGGREGATOR_VERSION"
            )
        );
        deployScript.deploy(cfg);
    }

    /// @notice The delay floor is an INDEPENDENT gate: a correctly-versioned aggregator whose delay was
    ///         shortened is still refused, so a matching version string never implies the delay.
    function test_Deploy_RevertsOnCorrectVersionButShortDelay() public {
        ScriptMockAggregator agg = new ScriptMockAggregator(REGISTRY, 1 days);
        vm.expectRevert(
            bytes("AGGREGATOR.VERIFIER_ROTATION_DELAY < 4 days: arming window too short to be publicly visible")
        );
        deployScript.deploy(_config(address(agg)));
    }

    /// @notice A longer-than-required delay is fine — the gate is a floor, not an equality check.
    function test_Deploy_AcceptsLongerRotationDelay() public {
        ScriptMockAggregator agg = new ScriptMockAggregator(REGISTRY, 7 days);
        deployScript.deploy(_config(address(agg)));
    }

    /// @notice An already-armed verifier and an in-flight rotation are WARNINGS, not blockers: whether
    ///         to overwrite them is the aggregator owner's call, so the script reports and proceeds.
    function test_Deploy_ProceedsWhenRotationAlreadyInFlight() public {
        ScriptMockAggregator agg = new ScriptMockAggregator(REGISTRY, 4 days);
        agg.setArmingState(address(0xA11CE), address(0xB0B), uint64(block.timestamp + 4 days));
        // Assert the three rotation-state getters are actually READ — otherwise this test would still
        // pass if the reads and their warnings were deleted (Codex Low #5).
        vm.expectCall(address(agg), abi.encodeWithSignature("fraudProofVerifier()"));
        vm.expectCall(address(agg), abi.encodeWithSignature("pendingFraudProofVerifier()"));
        vm.expectCall(address(agg), abi.encodeWithSignature("pendingFraudProofVerifierReadyAt()"));
        deployScript.deploy(_config(address(agg)));
    }

    /// @notice The post-deploy domain-parity gate is live: if the aggregator's `fraudProofDigest`
    ///         schema and the freshly deployed verifier disagree, the script fails at hand-off time
    ///         instead of leaving a verifier that silently rejects every real proof.
    function test_Deploy_RevertsOnDomainDigestMismatch() public {
        DivergentDomainMockAggregator agg = new DivergentDomainMockAggregator(REGISTRY);
        vm.expectRevert(bytes("domain digest mismatch: verifier not conformant with aggregator fraudProofDigest"));
        deployScript.deploy(_config(address(agg)));
    }

    /// @notice Pre-existing guards still hold on the new path: a non-canonical aggregator is refused.
    function test_Deploy_RevertsOnNonCanonicalAggregator() public {
        ScriptMockAggregator agg = new ScriptMockAggregator(REGISTRY, 4 days);
        DeployOverIssueVerifier.DeployConfig memory cfg = _config(address(agg));
        cfg.expectedAggregator = address(0xDEAD);
        vm.expectRevert(bytes("AGGREGATOR != canonical/expected aggregator"));
        deployScript.deploy(cfg);
    }

    /// @notice With no canonical pin at all, the operator must consciously acknowledge the address.
    function test_Deploy_RevertsWhenUnpinnedAndUnacknowledged() public {
        ScriptMockAggregator agg = new ScriptMockAggregator(REGISTRY, 4 days);
        DeployOverIssueVerifier.DeployConfig memory cfg = _config(address(agg));
        cfg.expectedAggregator = address(0);
        vm.expectRevert(
            bytes(
                "no canonical aggregator known: set CANONICAL_AGGREGATOR/EXPECTED_AGGREGATOR, or ALLOW_UNVERIFIED_AGGREGATOR=true to accept"
            )
        );
        deployScript.deploy(cfg);
    }

    /// @notice ...and the acknowledgement is the ONLY thing that unblocks it.
    function test_Deploy_AcceptsUnpinnedWhenExplicitlyAcknowledged() public {
        ScriptMockAggregator agg = new ScriptMockAggregator(REGISTRY, 4 days);
        DeployOverIssueVerifier.DeployConfig memory cfg = _config(address(agg));
        cfg.expectedAggregator = address(0);
        cfg.allowUnverifiedAggregator = true;
        deployScript.deploy(cfg);
    }

    /// @notice Wrong-RPC guard still fires ahead of any deployment.
    function test_Deploy_RevertsOnWrongChain() public {
        ScriptMockAggregator agg = new ScriptMockAggregator(REGISTRY, 4 days);
        DeployOverIssueVerifier.DeployConfig memory cfg = _config(address(agg));
        cfg.expectedChainId = block.chainid + 1;
        vm.expectRevert(bytes("wrong chain: set EXPECTED_CHAIN_ID for this RPC"));
        deployScript.deploy(cfg);
    }
}
