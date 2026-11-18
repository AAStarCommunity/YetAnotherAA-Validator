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
 *        3. SP ARMS it through the two-step, delay-guarded rotation
 *           (BLSAggregator.sol:1549/1568). There is deliberately NO direct setter and no
 *           deployment-time bypass. The direct `setFraudProofVerifier` setter (which took a single
 *           address) was removed — and the four-parameter, domain-bound verifier ABI it speaks
 *           was introduced — in the SAME SuperPaymaster change (the release reporting
 *           `version() == "BLSAggregator-4.10.0"`); an aggregator predating it carries BOTH
 *           the instant setter and the old three-parameter ABI, and MUST NOT be armed with
 *           this verifier. CC-115 B1 conformance was verified against
 *           `BLSAggregator-4.11.0`; the #441 verifier (3.0.0) recomputes the 4.14.0+ commitment, and
 *           the release to bind is a required input (EXPECTED_AGGREGATOR_VERSION). Arming:
 *             3a. owner (Safe M-of-N) calls proposeFraudProofVerifier(verifier)
 *                 → emits FraudProofVerifierRotationProposed(verifier, readyAt)
 *                 → readyAt = <propose block.timestamp> + VERIFIER_ROTATION_DELAY (4 days).
 *             3b. Wait the FULL VERIFIER_ROTATION_DELAY. `applyFraudProofVerifier()` reverts
 *                 with VerifierRotationNotReady(readyAt) before then — the four days of public
 *                 visibility ARE the security property (CC-48 MEDIUM-1); do not shorten them.
 *             3c. ANYONE calls applyFraudProofVerifier() — permissionless by design, so the
 *                 owner cannot sit on a matured, already-decided rotation as a second veto.
 *                 → emits FraudProofVerifierUpdated(previous, verifier).
 *           Record the propose receipt, `pendingFraudProofVerifierReadyAt`, and the apply
 *           receipt: the CC-115 B3 deployment manifest requires all three.
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
 *        EXPECTED_AGGREGATOR_VERSION (REQUIRED, no default) the exact
 *                                    string `AGGREGATOR.version()` must return. Set it ONLY after
 *                                    re-verifying that the new release still speaks the
 *                                    four-parameter fraud-proof ABI and still has no direct setter.
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
    /// @dev SP's release identifier, e.g. "BLSAggregator-4.11.0" (BLSAggregator.sol:396).
    function version() external view returns (string memory);
    // --- Two-step verifier rotation surface (BLSAggregator.sol:378/379/394) ---
    function VERIFIER_ROTATION_DELAY() external view returns (uint256);
    function fraudProofVerifier() external view returns (address);
    function pendingFraudProofVerifier() external view returns (address);
    function pendingFraudProofVerifierReadyAt() external view returns (uint64);
}

contract DeployOverIssueVerifier is Script {
    /// @notice The canonical SP A' BLSAggregator on the target testnet. Fill in once SP publishes it
    ///         (CC-89) → the deploy then HARD-REQUIRES AGGREGATOR == this. address(0) = not yet known.
    address internal constant CANONICAL_AGGREGATOR = address(0);

    /// @notice No release is pinned in this file (DSR 2026-11-17, #441). EXPECTED_AGGREGATOR_VERSION is
    ///         a REQUIRED input, compared for EQUALITY with `version()`: a different release may change
    ///         the fraud-proof ABI, the domain-digest schema or the arming path, and the verifier is
    ///         immutable once deployed. Independently, Gate A' only lets anchored releases
    ///         (>= BLSAggregator-4.14.0) through.
    /// @dev    Version alone is NOT identity: any contract can return this string. See the
    ///         canonical-pin note at the domain-parity gate below.

    /// @dev Classifies `v`: RELEASE_UNPARSEABLE unless it is exactly
    ///      "BLSAggregator-<major>.<minor>.<patch>" optionally followed by "-<suffix>" (non-empty,
    ///      [0-9A-Za-z.-]), each number 1-6 digits with no leading zero (except "0" itself); otherwise
    ///      RELEASE_ANCHORED when the release is >= 4.14.0 in semver order, else RELEASE_PRE_ANCHOR.
    ///      A pre-release of the floor itself ("4.14.0-rc.1") sorts BELOW 4.14.0 and is refused: it may
    ///      predate the parent-block-hash commitment (clestons #468, Low).
    uint8 internal constant RELEASE_UNPARSEABLE = 0;
    uint8 internal constant RELEASE_PRE_ANCHOR = 1;
    uint8 internal constant RELEASE_ANCHORED = 2;

    /// @dev The aggregator the deploy must bind to. A nonzero compiled `canonical` is authoritative:
    ///      `envExpected` must be zero or equal to it. Only while `canonical` is zero does the env decide.
    function _expectedAggregator(address envExpected, address canonical) internal pure returns (address) {
        if (canonical != address(0)) {
            require(
                envExpected == address(0) || envExpected == canonical,
                "EXPECTED_AGGREGATOR differs from the compiled CANONICAL_AGGREGATOR: the constant wins"
            );
            return canonical;
        }
        return envExpected;
    }

    function _releaseClass(string memory v) internal pure returns (uint8) {
        bytes memory b = bytes(v);
        bytes memory prefix = bytes("BLSAggregator-");
        if (b.length <= prefix.length) return RELEASE_UNPARSEABLE;
        for (uint256 i = 0; i < prefix.length; i++) {
            if (b[i] != prefix[i]) return RELEASE_UNPARSEABLE;
        }
        (bool ok1, uint256 major, uint256 i1) = _readStrictUint(b, prefix.length);
        if (!ok1 || i1 >= b.length || b[i1] != ".") return RELEASE_UNPARSEABLE;
        (bool ok2, uint256 minor, uint256 i2) = _readStrictUint(b, i1 + 1);
        if (!ok2 || i2 >= b.length || b[i2] != ".") return RELEASE_UNPARSEABLE;
        (bool ok3, uint256 patch, uint256 i3) = _readStrictUint(b, i2 + 1);
        if (!ok3) return RELEASE_UNPARSEABLE;
        if (i3 != b.length) {
            // "-<suffix>": non-empty, [0-9A-Za-z.-] only.
            if (b[i3] != "-" || i3 + 1 == b.length) return RELEASE_UNPARSEABLE;
            for (uint256 k = i3 + 1; k < b.length; k++) {
                bytes1 c = b[k];
                bool okc = (c >= "0" && c <= "9") || (c >= "A" && c <= "Z") || (c >= "a" && c <= "z") || c == "."
                    || c == "-";
                if (!okc) return RELEASE_UNPARSEABLE;
            }
        }
        bool preRelease = i3 != b.length;
        if (major == 4 && minor == 14 && patch == 0 && preRelease) return RELEASE_PRE_ANCHOR;
        return (major > 4 || (major == 4 && minor >= 14)) ? RELEASE_ANCHORED : RELEASE_PRE_ANCHOR;
    }

    /// @dev Reads 1-6 decimal digits at `i` with no leading zero (a lone "0" is allowed). The six-digit
    ///      limit is part of the grammar (it refuses e.g. "3.1000000.0" and "4.12.1000000"), and it also
    ///      bounds the arithmetic.
    function _readStrictUint(bytes memory b, uint256 i) private pure returns (bool ok, uint256 n, uint256 end) {
        end = i;
        while (end < b.length && b[end] >= "0" && b[end] <= "9") {
            if (end - i == 6) return (false, 0, end);
            n = n * 10 + (uint8(b[end]) - 48);
            end++;
        }
        if (end == i) return (false, 0, end);
        if (b[i] == "0" && end - i > 1) return (false, 0, end);
        ok = true;
    }

    /// @notice Minimum acceptable on-chain arming delay for a fraud-proof verifier rotation.
    ///         SP pins `VERIFIER_ROTATION_DELAY = GUARDIAN_SLASH_CASE_WINDOW = 4 days`
    ///         (BLSAggregator.sol:386/394). This script refuses to hand a verifier to an
    ///         aggregator that would arm it faster: the four days of public visibility before
    ///         an unbounded 100%-of-lock slash authority can act are the whole point of the
    ///         two-step rotation (CC-48 MEDIUM-1), and the CC-115 B3 manifest asserts them.
    ///         Deliberately NOT env-overridable — a shorter window is a security regression the
    ///         operator must see, not a knob to turn. This is an INDEPENDENT floor, not a proxy for
    ///         the version check: both must hold.
    uint256 internal constant MIN_VERIFIER_ROTATION_DELAY = 4 days;

    /// @notice Testnets only, until #447 (clestons #468). Step 5 of the verifier reads the token's
    ///         CURRENT isOverIssued(), not its state at the disputed slash, so this verifier must not
    ///         reach a chain where guardian stake has value. Sepolia, OP Sepolia, a local anvil.
    ///         Not env-overridable: lifting it is a reviewed change made together with #447.
    function _isTestnet(uint256 chainId) internal pure returns (bool) {
        return chainId == 11155111 || chainId == 11155420 || chainId == 31337;
    }

    /// @dev Every input `deploy` needs, so the guards below can be exercised by
    ///      `test/DeployOverIssueVerifierScript.t.sol` without touching process-global env vars
    ///      (forge runs test functions in parallel, so `vm.setEnv` races across them).
    struct DeployConfig {
        uint256 expectedChainId;
        address aggregator;
        /// @dev 0 falls THROUGH to CANONICAL_AGGREGATOR; it can never clear a real canonical pin.
        address expectedAggregator;
        bool allowUnverifiedAggregator;
        /// @dev REQUIRED. Empty is refused; it can never disable the check.
        string expectedAggregatorVersion;
    }

    /// @notice Env-driven entry point. Reads config, then defers every check to `deploy`.
    function run() external {
        // Wrong-RPC guard: default Sepolia, overridable for another testnet/local fork. Checked HERE,
        // before any other env read, so a wrong RPC is still reported as a wrong RPC even when
        // AGGREGATOR is missing or malformed (`vm.envAddress` would otherwise revert first and mask
        // it). `deploy` re-checks it, so the guard also holds for direct callers.
        uint256 expectedChainId = vm.envOr("EXPECTED_CHAIN_ID", uint256(11155111));
        require(block.chainid == expectedChainId, "wrong chain: set EXPECTED_CHAIN_ID for this RPC");

        // envAddress reverts if AGGREGATOR is unset — fail-closed rather than deploy against 0x0.
        deploy(
            DeployConfig({
                expectedChainId: expectedChainId,
                aggregator: vm.envAddress("AGGREGATOR"),
                expectedAggregator: vm.envOr("EXPECTED_AGGREGATOR", address(0)),
                allowUnverifiedAggregator: vm.envOr("ALLOW_UNVERIFIED_AGGREGATOR", false),
                expectedAggregatorVersion: vm.envOr("EXPECTED_AGGREGATOR_VERSION", string(""))
            })
        );
    }

    /// @notice Deploys the verifier against `cfg.aggregator` and prints the SP-side arming handoff.
    /// @return verifier The freshly deployed, domain-conformant `OverIssueFraudProofVerifier`.
    function deploy(DeployConfig memory cfg) public returns (OverIssueFraudProofVerifier verifier) {
        require(block.chainid == cfg.expectedChainId, "wrong chain: set EXPECTED_CHAIN_ID for this RPC");
        require(
            _isTestnet(block.chainid),
            "testnets only until #447: the verifier reads the token's current isOverIssued(), not its historical state"
        );

        address aggregator = cfg.aggregator;
        require(aggregator != address(0), "AGGREGATOR must be non-zero");
        require(aggregator.code.length > 0, "AGGREGATOR has no code (deploy the BLSAggregator first)");

        // MANDATORY canonical-identity match (Daybreak on #441, Medium). Once CANONICAL_AGGREGATOR is
        // compiled in, it wins: an EXPECTED_AGGREGATOR env may only repeat it, never replace it, so a
        // stale or hostile env cannot rebind the verifier to a look-alike. While the constant is zero
        // the env is the pin. If neither yields a nonzero address, the operator MUST explicitly
        // acknowledge deploying against an address verified out-of-band — never silent.
        address expected = _expectedAggregator(cfg.expectedAggregator, CANONICAL_AGGREGATOR);
        if (expected != address(0)) {
            require(aggregator == expected, "AGGREGATOR != canonical/expected aggregator");
        } else {
            require(
                cfg.allowUnverifiedAggregator,
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

        // GATE A — RELEASE IDENTITY (pre-broadcast). The removed direct `setFraudProofVerifier`
        // setter and the four-parameter, domain-bound fraud-proof ABI this verifier speaks arrived in
        // the SAME SuperPaymaster change, so "which release is this" is the question that decides
        // whether the verifier can ever be armed correctly. Ask it DIRECTLY via `version()` and
        // require EQUALITY with the release CC-115 B1 was conformance-verified against.
        //
        // Why equality against a pinned string, and not "does it expose VERIFIER_ROTATION_DELAY":
        // presence of that constant is NOT a release predicate. `BLSAggregator-4.10.0` already
        // exposed the full propose/apply surface with a 4-day delay, and a hostile or hybrid contract
        // can expose that surface AND keep an instant `setFraudProofVerifier`. Inferring a release
        // from one selector is exactly the silent-drift failure this gate exists to stop.
        require(
            bytes(cfg.expectedAggregatorVersion).length != 0,
            "EXPECTED_AGGREGATOR_VERSION is required: the exact version() of the aggregator being bound"
        );
        string memory expectedVersion = cfg.expectedAggregatorVersion;
        string memory reportedVersion;
        try IAggregatorProbe(aggregator).version() returns (string memory v) {
            reportedVersion = v;
        } catch {
            revert("AGGREGATOR exposes no version(): not a supported SuperPaymaster BLSAggregator");
        }
        require(
            keccak256(bytes(reportedVersion)) == keccak256(bytes(expectedVersion)),
            "AGGREGATOR.version() != expected: re-verify the fraud-proof ABI and the arming path for that release, then set EXPECTED_AGGREGATOR_VERSION"
        );
        // GATE A' — ANCHORED RELEASES ONLY (#441), no override. BLSAggregator-4.13.0 (SP rc.8 r3b)
        // keyed the signer commitment per path; 4.14.0 (SP #630, _computeSignersCommitment) ended it
        // with blockhash(block.number - 1). The floor is 4.14.0 (Daybreak on #441, Medium): a 4.13.x
        // commitment has no parent block hash, so this verifier would reject every honest proof there. This verifier (VERIFIER_VERSION
        // "OverIssueFraudProofVerifier-3.0.0") recomputes exactly that layout, with the parent block
        // hash supplied in the fraudProof, so it can never verify against a pre-4.14 aggregator. The
        // pre-#441 verifier was the reverse; this gate used to refuse >= 4.13.0. An unparseable
        // version string is refused too (fail closed). EXPECTED_AGGREGATOR_VERSION cannot lift this.
        uint8 releaseClass = _releaseClass(reportedVersion);
        require(
            releaseClass != RELEASE_UNPARSEABLE,
            "AGGREGATOR.version() is not a well-formed BLSAggregator-<major>.<minor>.<patch>[-suffix]: refusing"
        );
        require(
            releaseClass == RELEASE_ANCHORED,
            "AGGREGATOR is BLSAggregator < 4.14.0 (no parent-block-hash commitment): this verifier can never verify there"
        );

        // GATE B — ARMING DELAY. Independent of Gate A, and deliberately not implied by it: the
        // four days of public visibility before an unbounded 100%-of-lock slash authority can act are
        // a security property in their own right, so assert the constant rather than trusting that a
        // matching version string implies it.
        uint256 rotationDelay;
        try IAggregatorProbe(aggregator).VERIFIER_ROTATION_DELAY() returns (uint256 d) {
            rotationDelay = d;
        } catch {
            revert("AGGREGATOR exposes no VERIFIER_ROTATION_DELAY(): no delay-guarded arming path");
        }
        require(
            rotationDelay >= MIN_VERIFIER_ROTATION_DELAY,
            "AGGREGATOR.VERIFIER_ROTATION_DELAY < 4 days: arming window too short to be publicly visible"
        );

        // Rotation-state receipt (informational, recorded for the CC-115 B3 manifest). SP deploys
        // dormant (`fraudProofVerifier == address(0)`); a non-zero value means this deploy is a
        // ROTATION over a live verifier, and a non-zero pendingReadyAt means a rotation is already in
        // flight that `proposeFraudProofVerifier` would silently overwrite. Neither is blocked here —
        // both are the aggregator owner's call — but the operator must see them before proposing.
        address currentVerifier = IAggregatorProbe(aggregator).fraudProofVerifier();
        address pendingVerifier = IAggregatorProbe(aggregator).pendingFraudProofVerifier();
        uint64 pendingReadyAt = IAggregatorProbe(aggregator).pendingFraudProofVerifierReadyAt();

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
        verifier = new OverIssueFraudProofVerifier(aggregator, registry);
        vm.stopBroadcast();

        // Byte-for-byte domain-conformance gate: the verifier's reconstructed digest MUST equal the
        // aggregator's own `fraudProofDigest` for a probe (id, guardians). If SP's schema and the
        // verifier's constants ever diverge, this fails HERE (post-deploy, pre-handoff) instead of
        // silently rejecting every real proof on-chain.
        //
        // LOW-4 (config-control, not an on-chain exploit): the probes above and this parity check
        // prove the target EXPOSES the expected getters, REPORTS the expected release string, and
        // AGREES on the domain-digest schema — they do NOT prove it is the genuine, honest SP
        // aggregator. `version()` is a plain string a malicious contract returns at will, and such a
        // contract can implement every other getter conformantly while ALSO keeping an instant
        // `setFraudProofVerifier`. No on-chain check in this script can rule that out. The aggregator address AND its Registry MUST be
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

        console.log("--- aggregator rotation state (record for the B3 manifest) ---");
        console.log("aggregator version():       ", reportedVersion);
        console.log("VERIFIER_ROTATION_DELAY (s):", rotationDelay);
        console.log("current fraudProofVerifier: ", currentVerifier);
        if (currentVerifier == address(0)) {
            console.log("  -> dormant at deploy (expected for a first arming)");
        } else {
            console.log("  -> WARNING: a verifier is ALREADY armed; this is a ROTATION, not a first arming");
        }
        console.log("pendingFraudProofVerifier:  ", pendingVerifier);
        console.log("pendingReadyAt:             ", uint256(pendingReadyAt));
        if (pendingReadyAt != 0) {
            console.log(
                "  -> WARNING: a rotation is ALREADY in flight; proposing again OVERWRITES it and restarts the full delay"
            );
        }

        // NOTE: SP 4.11 has NO direct setter. Arming is propose -> full delay -> permissionless apply.
        console.log("--- NEXT (SP side, two-step arming on this aggregator) ---");
        console.log("    target release:", reportedVersion);
        console.log("1) SP owner (Safe M-of-N) calls on the aggregator:");
        console.log("     proposeFraudProofVerifier(", address(verifier), ")");
        console.log("   record the tx hash and the emitted readyAt (== propose block.timestamp + delay)");
        console.log("2) WAIT THE FULL DELAY (seconds):", rotationDelay);
        console.log("   applyFraudProofVerifier() reverts VerifierRotationNotReady(readyAt) before then");
        console.log("3) ANYONE (permissionless) calls: applyFraudProofVerifier()");
        console.log("   record the tx hash and the emitted FraudProofVerifierUpdated(prev, next)");
        console.log("This release has NO setFraudProofVerifier setter and no deployment-time bypass.");
    }
}
