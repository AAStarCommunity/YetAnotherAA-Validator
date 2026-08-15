// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.19;

/**
 * @title MockOverIssuableToken
 * @notice CC-89 joint-testnet E2E fixture. Exposes the CC-28 `isOverIssued()` shape so the
 *         over-issue guardian-slash chain can cite it as the disputed token. Defaults to
 *         `false` (NOT over-issued) → a slash accusing it of over-issue is FRAUDULENT, which is
 *         exactly what `OverIssueFraudProofVerifier` proves (step 5) to justify slashing the
 *         colluding guardians. `setOverIssued` lets the operator flip it to also exercise the
 *         negative path (verifier must REJECT when the token really is over-issued).
 */
contract MockOverIssuableToken {
    bool public over;
    address public immutable owner;

    constructor() {
        owner = msg.sender;
    }

    function isOverIssued() external view returns (bool) {
        return over;
    }

    function setOverIssued(bool v) external {
        require(msg.sender == owner, "only owner");
        over = v;
    }
}
