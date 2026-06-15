# Changelog

All notable changes to YetAnotherAA-Validator (the DVT BLS signer node) are
documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); versions follow SemVer.

## [1.1.0] — 2026-06-15 — DVT Fix 2 (Stage 1 + Stage 2)

The DVT node-side release of the cross-repo **DVT program** (coordination hub:
`AAStarCommunity/YetAnotherAA-Validator#42`). Turns the signer into a true
second factor that survives owner-key compromise.

### Added

- **Stage 1 — owner-authorization gate** on `POST /signature/sign` (#41). The
  node co-signs only when the request carries a valid account-owner ECDSA
  signature (`ownerAuth`, EIP-191) over the **authoritative `userOpHash` derived
  on-chain** via `EntryPoint.getUserOpHash` — never a caller-supplied hash.
  Closes the cross-account oracle hole; uniformly fail-closed with **403** on
  any failure.
- **Stage 2 — independent policy gate** (`PolicyService`, #43/#44), two layers
  ANDed:
  - **Layer 2 (node-operator floor, local):** per-tx native cap +
    recipient/contract allowlist; owner and CA cannot change it.
  - **Layer 1 (per-account, on-chain):** `IPolicyRegistry.checkPolicy` against
    the SuperPaymaster-deployed registry; co-signs only on
    `ALLOW`/`REQUIRE_DVT`, refuses on `REJECT` and any unknown decision
    (fail-closed).
  - Decodes `execute`/`executeBatch` and extracts ERC-20
    `transfer`/`transferFrom`/ `approve` amounts so per-asset limits apply to
    tokens, not just native ETH.
  - Owner-auth runs **before** the policy gate (no pre-auth policy oracle /
    registry RPC).
  - Opt-in via `POLICY_ENABLED` (default off); fail-fast if enabled with no
    rules.
- **Normative signing-format spec** `docs/design/dvt-node-protocol.md` +
  cross-repo **golden vector**
  (`hash_to_curve(userOpHash, DST=BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_)`).
- **Policy governance design** `docs/design/dvt-policy-governance.md`.
- `BlockchainService.checkPolicy` / `getAccountOwner` / `getUserOpHash` read
  paths.

### Changed (behavior)

- `POST /signature/sign` now **requires** `ownerAuth` and rejects unauthorized
  or out-of-policy requests with **403**. Callers integrated before Stage 1 must
  send the owner signature. (Aggregation/verify endpoints unchanged.)

### Security

- Verified end-to-end against the live Sepolia `PolicyRegistry`
  (`0x37e4E40e69Fb7d5C3fbAA0F52A4002D27472Ff29`).
- Passed a 4-round adversarial PK review (DeepSeek → Sonnet → Opus → Codex);
  fixes include a fail-open registry decision, a gate-ordering oracle, and a
  selector-collision allowlist bypass. 36/36 tests.

### Config

```
POLICY_ENABLED=true
POLICY_REGISTRY_ADDRESS=0x37e4E40e69Fb7d5C3fbAA0F52A4002D27472Ff29   # Sepolia
POLICY_ETH_SENTINEL=0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE
POLICY_PER_TX_MAX_WEI=...            # optional native cap
POLICY_RECIPIENT_ALLOWLIST=0x..,0x.. # optional contract+recipient allowlist
```

### Known follow-ups (v1.1.x)

- Independent (non-noble) RFC-9380 reference vector for the golden test.
- V8 `executeUserOp` selector decoding (currently fail-closed when policy on).
- Cross-repo on-chain E2E of a full combined signature (KMS/P256 main + DVT
  aggregate).
