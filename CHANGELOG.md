# Changelog

All notable changes to YetAnotherAA-Validator (the DVT BLS signer node) are
documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); versions follow SemVer.

## [1.3.0] — 2026-06-16 — node hardening + dependency pinning

### Added

- **Per-IP rate limiting** on `/signature/*` (#50 ⑦; opt-in
  `RATE_LIMIT_ENABLED`) — bounds pre-auth on-chain RPC amplification; over-limit
  → 429.
- **Multi-channel large-spend notification** (#52; Telegram first; opt-in
  `NOTIFY_ENABLED`) — after a high-value co-sign, fire-and-forget alerts the
  user; never blocks/fails signing.
- **Out-of-band confirmation, scheme A** (#50 ⑤; opt-in `CONFIRM_ENABLED`) — a
  high-value co-sign is **withheld** until the user approves a one-time token
  sent over an independent channel;
  `POST /signature/confirm {userOpHash, token}` releases it. **Fail-closed** if
  undeliverable. Single-use + TTL. The defense against owner-key compromise.
- **`scripts/check-deps.mjs`** — built-in upstream/downstream dependency check
  (release tags + on-chain presence vs the pinned baseline).
- **Pre-commit secret scanner** (`scripts/git-hooks/`) — blocks committing
  secret files / credentials; `prepare` sets `core.hooksPath`.
- README **上下游依赖 (PINNED)** section.

### Changed (consumer-facing)

- `POST /signature/sign` may return
  `{ status: "pending_confirmation", userOpHash }` instead of a signature when
  `CONFIRM_ENABLED` + the op is high-value. Consumers (aastar-sdk) must handle
  this response and the `/signature/confirm` flow.

### Dependencies

- Pinned: SuperPaymaster `v5.4.0-beta.1` (PolicyRegistry `0x37e4E40e…` unchanged
  after the 2026-06-16 Sepolia redeploy), airaccount-contract `v0.19.0-beta.2`,
  AirAccount `v0.23.0`.
- **Re-pinned airaccount-contract `v0.18.0-beta.2 → v0.19.0-beta.2`**
  (redeploy): `AAStarBLSAlgorithm`
  `0xA9EE4f8A… → 0x68c381Ad3A2e3380F22840008027E9Ec2783F43A`. **No Solidity
  logic change** — verifier/wire identical; the node's on-chain BLS validate was
  re-verified `= 0` against the new contract. Address-pin update only, no
  code/signing change.
- Re-pinned AirAccount `v0.22.0 → v0.23.0` (Sigsum transparency log; orthogonal
  to the ownerAuth contract — node unaffected).
- `scripts/check-deps.mjs` upgraded to parse the canonical address from each
  dependency's release notes (catches a same-tag REDEPLOY, not just version
  bumps); run via `npm run check-deps`.

### Notes

- All gates are opt-in (default off → behavior unchanged). Email + Nostr
  channels deferred to a later version (#52).

## [1.2.0] — 2026-06-16 — DVT v1 program RELEASED + aNode node service

Marks the cross-repo **DVT v1** milestone: protocol frozen, all four
implementing repos delivered, real on-chain evidence chain complete, and all
program issues closed (coordination hub
[#42](https://github.com/AAStarCommunity/YetAnotherAA-Validator/issues/42)
closed). This repo (the **aNode** reference node) ships the operational tooling.

### Added

- **aNode node service & ops** — `scripts/e2e/dvt-nodes.sh` one-click
  `start/status/info/logs/stop` for N running nodes; `gen-nodes.mjs`,
  `selftest.mjs`, `realnode-e2e.mjs`, `handleops-tx.mjs`.
- **Real-node E2E proven on Sepolia** — 3 running v1.1.0 nodes co-sign (Stage-1
  gated) → aggregate → `AAStarBLSAlgorithm.validate = 0 VALID`; negative control
  = 1. Independently reproduced SDK-side by aastar-sdk #76.
- **Docs** — `docs/aNode-dvt-operations.md` (operations runbook:
  start/monitor/stop/ recover/error/fix + production aNode startup);
  `docs/design/dvt-e2e-and-production.md` (production-readiness design); README
  retitled **“aNode DVT 说明”** with a Features section.

### Cross-repo (DVT v1, all CLOSED)

- SuperPaymaster #283 (`ROLE_DVT` + IPolicyRegistry, deployed v5.4.0-beta.1) ·
  airaccount-contract #110 (on-chain combined-sig validate, full handleOps
  Tier2/3) · AirAccount #70 (C1 binding vector) · aastar-sdk #63 (SDK assembly +
  real-node E2E) · Brood #3 (PGL incentive). Shared format byte-aligned: DST
  `_POP_`, EIP-2537 encoding, registration-slot bit order, `[nodeIds][blsSig]`
  wire.

### Production hardening (tracked separately, NOT in v1 scope)

node BLS key → KMS/HSM · M-of-N real operators · public node URLs · #40 Stage 2
passkey-owner auth · out-of-band confirmation · live slashing · mainnet audit.

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
