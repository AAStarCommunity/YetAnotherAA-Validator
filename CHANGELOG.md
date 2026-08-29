# Changelog

All notable changes to YetAnotherAA-Validator (the DVT BLS signer node) are
documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); versions follow SemVer.

## [1.15.0] — 2026-08-29 — CC-115 B1 domain-bound fraud-proof verifier + CC-97 committee floor

Two security changes landed on master today (PRs #240, #241). Both are
**source-level**: the contracts are non-upgradeable, so neither is live until a
new validator is deployed and the router re-mounted. The deployed committee
validator `0x1A8Db639…` still has **no** minimum-committee floor and still
carries the pre-4.11 fraud-proof ABI.

### Added — CC-115 B1: domain-bound 4-parameter fraud-proof verifier (#240)

- `IFraudProofVerifier` / `OverIssueFraudProofVerifier` upgraded from
  `verify(uint256,address[],bytes)` to SuperPaymaster 4.11's
  **`verify(bytes32,uint256,address[],bytes)`** (selector **`0x61077735`**).
  `domainDigest` is **recomputed and byte-compared** against the verifier's own
  `(chainid, AGGREGATOR, REGISTRY, tag)` — it is bound, not merely accepted —
  closing cross-chain / cross-aggregator / cross-Registry replay from the DVT
  side. `REGISTRY` is now an immutable constructor argument.
- Guilty-set rule tightened from `⊆ claimedSigners` to **SET-EXACT**, which SP's
  `assertSetBound` release gate requires and which closes the
  front-run-and-shrink vector (filing `(id,{A})` first burns the single-use
  `fraudProofId` and leaves B and C permanently immune). SP confirmed from the
  authoritative side that the verifier is the **only** enforcement point for
  this property.
- SP's `FraudProofVerifierConformance` fixture imported as a **byte-for-byte
  verbatim copy** (SHA-256 `220bfa18…`; only deviations are an additive
  provenance header and the pragma), and both release gates are run.

### Fixed — CC-115 B1: inner commitment layout was pre-4.11 (#240)

- `slashMessageHash` / the signers-commitment recompute used the obsolete
  encoding (empty reputation arrays, a string tag, raw chainid). Live SP
  commitments could therefore **never** verify, so genuine guardian fraud could
  never be slashed. Both now match `BLSAggregator` byte-for-byte
  (`domainSeparator() + TAG_EXECUTE_SLASH` / `+ TAG_SIGNERS_COMMITMENT`). The
  previous tests missed this because the mock reproduced the verifier's own
  format and drew its message hash from the verifier — circular; the suite is
  now de-circularised with a decisive current-layout-accepted /
  obsolete-layout-rejected pair.
- The off-chain path had the same drift: the guardian co-signer, the fraud-proof
  watcher, the filer and `cc89-cosign.mjs` all signed or verified the old hash,
  so the slash path was broken end to end. All of them now route through one
  shared source of truth, **`src/modules/audit/bls-consensus-domain.ts`**
  (mirrored for plain ESM in `scripts/lib/bls-consensus-encoding.mjs`), and a
  **cross-language golden** pins the same vector on both the TypeScript and
  Foundry sides.

### Added — CC-115 B1: fail-closed domain attestation (#240)

- The gossip quorum co-signer and the guardian slash watcher now verify on-chain
  that the locally configured domain equals `aggregator.domainSeparator()` (and
  that the Registry matches) **before** co-signing or polling; a mismatch
  refuses to arm / disables the watcher rather than mis-signing. **Armed nodes
  must set `AUDIT_REGISTRY_ADDRESS` to the aggregator's real Registry.**
- The shared commitment helper enforces canonical (strictly ascending, non-zero,
  duplicate-free) signer order instead of silently hashing a wrong set.

### Added — CC-97: committee minimum-size floor (#241)

- `AAStarCommitteeValidator.minCommittee` (constructor `3`; `setMinCommittee` is
  owner-only with a **hard floor of 3** and bumps `configVersion`). `validate()`
  fails closed and `requiredQuorum()` returns the unsatisfiable sentinel when
  the **frozen** pool is below it. Restores the floor agreed on 2026-08-16 that
  was lost when the global-N model was scrapped for the per-proposal rewrite:
  without it `ceil(2N/3)` degenerates at tiny N, so **N=1 gave quorum 1** and a
  single staked node cleared tier-2/3.
- **Pubkey uniqueness** (`nodeByPubkey` reverse lock) maintained through a
  shared bind/unbind seam on every key-state transition, including intra-batch
  duplicates. Without it the floor is satisfiable with fewer real keys than
  nodes — the bootstrap path previously allowed one key under two nodeIds.
- `setRegistry` / `setRequireStake` / `setMinStake` bump `configVersion` via a
  new `_onEligibilityConfigChanged` hook, so a snapshot pinned under one
  eligibility policy is not reused under another.

### Known limitations (unchanged by this release)

- **The floor is over the frozen REGISTERED pool, not a stake-verified one.**
  The configVersion bump invalidates old snapshots; it does not make the next
  one stake-clean, since nodes stay registered until `syncNode` evicts them.
  Closing that needs eligible-set accounting + "currently staked", blocked on
  the SuperPaymaster unbonding semantics (CC-112).
- **With committee mode off (`epochLength == 0`) the legacy whole-set path still
  has no floor and no quorum** — pre-existing behaviour, and the deploy script
  ships committee mode off deliberately. Giving that fallback a quorum would
  re-introduce the unscalable global-N model, so the alternative (an
  account-side gate before committee activation) is open with
  `airaccount-contract`.
- The over-issue verifier still adjudicates against the token's **current**
  `isOverIssued()` state, so a repaired supply can flip a once-justified slash.
  It remains testnet/E2E-only and **must not be wired to a slash-capable
  production deployment**.

## [1.14.0] — 2026-08-18 — CC-98 per-proposal committee BLS validator (retroactive entry)

Recorded here after the fact: `v1.14.0` was tagged and released on GitHub
without a changelog entry. Content is the CC-98 per-proposal random-committee
validator (`AAStarCommitteeValidator`, Sepolia
`0x1A8Db639b5d8Bd5742edB083656EDD56f416cd64`) plus the snapshot keeper and the
aggregator Merkle proof generator (PRs #236–#239).

## [1.13.1] — 2026-08-15 — CC-89 follow-up: aggregator-default alignment + audit/watcher bootstrap fail-closure

Backward-compatible hardening patch (raised on CC-90 by the KMS工兵: the DVT
code default `AUDIT_BLS_AGGREGATOR_ADDRESS` was a stale pre-CC-89 address).
Every touched path is opt-in (offline audit + guardian watcher, both default
off) — no change to default runtime behaviour, no breaking change. SP / SDK /
airaccount / paper need no changes; KMS only updates the watcher env example.

### Changed

- **Aggregator default aligned** `0xF51c0298…` (stale, SP's pre-CC-89 canonical)
  → `0x174b60bB462b00550F0EC7Bc35Fe39dDB6310158` (SP production A' 4.3.0).
  Tracks the real aggregator rotation that shipped with CC-89.

### Added (fail-closed hardening)

- **`aggregator-bootstrap-guard.ts`** (pure, shared) — one fail-closed policy
  for both audit consumers: reject a provider chain ≠ `AUDIT_CHAIN_ID`, and
  reject the Sepolia default silently inherited **off-Sepolia** unless
  `AUDIT_BLS_AGGREGATOR_ADDRESS` is set explicitly (a non-empty default
  otherwise masks the unset case).
- **`auditBlsAggregatorAddressFromEnv`** (`configuration.ts`) — tracks whether
  the aggregator address was set explicitly (not the resolved value).
- **Interface probe at bootstrap** — the offline rule (`getBLSPublicKey` +
  `validatorAtSlot`) and the guardian watcher (`validatorAtSlot` +
  `proposalSignersCommitment`) each statically exercise the exact methods they
  call at runtime, so a wrong-but-deployed address fails-closed at startup
  instead of fail-open per tick. New `BlockchainService.getChainId()` /
  `probeBlsAggregator()`.
- `.gitignore`: `guardian-operators.json` (production guardian EOA keys).

### Notes

- Codex Tier-1: 5 rounds, final verdict CLEAN (0 Critical/High/Medium/Low). One
  Medium (a hard canonical-identity address/codehash pin) deferred with
  rationale — it would false-disable on legitimate SP aggregator redeploys; the
  silent-default footgun this patch closes is the real issue.
- docs `cc89-e2e-record.md`: distinguishes the E2E throwaway aggregator from
  production.

## [1.13.0] — 2026-08-15 — CC-89 stage-2: over-issue guardian-collusion slash (testnet-E2E proven)

Production release. Adds the DVT half of the CC-89 guardian-collusion slashing
mechanism — the fraud-proof path that punishes ≥m colluding guardians who pass a
fraudulent over-issue slash — and proves the whole chain end-to-end on Sepolia
with SuperPaymaster.

### Added

- **`OverIssueFraudProofVerifier`** (`contracts/`, #223) + `IFraudProofVerifier`
  — the on-chain `verify()` (fail-closed view) that
  `BLSAggregator.executeGuardianSlash` calls: 5 checks (fraudProofId
  content-binding, canonical claimedSigners, A'-commitment reconstruction
  binding the disputed token, `guiltyGuardians ⊆ claimedSigners`,
  `isOverIssued(token)==false`). 16 Foundry tests + TS↔Solidity golden vector.
- **Guardian-slash watcher** (`src/modules/audit/guardian-slash-watcher.*`,
  #224) — in-process, opt-in (`AUDIT_GUARDIAN_WATCH_ENABLED`, default off),
  fail-closed: captures each `SlashExecuted`'s signer address set at the
  execution block into a 3-area durable store (verified / quarantine /
  dead-letter), the irreversible-A' data-availability layer. Restart-safe
  cursor.
- **Fraud-proof assembler** (`guardian-fraud-proof-assembler.ts`, #225) — builds
  the `(fraudProofId, guiltyGuardians, fraudProof)` the verifier accepts;
  refuses doomed/harmful inputs.
- **Stage-0 design + E2E runbook + shipping plan + E2E record** (docs/design/,
  #221/#226 + this release) — threat model, A' spec, cross-repo evidence
  convention, and the authoritative Sepolia E2E record for the RepCredit paper.
- **Joint-testnet tooling** — `DeployOverIssueVerifier.s.sol` (#227),
  `cc89-cosign.mjs` + `cc89-e2e-finish.mjs` + `MockOverIssuableToken.sol`
  (#229), `/goal` shipping-pipeline command.

### Verified

- **Testnet E2E PASSED on Sepolia** (CC-89): SP `verifyAndExecute` → A'
  commitment → DVT fraud proof → `executeGuardianSlash` (tx `0xb870688e…91ba`) →
  3 guardians' ROLE_DVT stake 30e18 → 0 → auto-eject. The paper's `ρ` detection
  half is now "implemented + testnet-verified" for the on-chain-objective
  (over-issue) class.

### Fixed (security)

- **`.gitignore`** (#228) — drop the stale `!node_dev_001.json` un-ignore that
  force-included a BLS private-key filename; all `node_dev_*.json` now ignored.

### Deferred (Phase-3 / gated)

- Trustless historical-state over-issue proof (BLOCKHASH + storage proof,
  bounded challenge window); watcher wrapped-call trace resolution; liveness
  class (gated on CC-29); production arming of an on-chain-objective slash rule.

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

- Pinned: SuperPaymaster `v5.4.0-beta.1-redeploy`, airaccount-contract
  `v0.19.0-beta.2`, AirAccount `v0.23.0`.
- **Re-pinned SuperPaymaster PolicyRegistry (2026-06-16 fresh Sepolia
  redeploy)**:
  `0x37e4E40e69Fb7d5C3fbAA0F52A4002D27472Ff29 → 0x8c2488d46d5447418558c38AA6441720df656094`
  **identical source/logic** — `PolicyRegistry.sol` is byte-for-byte the same as
  the integrated `v5.4.0-beta.1`; the deployed bytecode differs only by the
  `immutable` constructor args (new timelock/guardian/initialConsumer), and the
  `checkPolicy(address,address,address,uint256,bytes4) → (uint8,uint256)` ABI is
  unchanged. The whole v5.4 stack — SuperPaymaster proxy, Registry,
  TimelockController, X402Facilitator — was redeployed under the annotated tag
  `v5.4.0-beta.1-redeploy`, which ships **no GitHub release**. The node's
  layer-1 `checkPolicy` read was re-verified against the new registry
  (`decision=0 ALLOW`). Update `POLICY_REGISTRY_ADDRESS` to the new address when
  `POLICY_ENABLED=true`.
- **Re-pinned airaccount-contract `v0.18.0-beta.2 → v0.19.0-beta.2`**
  (redeploy): `AAStarBLSAlgorithm`
  `0xA9EE4f8A… → 0x68c381Ad3A2e3380F22840008027E9Ec2783F43A`. **No Solidity
  logic change** — verifier/wire identical; the node's on-chain BLS validate was
  re-verified `= 0` against the new contract. Address-pin update only, no
  code/signing change.
- Re-pinned AirAccount `v0.22.0 → v0.23.0` (Sigsum transparency log; orthogonal
  to the ownerAuth contract — node unaffected).
- `scripts/check-deps.mjs` upgraded to resolve each dependency's canonical
  address from its committed **deploy-config JSON on the default branch**
  (`deployments/config.sepolia.json`), not just GitHub release notes — this is
  what catches a **doc-less redeploy** shipped under an annotated `*-redeploy`
  tag with no release (exactly how the PolicyRegistry move above slipped past
  the old release-only check). It also scans all tags and flags
  `-redeploy`/variant tags. Run via `npm run check-deps`.

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
