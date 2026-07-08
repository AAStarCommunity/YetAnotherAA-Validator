# Release readiness — DVT independent + joint-with-KMS (test & prod)

Tracks every gap between the current state (v1.11.0, slash consensus proven E2E
on Sepolia against SuperPaymaster 5.4.2) and a real production release. Split by
**how DVT ships** (independent signer/auditor vs KMS-TEE joint) × **target**
(Sepolia test vs mainnet prod). Complements
[`RELEASE_TEST_CHECKLIST.md`](./RELEASE_TEST_CHECKLIST.md) (the per-arming
drill).

Status legend: ✅ done · 🟡 partial/needs-work · 🔴 blocker · ⏳ waiting on
another team/hardware.

> **The DVT has two roles.** As a **co-signer** (co-sign UserOps + owner-gate)
> it needs no slash gossip. As an **autonomous slash auditor** it needs the
> distributed gossip mesh + the on-chain slash contracts. Several gaps below
> apply only to the auditor role — noted inline.

---

## A. DVT independent release

### A1 — Test (Sepolia)

| #   | Gap                                                                          | Sev              | Role                  | Notes / owner                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| --- | ---------------------------------------------------------------------------- | ---------------- | --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 1   | ~~Gossip over public `wss` = cloudflare 502~~ — **diagnosed, NOT a blocker** | 🟢→🟡            | auditor (distributed) | **Re-tested 2026-07-08: distributed public-`wss` gossip WORKS** — origin `ws://localhost:4001/ws` ✅ OPEN, `wss://dvt1.aastar.io/ws` (via cloudflare) ✅ OPEN, mesh `peers=3` on all 3 nodes in public mode. The drill's 502 was a **startup-timing artifact**: the deploy script boots the nodes (which announce `wss://…`) BEFORE cloudflared warms up → the first connects 502 → SWIM retries → self-heals once the tunnel is up. Residual (🟡): gate node announce on cloudflared readiness, or accept the self-heal. `DRILL_LOCAL_GOSSIP=1` remains for co-located drills.                                                                        |
| 2   | Prod RPC (getLogs range ≥ lookback + reliable `eth_call` + archive)          | 🟢 (have it)     | auditor               | Paid Alchemy in `~/Dev/.env` (`SEPOLIA_RPC`) covers getLogs/eth_call/archive. Size `AUDIT_SLASH_LOOKBACK_BLOCKS` to its cap. Mainnet URL still needed for A2.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| 3   | Fresh independent `node_state` keys                                          | 🟠               | both                  | The old committed testnet key (`0x95c8…`) is **leaked** — every prod node must `node scripts/gen-node-state.mjs` a fresh key; never reuse any repo key.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| 4   | Real-slash arming gate                                                       | ✅ (documented)  | auditor               | `AUDIT_EXECUTE_SLASH` default-off; arming = watchlist + registered validators + `RELEASE_TEST_CHECKLIST.md` + cold-start-floor awareness.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| 5   | Prod monitoring / alerting                                                   | ✅ (PR #191)     | auditor               | `/audit/status` cumulative `metrics` counters + `[AUDIT-EVENT] kind=…` structured logs. Wire an alert on `SLASH_EXECUTED` / `ERROR` / rising `coSignAborts`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| 6   | **Watchlist should be DERIVED on-chain, not hand-curated**                   | 🟢 (built)       | auditor               | DONE (`feat/audit-watchlist-onchain-derive`). `AUDIT_ROLE_DERIVE=true` enumerates the CURRENT members of `AUDIT_ROLE_IDS` (default DVT,ANODE) from the Registry — `getRoleMembers` getter-first, `RoleRegistered/RoleGranted` (add) / `RoleExited/RoleRevoked` (remove) event-reconstruction fallback — UNIONed with the static `AUDIT_WATCHLIST` (now an additive override, never subtracts). Throttled refresh; fail-loud on getLogs error (keeps previous set, never empties). A `getRoleMembers(bytes32)` getter from @repo:sp gives O(1) reads (goutou pending); the event scan works today. Set `AUDIT_ROLE_FROM_BLOCK` = Registry deploy block. |
| 7   | **4 audit rules — building all four (CC-13 decision)**                       | 🟡 (in progress) | auditor               | ✅ `credit-over-limit`. Build order: ✅① watchlist-derive → ② offline-via-gossip-heartbeat → ③ token-over-issue (社区超发 mint; needs an on-chain issuance formula from @repo:sp) → ④ proof-forgery. NOTE: the account per-tx-cap / contract-allowlist "account rules" the user described are ALREADY enforced PROACTIVELY at sign-time via `PolicyRegistry.checkPolicy` (DVT refuses to co-sign a violating UserOp) — NOT an audit rule.                                                                                                                                                                                                              |

### A2 — Production (Mainnet) — **NOT READY**

| #   | Gap                                                  | Sev   | Notes / owner                                                                                                                                               |
| --- | ---------------------------------------------------- | ----- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | **Mainnet config is a placeholder**                  | 🔴    | `deploy/sdk-dvt-config.testnet.json` `environments.mainnet` = `"NOT DEPLOYED — placeholder"`. Needs all mainnet addresses + node URLs + `active='mainnet'`. |
| 2   | Mainnet slash contracts deployed                     | 🔴    | @repo:sp                                                                                                                                                    | Mainnet SuperPaymaster / Registry / BLSAggregator / DVTValidator (mirror the 5.4.2 Sepolia stack incl. the `_blsSlashCd` double-slash fix). |
| 3   | Mainnet validator registration                       | 🔴    | @repo:sp owner                                                                                                                                              | `addValidator×N` + `registerBLSPublicKey×N` (+ slots) on the mainnet BLSAggregator.                                                         |
| 4   | Mainnet `e2e_account`                                | ⏳    | @repo:airaccount-contract                                                                                                                                   | Mainnet `AAStarAirAccountV7` deploy → an account implementing `isValidOwnerAuth→0xa0cf00cf`.                                                |
| 5   | Everything in A1 (gossip 502, RPC, keys, monitoring) | 🔴/🟠 | applies to mainnet too                                                                                                                                      |
| 6   | `setSlashPolicyAdmin` → multisig                     | 🟠    | ops + @repo:sdk/@repo:yaaa                                                                                                                                  | Still deployer EOA; governance handoff page in progress (CC-13 SDK batch A/B).                                                              |

---

## B. Joint KMS-TEE release (CC-22)

### B1 — Test (Sepolia + imx93)

| #   | Gap                                              | Sev | Notes / owner                                                                                                                                                         |
| --- | ------------------------------------------------ | --- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | KMS `/sign` byte-alignment                       | ✅  | Confirmed byte-for-byte (wire + EIP-2537 c0/c1 order + DST) vs `bls.service.ts` / `bls.util.ts` (CC-22). KMS 0.28.0 shipped.                                          |
| 2   | key-less `node_state` provisioning               | ✅  | KMS side writes it (BlsGenKey→pubkey→`{nodeId, publicKey}`); DVT `node.service.ts` already supports key-less boot when `RUST_SIGNER_URL`+`RUST_SIGNER_REQUIRED=true`. |
| 3   | Full on-chain `validate=0` E2E on the board      | ⏳  | Gated on the **production imx93 board** arriving (`POST /node/register` + `ETH_PRIVATE_KEY` → realnode-e2e).                                                          |
| 4   | If slash consensus runs distributed on the board | 🔴  | Same gossip 502 (A1#1). Local BLS sign + owner-gate (CC-22's focus) is unaffected.                                                                                    |

### B2 — Production (Mainnet + imx93)

| #   | Gap                                                                     | Sev | Notes / owner                   |
| --- | ----------------------------------------------------------------------- | --- | ------------------------------- |
| 1   | All of A2 (mainnet config/contracts/registration/keys)                  | 🔴  |                                 |
| 2   | Mainnet `e2e_account`                                                   | ⏳  | @repo:airaccount-contract       |
| 3   | KMS-TEE prod keystore (EIP-2335 + passphrase→tmpfs + systemd hardening) | 🟡  | Designed; needs the real board. |
| 4   | Production imx93 board hardware                                         | ⏳  | ops                             |

---

## Config inputs needed from you (things DVT cannot self-serve)

**To run a DISTRIBUTED Sepolia slash drill / test-prod:**

- [ ] Prod-grade Sepolia **RPC URL** (getLogs range ≥ the lookback you want +
      reliable `eth_call` + archive). Paid Alchemy/Infura/QuickNode, etc.
- [ ] Decision on the **gossip transport** for distributed nodes: fix the
      cloudflare tunnel to pass `wss` upgrades, OR pick an alternative (direct
      port / different tunnel). (Infra access needed — not code.)
- [ ] The **watchlist** — which SuperPaymaster operator address(es) to audit in
      prod.

**To ship DVT on MAINNET (independent or joint):**

- [ ] Mainnet **RPC URL**.
- [ ] Mainnet contract addresses (from @repo:sp after the mainnet
      5.4.2-equivalent deploy): SuperPaymaster, Registry, BLSAggregator,
      DVTValidator, + the aPNTs/xPNTs token(s).
- [ ] Mainnet **validator registration** done by the SP owner (addValidator +
      registerBLSPublicKey + slot list).
- [ ] Mainnet **`e2e_account`** + owner (from @repo:airaccount-contract).
- [ ] Mainnet **node public URLs** (dvt1/2/3 mainnet endpoints).
- [ ] Funded mainnet **operator EOAs** (gas for queue/execute txs).

**For the joint KMS board E2E:**

- [ ] Production **imx93 board** access.
- [ ] KMS `/sign` endpoint URL + (optional) `X-Signer-Token`.
