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

| #   | Gap                                                                 | Sev             | Role                  | Notes / owner                                                                                                                                                                                                                                                                                                             |
| --- | ------------------------------------------------------------------- | --------------- | --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | **Gossip over public `wss` = cloudflare 502**                       | 🔴              | auditor (distributed) | `wss://dvtN.aastar.io/ws` returns 502 on the WebSocket upgrade; the drill used `DRILL_LOCAL_GOSSIP=1` (localhost) to bypass it. Distributed `dvt1/2/3` slash co-sign can't mesh until the tunnel supports `wss` (or a different gossip transport/port). **Co-signer role unaffected.** → infra (cloudflare tunnel config) |
| 2   | Prod RPC (getLogs range ≥ lookback + reliable `eth_call` + archive) | 🟠              | auditor               | Alchemy free caps `eth_getLogs` at 10 blocks → forces `AUDIT_SLASH_LOOKBACK_BLOCKS=9` (marginal). Prod needs a paid/archive RPC. → config (you provide the URL)                                                                                                                                                           |
| 3   | Fresh independent `node_state` keys                                 | 🟠              | both                  | The old committed testnet key (`0x95c8…`) is **leaked** — every prod node must `node scripts/gen-node-state.mjs` a fresh key; never reuse any repo key.                                                                                                                                                                   |
| 4   | Real-slash arming gate                                              | ✅ (documented) | auditor               | `AUDIT_EXECUTE_SLASH` default-off; arming = watchlist + registered validators + `RELEASE_TEST_CHECKLIST.md` + cold-start-floor awareness.                                                                                                                                                                                 |
| 5   | Prod monitoring / alerting                                          | 🟠              | auditor               | No prod hook for slash events / co-sign failures / gas. Add before arming against real operators.                                                                                                                                                                                                                         |

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
