# DVT test → prod (testnet → mainnet) switch — runbook

> Principle (confirmed against code): **KMS has no on-chain dependency; the DVT
> carries the chain dependencies.** So a network switch is a DVT-config change —
> **plus one external-dependency action the config alone can't do: registering
> the node's BLS pubkey on the target network's validator.** Code is identical
> across networks (`configuration.ts` just reads different env); see CLAUDE.md.

## What actually differs between networks (the only things to change)

| Knob                         | Where        | Note                                                                                                                                                                                                                                                                                        |
| ---------------------------- | ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ETH_RPC_URL`                | `dvt.env`    | target network RPC                                                                                                                                                                                                                                                                          |
| `VALIDATOR_CONTRACT_ADDRESS` | `dvt.env`    | **authoritative source = `deploy/sdk-dvt-config.testnet.json` → `environments[active].validator`** (this repo owns the `AAStarValidator`; that file declares itself the single source of truth). Testnet today = `0x539B9681aFd5BFbCaa655Fe4c6BdcFe1fa7864bC` (Plan A v3, LIVE on Sepolia). |
| `ENTRY_POINT_ADDRESS`        | `dvt.env`    | canonical v0.7 `0x0000000071727De22E5E9d8BAf0edAc6f37da032` (same both nets)                                                                                                                                                                                                                |
| BLS key registration         | **on-chain** | `registerPublicKey(nodeId, pubkey)` on the **target** validator — see step 3                                                                                                                                                                                                                |

Everything else (the app, node_modules, systemd) is byte-identical.

## Steps

1. **Confirm the target validator address.** It is DVT-owned; read it from
   `deploy/sdk-dvt-config.testnet.json` (flip `active` for mainnet once
   deployed). Cross-repo coupling to watch: the validator is mounted in
   airaccount's `ValidatorRouter 0xe68d6A7Bb60DA4caE62ceC2439722fc5eEF87a5c` — a
   validator redeploy means airaccount re-mounts it. If it ever changes, update
   that file (single source) and notify consumers (SDK `aastar-sdk#274`, KMS,
   this board).

2. **Point the node at the target network** — edit `dvt.env`: `ETH_RPC_URL`,
   `VALIDATOR_CONTRACT_ADDRESS`, `ENTRY_POINT_ADDRESS`. No code change.

3. **Register this node's BLS pubkey on the target validator** (one-time, per
   network — the config switch can't do this). Needs `ETH_PRIVATE_KEY` (operator
   EOA, funded on the target net) → `POST /node/register` (calls
   `blockchain.service.ts registerPublicKey`). Skip only if the same pubkey is
   already registered there.

4. **Restart + verify.** `systemctl restart dvt` → `curl /health` (version) →
   `curl /node/info` (pubkey) → a co-sign E2E that ends in
   `AAStarValidator.validate === 0` on the target net (see
   COMMUNITY_OPERATORS.md).

## KMS side (for contrast — no chain action)

KMS switch = rpId/Origin + production build only (remove passkey-export +
localhost-rpid-accept). No RPC, no contract, no registration. Owned by the
AirAccount/KMS repo, not here.

## Signing-key custody (orthogonal to the network switch)

- **BLS key** (co-signing): local encrypted keystore **or** KMS-TEE custody
  (`RUST_SIGNER_URL` + `RUST_SIGNER_REQUIRED=true`, key-less `node_state.json` —
  needs DVT ≥ v1.10.0). KMS-TEE is required for unattended power-on (no tmpfs
  passphrase to re-enter).
- **Operator/keeper ECDSA key** (`ETH_PRIVATE_KEY` / `KEEPER_PRIVATE_KEY`):
  today a plaintext `.env` EOA — **KMS-TEE custody of the BLS key does NOT
  protect it**. Routing it through KMS's secp256k1 signer is a separate feature
  (see `docs/KEEPER-KMS-SIGNING.md` proposal).
