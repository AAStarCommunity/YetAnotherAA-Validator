# Proposal — route operator/keeper ECDSA signing through KMS-TEE

Status: **evaluation + plan** (not built). Owner: DVT + KMS (cross-repo).

## Problem

KMS-TEE custody protects the **BLS** co-signing key (key-less
`node_state.json` + `RUST_SIGNER_URL` → KMS `/sign`). It does **not** protect
the **operator/keeper ECDSA key**: today all on-chain writes sign with a
plaintext EOA from `.env`.

Evidence:

- `blockchain.service.ts:136` `this.wallet = new ethers.Wallet(ETH_PRIVATE_KEY)`
- `blockchain.service.ts:148`
  `keeperWallet = new ethers.Wallet(KEEPER_PRIVATE_KEY)`
- `liveness-keeper.service.ts:21` — `attestLiveness()` from the **operator EOA**
- The only remote-signer seam that exists is **BLS-only** (`RUST_SIGNER_URL`,
  `bls.service.ts signViaRust`). There is **no ECDSA remote seam**.

So on a KMS-co-located board that runs a keeper, the operator k1 key is the last
plaintext secret on disk.

## Feasibility

**Yes.** KMS (AirAccount) already signs secp256k1 (`/kms/sign` supports
`secp256k1`/`p256`; keys sealed in OP-TEE). ethers v6 lets us drop in a custom
`AbstractSigner` whose `signTransaction`/`signMessage`/`signTypedData` call KMS
instead of holding a key. So **"the TEE key IS the keeper's EOA"** is exactly
right: KMS seals a k1 key, its derived address = the funded keeper EOA, and KMS
signs every tx in the TEE. The key never touches disk.

## Design (mirror the BLS seam — reuse, don't reinvent)

```
BLS   (today):  node_state key-less  + RUST_SIGNER_URL   → KMS /sign  (BLS12-381)
ECDSA (new):    no local EOA key     + KEEPER_SIGNER_URL  → KMS /kms/sign (secp256k1)
```

- New `KmsEcdsaSigner extends ethers.AbstractSigner`: `getAddress()` from a
  configured keeper address; `signTransaction(tx)` → serialize unsigned → KMS
  `/kms/sign` (keyId=keeper) → assemble `{r,s,v}` → return signed tx. Same
  `X-Signer-Token` auth as the BLS seam (`#182`).
- `BlockchainService.initializeProvider()`: when `KEEPER_SIGNER_URL` is set,
  build `wallet`/`keeperWallet` as `KmsEcdsaSigner` instead of
  `new ethers.Wallet(pk)`. **Fallback preserved**: `KEEPER_SIGNER_URL` unset →
  today's `.env` EOA path (standalone / non-co-located boards keep working —
  "允许降级为独立 env").
- `enqueueWalletWrite` nonce FIFO is unchanged (the signer swap is transparent
  to it).

## Provisioning flow — DVT-driven self-service (not KMS-manual)

The node **drives** provisioning; KMS is the key-custody backend it calls. One
`dvt init-kms` command / admin endpoint does the whole thing so it works the
same on any board (not a KMS operator hand-running commands on each box):

1. DVT → KMS `gen-bls-key` (TEE-sealed) → BLS pubkey → write key-less
   `node_state.json` → on-chain `registerPublicKey` on the target validator.
2. DVT → KMS `gen-keeper-eoa` (TEE-sealed secp256k1) → **keeper EOA address**.
3. DVT records the full pubkey + keeper EOA in its **config** (single source),
   and **displays them on the dashboard** (`dvt.aastar.io` / `/admin`) **masked
   in the middle** (e.g. `0x539B…64bC`) so the operator can read enough to act
   without the panel leaking full values. The full keeper EOA is in config so
   the operator can **fund it with ETH**.
4. `dvt.env`: `KEEPER_SIGNER_URL=http://127.0.0.1:3100`, `KEEPER_ADDRESS=0x…`,
   `KEEPER_ENABLED=true` (no `KEEPER_PRIVATE_KEY`).
5. Operator funds the keeper EOA. Keeper runs; every
   `attestLiveness`/`updatePrice`/`registerPublicKey` tx is signed in the TEE.
   Unattended-boot safe (no plaintext key, no tmpfs passphrase).

> Masking is display-only. Full values live in the node's config (readable by
> the operator on the box), never only-on-screen — the operator must be able to
> copy the keeper EOA to fund it.

## Cross-repo dependency (KMS side — must land first)

- KMS `/kms/sign` for secp256k1 reachable on the loopback `:3100` contract (like
  BLS `/sign`): `{keyId, digest}` → `{r,s,v}` (or `{signature}`). Confirm exact
  wire + whether it signs a raw 32-byte digest (needed for `signTransaction`).
- KMS `gen-keeper-key` provisioning (behind the same
  `KMS_BLS_PROVISIONING`-style gate) that returns the k1 address.

## Phases

1. **KMS**: expose secp256k1 `/kms/sign` (raw-digest) + `gen-keeper-key` on
   `:3100`.
2. **DVT**: `KmsEcdsaSigner` + `KEEPER_SIGNER_URL` seam in `BlockchainService`
   (fallback to `.env` when unset). Unit tests: byte-identical signature vs a
   local `ethers.Wallet` for the same key/digest.
3. **DVT**: provisioning docs + `dvt.env` wiring; real-board E2E (funded keeper
   EOA → attestLiveness tx signed via KMS).
4. Optional: extend to the operator wallet (`ETH_PRIVATE_KEY`) so registration
   also signs via KMS → **zero plaintext keys on the co-located board**.

## Payoff

A KMS-co-located DVT node holds **no plaintext secrets**: BLS via KMS-TEE, ECDSA
via KMS-TEE, both unattended-boot safe. Standalone nodes fall back to `.env`.
