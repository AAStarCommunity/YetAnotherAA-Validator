# KMS-TEE key-less co-located DVT (A-board "power-on → unattended KMS+DVT1")

DVT-side deliverable for CC-24. The board is KMS-controlled; the KMS
`node-setup` runs this recipe (method ②: it calls DVT's scripts, never edits DVT
code). This directory is the DVT half — the two "helpers" KMS is waiting on:

| Helper                      | File                                                                                 | Role                                                                  |
| --------------------------- | ------------------------------------------------------------------------------------ | --------------------------------------------------------------------- |
| key-less node_state writer  | [`scripts/write-keyless-node-state.mjs`](../../scripts/write-keyless-node-state.mjs) | KMS `gen-key` 48B G1 pubkey → `{nodeId, publicKey}`, no privateKey    |
| key-less systemd unit + env | [`dvt.service`](./dvt.service) + [`dvt.env.example`](./dvt.env.example)              | no tmpfs passphrase; `After=kms-api.service`; sources the KMS handoff |

## Why key-less (the whole point)

The board today runs an **isolated encrypted keystore** whose passphrase lives
in `/run/dvt/pass` (tmpfs) — wiped on every power cut, so DVT can't self-start
unattended. KMS-TEE custody removes the passphrase entirely: the BLS key is
sealed in the KMS OP-TEE, DVT boots key-less and signs via `RUST_SIGNER_URL`
(KMS `:3100`). Power-on → KMS unseals its own TEE key → DVT starts key-less →
signs.

## The recipe (what KMS node-setup runs on the board)

```bash
# KMS self-init has written /etc/airaccount/dvt-handoff.env:
#   RUST_SIGNER_URL / RUST_SIGNER_REQUIRED / RUST_SIGNER_TOKEN  +  KMS_BLS_PUBKEY
. /etc/airaccount/dvt-handoff.env

# 1. DVT v1.9.0/v1.7.1 → v1.12.0, bare-node build (pure JS, board-proven)
#    v1.12.0 is the first tag that bundles v1.11.0's signing + the CC-24 helpers
#    (write-keyless-node-state.mjs, this dir) + the CC-34 KmsEcdsaSigner.
cd /opt/dvt-build && git fetch --tags && git checkout v1.12.0 && ./scripts/build-bare-node.sh

# 2. key-less node_state from KMS's pubkey (DVT derives the nodeId — don't re-implement it)
node scripts/write-keyless-node-state.mjs "$KMS_BLS_PUBKEY"      # → /opt/dvt-build/node_state.json

# 3. config: DVT-owned dvt.env (non-secret) + KMS-owned handoff (signer wiring, already on disk)
cp deploy/kms-tee/dvt.env.example /opt/dvt-build/dvt.env         # edit only if PORT/validator differ

# 4. key-less unit: no /run/dvt/pass, ordered after KMS, enabled for boot
cp deploy/kms-tee/dvt.service /etc/systemd/system/dvt.service
systemctl daemon-reload && systemctl enable --now dvt.service
```

## Acceptance (local first, on-chain separate)

Cold-boot → `kms-api` up → `dvt` key-less up (waits quietly if KMS not ready
yet) → both `/health` green → `/sign` byte-aligned (CC-22 converged). On-chain
`registerBLSPublicKey` is **separately gated** on the operator key/gas — not
required for power-on self-run.

## Reversible

Unset the handoff (or `RUST_SIGNER_URL`) → DVT falls back to local-keystore
mode. Switch can't brick.
