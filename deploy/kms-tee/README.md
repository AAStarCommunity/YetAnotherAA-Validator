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

# 1. Get DVT v1.12.0 SOURCE onto the board, then build with DVT's own script (method ②).
#    v1.12.0 is the first tag bundling v1.11.0 signing + the CC-24 helpers + the CC-34 signer.
#    The A-board has NO git, so check out on a machine that does (your Mac) and rsync the
#    source — the board still builds DVT's UNMODIFIED code. Excludes preserve board state and
#    skip heavy/arch trees (build-bare-node re-installs node_modules fresh):
#      # on your Mac, in the DVT repo:
#      git fetch --tags && git checkout v1.12.0
#      rsync -a --delete \
#        --exclude .git --exclude node_modules --exclude dist --exclude contracts/lib \
#        --exclude node_state.json --exclude dvt.env --exclude 'dvt.log*' \
#        ./ root@<board>:/opt/dvt-build/
#    (Board WITH git instead: cd /opt/dvt-build && git fetch --tags && git checkout v1.12.0)
cd /opt/dvt-build && ./scripts/build-bare-node.sh               # npm ci + build → dist/main.js

# 2. Swap the OLD (v1.7.1 encrypted-keystore) node_state for a key-less one from KMS's pubkey.
rm -f /opt/dvt-build/node_state.json                            # drop the old keystore state
node scripts/write-keyless-node-state.mjs "$KMS_BLS_PUBKEY"     # → node_state.json (no privateKey)

# 3. config: DVT-owned dvt.env. ⚠️ PRESERVE the board's existing ETH_RPC_URL (don't clobber the
#    working RPC key) — only update VALIDATOR to 0x539B96 and add PORT/entrypoint if missing.
#    (Signer wiring RUST_SIGNER_* comes from the KMS handoff via dvt.service, not this file.)
#      sed -i 's|^VALIDATOR_CONTRACT_ADDRESS=.*|VALIDATOR_CONTRACT_ADDRESS=0x539B9681aFd5BFbCaa655Fe4c6BdcFe1fa7864bC|' /opt/dvt-build/dvt.env
#    or start from the template and re-add ETH_RPC_URL:
#      cp deploy/kms-tee/dvt.env.example /opt/dvt-build/dvt.env && $EDITOR /opt/dvt-build/dvt.env

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
