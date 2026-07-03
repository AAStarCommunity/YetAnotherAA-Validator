# BLS key at rest — EIP-2335 encrypted keystore (#5 / #50 ④)

By default `node_state.json` stores the BLS private key in **plaintext**
(git-ignored, but readable by anyone with the file). On a physical board
(i.MX93) that can be stolen or backed up, that's a real at-rest risk. #5 lets
you store the key **encrypted** in the same file using the EIP-2335 keystore
format (the format Ethereum validators use, same BLS12-381 curve), decrypted at
boot with a passphrase supplied from **outside** the disk.

**Boundary:** this protects the key AT REST only. It does not defend a
compromised running process (the key is decrypted in memory to sign) or someone
who has the passphrase. For hardware-bound keys you'd need an HSM / the board's
EdgeLock (future).

## Migrate an existing node (plaintext → encrypted)

```bash
npm run build   # the migration script imports the compiled keystore util
NODE_KEY_PASSPHRASE='your-strong-passphrase' node scripts/encrypt-node-key.mjs deploy/node1/node_state.json
# KDF=pbkdf2 for a lighter derivation on tiny boards; default scrypt is stronger (~256MB).
```

This replaces the plaintext `privateKey` with an encrypted `keystore` field and
writes a `node_state.json.bak` (STILL plaintext). Verify the node boots with the
passphrase, then **securely delete the `.bak`**.

## Run with the passphrase

Supply `NODE_KEY_PASSPHRASE` from **outside the machine's disk** — never store
it next to the keystore:

- **systemd**: a `LoadCredential=` / `systemd-creds` credential (sealed to the
  TPM/EdgeLock if available) → the node auto-restarts unattended AND the key
  stays encrypted at rest.
- **env var** injected at boot by your orchestrator.
- **typed by a human** at boot — most secure at rest, but the node can't
  self-restart unattended (a 3am crash stays down until someone types it).
  Trade-off per node.

At boot the node logs `BLS key loaded from encrypted keystore (EIP-2335)`.
Fail-closed: an encrypted keystore with **no** passphrase, or a **wrong** one,
aborts startup — the node never runs with an unusable/blank key.

## Notes

- Plaintext `privateKey` is still accepted (dev / existing nodes) — encryption
  is opt-in per node by running the migration. `saveNodeState` never writes the
  decrypted key back to disk when a keystore is present.
- scrypt (default) uses ~256 MB during derivation; on a 2 GB board prefer
  `KDF=pbkdf2` if that spike contends with the node + signer.
