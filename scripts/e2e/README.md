# DVT real-node E2E + node service

Boots **3 real v1.1.0 DVT signer node instances** and drives a real
combined-signature flow that verifies **on-chain** against the deployed
`AAStarBLSAlgorithm` — the same verifier airaccount-contract uses. Also serves
as the shareable DVT signer service for upstream/downstream (aastar-sdk #63
etc.). See `#42` and `docs/design/dvt-e2e-and-production.md`.

## Prereqs

- `.env.sepolia` at repo root with: `SEPOLIA_RPC_URL[,2,3]`,
  `ENTRY_POINT_ADDRESS`, `AIRACCOUNT_V020_BLS_ALGORITHM`,
  `BLS_TEST_NODE_ID_1/2`, `BLS_TEST_PRIVATE_KEY_1/2`, `PRIVATE_KEY_SUPPLIER` (=
  the test account's ECDSA `owner()`).
- `npm run build` (the manager runs it automatically if `dist/` is missing).

## One-click node service

```bash
./scripts/e2e/dvt-nodes.sh start    # build + gen keys (if needed) + boot 3 nodes (nohup, persistent)
./scripts/e2e/dvt-nodes.sh status   # which nodes are up
./scripts/e2e/dvt-nodes.sh info     # shareable: URL / nodeId / BLS publicKey (for #63 / SP registration)
./scripts/e2e/dvt-nodes.sh logs 1   # tail node 1 log
./scripts/e2e/dvt-nodes.sh stop     # stop all 3
```

Runtime state (keys, logs, pids) lives under `.e2e/` (git-ignored).

## Node endpoint contract (for #63 / consumers)

```
POST {url}/signature/sign
  body: { userOp: <PackedUserOperation v0.7>, ownerAuth: <owner EIP-191 sig over userOpHash> }
  → { nodeId, signature (EIP-2537 G2, 256B), signatureCompact, publicKey, message: userOpHash }
```

The node derives `userOpHash` itself via `EntryPoint.getUserOpHash`, enforces
the Stage-1 owner-auth gate (`ownerAuth` must be the account `owner()`'s
signature), then BLS-signs `hashToCurve(userOpHash)` (DST `_POP_`). Aggregate
the per-node `signature` (G2 point add).

## Run the E2E

```bash
node scripts/e2e/realnode-e2e.mjs
# [1] 3-node aggregate off-chain verify: ✅ VALID
# [2] on-chain AAStarBLSAlgorithm.validate: 0 ✅ VALID
```

node1/node2 BLS keys are already registered on-chain (BLS_TEST_1/2); node3 is
fresh (register its publicKey via SP `registerBLSPublicKey` before using it
on-chain).

> Cross-machine: URLs are `localhost`. For a consumer on another host, expose
> via a tunnel (ngrok/cloudflared) or run the service on a shared host; the
> endpoint contract is unchanged.
