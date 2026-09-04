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

## Which driver for which stack

Two node stacks exist and they are registered on **different validators**.
Pointing a driver at the wrong one produces a bare `validate: 1`, which is why
each driver now checks registration first and says so by name.

| stack                        | how to start                                                  | ports     | registered on                           | driver              |
| ---------------------------- | ------------------------------------------------------------- | --------- | --------------------------------------- | ------------------- |
| always-on testnet (dvt1/2/3) | `docker compose -f docker-compose.testnet.yml … up -d`        | 3001-3003 | router-mounted **committee** validator  | `committee-e2e.mjs` |
| `.e2e/` test nodes           | `E2E_PORTS="3011 3012 3013" ./scripts/e2e/dvt-nodes.sh start` | 3011-3013 | `AAStarBLSAlgorithm` (legacy whole-set) | `realnode-e2e.mjs`  |

Both default to 3001-3003, and the testnet stack is the one serving
`dvt1/2/3.aastar.io` — so the `.e2e/` stack takes `E2E_PORTS` (and the driver
`DVT_NODE_PORTS`) instead, and the two run side by side. Verifying the legacy
path must never require taking the public nodes down.

```bash
E2E_PORTS="3011 3012 3013" ./scripts/e2e/dvt-nodes.sh start
DVT_NODE_PORTS=3011,3012,3013 E2E_ACCOUNT=0x… node scripts/e2e/realnode-e2e.mjs
E2E_PORTS="3011 3012 3013" ./scripts/e2e/dvt-nodes.sh stop
```

> Drivers address nodes as `127.0.0.1`, never `localhost`: on a dual-stack host
> `localhost` resolves to `::1` first, and any unrelated IPv6 listener on that
> port answers instead of the node. Override with `DVT_NODE_HOST`.

## Run the E2E

```bash
node scripts/e2e/realnode-e2e.mjs          # legacy whole-set path (.e2e/ stack)
# [1] 3-node aggregate off-chain verify: ✅ VALID
# [2] on-chain AAStarBLSAlgorithm.validate: 0 ✅ VALID
```

### Committee mode (`npm run e2e:committee`)

`committee-e2e.mjs` drives the running nodes through the **committee** path on
the validator the router actually mounts at algId `0x01`: real co-sign, real
aggregate, the frozen `setRoot[e-1]` replayed from chain logs, a Merkle proof
per signer, the sortition draw, and the on-chain pairing — plus four negative
controls (below quorum, tampered proof, wrong hash, foreign accountId), each of
which must be rejected.

```bash
npm run e2e:committee
# [9] ON-CHAIN committee validate()
#     ✅ validate() == 0 ACCEPTED
# [10] negative controls — each must be REJECTED  (4/4 rejected)
```

`validate()` also requires the account to have called `enroll()` — an
account-level opt-in, and a DIFFERENT thing from DVT node registration.
`0x92EA8b02…` was enrolled on 2026-09-01 (tx `0xf8a68767…`, via
`execute(validator, 0, enroll())` from its owner), so the default run uses **no
simulation at all**. For an account that has not enrolled, the driver supplies
that single bit through an `eth_call` state override instead of sending a
transaction, and step 8 first proves the gate is genuinely closed without it —
so such a run cannot pass merely because the override made everything true.
`npm run e2e:selftest` is the cheap smoke test (3 nodes sign + a bad `ownerAuth`
must 403).

node1/node2 BLS keys are already registered on-chain (BLS_TEST_1/2); node3 is
fresh (register its publicKey via SP `registerBLSPublicKey` before using it
on-chain).

> Cross-machine: URLs are `localhost`. For a consumer on another host, expose
> via a tunnel (ngrok/cloudflared) or run the service on a shared host; the
> endpoint contract is unchanged.
