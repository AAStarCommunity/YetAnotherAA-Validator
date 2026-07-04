# Self-onboarding tool

A guided helper for a community operator standing up an independent DVT node. It
automates the parts that CAN be self-served and checks the path is clear. Full
context: [`../COMMUNITY_OPERATORS.md`](../COMMUNITY_OPERATORS.md).

```bash
# 1. make your own key
node deploy/onboarding/onboard.mjs keygen

# 2. get the request to send AAStar (on-chain register is owner-coordinated today)
node deploy/onboarding/onboard.mjs register-request
#    …then, with an RPC + the validator address, wait until you're registered:
ETH_RPC_URL=… VALIDATOR_CONTRACT_ADDRESS=… node deploy/onboarding/onboard.mjs wait-register

# 3–5. deploy (see ../imx93 or docker-compose.mainnet.yml) + set PUBLIC_URL / GOSSIP_* envs,
#      then check the path end-to-end against your public URL:
node deploy/onboarding/onboard.mjs verify https://dvt.your-community.org
```

`verify` checks: `/health` (+ version), `/node/info` (identity), `/gossip/peers`
(you're on the mesh — needs `GOSSIP_BOOTSTRAP_PEERS` pointed at a live seed),
and that the owner-auth gate is fail-closed (403). All green → run the full
co-sign E2E with the other operators (`scripts/e2e/realnode-e2e.mjs`).

## The one step that isn't self-service yet

On-chain registration (`registerPublicKey`) is **`onlyOwner`** on the deployed
validator, so step 2 is owner-coordinated: the tool emits your
`{nodeId, publicKey}` and polls `isRegistered` until AAStar registers you. When
the **permissionless PNT-staking** path is implemented on the validator (the
`registerPublicKey` staking-gate TODO), a `stake` subcommand will make step 2
fully self-service — and AAStar's owner-assisted path stays for operators who
don't want to stake. Both paths tracked in #157.

`NODE_STATE_FILE` overrides the key path (default
`deploy/node1/node_state.json`).
