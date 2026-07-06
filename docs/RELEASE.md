# Release flow — DVT validator + SuperPaymaster + SDK sync

The DVT validator (this repo) reads stake from SuperPaymaster and is consumed by
the SDK. A release therefore spans three repos. This is the settled flow.

## Roles

- **SuperPaymaster** (`AAStarCommunity/SuperPaymaster`) — economic layer:
  Registry / GTokenStaking / GToken / DVTValidator. Deployed once per network;
  the DVT validator only READS it (`hasRole`, `getEffectiveStake`). Rarely
  re-released.
- **YetAnotherAA-Validator** (this repo) — the `AAStarValidator` (Plan A v3):
  pubkey registry + aggregate BLS verify + stake-gated `registerWithProof`.
  Re-deployed on a contract change.
- **aastar-sdk** — consumes the validator ABI + address (aggregation wire,
  nodeIds).

## 1. Contract change → test

```bash
cd contracts && forge test          # unit + stake-binding + local E2E (Path A)
```

## 2. Deploy the validator (needs the SuperPaymaster addresses for the target network)

```bash
# SP addresses live in SuperPaymaster/deployments/config.<network>.json (registry, gToken,
# staking). The script defaults to the Sepolia registry; override via SP_REGISTRY.
cd contracts
SP_REGISTRY=0x… MIN_STAKE=30000000000000000000 \
  forge script script/DeployStakeBoundValidator.s.sol --rpc-url <RPC> --private-key <KEY> --broadcast
# → prints the deployed validator address. Keys: SuperPaymaster/.env.sepolia (Jason/Anni).
```

Leave `requireStake=false` (bootstrap) until nodes have re-registered via
`registerWithProof`; then `cast send <validator> "setRequireStake(bool)" true`.

## 3. Wire nodes (per operator) — stake → PoP register

```bash
# stake (operator, on SuperPaymaster): approve + registerRole(ROLE_DVT, 30 GToken)
cast send <GToken> "approve(address,uint256)" <staking> 33000000000000000000 --private-key <op>
cast send <registry> "registerRole(bytes32,address,bytes)" \
  0x3b5016dc6721b132ddcb7027030b137a739df81e419695dae0899a866c1c514d <op> \
  $(cast abi-encode "x(uint256)" 30000000000000000000) --private-key <op>

# PoP + register (on the validator)
node deploy/onboarding/onboard.mjs pop <operatorAddress>   # emits registerWithProof params
cast send <validator> "registerWithProof(bytes,bytes,bytes)" <pubkey> <popPoint> <popSig> --private-key <op>
```

Verified end-to-end on Sepolia (validator
`0xaAc436f262F6beeC4dd02008DA8ED20AD69E4cC2`):
`validateAggregateSignature([nodeId], coSig, messagePoint) == true`.

## 4. Sync the SDK (ABI + address)

```bash
VALIDATOR=<deployed> NETWORK=<network> ./scripts/sync-validator-abi.sh ../aastar-sdk
#   → writes deployments/AAStarValidator.abi.json + validator.<network>.json,
#     and copies them into the SDK's abi/ + deployments/. Then in the SDK:
#     commit, bump the version, and update any hardcoded nodeId config (nodeId is now
#     keccak256(pubkey) — see aastar-sdk#270).
```

## 5. Release notes

- Version-bump this repo (`npm run release:patch|minor|major`), tag, GitHub
  release.
- **Version naming (CC-14 convention):** in all human-readable outward text —
  release notes, PR titles, issue/board comments — write the product name in
  full: **`YetAnotherAA-Validator (DVT) vX.Y.Z`**. Never bare-report a number
  (`v1.9`) that could be confused with `@aastar/sdk 0.37.x` /
  `airaccount-contract v0.27.0` / `SuperPaymaster v5.4.x` /
  `AirAccount KMS openapi 0.27.x`. When reporting a cross-repo sync, name both
  sides. Keep the `package.json`/git-tag version a clean semver (no product name
  — it breaks npm/CI).
- If the ABI/address changed, land the SDK PR (step 4) referencing this release.
- Cross-link: SuperPaymaster #321 (stake source), aastar-sdk #270 (SDK impact),
  #163.

## Notes

- Stake is managed ONLY in SuperPaymaster — never redeploy
  GToken/registry/staking for a DVT-validator change; just re-point
  `SP_REGISTRY`.
- Governance: transfer the validator `owner` to a Gnosis Safe multisig after
  deploy (`transferOwnership`).
