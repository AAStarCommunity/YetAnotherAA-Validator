# DVT cross-repo interface contracts

Hard dependencies this repo has on **other repos' on-chain / config
interfaces**. Each entry is the thing that breaks us if the other side changes
it silently. Where an invariant can be machine-checked, it is locked by a unit
test so a drift fails CI instead of failing in production.

> **When syncing DVT** (bumping a dependency, or after an upstream release):
> re-check every entry below. When **airaccount / SDK** change one of these,
> they should flag it here (or on the Seeder coordination board) so we sync
> deliberately.

---

## 1. Account owner-auth gate — depends on `airaccount-contract`

**What we call:** the DVT owner-gate (`bls.service.ts:authorizeAndDeriveHash` →
`blockchain.service.ts:isValidOwnerAuth`) eth_calls the ACCOUNT
(`userOp.sender`):

```solidity
function isValidOwnerAuth(bytes32 userOpHash, bytes calldata ownerAuth) view returns (bytes4)
```

- **Success magic:** `0xa0cf00cf` — this is
  `selector(isValidOwnerAuth(bytes32,bytes))`, used as the return magic exactly
  like ERC-1271's `0x1626ba7e = selector(isValidSignature(bytes32,bytes))`. It
  is **NOT** standard ERC-1271.
- **Why delegate:** the account contract is the single source of truth for
  owner-auth (k1 ECDSA / P256 passkey / future schemes). DVT never verifies
  locally → never drifts, and supports passkey accounts whose `owner() == 0x0`.
- **Implemented by:** airaccount-contract `AAStarAirAccountV7` (behind its
  ValidatorRouter). An account that only implements standard ERC-1271 (e.g. an
  old test account) fails the gate closed — that is correct behavior, not a bug.

**Source of truth:** airaccount-contract. **DVT hardcodes** the selector + ABI
string (`OWNER_AUTH_FN` / `OWNER_AUTH_MAGIC` / `OWNER_AUTH_ABI` in
`blockchain.service.ts`).

**Auto-check (DVT half):** `blockchain.service.spec.ts` asserts
`selector(OWNER_AUTH_FN) === OWNER_AUTH_MAGIC` and that the ABI fragment's
selector matches — so changing the function name/params without updating the
magic (or vice versa) fails CI.

**Auto-check (airaccount half — coordination):** DVT cannot see airaccount's
source at build time, so **airaccount must flag any change to this signature**
(here or on the board). If they publish a machine-readable interface/selector,
DVT CI can cross-check it; until then this is a coordinated dependency, not a
fully automated one.

---

## 2. Validator contract + network config — DVT-owned

**File:**
[`deploy/sdk-dvt-config.testnet.json`](../deploy/sdk-dvt-config.testnet.json) —
the single authoritative source for the validator address + DVT node discovery
per network. The aNode reads `validator` as `VALIDATOR_CONTRACT_ADDRESS`; the
SDK reads the whole file (SDK is a **consumer**, not a source — sync tracked in
aastar-sdk#274).

| Field                            | Source of truth                                       | Notes                                              |
| -------------------------------- | ----------------------------------------------------- | -------------------------------------------------- |
| `validator`                      | **DVT** (this repo's `contracts/AAStarValidator.sol`) | current Sepolia `0x539B…`                          |
| `dvtNodes[]` (nodeId/pubkey/url) | **DVT** (each node's live `GET /node/info`)           | nodeId = keccak256(EIP-2537 pubkey)                |
| `entryPoint`                     | ERC-4337 canonical (fixed)                            | `0x0000000071727De22E5E9d8BAf0edAc6f37da032`       |
| `e2e_account`                    | **airaccount-contract**                               | an account implementing §1 (`0xa0cf00cf`)          |
| router mount                     | **airaccount-contract**                               | `AAStarAirAccount` ValidatorRouter (`0xe68d6A7B…`) |

**Add a network (e.g. mainnet):** fill `environments.mainnet` with the same
shape (DVT fills its own `validator` + `dvtNodes` from its mainnet deploy;
airaccount supplies `e2e_account`), then set `active: "mainnet"`. No code change
— testnet→mainnet is a config swap.

**Staying fresh:** the DVT-owned fields (`validator`, `dvtNodes`) are the ones
that went stale before — they can be re-synced from the live nodes'
`/node/info` + the deploy artifact rather than by hand.
