# AOA-DVT-01 — DVT score source and credit-OFF boundary (evidence)

> Work order: AOA-DVT-01 (Seeder CC-129, from repo:dsr, 2026-10-26). Covers:
> M2.4 / M2.5 / M4.4 as named by the work order. dvt cannot read those milestone
> definitions; this report answers the work order's own deliverable list item by
> item (mapping asked of DSR in the ACK).
>
> Pinned code: `1991e921556cbb43ac5f1dc64de7b168c39002ef` (master, unchanged
> since 2026-09-05). All `file:line` below refer to that commit.
>
> Execution: no signing, no broadcast, no merge, no rebuild/redeploy. DVT is
> under DSR v4 HOLD (+ HOLD-R-AMS). Every on-chain read is an `eth_call`.

## 0. What was re-run this round

| Id  | What                                                                                                                                                                | Env                                              | Result                                                                                      | Raw output (SHA256)                                            |
| --- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------ | ------------------------------------------------------------------------------------------- | -------------------------------------------------------------- |
| T1  | jest: `src/modules/bls`, `src/modules/signature`, `audit/{slash-consensus,bls-consensus-domain,gossip-quorum-cosigner,guardian-fraud-proof,guardian-slash-watcher}` | [`env.txt`](aoa-dvt-01/env.txt) `b939e797…c98a9` | exit 0 — 10 suites, 129 tests passed                                                        | [`t1-jest.log`](aoa-dvt-01/t1-jest.log) `e9e5fbb8…d697b`       |
| T2  | forge: `contracts/test/AAStarCommitteeValidator.t.sol`                                                                                                              | same; forge 1.7.1                                | exit 0 — 55 passed, 0 failed                                                                | [`t2-forge.log`](aoa-dvt-01/t2-forge.log) `51edf63c…9937e`     |
| T3  | read-only `eth_call` on committee validator, pinned block                                                                                                           | Sepolia, block 12,003,735, 2026-10-27T07:50Z     | `requiredQuorum()` = `2^256-1` (unusable sentinel), `epochLength()`=64, `configVersion()`=5 | [`t3-onchain.txt`](aoa-dvt-01/t3-onchain.txt) `8c33e992…c9e10` |

Environment: macOS 26.4.1 arm64, node v24.21.0, jest 30.4.2, forge 1.7.1, run
2026-10-27 ~07:44Z, in a **clean detached worktree at 1991e92**
(`tracked_changes=0`). The main checkout had one unrelated uncommitted change
(`docker-compose.testnet.yml`, not under `src/` or `contracts/`); it was not
used. Contract deps were the repo's pinned submodules (account-abstraction
`cc3893bc`, forge-std `f9062359`, OpenZeppelin `45558b81`).

Reproduce:

```bash
git worktree add --detach /tmp/w 1991e92 && cd /tmp/w && npm ci
NODE_OPTIONS=--experimental-vm-modules npx jest src/modules/bls src/modules/signature \
  src/modules/audit/slash-consensus src/modules/audit/bls-consensus-domain \
  src/modules/audit/gossip-quorum-cosigner src/modules/audit/guardian-fraud-proof \
  src/modules/audit/guardian-slash-watcher; echo exit=$?
cd contracts && git submodule update --init && forge test --match-path test/AAStarCommitteeValidator.t.sol; echo exit=$?
cast call 0x7ac7E9d471742FA4397Beef0B5b11fbD22D196a9 'requiredQuorum()(uint256)' --rpc-url $SEPOLIA_RPC_URL --block 12003735
```

Source file hashes at 1991e92: `bls.service.ts` `9d9cb765…`,
`slash-consensus.ts` `1c4995bf…`, `gossip-quorum-cosigner.ts` `fabfb322…`,
`bls-consensus-domain.ts` `95911ed6…`, `audit.service.ts` `88efcd84…`,
`AAStarCommitteeValidator.sol` `dad6e371…` (full digests in the commit).

## 1. Items

### 1. Current score source — **不适用 (DVT is not a score producer)**

Baseline: CC-121 accepted conclusion, not re-argued. Evidence that no DVT code
path computes or emits a reputation/credit score:

- `getEffectiveStake`, `credibilityScore`: 0 occurrences in `src/`.
- `getDebt` / `getIsOverIssued` exist only as unused readers in
  `src/modules/blockchain/blockchain.service.ts` (zero callers).
- The only reputation-shaped code is a **hash builder**:
  `src/modules/audit/bls-consensus-domain.ts:35` (`TAG_REPUTATION`), `:89`
  `reputationMessageHash`, `:99` field list
  `[domainSeparator, TAG_REPUTATION, proposalId, repUsers, newScores, epoch]`.
  It has no caller that signs it; the only call site passes empty arrays:
  `src/modules/audit/audit.service.ts:1789-1790`
  (`[], // slash-only ⇒ no reputation users/scores`).

The score that AOA can read (`Registry.globalReputation`, AUTO credit only) is
written on the SP side — see item 2.

### 2. Updater / permissions — **缺证据 on the dvt side → handed to repo:sp**

dvt can name the SP-side writers but cannot sign them off. Read from SP source
at tag `v5.5.0-rc.4` (`fbd74fb1`), not tested by dvt:

- `Registry.batchUpdateGlobalReputation` requires `isReputationSource` + BLS
  proof (`Registry.sol:535-561`, write at `:592`); `setReputationSource` and
  `setBLSAggregator` are `onlyOwner` and take effect immediately (`:853`,
  `:288`).
- `Registry.updateOperatorBlacklist` requires `msg.sender == blsAggregator`
  (`:624-631`); AOA validate reads `isBlocked` (`SuperPaymaster.sol:275-279`).
- `SuperPaymasterAdmin.updatePriceDVT` (`:425-433`) — callable by the BLS
  aggregator or owner, overwrites `cachedPrice`; the ±20% band applies only when
  Chainlink is fresh. **Not mentioned in spec 03** — flagged to SP.

On-chain readback (block 12,003,696, `eth_call`): aggregator `0xEaeC2F51…2E5D` =
`SP.BLS_AGGREGATOR` = `Registry.blsAggregator`;
`Registry.isReputationSource(aggregator) = true`; aggregator
`minThreshold = defaultThreshold = 2`; `owner = 0xb5600060…`.

Consequence that dvt states but does not certify: the aggregator's
`executeProposal` performs a generic `.call` to any target, gated by a BLS
quorum of `requiredThreshold ≥ minThreshold = 2` guardians (deployed source
`7cba99a9:contracts/src/modules/monitoring/BLSAggregator.sol:1028-1075`). A
2-of-3 guardian quorum therefore can write `globalReputation`, `isBlocked` and
`cachedPrice`. All three guardian keys are currently held by one operator: this
is a **trust assumption of the early phase, not decentralisation**.

### 3. Input and output paths — **适用**

DVT signing entrypoints and what they will sign:

| Entrypoint               | Input                                    | Signed message                                                                                                                    | file:line                                                                                                          |
| ------------------------ | ---------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| `POST /signature/sign`   | full `PackedUserOperation` + `ownerAuth` | `userOpHash` derived by the node via `EntryPoint.getUserOpHash`, only after the account's `isValidOwnerAuth` returns `0xa0cf00cf` | `src/modules/bls/bls.service.ts:52` (gate), `:126-127`, `:140`; `src/modules/signature/signature.service.ts:45,78` |
| audit co-signer (gossip) | `CoSignRequest`                          | hash **recomputed locally**; caller's `messageHash` ignored; only `queue`/`execute` slash steps, any other step throws            | `src/modules/audit/gossip-quorum-cosigner.ts:158-164,196-203`; `src/modules/audit/slash-consensus.ts:174-202`      |

Output: BLS signature shares; aggregation via `/signature/aggregate` into
EIP-2537 form. No DVT code path builds a reputation, price, or blacklist message
(`updatePriceDVT`, `updateOperatorBlacklist`: 0 occurrences in `src/`; control:
`buildQueueMessageHash` is found by the same search).

### 4. Signing / aggregation mechanism — **适用**

As item 3. Tested by T1 (owner-auth gate fail-closed, local recompute,
unknown-step rejection) and T2 (committee validator quorum/epoch logic). The
deployed slash pipeline is off: compose maps no `AUDIT_*`/`KEEPER_*` variables,
so audit co-signing is not armed in the running nodes.

### 5. Which DVT paths AOA balance-mode traverses — **适用**

- **AOA validate/postOp calls no DVT contract and no DVT service.**
  (`SuperPaymaster.sol:226-343` validate, `:377-451` postOp, SP rc.4.)
- AOA **reads** values that a guardian BLS quorum can write (item 2):
  `isBlocked`, `cachedPrice`, and — only when `creditPolicy = AUTO` and the
  balance lock is insufficient — `globalReputation` via
  `GlobalTierSource.tierOf → Registry.getCreditLimit`.
- DVT slash (disabled in deployment) would reduce operator aPNTs, i.e. the
  funding AOA sponsors from.
- **RepCredit only:** `TAG_REPUTATION` message shape, CC-89 guardian-fraud proof
  recompute (`guardian-fraud-proof.ts:192-201`,
  `guardian-slash-watcher.core.ts:97`), committee validator `0x7ac7E9d4…`
  (router algId 0x01, account auth — not paymaster).

### 6. Credit-OFF residual credit/debt fields — **不适用 to dvt → handed to repo:sp**

DVT holds no credit or debt state. The identifying fields are on the SP/xPNTs
side (rc.4 source, not checked by dvt): `xPNTsV2Base.sol:112-120` (`debts`,
`creditReq`, `creditReservedOf`, `_creditRes`, `policyEpoch`, `pendingPolicy`);
`SuperPaymasterStorage.sol:92-95` (`pendingDebts`, retired);
`xPNTsTokenV2.sol:337-350` `effectiveCreditCap` returns 0 when OFF (`:339`).
Per-token `creditPolicy` readbacks and live debt balances are for SP to produce;
dvt does not sign PASS on them.

### 7. Impact of DVT failure / staleness / permission change on AOA — **适用**

| Event                                                                              | Effect on AOA                                                                                                                 | Recovery boundary                                                                                   |
| ---------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| DVT nodes down                                                                     | none on validate/postOp; no guardian quorum → `cachedPrice`/blacklist/reputation cannot be updated by DVT                     | price falls back to permissionless `updatePrice` (`SuperPaymasterAdmin.sol:477-494`); SP-side       |
| `cachedPrice` stale                                                                | `validUntil = updatedAt + priceStalenessThreshold` (`SuperPaymaster.sol:248`); sponsorship stops being valid after the window | SP: refresh via `updatePrice`. Observed `updatedAt` = 1790488836, 30.1 days old at block 12,003,696 |
| guardian quorum (2-of-3) compromised                                               | can blacklist operators, set price, write reputation                                                                          | Registry owner can rotate aggregator (`setBLSAggregator`, immediate); trust assumption, see item 2  |
| committee validator fail-closed (current, by design under HOLD since epoch 184283) | none on AOA (account-auth path, not paymaster)                                                                                | DSR v4: keeper on a dedicated EOA + two observed epochs before restore                              |

T3 re-read confirms the committee validator is still fail-closed today; that is
the known HOLD baseline, not a new failure.

## 2. Not verified / limitations

- M2.4 / M2.5 / M4.4 definitions not readable by dvt.
- SP-side line references were read from rc.4 source, not executed; the deployed
  aggregator's bytecode was not diffed against rc.4 source (source diff
  7cba99a9→rc.4 for `BLSAggregator.sol` is non-empty, +228/−143).
- No claim of full decentralisation or full security coverage.

## 3. Changes since last delivery

None in code. No affected tests.
