# AOA-DVT-01 — erratum and per-interface permission matrix (2026-10-31)

> Appendix to [`aoa-dvt-01.md`](aoa-dvt-01.md). Answers the DSR erratum request
> on CC-129 (2026-10-30) and the CC-129 task in
> `AOA_Cross_Repo_Closure_2026-10-31.md` (DSR `389289c9`). No code change; no
> test re-run (T1/T2/T3 of the original delivery stay as historical evidence).
> No signing, no broadcast; DVT HOLD unchanged.

## 0. Corrections to the original delivery

| #   | Original text (`aoa-dvt-01.md`)                                                                                             | Correction                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| --- | --------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| E1  | "A 2-of-3 guardian quorum therefore can write `globalReputation`, `isBlocked` and `cachedPrice`."                           | Wrong as stated. Guardians cannot submit anything. Every write needs **a transaction from an authorised submitter AND a BLS proof**. Submitters differ per interface (§1): for `executeProposal` the only usable submitter is the owner EOA `0xb5600060…`; reputation writes have three active sources, one of which (`0x4Ec2D49D…`, ReputationSystem) forwards from **any** caller. Every one of those paths still needs the proof. The one exception is `SP.updatePriceDVT`: its owner path needs no proof at all. Per-interface rows in §1. |
| E2  | SP line references were given at `v5.5.0-rc.4` without saying it is not deployed.                                           | The Sepolia contracts are **BLSAggregator-4.11.0 / Registry-5.8.0 / SuperPaymaster-5.4.2**. Their source is SP `d23ab088` (deploy record `deployments/deploy-record-cc115-b3-sepolia.md`). `v5.5.0-rc.4` (`fbd74fb1`, identical to `origin/main` `d3af1ddc` for these files) is SP's **target pin**, which is not on chain. The AOA balance-mode `validatePaymasterUserOp` exists only at the target pin. §1 gives both line sets.                                                                                                             |
| E3  | "Registry owner can rotate aggregator (`setBLSAggregator`, immediate)" was listed as the recovery for a compromised quorum. | Correct, but it is also an **owner power**: on Registry-5.8.0 it replaces the verifier that blacklist/reputation proofs are checked against, with no delay. It is listed as an owner path in §1, not only as a recovery step.                                                                                                                                                                                                                                                                                                                  |

The rest of the original delivery stands. That includes the DVT-side findings:
DVT code signs only owner-authorised userOpHashes and locally recomputed slash
hashes; it never signs price, blacklist or reputation messages.

## 1. Per-interface matrix

`D` = deployed source SP `d23ab088`; `T` = target pin SP `fbd74fb1`
(`v5.5.0-rc.4`). Paths: `A` =
`contracts/src/modules/monitoring/BLSAggregator.sol`, `R` =
`contracts/src/core/Registry.sol`, `S` =
`contracts/src/paymasters/superpaymaster/v3/SuperPaymaster.sol`, `SA` =
`…/v3/SuperPaymasterAdmin.sol` (T only), `RS` =
`contracts/src/modules/reputation/ReputationSystem.sol`, `DV` =
`contracts/src/modules/monitoring/DVTValidator.sol`. Deployed values are
read-only `eth_call`s at block 12,030,989 (§5).

| Interface                                                                       | Who may submit                                                                                                                                                                                                                          | What proof is checked, and against what threshold                                                                                                                                                                                                                                                                                                                                                              | Owner direct path (no proof)                                                                                                                                                                 | Deployed config                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| ------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **`BLSAggregator.executeProposal`** (generic `target.call`)                     | `msg.sender == DVT_VALIDATOR \|\| == owner()`: D `A:1041`, T `A:1097`                                                                                                                                                                   | Always `_checkSignatures` over `keccak256(domainSeparator, TAG_PROPOSAL, proposalId, target, keccak256(callData), requiredThreshold)`, with `requiredThreshold ≥ minThreshold` (D `A:1077`, T `A:1128`; the call itself at D `A:1080`, T `A:1131`). Signer slots are rebuilt on-chain; each signer must hold `ROLE_DVT` with stake ≥ minStake (D `A:1186-1218`, T `A:1246-1274`). Slash selectors are refused. | **None.** The owner can submit but cannot skip `_checkSignatures`.                                                                                                                           | `minThreshold = 2`. 3 guardian slots. `DVT_VALIDATOR = 0x568b…` (DVTValidator-0.6.0), which cannot call `executeProposal`: its source has no such call (D `DV`, 0 occurrences) and its runtime has no `0x5e1a03a2` in any encoding, while the outbound selectors the source does call are present (`verifyAndExecute`, `queueSlashWithConsensus`, `hasRole`, …), and it has only 2 `CALL`s and no `DELEGATECALL` (`dvtvalidator-selectors.txt`). So **at the pin block the only usable `executeProposal` submitter is the owner `0xb5600060…`**, whatever the `isValidator` set is. The owner can change this with `setDVTValidator` (`onlyOwner`; D `A:1478`, T `A:1535`). |
| **`BLSAggregator.verifyAndExecute`** (reputation leg)                           | `DVT_VALIDATOR \|\| owner()`: D `A:933`. In turn `DVTValidator.executeWithProof` lets `isValidator` accounts in.                                                                                                                        | `_checkSignatures` over the reputation hash at `defaultThreshold`; then Registry checks again (next rows).                                                                                                                                                                                                                                                                                                     | None.                                                                                                                                                                                        | `defaultThreshold = 2`. `DVTValidator.isValidator` was read for **4 addresses only**, on one RPC: `0xb5600060… = true`, all 3 guardians `false`. The full set was not enumerated: `addValidator` emits no event (D `DV:136-151`).                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| **`Registry.updateOperatorBlacklist`** → `SP.updateBlockedStatus` → `isBlocked` | `msg.sender == blsAggregator` only: D `R:593`, T `R:631`. SP accepts only from Registry: D `S:613-614`.                                                                                                                                 | A **second**, independent proof: `_verifyBLS` over `(blsDomainSeparator, TAG_BLACKLIST, nonce, operator, users, statuses)` at the aggregator's `defaultThreshold`. D `R:488-495` / `R:603`, T `R:526-533` / `R:641`. Reached through `executeProposal`, so a blacklist write carries **two** quorum proofs from the same guardian set.                                                                         | **None directly.** Indirect: `Registry.setBLSAggregator` (`onlyOwner`, no delay; D `R:264`, T `R:288`) swaps the contract that does the verifying.                                           | `blsAggregator = 0xEaeC2F51…` (= `SP.BLS_AGGREGATOR`).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| **`Registry.batchUpdateGlobalReputation`** → `globalReputation`                 | `isReputationSource[msg.sender]`: D `R:504`, T `R:542`. One source, `0x4Ec2D49D…` (ReputationSystem), exposes `syncToRegistry` with **no caller check** (D/T `RS:178`, call at `RS:199`), so in effect anyone can submit, with a proof. | `_verifyBLS` at `defaultThreshold` over `(…TAG_REPUTATION, proposalId, users, newScores, epoch)` (D `R:523`, T `R:561`). Also checked: `creditPopulationSeededAt != 0` (D `R:519`), per-user `epoch > lastReputationEpoch` (D `R:532`), ±100 per-update clamp (D `R:538-539`), per-proposal aggregate uplift cap (D `R:560`).                                                                                  | **None directly** (a proof is required even from an owner-held source). Indirect: `setReputationSource` (`onlyOwner`, no delay; D `R:815`, T `R:853`) and `setBLSAggregator`.                | Active sources: **`0x4Ec2D49D…` (Reputation-0.3.2, a contract; `REGISTRY()` = this Registry; `syncToRegistry` selector present in its runtime), `0xb5600060…` (owner EOA), `0xEaeC2F51…` (aggregator, via `verifyAndExecute`)**. The old aggregator `0x174b60bB…` = false. `creditPopulationSeededAt = 1788104232` (path open).                                                                                                                                                                                                                                                                                                                                             |
| **`SP.updatePriceDVT`** → `cachedPrice`                                         | `msg.sender == BLS_AGGREGATOR \|\| == owner()`: D `S:648`, T `SA:433`                                                                                                                                                                   | **No proof is checked in SP.** The `proof` argument is ignored (T `SA:431`). From the aggregator it arrives only via `executeProposal` (≥ minThreshold). Checks either way: `updatedAt` strictly increasing, not older than 2 h, ≤ now + 15 s; `MIN/MAX_ETH_USD_PRICE`; ±20 % against Chainlink **only if Chainlink is < 2 h old** (D `S:684`, T `SA:453`).                                                    | **Yes. This is the only interface here that the SP owner can call directly with no quorum.** It takes effect immediately (unlike `emergencySetPrice`, which has a 1 h timelock, T `SA:376`). | `SP.owner = 0xb5600060…`. Chainlink was 3,060 s old at the pin block, so the ±20 % guard was **active**. `cachedPrice.updatedAt = 1790488836` (≈ 34 d old at the pin block).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |

Not "owner can bypass all quorums". The owner can:

- write price directly (`updatePriceDVT`);
- replace the verifier or the source list (`setBLSAggregator`,
  `setReputationSource`), which are indirect paths;
- lower thresholds to the floor of 2 (`setMinThreshold` / `setDefaultThreshold`;
  D `A:1487` / `A:1507`, T `A:1544` / `A:1564`);
- admit keys (`registerBLSPublicKey`, owner path, PoP mandatory; D `A:702-735`).

The owner **cannot**, with the deployed contracts, make `executeProposal`,
`updateOperatorBlacklist` or `batchUpdateGlobalReputation` succeed without a
valid BLS proof from the registered guardian set.

## 2. Three things stated separately

1. **Deployed guardian configuration (single operator).** 3 guardian slots
   (`0x5D870E13…`, `0x40F0b121…`, `0xD904A706…`, matching SP
   `deployments/config.sepolia.json` `blsGuardians`);
   `minThreshold = defaultThreshold = 2`;
   `permissionlessBLSRegistration = false`. Because permissionless registration
   is off, all three keys were admitted by the owner path. Aggregator, Registry,
   SP, DVTValidator and ReputationSystem all have the same owner, `0xb5600060…`.
   That EOA is the only usable `executeProposal` submitter and one of three
   active reputation sources (§1). That a single operator **holds** the three
   guardian BLS secrets is the operator's own declaration (trusted-operator
   phase). It is not something this readback proves.
2. **Protocol design (source defaults).** `MAX_VALIDATORS = 13`. Source defaults
   are `minThreshold = 3` and `defaultThreshold = 7` (D `A:203-205`, T
   `A:217-219`). **9-of-13** appears in SP only as an open BFT target for
   slashing (`docs/security/ISSUE-slash-mechanism-design.md:33,75`,
   "简单多数(7/13) 还是 BFT(≥9/13)"). It is not a source default and not
   deployed. Describe it as a design target, not a property.
3. **Committee validator HOLD.** `AAStarCommitteeValidator 0x7ac7E9d4…` (router
   algId 0x01, account authentication) is fail-closed under DSR v4. It is a
   different contract with a different signer set from the BLSAggregator
   guardians above, and the AOA paymaster path does not use it. HOLD is not
   lifted.

## 3. AOA validation path and DVT

At the target pin (T `S:226-343`, unchanged at `origin/main`),
`validatePaymasterUserOp` makes no call to BLSAggregator, DVTValidator, Registry
BLS functions or any DVT service. It reads SP storage that the rows above can
write: `cachedPrice` (`validUntil`, `S:248`) and `userOpState[…].isBlocked`
(`S:275-279`). `globalReputation` matters only when `creditPolicy = AUTO` (see
the original delivery, item 5). The deployed SP-5.4.2 has no AOA balance mode,
so for AOA this is a **source-level** statement about the target pin, not a
deployed one.

## 4. spec 03 `updatePriceDVT` omission — SP owns the fix

`docs/design/aoa-balance-mode/03-final-spec.md` still has **0** mentions of
`updatePriceDVT` at both `fbd74fb1` and `origin/main d3af1ddc`. Its trust table
lists the price writers as keeper `updatePrice` (§619), `setAPNTSPrice` and
`emergencySetPrice` (§611). The owner-immediate and aggregator paths of
`updatePriceDVT` are missing. The file is SP's, so the edit goes through an SP
PR. dvt does not edit it. Proposed text for the SP owner row (§611) and a new
row:

> SP owner: … `updatePriceDVT` (`SuperPaymasterAdmin.sol:425`, owner =
> break-glass, **immediate**, no BLS proof; bounded only by monotone/recent
> `updatedAt`, MIN/MAX price, and ±20 % vs Chainlink when Chainlink < 2 h).
>
> BLS aggregator (via `executeProposal`, owner-or-DVTValidator submitter + ≥
> `minThreshold` guardian proof): `updatePriceDVT` (same bounds);
> `Registry.updateOperatorBlacklist` (+ a second `defaultThreshold` proof) →
> `isBlocked`.

## 5. Evidence (block 12,030,989, hash `0xec49c475…93fb`)

Two independent providers, Alchemy and publicnode (credentials removed), read at
the same pinned block. The 20 `eth_call`s in `calls.txt` matched line for line
(`diff rpc1.txt rpc2.txt` → identical). In `impl.txt`, the ERC-1967
implementation/codehash, Chainlink and `isReputationSource` reads were taken on
both RPCs and agree; the DVTValidator `version()`/selector/`isValidator` lines
were taken on **one** RPC only. The rpc2 event-log scan did not finish (§6), and
rpc2 could not serve the `0x4Ec2…` codehash at this block
(`repsource-0x4ec2.txt`).

| File                                                    | Content                                                                                                                                                                                                       |
| ------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `aoa-dvt-01/erratum-2026-10-31/pin.txt`                 | block, hash, time, endpoint hosts                                                                                                                                                                             |
| `…/calls.txt`, `rpc1.txt`, `rpc2.txt`                   | versions, owners, `DVT_VALIDATOR`, thresholds, `blsAggregator`, `cachedPrice`, Chainlink feed                                                                                                                 |
| `…/codehash.txt`, `impl.txt`                            | runtime codehashes, ERC-1967 implementations (Registry → `0x9beD0F58…`, matching the deploy record; SP → `0xe25f88db…`), DVTValidator `version()` control, `isValidator`, `isReputationSource`, Chainlink age |
| `…/slots.txt`                                           | `validatorAtSlot(1..13)` on both RPCs (slots 4–13 are the zero address)                                                                                                                                       |
| `…/dvtvalidator-selectors.txt`, `outbound_selectors.py` | DVTValidator runtime selectors, including `SHL`-encoded outbound ones, with same-shape positive controls; opcode counts; runtime identical on both RPCs                                                       |
| `…/repsource-logs.txt`                                  | all `ReputationSourceUpdated` events, block 0 → pin (Alchemy)                                                                                                                                                 |
| `…/repsource-0x4ec2.txt`                                | `0x4Ec2…` `REGISTRY()`, `version()`, `owner()`, codehash, `syncToRegistry` selector check, both RPCs                                                                                                          |

Reproduce: `cast call <addr> '<sig>' --block 12030989 --rpc-url <rpc>` for each
line of `calls.txt`. Source:
`git -C SuperPaymaster show d23ab088:<path> | sed -n '<lines>p'`.

## 6. Limitations

- The deployed runtime bytecode was **not** rebuilt and compared with
  `d23ab088`. Source↔deployment correspondence rests on `version()` strings, the
  SP deploy record, and the Registry implementation address matching it. Exact
  codehash binding belongs to SP's M1.6 package.
- SP-5.4.2's implementation source commit was not pinned beyond "a commit
  carrying `SuperPaymaster-5.4.2`". `d23ab088` is used because it is the
  deploy-record source for the B3 generation. The original delivery cited
  `7cba99a9`, a later descendant of `d23ab088`: for `BLSAggregator.sol`,
  `SuperPaymaster.sol`, `ReputationSystem.sol` and `DVTValidator.sol` the two
  are byte-identical, and `Registry.sol` differs only in comments (+36/−3 from
  `d23ab088` to `7cba99a9` lines), so Registry line numbers differ between them;
  this file uses `d23ab088`.
- The publicnode log query over the full history did not finish within this
  session. Reputation-source **state** was read on both RPCs; event history is
  from Alchemy only.
- A plain hex search cannot find most of DVTValidator's outbound selectors: solc
  stores even selectors as a shifted constant plus `SHL` (`hasRole` 0x91d14854 =
  `0x24745215 << 226`). The earlier `version()` control was inbound and could
  not show this. The script decodes `PUSH4`, `PUSHn`+`PUSHm`+`SHL` and
  left-aligned `PUSH32`; the scan is linear, not control-flow analysis, and the
  source was not rebuilt. The decoded selectors are consistent with `d23ab088`
  but do not prove a byte match.
- `0x4Ec2…` was not bytecode-matched to `RS` source; the claim that
  `syncToRegistry` has no caller check is source-level (`version()` + selector
  presence only).
- `ROLE_DVT` grant/revoke authority in Registry, and GToken stake custody, were
  not expanded. They gate which slots can sign but do not change the rows above.
- Who custodies the guardian secrets: operator declaration (§2.1), not proven.
