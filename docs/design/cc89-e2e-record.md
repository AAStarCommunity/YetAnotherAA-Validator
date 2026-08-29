# CC-89 — over-issue guardian-collusion slash: testnet E2E record (for RepCredit paper)

> **Frozen historical record — not CC-115 route-B evidence.** It predates the SP
> 4.11 domain-bound verifier and queue/exit-freeze lifecycle. Preserve its
> receipts for audit, but do not use it to support the RepCredit v16 successor
> deployment, exact-set, exit-freeze, or production-security claims. Route B
> requires a new reviewed successor deployment and evidence generation.

> Authoritative record of the CC-89 stage-2 mechanism and its **end-to-end
> Sepolia run**, for the RepCredit paper (IET Blockchain). Everything below is
> on-chain-verifiable. Companion: `guardian-collusion-slash.md` (threat model +
> A' spec), `cc89-e2e-runbook.md` (chain + convention),
> `cc89-stage2-shipping-plan.md` (delivery). Coordination thread: Seeder CC-89.

## 1. The gap the paper identified (confirmed)

BLSAggregator's `verifyAndExecute` verifies `m` guardian signatures and binds an
`evidenceHash`, but **never re-checks the evidence content**. So `≥ m` colluding
DVT guardians can pass a _valid_ slash of an innocent operator at zero cost. The
paper's anti-collusion deterrent `k·C_max < m·ρ·S_op·p_G` has **no on-chain
counterpart for `ρ·S_op`**: the executed slash burns the operator's `aPNTs`, not
the colluding guardians' `ROLE_DVT` GToken stake (asset distinction, not party —
addresses may overlap). Two corrections the paper must carry: **(a)** for the
slash path `m = slashThresholds[level]` (bootstrap WARNING/MINOR/MAJOR = 2/3/3),
**not** `defaultThreshold=7`; **(b)** the gap is "different **asset**" (aPNTs ≠
ROLE_DVT lock), not "different party".

## 2. The mechanism (built + deployed)

Two halves ship together (SP = SuperPaymaster, DVT = this repo):

- **SP `executeGuardianSlash`** (BLSAggregator, permissionless +
  verifier-gated): a fraud proof's _validity_ (not the caller) authorizes
  slashing the guilty guardians' ROLE_DVT lock **in full → 0 < minStake →
  `_reconstructPkAgg` auto-ejects** them from the signer set. Breaks the
  "colluding quorum won't slash itself" circular dependency.
- **SP A' commitment** (`proposalSignersCommitment[proposalId]`):
  `verifyAndExecute` stores a `bytes32` fingerprint of the fraud-time signer
  ADDRESS set (irreversible), so a later fraud proof can attribute the slash to
  real addresses.
- **DVT `OverIssueFraudProofVerifier`** (`IFraudProofVerifier.verify` view,
  fail-closed): 5 checks — fraudProofId content-binding; canonical
  claimedSigners; reconstruct `evidenceHash → messageHash → commitment` (binds
  the disputed token, blocking a token-swap forgery);
  `guiltyGuardians ⊆ claimedSigners` (never slash an innocent address);
  `isOverIssued(token) == false` (the slash was a lie).
- **DVT watcher + assembler** (off-chain data-availability): capture
  `claimedSigners` at the execution block (`validatorAtSlot`, uint160-sorted,
  byte-identical to SP's commitment) → build the `fraudProof`.
  Multi-node-redundant (commitment is irreversible → a set no node records is
  permanently un-attributable).

Cross-repo evidence convention (frozen):
`evidenceHash = keccak256(abi.encode( "DVT_OVERISSUE_EVIDENCE_V1", disputedToken, operator, epoch))`,
pure slash (`repUsers` & `newScores` empty). The verifier couples `operator`
between the messageHash field and the evidence op — for a no-real-victim demo,
`operator = op = address(0)`.

## 3. The end-to-end Sepolia run — PASSED ✅

**On-chain material (Sepolia, chainId 11155111):**

| Contract                                           | Address                                      |
| -------------------------------------------------- | -------------------------------------------- |
| BLSAggregator 4.3.0 (A' commitment), owner = jason | `0xf44E7E51EFFa867114BE48fA92411fE216b1A285` |
| OverIssueFraudProofVerifier (bound to aggregator)  | `0xd7111fcC31B52dC451f2B7400Cd75B434E2b1abd` |
| GTokenStaking                                      | `0x472297B557c1d0F030f281a5Bb8A535f6c5AB65e` |
| MockOverIssuableToken (`isOverIssued()==false`)    | `0x8dE1b6585Bdf5a3e6F13B3125B2d40CC34fc005b` |

> **⚠️ These are the E2E throwaway deployment addresses — NOT production.** The
> aggregator `0xf44E7E51…` above was a single-run fixture (its 3 guardians are
> now slashed to 0 and ejected). The **production** Sepolia SuperPaymaster
> BLSAggregator (A' 4.3.0) is **`0x174b60bB462b00550F0EC7Bc35Fe39dDB6310158`**
> (the config default; see `src/config/configuration.ts`
> `auditBlsAggregatorAddress`), with production verifier `0x128847cF…` and 3
> persistent guardians (CC-89 comment `b26903ec`). Guardian nodes must set
> `AUDIT_BLS_AGGREGATOR_ADDRESS` to the **production** aggregator; do not copy
> the E2E address from this record.

3 guardians registered at slots 1/2/3, each with **30e18 ROLE_DVT** locked
(`ROLE_DVT = keccak256("DVT")`): `0xb5600060…` (slot1), `0x6F7D30f2…F96E`
(slot2), `0x09a0ca08…5c93` (slot3).

**The chain, step by step (each independently on-chain-verified):**

1. **Craft the fraudulent slash.** DVT's 3 guardian keys co-sign SP's slash
   `expectedMessageHash` (`cc89-cosign.mjs`, 3-of-3 BLS aggregate,
   `signerMask=0x7`). Pre-verified on-chain:
   `aggregator.verify(messageHash, 0x7, 3, sigG2) == true`. Bundle:
   `proposalId=8900001`, `operator=op=0`, `slashLevel=1` (MINOR, threshold 3),
   `epoch=1`, `evidenceHash=0x4538e11c…da6407`, `messageHash=0x8285eeb4…af8c`.
2. **SP submits**
   `verifyAndExecute(8900001, 0, 1, [], [], 1, evidenceHash, proof)` →
   `proposalSignersCommitment(8900001) = 0x8904b1b9…4f34` (A' snapshot stored).
3. **DVT watcher** resolves `claimedSigners` at the execution block =
   `[0x09a0ca08…, 0x6F7D30f2…, 0xb5600060…]` (uint160-ascending, reproduces the
   commitment).
4. **DVT assembler** builds the `fraudProof`; on-chain preflight
   `verifier.verify(fraudProofId, guilty, fraudProof) == true`.
5. **executeGuardianSlash** (tx
   **`0xb870688e6c156e4e7f97cbad390e72e5900fc3384da0809d042fa023307991ba`**,
   status 1, gas 331215): guilty = all 3 guardians.
6. **Result:** the 3 guardians' ROLE_DVT lock **30e18 → 0**; a fresh
   `verify(mask=0x7)` now **reverts** (`SlotValidatorStakeBelowMinimum`) —
   **auto-eject confirmed**.

**Closed loop demonstrated:** accuse a not-over-issued token → 3 guardians
collude to pass the slash → fraud proof catches it → their stake is slashed in
full → they are ejected from the signer set.

## 4. Conclusions for the paper

- **`ρ`'s detection half is now "implemented + testnet-E2E-verified"**, no
  longer a bare modeling parameter — cite this Sepolia run for the
  **on-chain-objective, over-issue class**.
- **Coverage is bounded** (state honestly): `ρ` is a system property only for
  on-chain-objective violations. **Liveness** class is gated on CC-29
  (LivenessRegistry — no on-chain liveness signal yet); **purely off-chain
  evidence** stays a governance assumption.
- **Historical-state caveat:** the E2E used the _current-state_ `isOverIssued()`
  variant (state held constant slash→proof). Trustless historical-state
  (BLOCKHASH + EIP-1186 storage proof over the epoch block, ~256-block challenge
  window) is Phase-3 production hardening — so `ρ` for over-issue is a system
  property **only within a bounded challenge window**, not indefinitely.
- Keep corrections from §1: `m = slashThresholds[level]`; gap = "different
  asset".

## 5. Reproducibility

Tooling (this repo): `scripts/cc89-cosign.mjs` (3-key aggregate + on-chain
self-verify), `scripts/cc89-e2e-finish.mjs` (resident auto-finisher: watch
commitment → fraudProof → executeGuardianSlash → verify locks→0 + auto-eject),
`contracts/script/DeployOverIssueVerifier.s.sol` (verifier deploy with identity
guards), `contracts/src/mocks/MockOverIssuableToken.sol`. Verifier +
watcher-core + assembler unit/Foundry tests are in the merged PRs
(#221/#223/#224/#225/#226/#227/#229) with a TS↔Solidity golden vector pinning
byte-alignment. Re-running requires re-staking the 3 guardians (their ROLE_DVT
lock is now 0 from this run).
