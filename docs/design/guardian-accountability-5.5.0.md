# Guardian accountability for SuperPaymaster 5.5.0 — M0 design

> **Status: DESIGN (M0), for DSR review before any build.** No contract or
> service in this document exists yet. Nothing here sends a transaction. Owner
> rulings are quoted with their date; everything else is a proposal and says so.

## 0. Decisions this design is built on

| #   | Decision                                                                                                                                                                               | Source                      |
| --- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------- |
| D1  | No on-chain automatic slashing at this stage, of operators **or** guardians. Accountability is public disclosure; the misbehaving party bears a reputation cost.                       | Author, 2026-11-09 (direct) |
| D2  | Disclosure goes to the DVT repo (evidence record), Telegram, and an on-chain record.                                                                                                   | Author, 2026-11-09          |
| D3  | The on-chain record is written by the watcher only.                                                                                                                                    | Author, 2026-11-09          |
| D4  | No reputation **scoring** in `ReputationSystem` (it needs multisig rules); the record lives in the disclosure registry.                                                                | Author, 2026-11-09          |
| D5  | Keep `pauseUnderstakedOperator` (SP 5.5.1) as a watcher duty.                                                                                                                          | Author, 2026-11-09          |
| D6  | N=3 is the bootstrap size, not a system property. Target: one guardian per community, a dozen or more. Heavier penalties require more signatures. No penalty without a verified proof. | Author, 2026-11-09          |
| D7  | Random committee selection: prepare design and interface now; not enabled in 5.5.0.                                                                                                    | Author, 2026-11-09          |
| D8  | Raw evidence goes on-chain; DVTValidator accepts only an immutable category allowlist; unknown categories revert.                                                                      | DSR, 2026-11-09             |
| D9  | Manifest gate asserts `fraudProofVerifier == address(0)`; A12b is not applied.                                                                                                         | DSR, 2026-11-09             |

Prior decision still in force: over-issue (rule ③) and credit (rule ①) are not
slash rules (2026-07-09, PR #205). Honest DVT nodes co-sign no slash today: the
co-sign responder is unarmed (`src/modules/audit/audit.service.ts:42-46, :455`).

## 1. What we are protecting against

| Actor                                                               | Risk                                                                                                                                              | 5.5.0 handling                                                                                                                                    |
| ------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| Community / operator                                                | Over-issues xPNTs                                                                                                                                 | Unchanged: on-chain views `isOverIssued()` / `credibilityScore()`; DVT does nothing.                                                              |
| **Guardians** (the BLS signer set)                                  | A quorum signs an action it should not: a false slash, a false reputation batch, or a generic proposal (e.g. `Registry.updateOperatorBlacklist`). | **This document.** Operator slash impossible by construction (empty allowlist, §3); every BLS-executed action is detected and disclosed (§4, §5). |
| Operator already slashed below `minStake` by Registry/GTokenStaking | Keeps operating                                                                                                                                   | Watcher calls `pauseUnderstakedOperator(op)` (§5.4).                                                                                              |

Every guardian power goes through `BLSAggregator.verifyAndExecute`,
`queueSlashWithConsensus` or `executeProposal`, and all three accept only
`DVT_VALIDATOR` or `owner()` as caller (SuperPaymaster `origin/main` afe405fa,
`BLSAggregator.sol` around :959, :980, :1089). So the watcher's surface is
exactly: the events of those three entry points.

## 2. Measured facts (2026-11-09, read-only)

- EIP-2935 history contract `0x0000F90827F1C53a10cb7A02335B175320002935` is
  deployed on OP Mainnet (chain 10) and OP Sepolia (chain 11155420): 83 bytes,
  code keccak
  `0x6e49e66782037c0555897870e29fa5e552daf4719552131a0abce779daec0a5d` on both,
  read from two independent RPCs each. Calling it for
  `head-1, -100, -8000, -8191` returned the canonical block hash; `head-8192`
  reverted. The window is exactly 8191 blocks (~4.55 h at 2 s). SP read the same
  code on Sepolia L1. Script: `scripts/` copy to be added with M1.
- Current OP block headers carry 21 fields (through `requestsHash`). Any header
  parser must read fields by position and accept trailing fields.
- `BLSAggregator.MAX_VALIDATORS = 13` has no security or gas derivation. It
  comes from SP's 2025-12 `docs/V2-DVT-BLS-SLASH-MECHANISM.md` ("13 nodes,
  7/13"). The technical limit is the 256-bit `signerMask`. SP is raising it to
  64 in rc.8 round 3a.
- `Registry.batchUpdateGlobalReputation` requires popcount(signerMask) ≥
  `defaultThreshold` (7) and writes per-user credit;
  `ReputationSystem.setCommunityReputation` scores users within a community.
  Neither is a guardian/community reputation channel; per D4 neither is used.

## 3. On-chain evidence framework in DVTValidator (SP implements; spec here)

Goal (D6, D8): no penalty can execute unless its evidence is supplied in full
and passes an on-chain check fixed at deployment. In 5.5.0 the allowlist is
empty, so no BLS operator slash can execute at all (D1).

### 3.1 Encoding

```
evidence   = abi.encode(bytes32 category, bytes body)
category   = keccak256("DVT.Evidence.<Name>.v<N>")        // versioned, collision-free
evidenceHash = keccak256(abi.encode(TAG_EVIDENCE, category, keccak256(body)))
TAG_EVIDENCE = keccak256("SuperPaymaster.DVT.Evidence.v2")
```

`evidenceHash` is the value DVTValidator passes into `verifyAndExecute`, so the
aggregator's existing slash message (and hence the signer commitment) binds it.
Chain, aggregator and Registry are already bound by the aggregator's
`domainSeparator`; repeating them here buys nothing.

### 3.2 Allowlist and check

```
interface IEvidenceCategory {
    // view, never reverts: true only if `body` proves the violation for (operator, level, epoch)
    function check(address operator, uint8 level, uint256 epoch, bytes calldata body)
        external view returns (bool);
}
constructor(..., bytes32[] memory categories, address[] memory checkers)  // immutable, no setter
```

- On the **execute** step (the one that moves stake): decode `evidence`;
  `checker = checkerOf[category]`; `checker == 0` →
  `revert UnknownEvidenceCategory(category)`; `!checker.check(...)` →
  `revert EvidenceRejected(category)`; then compute `evidenceHash` and call the
  aggregator.
- On the **queue** step (the reversible pre-flag, whose aggregator message does
  not include `evidenceHash`): require the same decode + known category +
  passing check, so a quorum cannot freeze an operator without evidence. It does
  not bind; the execute step binds.
- A new category means a new DVTValidator through the normal rotation. No owner
  setter: an owner-editable allowlist would make governance the trust anchor.
- 5.5.0 manifest: `categories = []`. The gate asserts `categoryCount() == 0`.

### 3.3 Categories that carry a disputed block B (for later, not deployed in 5.5.0)

Body prefix for any category whose predicate depends on chain state:
`(uint256 B, bytes32 blockhashB, ...)`. DVTValidator enforces at execution (DSR
point 1):

```
B < block.number && block.number - B <= W                    // W immutable, W <= 7000 on OP
EIP2935.get(B) == blockhashB                                  // staticcall, 32-byte input
```

Failure reverts, so an execution held back past the window never happens through
DVTValidator. `W` proposal: 1800 blocks on OP (1 h). Honest nodes sign only if
`latest - B <= W/4`, leaving 3/4 of W for quorum collection and inclusion.

The over-issue category, if the owner ever enables it, would be
`body = abi.encode(uint256 B, bytes32 blockhashB, address token, address operator, uint256 epoch)`
and its checker returns `IOverIssuable(token).isOverIssued()` **at execution**
plus the B checks above. That is a check on current state taken while B is
fresh, i.e. an ex-ante proof check. It is acceptable only as an ex-ante gate: a
stale or repaired state makes execution revert rather than framing anyone. It
must also restrict `token` to an immutable set of known implementation
codehashes (the xPNTs EIP-1167 clones), otherwise a mutable token returns `true`
on demand. Not written now (DSR ruling: no category predicate until the owner
enables one).

### 3.4 Off-chain half: verify before signing

Each guardian node re-runs the category check itself before contributing a BLS
share, evaluating chain state with `eth_call` at `blockTag = B` (the post-state
of B, the state `stateRoot(B)` commits to — never `latest` or `pending`). This
is the existing, currently unarmed co-sign gate (`GossipQuorumCoSigner` →
`verifyViolationForCoSign`), re-armed per category. A node that cannot verify
does not sign. In 5.5.0 no category exists, so the gate stays unarmed.

## 4. DisclosureRegistry (new contract, DVT repo; SP vendors byte-identical if it wants)

Purpose (D2–D4): an append-only on-chain record of every BLS-executed action the
watcher flags, whose factual fields are verified on-chain at write time.

### 4.1 Properties (DSR constraints)

- Events carry the record. Storage is limited to a counter and one word per
  entry,
  `entryBinding[entryId] = keccak256(abi.encode(kind, proposalId, subjectToken))`,
  which a reply must match. No admin, no delete, no edit, no upgrade, no proxy.
- `WRITER` (the watcher EOA) and `AGGREGATOR` are immutable constructor
  arguments. Only `WRITER` may append a primary entry.
- Rotation: a lost or compromised watcher key means a new registry. So does a
  new aggregator (for example for more than 64 guardians), because `AGGREGATOR`
  and its `domainSeparator` are fixed. The manifest pins the current registry;
  readers follow the manifest; old registries stay readable.

### 4.2 Primary entry

```
function disclose(
    uint256 proposalId, uint8 kind,            // 0 = slash/rep (verifyAndExecute), 1 = generic (executeProposal),
                                               // 2 = queue (queueSlashWithConsensus) — reserved, see 4.2a
    bytes calldata messageInputs,              // kind 1: abi.encode(target, callDataHash, requiredThreshold)
                                               // kind 0: abi.encode of the aggregator's execute-slash fields
    address subjectToken,                      // community token the entry concerns, or 0
    uint256 signerMask, address[] calldata signers,
    bytes32 anchor,                            // once SP's anchor lands; else 0
    bytes32 txHash, uint64 blockNumber,
    bytes32 evidenceHash, bytes20 rulesetCommit,   // git SHA of the pinned ruleset (§5.2)
    string calldata recordURI, bytes32 recordHash
) external returns (uint256 entryId)
```

On-chain checks, all must pass or revert:

1. `msg.sender == WRITER`.
2. Recompute `messageHash` from the supplied inputs exactly as the aggregator
   does for `kind` (generic:
   `keccak256(abi.encode(domainSeparator, TAG_PROPOSAL, proposalId, target, callDataHash, requiredThreshold))`;
   slash: the aggregator's execute-slash preimage). So `target`, `callDataHash`
   and thresholds are verified, not claimed.
3. `signers` strictly ascending by `uint160`, length == popcount(`signerMask`).
4. `keccak256(abi.encode(domainSeparator, TAG_SIGNERS_COMMITMENT, proposalId, messageHash, signerMask, signers [, anchor]))`
   == `AGGREGATOR.proposalSignersCommitment(key)`, where `key` is the per-path
   namespaced key SP settles (§7 item 3; **pending**). The registry derives it
   from `kind` and the on-chain tag constants, and must not assume the raw id on
   either path. The final tuple and key scheme come from SP's implemented code.
   A non-zero commitment is required (an unexecuted key has commitment 0 and is
   rejected).
5. Block binding (once the anchor is in the commitment): if `blockNumber - 1` is
   inside the EIP-2935 window as seen now, require
   `EIP2935.get(blockNumber - 1) == anchor` and set `blockVerified = true`.
   Outside the window, set `blockVerified = false`; do not revert. The watcher
   writes within minutes, so the normal case is verified.
6. Emit
   `Disclosed(entryId, proposalId, kind, signers, txHash, blockNumber, blockVerified, evidenceHash, rulesetCommit, recordURI, recordHash)`.

What stays a **claim**: `txHash`, `blockNumber` when `blockVerified = false`,
the `recordURI` content, and the interpretation of why the action is
misbehaviour. The recheck script confirms the first two. Readers treat an entry
as a claim to recheck; the paper says so.

### 4.2a The queue path (kind 2) — blocking, pending SP

`queueSlashWithConsensus` is a guardian-quorum action too: it freezes an
operator. It does **not** write `proposalSignersCommitment` (SuperPaymaster
`origin/main`: it checks the signatures, calls `SUPERPAYMASTER.queueSlash`, and
emits `SlashPreQueued`). A disclosure of a quorum freeze therefore cannot have
its signer set verified on-chain today. There are two ways forward:

- SP adds a commitment on the queue path under its own typed key (for example
  `keccak256(abi.encode(TAG_QUEUE, messageHash))`). The registry then verifies
  kind 2 exactly like kinds 0 and 1.
- If SP cannot add it, kind 2 entries carry `signersVerified = false`, and the
  paper states that queue disclosures are unverified claims.

`kind = 2` is reserved in the enum either way. The registry interface is not
frozen until this is settled.

### 4.3 Reply entry (right of reply)

```
function reply(uint256 entryId, uint8 kind, uint256 proposalId, address subjectToken,
               bytes32 messageHash, uint256 signerMask, address[] calldata signers, bytes32 anchor,
               string calldata replyURI, bytes32 replyHash) external
```

- `keccak256(abi.encode(kind, proposalId, subjectToken)) == entryBinding[entryId]`
  (so the entry exists and the reply cites the same proposal).
- The caller is either a member of `signers`, where `signers` reproduces the
  commitment exactly as in §4.2 step 4, or
  `IxPNTsToken(subjectToken).communityOwner()` when `subjectToken != 0`.
- Emits `Replied(entryId, msg.sender, replyURI, replyHash)`. Cannot edit or
  delete anything.

### 4.4 Tests (each mutation-checked on the implementation)

- Correct signer set accepted; one signer swapped, wrong `messageHash`, wrong
  anchor → revert.
- A wrong `target` or `callDataHash` → revert (via recompute).
- A non-writer primary write → revert; the constructor writer is the only
  primary writer.
- Accused signer replies → ok; stranger replies → revert; reply to a missing
  entry → revert.
- An independent script rebuilds an entry from the tx alone (RPC only, no DVT
  state) and matches; a deliberately wrong entry is flagged by the same script.

## 5. Watcher service (DVT repo, Mac Mini only)

### 5.1 Process

A standalone long-running Node service (`services/guardian-watcher/`), reusing
`guardian-fraud-proof*.ts`, `guardian-signer-store.ts` and the watcher core.
launchd on the Mini (KeepAlive, RunAtLoad); not in the DVT node process; never
on the author's laptop. The committee keeper and apply-rotation jobs stay
disabled.

### 5.2 Detection

- Persisted cursor over the aggregator's `SlashExecuted`, `ProposalExecuted`,
  `ReputationEpochTriggered`, `SlashConsensusReached` events, with configurable
  confirmations.
- Signer set from `signerMask` in the event (SP rc.8 round 3a) resolved through
  `validatorAtSlot` at the execution block; self-checked against
  `proposalSignersCommitment` before anything is written. Until the event
  carries the mask, top-level `verifyAndExecute`/`executeProposal` calldata is
  decoded; wrapped calls are dead-lettered and alerted (the known gap closes
  when the event lands).
- Every BLS-executed action produces a record. A record is flagged
  **suspicious** when a rule says so (5.5.0 rules: any operator slash at all —
  impossible under the empty allowlist, so its appearance is itself the finding;
  any generic call whose target/selector is outside the expected set; any
  reputation batch; any queue freeze). Unflagged actions are still recorded as
  routine.
- The expected set of generic targets and selectors, and every flag rule, live
  in one pinned file in this repo (`services/guardian-watcher/ruleset.json`).
  Every record, and the registry event (`rulesetCommit`), carries the commit SHA
  of the ruleset that produced the flag. That way the watcher cannot decide
  after the fact what counts as suspicious.

### 5.3 Disclosure

For a flagged action: write the repo evidence record (JSON: tx, block, signers,
target, calldata, evidence, the recheck command), send Telegram, then
`DisclosureRegistry.disclose`. Each step is idempotent by `(proposalId, kind)`.

### 5.4 `pauseUnderstakedOperator`

On any Registry / GTokenStaking slash event that leaves a `PAYMASTER_SUPER`
operator below `minStake`, call SP's permissionless
`pauseUnderstakedOperator(op)` (reverts if at or above min). Log slash tx time,
detection time, pause tx time.

### 5.5 Ops and keys

- `status.json` every scan: last scanned block, lag, pending records, dead
  letters, balances, last RPC error. An independent external check (same pattern
  as the price-keeper stale-watch) alerts through the existing bot and chat on
  lag, RPC failure, low balance, stale heartbeat.
- Sender: a new low-balance EOA, JSON keystore, password in the macOS Keychain.
  Never in `.env` or plaintext; not a guardian, owner or deployer key.

## 6. Random committee (D7: prepared, not enabled)

- Selection: `index_i = H(seed, proposalId, i) mod N` with rejection of
  duplicates, over the frozen active set of the epoch (the pattern already in
  `AAStarCommitteeValidator`: per-epoch seed, frozen set root one epoch ahead,
  minimum committee floor).
- Seed: not OP `PREVRANDAO` (the sequencer knows it). Candidates: a pinned past
  block hash (as in `AAStarCommitteeValidator`) or a drand round after proposal
  creation, verifiable with EIP-2537.
- Size by risk: `k(level)` from a table, threshold ⌈2k/3⌉. Exact hypergeometric
  numbers for N=100 with a third corrupt: k=10 → forge ≈ 2^-6.2; k=20 → 2^-12.5;
  k=47 → 2^-42.7. Small committees are only for reversible actions (disclosure);
  irreversible ones need k ≥ 47 or the full set.
- The corrupt fraction must be measured by stake, not by guardian count: "one
  guardian per community" does not stop one party registering many communities.
- Placement: DVTValidator computes the committee and checks
  `signers ⊆ committee` before calling the aggregator. The aggregator only
  verifies the aggregate (it has no byte room).
- Interface prepared in 5.5.0: DVTValidator reserves `committeeOf(proposalId)`
  returning the full set (no selection) so callers and nodes already speak the
  interface.

## 7. Dependencies on SP (rc.8)

1. Anchor `blockhash(block.number-1)` in the commitment — round 3a. Final
   `abi.encode` tuple to DVT.
2. `signerMask` in `SlashExecuted` / `ProposalExecuted` — round 3a. Priority
   over the anchor if bytes are short.
3. **C4-L-01 commitment collision — key scheme pending from SP.** Today both
   paths share `executedProposals[proposalId]`, so an id executes once. Once
   C4-L-01 separates the replay bits, a raw id on one path can collide with a
   namespaced key on the other and overwrite `proposalSignersCommitment`. This
   holds in both directions: DSR found that a slash whose raw id equals
   `keccak256(abi.encode(TAG_PROPOSAL, id'))` overwrites the generic commitment
   of `id'`. SP's plan, pending byte measurement:
   - slash key `keccak256(abi.encode(TAG_SLASH, id))`;
   - generic key `keccak256(abi.encode(TAG_PROPOSAL, id))`;
   - the same key for both `executedProposals` and `proposalSignersCommitment`.

   Fallback: the raw slash id with `require(id < 2**128)`. SP rejected "require
   the slot empty", because a generic id executed first would pre-consume a
   slash id. DVT builds on whichever scheme SP ships. Also open: whether the
   `proposalId` field _inside_ the commitment tuple is the raw id or the key.

4. `MAX_VALIDATORS` 13 → 64; signerMask width unchanged (uint256).
5. DVTValidator raw evidence per §3, empty allowlist in the 5.5.0 manifest.

## 8. Deferred (not in 5.5.0)

- The historical-state fraud-proof verifier (dual anchor, EIP-2935 + EIP-1186
  proofs, xPNTs recompute). If on-chain enforcement is ever enabled, DSR's six
  points apply as requirements: on-chain freshness at execution, blockTag=B
  semantics, differential fuzz against `isOverIssued()`, EIP-1967 implementation
  slots for SP (UUPS; the factories are not proxies, the tokens are EIP-1167
  clones), an immutable known-implementation set, and real-header RLP tests. An
  owner-route execution outside the window must make the verifier return false,
  never a fraud verdict.
- Queue/execute submission by the watcher and OP forced inclusion: not needed
  while D1 holds.

## 9. Rehearsal bar for 5.5.0 (DSR)

On the A7 fork, archived under `docs/evidence/guardian-watcher-rehearsal/`:

1. Detection of each BLS-executed action, signer set from `signerMask`, target
   and calldata.
2. A disclosure record published to the repo, Telegram and the registry.
3. Negative control: a routine action is recorded but not flagged.
4. Kill-alert: watcher killed, external alert delivered (Telegram `ok:true`),
   then RECOVERED.
5. `pauseUnderstakedOperator` gap: injected staking slash below min → slash,
   detection, pause times.
6. Rebuild one record from an RPC with no DVT state. 6a. A queue-path (kind 2)
   disclosure, once §4.2a is settled.
7. Deployment facts: Mini only, keystore EOA distinct from
   guardian/owner/deployer, committee keeper disabled,
   `fraudProofVerifier == 0`, `categoryCount() == 0`.

## 10. Facts for the paper (DSR owns wording)

- 5.5.0 has no on-chain slashing and no on-chain reputation scoring;
  misbehaviour is recorded in an append-only on-chain registry whose signer-set
  and message fields are verified on-chain against the BLS commitment; the
  interpretation is a checkable claim by an open-source watcher.
- DVT initiates no slash in the early stage; N=3 is the bootstrap size.
- The watcher runs on one host (single point of failure); node-local capture is
  redundancy only.
- The rehearsal proves the pipeline, not ρ.
- More than 64 guardians (after round 3a) requires a new aggregator and
  migration.
