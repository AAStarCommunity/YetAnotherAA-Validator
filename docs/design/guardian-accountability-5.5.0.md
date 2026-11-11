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

| Actor                                                               | Risk                                                                                                                                               | 5.5.0 handling                                                                                                                                                                                                                    |
| ------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Community / operator                                                | Over-issues xPNTs                                                                                                                                  | Unchanged: on-chain views `isOverIssued()` / `credibilityScore()`; DVT does nothing.                                                                                                                                              |
| **Guardians** (the BLS signer set)                                  | A quorum signs an action it should not: a false slash, a false reputation batch, or a generic proposal (e.g. `Registry.updateOperatorBlacklist`).  | **This document.** No operator slash can execute _through DVTValidator_ (empty allowlist, §3); the owner route below is a named trust assumption; every BLS-executed action, on either route, is detected and disclosed (§4, §5). |
| **Aggregator `owner()`** (the Safe, per SP)                         | Calls `verifyAndExecute` / `queueSlashWithConsensus` / `executeProposal` directly with a guardian quorum, skipping DVTValidator and its allowlist. | Trust assumption, not prevented: the Safe's signers are trusted in 5.5.0. Made checkable: the manifest pins `owner()` and §9 item 7 reads it back; the watcher flags any operator slash regardless of caller (§5.2).              |
| Operator already slashed below `minStake` by Registry/GTokenStaking | Keeps operating                                                                                                                                    | Watcher calls `pauseUnderstakedOperator(op)` (§5.4).                                                                                                                                                                              |

Every guardian power goes through `BLSAggregator.verifyAndExecute`,
`queueSlashWithConsensus` or `executeProposal`, and all three accept only
`DVT_VALIDATOR` or `owner()` as caller (SuperPaymaster `origin/main` afe405fa,
`BLSAggregator.sol` :963, :990, :1097). So the watcher's surface is exactly: the
events of those three entry points.

The `owner()` caller is a second route that never reaches DVTValidator. Per SP
the 5.5.0 aggregator owner is the protocol Safe (not a timelock), and
`setDVTValidator` is immediate. Slash thresholds are WARNING=2, MINOR=3, MAJOR=3
(`:673-675`), so with N=3 the Safe plus a 2–3 guardian quorum can execute a
slash directly. 5.5.0 does not remove this route; it treats the Safe as trusted
(consistent with the trusted-operator bootstrap phase) and makes the route
observable. Every claim below of the form "no slash" means "no slash through
DVTValidator".

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
empty, so no BLS operator slash can execute through DVTValidator (D1). The owner
route (§1) bypasses this framework; it is a trust assumption, not covered here.

### 3.1 Encoding

```
evidence   = abi.encode(bytes32 category, bytes body)
category   = keccak256("DVT.Evidence.<Name>.v<N>")        // versioned, collision-free
evidenceHash = keccak256(abi.encode(TAG_EVIDENCE, category, keccak256(body)))
TAG_EVIDENCE = keccak256("SuperPaymaster.DVT.Evidence.v2")
```

Vectors: `contracts/test/fixtures/evidence-vectors.json`, generated from
`scripts/disclosure/recheck-lib.mjs` (`npm run check:disclosure` diffs it) and
recomputed in Solidity by `contracts/test/EvidenceHashParity.t.sol` (an
independent recomputation, not SP's contract). Running SP's DVTValidator 0.8.0
against the same file is planned once its branch is published; until then the
parity covers our two implementations only. `abi.encode`, never `encodePacked`:
for `evidenceHash` the two coincide (three static `bytes32` words), but for
`evidence` they differ, since `bytes` is dynamic and `abi.encode` adds its
offset and length.

The DVT node does not yet build proposals this way (it files
`evidenceHash = proofHash`, and over-issue uses its own tag). That is closed in
5.5.0 (`categoryCount() == 0`, and node slash submission is disabled), and is
moved to §3.1 before the first category is deployed (DSR 918b553d): each
category's body is a versioned ABI struct; the audit-slash body carries the
proof identity's ABI fields and `bytes32 proofHash` (still the off-chain archive
address, no longer the evidenceHash); over-issue becomes
`DVT.Evidence.OverIssue.v1`.

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

- Events carry the record. Storage is limited to a counter and two words per
  entry:
  `entryBinding[entryId] = keccak256(abi.encode(kind, key, subjectToken))`,
  which a reply must match, and
  `entryOf[keccak256(abi.encode(kind, key))] = entryId`. No admin, no delete, no
  edit, no upgrade, no proxy.
- One primary entry per action: a second `disclose` of the same `(kind, key)`
  reverts `AlreadyDisclosed(entryId)`, whatever the claim fields say. Duplicates
  are impossible on chain, independent of the watcher's journal.
- The claim fields of an entry can be corrected only by
  `amend(entryId, Amendment{txHash, blockNumber, rulesetCommit, recordURI, recordHash}, reasonHash)`:
  WRITER only, append-only, emits `Amended`, never edits the primary entry;
  readers apply amendments in order, each replacing the previous claim values in
  full. A corrected `blockNumber` is a claim (not re-verified against EIP-2935).
  `subjectToken` is part of the binding and cannot be amended (§4.3). The
  on-chain-verified fields (signers, message, key) cannot be wrong and are never
  amended. The watcher builds every entry from `rebuildFromAction` (the recheck
  library), so its verified fields already reproduce the commitment before
  `disclose`; amendments are for its claim fields and are the exception. The
  recheck tool currently reads the original claims of an entry; applying
  amendments (an amended `txHash`/`blockNumber` changes which tx it rebuilds
  from) is a follow-up, and until then an amended entry is rechecked against its
  original claims. An amended `blockNumber` never inherits the entry's
  `blockVerified`.
- `version()` returns `"DisclosureRegistry-1.0.0"` (SP's IVersioned shape), read
  back by the release manifest.
- `WRITER` (the watcher EOA) and `AGGREGATOR` are immutable constructor
  arguments. Only `WRITER` may append a primary entry or an amendment.
- Rotation: a lost or compromised watcher key means a new registry. So does a
  new aggregator (for example for more than 64 guardians), because `AGGREGATOR`
  and its `domainSeparator` are fixed. The manifest pins the current registry;
  readers follow the manifest; old registries stay readable.

### 4.2 Primary entry

As implemented in PR #396 (`contracts/src/disclosure/DisclosureRegistry.sol`):

```
enum Kind { SLASH, GENERIC, QUEUE, REPUTATION }
struct Signed {
    Kind kind;
    uint256 proposalId;      // 0 for QUEUE; non-zero otherwise; < 2^128 for SLASH and REPUTATION
    bytes messageInputs;     // per kind, below
    uint256 signerMask;
    address[] signers;       // ascending by uint160
    bytes32 anchor;          // blockhash(N-1) from the commitment
}
function disclose(Signed calldata s, address subjectToken, bytes32 txHash, uint64 blockNumber,
                  bytes20 rulesetCommit,       // git SHA of the pinned ruleset (§5.2)
                  string calldata recordURI, bytes32 recordHash) external returns (uint256 entryId)
```

`messageInputs` per kind, each mirroring one aggregator pre-image:

| Kind       | Entry point                              | `messageInputs`                                 | Signed message                                                                           |
| ---------- | ---------------------------------------- | ----------------------------------------------- | ---------------------------------------------------------------------------------------- |
| SLASH      | `verifyAndExecute`, `repUsers` empty     | `(operator, slashLevel, epoch, evidenceHash)`   | `keccak(ds, TAG_EXECUTE_SLASH, id, operator, level, epoch, evidenceHash)`                |
| REPUTATION | `verifyAndExecute`, `repUsers` non-empty | `(address[] users, uint256[] newScores, epoch)` | `keccak(ds, TAG_REPUTATION, id, users, newScores, epoch)` (threshold `defaultThreshold`) |
| GENERIC    | `executeProposal`                        | `(target, callDataHash, requiredThreshold)`     | `keccak(ds, TAG_PROPOSAL, id, target, callDataHash, threshold)`                          |
| QUEUE      | `queueSlashWithConsensus`                | `(operator, slashLevel, epoch)`                 | `keccak(ds, TAG_QUEUE_SLASH, operator, level, epoch)`                                    |

On-chain checks, all must pass or revert:

1. `msg.sender == WRITER`.
2. Recompute `messageHash` from `messageInputs` exactly as the aggregator does
   for `kind` (table above). So `target`, `callDataHash`, thresholds, the
   reputation arrays and the slash fields are verified, not claimed.
3. `signers` strictly ascending by `uint160`, length == popcount(`signerMask`).
4. `keccak256(abi.encode(domainSeparator, TAG_SIGNERS_COMMITMENT, key, messageHash, signerMask, signers, anchor))`
   == `AGGREGATOR.proposalSignersCommitment(key)`, with the key per path from
   SP's BLSAggregator-4.13.0 (rc.8 r3b, §7 item 3):
   - SLASH and REPUTATION: the raw `proposalId`, which must be `< 2^128` (SP
     reverts `InvalidProposalId` otherwise; the registry enforces the same
     bound);
   - GENERIC: `uint256(keccak256(abi.encode(TAG_PROPOSAL, proposalId)))`;
   - QUEUE: `uint256(messageHash)`.

   A non-zero commitment is required (an unexecuted key has commitment 0 and is
   rejected). Re-checked against SP's committed source SHA before the interface
   freezes.

5. Block binding (once the anchor is in the commitment): if `blockNumber - 1` is
   inside the EIP-2935 window as seen now, require
   `EIP2935.get(blockNumber - 1) == anchor` and set `blockVerified = true`.
   Outside the window, set `blockVerified = false`; do not revert. The watcher
   writes within minutes, so the normal case is verified.
6. Store
   `entryBinding[entryId] = keccak256(abi.encode(kind, key, subjectToken))` and
   emit
   `Disclosed(entryId, kind, key, proposalId, messageHash, signers, record)`,
   where
   `record = (subjectToken, txHash, blockNumber, blockVerified, rulesetCommit, recordURI, recordHash)`.
   `messageInputs` must be the canonical ABI encoding of the decoded fields
   (trailing bytes or non-canonical offsets revert `NonCanonicalInputs`).

What stays a **claim**: `txHash`, `blockNumber` when `blockVerified = false`,
the `recordURI` content, and the interpretation of why the action is
misbehaviour. The recheck script confirms the first two. Readers treat an entry
as a claim to recheck; the paper says so.

### 4.2a The queue path (QUEUE) — settled by SP r3b

`queueSlashWithConsensus` is a guardian-quorum action too: it freezes an
operator. On SuperPaymaster `origin/main` it writes no commitment (`:959-977`:
it checks the signatures, calls `SUPERPAYMASTER.queueSlash`, and emits
`SlashPreQueued`). SP rc.8 r3b adds one, with the same tuple as the other paths,
keyed at `uint256(messageHash)` (no extra `TAG_QUEUE` wrap; the queue message is
already domain- and tag-separated). The registry verifies QUEUE entries exactly
like the other kinds. Because the key carries no proposal id, `proposalId` must
be 0 for QUEUE.

### 4.3 Reply entry (right of reply)

```
function reply(uint256 entryId, Signed calldata s, address subjectToken,
               string calldata replyURI, bytes32 replyHash) external
```

- `s` passes the same checks as §4.2 steps 2–4, and
  `keccak256(abi.encode(s.kind, key, subjectToken)) == entryBinding[entryId]`
  (so the entry exists and the reply cites the same action).
- The caller is one of:
  - a member of `signers`, where `signers` reproduces the commitment exactly as
    in §4.2 step 4;
  - a party the signed message names, which the commitment therefore covers: the
    `operator` of a SLASH or QUEUE action, or a user of a REPUTATION batch;
  - `IxPNTsToken(subjectToken).communityOwner()` when `subjectToken != 0`.
- `subjectToken` is the writer's claim: no commitment covers it, and the recheck
  reports it as unverified. The second route lets the party an action actually
  named reply even when the entry is attributed to the wrong community. A
  GENERIC action names no reply party (its target is only a contract address);
  its signers and the claimed community owner can reply. `subjectToken` is part
  of `entryBinding` and cannot be amended, so a wrong `subjectToken` in the
  first entry permanently gives that token's community owner the right of reply.
  That is harmless: replies are append-only claims, and the parties the action
  actually names keep their own reply route.
- Emits `Replied(entryId, msg.sender, replyURI, replyHash)`. Cannot edit or
  delete anything.

### 4.4 Tests (each mutation-checked on the implementation)

- Correct signer set accepted for each of the four kinds, including a reputation
  batch; one signer swapped, wrong `messageHash`, wrong anchor → revert.
- A wrong `target`, `callDataHash`, slash field or reputation array → revert
  (via recompute).
- A slash/reputation id ≥ 2^128 → revert, including one equal to a live generic
  key (cross-path claim); a QUEUE entry with a non-zero id → revert.
- A non-writer primary write → revert; the constructor writer is the only
  primary writer.
- Accused signer replies → ok; stranger replies → revert; reply to a missing
  entry → revert.
- An independent script rebuilds an entry from the tx alone (RPC only, no DVT
  state) and matches; a deliberately wrong entry is flagged by the same script.
  Its verdict has three values: MATCH (the verified fields agree; claims such as
  `subjectToken` are listed as unverified), MISMATCH (provably wrong), and
  INCONCLUSIVE (not decidable from the tx's own data: a wrapped call, a
  non-canonical block, or a slot table that changed inside the block). Every
  read is pinned to one confirmed snapshot, and canonical inclusion is checked
  before and after (`scripts/disclosure/recheck-entry.mjs`). Absent evidence (a
  tx or receipt the RPC does not return, a header without `parentHash`, a
  receipt without an explicit status) is INCONCLUSIVE, never MISMATCH. Two trust
  premises: the registry and aggregator addresses come from the release
  manifest, and consumers treat INCONCLUSIVE as unverified.
- Message fields are recovered from the transaction and, for the forwarders the
  release manifest pins (DVTValidator, the owner Safe, optionally Safe's
  MultiSendCallOnly), from their calldata and pre-execution state. A forwarder
  is followed only at its pinned address, never by selector alone. Routes:
  - `DVTValidator.executeWithProof`: `operator`, `slashLevel`, `evidenceHash`
    are read from `proposals(id)` at block N-1. They never change after creation
    (DVTValidator-0.7.0 @ f00be603 :215-238, :257); a proposal that did not yet
    exist at N-1 is INCONCLUSIVE.
  - `DVTValidator.queueSlashWithProof`: forwarded unchanged; decoded directly.
  - owner Safe `execTransaction` with operation CALL is followed; a DELEGATECALL
    is followed only into the pinned MultiSendCallOnly, and only through
    sub-transactions that are all CALLs; module routes are not followed.
  - any other wrapper, and a pinned forwarder that led to no decodable call: a
    `callTracer` trace, decoding only error-free CALL frames into the pinned
    aggregator or DVTValidator. The route rules apply inside the trace: module
    calls are pruned; a DELEGATECALL is followed only as the owner Safe's own
    proxy hop into its singleton (slot 0 read from the pre-tx state via
    `prestateTracer`, and at blocks N-1 and N; a Safe that re-points its
    singleton inside the same tx before the hop is a known INCONCLUSIVE case) or
    into the pinned MultiSendCallOnly with all-CALL children. Without a trace,
    INCONCLUSIVE.

  Whatever the route, a recovered call's message counts only if it reproduces
  the stored commitment, or if the call is proven to have succeeded (the
  top-level call of a successful tx into the pinned aggregator, or an error-free
  trace frame into it). A call proven to have succeeded also counts without the
  commitment, which is sound because SuperPaymaster allows each key to succeed
  only once (`executedProposals`, `usedSlashQueueHashes`, every entry point
  `nonReentrant`). A Safe inner call or a DVTValidator-derived call is not
  proven, so it counts only through the commitment. A decoding error therefore
  ends in INCONCLUSIVE or MISMATCH, never MATCH, and an unauthenticated
  recovered call is not evidence.

## 5. Watcher service (DVT repo, Mac Mini only)

### 5.1 Process

A standalone long-running Node service (`services/guardian-watcher/`), reusing
`guardian-fraud-proof*.ts`, `guardian-signer-store.ts` and the watcher core.
launchd on the Mini (KeepAlive, RunAtLoad); not in the DVT node process; never
on the author's laptop. The committee keeper and apply-rotation jobs stay
disabled.

### 5.2 Detection

- Persisted cursor over the aggregator's `SignersCommitted(key, signerMask)` (SP
  rc.8 r3b; one per BLS-executed action on every path and either caller), joined
  in the same tx with `SlashExecuted`, `ProposalExecuted`,
  `ReputationEpochTriggered`, `SlashPreQueued` / `SlashConsensusReached` to
  classify the kind, with configurable confirmations.
- Signer set from that `signerMask`, resolved through `validatorAtSlot` at the
  execution block; self-checked against `proposalSignersCommitment(key)` before
  anything is written. The message fields come from the tx's calldata; a wrapped
  call (not a top-level call to the aggregator) is read from the trace, or
  dead-lettered and alerted if the trace is unavailable. The tx's `from`/caller
  is recorded so an owner-route action is identified.
- Every BLS-executed action produces a record. A record is flagged
  **suspicious** when a rule says so (5.5.0 rules: any operator slash at all —
  impossible through DVTValidator under the empty allowlist, so its appearance
  (necessarily via the owner route) is itself the finding; any generic call
  whose target/selector is outside the expected set; any reputation batch; any
  queue freeze; every BLS price update, i.e. an `executeProposal` calling
  `SuperPaymaster.updatePriceDVT`). Unflagged actions are still recorded as
  routine.
- Price updates are flagged even though they are expected: `executeProposal`
  takes a caller-chosen threshold (at least `minThreshold` = 2), and SP bounds
  each update to 20% but not a chain of updates inside `[MIN, MAX]`. The record
  carries the price before and after (read at the parent block and at the
  execution block) and the signer set.
- The expected set of generic targets and selectors, and every flag rule, live
  in one pinned file in this repo (`services/guardian-watcher/ruleset.json`).
  Every record, and the registry event (`rulesetCommit`), carries the commit SHA
  of the ruleset that produced the flag. That way the watcher cannot decide
  after the fact what counts as suspicious.

#### 5.2a SuperPaymaster events outside a BLS action: classified by the emitting call (#400 M1)

A watched SuperPaymaster event that the trace does not place inside a BLS
action's aggregator call is **not** an owner action by default. Three functions
that emit watched events are permissionless in SP 5.5.1
(`SuperPaymasterAdmin.sol` at `7eb1fc87`):

| Function                                            | Emits                                                         | Verdict (DSR, 2026-11-10)                                                                                                                                                                                                         |
| --------------------------------------------------- | ------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `updatePrice()` :507 (Chainlink refresh)            | `PriceUpdated`, `PriceModeChanged`, `EmergencyPriceCancelled` | routine when the call emits only `PriceUpdated`; **flagged as informational** ("price mode changed via permissionless refresh, caller not accused") when the same call also emits `PriceModeChanged` or `EmergencyPriceCancelled` |
| `executeEmergencyPrice()` :417 (after the timelock) | `PriceModeChanged`, `EmergencyPriceExecuted`, `PriceUpdated`  | flagged, with the price before and after; the caller is not accused (the owner's queueing was already flagged)                                                                                                                    |
| `pauseUnderstakedOperator(address)` :105            | `OperatorPaused`                                              | routine, not flagged (W3 owns it)                                                                                                                                                                                                 |

Every other function that emits a watched event is owner-, guardian- or
aggregator-only.

- The event is classified by **the call into SuperPaymaster that emitted it**:
  its selector and `msg.sender`. These come from the nearest enclosing
  error-free `CALL` into SP in the `callTracer` trace, aligned log by log with
  the receipt (a `DELEGATECALL` from SP into its own module is looked through).
  The transaction's own calldata names only the root call, and an event name
  matching what the root function can emit does not exclude a nested SP call
  emitting the same event. So an event a permissionless function _can_ emit is
  attributed **only** by its aligned emitting frame in the trace, for direct
  calls too. A tracing RPC (`debug_traceTransaction`, `callTracer` with
  `withLog`) is therefore a requirement, not an optimisation. The capability is
  known only by **positive verification**: a real transaction with logs whose
  trace aligns log by log with its receipt, either one the scan traced (its
  receipt must contain every watched log `getLogs` returned, identical in
  address, topics and data at the same position, and no other watched log; every
  receipt log at its own position) or a sample: the stored sample transaction
  first, then the newest finalized blocks. A lookup miss proves nothing, since a
  node resolves the transaction before it builds the tracer. The proof is stored
  and re-checked when older than `traceVerifyMs` (1 h), on quiet ticks too; any
  trace showing the method missing or `withLog` ignored (a watched log seen by
  `getLogs` makes a log-less trace conclusive, whatever the receipt says), or a
  receipt that disagrees with `getLogs`, drops it, and only a new positive
  verification restores health. The watcher is in an explicitly labelled
  **degraded** mode (`status.degraded` lists why, `status.healthy` is false,
  `--once` exits non-zero) when the method or tracer is missing, a trace of a
  transaction with logs carries none, a receipt disagrees with `getLogs`, the
  proof is older than twice the interval, or every trace call of the tick, or of
  a verification attempt, failed. It is never shown as healthy. Checking this on
  the production RPC is a Phase D pre-deploy item. A fallback that attributes
  without a trace is backlog after 5.5.0. A selector shorter than 4 bytes proves
  no function. A selector listed in `ruleset.json` `publicRoute.functions` gives
  the **public** route. Any other selector gives the **owner** route. Every
  record carries `caller`, `selector`, `from`, `to` and `callerSource` (`tx` |
  `trace` | `unknown`), so the ruleset can change later without re-scanning.
- An event that a permissionless function _can_ emit, whose call cannot be
  determined (no trace, unaligned trace, tx unavailable), is never guessed. The
  transaction becomes a dead letter (route `tx`) and is retried each tick. An
  event that only privileged functions can emit is the owner route whatever the
  trace says. Its caller is recorded when known.

- **Scope of the trace and receipt checks.** They defend against an RPC that is
  honest but inconsistent, lagging or only partly supporting the tracer, and
  against client format differences:
  - the receipt must name the tx and its block, succeed explicitly and carry no
    removed or foreign log, and the receipt, its logs and the tx must all name
    the block the `getLogs` evidence came from (a stale backend can answer from
    an orphaned earlier inclusion);
  - the trace root must be the tx itself (sender, destination, full input);
  - positions are parsed strictly and must be unique and contiguous;
  - logs must be well formed;
  - traces from geth before log positions are accepted where the order is
    unambiguous.

  They do **not** defend against an RPC that fabricates a well-formed trace (for
  example a different caller frame, or a log placed in a static call), because
  such an RPC could equally omit an event from `getLogs`, which no trace check
  can detect. The RPC is a deployment trust assumption: an operator-chosen node.
  Before Phase D, a separate gate (**D-RPC2**, must merge before Phase D, no
  bypass) re-fetches every accusatory record's tx from a second, independently
  operated RPC (a different provider) and holds the record as unconfirmed unless
  both agree; records that confirm no violation are exempt. Comparing several
  independent RPCs on every scan is backlog after 5.5.0.

#### 5.2b Dead letters, exhaustion and read integrity

- A transient read failure is a retried dead letter, never a permanent gap:
  - a tx that cannot be fetched;
  - a price read that fails, for a record that needs the price;
  - an action that cannot yet be authenticated.
- After `MAX_DEADLETTER_ATTEMPTS` (20), a dead letter becomes a record, so every
  BLS-executed action and every watched event ends with one:
  - an unauthenticated BLS action becomes `UNRECOVERED` (flagged per ruleset;
    published to the repo and Telegram only, with no registry entry, since
    nothing on chain verifies it);
  - an undeterminable SP event becomes `unattributed` (flagged, nobody accused);
  - a record whose price never read (an authenticated BLS action, or an SP event
    already classified) is kept with its route, caller and verdict, and
    `price.unavailable`.
- One tx never stops the scan: any exception while processing a tx (for example
  a malformed RPC answer such as a frame address that is not an address, or an
  aggregator log without its key) makes that tx a dead letter with its watched
  evidence, and the cursor moves on. At the attempt cap it becomes an
  `unattributed` record (`UNREADABLE`, nobody accused) carrying that evidence;
  `status.json` counts txs isolated in the tick and unreadable txs in total.
- A BLS action with an open dead letter is retried by that dead letter alone,
  once per tick; retirements of one id are numbered, never overwritten.
- An SP effect that the trace proves to belong to a BLS action only after the
  action's record was written is kept beside the record as an amendment
  (`amendments/bls-<key>.json`, first-write-wins); one proven while the action's
  dead letter is open goes into that dead letter and so into the record.
- An unattributed record keeps what is known of the tx itself (sender, target,
  root selector), never as the caller.
- A transaction dead letter stores the watched logs exactly as `getLogs`
  returned them. Its retries are judged against that evidence, never against a
  receipt that may be the thing in dispute; one written without it re-reads its
  block's logs by hash.
- Evidence a dead letter has established survives every later, weaker failure:
  an authenticated BLS record awaiting its price, and classified SP records
  awaiting theirs, are retried for the price only and never rebuilt. A BLS
  action counts as done only when a parseable, authenticated record exists; an
  `UNRECOVERED` placeholder or a corrupt file does not stop a later
  reconstruction.
- `status.json` counts open, corrupt and exhausted dead letters. A corrupt
  dead-letter file is counted, never fatal. A record file that does not parse is
  rewritten. All state writes are fsynced (file, then directory) before they
  count as done.
- **logsBloom cross-check (DSR).** For every scanned block, if the header's
  `logsBloom` says a watched (address, topic) may be present but the range
  `getLogs` returned no such log, the block is re-read with `getLogs` by
  `blockHash` (EIP-234):
  - a node that lacks the block errors instead of answering empty, so the tick
    fails and is retried (the cursor does not move);
  - logs that come back are merged in;
  - an empty answer by hash confirms a bloom false positive, which is counted.

  The check runs per (address, topic), so a returned topic cannot mask a missing
  one in the same block. A bloom cannot reveal a missing _second_ log of a topic
  that did come back.

  Headers without a bloom are counted as unchecked and never stop the scan.

- **Residual:** a load-balanced RPC can still serve different node views to
  different calls. The bloom check catches a node that is behind for a block it
  was asked about. It does not make a load-balanced endpoint safe in general.
  Run the Mini's watcher against **one** non-load-balanced endpoint.

### 5.3 Disclosure

For a flagged action: write the repo evidence record (JSON: tx, block, signers,
target, calldata, evidence, the recheck command), send Telegram, then
`DisclosureRegistry.disclose`. Each step is idempotent by `(kind, key)` (QUEUE
has no proposal id; its key is the message hash), and the registry itself
refuses a second primary entry for the same `(kind, key)`.

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

Status as SP reported it from its implementation (BLSAggregator-4.13.0, 24,542
B, rc.8 r3b; **not yet on `origin/main`** — DVT re-checks against the committed
SHA before freezing the registry):

1. Anchor `blockhash(block.number-1)` as the last element of the commitment
   tuple, identical on all paths:
   `keccak256(abi.encode(domainSeparator, TAG_SIGNERS_COMMITMENT, key, messageHash, signerMask, signers, blockhash(N-1)))`.
2. `SignersCommitted(uint256 indexed key, uint256 signerMask)` emitted with
   every commitment. The watcher detects from this event (§5.2).
3. **C4-L-01 commitment collision — settled.** Once C4-L-01 separates the replay
   bits, a raw id on one path could collide with a namespaced key on the other
   and overwrite `proposalSignersCommitment` (DSR found the reverse case: a
   slash whose raw id equals `keccak256(abi.encode(TAG_PROPOSAL, id'))`). SP's
   choice (the pre-approved fallback; the typed slash key did not fit in bytes):
   - slash and reputation (`verifyAndExecute`): the raw id,
     `require(id < 2**128)` on the whole function (DVT confirmed it generates no
     reputation ids and its slash ids are DVTValidator's auto-increment
     counter);
   - generic: `keccak256(abi.encode(TAG_PROPOSAL, id))`, same as its replay
     slot;
   - queue: `uint256(messageHash)`;
   - the commitment tuple carries the storage key, not the raw id.

4. `MAX_VALIDATORS` 13 → 64; signerMask width unchanged (uint256).
5. DVTValidator raw evidence per §3, empty allowlist in the 5.5.0 manifest.
6. The manifest pins the aggregator's `owner()` (the Safe) so the owner-route
   trust assumption (§1) is checkable. Removing the owner caller from the three
   entry points is not planned for 5.5.0.

## 8. Deferred (not in 5.5.0)

- The historical-state fraud-proof verifier (dual anchor, EIP-2935 + EIP-1186
  proofs, xPNTs recompute). If on-chain enforcement is ever enabled, DSR's six
  points apply as requirements: on-chain freshness at execution, blockTag=B
  semantics, differential fuzz against `isOverIssued()`, EIP-1967 implementation
  slots for SP (UUPS; the factories are not proxies, the tokens are EIP-1167
  clones), an immutable known-implementation set, and real-header RLP tests. An
  owner-route (Safe) execution outside the window must make the verifier return
  false, never a fraud verdict.
- Queue/execute submission by the watcher and OP forced inclusion: not needed
  while D1 holds.

## 9. Rehearsal bar for 5.5.0 (DSR)

On the A7 fork, archived under `docs/evidence/guardian-watcher-rehearsal/`:

1. Detection of each BLS-executed action, signer set from `signerMask`, target
   and calldata.
2. A disclosure record published to the repo, Telegram and the registry.
3. Negative control: a routine action is recorded but not flagged. 3a. Positive
   control: one `updatePriceDVT` via `executeProposal` is detected and disclosed
   with old price, new price and signer set.
4. Kill-alert: watcher killed, external alert delivered (Telegram `ok:true`),
   then RECOVERED.
5. `pauseUnderstakedOperator` gap: injected staking slash below min → slash,
   detection, pause times.
6. Rebuild one record from an RPC with no DVT state. 6a. A queue-path (QUEUE)
   disclosure. 6b. A reputation-batch (REPUTATION) disclosure.
7. Deployment facts: Mini only, keystore EOA distinct from
   guardian/owner/deployer, committee keeper disabled,
   `fraudProofVerifier == 0`, `categoryCount() == 0`, and the aggregator's
   `owner()` read back equal to the manifest's Safe.
8. Owner-route detection: an operator slash executed with `owner()` as caller
   (fork only, no real guardian key) is detected and flagged.

Prerequisite: the fraud-drill proposal id in `deploy/reregister-guardians.mjs`
is keccak-derived (≥ 2^128) and would revert under the r3b bound; it is changed
to an id < 2^128 or retired before the rehearsal.

## 10. Facts for the paper (DSR owns wording)

- 5.5.0 executes no operator slash through DVTValidator (empty evidence
  allowlist) and does no on-chain reputation scoring. The aggregator owner (the
  Safe) can still call the BLS entry points directly with a guardian quorum;
  that route is a trust assumption of the bootstrap phase, pinned in the
  manifest and watched, not prevented. Misbehaviour is recorded in an
  append-only on-chain registry whose signer-set and message fields are verified
  on-chain against the BLS commitment; the interpretation is a checkable claim
  by an open-source watcher.
- DVT initiates no slash in the early stage; N=3 is the bootstrap size.
- The watcher runs on one host (single point of failure); node-local capture is
  redundancy only.
- The rehearsal proves the pipeline, not ρ.
- More than 64 guardians (after round 3a) requires a new aggregator and
  migration.
