# DVT (YetAnotherAA-Validator) — Handoff

> **As of 2026-10-10.** Every fact below was re-read from its live source on
> this date (chain, GitHub, launchd, Seeder), not carried over from earlier
> notes. Facts here decay: re-derive before relying on any of them — §9 lists
> the commands.
>
> **Read §1 first.** The repo is under an external HOLD that forbids actions
> which look like ordinary maintenance.

---

## 0. TL;DR

- **The repo is frozen.** DSR execution instruction **v4** (2026-10-09): _DVT
  does not merge, rebuild, redeploy, or write to Sepolia._ `master` has not
  moved since `1991e92` (2026-09-05).
- **The three public nodes are healthy** (`dvt{1,2,3}.aastar.io` → 200, version
  **1.13.1**).
- **The committee validator `0x7ac7E9d4…` is fail-closed on purpose.** Its
  keeper was stopped on 2026-09-27 to comply with the HOLD. **Do not restart the
  keeper to "fix" it** — that is a Sepolia write. See §2.3.
- **Two PRs carry finished work, deliberately unmerged:** #377 (keeper alert
  self-check, approved) and #378 (node key-consistency self-check, CC-36).
- **One security finding has no other mitigation:** issue #376 — the off-chain
  gate that authorises an _irreversible_ slash checks role membership, not
  stake. It must be fixed before the audit slash path is ever enabled.
- **Waiting on others:** DSR acceptance of SP 5.5.0 A2/A2a (currently _NOT
  ACCEPTED_); the author's A3a go (currently _NO-GO_); airaccount-contract's
  final ✅ on CC-98.

---

## 1. Governing constraints — read before doing anything

### 1.1 Where the instructions live

| Instruction        | Location                                                                                                               | Status           |
| ------------------ | ---------------------------------------------------------------------------------------------------------------------- | ---------------- |
| **v4** — current   | Seeder **CC-122**, comment `[from:dsr] 执行指令 v4 — Decision 1/2 端到端复核后的纠偏（2026-10-09）`, 2026-10-09T04:05Z | **in force**     |
| v3                 | Seeder CC-122, comment `9102bef8-afbf-4a65-a42b-cdd6a836225d`, 2026-09-27T11:34Z                                       | superseded by v4 |
| B6 DVT instruction | `DSR-Research-Flow/writing/paper7-RepCredit/handoff/B6_DVT_INSTRUCTION_2026-09-05.md`                                  | historical       |

⚠️ **v3 and v4 are not in the handoff directory** — they exist only as Seeder
comments. Seeder's comment API returns only the oldest 100 comments per task;
CC-115 is past that limit, so read DSR's newest instruction on **CC-122**.

### 1.2 What v4 says for dvt (verbatim)

> repo:sdk / repo:yaaa / repo:dvt — HOLD ……
> **DVT 不 merge/rebuild/redeploy、不写 Sepolia；committee
> validator 当前 fail-closed 属已知 HOLD 状态。恢复前必须将 committee-keeper 换专用 EOA 并观测连续两个 epoch。**
> CC-121 的结论已接受：DVT 不是 score producer；还债/自动评分主张不得写入论文。
>
> 停止条件 …… **没有 accepted 或作者 go：禁止 Sepolia 写交易。**

### 1.3 Allowed vs forbidden, concretely

| Action                                                                   | Allowed? | Why                                                                     |
| ------------------------------------------------------------------------ | -------- | ----------------------------------------------------------------------- |
| Open a PR on a branch                                                    | ✅       | v4 forbids _merging_, not opening                                       |
| Merge anything to `master` (incl. dependabot)                            | ❌       | "DVT 不 merge"; `master` is also branch-protected                       |
| `docker compose up --build` / change the image                           | ❌       | "不 rebuild/redeploy" — the running image is the frozen 1.13.1 evidence |
| Change `docker-compose.testnet.yml` or `deploy/.env.testnet`             | ❌       | rebuild/redeploy, and B3-old evidence must stay frozen                  |
| Restart a node / OrbStack after an outage                                | ✅       | restores the frozen state; does not change it                           |
| Any Sepolia write (incl. `snapshotEpoch`, funding an EOA, `updatePrice`) | ❌       | needs DSR `accepted` **and** an author `go`                             |
| Read-only chain reads, replies on Seeder, issues                         | ✅       |                                                                         |
| Promote rc.2 readings to final evidence                                  | ❌       | rc.2 stays _candidate_ until DSR acceptance                             |

**Security-emergency exception** (agreed with DSR 2026-09-05): only for
something _externally triggerable AND irreversible or touching funds/keys_.
Availability problems never qualify; neither does any finding in §5 today — each
one is verified unreachable in the current deployment.

---

## 2. Current state snapshot

### 2.1 Versions — note the three different numbers

| What                            | Value                                                           |
| ------------------------------- | --------------------------------------------------------------- |
| `master`                        | `1991e92` (2026-09-05, #319)                                    |
| `package.json` / latest tag     | **1.15.0** / `v1.15.0`                                          |
| **Running on the public nodes** | **1.13.1** — Docker image `aastar-dvt:latest`, built 2026-08-18 |

`master` and the deployed nodes are **not the same code**. The image is pinned
by the freeze. Never `--build`: on-disk `dist/` is newer and rebuilding silently
upgrades the nodes.

### 2.2 Runtime topology (all on one laptop)

```
login → io.aastar.orbstack-keeper (120 s poll) ─┐
                                                 ├─ docker daemon (OrbStack)
                                                 │    ├─ dvt-node-1/2/3   127.0.0.1:3001-3003   restart: unless-stopped
                                                 │    ├─ dvt-autoheal      restarts unhealthy nodes
                                                 │    └─ dvt-cloudflared   tunnel de08f3f4 → dvt{1,2,3}.aastar.io
io.aastar.dvt-tunnel-keepalive (300 s) ──────────┘   probes the PUBLIC URLs; restarts cloudflared
```

- **The tunnel ingress points at Docker container names**
  (`http://dvt-node-N:300N`). A host-side cloudflared can never serve it — it
  can only return 502. This is why `deploy/dvt-testnet.sh` (bare processes on
  4001-4003) is a **decommissioned trap**: it starts, looks healthy locally, and
  can never serve public traffic. Its launchd job is disabled.
- **Self-heal has three layers and a bottom.** `restart: unless-stopped`,
  autoheal and tunnel-keepalive all live _above_ the Docker daemon.
  `io.aastar.orbstack-keeper` (added 2026-09-27, outside the repo at
  `~/.local/bin/orbstack-keeper.sh`) is the bottom layer: it restarts OrbStack
  when the daemon is down. Verified by fault injection through the real launchd
  trigger (recovered in 91 s). A macOS login item was tried first and was
  **not** enough — it starts the app once and nothing restarts it.
- **Only the signer runs in the containers.** `x-dvt-env` in
  `docker-compose.testnet.yml` maps five variables and nothing from `AUDIT_*`,
  `KEEPER_*`, `RELAY_*`, `X402_*`, `OPS_ALERT_*`. Public `/health` therefore
  reports every capability `enabled: false`. `deploy/.env.testnet` sets
  `KEEPER_ENABLED=true` — _configured on, deployed off_.

### 2.3 Sepolia writers — deliberately stopped

| launchd job                      | Wrote                                                                                     | State        | Stopped because                                                                |
| -------------------------------- | ----------------------------------------------------------------------------------------- | ------------ | ------------------------------------------------------------------------------ |
| `io.aastar.dvt-committee-keeper` | `snapshotEpoch` every epoch (~112 tx/day) from the **deployer/owner EOA**                 | **disabled** | v3/v4 hard stop; author decision 2026-09-27                                    |
| `io.aastar.dvt-apply-rotation`   | hourly `apply-verifier-rotation.mjs --broadcast` — auto-applies any due verifier rotation | **disabled** | same; an armed auto-broadcaster would bypass per-transaction review in A3a/A3b |

Both were `bootout` + `disable`, and the persistent table
`/var/db/com.apple.xpc.launchd/disabled.<uid>.plist` shows both `true` — they
survive a reboot.

**Observed consequence:** from block **11,794,114 / epoch 184283** the committee
validator `0x7ac7E9d4` returns `requiredQuorum() == type(uint256).max` —
fail-closed. Router algId 0x01 tier-2/3 is unavailable. v4 classifies this as
_known HOLD state_. Issues **#379** and **#381** are the monitor reporting it
correctly; keep them **open** (the monitor files one issue per category and
stays quiet while it is open — closing them makes it re-alert).

**Restore** — only after DSR A2 `accepted` + author `go`, and in this order (v4
makes the first two mandatory):

1. Move the keeper to a **dedicated EOA**. `snapshotEpoch` is permissionless
   (verified: none of its 10 `require`s touch `msg.sender`/`onlyOwner`). Sharing
   the deployer EOA with A3a's `onlyOwner` transactions risks nonce collision —
   a higher-gas `snapshotEpoch` could silently _replace_ an A3a transaction.
2. `launchctl enable gui/<uid>/io.aastar.dvt-committee-keeper && launchctl bootstrap gui/<uid> ~/Library/LaunchAgents/io.aastar.dvt-committee-keeper.plist`,
   then **observe two consecutive epochs** pinned.
3. Validator usability needs the current _and_ previous epoch pinned, so it
   returns ≤ 1 epoch after restart.
4. Epochs during the HOLD can never be pinned (256-block window). **B3′/B6′
   measurements must not span that gap.**
5. Do **not** re-arm `dvt-apply-rotation` as a timer before the 5.5.0 upgrade
   window closes — apply rotations by hand.

### 2.4 Addresses (Sepolia)

| Role                                             | Address                                      | Notes                                                        |
| ------------------------------------------------ | -------------------------------------------- | ------------------------------------------------------------ |
| Committee validator (router algId 0x01)          | `0x7ac7E9d471742FA4397Beef0B5b11fbD22D196a9` | committee ON, epochLength 64, minCommittee 3, 4 active nodes |
| `AAStarValidator` (`VALIDATOR_CONTRACT_ADDRESS`) | `0x539B9681aFd5BFbCaa655Fe4c6BdcFe1fa7864bC` |                                                              |
| Router                                           | `0xA97A752779ebfDA58612F6727Ec7C8366c39f897` |                                                              |
| BLSAggregator 4.11.0                             | `0xEaeC2F512eA50708211fa95533e4dBb60e3d2E5D` | domainSeparator `0x79613488…1ee2b`                           |
| Registry                                         | `0xf5Bf37ca83AfdAab73691bA7eCcDfA69b8708E71` | `ROLE_DVT = keccak256("DVT")`; minStake 30e18                |
| SuperPaymaster                                   | `0x09DF0d2e3722EC0e401fE3819E64278a42ae4DE9` |                                                              |
| LivenessRegistry                                 | `0x02d841F7905aFb4424DBA71680D27C0F75d36BE7` | window 300 blocks; no consumer on either side yet            |
| Owner / deployer EOA                             | `0xb5600060e6de5E11D3636731964218E53caadf0E` | owns both validators **and** holds `ROLE_DVT` with 0 stake   |
| Community Safe (mainnet owner target)            | `0x51eDf11fDb0A4F66220eFb8efA54Eca77232E114` | CC-31                                                        |

---

## 3. Milestone plan

### 3.1 Program level — CC-122 (SP 5.5.0, then RepCredit)

Order fixed by DSR v3/v4:

```
DSR witness ∥ SP docs + A3a packet → A2/A2a accepted → author A3a go → A3a → A3b → A5s → A4
     → exclusive measurement window (R3–R5, B5′/B6′) → A6 mainnet experiment → A7 / R6 submission
```

| Stage                                                       | State on 2026-10-10                                                                      |
| ----------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| R0 site protection, R1 F0 acceptance pack                   | done                                                                                     |
| A1 / M-1 Part B, M-2 D5c-1/D5c-2 (Halmos), M-3 D7, M-4, D5b | done                                                                                     |
| **M-11** ABI notice                                         | done — dvt review: **runtime unaffected**; one code change owed (`getDebt` → v2 `debts`) |
| **A2 / A2a** RC gate                                        | **NOT ACCEPTED** (DSR final-tag I9 witness inconclusive)                                 |
| **A3a**                                                     | **NO-GO**                                                                                |
| A3b, A5s, A4, A2f, M-7, W-1/W-2, A6, A7, R2–R6              | not started                                                                              |

Candidate coordinate: **SP `v5.5.0-rc.2` → `1ac0e1c5`** (verified that the tag
points there). Record it as _candidate_. Between dvt's M-11 pin `898748c5` and
rc.2, **zero `contracts/src` files changed** — verified with a control (the same
pathspec matched exactly the 10 contracts `2d66867f` changed) — so the M-11
conclusion holds at rc.2.

### 3.2 DVT's own path once the HOLD lifts (in order)

1. **Restore the committee keeper** per §2.3 (dedicated EOA → two epochs
   observed).
2. **Fix #376 before any audit slash path is enabled** — a hard gate agreed with
   SP.
3. Merge the finished PRs (#378, #377) and, if DSR allows, the dependabot set
   (§4).
4. `getDebt` → `debts` for SP v2 tokens (M-11; zero callers today, so a latent
   trap, not a live fault).
5. B3′/B6′ readings at the accepted rc.2 coordinate.
6. **Measurement matrix** (CC-122, DSR 2026-10-10): _"DVT/BLS
   m={2,3,5,7,9,13}每点5个新proposal"_. ⚠️ Open: the live committee has **4**
   active nodes. m up to 13 needs either synthetic keys in a local harness (as
   CC-99's n-scan did) or more signers. Ask DSR which one before planning it.
7. Only if the author wants the in-node price keeper as a second keeper
   (CC-122): map only `KEEPER_*` and `OPS_ALERT_*` in compose — never `AUDIT_*`,
   which would open the slash path before #376 — point it at the live SP,
   configure alerting and **run a real alert drill**.

### 3.3 Longer term

- **Mainnet** — CC-30 / CC-46 / #106 / `deploy/TESTNET-TO-MAINNET.md`. Needs the
  author: mainnet validator deployment (only once code stops changing) and the
  node-count / stake-buffer policy. Today's margin is **0** (all four operators
  stake exactly `minStake`).
- `docs/ROADMAP.md` is **stale** (last edited 2026-07-07; still plans
  v1.3–v1.6). Don't plan from it — use this file plus CC-122.

---

## 4. Work in flight — open PRs

| PR                                            | State                                     | Notes                                                                                                                                                                                                                                                                                                                               |
| --------------------------------------------- | ----------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **#378** CC-36 key-consistency self-check     | changes requested → **fixed** (`5f2b514`) | pr-daemon's only blocker was `format:check`; prettier applied. Five Codex rounds; every fix mutation-verified. One Codex Medium explicitly deferred (scope tag missing on two _error_ paths; never yields an untagged `ok`). pr-daemon's non-blocking note: unauthenticated `/health` exposes `checkerError` (raw `error.message`). |
| **#377** keeper alert-config self-check       | **approved**                              | Checks _configured_, not _deliverable_ — a dead-but-configured token still passes. Three Codex rounds, mutation-verified.                                                                                                                                                                                                           |
| #364 `@nestjs/platform-express` 12.0.1→12.0.3 | approved                                  | Does **not** clear the audit alone — see #338                                                                                                                                                                                                                                                                                       |
| #334 #336 #349 #351 #365 #366 #367 #368 #369  | approved                                  | devDependency bumps; lockfiles conflict — once one merges, the rest need rebase **and a fresh review of the regenerated lockfile**                                                                                                                                                                                                  |

`Security Audit` fails on every PR run — that is #338, not the PRs. `master`'s
last CI run (2026-09-05, `1991e92`) passed it, but **that run predates the
multer advisories**. `master` has not changed and still pins `multer` 2.2.0, so
a re-run would very likely fail the same way — inferred, not re-run.

---

## 5. Problems and risks

### 5.1 Security / correctness (code)

- **#376 — highest.** `confirmSlashableAtBlock()`
  (`src/modules/audit/audit.service.ts:791-808`) authorises an **irreversible**
  slash on `hasRole` alone. A guardian slashed to zero keeps `hasRole=true`
  forever, so it stays permanently "slashable": every recurring predicate hit
  spends a BLS co-sign round on it — a griefing surface fed by enforcement
  itself. The author decided (2026-09-27) **not** to clean those members up and
  **not** to upgrade the Registry, so this application-level fix is the **only**
  defence, permanently. `getEffectiveStake` has **zero call sites** in `src/` —
  the predicate in `docs/SLASH_ROLLOUT_GATE.md:283` is documented, not
  implemented. Not live today (audit is not deployed). Cross-repo convention
  agreed with SP: admission/denominator/eligibility checks read
  `effectiveStake >= minStake`, never `hasRole` alone. The contract already
  complies (`AAStarValidator._isStaked`, `:950`); only the off-chain service
  does not.
- **#338** — the four `npm audit` highs share one root cause: `package.json`
  `overrides.multer = "2.2.0"`, pinned by commit `78495bf` titled _"clear all
  high/critical npm audit findings"_ — the security pin is now what holds the
  vulnerability in place. The fix is one line (`2.2.0` → `2.4.0`) together with
  #364. Not externally triggerable here (zero multipart routes across all 32
  HTTP routes). Note: plain `npm audit` fails because the default registry
  (npmmirror) has no audit endpoint — use
  `--registry=https://registry.npmjs.org`.
- **#320, #314** — compiled-in contract addresses can silently diverge from the
  Registry's canonical pointer.

### 5.2 Operations

- **#379 / #381** — expected HOLD state (§2.3). Keep open.
- **#380** — a single _undetermined_ reading on 2026-09-28
  (`missing revert data`). Different from fail-closed; likely an RPC blip.
  Re-check before closing.
- **#317** — `CLOUDFLARE_TUNNEL_TOKEN` names two different secrets (API token vs
  run token); `tunnel-keepalive.sh` works around it by deriving the run token at
  runtime.
- **The owner EOA is overloaded** — owner of both validators and of
  LivenessRegistry, SP deployer, and a zero-stake `ROLE_DVT` holder. Mainnet
  must land the owner directly on the community Safe (CC-31).
- **Remote (Rust/TEE) signer keys are not verified** by #378 — that would
  require a probe signature outside the authorisation gate, which was rejected.
  Follow-ups: passively record `public_key` from real authorised `/sign`
  responses, or ask `repo:kms` for a read-only public-key endpoint.

### 5.3 Design / direction (registered, not active)

#222 (CC-89 stage 2), #202 (offline-slash soundness), #201 (libp2p gossipsub),
#163, #157, #140, #122, #106, #100, #98, #88, #67, #63, #62, #61, #60, #59, #58,
#52, #50, #45, #40, #278, #257, #346 (SP 5.5.0 ABI split — DVT uses inline ABI
fragments, so likely unaffected; verify at R2).

### 5.4 Decisions only the author can make

1. Whether dependabot bumps may merge during the HOLD (v4 reads as a blanket "no
   merge").
2. CC-30 — keep pushing mainnet now, or after 5.5.0?
3. CC-44 — bring x402 back online within the current priorities?
4. CC-46 — authorise the mainnet validator; choose node count and stake buffer.
5. Measurement matrix m up to 13 vs a 4-node committee (§3.2-6) — ask DSR.

---

## 6. Seeder (Cooperation Center) tasks involving dvt

| Task                                                  | dvt status                                 | Owed                                                                                                                                             |
| ----------------------------------------------------- | ------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| **CC-122** SP 5.5.0 / RepCredit sequencing            | active                                     | B3′/B6′ readings after acceptance; keeper restore                                                                                                |
| **CC-121** global-reputation scoring                  | ✅ accepted by DSR                         | — (DVT is not a score producer)                                                                                                                  |
| **CC-29** LivenessRegistry                            | answered                                   | DVT wiring blocked by HOLD; never enable exclusion before attest coverage is measured; a live-count floor must _skip_ exclusion, not fail closed |
| **CC-28** xPNTs issuance cap                          | ✅ no DVT code change                      | —                                                                                                                                                |
| **CC-98** committee model (**dvt is the originator**) | awaiting airaccount-contract ✅            | dvt closes it once that arrives                                                                                                                  |
| **CC-36** stake + register                            | PR #378                                    | merge after HOLD                                                                                                                                 |
| **CC-49** model B funding service                     | design review delivered                    | not to be built now                                                                                                                              |
| **CC-31** community Safe                              | adopted                                    | mainnet only                                                                                                                                     |
| **CC-30 / CC-44 / CC-46**                             | need the author                            | §5.4                                                                                                                                             |
| CC-13                                                 | correction posted — superseded by CC-28/29 | originator should close                                                                                                                          |
| CC-14, 32, 38, 95, 96, 97, 99, 104, 106               | delivered                                  | originators should close                                                                                                                         |
| CC-66, 111, 120                                       | announcements                              | —                                                                                                                                                |

---

## 7. Document index

**This repo**

| Topic                    | Document                                                                                                                                                                                                                                                               |
| ------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Developer guide          | [`README.md`](../README.md), [`CONTRIBUTING.md`](../CONTRIBUTING.md). The agent guide `CLAUDE.md` is **local-only** (excluded via `.git/info/exclude`, never committed) — it exists on the maintainer's machine, not in this repo.                                     |
| Operations               | [`docs/DVT_OPERATIONS.md`](DVT_OPERATIONS.md), [`docs/MONITORING.md`](MONITORING.md), [`deploy/README.md`](../deploy/README.md), [`deploy/README-heartbeat.md`](../deploy/README-heartbeat.md)                                                                         |
| Deployment               | [`docs/PRODUCTION_DEPLOYMENT.md`](PRODUCTION_DEPLOYMENT.md), [`deploy/DEPLOYMENT_OPTIONS.md`](../deploy/DEPLOYMENT_OPTIONS.md), [`deploy/TESTNET-TO-MAINNET.md`](../deploy/TESTNET-TO-MAINNET.md), [`deploy/COMMUNITY_OPERATORS.md`](../deploy/COMMUNITY_OPERATORS.md) |
| Release                  | [`docs/RELEASE.md`](RELEASE.md), [`docs/RELEASE_READINESS.md`](RELEASE_READINESS.md), [`docs/RELEASE_TEST_CHECKLIST.md`](RELEASE_TEST_CHECKLIST.md), [`docs/TESTNET_RELEASE_PLAN.md`](TESTNET_RELEASE_PLAN.md), [`RELEASING.md`](../RELEASING.md)                      |
| Interfaces / integration | [`docs/INTERFACES.md`](INTERFACES.md), [`docs/HOW_TO_INTEGRATION.md`](HOW_TO_INTEGRATION.md), [`HYBRID_ARCHITECTURE.md`](../HYBRID_ARCHITECTURE.md)                                                                                                                    |
| Audit / slash model      | [`docs/AUDIT_SLASH_MODEL.md`](AUDIT_SLASH_MODEL.md), [`docs/SLASH_ROLLOUT_GATE.md`](SLASH_ROLLOUT_GATE.md)                                                                                                                                                             |
| Design                   | [`docs/design/`](design/) — guardian-collusion-slash, committee-min-quorum-hardening, offline-penalty-escalation, fraud-verifier-threshold-curve, cc89-stage2-shipping-plan, dvt-node-protocol, dvt-policy-governance                                                  |
| Frozen evidence          | [`docs/evidence/cc115-b3-arming-sepolia.md`](evidence/cc115-b3-arming-sepolia.md)                                                                                                                                                                                      |
| Keys / signing           | [`docs/KEYSTORE.md`](KEYSTORE.md), [`docs/KEEPER-KMS-SIGNING.md`](KEEPER-KMS-SIGNING.md)                                                                                                                                                                               |
| Modules                  | [`docs/x402-facilitator.md`](x402-facilitator.md), [`docs/out-of-band-confirmation.md`](out-of-band-confirmation.md)                                                                                                                                                   |
| Roadmap (stale)          | [`docs/ROADMAP.md`](ROADMAP.md) — see §3.3                                                                                                                                                                                                                             |

**Other repos**

| Topic                         | Location                                                                               |
| ----------------------------- | -------------------------------------------------------------------------------------- |
| SP 5.5.0 final spec           | `SuperPaymaster` `docs/design/aoa-balance-mode/03-final-spec.md`                       |
| SP rc.2 attestation           | `SuperPaymaster` PR #445, `docs/release/v5.5.0-rc.2-attestation.{md,json}`             |
| SP M-11                       | `SuperPaymaster` PR #444                                                               |
| DSR plan & B5/B6 instructions | `repcredit-e2e-worktrees/20260823/DSR-Research-Flow/writing/paper7-RepCredit/handoff/` |
| Model B design (CC-49)        | `AirAccount/kms/docs/community-node-register-modelB-funding-service.md`                |
| Snapshot tag (R0)             | `repcredit-pre550-snapshot-20260913` (all 5 repos)                                     |

---

## 8. Traps — each one cost real time

| Trap                                             | What actually happens                                                                                                                                        |
| ------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| A launchd job's **name** is not its owner        | `io.aastar.price-keeper` runs `aastar-sdk/run-keeper.sh`; `io.aastar.kms-tunnel` ran the **DVT** tunnel. Read `ProgramArguments`.                            |
| `StartInterval` nested in `EnvironmentVariables` | passes `plutil -lint`; launchd silently ignores it. Verify with `launchctl print … \| grep "run interval"`.                                                  |
| `orb config set app.*`                           | exits 0 and changes nothing — read the value back                                                                                                            |
| `KeepAlive=true`                                 | guarantees the process _exists_, not that it _works_. The SDK price keeper ran 3.5 weeks: 8,455 RPC 403s, 0 updates, alert channel also broken               |
| An empty result                                  | is evidence only after the same probe is shown to hit something — run a control                                                                              |
| Wrong dynamic-tuple ABI                          | does not revert: `getRoleConfig` with a guessed signature returns `minStake = 32 wei` (the ABI offset `0x20`). Use the full signature or read storage slot 6 |
| Unquoted variables in zsh                        | are not word-split: `prettier --write $FILES` receives one argument                                                                                          |
| PR checks                                        | include `npm run format:check` — not only `lint:check` and `type-check`                                                                                      |

---

## 9. Taking over — first commands

```bash
# public health (expect 200 / 1.13.1)
for u in dvt1 dvt2 dvt3; do curl -s https://$u.aastar.io/health | jq -c '{status,version}'; done

# runtime + guards
docker ps --format '{{.Names}}\t{{.Status}}' | grep dvt
~/.local/bin/orbstack-keeper.sh --check
PATH="/opt/homebrew/bin:$PATH" bash deploy/tunnel-keepalive.sh --check

# Sepolia writers must stay disabled during the HOLD
launchctl print-disabled gui/$(id -u) | grep -E 'committee-keeper|apply-rotation'

# latest DSR instruction — newest [from:dsr] comment on Seeder CC-122
```

**Local branch housekeeping (2026-10-10).** 51 local branches and two agent
worktrees were pruned after proving every commit reachable from a remote or a
GitHub PR ref. The only two branches holding commits no remote had were
resolved:

- `opt/validator-gas-safe` (`8848937`) — **pushed to `origin` as an archive.**
  The CC-96 `_hashToG2` buffer optimisation that was measured and **declined**
  (~0.3 %; paper §6.5). Deliberately **no PR**: it is a record of a rejected
  change, not a candidate for merging.
- `pr-244` (`37b45ed207911d66d0f82bcbcb0678cb0c6e729d`) — **deleted.** A
  pre-merge iteration of #244, superseded by the merged `b97e533`. Recoverable
  by SHA while the object survives local GC.
