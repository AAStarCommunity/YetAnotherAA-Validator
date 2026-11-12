# Phase D runbook — guardian watcher on the Mac Mini

For the author, in order. Every step is a command to paste; nothing here needs a
judgement call. Secrets are typed **only** into the interactive `security … -w`
prompt (step 2): never on a command line, in a file, in `.env`, or in a chat.
Phase D (`check:phase-d`, step 9) passes only when every step below is done; it
never prints a secret value.

Scope of what Phase D proves: an honest operator's mistakes and secret
disclosure, not the Mini's operator (M0 §5.5).

## 0. Prerequisites

- The Mac Mini, logged in as the user that will run the watcher (`id -un`).
- `node` at `/opt/homebrew/bin/node` (the wrapper's PATH), `gh` logged in,
  `git`, `docker`.
- The step-13 manifest is published: you have the DVTValidator, BLSAggregator,
  SuperPaymaster, DisclosureRegistry, owner Safe and deployer addresses, every
  guardian address, and the SP rc.8 release tag's full commit.
- Do **not** send any transaction from
  `0xb5600060e6de5E11D3636731964218E53caadf0E` (D). Use senders A or E only
  after SP confirms.

## 1. Checkout and directories

```sh
mkdir -p ~/.aoa-watcher/data ~/.aoa-watcher/evidence && chmod 700 ~/.aoa-watcher
git clone https://github.com/AAStarCommunity/YetAnotherAA-Validator ~/.aoa-watcher/repo
cd ~/.aoa-watcher/repo && git checkout <the release commit> && npm ci --ignore-scripts
REPO=~/.aoa-watcher/repo
```

Phase D trusts the checkout it runs from, and the watcher must run from the same
checkout (`watcher-job-binding`). Every later step uses `$REPO`.

## 2. Keychain: the six secrets (account `aoa-watcher`)

Run each line; `security` prompts for the value twice. Paste the value at the
prompt only.

```sh
security add-generic-password -U -a aoa-watcher -s aoa-dvt-pinata-jwt          -w
security add-generic-password -U -a aoa-watcher -s aoa-dvt-filebase-token      -w
security add-generic-password -U -a aoa-watcher -s aoa-dvt-watcher-keystore-pw -w
security add-generic-password -U -a aoa-watcher -s aoa-dvt-alert-bot-token     -w
security add-generic-password -U -a aoa-watcher -s aoa-dvt-rpc-primary         -w
security add-generic-password -U -a aoa-watcher -s aoa-dvt-rpc-secondary       -w
```

- `aoa-dvt-watcher-keystore-pw`: a new random password, at least 16 characters
  (it encrypts the sender keystore in step 3; it is never needed by hand again).
- `aoa-dvt-rpc-primary` / `-secondary`: trace-capable RPC URLs from **two
  different operators** on **two different hosts** (`rpc-independent`).

Check (prints metadata, not the value):
`for s in pinata-jwt filebase-token watcher-keystore-pw alert-bot-token rpc-primary rpc-secondary; do security find-generic-password -a aoa-watcher -s aoa-dvt-$s >/dev/null && echo "ok $s"; done`

## 3. The watcher sender (DisclosureRegistry writer)

```sh
cd $REPO && node deploy/guardian-watcher/new-sender-keystore.mjs
```

It prints the new **sender address** only and writes
`~/.aoa-watcher/sender.keystore.json` (mode 600). It refuses to overwrite an
existing keystore. The sender must not be a guardian, the owner Safe or the
deployer (`sender-keystore`). Fund it with at least 0.05 Sepolia ETH
(`sender-balance`, `sender.minBalanceWei`), from a sender SP has confirmed
(never D).

## 4. The watcher config

```sh
cp $REPO/deploy/guardian-watcher/config.example.json ~/.aoa-watcher/config.json
sed -i '' "s|REPLACE_USER|$(id -un)|g" ~/.aoa-watcher/config.json
```

Check `chainId` (the example's is Sepolia, 11155111; it must equal
`phase-d.json` `chainId`: the watcher refuses to publish without it, and
`watcher-publish` compares the two). Fill every `<...>` from the step-13
manifest (public data only): `aggregator`, `roles.superPaymaster`,
`forwarders.dvtValidator` / `ownerSafe` / `multiSendCallOnly` (Phase D's
`onchain:binding` compares `forwarders.dvtValidator` with `phase-d.json`
`contracts.dvtValidator`), `startBlock` (the aggregator's deployment block),
`publish.registry` (DisclosureRegistry address, its deployment block as
`fromBlock`, the deployer, and `maxFeePerGas`: the absolute fee ceiling in wei
as a decimal string; its `keystore` must be the same file as `phase-d.json`
`sender.keystore`), the Pinata gateway, the Telegram chat id. Keep
`publish.enabled: true` (`watcher-publish`). The git mirror needs a bare clone
whose push key is in the ssh-agent:
`git clone --bare git@github.com:AAStarCommunity/YetAnotherAA-Validator.git ~/.aoa-watcher/mirror.git`.

## 5. The Phase D config

```sh
cp $REPO/deploy/guardian-watcher/phase-d.example.json ~/.aoa-watcher/phase-d.json
```

Fill every `<...>`: `release.spCommit`, the two RPC operator names, every
guardian address, the owner Safe, the deployer, `contracts.*`, `launchd.domain`
(`gui/$(id -u)`), and in `dvtNodes.notDvt` every running container that is not a
DVT node (`docker ps --format '{{.Names}}'`). Operator names are public labels:
never paste a URL there.

## 6. The wrapper (exactly the template, two values filled)

```sh
sed -e "s|^WATCHER_CONFIG=\"__WATCHER_CONFIG__\"\$|WATCHER_CONFIG=\"$HOME/.aoa-watcher/config.json\"|" \
    -e "s|^WATCHER_ENTRY=\"__WATCHER_ENTRY__\"\$|WATCHER_ENTRY=\"$REPO/services/guardian-watcher/watcher.mjs\"|" \
    $REPO/deploy/guardian-watcher/run-watcher.sh > ~/.aoa-watcher/run-watcher.sh
chmod 700 ~/.aoa-watcher/run-watcher.sh
```

Use absolute paths without spaces (`$HOME`, not `~`, inside the quotes). Any
other edit fails `watcher-job-binding`.

## 7. launchd: the keeper jobs off, then the watcher, then the heartbeat

The committee keeper and the apply-rotation job must stay off (`launchd-off`):

```sh
launchctl print gui/$(id -u)/io.aastar.dvt-committee-keeper 2>&1 | head -1   # expect: Could not find service
launchctl print gui/$(id -u)/io.aastar.dvt-apply-rotation   2>&1 | head -1   # expect: Could not find service
```

The watcher first (the heartbeat alerts on a missing `status.json`):

```sh
for j in ai.aastar.aoa-watcher ai.aastar.aoa-watcher-heartbeat; do
  sed "s|REPLACE_USER|$(id -un)|g" $REPO/deploy/guardian-watcher/$j.plist > ~/Library/LaunchAgents/$j.plist
  plutil -lint ~/Library/LaunchAgents/$j.plist
done
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/ai.aastar.aoa-watcher.plist
sleep 120 && ls -l ~/.aoa-watcher/data/status.json      # the first tick has written status
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/ai.aastar.aoa-watcher-heartbeat.plist
launchctl print gui/$(id -u)/ai.aastar.aoa-watcher-heartbeat | grep "run interval"   # expect 300
node $REPO/deploy/guardian-watcher/heartbeat.mjs --config ~/.aoa-watcher/config.json --test   # one TEST message in the chat
```

After **any** later change to the config, the wrapper or the checkout, restart
the watcher before Phase D (`watcher-job-binding` compares the process start
with those files): `launchctl kickstart -k gui/$(id -u)/ai.aastar.aoa-watcher`.

## 8. Release evidence

```sh
cd $REPO
npm run -s check:sp-parity -- <rc.8 SP commit> --out "$(mktemp -d)" > ~/.aoa-watcher/evidence/sp-evidence-parity.json
node scripts/disclosure/a3-emission-diff.mjs <SP's A3 table.json> --json > ~/.aoa-watcher/evidence/a3-emissions.json
```

Both must pass for this release, fixture and ruleset (`evidence:spParity`,
`evidence:a3`).

## 9. DVT nodes: slash submission explicitly off

`node-slash-off:<container>` needs `AUDIT_ENABLED=false` and
`AUDIT_EXECUTE_SLASH=false` **in the running container's environment** (the
compose files set both). Recreating a container is the author's call: one
container at a time, 2 of 3 always up, no BLS proposal in flight, then
`docker inspect` for health and both variables before the next:

```sh
docker compose -f docker-compose.testnet.yml up -d --no-build dvt-node-1
docker inspect -f '{{.State.Health.Status}}' dvt-node-1     # expect: healthy
# only the two audit variables, matched by exact name (other variables can hold credentials):
docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' dvt-node-1 \
  | grep -E '^AUDIT_(ENABLED|EXECUTE_SLASH)=' # expect both =false
```

## 10. Run Phase D

```sh
cd $REPO && npm run -s check:phase-d -- --config ~/.aoa-watcher/phase-d.json
```

It exits **0 only when every line is PASS** (`N PASS, 0 FAIL, 0 MISSING`). Each
line:

| id                                                        | PASS means                                                                                                                                                                                                                                                                           |
| --------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `keychain:account`, `keychain:<item>`                     | the six Keychain items of step 2 exist under `aoa-watcher`                                                                                                                                                                                                                           |
| `watcher-config`                                          | `~/.aoa-watcher/config.json` loads with the watcher's own validation and its data dir is writable                                                                                                                                                                                    |
| `watcher-publish`                                         | publication is enabled, the watcher's publish config validates, and it uses `sender.keystore` and the Keychain items of step 2                                                                                                                                                       |
| `sender-keystore`                                         | encrypted, mode 600, decrypts with the Keychain password, address not a guardian / owner Safe / deployer, not SP's guardian                                                                                                                                                          |
| `sender-balance`                                          | the sender holds at least `sender.minBalanceWei`                                                                                                                                                                                                                                     |
| `launchd-off:<job>`                                       | the committee keeper and apply-rotation jobs are not loaded                                                                                                                                                                                                                          |
| `launchd-on:<job>`                                        | the watcher and the heartbeat are loaded and running with a pid                                                                                                                                                                                                                      |
| `watcher-job-binding`                                     | the job runs exactly `~/.aoa-watcher/run-watcher.sh`, which is byte-for-byte the template with the two values; the live pid is `node <$REPO watcher.mjs> --config <config>` with the Keychain RPCs in its environment; the process started after every checked file was last changed |
| `node-compose`, `node-discovery:*`, `node-unclassified:*` | the compose file is the deployment's, every running container is a DVT node or listed in `notDvt`                                                                                                                                                                                    |
| `node-slash-off:<container>`                              | `AUDIT_ENABLED=false` and `AUDIT_EXECUTE_SLASH=false` explicitly in the container's environment                                                                                                                                                                                      |
| `rpc-primary`, `rpc-second`                               | right chain id, trace capability positively verified                                                                                                                                                                                                                                 |
| `rpc-independent`                                         | two declared operators on two different hosts                                                                                                                                                                                                                                        |
| `release-mode`                                            | no `PHASE_D_RPC_*` override (a dry run is never a release acceptance)                                                                                                                                                                                                                |
| `chain-id`                                                | `chainId` is set                                                                                                                                                                                                                                                                     |
| `onchain:binding` and the on-chain facts                  | the contracts equal the watcher config; `aggregator.DVT_VALIDATOR == dvtValidator`, `categoryCount == 0`, `fraudProofVerifier == 0`, owner is the Safe                                                                                                                               |
| `release:spCommit`, `evidence:spParity`, `evidence:a3`    | the release commit is set and both evidence reports pass for it                                                                                                                                                                                                                      |

A MISSING line names what is not set or not reachable; a FAIL line names what is
wrong. Fix it, restart the watcher if a watched file changed (step 7), and run
step 10 again. The report never contains a Keychain value; a label that looks
like a URL is replaced by `(a URL: not shown)`.

## After acceptance: re-arming a held accusation (D-RPC2)

An accusatory record is published only after a second, independent provider has
reproduced it. If the second provider keeps reproducing something else
(`CONFIRM_MAX_ATTEMPTS` mismatches), the record is held for good
(`unconfirmed-final`) and the watcher stays degraded. An outage of the second
provider never does this: unavailable answers are retried with a backoff (at
most 1 h) for as long as it takes.

Once the cause is understood and fixed (for example the second provider was
misconfigured), re-arm the record so the second provider is asked again. The
command refuses anything but `unconfirmed-final`, needs the watcher stopped, and
writes the states before and after and your reason into the record's journal
(`holdRearms`; an entry left `pending` by an interrupted run is settled by
running the command again). It publishes nothing: the record stays held until
confirmed.

```sh
launchctl bootout gui/$(id -u)/ai.aastar.aoa-watcher
node $REPO/deploy/guardian-watcher/rearm-hold.mjs --config ~/.aoa-watcher/config.json \
  --id <record id> --reason "<why, one plain line, no URL>"
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/ai.aastar.aoa-watcher.plist
```

The record id is the file name (without `.json`) under `holds/` in the data
directory; `status.json` counts the held records (`confirm.final`).

## After acceptance: when the primary provider wrote a bad record (D-RPC2)

**How it shows.** The watcher is degraded with
`N accusatory record(s) differ on the second provider (held, not published)`
(or, after repeated mismatches, `… final after repeated mismatches …`). The
record's hold, `holds/<record id>.json` in the data directory, names the fields
the two providers disagree on (`fields`, `reason`). An incident alert can also
point at the record.

**It is already contained.** A held record is not uploaded, mirrored, sent to
Telegram or disclosed; nothing has to be stopped to keep it from spreading.

**Find out which provider is wrong.** Compare the record's transaction (its
`txHash` and block) against a third, independent source, such as a block
explorer or another RPC, for the fields listed in the hold.

- **The second provider was wrong.** Fix or replace it (Keychain item
  `aoa-dvt-rpc-secondary`, then
  `launchctl kickstart -k gui/$(id -u)/ai.aastar.aoa-watcher`). The record is
  confirmed on a later pass; if it had become final, re-arm it (previous
  section).
- **The primary provider's record is wrong.** It is never published while it
  disagrees, so nothing on chain needs correcting. To have the record produced
  again from a corrected primary:
  1. stop the watcher (`launchctl bootout gui/$(id -u)/ai.aastar.aoa-watcher`);
  2. set aside, under a new `manual-quarantine/` directory in the data directory
     (keep everything as evidence; the watcher does not read it), each into its
     own subdirectory so no file overwrites another:
     - `records/<record id>.json` to `manual-quarantine/records/`;
     - `holds/<record id>.json` to `manual-quarantine/holds/`;
     - every file under `deadletters/` that belongs to the record's transaction
       (its `txHash`; a dead letter keeps the classified record and is retried
       before the scan, so it would write the old record back) to
       `manual-quarantine/deadletters/`;
     - `publications/<record id>.json` to `manual-quarantine/publications/` if
       it carries a `cid` (a journal committed to the old bytes would stop the
       new record as a bytes-change incident); a journal without `cid`, e.g. one
       that only holds `holdRearms`, can stay;
     - for a BLS record, `amendments/bls-<key>.json` and every file whose name
       starts with it (`.conflict.*`, `.invalid.*`; `<key>` is the 64 hex digits
       at the end of the record id) to `manual-quarantine/amendments/`. Nothing
       publishes or alerts from these files: they hold SP effects proven for the
       action after its record was written, and are only counted in
       `status.json`. They came from the same wrong primary, though, and a later
       correct proof for the action would be stored as a conflict against them;
       set aside, the corrected proof is written as the only one;
  3. fix or replace the primary (Keychain item `aoa-dvt-rpc-primary`);
  4. rewind `cursor.json` to the block before the record's block, B:
     `{"block": <B-1>, "hash": "<hash of block B-1 from a trusted source>"}`.
     The watcher checks that hash against its RPC and refuses to scan on a
     mismatch, so a wrong hash stops the tick instead of skipping anything. The
     scan then starts at block B; rescanning creates no duplicates; the blocks
     from B on are read again, at most `maxBlocksPerTick` per tick;
  5. start the watcher (`launchctl bootstrap …`). The record is written again
     and goes through D-RPC2 like any new one. There is no tool for steps 2 and
     4 yet.
- **Already on chain.** An accusation reaches DisclosureRegistry only after both
  providers agreed, so a wrong entry means both were wrong (not defended, M0
  §5.5a item 5). Its claim fields are corrected with the registry's `amend` from
  the sender key; an entry cannot be deleted, and readers take the latest
  `Amended` and recheck it (M0 §5.5a). There is no amend tool in this repository
  yet.

## After a registry switch: a record waits for a nonce, or a nonce gap (W2d)

**How it shows.** One of two degraded reasons:

- `N record(s) wait after a registry switch for the writer's nonce(s) n to be consumed at the finalized block`:
  `publish.registry` changed while a disclose of the same writer, on the same
  chain, was still in flight. The record discloses again on the new registry
  only once nonce `n` is used, so the writer's nonces stay contiguous. Nothing
  is rebroadcast or re-priced meanwhile. Usually this clears by itself: the old
  transaction is mined.
- `writer nonce(s) n pending or skipped but held by no journal`: a nonce of the
  writer is in a mempool, or was skipped below a journalled one, and no record's
  current stage holds it. Example: the writer was switched away and back while
  an old transaction was pending.

**If it does not clear.** It stays this way when the old transaction was evicted
and nothing will ever use the nonce. There are two ways out:

1. **Preferred: a new writer (M0 §5.5a recovery).** A new writer has its own
   nonce space, so after the switch nothing waits.
2. **For one stuck nonce: `fill-nonce`.** It sends one 0-value transfer from the
   writer to itself at nonce `n` and touches no registry. It refuses:
   - a nonce held by a stage on the current registry;
   - a nonce that no record waits for and that is not a reported gap;
   - a consumed nonce;
   - a nonce whose old transaction a node still knows (wait for that one).

   It needs the watcher stopped and `RPC_URL` set, as for the watcher. It
   journals every run in `<dataDir>/nonce-fills.json`: `pending` before signing,
   the hash before the broadcast, then `applied`. Run it again to settle an
   interrupted run.

```sh
launchctl bootout gui/$(id -u)/ai.aastar.aoa-watcher
RPC_URL="$(security find-generic-password -a aoa-watcher -s aoa-dvt-rpc-primary -w)" \
  node $REPO/deploy/guardian-watcher/fill-nonce.mjs --config ~/.aoa-watcher/config.json \
  --nonce <n> --reason "<why, one plain line, no URL>"
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/ai.aastar.aoa-watcher.plist
```

Once the fill is consumed at the finalized block, the waiting record is archived
and disclosed again on the new registry as usual.
