// Committee liveness health check — the thing that was missing when tier-2/3 went down for ten hours.
//
// WHY THIS EXISTS
// ---------------
// On 2026-08-30 the committee validator sat with `committeeActive() == true` and `requiredQuorum()`
// returning the unsatisfiable sentinel for about ten hours. Accounts had already switched to the
// committee decode path, so tier-2/3 was failing closed on every stack mounted on that validator,
// while every dashboard-friendly getter looked fine. The underlying bug was nine lines (the keeper
// called a `snapshotEpoch` ABI the deployed contract did not have, #249). It did not take ten hours
// because it was subtle. It took ten hours because NOTHING WAS WATCHING.
//
// This check is deliberately INDEPENDENT of the keeper: the keeper being dead, wedged, or calling the
// wrong ABI is precisely the condition being detected, so a warning emitted from inside the keeper's
// own loop would have been silent for exactly the same ten hours. Run it from cron/monitoring.
//
// THE SENTINEL IS A CONJUNCTION, AND THAT MATTERS TWICE
// ----------------------------------------------------
// `requiredQuorum()` returns the sentinel when ANY of these fails (AAStarCommitteeValidator:633-646):
//
//     epochPinned[e]                              epochPinned[e-1]
//     epochConfigVersion[e]  == configVersion     ... same for e-1
//     block.timestamp < epochSetValidUntil[e]     ... same for e-1     (D2 only)
//     epochSetCount[e-1] >= minCommittee                               (D2 only, CC-97 floor)
//
// Reading only the sentinel loses nothing in DETECTION but everything in ATTRIBUTION: a configVersion
// bump (five call sites: :225 :263 :277 :285 :300) instantly makes BOTH epochs stale, and an operator
// woken at 3am would be sent to "check the keeper's snapshotEpoch ABI" — the cause of the LAST
// incident, not this one. So every conjunct is read and the failing one is named.
//
// It matters a second time, and this is the part that would have made the tool useless. Pre-D2's
// `requiredQuorum()` only consults e-1, so the current epoch being unpinned is harmless. D2 (:643)
// requires `_epochUsable(e) && _epochUsable(e-1)`, so during the keeper's ordinary pin latency —
// measured at ~4-5 blocks of every 64, about a 7% duty cycle — D2 returns the sentinel while nothing
// is actually wrong. Paging 7% of the time is how you train an operator to ignore the alert, and
// alert fatigue is what the ten-hour outage was made of. So a sentinel whose ONLY failing conjunct is
// "the current epoch is not pinned yet, and it is still inside its window" is a WARN, not a page:
// e-1 still serves every payload in that state. Anything else is a real page.
//
// Exit codes: 0 healthy/warn, 1 alert, 2 could not determine (RPC/config).
// PAGE ON ANY NON-ZERO EXIT. A 2 is not "fine": a cron started in the wrong directory, or a dead RPC,
// exits 2 forever and reports nothing — which is the same silence this tool exists to end.
//
// env file (default: .env.sepolia at the REPO ROOT relative to this script, NOT the caller's cwd, so a
// cron started anywhere still finds it). With --env the file wins over the environment; without it the
// environment wins over the default file -- explicit beats implicit, whichever side is explicit.
//   SEPOLIA_RPC_URL / ETH_RPC_URL / RPC_URL, COMMITTEE_VALIDATOR (optional)
// Any of those three names is also read from the process environment.
// Usage:
//   node deploy/committee-health.mjs
//   node deploy/committee-health.mjs --json          (one line of JSON, on EVERY path including errors)
//   node deploy/committee-health.mjs --router 0x…      (derive the validator from algId 0x01)
//   node deploy/committee-health.mjs --validator 0x… --env ../SuperPaymaster/.env.sepolia
//   node deploy/committee-health.mjs --expect-armed   (epochLength == 0 becomes CRITICAL, not OK;
//                                                      also via EXPECT_COMMITTEE_ACTIVE=true)
import { ethers } from "ethers";
import { readFileSync } from "fs";
import { dirname, resolve } from "path";
import { fileURLToPath } from "url";

const SENTINEL = (1n << 256n) - 1n;
const BLOCKHASH_WINDOW = 256n;
const HERE = dirname(fileURLToPath(import.meta.url));

const argv = process.argv.slice(2);
// Guarded: a bare trailing `--validator`, or `--env --json`, must not silently consume the next flag
// (or undefined) as its value and then report OK against the hard-coded default address.
const flag = n => {
  const i = argv.indexOf(n);
  if (i === -1) return undefined;
  const v = argv[i + 1];
  if (v === undefined || v.startsWith("--")) {
    // --json is an invariant of EVERY exit path, including this one. It is checked directly off argv
    // rather than via JSON_OUT because this guard can run before that binding is initialised.
    const msg = `${n} requires a value`;
    if (argv.includes("--json"))
      process.stdout.write(JSON.stringify({ status: "UNKNOWN", summary: msg }) + "\n");
    else console.error(`\n✗ ${msg}`);
    process.exit(2);
  }
  return v;
};
const JSON_OUT = argv.includes("--json");
// Resolved against THIS FILE's directory, not the caller's cwd: a cron launched from anywhere would
// otherwise miss the env file and exit 2 forever, which is a silent monitor.
const ENV_FILE_EXPLICIT = flag("--env") || process.env.DVT_ENV_FILE;
const ENV_FILE = ENV_FILE_EXPLICIT || resolve(HERE, "..", ".env.sepolia");

const strip = s => s.replace(/^["']|["']$/g, "");
let env = {};
try {
  env = Object.fromEntries(
    readFileSync(ENV_FILE, "utf8")
      .split("\n")
      .filter(l => l.includes("=") && !l.trim().startsWith("#"))
      .map(l => {
        const i = l.indexOf("=");
        return [l.slice(0, i).trim(), strip(l.slice(i + 1).trim())];
      })
  );
} catch {
  /* an env file is optional when --validator and an ambient RPC are supplied */
}

// Every alias the docs promise, from BOTH sources. The process environment previously honoured only
// SEPOLIA_RPC_URL while the file honoured all three, so `ETH_RPC_URL=… node …` exited 2 "no RPC url"
// despite the header advertising it.
//
// Precedence is EXPLICIT-BEATS-IMPLICIT, symmetric on both sides, because either one can be the
// deliberate instruction:
//   --env <path> given  -> the FILE wins. The operator named it; a stale exported variable must not
//                          silently redirect the run (the fork-vs-Sepolia trap from #248).
//   no --env given      -> the ENVIRONMENT wins. The default file is an implicit convenience, and a
//                          repo that happens to contain .env.sepolia must not quietly override an
//                          RPC the operator set on purpose. Found by testing: with the default file
//                          present, `SEPOLIA_RPC_URL=<broken> node …` reported OK against the real
//                          chain -- the run was not measuring what the command said.
const pick = (...names) =>
  names
    .map(n => (ENV_FILE_EXPLICIT ? env[n] || process.env[n] : process.env[n] || env[n]))
    .find(Boolean);
const RPC = pick("SEPOLIA_RPC_URL", "ETH_RPC_URL", "RPC_URL");
// Opt-in: assert that this validator is supposed to have committee mode ON. See the epochLength == 0
// branch for why the default cannot be "always expect armed" -- an unmounted candidate legitimately
// sits at 0.
const expectArmed =
  argv.includes("--expect-armed") ||
  /^(1|true|yes)$/i.test(process.env.EXPECT_COMMITTEE_ACTIVE || "");
// Prefer naming the STACK, not the address. A router's algId 0x01 is what actually decides which
// validator an account stack uses, so deriving from it means the check can never end up watching a
// contract the stack does not use -- the failure this file's own header predicted ("mount a different
// committee validator and this workflow keeps reporting green about a contract nobody uses") and
// which came true the day v0.33.0 shipped: the scheduled run was still pinned to the previous stack's
// validator by a repository variable nobody remembered to move.
//
// An explicit --validator still wins, for probing a candidate that no stack mounts yet.
const ROUTER = flag("--router") || process.env.COMMITTEE_ROUTER || env.COMMITTEE_ROUTER;
// A validator from the COMMAND or the ENVIRONMENT is a deliberate act and outranks a router. One
// left behind in an env FILE is not: deleting the repository variable does not reach a stale
// .env.sepolia sitting next to a developer, and letting that silently win would reintroduce exactly
// the "pinned to an address nobody mounts" failure this change exists to remove -- only harder to
// see, because the router would appear configured.
const VALIDATOR_FROM_FILE = env.COMMITTEE_VALIDATOR;
const VALIDATOR_EXPLICIT =
  flag("--validator") ||
  process.env.COMMITTEE_VALIDATOR ||
  (ROUTER ? undefined : VALIDATOR_FROM_FILE);
// The default applies ONLY when no router was asked for. Every emit() stamps the current VALIDATOR
// into its report, and that default is 0x1A8Db639 -- the RETIRED pre-D2 validator. If a router was
// requested, the honest value until it resolves is "unknown": an alert reading
// `"validator":"0x1A8Db639…"` next to a summary saying the router could not be read tells the reader
// this heartbeat is watching the retired stack, which is a monitor lying about its own observation
// target. Cleared HERE rather than inside the router branch, because failures BEFORE that branch --
// "no RPC url" is the common one -- emit too, and the earlier fix only covered the later path.
let VALIDATOR = VALIDATOR_EXPLICIT || (ROUTER ? null : "0x1A8Db639b5d8Bd5742edB083656EDD56f416cd64");

const ABI = [
  "function epochLength() view returns (uint256)",
  "function committeeActive() view returns (bool)",
  "function requiredQuorum() view returns (uint256)",
  "function epochPinned(uint256) view returns (bool)",
  "function epochConfigVersion(uint256) view returns (uint256)",
  "function epochSetCount(uint256) view returns (uint256)",
  "function configVersion() view returns (uint256)",
  "function activeCount() view returns (uint256)",
  // D2-only below; absence is detected, never assumed.
  "function minCommittee() view returns (uint256)",
  "function epochSetValidUntil(uint256) view returns (uint64)",
];

const out = [];
const say = s => out.push(s);

// In --json mode stdout must carry EXACTLY one line of JSON and nothing else. ethers writes its own
// chatter straight to stdout -- "JsonRpcProvider failed to detect network and cannot start up; retry
// in 1s ..." -- on precisely the RPC failures a monitor is most likely to hit. Our JSON was already
// correct and the exit code was already 2, but that stray line made the stream unparseable, so an
// agent's JSON.parse threw and a pipeline grepping for CRITICAL read the empty result as "not
// critical". Found by separating stdout from stderr in the test, not by reading the code.
const realLog = console.log;
if (JSON_OUT) console.log = () => {};
const emitLine = s => process.stdout.write(s + "\n");

function emit(status, code, summary, detail = {}) {
  if (JSON_OUT) emitLine(JSON.stringify({ status, validator: VALIDATOR, summary, ...detail }));
  else {
    say(`\n${status}: ${summary}`);
    realLog(out.join("\n"));
  }
  process.exit(code);
}

/// Read a D2-only view. A contract that does not implement it returns empty calldata, which ethers
/// surfaces as BAD_DATA/CALL_EXCEPTION; anything else (429, timeout, gateway error) is a TRANSPORT
/// failure and must NOT be reported as "this is a pre-D2 contract". Inferring a contract generation
/// from an error with several possible causes is how a flaky RPC gets printed as a fact.
async function optional(call) {
  try {
    return { present: true, value: await call() };
  } catch (e) {
    const c = e.code;
    if (c === "BAD_DATA" || c === "CALL_EXCEPTION") return { present: false, value: null };
    throw e;
  }
}

async function main() {
  if (!RPC) {
    emit(
      "UNKNOWN",
      2,
      `no RPC url (looked for SEPOLIA_RPC_URL/ETH_RPC_URL/RPC_URL in ${ENV_FILE} and the environment)`
    );
  }
  const provider = new ethers.JsonRpcProvider(RPC);

  // Resolve the router BEFORE the validator contract is bound. Binding first and reassigning
  // VALIDATOR afterwards changes only the STRING -- an ethers.Contract keeps the address it was
  // constructed with -- so every read would still hit the old hard-coded address while getCode and
  // the printed output showed the new one. That is worse than the drift this PR fixes: the previous
  // version watched the wrong contract but SAID SO, and that honest label is how the drift was
  // spotted at all.
  if (ROUTER && !VALIDATOR_EXPLICIT) {
    // VALIDATOR is already null here (see its declaration): with a router requested, the default is
    // never adopted in the first place.
    if (!ethers.isAddress(ROUTER))
      emit("UNKNOWN", 2, `COMMITTEE_ROUTER is not an address: ${ROUTER}`);
    try {
      const r = new ethers.Contract(
        ROUTER,
        ["function getAlgorithm(uint8) view returns (address)"],
        provider
      );
      const derived = await r.getAlgorithm(1);
      if (derived === ethers.ZeroAddress) {
        emit("UNKNOWN", 2, `router ${ROUTER} has no algorithm mounted at 0x01 — nothing to watch`);
      }
      VALIDATOR = derived;
      say(`router     ${ROUTER}  ->  algId 0x01`);
      // Say it HERE, not in the branch below. This is the path where an env-file COMMITTEE_VALIDATOR
      // actually loses -- VALIDATOR_EXPLICIT already excluded it once ROUTER exists, so the message
      // in the else-if can never be reached for this case. The whole thread this change comes from is
      // "a silent precedence change misled someone"; leaving the mitigation in an unreachable branch
      // would have kept one silence in the fix for the silence.
      if (VALIDATOR_FROM_FILE) {
        say(
          `           (${ENV_FILE} sets COMMITTEE_VALIDATOR=${VALIDATOR_FROM_FILE}; the router won)`
        );
      }
    } catch (e) {
      emit(
        "UNKNOWN",
        2,
        `could not read getAlgorithm(0x01) from router ${ROUTER}: ${e?.shortMessage ?? e?.message ?? String(e)}`
      );
    }
  } else if (ROUTER && VALIDATOR_EXPLICIT) {
    say(`router     ${ROUTER} ignored — an explicit validator was given`);
    if (VALIDATOR_FROM_FILE && VALIDATOR_FROM_FILE !== VALIDATOR_EXPLICIT) {
      say(
        `           (${ENV_FILE} also sets COMMITTEE_VALIDATOR=${VALIDATOR_FROM_FILE}; it lost to the explicit one)`
      );
    }
  }

  // Bound AFTER resolution, and from the same variable that gets reported, so "what it reads" and
  // "what it says" cannot diverge.
  const v = new ethers.Contract(VALIDATOR, ABI, provider);

  if ((await provider.getCode(VALIDATOR)) === "0x")
    emit("UNKNOWN", 2, `no code at ${VALIDATOR} on this chain`);

  // Pin EVERY read to one block. Sampling `requiredQuorum()` at block N and `epochPinned` at N+1 can
  // straddle a pin and produce a self-contradictory report — precisely at the boundary this tool is
  // supposed to reason about.
  const blockTag = await provider.getBlockNumber();
  const at = { blockTag };
  const bn = BigInt(blockTag);

  const [epochLength, active, configVersion, activeCount] = await Promise.all([
    v.epochLength(at),
    v.committeeActive(at),
    v.configVersion(at),
    v.activeCount(at),
  ]);
  say(`validator       ${VALIDATOR}`);
  say(`block           ${bn}`);
  say(`committeeActive ${active}`);
  say(`epochLength     ${epochLength}`);
  say(`activeCount     ${activeCount}`);

  if (epochLength === 0n) {
    // Whether this is fine depends entirely on whether this validator is SUPPOSED to be armed, and
    // only the caller knows that. Reporting OK unconditionally means that if committee mode is ever
    // switched off by mistake on a mounted validator, this checker goes quiet -- while the account
    // layer's CC-116 gate makes tier-2/3 fail closed for every account on it. Silence identical to
    // health, one level below the one the header already names.
    //
    // Default stays OK so an unmounted candidate (epochLength 0 by design) is not a false alarm; the
    // scheduled watch sets EXPECT_COMMITTEE_ACTIVE because the validator it watches IS armed; a
    // workflow_dispatch at another address explicitly does not, since that address may be a candidate
    // that is meant to sit at 0.
    if (expectArmed) {
      emit(
        "CRITICAL",
        1,
        "committee mode is OFF (epochLength == 0) on a validator expected to be ARMED — every account mounted here has tier-2/3 failing closed",
        {
          block: blockTag,
          committeeActive: active,
          epochLength: 0,
          expectArmed: true,
        }
      );
    }
    emit("OK", 0, "committee mode is OFF (epochLength == 0) — nothing is being served", {
      block: blockTag,
      committeeActive: active,
      epochLength: 0,
      expectArmed: false,
    });
  }

  const e = bn / epochLength;
  if (e === 0n) {
    // The contract returns the sentinel for e == 0 too, but this script reads epoch e-1 first, and
    // -1 does not encode as uint256 -- it would throw before reaching that. Only possible below block
    // `epochLength`, i.e. a fresh devnet.
    emit(
      "UNKNOWN",
      2,
      `chain height ${bn} is inside epoch 0; requiredQuorum() is the sentinel by definition and there is no epoch e-1 to read`,
      { block: blockTag, epoch: 0 }
    );
  }
  const start = e * epochLength;
  // The pin deadline is NOT start+256. `snapshotEpoch` requires block.number <= start + 256 AND
  // recomputes e = block.number / epochLength, so it stops accepting the moment the epoch ends:
  // start + min(256, epochLength - 1). Matches the contract's own note at :192.
  const deadline =
    start + (epochLength - 1n < BLOCKHASH_WINDOW ? epochLength - 1n : BLOCKHASH_WINDOW);
  // Three states, not two. At the epoch's FIRST block the window has not opened yet (the guard is
  // `bn > start`); conflating that with having missed it fires a false CRITICAL every epoch boundary.
  // pastWindow needs epochLength >= 258 to be reachable at all (inside epoch e, bn <= start+L-1), so
  // at today's L=64 it cannot fire — the sentinel classification below is the early warning, not this.
  const beforeWindow = bn <= start;
  const pastWindow = bn > deadline;

  const [quorum, minC, ...rest] = await Promise.all([
    v.requiredQuorum(at),
    optional(() => v.minCommittee(at)),
    v.epochPinned(e, at),
    v.epochPinned(e - 1n, at),
    v.epochConfigVersion(e, at),
    v.epochConfigVersion(e - 1n, at),
    v.epochSetCount(e - 1n, at),
    optional(() => v.epochSetValidUntil(e, at)),
    optional(() => v.epochSetValidUntil(e - 1n, at)),
  ]);
  const [pinnedE, pinnedPrev, cfgE, cfgPrev, setCountPrev, validUntilE, validUntilPrev] = rest;
  const now = BigInt((await provider.getBlock(blockTag)).timestamp);
  // Two DIFFERENT probes, deliberately not one. `isD2` asks a GENERATION question -- does this
  // contract's requiredQuorum consult epoch e as well as e-1 -- and answers it via minCommittee()'s
  // presence. `usable()` below asks a FIELD question about epochSetValidUntil and probes that field
  // directly. Neither implies the other, and a future contract could carry one without the other, so
  // do not collapse them into a single "is this D2" flag.
  const isD2 = minC.present;

  // Rebuild _epochUsable locally so the failing conjunct can be named. D2-only terms are simply true
  // on a pre-D2 contract, which is exactly its semantics.
  const usable = (pinned, cfg, validUntil) =>
    pinned && cfg === configVersion && (!validUntil.present || now < BigInt(validUntil.value));
  const usableE = usable(pinnedE, cfgE, validUntilE);
  const usablePrev = usable(pinnedPrev, cfgPrev, validUntilPrev);
  const floorOk = !isD2 || setCountPrev >= minC.value;

  // The e-side conjuncts exist ONLY in D2's requiredQuorum (:643 checks _epochUsable(e) AND (e-1));
  // pre-D2 consults e-1 alone. Listing "epoch e is not pinned" against the pre-D2 contract that is
  // actually deployed would name a term that generation's formula does not contain -- and attribution
  // is the entire point of reading the conjuncts instead of just the sentinel.
  const why = [];
  if (isD2 && !pinnedE) why.push(`epoch ${e} is not pinned`);
  if (isD2 && pinnedE && cfgE !== configVersion)
    why.push(`epoch ${e} was pinned under configVersion ${cfgE}, now ${configVersion}`);
  if (isD2 && pinnedE && validUntilE.present && now >= BigInt(validUntilE.value))
    why.push(`epoch ${e}'s snapshot expired at ${validUntilE.value}`);
  if (!pinnedPrev) why.push(`epoch ${e - 1n} is not pinned`);
  if (pinnedPrev && cfgPrev !== configVersion)
    why.push(`epoch ${e - 1n} was pinned under configVersion ${cfgPrev}, now ${configVersion}`);
  if (pinnedPrev && validUntilPrev.present && now >= BigInt(validUntilPrev.value))
    why.push(`epoch ${e - 1n}'s snapshot expired at ${validUntilPrev.value}`);
  if (!floorOk)
    why.push(`frozen set of epoch ${e - 1n} is ${setCountPrev}, below minCommittee ${minC.value}`);

  say(`epoch           ${e}  (starts ${start}, pinnable through ${deadline})`);
  say(
    `  epoch ${e}     pinned=${pinnedE} cfg=${cfgE}${validUntilE.present ? ` validUntil=${validUntilE.value}` : ""} usable=${usableE}`
  );
  say(
    `  epoch ${e - 1n} pinned=${pinnedPrev} cfg=${cfgPrev}${validUntilPrev.present ? ` validUntil=${validUntilPrev.value}` : ""} usable=${usablePrev} setCount=${setCountPrev}`
  );
  say(`configVersion   ${configVersion}`);
  say(`minCommittee    ${isD2 ? minC.value : "n/a (pre-D2 validator: no CC-97 floor)"}`);
  say(`requiredQuorum  ${quorum === SENTINEL ? "SENTINEL (unsatisfiable)" : quorum}`);

  const detail = {
    block: blockTag,
    epoch: Number(e),
    epochLength: Number(epochLength),
    generation: isD2 ? "d2" : "pre-d2",
    pinnedCurrent: pinnedE,
    pinnedPrevious: pinnedPrev,
    usableCurrent: usableE,
    usablePrevious: usablePrev,
    beforeWindow,
    pastWindow,
    configVersion: Number(configVersion),
    requiredQuorum: quorum === SENTINEL ? "sentinel" : Number(quorum),
    activeCount: Number(activeCount),
    minCommittee: isD2 ? Number(minC.value) : null,
    failingConjuncts: why,
  };

  if (quorum === SENTINEL) {
    // The one benign sentinel: on D2 the current epoch simply has not been pinned yet and is still
    // inside its window, while e-1 still serves every payload. That is the keeper's normal latency
    // (~4-5 blocks in 64), not an incident. Paging on it would be a 7% duty cycle.
    // Gated on isD2 to match its own argument: the exemption exists because D2 requires _epochUsable(e),
    // so an unpinned current epoch alone turns the sentinel on. Pre-D2 never produces a sentinel from
    // that state (verified on the live contract: it returns 2), so a sentinel there is never benign.
    // `!beforeWindow` USED TO BE A CONJUNCT HERE, and dropping it is a fix, not a loosening.
    // beforeWindow means bn == start: the epoch's very FIRST block, where the contract's own guard is
    // `bn > start`, so epoch e cannot have been pinned by anyone. The sentinel there is structurally
    // unavoidable, nobody can act on it, and it clears in one block (~12s). Excluding that state from
    // the exemption paged CRITICAL once per epoch boundary -- 1 block in 64, so roughly one false page
    // every few hours at a 15-minute sampling interval, which is the alert fatigue this whole file is
    // built to avoid. The comment on `beforeWindow` above already made exactly this argument
    // ("conflating that with having missed it fires a false CRITICAL every epoch boundary"); it was
    // applied to the pastWindow branch and not to this one, so the boundary still paged, just from a
    // different branch. Observed live: block 11605312 == epoch 181333 * 64, pinned five blocks later.
    const onlyPendingPin = isD2 && !usableE && usablePrev && floorOk && !pinnedE && !pastWindow;
    if (onlyPendingPin) {
      emit(
        "WARN",
        0,
        beforeWindow
          ? `epoch ${e} cannot be pinned yet: block ${bn} is the epoch's first block and snapshotEpoch requires bn > ${start}. The window opens next block and closes at ${deadline}; epoch ${e - 1n} still serves. Structural, not an incident.`
          : `epoch ${e} is not pinned yet but is still inside its window (pinnable through ${deadline}); epoch ${e - 1n} still serves. Normal keeper latency.`,
        detail
      );
    }
    emit(
      "CRITICAL",
      1,
      `committee is ACTIVE but requiredQuorum() is the unsatisfiable sentinel — tier-2/3 is failing closed right now on every account stack mounted here. Failing: ${why.join("; ") || "unknown (all conjuncts read as satisfied — re-check against the contract)"}`,
      detail
    );
  }
  if (!pinnedE && pastWindow) {
    emit(
      "CRITICAL",
      1,
      `epoch ${e} is unpinned and block ${bn} is past its pin deadline ${deadline} — it can no longer be pinned. The keeper missed this window.`,
      detail
    );
  }
  if (!pinnedE && beforeWindow) {
    emit(
      "OK",
      0,
      `epoch ${e} just started at block ${start}; its pin window opens at ${start + 1n}`,
      detail
    );
  }
  if (!pinnedE) {
    emit(
      "WARN",
      0,
      `epoch ${e} is not pinned yet, but block ${bn} is still inside the pin window`,
      detail
    );
  }
  emit(
    "OK",
    0,
    `committee armed and satisfiable: requiredQuorum ${quorum} over ${activeCount} active nodes`,
    detail
  );
}

main().catch(e => {
  // --json must hold on EVERY path, and this is the path most likely to be taken in anger: any RPC
  // blip landed here and printed three lines of prose, so an agent's JSON.parse threw and a pipeline
  // grepping for CRITICAL read the empty result as "not critical" — the silent-monitor failure this
  // whole file exists to prevent, occurring in the monitor itself.
  const summary = e.shortMessage ?? e.message;
  if (JSON_OUT) emitLine(JSON.stringify({ status: "UNKNOWN", validator: VALIDATOR, summary }));
  else {
    say(`\nUNKNOWN: ${summary}`);
    realLog(out.join("\n"));
  }
  process.exit(2);
});
