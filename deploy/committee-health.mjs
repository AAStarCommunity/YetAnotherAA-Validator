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
// WHAT IT ASSERTS
//   - committee OFF (epochLength == 0)          -> healthy: nothing is being served, nothing to break
//   - requiredQuorum() == sentinel while ACTIVE  -> CRITICAL: armed but unsatisfiable. This is the
//     state accounts cannot distinguish, because `committeeActive()` is literally `epochLength != 0`
//     and answers "did anyone set an epoch length", not "can this validator serve a signature today".
//   - current epoch unpinned but still in window -> WARN: the keeper still has time.
//   - current epoch unpinned and PAST its window -> CRITICAL. Only reachable when epochLength > 256;
//     at today's epochLength 64 the sentinel test above is what catches a stopped keeper, roughly one
//     epoch (~13 min) after the last successful pin. See the note at the reachability split below.
//   - epochConfigVersion(e) != configVersion     -> CRITICAL: a reconfiguration invalidated the pin.
//
// Exit codes: 0 healthy, 1 unhealthy (alert on this), 2 could not determine (RPC/config).
// A non-zero exit with no output is impossible: every path prints its reason first.
//
// env file (default .env.sepolia): SEPOLIA_RPC_URL (or ETH_RPC_URL), COMMITTEE_VALIDATOR (optional)
// Usage:
//   node deploy/committee-health.mjs
//   node deploy/committee-health.mjs --json          (one line of JSON for a monitoring agent)
//   node deploy/committee-health.mjs --validator 0x… --env ../SuperPaymaster/.env.sepolia
import { ethers } from "ethers";
import { readFileSync } from "fs";

const SENTINEL = (1n << 256n) - 1n;
const PIN_WINDOW = 256n; // blockhash availability, same constant the keeper and the contract use

const argv = process.argv.slice(2);
const flag = n => {
  const i = argv.indexOf(n);
  return i === -1 ? undefined : argv[i + 1];
};
const JSON_OUT = argv.includes("--json");
const ENV_FILE = flag("--env") || process.env.DVT_ENV_FILE || ".env.sepolia";

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

const RPC = env.SEPOLIA_RPC_URL || env.ETH_RPC_URL || env.RPC_URL || process.env.SEPOLIA_RPC_URL;
const VALIDATOR =
  flag("--validator") ||
  process.env.COMMITTEE_VALIDATOR ||
  env.COMMITTEE_VALIDATOR ||
  "0x1A8Db639b5d8Bd5742edB083656EDD56f416cd64";

// Views common to BOTH validator generations. `minCommittee` is D2-only and read defensively — this
// check must keep working against the pre-D2 contract that is actually deployed.
const ABI = [
  "function epochLength() view returns (uint256)",
  "function committeeActive() view returns (bool)",
  "function requiredQuorum() view returns (uint256)",
  "function epochPinned(uint256) view returns (bool)",
  "function epochConfigVersion(uint256) view returns (uint256)",
  "function configVersion() view returns (uint256)",
  "function activeCount() view returns (uint256)",
  "function minCommittee() view returns (uint256)",
];

const out = [];
const say = s => out.push(s);

function report(status, code, summary, detail) {
  if (JSON_OUT) {
    console.log(JSON.stringify({ status, validator: VALIDATOR, summary, ...detail }));
  } else {
    say(`\n${status}: ${summary}`);
    console.log(out.join("\n"));
  }
  process.exit(code);
}

async function main() {
  if (!RPC) report("UNKNOWN", 2, `no RPC url (looked in ${ENV_FILE}, then the environment)`, {});
  const provider = new ethers.JsonRpcProvider(RPC);
  const v = new ethers.Contract(VALIDATOR, ABI, provider);

  if ((await provider.getCode(VALIDATOR)) === "0x") {
    report("UNKNOWN", 2, `no code at ${VALIDATOR} on this chain`, {});
  }

  const [bn, epochLength, active, configVersion, activeCount] = await Promise.all([
    provider.getBlockNumber().then(BigInt),
    v.epochLength(),
    v.committeeActive(),
    v.configVersion(),
    v.activeCount(),
  ]);
  say(`validator     ${VALIDATOR}`);
  say(`block         ${bn}`);
  say(`epochLength   ${epochLength}`);
  say(`activeCount   ${activeCount}`);

  if (epochLength === 0n) {
    report("OK", 0, "committee mode is OFF (epochLength == 0) — nothing is being served", {
      committeeActive: active,
      epochLength: 0,
    });
  }

  const e = bn / epochLength;
  const start = e * epochLength;
  // Three states, not two. The guard is `bn > start`, so at the epoch's FIRST block the window has not
  // opened yet — that is NOT the same as having missed it, and conflating them fires a false CRITICAL
  // at every single epoch boundary.
  //
  // Reachability, stated plainly rather than implied: while inside epoch e, `bn` is at most
  // `start + epochLength - 1`, so `pastWindow` requires epochLength > PIN_WINDOW (256). Every
  // validator deployed today runs epochLength 64, so THAT BRANCH CANNOT FIRE IN THE CURRENT
  // CONFIGURATION. It is kept because D2 permits epochLength up to 3599 and the branch becomes live
  // the moment anyone sets one above 256 — but the check that actually catches a stopped keeper today
  // is the sentinel test above, which trips one epoch (~13 min at L=64) after the last successful pin.
  // Do not read this branch as the early-warning; the sentinel is.
  const beforeWindow = bn <= start;
  const pastWindow = bn > start + PIN_WINDOW;
  const inWindow = !beforeWindow && !pastWindow;
  const [quorum, pinned, pinnedCfg] = await Promise.all([
    v.requiredQuorum(),
    v.epochPinned(e),
    v.epochConfigVersion(e),
  ]);
  let minCommittee = null;
  try {
    minCommittee = await v.minCommittee();
  } catch {
    /* pre-D2 validator: no CC-97 floor. Reported as such rather than guessed. */
  }

  say(`epoch         ${e}  (starts ${start}, pin window [${start + 1n}, ${start + PIN_WINDOW}])`);
  say(`pinned        ${pinned}${pinned ? ` (configVersion ${pinnedCfg}, current ${configVersion})` : ""}`);
  say(`requiredQuorum${quorum === SENTINEL ? " SENTINEL (unsatisfiable)" : ` ${quorum}`}`);
  say(`minCommittee  ${minCommittee === null ? "n/a (pre-D2 validator: no CC-97 floor)" : minCommittee}`);

  const detail = {
    block: Number(bn),
    epoch: Number(e),
    epochLength: Number(epochLength),
    pinned,
    inWindow,
    beforeWindow,
    pastWindow,
    requiredQuorum: quorum === SENTINEL ? "sentinel" : Number(quorum),
    activeCount: Number(activeCount),
    minCommittee: minCommittee === null ? null : Number(minCommittee),
  };

  // Ordered most-severe first: an armed-but-unsatisfiable validator is already failing user
  // operations, whereas an unpinned epoch is a prediction about the next one.
  if (quorum === SENTINEL) {
    report(
      "CRITICAL",
      1,
      "committee is ACTIVE but requiredQuorum() is the unsatisfiable sentinel — tier-2/3 is failing " +
        "closed right now on every account stack mounted here. Check the keeper: is it running, and " +
        "does it call the snapshotEpoch ABI this validator actually implements (see #249)?",
      detail
    );
  }
  if (pinned && pinnedCfg !== configVersion) {
    report(
      "CRITICAL",
      1,
      `epoch ${e} was pinned under configVersion ${pinnedCfg} but the validator is now at ` +
        `${configVersion} — a reconfiguration invalidated the snapshot and it must be re-pinned`,
      detail
    );
  }
  if (!pinned && pastWindow) {
    report(
      "CRITICAL",
      1,
      `epoch ${e} is unpinned and block ${bn} is PAST its pin window — it can no longer be pinned, so ` +
        `the next epoch's requiredQuorum will be the sentinel. The keeper missed this window.`,
      detail
    );
  }
  if (!pinned && beforeWindow) {
    report("OK", 0, `epoch ${e} just started at block ${start}; its pin window opens at ${start + 1n}`, detail);
  }
  if (!pinned) {
    report("WARN", 0, `epoch ${e} is not pinned yet, but block ${bn} is still inside the pin window`, detail);
  }
  report("OK", 0, `committee armed and satisfiable: requiredQuorum ${quorum} over ${activeCount} active nodes`, detail);
}

main().catch(e => {
  say(`\nUNKNOWN: ${e.shortMessage ?? e.message}`);
  console.log(out.join("\n"));
  process.exit(2);
});
