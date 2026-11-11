// Phase D "watcher-job binding" predicate (Codex R6, R7, R8): is the running launchd job exactly the
// configured wrapper, and is that wrapper byte-for-byte this checkout's run-watcher.sh template with
// only its two placeholders filled (config = Phase D's watcherConfig, entry = this checkout's
// watcher.mjs)? Text matching line by line is not enough (R8: an `exec sleep` before the expected
// lines, a here-document around them, or a later reassignment all kept matching), so the wrapper must
// EQUAL the canonical rendering. The template reads the RPC URLs from fixed Keychain items; the
// Phase D config must name those same items. Pure: launchctl output, file texts and paths come in.
// Self-test: node deploy/guardian-watcher/check-phase-d-binding.mjs

/** program, argv and pid as `launchctl print` shows them. */
export function parseLaunchd(out) {
  const program = out.match(/^\s*program = (.+)$/m)?.[1]?.trim() ?? null;
  const block = out.match(/^\s*arguments = \{\n([\s\S]*?)\n\s*\}/m)?.[1] ?? "";
  const argv = block
    .split("\n")
    .map(x => x.trim())
    .filter(Boolean);
  const pid = Number(out.match(/^\s*pid = (\d+)$/m)?.[1]);
  return { program, argv, pid: Number.isSafeInteger(pid) && pid > 0 ? pid : null };
}

/**
 * The LIVE process (Codex R9): the job's pid must be the watcher itself, i.e. the wrapper's final
 * exec happened. Its command line must be exactly `node <entry> --config <config>`, and its
 * environment must hold RPC_URL and RPC_URL_2 equal to the Keychain values Phase D verified. This
 * catches what file checks cannot: a bash startup injection (BASH_ENV) that never reaches the
 * wrapper, and a wrapper or symlink replaced after the job started. Values are compared in memory and
 * never returned; only fixed wording is.
 * @param psCommand `ps -ww -o command= -p <pid>`; psEnv `ps -E -ww -o command= -p <pid>`
 */
export function liveProblems({
  pid,
  psCommand,
  psEnv,
  wantEntry,
  wantConfig,
  rpcPrimary,
  rpcSecondary,
}) {
  if (!pid) return ["the watcher job has no pid"];
  if (typeof psCommand !== "string" || typeof psEnv !== "string")
    return ["the watcher process cannot be inspected"];
  const problems = [];
  const argv = psCommand.trim().split(/ +/);
  if (
    !SAFE_PATH.test(wantEntry ?? "") ||
    !SAFE_PATH.test(wantConfig ?? "") ||
    argv.length !== 4 ||
    !/(^|\/)node$/.test(argv[0]) ||
    argv[1] !== wantEntry ||
    argv[2] !== "--config" ||
    argv[3] !== wantConfig
  )
    problems.push(
      "the running process is not the watcher with this config (wrapper never reached its exec?)"
    );
  // the environment follows the command line in ps -E output
  if (!psEnv.startsWith(psCommand.trim())) problems.push("the watcher process cannot be inspected");
  else if (!rpcPrimary || !rpcSecondary)
    problems.push("RPC URLs not in the Keychain: the process environment is not checkable");
  else {
    const env = psEnv.trim().slice(psCommand.trim().length).trim().split(/ +/);
    const one = (k, v) => {
      const hits = env.filter(t => t.startsWith(`${k}=`));
      return hits.length === 1 && hits[0] === `${k}=${v}`;
    };
    if (!one("RPC_URL", rpcPrimary) || !one("RPC_URL_2", rpcSecondary))
      problems.push("the running watcher's RPC URLs are not the Keychain items Phase D verified");
  }
  return problems;
}

// a value placed between double quotes in the wrapper: no shell expansion, no quote, no newline
const SAFE_PATH = /^\/[A-Za-z0-9._\-/]+$/;

/** The wrapper Phase D accepts, or null when a value cannot be placed safely. */
export function canonicalWrapper(template, { config, entry }) {
  if (!SAFE_PATH.test(config ?? "") || !SAFE_PATH.test(entry ?? "")) return null;
  // only the two assignment lines are filled; every other byte (comments included) stays the template's
  const C = 'WATCHER_CONFIG="__WATCHER_CONFIG__"';
  const E = 'WATCHER_ENTRY="__WATCHER_ENTRY__"';
  const lines = template.split("\n");
  if (lines.filter(l => l === C).length !== 1 || lines.filter(l => l === E).length !== 1)
    return null;
  return lines
    .map(l => (l === C ? `WATCHER_CONFIG="${config}"` : l === E ? `WATCHER_ENTRY="${entry}"` : l))
    .join("\n");
}

/** The Keychain service names the template reads, in order (RPC_URL, RPC_URL_2), and its account. */
export function templateKeychain(template) {
  const m = [
    ...template.matchAll(
      /^(RPC_URL|RPC_URL_2)="\$\(security find-generic-password -s ([A-Za-z0-9._-]+) -a ([A-Za-z0-9._-]+) -w\)"$/gm
    ),
  ];
  const a = m.find(x => x[1] === "RPC_URL");
  const b = m.find(x => x[1] === "RPC_URL_2");
  if (m.length !== 2 || !a || !b || a[3] !== b[3]) return null;
  return { rpcPrimary: a[2], rpcSecondary: b[2], account: a[3] };
}

/**
 * @returns {string[]} problems, empty when bound. Fixed wording; nothing from the inputs is echoed.
 */
export function bindingProblems({
  program,
  argv,
  wrapper,
  text,
  template,
  wantConfig,
  wantEntry,
  services,
  account,
}) {
  const problems = [];
  // the executable AND the whole argument list form one allowed invocation (Codex R7 #1): the
  // wrapper itself with no arguments, or /bin/bash running it; an argv naming the wrapper never
  // excuses a different program (Program=/bin/sleep, ProgramArguments=[wrapper, ...] fails)
  const direct = program === wrapper && argv.length === 1 && argv[0] === wrapper;
  const viaBash =
    program === "/bin/bash" &&
    argv.length === 2 &&
    (argv[0] === "/bin/bash" || argv[0] === "bash") &&
    argv[1] === wrapper;
  if (!direct && !viaBash) problems.push("the job does not run exactly the configured wrapper");
  if (typeof template !== "string") {
    problems.push("this checkout's run-watcher.sh template unreadable");
    return problems;
  }
  // the Phase D config names the very Keychain items the template reads (Codex R7 #2)
  const kc = templateKeychain(template);
  if (
    !kc ||
    services?.rpcPrimary !== kc.rpcPrimary ||
    services?.rpcSecondary !== kc.rpcSecondary ||
    account !== kc.account
  )
    problems.push("Phase D's RPC Keychain items are not the ones the wrapper reads");
  if (typeof text !== "string") {
    problems.push("wrapper unreadable");
    return problems;
  }
  // the whole wrapper is the canonical rendering (Codex R8 #1, #2): config AND entry bound
  const want = canonicalWrapper(template, { config: wantConfig, entry: wantEntry });
  if (want === null)
    problems.push("watcherConfig or the watcher entry cannot be placed in the wrapper");
  else if (text !== want)
    problems.push(
      "wrapper is not this checkout's run-watcher.sh with watcherConfig and this checkout's watcher.mjs"
    );
  return problems;
}
