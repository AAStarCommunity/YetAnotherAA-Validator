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

/** `ps -o lstart=` (LC_ALL=C), local time, whole seconds -> epoch ms, or null. */
export function parseLstart(s) {
  const t = String(s ?? "").trim();
  if (!/^[A-Z][a-z]{2} [A-Z][a-z]{2} +\d{1,2} \d{2}:\d{2}:\d{2} \d{4}$/.test(t)) return null;
  const ms = new Date(t.replace(/ +/g, " ")).getTime();
  return Number.isFinite(ms) ? ms : null;
}

/**
 * The running watcher loaded what Phase D checks (Codex R10): it reads its config and code once at
 * start, so a config, wrapper or watcher source changed after the process started (an honest
 * "edited, forgot to restart") means Phase D validated files the process is not running. Any such
 * file whose mtime is not strictly before the start second fails (same-second is ambiguous: fail).
 * files: [{label, mtimeMs | null}]; a file that cannot be stat'ed fails.
 */
export function staleProblems({ startedAtMs, files }) {
  if (startedAtMs === null || startedAtMs === undefined)
    return ["the watcher process start time cannot be read"];
  const startSec = Math.floor(startedAtMs / 1000);
  const late = files
    .filter(
      f => f.mtimeMs === null || f.mtimeMs === undefined || Math.floor(f.mtimeMs / 1000) >= startSec
    )
    .map(f => f.label);
  return late.length
    ? [`changed after the watcher started (restart it): ${[...new Set(late)].join(", ")}`]
    : [];
}

/**
 * Every file the watcher process loads from the checkout (Codex R11): the transitive closure of
 * RELATIVE static and dynamic imports from the entry, so a shared module outside
 * services/guardian-watcher (scripts/disclosure/recheck-lib.mjs) is covered. Comments are stripped
 * before matching, so a commented-out import does not count. read(path) -> text | null; a module that
 * cannot be read is returned with missing: true (the freshness check then fails on it).
 */
export function importClosure(entry, read, resolveRel) {
  const seen = new Map();
  const todo = [entry];
  while (todo.length) {
    const f = todo.pop();
    if (seen.has(f)) continue;
    const text = read(f);
    seen.set(f, text === null);
    if (text === null) continue;
    const code = text.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:"'`])\/\/.*$/gm, "$1");
    for (const m of code.matchAll(
      /(?:\bfrom\s*|\bimport\s*\(\s*|\bimport\s+)["'](\.{1,2}\/[^"']+)["']/g
    ))
      todo.push(resolveRel(f, m[1]));
  }
  return [...seen].map(([path, missing]) => ({ path, missing }));
}

/**
 * The watcher-publish binding (Codex W2c R11; #413 review N2 follow-up): the watcher that runs must
 * publish, through the keystore and Keychain items Phase D verifies, on the chain Phase D checks.
 * `pc` is the watcher's validated publish config (null when publication is off); `samePath(a, b)`
 * compares two configured paths after expansion. Returns the problems, in fixed wording.
 */
export function publishBindingProblems({ wcfg, pc, cfg, samePath }) {
  const problems = [];
  if (!pc) {
    problems.push("publication is not enabled in the watcher config");
    return problems;
  }
  // samePath is the caller's exact predicate (a placeholder sender.keystore never matches); its
  // exceptions propagate, as before the extraction
  if (!samePath(pc.registry.keystore, cfg.sender?.keystore))
    problems.push("the watcher's registry.keystore is not sender.keystore");
  if (pc.registry.service !== cfg.keychain?.services?.keystorePassword)
    problems.push("the watcher's keystore password item is not keychain.services.keystorePassword");
  if (pc.keychainAccount !== cfg.keychain?.account)
    problems.push("the watcher's keychainAccount is not keychain.account");
  // the watcher refuses to publish without chainId, and signs only for it (#413 review N2): it must
  // be the chain Phase D verifies its RPCs and contracts on
  if (!Number.isSafeInteger(wcfg?.chainId)) problems.push("the watcher config has no chainId");
  else if (wcfg.chainId !== cfg.chainId)
    problems.push("the watcher's chainId is not phase-d.json chainId");
  return problems;
}

/**
 * The mirror deploy key file (DSR: a file, not the ssh-agent): a regular file, mode exactly 0600,
 * owned by the account running the check (the watcher's), and usable without a passphrase
 * (`noPassphrase`: `ssh-keygen -y -P "" -f <key>` succeeded). `st` is lstat-like (a symlink is
 * refused, as it could point anywhere). Returns the problems, in fixed wording.
 */
export function mirrorKeyProblems({ st, uid, noPassphrase }) {
  const problems = [];
  if (!st) return ["the deploy key file is not present"];
  if (st.isSymbolicLink?.()) problems.push("the deploy key path is a symlink");
  else if (!st.isFile?.()) problems.push("the deploy key path is not a regular file");
  const mode = st.mode & 0o777;
  if (mode !== 0o600) problems.push(`mode ${mode.toString(8).padStart(3, "0")}, required 600`);
  if (st.uid !== uid) problems.push("not owned by the watcher's account");
  if (noPassphrase !== true)
    problems.push("not an unencrypted private key ssh can load unattended");
  return problems;
}

/**
 * The mirror's dedicated repository is isolated (DSR): Actions disabled (a pushed workflow cannot
 * run), no Actions secrets, and exactly one branch, the mirror's. `actions` is GitHub's
 * actions/permissions answer, `secrets` actions/secrets, `branches` the branch list (null =
 * unreadable). Returns the problems, in fixed wording.
 */
export function mirrorIsolationProblems({ actions, secrets, branches, branch }) {
  const problems = [];
  if (!actions || typeof actions.enabled !== "boolean")
    problems.push("the repository's Actions settings could not be read");
  else if (actions.enabled !== false) problems.push("GitHub Actions is enabled on the repository");
  if (!secrets || !Number.isSafeInteger(secrets.total_count))
    problems.push("the repository's secrets could not be listed (needs the repository admin's gh)");
  else if (secrets.total_count !== 0) problems.push("the repository has Actions secrets");
  if (!Array.isArray(branches)) problems.push("the repository's branches could not be listed");
  else if (branches.length !== 1 || branches[0]?.name !== branch)
    problems.push(`the repository must have exactly one branch, ${branch}`);
  return problems;
}

/**
 * The dedicated mirror repository's rulesets protect EVERY branch (Codex Phase D R5): at least one
 * repository ruleset (full details, as GET rulesets/<id> returns them) that is active, targets
 * branches, includes ~ALL with no exclusion, has no bypass actor, and has the creation, deletion
 * and non_fast_forward rules. A ruleset scoped to one branch would leave branch creation open.
 */
export function allBranchRulesetProblems(rulesets) {
  if (!Array.isArray(rulesets)) return ["the repository's rulesets could not be read"];
  const need = ["creation", "deletion", "non_fast_forward"];
  const covers = r =>
    r?.enforcement === "active" &&
    r?.target === "branch" &&
    Array.isArray(r?.conditions?.ref_name?.include) &&
    r.conditions.ref_name.include.includes("~ALL") &&
    (r.conditions.ref_name.exclude ?? []).length === 0 &&
    (r.bypass_actors ?? []).length === 0 &&
    need.every(t => (r.rules ?? []).some(x => x?.type === t));
  return rulesets.some(covers)
    ? []
    : [
        "no active ruleset on all branches (~ALL, no exclusion, no bypass) restricting creation, deletion and force-pushes",
      ];
}

/**
 * The key file is a WRITE deploy key of the mirror repository (#428 review M2): its public key
 * (`ssh-keygen -y -f <key>`) equals one of the repository's deploy keys (`repos/<r>/keys`) with
 * read_only false. A personal key with write access would pass mirror-push but is not confined to
 * the mirror repository. Keys compare on type and base64 body (comments ignored).
 */
export function deployKeyProblems(pub, keys) {
  const body = k =>
    String(k ?? "")
      .trim()
      .split(/\s+/)
      .slice(0, 2)
      .join(" ");
  const mine = body(pub);
  if (!/^[a-z0-9][a-z0-9@.-]* [A-Za-z0-9+/=]+$/.test(mine))
    return ["the key file's public key could not be read"];
  if (!Array.isArray(keys)) return ["the repository's deploy keys could not be listed"];
  const match = keys.filter(k => body(k?.key) === mine);
  if (!match.length) return ["the key file is not a deploy key of the mirror repository"];
  if (!match.some(k => k?.read_only === false)) return ["the deploy key has no write access"];
  return [];
}

/**
 * `gh api --paginate --slurp` output (an array of pages, each a JSON array) as one list, or null
 * when it is anything else (Codex Phase D R8: every page counts; never a textual join, as a value can
 * contain "][").
 */
export function flattenPages(stdout) {
  try {
    const pages = JSON.parse(String(stdout));
    return Array.isArray(pages) && pages.every(Array.isArray) ? pages.flat() : null;
  } catch {
    return null;
  }
}
