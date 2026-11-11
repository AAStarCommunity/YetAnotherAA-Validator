// Phase D "watcher-job-binding" predicate (Codex R6, R7): is the running launchd job exactly the
// configured wrapper, and does that wrapper run the watcher with this config and the RPC URLs from
// the very Keychain items Phase D verified? Pure: launchctl output and the wrapper text come in.
// Self-test: node deploy/guardian-watcher/check-phase-d-binding.mjs

const reEsc = s => String(s).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/** program and argv as `launchctl print` shows them. */
export function parseLaunchd(out) {
  const program = out.match(/^\s*program = (.+)$/m)?.[1]?.trim() ?? null;
  const block = out.match(/^\s*arguments = \{\n([\s\S]*?)\n\s*\}/m)?.[1] ?? "";
  const argv = block
    .split("\n")
    .map(x => x.trim())
    .filter(Boolean);
  return { program, argv };
}

/**
 * @returns {string[]} problems, empty when bound. Fixed wording; nothing from the inputs is echoed.
 * ok(v) says a config value is set (not a placeholder).
 */
export function bindingProblems({
  program,
  argv,
  wrapper,
  text,
  wantConfig,
  services,
  account,
  ok,
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
  if (text === null || text === undefined) {
    problems.push("wrapper unreadable");
    return problems;
  }
  if (!wantConfig || !text.includes(`WATCHER_CONFIG="${wantConfig}"`))
    problems.push("wrapper names another config than watcherConfig");
  // the wrapper reads the SAME Keychain items Phase D tested (Codex R7 #2), each into its own
  // variable: built from the configured services and account, so a Phase D config pointing at other
  // items than the wrapper reads cannot pass
  const reads = (v, svc) =>
    ok(svc) &&
    ok(account) &&
    new RegExp(
      `^${v}="\\$\\(security find-generic-password -s ${reEsc(svc)} -a ${reEsc(account)} -w\\)"$`,
      "m"
    ).test(text);
  if (!reads("RPC_URL", services?.rpcPrimary) || !reads("RPC_URL_2", services?.rpcSecondary))
    problems.push(
      "wrapper does not read both RPC URLs from the Keychain items this check verified"
    );
  if ((text.match(/security find-generic-password/g) ?? []).length !== 2)
    problems.push("wrapper reads more Keychain items than the two RPC URLs");
  if (/https?:\/\//i.test(text)) problems.push("wrapper holds a URL");
  if (!/^exec node "\$WATCHER_ENTRY" --config "\$WATCHER_CONFIG"$/m.test(text))
    problems.push("wrapper does not exec the watcher with that config");
  return problems;
}
