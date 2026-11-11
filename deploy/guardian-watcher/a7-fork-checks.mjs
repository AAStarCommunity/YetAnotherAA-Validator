// The checks a7-fork.mjs makes around the anvil it starts, as pure functions with injected I/O so
// each one has a test cell (#412 review M1, DSR): whether the evidence stands depends on them.
// Exit codes (a7-fork.mjs): 0 SAME STATE, 1 a check failed (STOP), 2 usage, 3 no verdict (a read
// or a start failed: a failed observation proves nothing).
//
// A failure is returned as { code, msg }; null means the check passed. Messages are fixed wording:
// nothing from an RPC response or from anvil's own output is ever included.

export const EXIT = Object.freeze({ SAME_STATE: 0, STOP: 1, USAGE: 2, NO_VERDICT: 3 });

/** A child process is alive only while it has neither exited nor been killed by a signal (a
 * signal-terminated child keeps exitCode null and sets signalCode: Codex M1 R1). */
export const isAlive = proc => proc.exitCode === null && (proc.signalCode ?? null) === null;

/**
 * Before anything starts (#412 review F2, N1): the UPSTREAM is the read-back's chain and has the
 * fork block (anvil's own chainId is whatever --chain-id says, so it proves nothing), and nothing
 * already answers on --port (the tool would otherwise compare against that process).
 * `rpc(url, method, params)` resolves to the JSON-RPC result, or undefined when there is none.
 * Stricter than the inline code it replaces (declared, each with a cell): a null chain id is no
 * answer (exit 3, was 1 via Number(null) = 0); chain id and head must be hex quantities (a
 * non-numeric head used to pass, since NaN < forkBlock is false).
 */
export async function preflight({ rpc, forkUrl, chainId, forkBlock, port }) {
  const upChain = await rpc(forkUrl, "eth_chainId", []);
  if (upChain === undefined || upChain === null)
    return { code: EXIT.NO_VERDICT, msg: "the fork RPC does not answer eth_chainId" };
  if (!isQuantity(upChain) || Number(upChain) !== chainId)
    return { code: EXIT.STOP, msg: "the fork RPC is not the read-back's chain (eth_chainId)" };
  const upHead = await rpc(forkUrl, "eth_blockNumber", []);
  if (!isQuantity(upHead) || Number(upHead) < forkBlock)
    return { code: EXIT.STOP, msg: "the fork RPC does not have header.forkBlock yet" };
  if ((await rpc(`http://127.0.0.1:${port}`, "eth_chainId", [])) !== undefined)
    return {
      code: EXIT.STOP,
      msg: `something already listens on --port ${port}: refusing to compare against it`,
    };
  return null;
}
const isQuantity = v => typeof v === "string" && /^0x[0-9a-f]+$/i.test(v);

/**
 * `anvil --version` output against SP's pinned build: the commit must be the pinned one and the
 * first line must equal the read-back's header.anvilVersion. versionText null = not runnable.
 */
export function anvilBuild(versionText, { pinnedCommit, headerVersion }) {
  if (typeof versionText !== "string")
    return { fail: { code: EXIT.NO_VERDICT, msg: "anvil not runnable (--anvil <path>)" } };
  const version = versionText.split("\n")[0].trim();
  const commit = versionText.match(/^Commit SHA:\s*([0-9a-f]{40})\s*$/m)?.[1] ?? null;
  if (commit !== pinnedCommit)
    return {
      version,
      commit,
      fail: {
        code: EXIT.STOP,
        msg: `anvil commit is ${commit ?? "unknown"}, required ${pinnedCommit} (--anvil <path>)`,
      },
    };
  if (version !== headerVersion)
    return {
      version,
      commit,
      fail: {
        code: EXIT.STOP,
        msg: "anvil --version differs from the read-back's header.anvilVersion",
      },
    };
  return { version, commit, fail: null };
}

/**
 * Wait for the anvil this tool started (#412 review N1): up only while that process is alive, so a
 * different process that answers on the port is never taken for it.
 * `proc.exitCode` is null while it runs; `ping()` resolves when the RPC answers.
 */
export async function waitForAnvil({ proc, ping, sleep, tries = 120 }) {
  for (let i = 0; i < tries; i++) {
    await sleep();
    if (!isAlive(proc)) return false;
    try {
      await ping();
      return isAlive(proc);
    } catch {
      // starting
    }
  }
  return false;
}

/** anvil's own message may echo the fork URL: only a fixed category is shown. */
export function startFailure(anvilErr) {
  const e = String(anvilErr ?? "");
  const why = /panicked|unimplemented/i.test(e)
    ? "it crashed: this build cannot run the read-back's hardfork"
    : /fork|connect|request|dns|timed? ?out/i.test(e)
      ? "cannot reach or read the fork RPC"
      : /unknown|invalid/i.test(e)
        ? "rejected an argument"
        : "no RPC";
  return { code: EXIT.NO_VERDICT, msg: `anvil did not start (${why})` };
}

/**
 * The verdict: SAME STATE only with no failed comparison, nothing unverified, and the anvil this
 * tool started still running (#412 review N1; `anvil` is that child process). Returns the failed
 * list (with that line added when anvil is gone), proven, and the process exit code.
 */
export function verdict({ cmp, unverified, anvil }) {
  const failed = cmp.filter(x => !x.ok);
  if (!isAlive(anvil))
    failed.push({ path: "anvil exited before the verdict", sp: null, fork: null, ok: false });
  const proven = failed.length === 0 && unverified.length === 0;
  return { failed, proven, exitCode: proven ? EXIT.SAME_STATE : EXIT.STOP };
}
