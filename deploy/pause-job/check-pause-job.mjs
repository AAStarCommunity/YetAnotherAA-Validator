#!/usr/bin/env node
// Pure cells of the pause job: state invariants, ranges, config, the SP pin parser, revert
// decoding, and the host preflight rules. Everything that touches a chain (the pause path, the
// cap, crash recovery, nonce history, the identity check) runs against SP's REAL contracts on
// anvil in e2e-anvil.mjs (DSR 4019916a condition 3: no mocks on the pause path).
//   node deploy/pause-job/check-pause-job.mjs
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { ethers } from "ethers";
import {
  emptyState,
  stateProblems,
  ranges,
  revertData,
  costOf,
  PIN,
  spIface,
} from "./lib/core.mjs";
import { configProblems, CAP_CEILING } from "./pause-job.mjs";
import { parseRoles } from "./gen-sp-pin.mjs";
import { launchdOff, nodeSlashOff, runsSender, PAUSE_LABEL } from "./preflight.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const results = [];
const cell = (name, ok, got) => results.push({ name, ok: !!ok, got: JSON.stringify(got ?? null) });
const A = "0x1111111111111111111111111111111111111111";
const B = "0x2222222222222222222222222222222222222222";

// ---- state invariants
const base = () =>
  emptyState({ chainId: 31337, signer: A, spProxy: A, registry: B, startBlock: 10, cap: "1000" });
cell("a fresh state has no problems", stateProblems(base()).length === 0, stateProblems(base()));
{
  const st = base();
  st.ledger.txs.push({ nonce: 0, reserve: "600", status: "sent" });
  cell(
    "an open reservation not counted in reserved is a problem",
    stateProblems(st).some(p => p.startsWith("reserved")),
    stateProblems(st)
  );
  st.ledger.reserved = "600";
  cell(
    "an open reservation counted in reserved is fine",
    stateProblems(st).length === 0,
    stateProblems(st)
  );
  st.ledger.txs.push({ nonce: 1, reserve: "500", status: "signed" });
  st.ledger.reserved = "1100";
  const p = stateProblems(st);
  cell(
    "spent + reserved > cap is a problem",
    p.some(x => x.includes("exceeds the cap")),
    p
  );
}
{
  const st = base();
  st.ledger.txs.push({ nonce: 0, reserve: "100", status: "sent" });
  st.ledger.txs.push({ nonce: 1, reserve: "100", status: "included" });
  st.ledger.reserved = "200";
  cell(
    "an included transaction after a pending one is a problem",
    stateProblems(st).some(x => x.includes("after a pending")),
    stateProblems(st)
  );
  st.ledger.txs[0].status = "included";
  st.ledger.txs[1].status = "sent";
  cell(
    "included then pending holds both reservations and is fine",
    stateProblems(st).length === 0,
    stateProblems(st)
  );
}
// ---- costs: L1 is execution only; OP adds the GasPriceOracle's L1 + operator fees, never less
{
  const r = { gasUsed: "100", effectiveGasPrice: "7", l1Fee: "50" };
  cell("costOf on Sepolia: gasUsed x effectiveGasPrice", costOf(r, 11155111) === 700n);
  cell(
    "costOf on OP: execution + GasPriceOracle L1 fee + operator fee",
    costOf(r, 10, { l1Fee: 80n, operatorFee: 9n }) === 789n
  );
  cell(
    "costOf on OP takes the receipt's l1Fee when it is larger (never undercount)",
    costOf(r, 10, { l1Fee: 10n, operatorFee: 0n }) === 750n
  );
  let threw = false;
  try {
    costOf(r, 10, null);
  } catch {
    threw = true;
  }
  cell("costOf on OP without the oracle fees refuses (fail closed)", threw);
}
{
  const st = base();
  st.ledger.txs.push({ nonce: 1, cost: "5", status: "final" });
  st.ledger.spent = "5";
  cell(
    "a ledger whose nonces do not start at 0 is a problem",
    stateProblems(st).some(p => p.includes("nonces")),
    stateProblems(st)
  );
}
{
  const st = base();
  st.ledger.txs.push({ nonce: 0, cost: "5", status: "final" });
  cell(
    "spent that does not equal the mined costs is a problem",
    stateProblems(st).some(p => p.startsWith("spent does not")),
    stateProblems(st)
  );
}
cell(
  "the cursor starts one block before startBlock",
  base().cursor.operators === 9 && base().cursor.roles === 9,
  base().cursor
);

// ---- ranges
cell(
  "ranges cover [a,b] in chunks, inclusive",
  JSON.stringify(ranges(10, 25, 7)) === "[[10,16],[17,23],[24,25]]",
  ranges(10, 25, 7)
);
cell("an empty range has no chunks", ranges(11, 10, 5).length === 0, ranges(11, 10, 5));

// ---- revert data
const sel = n => spIface.getError(n).selector;
cell(
  "revertData reads a selector from error.data",
  revertData({ data: sel("OperatorMeetsMinimumStake") }) === sel("OperatorMeetsMinimumStake")
);
cell(
  "revertData reads a selector from info.error.data",
  revertData({ info: { error: { data: sel("OperatorNotConfigured") } } }) ===
    sel("OperatorNotConfigured")
);
cell(
  "revertData ignores longer data (an error with arguments is not one of ours)",
  revertData({ data: `${sel("OperatorNotConfigured")}00` }) === null
);
cell("revertData ignores a message", revertData({ message: "execution reverted" }) === null);

// ---- config
const good = {
  chainId: 11155111,
  spProxy: A,
  registry: B,
  startBlock: 100,
  registryStartBlock: 90,
  capWei: String(10n ** 17n),
  gasLimitMax: "200000",
  maxFeePerGasCap: "200000000000",
  maxPriorityFeePerGas: "1000000000",
  logChunk: 5000,
  stateDir: "/Users/x/.aoa-pause-job/state",
  secretsDir: "/Users/x/.aoa-pause-job/secrets",
  keystore: "/Users/x/.aoa-pause-job/keystore/pause-signer",
  telegram: { chatId: "-100123" },
  realertMinutes: 60,
  lockPort: 47219,
  rpc: { primary: "alchemy", fallback: "infura" },
};
cell("the example-shaped config passes", configProblems(good).length === 0, configProblems(good));
cell(
  "a cap above the Sepolia ceiling (0.1 ETH) is refused",
  configProblems({ ...good, capWei: String(10n ** 17n + 1n) }).some(p => p.includes("ceiling"))
);
cell(
  "a cap above the OP ceiling (0.02 ETH) is refused",
  configProblems({ ...good, chainId: 10, capWei: String(3n * 10n ** 16n) }).some(p =>
    p.includes("ceiling")
  )
);
cell(
  "the ceilings are 0.1 ETH Sepolia and 0.02 ETH OP",
  CAP_CEILING[11155111] === 10n ** 17n && CAP_CEILING[10] === 2n * 10n ** 16n
);
cell(
  "an unknown chain is refused",
  configProblems({ ...good, chainId: 1 }).some(p => p.startsWith("chainId"))
);
cell(
  "a relative state path is refused",
  configProblems({ ...good, stateDir: "state" }).some(p => p.startsWith("stateDir"))
);
cell(
  "the same provider twice is refused",
  configProblems({ ...good, rpc: { primary: "alchemy", fallback: "alchemy" } }).some(p =>
    p.includes("different providers")
  )
);
cell(
  "a provider URL in place of a name is refused",
  configProblems({ ...good, rpc: { primary: "https://x", fallback: "infura" } }).some(p =>
    p.startsWith("rpc")
  )
);
cell(
  "startBlock 0 is refused",
  configProblems({ ...good, startBlock: 0 }).some(p => p.startsWith("startBlock"))
);

// ---- the SP pin
cell(
  "sp-pin.json has a 40-hex spCommit and the seven Registry roles",
  /^[0-9a-f]{40}$/.test(PIN.spCommit) && Object.keys(PIN.roles).length === 7,
  Object.keys(PIN.roles)
);
cell(
  "each pinned role id is keccak256 of its name",
  Object.entries(PIN.roles).every(([n, id]) => id === ethers.id(n.slice(5)))
);
cell(
  "operators() in the pin has isPaused as its third output",
  PIN.abi.superPaymaster.find(f => f.name === "operators").outputs[2].name === "isPaused"
);
{
  const src =
    'bytes32 constant ROLE_A = keccak256("A");\nbytes32 constant ROLE_B = keccak256("B");\n';
  cell("parseRoles reads the constants", Object.keys(parseRoles(src)).join() === "ROLE_A,ROLE_B");
  let t1 = false;
  try {
    parseRoles('bytes32 constant ROLE_A = keccak256("B");');
  } catch {
    t1 = true;
  }
  cell("parseRoles refuses a constant that hashes another name", t1);
  cell(
    "parseRoles reads a declaration with a block comment inside it (Codex R2 P2-7)",
    Object.keys(
      parseRoles(
        'bytes32 constant ROLE_A = keccak256("A");\nbytes32 /* doc */ constant ROLE_X = keccak256("X");'
      )
    ).join() === "ROLE_A,ROLE_X"
  );
  cell(
    "parseRoles ignores a commented-out declaration",
    Object.keys(
      parseRoles(
        'bytes32 constant ROLE_A = keccak256("A");\n// bytes32 constant ROLE_Z = keccak256("Z");'
      )
    ).join() === "ROLE_A"
  );
  let t2 = false;
  try {
    parseRoles('bytes32 constant ROLE_A = keccak256("A");\nbytes32 constant ROLE_X = 0x01;');
  } catch {
    t2 = true;
  }
  cell("parseRoles refuses a ROLE_ constant in a form it does not read (fail closed)", t2);
}

// ---- preflight rules
{
  const ok = launchdOff(
    [PAUSE_LABEL, "io.aastar.price-keeper", "com.apple.x"],
    l => (l === "com.apple.x" ? null : ["/bin/bash", `/x/${l}.sh`]),
    () => ({ kind: "text", text: "echo unrelated" })
  );
  cell("launchd-off passes with only the pause job and unrelated jobs", ok.length === 0, ok);
  const k = launchdOff([PAUSE_LABEL, "io.aastar.dvt-committee-keeper"], () => []);
  cell(
    "launchd-off fails when the committee keeper is loaded",
    k.some(p => p.includes("committee-keeper")),
    k
  );
  const r = launchdOff([PAUSE_LABEL, "io.aastar.dvt-apply-rotation"], () => []);
  cell(
    "launchd-off fails when apply-rotation is loaded",
    r.some(p => p.includes("apply-rotation")),
    r
  );
  const n = launchdOff([], () => []);
  cell(
    "launchd-off fails when the pause job itself is not loaded",
    n.some(p => p.includes("not loaded")),
    n
  );
  const m = launchdOff([PAUSE_LABEL, "io.aastar.harmless"], () => [
    "/usr/bin/node",
    "/repo/deploy/committee-keeper.mjs",
  ]);
  cell(
    "launchd-off fails when a job under another name runs the committee keeper",
    m.some(p => p.includes("runs committee-keeper.mjs")),
    m
  );
  const u = launchdOff([PAUSE_LABEL, "io.aastar.unreadable"], () => null);
  cell(
    "launchd-off fails closed on a non-Apple job it cannot read",
    u.some(p => p.includes("cannot be read")),
    u
  );
}
{
  const env = { n1: ["AUDIT_ENABLED=false"], n2: [], n3: ["AUDIT_EXECUTE_SLASH=false", "X=1"] };
  cell(
    "node-slash-off passes with false or absent",
    nodeSlashOff(n => env[n] ?? null, ["n1", "n2", "n3"]).length === 0
  );
  for (const [name, e] of [
    ["true", ["AUDIT_ENABLED=true"]],
    ["TRUE (off in code, refused here)", ["AUDIT_EXECUTE_SLASH=TRUE"]],
    ["set twice", ["AUDIT_ENABLED=false", "AUDIT_ENABLED=false"]],
    ["empty", ["AUDIT_EXECUTE_SLASH="]],
  ])
    cell(
      `node-slash-off fails on ${name}`,
      nodeSlashOff(() => e, ["n"]).length > 0,
      nodeSlashOff(() => e, ["n"])
    );
  cell("node-slash-off fails on an empty inventory", nodeSlashOff(() => [], []).length > 0);
  cell(
    "node-slash-off fails when a running dvt-node-* is not in the inventory",
    nodeSlashOff(() => [], ["dvt-node-1"], ["dvt-node-1", "dvt-node-4"]).some(x =>
      x.includes("dvt-node-4")
    )
  );
  cell(
    "runsSender: a sending script inside sh -c is found",
    runsSender(["/bin/sh", "-c", "node /repo/deploy/committee-keeper.mjs --watch"]).includes(
      "committee-keeper.mjs"
    )
  );
  cell(
    "runsSender: a wrapper script that runs one is found by reading it",
    runsSender(["/bin/bash", "/x/run.sh"], () => ({
      kind: "text",
      text: "exec node deploy/apply-verifier-rotation.mjs",
    })).includes("apply-verifier-rotation.mjs")
  );
  cell(
    "runsSender: an unreadable wrapper is reported (fail closed)",
    runsSender(["/bin/bash", "/x/run.sh"], () => ({ kind: "unreadable" })).some(x =>
      x.includes("unreadable")
    )
  );
  cell(
    "runsSender: an extensionless wrapper is read too (Codex R2 P2-5)",
    runsSender(["/bin/bash", "/repo/run-keeper"], p =>
      p === "/repo/run-keeper"
        ? { kind: "text", text: "node deploy/committee-keeper.mjs" }
        : { kind: "binary" }
    ).includes("committee-keeper.mjs")
  );
  cell(
    "runsSender: a binary interpreter is not searched",
    runsSender(["/opt/homebrew/bin/node", "/x/y.mjs"], p =>
      p.endsWith("node") ? { kind: "binary" } : { kind: "text", text: "console.log(1)" }
    ).length === 0
  );
  {
    // the reviewed exception (DSR bc3be95b): label, FULL args, loaded == plist, env names, file hashes
    const r = {
      label: "io.aastar.dvt-committee-health",
      interpreter: "/bin/bash",
      wrapper: "deploy/local-heartbeat.sh",
      args: ["health"],
      envKeys: ["HOME", "PATH"],
      files: {
        "deploy/local-heartbeat.sh": "a".repeat(64),
        "deploy/committee-health.mjs": "b".repeat(64),
      },
    };
    const args = ["/bin/bash", "/r/deploy/local-heartbeat.sh", "health"];
    const plist = {
      Label: r.label,
      ProgramArguments: args,
      EnvironmentVariables: { HOME: "/h", PATH: "/p" },
    };
    const sha = path =>
      ({
        "/r/deploy/local-heartbeat.sh": "a".repeat(64),
        "/r/deploy/committee-health.mjs": "b".repeat(64),
      })[path] ?? null;
    const txt = () => ({
      kind: "text",
      text: "apply) node deploy/apply-verifier-rotation.mjs --broadcast",
    });
    const run = (pl, loaded = args, s = sha, labels = [PAUSE_LABEL, r.label]) =>
      launchdOff(labels, () => loaded, txt, [r], s, { [r.label]: pl });
    cell(
      "reviewed: the exact plist, loaded args, env names and both file hashes pass",
      run(plist).length === 0,
      run(plist)
    );
    cell(
      "reviewed: another mode fails",
      run({ ...plist, ProgramArguments: ["/bin/bash", "/r/deploy/local-heartbeat.sh", "apply"] }, [
        "/bin/bash",
        "/r/deploy/local-heartbeat.sh",
        "apply",
      ]).length > 0
    );
    {
      const bashC = [
        "/bin/bash",
        "-c",
        "node deploy/apply-verifier-rotation.mjs --broadcast",
        "/r/deploy/local-heartbeat.sh",
        "health",
      ];
      cell(
        "reviewed: bash -c with the wrapper as mere argument data fails (Codex R2 P2-5)",
        run({ ...plist, ProgramArguments: bashC }, bashC).length > 0
      );
    }
    cell(
      "reviewed: an extra argument fails",
      run({ ...plist, ProgramArguments: [...args, "--x"] }, [...args, "--x"]).length > 0
    );
    cell(
      "reviewed: another interpreter fails",
      run({ ...plist, ProgramArguments: ["/bin/zsh", ...args.slice(1)] }, [
        "/bin/zsh",
        ...args.slice(1),
      ]).length > 0
    );
    cell(
      "reviewed: loaded args that differ from the plist fail",
      run(plist, ["/bin/bash", "/other/deploy/local-heartbeat.sh", "health"]).length > 0
    );
    cell(
      "reviewed: an extra environment variable (e.g. BASH_ENV) fails",
      run({ ...plist, EnvironmentVariables: { ...plist.EnvironmentVariables, BASH_ENV: "/tmp/x" } })
        .length > 0
    );
    cell(
      "reviewed: a changed wrapper hash fails",
      run(plist, args, p => (p.endsWith("local-heartbeat.sh") ? "c".repeat(64) : sha(p))).length > 0
    );
    cell(
      "reviewed: a changed committee-health.mjs hash fails",
      run(plist, args, p => (p.endsWith("committee-health.mjs") ? "c".repeat(64) : sha(p))).length >
        0
    );
    cell(
      "reviewed: no plist for the job fails",
      launchdOff([PAUSE_LABEL, r.label], () => args, txt, [r], sha, {}).length > 0
    );
    cell(
      "reviewed: apply-rotation loaded still fails (the exception covers health only)",
      run(plist, args, sha, [PAUSE_LABEL, r.label, "io.aastar.dvt-apply-rotation"]).some(x =>
        x.includes("apply-rotation is loaded")
      )
    );
    cell(
      "reviewed: a forbidden label cannot be made an exception",
      launchdOff(
        [PAUSE_LABEL],
        () => [],
        txt,
        [{ ...r, label: "io.aastar.dvt-committee-keeper" }],
        sha,
        {}
      ).some(x => x.includes("cannot be a reviewed"))
    );
  }
  {
    // preflight-reviewed.json must hash what the repository holds (DSR bc3be95b: changes only by a
    // PR that states the new hashes; this cell turns CI red when a reviewed file changes alone)
    const rv = JSON.parse(readFileSync(join(here, "preflight-reviewed.json"), "utf8"));
    const repo = join(here, "../..");
    const bad = rv.jobs.flatMap(j =>
      Object.entries(j.files)
        .filter(
          ([rel, h]) =>
            createHash("sha256")
              .update(readFileSync(join(repo, rel)))
              .digest("hex") !== h
        )
        .map(([rel]) => rel)
    );
    cell(
      "preflight-reviewed.json hashes equal the repository's reviewed files",
      bad.length === 0,
      bad
    );
  }
  cell(
    "node-slash-off fails on a missing container",
    nodeSlashOff(() => null, ["gone"]).length === 1
  );
}

// ---- the README states the cap and the funding rule
{
  const readme = readFileSync(join(here, "README.md"), "utf8");
  cell(
    "README names the per-chain caps and the funding rule",
    /0\.1 ETH/.test(readme) && /0\.02 ETH/.test(readme) && /DSR/.test(readme)
  );
}

let nf = 0;
for (const r of results) {
  console.log(`${r.ok ? "ok  " : "FAIL"} ${r.name}${r.ok ? "" : `\n     got ${r.got}`}`);
  if (!r.ok) nf++;
}
console.log(`\n${results.length - nf}/${results.length} cells`);
process.exit(nf ? 1 : 0);
