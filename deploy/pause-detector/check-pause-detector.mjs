#!/usr/bin/env node
// Cells for the rc.8 pause detector (deploy/pause-detector). Pure and scripted-chain cells; no
// network. Run: npm run check:pause-detector
//
// The first group is the guarantee DSR asked for: the detector has NO key, keystore, signing or
// broadcast code. It fails if any such call appears in the detector or anything it imports, and
// its own control cells prove the scanner sees one when it is there.
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { spawn, spawnSync } from "node:child_process";
import { createServer as createHttpServer } from "node:http";
import { homedir, tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { ethers } from "ethers";
import {
  emptyState,
  runRound,
  stateProblems,
  spIface,
  regIface,
  IMPL_SLOT,
  OPERATOR_CONFIGURED,
  ROLE_PAYMASTER_SUPER,
  pauseCommand,
  ranges,
  headStale,
} from "./lib/detect.mjs";
import {
  configProblems,
  readOnlyChain,
  READ_METHODS,
  dueAlerts,
  resolvedKeys,
  DETECTOR_SECRETS,
  batches,
  deliver,
  telegram,
  MESSAGE_CHARS,
  rpcTransport,
} from "./run.mjs";
import {
  bundleProblems,
  launchProblems,
  crashLabel,
  readOwnJson,
  recordStop,
  symlinkProblems,
} from "./lib/guard.mjs";
import { readSecretFile } from "../pause-job/lib/secret-file.mjs";
import { scanSource, scanTree } from "./no-signing-scan.mjs";
import {
  compactQueue,
  deadmanDecision,
  main as deadmanMain,
  MAX_SILENCE_MS,
  QUEUE_MAX,
  REALERT_MS,
} from "./deadman-run.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
let pass = 0;
let fail = 0;
const cell = async (name, fn) => {
  try {
    await fn();
    pass++;
    console.log(`ok   ${name}`);
  } catch (e) {
    fail++;
    console.log(`FAIL ${name}: ${e?.message ?? e}`);
  }
};
const assert = (c, m) => {
  if (!c) throw new Error(m);
};

// ---------------------------------------------------------------- no key, no signing, no broadcast

await cell(
  "no-signing: the detector and everything it imports hold no signing or broadcast code",
  () => {
    const p = scanTree(join(HERE, "detector.mjs"));
    assert(p.length === 0, p.join("; "));
  }
);
await cell(
  "no-signing: the scan reaches lib/detect.mjs and the shared secret-file/safe-error modules",
  () => {
    const seen = new Set();
    scanTree(join(HERE, "detector.mjs"), undefined, seen);
    for (const f of [
      "lib/detect.mjs",
      "../pause-job/lib/secret-file.mjs",
      "../pause-job/lib/safe-error.mjs",
    ])
      assert(seen.has(resolve(HERE, f)), `${f} not scanned`);
  }
);
// every one of these must be caught: Codex R1's bypasses first, then the plain forms
const CAUGHT = {
  "computed ethers member": 'import { ethers } from "ethers";\nconst W = ethers["Wal" + "let"];',
  "code between strings holding comment markers":
    'const a = "/*";\nconst w = x.signTransaction(t);\nconst b = "*/";',
  "an import after another statement on one line":
    'const a = 1; import { execFile } from "node:child_process";',
  "an ethers alias": 'import { ethers } from "ethers";\nconst e = ethers;',
  "an ethers signer": 'import { ethers } from "ethers";\nconst w = new ethers.Wallet(k);',
  "a JsonRpcProvider": 'import { ethers } from "ethers";\nconst p = new ethers.JsonRpcProvider(u);',
  "a broadcast method name": 'await rpc("eth_sendRawTransaction", [raw]);',
  "a broadcast method in a template": "await rpc(`eth_send${x}`, [raw]); const t = `x keystore`;",
  child_process: 'import { execFile } from "node:child_process";',
  "net beyond the lock": 'import { connect } from "node:net";',
  "a keystore file": "const k = readFileSync(cfg.keystore);",
  "a dynamic import": 'const m = await import("./x.mjs");',
  require: 'const m = require("x");',
  eval: 'eval("x")',
  "new Function": 'new Function("return 1")',
  globalThis: "globalThis.fetch(u)",
  "a computed process member": 'process["bind" + "ing"]("x")',
  "a fetch alias": "const f = fetch; f(u);",
  "a fetch to an arbitrary URL": "await fetch(u, {});",
  "a fetch outside rpcTransport": "function other(url) { return fetch(url); }",
  "a second JSON-RPC fetch": "function rpcTransport(url) { fetch(url); fetch(url); }",
  "an object key naming a signer": "const o = { signTransaction: 1 };",
  "a private key field": "const k = cfg.privateKey;",
  // Codex R2's bypasses
  "a process alias": "const p = process; p.getuid();",
  "a computed name built from strings": 'const f = x["exec" + "Sync"];',
  "a computed string member": 'const f = x["execSync"];',
  "Function via .constructor": '(() => 1).constructor("return 1")();',
  getBuiltinModule: "process.getBuiltinModule('node:child_process');",
  "console beyond log and error": "console.table(x);",
  // Codex R3's bypasses (the ones a static scan can see; see README for what it cannot)
  "a constructor name in a string": 'const k = "constructor"; const F = (() => {})[k];',
  "a quoted constructor key": 'const { "constructor": F } = () => {};',
  "a signing method on a class": "class A { signTransaction() {} }",
  "a getBuiltinModule string": 'const m = "getBuiltinModule";',
};
await cell(
  "no-signing CONTROL: every forbidden form is caught (incl. Codex R1's four bypasses)",
  () => {
    const missed = Object.entries(CAUGHT).filter(
      ([, src]) => scanSource("/y.mjs", src).length === 0
    );
    assert(missed.length === 0, `not caught: ${missed.map(([k]) => k).join(", ")}`);
  }
);
await cell(
  "no-signing: the JSON-RPC transport itself refuses a write method (no fetch made)",
  async () => {
    const real = globalThis.fetch;
    let fetched = 0;
    globalThis.fetch = async () => {
      fetched++;
      return { ok: true, json: async () => ({ result: "0x" }) };
    };
    try {
      // DSR: every send, sign and personal_* method is refused, each one tried
      for (const m of [
        "eth_" + "sendRaw" + "Transaction",
        "eth_sendTransaction",
        "eth_sign",
        "eth_signTransaction",
        "eth_signTypedData",
        "eth_signTypedData_v4",
        "personal_sign",
        "personal_sendTransaction",
        "personal_unlockAccount",
        "personal_importRawKey",
      ]) {
        let refused = false;
        try {
          await rpcTransport("http://x")(m, ["0x00"]);
        } catch (e) {
          refused = /refused/.test(e.message);
        }
        assert(refused, `${m} not refused`);
      }
      assert(fetched === 0, `fetched=${fetched}`);
      await rpcTransport("http://x")("eth_chainId", []);
      assert(fetched === 1, "a read method did not pass (control)");
    } finally {
      globalThis.fetch = real;
    }
  }
);
await cell("no-signing CONTROL: a re-export (export * from) is followed", () => {
  const files = {
    "/r/a.mjs": 'export * from "./evil.mjs";',
    "/r/evil.mjs": "x.sendTransaction(t);",
  };
  const p = scanTree("/r/a.mjs", f => files[f]);
  assert(
    p.some(x => x.includes("/r/evil.mjs")),
    p.join("; ")
  );
});
await cell("no-signing CONTROL: a signing module two imports deep is caught", () => {
  const files = {
    "/x/a.mjs": 'import { b } from "./b.mjs";\n',
    "/x/b.mjs": 'export { c } from "./c.mjs";\n',
    "/x/c.mjs": "export const c = w => w.signTransaction({});\n",
  };
  const p = scanTree("/x/a.mjs", f => files[f]);
  assert(
    p.some(x => x.includes("/x/c.mjs") && x.includes("signTransaction")),
    p.join("; ")
  );
});
await cell("no-signing CONTROL: comments are not code; the two allowed fetches pass", () => {
  const ok = [
    "// no Wallet, no signTransaction here\n/* keystore */\nconst a = 1;\n",
    "async function t(token) { return fetch(`https://api.telegram.org/bot${token}/sendMessage`, {}); }",
    "function rpcTransport(url) { return () => fetch(url, {}); }",
    'import { createServer } from "node:net";',
    'import { ethers } from "ethers";\nconst i = new ethers.Interface([]);',
  ];
  for (const src of ok) {
    const p = scanSource("/z.mjs", src);
    assert(p.length === 0, `${src}: ${p.join("; ")}`);
  }
});
await cell(
  "no-signing: the RPC client refuses every write method before the transport sees it",
  async () => {
    const seen = [];
    const c = readOnlyChain("http://unused", async m => {
      seen.push(m);
      return "0x1";
    });
    for (const m of [
      "eth_sendRawTransaction",
      "eth_sendTransaction",
      "eth_sign",
      "eth_signTransaction",
      "eth_signTypedData",
      "eth_signTypedData_v3",
      "eth_signTypedData_v4",
      "personal_sign",
      "personal_sendTransaction",
      "personal_signTransaction",
      "personal_unlockAccount",
      "personal_importRawKey",
      "eth_accounts",
      "eth_estimateGas",
      "eth_getTransactionCount",
    ]) {
      let refused = false;
      try {
        await c.rpc(m, []);
      } catch (e) {
        refused = /refused/.test(e.message);
      }
      assert(refused, `${m} not refused`);
    }
    assert(seen.length === 0, `transport saw ${seen.join(",")}`);
    // control: a read method passes through
    await c.chainId();
    assert(seen.length === 1 && seen[0] === "eth_chainId", "read method did not pass");
  }
);
await cell("no-signing: the read-only allowlist is exactly the seven read methods", () => {
  assert(
    [...READ_METHODS].sort().join() ===
      [
        "eth_call",
        "eth_chainId",
        "eth_getBlockByHash",
        "eth_getBlockByNumber",
        "eth_getCode",
        "eth_getLogs",
        "eth_getStorageAt",
      ].join(),
    READ_METHODS.join()
  );
});

// ---------------------------------------------------------------- a scripted chain

const SP = "0x00000000000000000000000000000000000000a1";
const REG = "0x00000000000000000000000000000000000000b2";
const IMPL = "0x00000000000000000000000000000000000000c3";
const PROXY_CODE = "0x6001";
const IMPL_CODE = "0x6002";
const REG_CODE = "0x6003";
const REG_IMPL = "0x00000000000000000000000000000000000000c4";
const REG_IMPL_CODE = "0x6004";
const OP1 = "0x1111111111111111111111111111111111111111";
const OP2 = "0x2222222222222222222222222222222222222222";
const cfgOf = over => ({
  chainId: 11155111,
  spProxy: SP,
  registry: REG,
  implementation: IMPL,
  proxyCodeHash: ethers.keccak256(PROXY_CODE),
  implementationCodeHash: ethers.keccak256(IMPL_CODE),
  registryCodeHash: ethers.keccak256(REG_CODE),
  registryImplementation: REG_IMPL,
  registryImplementationCodeHash: ethers.keccak256(REG_IMPL_CODE),
  startBlock: 100,
  logChunk: 50,
  rescanBlocks: 60,
  maxHeadAgeSec: 1800,
  ...over,
});

/**
 * world: { ops: { addr: { configured, paused, role, eff, logBlock } }, minStake, latest, finalized,
 * impl, fail: Set of "what" names, reorg }. Every eth_call and code/storage read must be at B by
 * hash (EIP-1898, requireCanonical), else the fake throws: the round may not read at another block.
 */
function fakeChain(w) {
  const hashOf = n => ethers.zeroPadValue(ethers.toBeHex(n), 32);
  let afterB = false;
  const atB = tag => {
    if (!(tag?.requireCanonical === true && tag?.blockHash === hashOf(w.latest)))
      throw new Error("a read not at B by hash");
  };
  const failIf = what => {
    if (w.fail?.has(what)) {
      const e = new Error("boom");
      e.code = "SERVER_ERROR";
      throw e;
    }
  };
  const revert = sel => {
    const e = new Error("revert");
    e.data = sel;
    throw e;
  };
  const enc = (iface, fn, v) => iface.encodeFunctionResult(fn, v);
  return {
    calls: [],
    chainId: async () => "0xaa36a7",
    blockNumber: async tag => {
      if (tag === "finalized") return w.finalizedRaw ?? w.finalized;
      return w.latest;
    },
    blockByHash: async h => {
      failIf("blockByHash");
      const n = Number(BigInt(h));
      if (w.oldFork && Object.values(w.oldFork).includes(h)) {
        const m = Number(Object.keys(w.oldFork).find(k => w.oldFork[k] === h));
        return { number: m, hash: h, parentHash: hashOf(m - 1) };
      }
      if (!(n >= 0 && n <= w.latest) || h !== hashOf(n)) return null;
      return {
        number: n,
        hash: h,
        parentHash: w.forkParentAt === n ? hashOf(n + 7777) : hashOf(n - 1),
      };
    },
    blockByNumber: async n => {
      // the head is `headAgeSec` old at the round's `now` (12 s by default): w.frozenAt freezes it
      const ts = Math.floor((w.nowMs ?? Date.now()) / 1000) - (w.headAgeSec ?? 12);
      if (n === "latest")
        return w.noLatest
          ? null
          : { number: w.latest, hash: hashOf(w.latest), timestamp: w.frozenAt ?? ts };
      if (w.oldFork?.[n]) return { number: n, hash: w.oldFork[n] };
      afterB = true;
      return { number: n, hash: w.reorg ? hashOf(n + 9999) : hashOf(n) };
    },
    getLogs: async f => {
      assert(f.address === SP && f.topics[0] === OPERATOR_CONFIGURED, "log filter");
      let a;
      let b;
      if (f.blockHash) {
        // EIP-234: one block by hash; a backend that has not indexed it fails
        if (w.oldFork && Object.values(w.oldFork).includes(f.blockHash)) return [];
        const n = Number(BigInt(f.blockHash));
        assert(f.blockHash === hashOf(n) && n <= w.latest, "blockHash filter of an unknown block");
        if (n === w.latest) failIf("logs-at-B");
        failIf(`logs-at-${n}`);
        a = b = n;
      } else {
        if (w.failOnce?.delete(`logs:${Number(f.fromBlock)}`)) throw new Error("once");
        failIf(`logs:${Number(f.fromBlock)}`);
        failIf("logs");
        a = Number(f.fromBlock);
        b = Number(f.toBlock);
      }
      w.scanned = [...(w.scanned ?? []), [a, b]];
      return Object.entries(w.ops)
        .filter(
          ([, o]) =>
            o.logBlock >= a &&
            o.logBlock <= b &&
            !w.hidden?.has(o.logBlock) &&
            !(w.rangeSkipsB && !f.blockHash && o.logBlock === w.latest) &&
            !(w.rangeHides?.has(o.logBlock) && !f.blockHash) &&
            !(w.hashHides?.has(o.logBlock) && f.blockHash)
        )
        .map(([op, o]) => ({
          address: SP,
          topics: [OPERATOR_CONFIGURED, w.topicOf?.(op) ?? ethers.zeroPadValue(op, 32)],
          blockNumber: ethers.toQuantity(o.logBlock),
          blockHash: w.forkedLog === o.logBlock ? hashOf(o.logBlock + 5555) : hashOf(o.logBlock),
          removed: false,
        }));
    },
    code: async (a, tag) => {
      atB(tag);
      failIf(`code:${a}`);
      return (
        {
          [SP]: PROXY_CODE,
          [IMPL]: IMPL_CODE,
          [w.impl ?? IMPL]: w.implCode ?? IMPL_CODE,
          [REG]: REG_CODE,
          [w.regImpl ?? REG_IMPL]: REG_IMPL_CODE,
        }[a.toLowerCase()] ?? "0x"
      );
    },
    storageAt: async (a, slot, tag) => {
      atB(tag);
      assert((a === SP || a === REG) && slot === IMPL_SLOT, "slot");
      return ethers.zeroPadValue(a === SP ? (w.impl ?? IMPL) : (w.regImpl ?? REG_IMPL), 32);
    },
    call: async (tx, tag) => {
      atB(tag);
      const to = tx.to.toLowerCase();
      const iface = to === SP ? spIface : regIface;
      const p = iface.parseTransaction({ data: tx.data });
      failIf(`call:${p.name}`);
      if (p.name === "REGISTRY") return enc(spIface, "REGISTRY", [w.registry ?? REG]);
      const op = p.args[p.name === "getEffectiveStake" ? 0 : p.name === "hasRole" ? 1 : 0];
      const o = w.ops[String(op).toLowerCase()];
      if (p.name === "operators")
        return enc(spIface, "operators", [
          0n,
          o?.configured ?? false,
          o?.paused ?? false,
          ethers.ZeroAddress,
          0,
          0n,
          ethers.ZeroAddress,
          0n,
          0n,
        ]);
      if (p.name === "hasRole") {
        assert(p.args[0] === ROLE_PAYMASTER_SUPER, "role id");
        return enc(regIface, "hasRole", [o?.role ?? false]);
      }
      if (p.name === "getRoleConfig") {
        const f = regIface.getFunction("getRoleConfig").outputs[0];
        const v = f.components.map(c =>
          c.name === "minStake"
            ? w.minStake
            : c.type === "bool"
              ? false
              : c.type === "string"
                ? ""
                : c.type === "address"
                  ? ethers.ZeroAddress
                  : 0n
        );
        return enc(regIface, "getRoleConfig", [v]);
      }
      if (p.name === "getEffectiveStake") return enc(regIface, "getEffectiveStake", [o?.eff ?? 0n]);
      if (p.name === "pauseUnderstakedOperator") {
        assert(tx.from === ethers.ZeroAddress, "simulated from a non-zero address");
        if ("simResult" in w) return w.simResult;
        if (w.simSays)
          return w.simSays === "ok" ? "0x" : revert(spIface.getError(w.simSays).selector);
        if (!o?.configured) revert(spIface.getError("OperatorNotConfigured").selector);
        if (o.role && o.eff >= w.minStake)
          revert(spIface.getError("OperatorMeetsMinimumStake").selector);
        return "0x";
      }
      throw new Error(`unexpected call ${p.name}`);
    },
  };
}
const world = over => ({
  latest: 300,
  finalized: 250,
  minStake: 100n,
  ops: {
    [OP1.toLowerCase()]: { configured: true, paused: false, role: true, eff: 150n, logBlock: 120 },
  },
  ...over,
});
const round = async (w, cfg = cfgOf(), st = emptyState(cfg), now = 1e12) => {
  w.nowMs = now;
  return { st, ...(await runRound(st, { chain: fakeChain(w), cfg, now })) };
};

await cell(
  "round CONTROL: a staked operator is ok, the round is clear, nothing alerts",
  async () => {
    const { alerts, report, st } = await round(world());
    assert(alerts.length === 0, alerts.map(a => a.text).join("; "));
    assert(report.clear === true, "not clear");
    assert(report.operators[0].status === "ok", report.operators[0].status);
    assert(st.cursor === 250 && st.operators[ethers.getAddress(OP1)] === 120, "inventory");
  }
);
await cell(
  "round: understaked and not paused alerts PAUSE NEEDED with the exact cast command",
  async () => {
    const w = world();
    w.ops[OP1.toLowerCase()].eff = 50n;
    const { alerts, report } = await round(w);
    const a = alerts.find(x => x.key === `actionable:${ethers.getAddress(OP1)}`);
    assert(a, "no actionable alert");
    assert(
      a.text.includes(
        `cast send ${ethers.getAddress(SP)} "pauseUnderstakedOperator(address)" ${ethers.getAddress(OP1)}`
      ),
      a.text
    );
    assert(a.text.includes("50") && a.text.includes("100"), "stake numbers missing");
    assert(report.clear === false, "clear with an actionable operator");
  }
);
await cell("round: a configured operator without ROLE_PAYMASTER_SUPER is understaked", async () => {
  const w = world();
  w.ops[OP1.toLowerCase()].role = false;
  const { alerts } = await round(w);
  const a = alerts.find(x => x.key.startsWith("actionable:"));
  assert(a && a.text.includes("no ROLE_PAYMASTER_SUPER"), alerts.map(x => x.text).join("; "));
});
await cell("round: understaked but already paused is clear and silent", async () => {
  const w = world();
  Object.assign(w.ops[OP1.toLowerCase()], { eff: 0n, paused: true });
  const { alerts, report } = await round(w);
  assert(
    alerts.length === 0 && report.clear === true && report.operators[0].status === "paused",
    "not silent"
  );
});
await cell("round: stake exactly at the minimum meets it (>=, as SP)", async () => {
  const w = world();
  w.ops[OP1.toLowerCase()].eff = 100n;
  const { report } = await round(w);
  assert(report.operators[0].status === "ok", report.operators[0].status);
});
await cell("round: a failed stake read is unknown, never clear", async () => {
  const w = world({ fail: new Set(["call:getEffectiveStake"]) });
  const { alerts, report } = await round(w);
  assert(
    alerts.some(a => a.key.startsWith("unknown:") && a.text.startsWith("unknown:")),
    "no unknown alert"
  );
  assert(
    alerts.some(a => a.text.includes("Registry.getEffectiveStake failed")),
    "the failed read is not named"
  );
  assert(report.clear === false, "clear after a failed read");
});
await cell("round: the reads and SP's own check disagreeing is unknown", async () => {
  const w = world({ simSays: "ok" }); // reads say meets, the simulation says understaked
  const { alerts, report } = await round(w);
  assert(
    alerts.some(a => a.key.startsWith("unknown:") && /disagree|says/.test(a.text)),
    alerts.map(a => a.text).join("; ")
  );
  assert(report.clear === false, "clear on disagreement");
});
await cell("round: a failed simulation (not a known selector) is unknown", async () => {
  const w = world({ fail: new Set(["call:pauseUnderstakedOperator"]) });
  const { report } = await round(w);
  assert(report.operators[0].status === "unknown" && report.clear === false, "not unknown");
});
await cell(
  "round: a wrong implementation fails identity; no PAUSE NEEDED and not clear",
  async () => {
    const w = world({ impl: "0x00000000000000000000000000000000000000d4" });
    w.ops[OP1.toLowerCase()].eff = 0n;
    const { alerts, report } = await round(w);
    assert(
      alerts.some(a => a.key === "identity" && a.text.startsWith("unknown:")),
      "no identity alert"
    );
    assert(!alerts.some(a => a.key.startsWith("actionable:")), "actionable despite identity");
    assert(report.clear === false, "clear with identity failed");
  }
);
await cell("round: SP.REGISTRY() not the configured Registry fails identity", async () => {
  const { alerts, report } = await round(
    world({ registry: "0x00000000000000000000000000000000000000e5" })
  );
  assert(alerts.some(a => a.key === "identity") && report.clear === false, "no identity failure");
});
await cell(
  "round: a Registry proxy pointing at another implementation fails identity",
  async () => {
    const { alerts, report } = await round(
      world({ regImpl: "0x00000000000000000000000000000000000000d5" })
    );
    assert(
      alerts.some(a => a.key === "identity" && /Registry proxy/.test(a.text)) && !report.clear,
      "not caught"
    );
  }
);
await cell("round: a wrong code hash fails identity (each proxy and implementation)", async () => {
  for (const k of [
    "proxyCodeHash",
    "implementationCodeHash",
    "registryCodeHash",
    "registryImplementationCodeHash",
  ]) {
    const { alerts } = await round(world(), cfgOf({ [k]: ethers.keccak256("0x00") }));
    assert(
      alerts.some(a => a.key === "identity"),
      `${k} not checked`
    );
  }
});
await cell("round: B leaving the canonical chain makes the round unknown", async () => {
  const w = world({ reorg: true });
  const { alerts, report } = await round(w);
  assert(alerts.some(a => a.key === "reorg") && report.clear === false, "reorg not caught");
});
await cell("round: a failed getLogs keeps the cursor, alerts unknown, not clear", async () => {
  const w = world({ fail: new Set(["logs:100"]) });
  const { alerts, report, st } = await round(w);
  assert(st.cursor === 99, `cursor moved to ${st.cursor}`);
  assert(
    alerts.some(a => a.key === "inventory" && a.text.startsWith("unknown:")),
    "no inventory alert"
  );
  assert(report.clear === false, "clear with a failed inventory");
});
await cell(
  "round: a failed finalized inventory is not clear even when the recent scan then succeeds",
  async () => {
    const w = world({ failOnce: new Set(["logs:100"]) });
    const { alerts, report, st } = await round(w);
    assert(st.cursor === 99, `cursor moved to ${st.cursor}`);
    assert(
      alerts.some(a => a.key === "inventory") && !alerts.some(a => a.key === "inventory-recent"),
      "alerts"
    );
    assert(report.operators.length === 1, "the recent scan did not read the operator");
    assert(report.clear === false, "clear with a failed inventory");
  }
);
await cell(
  "round: an operator configured after finalized (cursor, B] is read and kept (the inventory only grows)",
  async () => {
    const w = world();
    w.ops[OP2.toLowerCase()] = {
      configured: true,
      paused: false,
      role: true,
      eff: 1n,
      logBlock: 280,
    };
    const { alerts, st } = await round(w);
    assert(
      alerts.some(a => a.key === `actionable:${ethers.getAddress(OP2)}`),
      "recent operator not read"
    );
    // the inventory only grows (Codex R9): seen once, read every round from now on
    assert(st.operators[ethers.getAddress(OP2)] === 280, "a seen operator was not persisted");
  }
);
await cell(
  "round: a configured-then-removed operator alerts not-configured, still clear",
  async () => {
    const w = world();
    w.ops[OP1.toLowerCase()].configured = false;
    const { alerts, report } = await round(w);
    assert(
      alerts.some(a => a.key.startsWith("not-configured:")) && report.clear === true,
      "not-configured"
    );
  }
);
await cell("round: a state of another SuperPaymaster is refused", async () => {
  const st = emptyState(cfgOf({ spProxy: "0x00000000000000000000000000000000000000f6" }));
  let refused = false;
  try {
    await runRound(st, { chain: fakeChain(world()), cfg: cfgOf() });
  } catch (e) {
    refused = /another SuperPaymaster/.test(e.message);
  }
  assert(refused, "not refused");
});

await cell(
  "round: an operator topic with non-zero padding is refused (unknown), not decoded",
  async () => {
    const w = world({ topicOf: op => `0x${"ab".repeat(12)}${op.slice(2)}` });
    const { alerts, report, st } = await round(w);
    assert(Object.keys(st.operators).length === 0 && st.cursor === 99, "decoded or cursor moved");
    assert(
      alerts.some(a => a.key === "inventory" && /not an address/.test(a.text)) && !report.clear,
      "not refused"
    );
  }
);
await cell("round: a log whose blockHash is not canonical is refused (unknown)", async () => {
  const { alerts, report, st } = await round(world({ forkedLog: 120 }));
  assert(st.cursor === 99 && !report.clear, "accepted a forked log");
  assert(
    alerts.some(a => /not on the canonical chain/.test(a.text)),
    alerts.map(a => a.text).join("; ")
  );
});
await cell(
  "round: a backend that cannot give B's logs by hash makes the recent scan unknown",
  async () => {
    const { alerts, report } = await round(world({ fail: new Set(["logs-at-B"]) }));
    assert(alerts.some(a => a.key === "inventory-recent") && !report.clear, "not unknown");
  }
);
await cell(
  "round: a lagging backend's [] is caught by the next round's rescan window",
  async () => {
    const cfg = cfgOf();
    const st = emptyState(cfg);
    const w = world({ hidden: new Set([120]), latest: 300, finalized: 250 });
    await round(w, cfg, st, 1e12); // first (full) round: block 120 answered [] by the backend
    assert(Object.keys(st.operators).length === 0, "seen despite hidden");
    // the backend catches up; the cursor is at 250, the window re-reads 191..250: 120 is outside
    w.hidden = new Set();
    w.ops[OP1.toLowerCase()].logBlock = 200; // an operator inside the window
    await round(w, cfg, st, 1e12 + 3600_000);
    assert(st.operators[ethers.getAddress(OP1)] === 200, "the rescan window did not find it");
  }
);
await cell(
  "round: a missed operator outside the window is found by the daily full rescan",
  async () => {
    const cfg = cfgOf();
    const st = emptyState(cfg);
    const w = world({ hidden: new Set([120]) });
    await round(w, cfg, st, 1e12);
    w.hidden = new Set();
    await round(w, cfg, st, 1e12 + 3600_000); // window only: 120 is outside
    assert(Object.keys(st.operators).length === 0, "found without the full rescan");
    await round(w, cfg, st, 1e12 + 24 * 3600_000); // a day later: full rescan from startBlock
    assert(st.operators[ethers.getAddress(OP1)] === 120, "the daily rescan did not find it");
    assert(st.lastFullScan === 1e12 + 24 * 3600_000, "lastFullScan not recorded");
  }
);
await cell("round: a failed full rescan does not record lastFullScan", async () => {
  const st = emptyState(cfgOf());
  await round(world({ fail: new Set(["logs:100"]) }), cfgOf(), st, 1e12);
  assert(st.lastFullScan === 0, "recorded a failed full scan");
});
await cell("state: an operators array (or bad entries) is refused, not silently emptied", () => {
  const c = cfgOf();
  const lowerCase = `0x${"ab".repeat(20)}`; // not its own checksum form
  assert(ethers.getAddress(lowerCase) !== lowerCase, "fixture");
  for (const bad of [[], { [lowerCase]: 120 }, { [ethers.getAddress(OP1)]: "120" }, { x: 1 }]) {
    const st = { ...emptyState(c), cursor: 250, operators: bad };
    assert(
      stateProblems(st, c).some(x => /operators/.test(x)),
      `accepted ${JSON.stringify(bad)}`
    );
  }
  assert(
    stateProblems({ ...emptyState(c), alerts: [] }, c).some(x => /alerts/.test(x)),
    "alerts array"
  );
  const good = { ...emptyState(c), cursor: 250, operators: { [ethers.getAddress(OP1)]: 120 } };
  assert(stateProblems(good, c).length === 0, stateProblems(good, c).join("; "));
});

await cell(
  "round: an operator only in the by-hash answer for B still counts, and the disagreement is unknown",
  async () => {
    const w = world({ rangeSkipsB: true });
    w.ops[OP2.toLowerCase()] = {
      configured: true,
      paused: false,
      role: true,
      eff: 1n,
      logBlock: 300,
    };
    const { alerts, report } = await round(w);
    assert(
      report.operators.some(o => o.operator === ethers.getAddress(OP2)),
      "the by-hash operator was dropped"
    );
    assert(
      alerts.some(a => a.key === "inventory-recent" && /differ/.test(a.text)) && !report.clear,
      "disagreement not unknown"
    );
  }
);
await cell(
  "round: a block above finalized that is not B's ancestor makes the recent scan unknown",
  async () => {
    const { alerts, report } = await round(world({ forkParentAt: 280 }));
    assert(
      alerts.some(a => a.key === "inventory-recent") && !report.clear,
      "a forked ancestry was accepted"
    );
  }
);
await cell("round: B's ancestry must reach the finalized block the backend reports", async () => {
  const { alerts, report } = await round(world({ forkParentAt: 251 }));
  assert(
    alerts.some(a => /descend|ancestry/.test(a.text)) && !report.clear,
    alerts.map(a => a.text).join("; ")
  );
});
await cell(
  "round: a state cursor ahead of the finalized block re-reads everything from startBlock (no silent skip)",
  async () => {
    const w = world();
    w.ops[OP1.toLowerCase()].eff = 0n;
    const st = { ...emptyState(cfgOf()), cursor: 10_000, checked: 10_000, lastFullScan: 1e12 };
    const r = await runRound(st, { chain: fakeChain(w), cfg: cfgOf(), now: 1e12 + 1000 });
    assert(
      r.alerts.some(a => a.key === "reverify") && !r.report.clear,
      r.alerts.map(a => a.key).join(",")
    );
    assert(
      r.alerts.some(a => a.key.startsWith("actionable:")),
      "the operator at block 120 was not found again"
    );
    assert(
      st.cursor === 250 && st.checked === 250,
      `rebuilt: cursor=${st.cursor} checked=${st.checked}`
    );
  }
);
await cell(
  "round: state times after now are reset and reported; the full rescan runs",
  async () => {
    const st = { ...emptyState(cfgOf()), lastFullScan: 5e12, alerts: { "actionable:x": 5e12 } };
    const { alerts } = await round(world(), cfgOf(), st, 1e12);
    assert(
      alerts.some(a => a.key === "clock"),
      "no clock alert"
    );
    assert(st.lastFullScan === 1e12 && st.alerts["actionable:x"] === 0, JSON.stringify(st.alerts));
  }
);

await cell(
  "round: a log above finalized that the range answer omits is caught by its by-hash answer",
  async () => {
    const w = world({ rangeHides: new Set([280]) });
    w.ops[OP2.toLowerCase()] = {
      configured: true,
      paused: false,
      role: true,
      eff: 1n,
      logBlock: 280,
    };
    const { alerts, report } = await round(w);
    assert(
      report.operators.some(o => o.operator === ethers.getAddress(OP2)),
      "the omitted operator was not read"
    );
    assert(
      alerts.some(a => /block 280 differ/.test(a.text)) && !report.clear,
      alerts.map(a => a.text).join("; ")
    );
  }
);
await cell("round: B == finalized == cursor still asks B by hash and compares", async () => {
  const w = world({ latest: 250, finalized: 250, rangeHides: new Set([250]) });
  w.ops[OP2.toLowerCase()] = {
    configured: true,
    paused: false,
    role: true,
    eff: 1n,
    logBlock: 250,
  };
  const { alerts, report } = await round(w);
  assert(
    report.operators.some(o => o.operator === ethers.getAddress(OP2)),
    "B's by-hash operator dropped"
  );
  assert(
    !report.clear && alerts.some(a => /block 250 differ/.test(a.text)),
    alerts.map(a => a.text).join("; ")
  );
});
await cell(
  "round: a latest block below finalized (a lagging backend) stops the round",
  async () => {
    let stopped = false;
    try {
      await round(world({ latest: 200, finalized: 250 }));
    } catch (e) {
      stopped = /lagging backend/.test(e.message);
    }
    assert(stopped, "not stopped");
  }
);
await cell(
  "round: a non-integer finalized height stops the round before any range is built",
  async () => {
    let stopped = false;
    try {
      await round(world({ finalizedRaw: Infinity }));
    } catch (e) {
      stopped = /not a block number/.test(e.message);
    }
    assert(stopped, "not stopped");
  }
);
await cell("ranges: refuses non-integer bounds and an unbounded number of chunks", () => {
  for (const [a, b, z] of [
    [0, Infinity, 10],
    [0, 1e12, 1],
    [0.5, 10, 1],
    [0, 10, 0],
  ]) {
    let refused = false;
    try {
      ranges(a, b, z);
    } catch {
      refused = true;
    }
    assert(refused, `accepted ${a},${b},${z}`);
  }
  assert(ranges(1, 10, 5).length === 2, "control");
});

await cell(
  "round: a simulation that returns anything but empty data is unknown, never clear (Codex R5 P1-2)",
  async () => {
    for (const bad of [null, "0x00", "0x" + "00".repeat(32), undefined]) {
      const w = world({ simResult: bad });
      Object.assign(w.ops[OP1.toLowerCase()], { eff: 0n, paused: true });
      const { report } = await round(w);
      assert(
        report.operators[0].status === "unknown" && !report.clear,
        `${bad}: ${report.operators[0].status}`
      );
    }
  }
);

await cell(
  "round: a by-hash/range disagreement moves the cursor back, so the next round reads that block again (Codex R8 P1-1)",
  async () => {
    const cfg = cfgOf({ rescanBlocks: 0 });
    const st = { ...emptyState(cfg), lastFullScan: 1e12 };
    const w = world({ latest: 300, finalized: 300, rangeHides: new Set([300]) });
    w.ops[OP2.toLowerCase()] = {
      configured: true,
      paused: false,
      role: true,
      eff: 1n,
      logBlock: 300,
    };
    st.cursor = 299;
    const r1 = await round(w, cfg, st, 1e12 + 1000);
    assert(
      !r1.report.clear && st.cursor === 299,
      `round 1: clear=${r1.report.clear} cursor=${st.cursor}`
    );
    // the backend recovers; B moves on: block 300 must still be read, and the operator found
    w.rangeHides = new Set();
    w.latest = 301;
    w.finalized = 301;
    const r2 = await round(w, cfg, st, 1e12 + 2000);
    assert(
      st.operators[ethers.getAddress(OP2)] === 300,
      "the operator at the skipped block was never found"
    );
    assert(
      r2.alerts.some(a => a.key === `actionable:${ethers.getAddress(OP2)}`) && !r2.report.clear,
      "no PAUSE NEEDED after recovery"
    );
  }
);

await cell(
  "round: a block not yet cross-checked stays pending across finalization until by-hash and by-range agree (Codex R9, R10)",
  async () => {
    const cfg = cfgOf({ rescanBlocks: 20000 });
    const st = { ...emptyState(cfg), lastFullScan: 1e12 };
    const w = world({ latest: 300, finalized: 250, rangeHides: new Set([290]) });
    // a staked operator, so "clear" is a real claim once the check catches up
    w.ops[OP2.toLowerCase()] = {
      configured: true,
      paused: false,
      role: true,
      eff: 500n,
      logBlock: 290,
    };
    const r1 = await round(w, cfg, st, 1e12 + 1000);
    assert(
      !r1.report.clear && st.checked < 290,
      `round 1: clear=${r1.report.clear} checked=${st.checked}`
    );
    assert(st.operators[ethers.getAddress(OP2)] === 290, "the hash-only operator was not kept");
    // block 290 is finalized now; the range backend STILL omits it: not clear, 290 still pending
    Object.assign(w, { latest: 600, finalized: 550 });
    const r2 = await round(w, cfg, st, 1e12 + 2000);
    assert(
      !r2.report.clear && st.checked < 290,
      `round 2: clear=${r2.report.clear} checked=${st.checked}`
    );
    assert(
      r2.report.operators.some(o => o.operator === ethers.getAddress(OP2)),
      "the operator disappeared"
    );
    // a failed by-hash read at 290 (Codex R10 #1): still pending, not clear
    w.fail = new Set(["logs-at-290"]);
    w.rangeHides = new Set();
    const r2b = await round(w, cfg, st, 1e12 + 2500);
    assert(
      !r2b.report.clear && st.checked < 290,
      `failed read: clear=${r2b.report.clear} checked=${st.checked}`
    );
    // control: both answers recover; the watermark catches up and the round is clear
    w.fail = new Set();
    Object.assign(w, { latest: 601, finalized: 551 });
    const r3 = await round(w, cfg, st, 1e12 + 3000);
    assert(
      r3.report.clear && st.checked === 551,
      `round 3: clear=${r3.report.clear} checked=${st.checked} ${r3.alerts.map(a => a.text).join("; ")}`
    );
  }
);
await cell(
  "round: a watermark above the finalized block is pulled back, so those blocks are compared again",
  async () => {
    const cfg = cfgOf({ rescanBlocks: 0 });
    const st = { ...emptyState(cfg), lastFullScan: 1e12, cursor: 250, checked: 280 };
    const w = world({ latest: 300, finalized: 250, rangeHides: new Set([260]) });
    w.ops[OP2.toLowerCase()] = {
      configured: true,
      paused: false,
      role: true,
      eff: 500n,
      logBlock: 260,
    };
    const r = await round(w, cfg, st, 1e12 + 1000);
    assert(
      !r.report.clear && r.alerts.some(a => /block 260 differ/.test(a.text)),
      r.alerts.map(a => a.text).join("; ")
    );
  }
);
await cell(
  "round: a cross-check backlog over MAX_CHECK blocks is worked off over rounds, unknown meanwhile",
  async () => {
    const cfg = cfgOf({ rescanBlocks: 0, logChunk: 5000 });
    const st = {
      ...emptyState(cfg),
      lastFullScan: 1e12,
      cursor: 9000,
      checked: 100,
      checkedHash: ethers.zeroPadValue(ethers.toBeHex(100), 32),
    };
    const w = world({ latest: 9010, finalized: 9000 });
    const r = await round(w, cfg, st, 1e12 + 1000);
    assert(
      !r.report.clear && r.alerts.some(a => /cross-check is behind/.test(a.text)),
      "a backlog read clear"
    );
    assert(st.checked === 100 + 4096, `watermark ${st.checked}`);
    await round(w, cfg, st, 1e12 + 2000);
    const r3 = await round(w, cfg, st, 1e12 + 3000);
    assert(
      r3.report.clear && st.checked === 9000,
      `after the backlog: clear=${r3.report.clear} checked=${st.checked}`
    );
  }
);
await cell(
  "round: a failed first round skips nothing: the watermark starts below startBlock (Codex R11 P1-1)",
  async () => {
    const cfg = cfgOf({ rescanBlocks: 20000 });
    const st = emptyState(cfg);
    assert(st.checked === cfg.startBlock - 1 && st.checkedHash === null, "fresh watermark");
    const w = world({
      latest: 300,
      finalized: 250,
      rangeHides: new Set([290]),
      fail: new Set(["blockByHash"]),
    });
    w.ops[OP2.toLowerCase()] = {
      configured: true,
      paused: false,
      role: true,
      eff: 1n,
      logBlock: 290,
    };
    const r1 = await round(w, cfg, st, 1e12);
    assert(!r1.report.clear, "round 1 clear with a failed ancestry walk");
    // the backend recovers its ancestry, much later; the range still omits 290
    Object.assign(w, { fail: new Set(), latest: 600, finalized: 550 });
    const r2 = await round(w, cfg, st, 1e12 + 3600_000);
    assert(
      !r2.report.clear && st.operators[ethers.getAddress(OP2)] === 290,
      `round 2: clear=${r2.report.clear}`
    );
    assert(
      r2.alerts.some(a => /block 290 differ/.test(a.text)),
      r2.alerts.map(a => a.text).join("; ")
    );
  }
);
await cell(
  "round: a round whose B left the chain commits no progress (Codex R11 P1-2)",
  async () => {
    const cfg = cfgOf({ rescanBlocks: 0 });
    const st = { ...emptyState(cfg), lastFullScan: 1e12, cursor: 250, checked: 249 };
    const before = JSON.stringify({
      c: st.cursor,
      k: st.checked,
      h: st.checkedHash,
      f: st.lastFullScan,
    });
    const r = await round(
      world({ latest: 300, finalized: 300, reorg: true }),
      cfg,
      st,
      1e12 + 1000
    );
    assert(r.alerts.some(a => a.key === "reorg") && !r.report.clear, "no reorg");
    const after = JSON.stringify({
      c: st.cursor,
      k: st.checked,
      h: st.checkedHash,
      f: st.lastFullScan,
    });
    assert(after === before, `progress kept: ${after} vs ${before}`);
  }
);
await cell(
  "round: a watermark whose block hash changed re-verifies from startBlock, cursor with it, and says so (Codex R12)",
  async () => {
    const cfg = cfgOf({ rescanBlocks: 0 });
    const st = {
      ...emptyState(cfg),
      lastFullScan: 1e12,
      cursor: 250,
      checked: 240,
      checkedHash: `0x${"ee".repeat(32)}`,
    };
    const r = await round(world({ latest: 300, finalized: 250 }), cfg, st, 1e12 + 1000);
    assert(
      r.alerts.some(a => a.key === "reverify"),
      r.alerts.map(a => a.key).join(",")
    );
    assert(
      st.checked === 250 && st.checkedHash !== null,
      `re-checked from the start: checked=${st.checked}`
    );
  }
);
await cell(
  "round: an operator seen only in a block's own range retry is kept (Codex R10 #2)",
  async () => {
    const cfg = cfgOf({ rescanBlocks: 0 });
    const st = { ...emptyState(cfg), lastFullScan: 1e12, cursor: 299, checked: 279 };
    // the range retry of block 280 (not covered by this round's scans) shows it; by hash it is missing
    const w = world({ latest: 300, finalized: 300, hashHides: new Set([280]) });
    w.ops[OP2.toLowerCase()] = {
      configured: true,
      paused: false,
      role: true,
      eff: 1n,
      logBlock: 280,
    };
    await round(w, cfg, st, 1e12 + 1000);
    assert(st.operators[ethers.getAddress(OP2)] === 280, "the range-retry operator was not kept");
  }
);

await cell(
  "round: a replaced chain under the watermark re-verifies from startBlock, so an omitted older log is caught (Codex R12 P1-1)",
  async () => {
    const cfg = cfgOf({ rescanBlocks: 0 });
    // an earlier round's inventory failed (cursor 99) while its cross-check reached 250
    const st = {
      ...emptyState(cfg),
      lastFullScan: 1e12,
      cursor: 99,
      checked: 250,
      checkedHash: ethers.zeroPadValue(ethers.toBeHex(250), 32),
    };
    // the replacement chain finalizes only 200; an understaked operator at 150 is omitted by range
    const w = world({ latest: 220, finalized: 200, rangeHides: new Set([150]) });
    w.ops[OP2.toLowerCase()] = {
      configured: true,
      paused: false,
      role: true,
      eff: 1n,
      logBlock: 150,
    };
    const r = await round(w, cfg, st, 1e12 + 1000);
    assert(
      !r.report.clear && r.alerts.some(a => a.key === "reverify"),
      r.alerts.map(a => a.key).join(",")
    );
    assert(
      r.alerts.some(a => /block 150 differ/.test(a.text)),
      "block 150 was never compared"
    );
  }
);
await cell(
  "round: a throw after the inventory advanced leaves cursor and rescan time as they were (Codex R12 P1-2)",
  async () => {
    const cfg = cfgOf();
    const st = emptyState(cfg);
    const before = JSON.stringify({ c: st.cursor, k: st.checked, f: st.lastFullScan });
    let threw = false;
    try {
      await round(world({ noLatest: true }), cfg, st, 1e12);
    } catch (e) {
      threw = /no latest block/.test(e.message);
    }
    assert(threw, "did not throw");
    const after = JSON.stringify({ c: st.cursor, k: st.checked, f: st.lastFullScan });
    assert(after === before, `progress kept after a throw: ${after} vs ${before}`);
    assert(Object.keys(st.operators).length === 1, "the inventory should still keep what it saw");
  }
);

await cell(
  "round: a by-number hash from another fork below finalized breaks the checked chain (Codex R13 P1-1)",
  async () => {
    const cfg = cfgOf({ rescanBlocks: 0 });
    const st = { ...emptyState(cfg), lastFullScan: 1e12, cursor: 250 };
    // the backend answers block 150 by number from an old fork (empty logs both ways), while the
    // canonical chain has an understaked operator configured at 150
    const w = world({
      latest: 300,
      finalized: 250,
      rangeHides: new Set([150]),
      oldFork: { 150: `0x${"0f".repeat(32)}` },
    });
    w.ops[OP2.toLowerCase()] = {
      configured: true,
      paused: false,
      role: true,
      eff: 1n,
      logBlock: 150,
    };
    const r = await round(w, cfg, st, 1e12 + 1000);
    assert(
      !r.report.clear && r.alerts.some(a => /does not follow the checked chain/.test(a.text)),
      r.alerts.map(a => a.text).join("; ")
    );
    assert(st.checked < 151, `the watermark crossed the fork: ${st.checked}`);
  }
);
await cell(
  "round: an advanced watermark without its hash re-verifies from startBlock (Codex R13 P1-2)",
  async () => {
    const cfg = cfgOf({ rescanBlocks: 0 });
    const st = {
      ...emptyState(cfg),
      lastFullScan: 1e12,
      cursor: 250,
      checked: 250,
      checkedHash: null,
    };
    const w = world({ latest: 300, finalized: 250, rangeHides: new Set([150]) });
    w.ops[OP2.toLowerCase()] = {
      configured: true,
      paused: false,
      role: true,
      eff: 500n,
      logBlock: 150,
    };
    const r = await round(w, cfg, st, 1e12 + 1000);
    assert(
      r.alerts.some(a => a.key === "reverify") && !r.report.clear,
      r.alerts.map(a => a.key).join(",")
    );
  }
);

await cell(
  "round: a node frozen at a height is unknown, never clear (clestons #434 B1)",
  async () => {
    const cfg = cfgOf();
    const st = emptyState(cfg);
    const w = world();
    // control: a fresh head (12 s old) reads clear
    const r0 = await round(w, cfg, st, 1e12);
    assert(r0.report.clear, "control: a fresh head is not clear");
    // the node freezes: the head stays at block 300 with its old timestamp; one hour later is still
    // within maxHeadAgeSec, a day and a week later are not
    w.frozenAt = Math.floor(1e12 / 1000) - 12;
    const r1 = await round(w, cfg, st, 1e12 + 1000 * 1000);
    assert(r1.report.clear, "control: a head 1000 s old (under 1800) is still clear");
    for (const later of [86_400_000, 7 * 86_400_000]) {
      let why = "";
      try {
        await round(w, cfg, st, 1e12 + later);
      } catch (e) {
        why = e.message;
      }
      assert(
        /frozen or lagging node/.test(why),
        `${later / 3600000} h later: ${why || "no error"}`
      );
    }
  }
);
await cell("round: a head without a timestamp is stale (fail closed)", async () => {
  assert(
    headStale({ number: 1 }, 1e12, 1800) && headStale({ timestamp: "x" }, 1e12, 1800),
    "accepted"
  );
  assert(!headStale({ timestamp: 1e9 - 10 }, 1e12, 1800), "control");
  assert(headStale({ timestamp: 1e9 - 1801 }, 1e12, 1800), "boundary");
});

await cell(
  "round: the SP proxy pointing at ANOTHER implementation fails identity, even with the configured one still deployed (clestons #434 F4)",
  async () => {
    // the configured implementation's code is still on chain (hash matches), but the proxy's slot
    // points at a different contract: only the slot check can see that
    const { alerts, report } = await round(
      world({ impl: "0x00000000000000000000000000000000000000d7", implCode: "0x60ff" })
    );
    assert(
      !report.identity.ok &&
        alerts.some(a => a.key === "identity" && /SuperPaymaster proxy/.test(a.text)),
      alerts.map(a => a.text).join("; ")
    );
  }
);

await cell(
  "round: a head fresh at the start but stale by the end of a long round is not clear (Codex R16 P1-2)",
  async () => {
    const cfg = cfgOf();
    const w = world({ headAgeSec: 1790 });
    w.nowMs = 1e12;
    let calls = 0;
    // the first look (accepting B) is at the start; every later one is 20 s on: 1810 s > 1800
    const clock = () => (calls++ === 0 ? 1e12 : 1e12 + 20_000);
    const r = await runRound(emptyState(cfg), { chain: fakeChain(w), cfg, now: 1e12, clock });
    assert(
      !r.report.clear && r.alerts.some(a => a.key === "stale-at-end"),
      r.alerts.map(a => a.key).join(",")
    );
    // control: the same round with a clock that does not move reads clear
    const c = await runRound(emptyState(cfg), {
      chain: fakeChain(w),
      cfg,
      now: 1e12,
      clock: () => 1e12,
    });
    assert(c.report.clear, "control: not clear");
  }
);
await cell(
  "files: recordStop writes only into our own real state directory (Codex R16 P1-1)",
  () => {
    const home = realpathSync(mkdtempSync(join(tmpdir(), "pd-rs-")));
    try {
      const d = join(home, ".aoa-pause-detector");
      mkdirSync(d, { mode: 0o700 });
      const elsewhere = join(home, "elsewhere");
      mkdirSync(elsewhere);
      symlinkSync(elsewhere, join(d, "state"));
      recordStop(home, "x");
      assert(
        !existsSync(join(elsewhere, "status.json")),
        "wrote through a symlinked state directory"
      );
      rmSync(join(d, "state"));
      mkdirSync(join(d, "state"), { mode: 0o700 });
      recordStop(home, "stopped for a reason");
      const j = JSON.parse(readFileSync(join(d, "state", "status.json"), "utf8"));
      assert(j.clear === false && j.startup === "stopped for a reason", "control: not written");
    } finally {
      rmSync(home, { recursive: true, force: true });
    }
  }
);

// ---------------------------------------------------------------- delivery

await cell("delivery: many alerts are split into whole-line messages under the limit", () => {
  const entries = Array.from({ length: 40 }, (_, k) => ({ line: `- ${"x".repeat(180)} ${k}` }));
  const b = batches("H:", entries);
  assert(b.length > 1 && b.every(m => m.text.length <= MESSAGE_CHARS), "over the limit");
  assert(b.flatMap(m => m.items).length === 40, "a line lost");
  assert(
    b.every(m => m.items.every(e => m.text.includes(e.line))),
    "a line cut"
  );
});
await cell("delivery: only alerts in messages Telegram accepted are marked sent", async () => {
  const st = { alerts: { old: 1 } };
  const due = Array.from({ length: 40 }, (_, k) => ({
    key: `k${k}`,
    text: `${"y".repeat(180)} ${k}`,
  }));
  let n = 0;
  const r = await deliver(st, due, ["old"], "H:", 5, async () =>
    n++ === 0 ? { ok: true } : { ok: false, why: "x" }
  );
  const marked = Object.keys(st.alerts).filter(k => st.alerts[k] === 5);
  assert(
    !r.ok && r.failed > 0 && marked.length === r.sent && marked.length < 40,
    JSON.stringify(r)
  );
  // the resolution rides in the last message, which failed: it must still be pending
  assert("old" in st.alerts, "a resolution in a failed message was acknowledged");
});
await cell("delivery: HTTP 200 with ok:false or a non-JSON body is NOT delivered", async () => {
  const cfg = { telegram: { chatId: "1" } };
  const res = (status, body) => ({
    ok: status < 300,
    status,
    json: async () => (body === "bad" ? JSON.parse("{") : body),
  });
  assert(
    (await telegram(cfg, "t", "x", async () => res(200, { ok: true }))).ok === true,
    "ok:true not ok"
  );
  assert(
    (await telegram(cfg, "t", "x", async () => res(200, { ok: false }))).ok === false,
    "ok:false accepted"
  );
  assert(
    (await telegram(cfg, "t", "x", async () => res(200, "bad"))).ok === false,
    "non-JSON accepted"
  );
  assert(
    (await telegram(cfg, "t", "x", async () => res(429, { ok: false }))).ok === false,
    "429 accepted"
  );
});

// ---------------------------------------------------------------- alert bookkeeping

await cell("alerts: a key alerted within realertMinutes is not resent; after it is", () => {
  const st = { alerts: { k: 1_000 } };
  assert(dueAlerts(st, [{ key: "k" }], 60, 1_000 + 59 * 60_000).length === 0, "resent early");
  assert(dueAlerts(st, [{ key: "k" }], 60, 1_000 + 60 * 60_000).length === 1, "not resent");
  assert(dueAlerts(st, [{ key: "new" }], 60, 0).length === 1, "new key not sent");
});
await cell(
  "alerts: an actionable key resolves only when that operator was read clear at a canonical B",
  () => {
    const k = `actionable:${ethers.getAddress(OP1)}`;
    const st = { alerts: { [k]: 1, identity: 1 } };
    const ok = {
      canonical: true,
      identity: { ok: true },
      operators: [{ operator: ethers.getAddress(OP1), status: "ok" }],
    };
    assert(
      resolvedKeys(st, [], ok).sort().join() === [k, "identity"].sort().join(),
      "not resolved"
    );
    assert(resolvedKeys(st, [], { ...ok, canonical: false }).length === 0, "resolved on a reorg");
    assert(
      resolvedKeys(st, [], { ...ok, fresh: false }).length === 0,
      "resolved on a head stale by the end (Codex R17)"
    );
    assert(
      !resolvedKeys(st, [], { ...ok, identity: { ok: false } }).includes(k),
      "resolved without identity"
    );
    assert(
      !resolvedKeys(st, [], { ...ok, operators: [] }).includes(k),
      "resolved without reading the operator"
    );
    assert(
      !resolvedKeys(st, [], {
        ...ok,
        operators: [{ operator: ethers.getAddress(OP1), status: "unknown" }],
      }).includes(k),
      "resolved on an unknown read"
    );
    assert(resolvedKeys(st, [{ key: k }], ok).length === 1, "an alert still present resolved");
  }
);

// ---------------------------------------------------------------- config

await cell("secrets: the detector's name table holds no keystore or password file", () => {
  const names = Object.values(DETECTOR_SECRETS);
  assert(
    names.length === 3 && !names.some(n => /keystore|pw|password|key$/i.test(n)),
    names.join()
  );
});
await cell("secrets: the detector cannot read the pause job's keystore password file", () => {
  let refused = false;
  try {
    readSecretFile("aoa-dvt-pause-keystore-pw", "/tmp", { names: DETECTOR_SECRETS });
  } catch (e) {
    refused = /not a known secret name/.test(e.message);
  }
  assert(refused, "the keystore password name was accepted");
});
await cell("config: the example config is valid", () => {
  const c = JSON.parse(readFileSync(join(HERE, "config.example.json"), "utf8"));
  const p = configProblems(c);
  assert(p.length === 0, p.join("; "));
});
await cell(
  "config: a missing code hash or implementation is refused (no unpinned identity)",
  () => {
    const c = JSON.parse(readFileSync(join(HERE, "config.example.json"), "utf8"));
    for (const k of [
      "implementation",
      "registryImplementation",
      "proxyCodeHash",
      "implementationCodeHash",
      "registryCodeHash",
      "registryImplementationCodeHash",
    ]) {
      const d = { ...c };
      delete d[k];
      assert(
        configProblems(d).some(x => x.startsWith(k)),
        `${k} not required`
      );
    }
  }
);
// the confinement: Node's permission model with the plist's flags, run from a real bundle
const PERM_FLAG =
  Number(process.versions.node.split(".")[0]) >= 22 ? "--permission" : "--experimental-permission";
const runNode = (flags, code) =>
  spawnSync(process.execPath, [...flags, "--input-type=module", "-e", code], { encoding: "utf8" });
/** A fresh home with ~/.aoa-pause-detector/{state,app}: the app built by bundle.mjs. */
const makeHome = () => {
  const home = realpathSync(mkdtempSync(join(homedir(), ".pd-check-")));
  const d = join(home, ".aoa-pause-detector");
  mkdirSync(join(d, "state"), { recursive: true, mode: 0o700 });
  const b = spawnSync(
    process.execPath,
    [join(HERE, "bundle.mjs"), "--out", join(d, "app"), "--allow-dirty"],
    {
      encoding: "utf8",
    }
  );
  if (b.status !== 0) {
    rmSync(home, { recursive: true, force: true }); // no home left behind on a failed build
    throw new Error(`bundle failed: ${b.stderr}`);
  }
  return { home, d, app: join(d, "app") };
};
const plistFlags = d => [PERM_FLAG, `--allow-fs-read=${d}`, `--allow-fs-write=${join(d, "state")}`];
const runDetector = ({ home, d }, env = {}) =>
  spawnSync(
    process.execPath,
    [
      ...plistFlags(d),
      join(d, "app/deploy/pause-detector/detector.mjs"),
      "--config",
      join(d, "config.json"),
    ],
    { encoding: "utf8", env: { PATH: process.env.PATH, HOME: home, ...env } }
  );
const withHomeAsync = async fn => {
  const h = makeHome();
  try {
    await fn(h);
  } finally {
    rmSync(h.home, { recursive: true, force: true });
  }
};
const runDetectorAsync = ({ home, d }, env = {}) =>
  new Promise(res => {
    const c = spawn(
      process.execPath,
      [
        ...plistFlags(d),
        join(d, "app/deploy/pause-detector/detector.mjs"),
        "--config",
        join(d, "config.json"),
      ],
      { env: { PATH: process.env.PATH, HOME: home, ...env } }
    );
    let stderr = "";
    c.stderr.on("data", x => (stderr += x));
    c.on("close", status => res({ status, stderr }));
  });
const withHome = fn => {
  const h = makeHome();
  try {
    fn(h);
  } finally {
    rmSync(h.home, { recursive: true, force: true });
  }
};

await cell(
  "permission: under the plist's flags no child process, worker or outside read is possible",
  () =>
    withHome(({ home, d, app }) => {
      writeFileSync(join(home, "key.env"), "KEEPER_PRIVATE_KEY=0xnot-a-key");
      const probe = `
      const out = [];
      try { (await import("node:child_process")).execFileSync("/usr/bin/true"); out.push("spawn"); } catch {}
      try { new (await import("node:worker_threads")).Worker("1", { eval: true }); out.push("worker"); } catch {}
      try { (await import("node:fs")).readFileSync(${JSON.stringify(join(home, "key.env"))}); out.push("read"); } catch {}
      try { (await import("node:fs")).readFileSync(${JSON.stringify(join(resolve(HERE, "../.."), "package.json"))}); out.push("read-repo"); } catch {}
      const { permissionProblems } = await import(${JSON.stringify(join(app, "deploy/pause-detector/lib/guard.mjs"))});
      console.log(JSON.stringify({ out, problems: permissionProblems(process.permission, ${JSON.stringify(home)}) }));`;
      const last = r => JSON.parse(r.stdout.trim().split("\n").pop());
      const j = last(runNode(plistFlags(d), probe));
      assert(j.out.length === 0, `allowed: ${j.out.join(",")}`);
      assert(j.problems.length === 0, j.problems.join("; "));
      // controls: without the model, and with child processes allowed, the guard reports problems
      const bare = last(runNode([], probe));
      assert(
        bare.problems.length > 0 && bare.out.includes("spawn"),
        "control: no model not refused"
      );
      const child = last(runNode([...plistFlags(d), "--allow-child-process"], probe));
      assert(
        child.problems.some(x => /child processes/.test(x)),
        "control: child processes not refused"
      );
    })
);
await cell("permission: launchProblems accepts exactly the plist's launch and nothing more", () => {
  const H = "/Users/u";
  const d = `${H}/.aoa-pause-detector`;
  const good = ["--permission", `--allow-fs-read=${d}`, `--allow-fs-write=${d}/state`];
  const script = `${d}/app/deploy/pause-detector/detector.mjs`;
  const args = ["--config", `${d}/config.json`];
  const ok = x => launchProblems({ home: H, script, args, envNames: ["PATH", "HOME"], ...x });
  assert(ok({ execArgv: good }).length === 0, ok({ execArgv: good }).join("; "));
  assert(
    ok({ execArgv: ["--experimental-permission", ...good.slice(1)] }).length === 0,
    "node 20 form"
  );
  for (const [what, x] of [
    ["an extra read", { execArgv: [...good, `--allow-fs-read=${H}/.ssh/id_ed25519`] }],
    [
      "the repo granted (Codex R7)",
      { execArgv: [good[0], "--allow-fs-read=/Users/u/Dev/repo", ...good.slice(1)] },
    ],
    ["child processes", { execArgv: [...good, "--allow-child-process"] }],
    ["no --permission", { execArgv: good.slice(1) }],
    [
      "an extra argument after the script (F3)",
      { execArgv: good, args: [...args, "--private-key", "0x1"] },
    ],
    ["another config", { execArgv: good, args: ["--config", "/tmp/x.json"] }],
    [
      "run from a checkout, not the bundle",
      { execArgv: good, script: "/Users/u/Dev/repo/deploy/pause-detector/detector.mjs" },
    ],
  ])
    assert(ok(x).length > 0, `accepted ${what}`);
  for (const n of ["NODE_OPTIONS", "NODE_PATH", "DYLD_INSERT_LIBRARIES", "BASH_ENV"])
    assert(ok({ execArgv: good, envNames: ["PATH", n] }).length > 0, `accepted ${n}`);
  // an allowlist: a key in the environment, or anything unknown, refuses (Codex R8 P1-2)
  for (const n of ["KEEPER_PRIVATE_KEY", "PRIVATE_KEY", "RPC_URL", "anything"])
    assert(
      ok({ execArgv: good, envNames: ["PATH", n] }).some(x => /allowlist/.test(x)),
      `accepted ${n}`
    );
  const launchdEnv = [
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "SHELL",
    "TMPDIR",
    "XPC_FLAGS",
    "XPC_SERVICE_NAME",
    "OSLogRateLimit",
    "__CF_USER_TEXT_ENCODING",
    "SSH_AUTH_SOCK",
  ];
  assert(
    ok({ execArgv: good, envNames: launchdEnv }).length === 0,
    "control: launchd's own variables refused"
  );
});
await cell(
  "permission: the real bundle, launched as the plist does, passes every guard (control)",
  () =>
    withHome(h => {
      const r = runDetector(h);
      // past the guards and into run.mjs: it stops at the missing config, nothing earlier
      assert(r.status === 78 && /config: missing/.test(r.stderr), `${r.status} ${r.stderr}`);
    })
);
await cell("permission: a NODE_OPTIONS grant makes detector.mjs refuse (Codex R4 P1-1)", () =>
  withHome(h => {
    const r = runDetector(h, { NODE_OPTIONS: `--allow-fs-read=${join(h.home, "key.env")}` });
    assert(
      r.status === 78 && /option-injecting variables are set: NODE_OPTIONS/.test(r.stderr),
      `${r.status} ${r.stderr}`
    );
    // the refusal is not silent: status.json records it, and preflight FAILs on that (F1)
    const stop = JSON.parse(readFileSync(join(h.d, "state", "status.json"), "utf8"));
    assert(stop.clear === false && /option-injecting/.test(stop.startup), JSON.stringify(stop));
  })
);
await cell(
  "files: readOwnJson never follows a symlink, needs our own file, never echoes bytes",
  () => {
    const d = realpathSync(mkdtempSync(join(tmpdir(), "pd-own-")));
    try {
      writeFileSync(join(d, "ok.json"), '{"a":1}', { mode: 0o600 });
      assert(readOwnJson(join(d, "ok.json"), "x").a === 1, "control");
      writeFileSync(join(d, "key.env"), "KEEPER_PRIVATE_KEY=0xnot-a-key", { mode: 0o600 });
      symlinkSync(join(d, "key.env"), join(d, "link.json"));
      writeFileSync(join(d, "gw.json"), "{}");
      chmodSync(join(d, "gw.json"), 0o664);
      for (const [f, re] of [
        ["link.json", /symlink/],
        ["gw.json", /group or others/],
        ["none.json", /missing/],
        ["key.env", /not JSON/],
      ]) {
        let why = "";
        try {
          readOwnJson(join(d, f), "x");
        } catch (e) {
          why = e.message;
        }
        assert(re.test(why) && !/not-a-key/.test(why), `${f}: ${why}`);
      }
      assert(
        symlinkProblems(d).some(x => x.includes("link.json")),
        "symlink not found"
      );
      rmSync(join(d, "link.json"));
      assert(symlinkProblems(d).length === 0, "control: no symlink");
    } finally {
      rmSync(d, { recursive: true, force: true });
    }
  }
);
await cell(
  "bundle: bundle.mjs makes a bundle that is exactly its manifest; any change is refused",
  () =>
    withHome(({ app }) => {
      assert(bundleProblems(app).length === 0, bundleProblems(app).join("; "));
      const man = JSON.parse(readFileSync(join(app, "MANIFEST.json"), "utf8"));
      for (const f of [
        "deploy/pause-detector/detector.mjs",
        "deploy/pause-detector/run.mjs",
        "deploy/pause-detector/lib/guard.mjs",
        "deploy/pause-detector/lib/detect.mjs",
        "deploy/pause-job/lib/secret-file.mjs",
        "deploy/pause-job/lib/safe-error.mjs",
        "deploy/pause-job/sp-pin.json",
        "node_modules/ethers/package.json",
      ])
        assert(f in man.files, `${f} not bundled`);
      assert(
        !Object.keys(man.files).some(f =>
          /node_state|\.env|\.keys|bundle\.mjs|check-|e2e-/.test(f)
        ),
        "a non-runtime file bundled"
      );
      const edits = [
        [
          "an extra file (a key someone left there)",
          () => writeFileSync(join(app, "node_state.json"), "{}"),
          /not in its manifest/,
        ],
        [
          "a changed file",
          () => writeFileSync(join(app, "deploy/pause-job/sp-pin.json"), "{}"),
          /does not hash/,
        ],
        [
          "a missing file",
          () => rmSync(join(app, "deploy/pause-detector/lib/detect.mjs")),
          /missing/,
        ],
        ["a symlink", () => symlinkSync("/etc/hosts", join(app, "x")), /is a symlink/],
      ];
      for (const [what, act, re] of edits) {
        const before = readFileSync(join(app, "MANIFEST.json"));
        act();
        const p = bundleProblems(app);
        assert(
          p.some(x => re.test(x)),
          `${what}: ${p.join("; ")}`
        );
        // undo by rebuilding the state the next edit expects
        rmSync(join(app, "node_state.json"), { force: true });
        rmSync(join(app, "x"), { force: true });
        writeFileSync(join(app, "MANIFEST.json"), before);
      }
    })
);
await cell(
  "permission: an sp-pin.json symlinked to a key makes detector.mjs refuse BEFORE run.mjs is loaded (Codex R7 P1-2)",
  () =>
    withHome(({ home, app, d }) => {
      writeFileSync(join(home, "key.env"), "KEEPER_PRIVATE_KEY=0xnot-a-key", { mode: 0o600 });
      rmSync(join(app, "deploy/pause-job/sp-pin.json"));
      symlinkSync(join(home, "key.env"), join(app, "deploy/pause-job/sp-pin.json"));
      const r = runDetector({ home, d });
      assert(
        r.status === 78 && /refusing to run/.test(r.stderr) && /symlink/.test(r.stderr),
        `${r.status} ${r.stderr}`
      );
      assert(!/not-a-key/.test(r.stderr + r.stdout), "key text leaked");
    })
);
await cell(
  "permission: a config.json symlinked to a key makes detector.mjs refuse without reading it",
  () =>
    withHome(({ home, d }) => {
      writeFileSync(join(home, "key.env"), "KEEPER_PRIVATE_KEY=0xnot-a-key", { mode: 0o600 });
      symlinkSync(join(home, "key.env"), join(d, "config.json"));
      const r = runDetector({ home, d });
      assert(
        r.status === 78 && /symlink/.test(r.stderr) && !/not-a-key/.test(r.stderr + r.stdout),
        `${r.status} ${r.stderr}`
      );
    })
);
// a minimal JSON-RPC server: Sepolia's chain id, and a head `age` seconds old
const rpcServer = age =>
  new Promise(res => {
    const srv = createHttpServer((req, out) => {
      let body = "";
      req.on("data", c => (body += c));
      req.on("end", () => {
        const { id, method } = JSON.parse(body);
        const result =
          method === "eth_chainId"
            ? "0xaa36a7"
            : method === "eth_getBlockByNumber"
              ? {
                  number: "0x12c",
                  hash: `0x${"ab".repeat(32)}`,
                  timestamp: ethers.toQuantity(Math.floor(Date.now() / 1000) - age),
                }
              : null;
        out.setHeader("content-type", "application/json");
        out.end(
          JSON.stringify(
            result === null
              ? { jsonrpc: "2.0", id, error: { code: -32000, message: "no" } }
              : { jsonrpc: "2.0", id, result }
          )
        );
      });
    });
    srv.listen(0, "127.0.0.1", () => res(srv));
  });
const runBundleAgainst = async (age, fn) => {
  const srv = await rpcServer(age);
  try {
    await withHomeAsync(async h => {
      const url = `http://127.0.0.1:${srv.address().port}`;
      mkdirSync(join(h.d, "secrets"), { mode: 0o700 });
      for (const n of ["aoa-dvt-detector-rpc-primary", "aoa-dvt-detector-rpc-fallback"])
        writeFileSync(join(h.d, "secrets", n), url, { mode: 0o600 });
      const ex = JSON.parse(readFileSync(join(HERE, "config.example.json"), "utf8"));
      writeFileSync(
        join(h.d, "config.json"),
        JSON.stringify({
          ...ex,
          stateDir: join(h.d, "state"),
          secretsDir: join(h.d, "secrets"),
          telegram: null,
          lockPort: 40000 + Math.floor(Math.random() * 20000),
        }),
        { mode: 0o600 }
      );
      const r = await runDetectorAsync(h);
      const status = JSON.parse(readFileSync(join(h.d, "state", "status.json"), "utf8"));
      fn(r, status, h);
    });
  } finally {
    srv.close();
  }
};
await cell(
  "provider: a frozen head (a week old) on both providers ends the run unknown, never clear (clestons #434 B1, end to end)",
  async () =>
    runBundleAgainst(7 * 86400, (r, status, h) => {
      assert(
        !existsSync(join(h.d, "state", "heartbeat.json")),
        "a run on a frozen head wrote a heartbeat"
      );
      assert(r.status !== 0 && status.clear === false, `exit ${r.status}, clear ${status.clear}`);
      assert(
        /no RPC provider has a fresh head \(stale: alchemy, infura/.test(status.startup ?? ""),
        JSON.stringify(status)
      );
    })
);
await cell(
  "provider: CONTROL a fresh head gets past the probe (and fails later, unknown, on the missing reads)",
  async () =>
    runBundleAgainst(5, (r, status, h) => {
      // a completed round, even one that reads unknown, is proof of life for the dead-man
      assert(
        existsSync(join(h.d, "state", "heartbeat.json")),
        "a completed round wrote no heartbeat"
      );
      assert(
        status.clear === false && !/fresh head/.test(JSON.stringify(status)),
        JSON.stringify(status).slice(0, 300)
      );
    })
);
await cell(
  "crash label: only an allowlisted code or class, never text, never a throw (Codex dm-R1 P1-3)",
  () => {
    assert(crashLabel({ code: "ERR_ACCESS_DENIED" }) === "ERR_ACCESS_DENIED", "control code");
    assert(crashLabel(new TypeError("x https://key@rpc")) === "TypeError", "control class");
    for (const e of [
      { code: "https://provider.example/secret" },
      { name: "https://provider.example/secret" },
      { code: "E" + "x".repeat(40) },
      "a string with a url https://x",
      null,
      {
        get code() {
          throw new Error("boom");
        },
        get name() {
          throw new Error("boom");
        },
      },
    ])
      assert(
        crashLabel(e) === "error",
        "a non-allowlisted error produced a label other than error"
      );
  }
);

await cell(
  "dead-man: a long undelivered queue keeps the first outage and the full count (Codex dm-R2 P1-1)",
  () => {
    let q = [];
    for (let k = 0; k < 30; k++) q = compactQueue([...q, `m${k}`]);
    assert(q.length <= QUEUE_MAX && q[0] === "m0" && q[q.length - 1] === "m29", q.join(" | "));
    const folded = Number(/^\((\d+) more/.exec(q[1])?.[1]);
    assert(
      1 + folded + (q.length - 2) === 30,
      `messages represented: ${1 + folded + (q.length - 2)}`
    );
    assert(compactQueue(["a", "b"]).join() === "a,b", "control: a short queue is untouched");
  }
);

await cell(
  "dead-man: the outage is on disk BEFORE delivery is attempted (write-ahead, Codex dm-R3 P1)",
  async () => {
    const home = realpathSync(mkdtempSync(join(tmpdir(), "pd-wa-")));
    const realHome = process.env.HOME;
    try {
      const d = join(home, ".aoa-pause-detector");
      mkdirSync(join(d, "deadman"), { recursive: true, mode: 0o700 });
      mkdirSync(join(d, "state"), { mode: 0o700 });
      writeFileSync(join(d, "config.json"), JSON.stringify({ chainId: 11155111, telegram: null }), {
        mode: 0o600,
      });
      process.env.HOME = home;
      let onDisk = null;
      // the delivery "dies": it never returns ok, and before it does we look at what is persisted
      const code = await deadmanMain({
        send: async () => {
          onDisk = JSON.parse(readFileSync(join(d, "deadman", "state.json"), "utf8"));
          return { ok: false, why: "killed" };
        },
      });
      assert(
        onDisk &&
          onDisk.alerting === true &&
          onDisk.queue.length === 1 &&
          /DEAD-MAN/.test(onDisk.queue[0]),
        `not written ahead: ${JSON.stringify(onDisk)}`
      );
      assert(code === 1, `exit ${code}`);
      // a later run that delivers empties the queue
      const code2 = await deadmanMain({ send: async () => ({ ok: true }) });
      const after = JSON.parse(readFileSync(join(d, "deadman", "state.json"), "utf8"));
      assert(
        after.queue.length === 0 && code2 === 1,
        `after delivery: ${JSON.stringify(after)} exit ${code2}`
      );
    } finally {
      process.env.HOME = realHome;
      rmSync(home, { recursive: true, force: true });
    }
  }
);

await cell(
  "dead-man: a gap between completed rounds is reported once from the heartbeat, even after a lost queue (Codex dm-R4 P1)",
  () => {
    const T = 1e12;
    const iso = ms => new Date(ms).toISOString();
    // rounds resumed a minute ago after 5 h of silence; the dead-man's state was rolled back (no
    // record of having alerted): the gap is still reported
    const hb = {
      schema: "aoa-pause-detector-heartbeat/1",
      at: iso(T - 60_000),
      prevAt: iso(T - 60_000 - 5 * 3600_000),
    };
    const a = deadmanDecision(hb, T, {});
    assert(!a.silent && /no successful round from .* \(300 min\)/.test(a.message ?? ""), a.message);
    // the next run, with that recorded, says nothing more
    const b = deadmanDecision(hb, T + 900_000, a.next);
    assert(b.message === null, `reported twice: ${b.message}`);
    // control: a normal hourly gap is not reported
    const c = deadmanDecision({ ...hb, prevAt: iso(T - 60_000 - 3600_000) }, T, {});
    assert(c.message === null, `an hourly gap reported: ${c.message}`);
  }
);

// ---------------------------------------------------------------- dead-man (DSR)

await cell("dead-man: the decision (alive, silent, re-alert, resume, missing, future)", () => {
  const T = 1e12;
  const hb = msAgo => ({
    schema: "aoa-pause-detector-heartbeat/1",
    at: new Date(T - msAgo).toISOString(),
  });
  const fresh = deadmanDecision(hb(3600_000), T, {});
  assert(!fresh.silent && fresh.message === null, "a 1 h old heartbeat is not alive");
  const edge = deadmanDecision(hb(MAX_SILENCE_MS), T, {});
  assert(!edge.silent, "exactly 2 h is still alive (control)");
  const late = deadmanDecision(hb(MAX_SILENCE_MS + 1000), T, {});
  assert(
    late.silent && /no successful round for more than 2 h/.test(late.message) && late.next.alerting,
    "not alerted"
  );
  const again = deadmanDecision(hb(MAX_SILENCE_MS + 2000), T, {
    alerting: true,
    lastSent: T - 1000,
  });
  assert(again.silent && again.message === null, "re-alerted too soon");
  const later = deadmanDecision(hb(MAX_SILENCE_MS + 2000), T, {
    alerting: true,
    lastSent: T - REALERT_MS,
  });
  assert(later.message !== null, "not re-alerted after REALERT_MS");
  const back = deadmanDecision(hb(60_000), T, { alerting: true, lastSent: T - 1000 });
  assert(
    !back.silent && /resumed/.test(back.message) && back.next.alerting === false,
    "no resume notice"
  );
  for (const h of [null, {}, { schema: "x", at: new Date(T).toISOString() }, hb(-600_000)])
    assert(deadmanDecision(h, T, {}).silent, `alive on ${JSON.stringify(h)}`);
});
await cell(
  "dead-man: launchProblems accepts only the dead-man's own launch (writes deadman/, runs deadman.mjs)",
  () => {
    const H = "/Users/u";
    const d = `${H}/.aoa-pause-detector`;
    const base = {
      home: H,
      args: ["--config", `${d}/config.json`],
      envNames: ["PATH", "HOME"],
      entry: "deadman",
    };
    const ok = ["--permission", `--allow-fs-read=${d}`, `--allow-fs-write=${d}/deadman`];
    assert(
      launchProblems({
        ...base,
        execArgv: ok,
        script: `${d}/app/deploy/pause-detector/deadman.mjs`,
      }).length === 0,
      "control"
    );
    assert(
      launchProblems({
        ...base,
        execArgv: [ok[0], ok[1], `--allow-fs-write=${d}/state`],
        script: `${d}/app/deploy/pause-detector/deadman.mjs`,
      }).length > 0,
      "may write the detector's state"
    );
    assert(
      launchProblems({
        ...base,
        execArgv: ok,
        script: `${d}/app/deploy/pause-detector/detector.mjs`,
      }).length > 0,
      "runs the detector"
    );
  }
);
await cell("dead-man: the bundle carries both entries and the scan covers deadman.mjs", () =>
  withHome(({ app }) => {
    const man = JSON.parse(readFileSync(join(app, "MANIFEST.json"), "utf8"));
    for (const f of ["deploy/pause-detector/deadman.mjs", "deploy/pause-detector/deadman-run.mjs"])
      assert(f in man.files, `${f} not bundled`);
    const p = scanTree(join(HERE, "deadman.mjs"));
    assert(p.length === 0, p.join("; "));
  })
);
await cell("dead-man: the plist runs the dead-man every 15 minutes, exactly", () => {
  const x = readFileSync(join(HERE, "io.aastar.dvt-pause-detector-deadman.plist"), "utf8");
  const args = [
    ...x
      .match(/<key>ProgramArguments<\/key>\s*<array>([\s\S]*?)<\/array>/)[1]
      .matchAll(/<string>([^<]*)<\/string>/g),
  ].map(m => m[1]);
  assert(
    args.join("\n") ===
      [
        "__HOME__/.local/keeper-node/node-v24.21.0/bin/node",
        "--permission",
        "--allow-fs-read=__HOME__/.aoa-pause-detector",
        "--allow-fs-write=__HOME__/.aoa-pause-detector/deadman",
        "__HOME__/.aoa-pause-detector/app/deploy/pause-detector/deadman.mjs",
        "--config",
        "__HOME__/.aoa-pause-detector/config.json",
      ].join("\n"),
    args.join(" ")
  );
  assert(/<key>StartInterval<\/key>\s*<integer>900<\/integer>/.test(x), "not every 15 min");
  assert(/<string>io\.aastar\.dvt-pause-detector-deadman<\/string>/.test(x), "label");
});
await cell(
  "dead-man: end to end, launched as its plist does: no heartbeat is silent; a fresh one is alive",
  () =>
    withHome(({ home, d }) => {
      mkdirSync(join(d, "deadman"), { mode: 0o700 });
      writeFileSync(join(d, "config.json"), JSON.stringify({ chainId: 11155111, telegram: null }), {
        mode: 0o600,
      });
      const run = () =>
        spawnSync(
          process.execPath,
          [
            PERM_FLAG,
            `--allow-fs-read=${d}`,
            `--allow-fs-write=${join(d, "deadman")}`,
            join(d, "app/deploy/pause-detector/deadman.mjs"),
            "--config",
            join(d, "config.json"),
          ],
          { encoding: "utf8", env: { PATH: process.env.PATH, HOME: home } }
        );
      const status = () => JSON.parse(readFileSync(join(d, "deadman", "status.json"), "utf8"));
      const r1 = run();
      assert(
        r1.status === 1 && status().silent === true && /DEAD-MAN/.test(r1.stderr),
        `no heartbeat: ${r1.status} ${r1.stderr}`
      );
      // a heartbeat a minute old, written as the detector writes it
      writeFileSync(
        join(d, "state", "heartbeat.json"),
        JSON.stringify({
          schema: "aoa-pause-detector-heartbeat/1",
          at: new Date(Date.now() - 60_000).toISOString(),
          block: 1,
          clear: true,
        }),
        { mode: 0o600 }
      );
      const r2 = run();
      // alive now; with telegram null nothing can be delivered, so the outage alert and the
      // resume notice stay queued (exit 1) and are never dropped (Codex dm-R1 P1-1)
      assert(
        r2.status === 1 && status().silent === false && status().undelivered === 2,
        `fresh heartbeat: ${r2.status} ${JSON.stringify(status())}`
      );
      // an existing state that cannot be read is a visible stop, and it is left as it is
      // (Codex dm-R2 P1-2): never overwritten as healthy
      writeFileSync(join(d, "deadman", "state.json"), "{ not json", { mode: 0o600 });
      const r3 = run();
      assert(
        r3.status === 1 && /unreadable/.test(status().startup ?? ""),
        `unreadable state: ${r3.status} ${JSON.stringify(status())}`
      );
      assert(
        readFileSync(join(d, "deadman", "state.json"), "utf8") === "{ not json",
        "the unreadable state was overwritten"
      );
      // and it may not write the detector's state (the grant is deadman/ only)
      assert(
        !existsSync(join(d, "state", "status.json")),
        "the dead-man wrote the detector's status"
      );
    })
);

await cell("permission: detector.mjs refuses to start outside the permission model", () =>
  withHome(({ home, d }) => {
    const r = spawnSync(
      process.execPath,
      [join(d, "app/deploy/pause-detector/detector.mjs"), "--config", "/x"],
      {
        encoding: "utf8",
        env: { PATH: process.env.PATH, HOME: home },
      }
    );
    assert(r.status === 78 && /permission model/.test(r.stderr), `${r.status} ${r.stderr}`);
  })
);
await cell(
  "config: the plist runs the pinned node, under the permission model, from the bundle, exactly",
  () => {
    const x = readFileSync(join(HERE, "io.aastar.dvt-pause-detector.plist"), "utf8");
    const args = [
      ...x
        .match(/<key>ProgramArguments<\/key>\s*<array>([\s\S]*?)<\/array>/)[1]
        .matchAll(/<string>([^<]*)<\/string>/g),
    ].map(m => m[1]);
    const want = [
      "__HOME__/.local/keeper-node/node-v24.21.0/bin/node",
      "--permission",
      "--allow-fs-read=__HOME__/.aoa-pause-detector",
      "--allow-fs-write=__HOME__/.aoa-pause-detector/state",
      "__HOME__/.aoa-pause-detector/app/deploy/pause-detector/detector.mjs",
      "--config",
      "__HOME__/.aoa-pause-detector/config.json",
    ];
    assert(args.join("\n") === want.join("\n"), args.join(" "));
    assert(!x.includes("__REPO__"), "the plist still names a repository");
  }
);
await cell("config: the plist runs only detector.mjs, hourly, and passes no secret in argv", () => {
  const x = readFileSync(join(HERE, "io.aastar.dvt-pause-detector.plist"), "utf8");
  assert(/<key>StartInterval<\/key>\s*<integer>3600<\/integer>/.test(x), "not hourly");
  assert(x.includes("deploy/pause-detector/detector.mjs"), "does not run detector.mjs");
  assert(!/EnvironmentVariables/.test(x), "has EnvironmentVariables");
  // the plist's <string> values (its arguments and keys), never its comment text
  const values = [...x.matchAll(/<string>([^<]*)<\/string>/g)].map(m => m[1]);
  assert(
    values.length > 0 && !values.some(v => /pause-job\.mjs|keystore/i.test(v)),
    "references the sender or a keystore"
  );
});
await cell("pauseCommand: checksummed SP and operator", () => {
  assert(
    pauseCommand(SP, OP1) ===
      `cast send ${ethers.getAddress(SP)} "pauseUnderstakedOperator(address)" ${ethers.getAddress(OP1)}`,
    pauseCommand(SP, OP1)
  );
});
await cell("state: stateProblems binds chainId, spProxy, startBlock", () => {
  const c = cfgOf();
  assert(stateProblems(emptyState(c), c).length === 0, "fresh state has problems");
  assert(stateProblems(emptyState(c), { ...c, chainId: 10 }).length > 0, "chain not bound");
  assert(
    stateProblems(emptyState(c), { ...c, startBlock: 101 }).length > 0,
    "startBlock not bound"
  );
});

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
