#!/usr/bin/env node
// Cells for the rc.8 pause detector (deploy/pause-detector). Pure and scripted-chain cells; no
// network. Run: npm run check:pause-detector
//
// The first group is the guarantee DSR asked for: the detector has NO key, keystore, signing or
// broadcast code. It fails if any such call appears in the detector or anything it imports, and
// its own control cells prove the scanner sees one when it is there.
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
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
} from "./detector.mjs";
import { readSecretFile } from "../pause-job/lib/secret-file.mjs";
import { scanSource, scanTree } from "./no-signing-scan.mjs";

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
      let refused = false;
      try {
        await rpcTransport("http://x")("eth_" + "sendRaw" + "Transaction", ["0x00"]);
      } catch (e) {
        refused = /refused/.test(e.message);
      }
      assert(refused && fetched === 0, `refused=${refused} fetched=${fetched}`);
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
      "personal_sign",
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
      if (!(n >= 0 && n <= w.latest) || h !== hashOf(n)) return null;
      return {
        number: n,
        hash: h,
        parentHash: w.forkParentAt === n ? hashOf(n + 7777) : hashOf(n - 1),
      };
    },
    blockByNumber: async n => {
      if (n === "latest") return { number: w.latest, hash: hashOf(w.latest) };
      afterB = true;
      return { number: n, hash: w.reorg ? hashOf(n + 9999) : hashOf(n) };
    },
    getLogs: async f => {
      assert(f.address === SP && f.topics[0] === OPERATOR_CONFIGURED, "log filter");
      let a;
      let b;
      if (f.blockHash) {
        // EIP-234: one block by hash; a backend that has not indexed it fails
        const n = Number(BigInt(f.blockHash));
        assert(f.blockHash === hashOf(n) && n <= w.latest, "blockHash filter of an unknown block");
        if (n === w.latest) failIf("logs-at-B");
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
            !(w.rangeHides?.has(o.logBlock) && !f.blockHash)
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
          [w.impl ?? IMPL]: IMPL_CODE,
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
const round = async (w, cfg = cfgOf(), st = emptyState(cfg), now = 1e12) => ({
  st,
  ...(await runRound(st, { chain: fakeChain(w), cfg, now })),
});

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
  "round: an operator configured after finalized (cursor, B] is read this round, not persisted",
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
    assert(
      st.operators[ethers.getAddress(OP2)] === undefined,
      "recent operator persisted before finality"
    );
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
  "round: a state cursor ahead of the finalized block stops the round (no silent skip)",
  async () => {
    const st = { ...emptyState(cfgOf()), cursor: 10_000, lastFullScan: 1e12 };
    let stopped = false;
    try {
      await runRound(st, { chain: fakeChain(world()), cfg: cfgOf(), now: 1e12 + 1000 });
    } catch (e) {
      stopped = /ahead of the finalized/.test(e.message);
    }
    assert(stopped, "not stopped");
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
// the process boundary: Node's permission model (the plist's flags), proven by running node
const PERM_FLAG =
  Number(process.versions.node.split(".")[0]) >= 22 ? "--permission" : "--experimental-permission";
const runNode = (flags, code) =>
  spawnSync(process.execPath, [...flags, "--input-type=module", "-e", code], { encoding: "utf8" });
await cell(
  "permission: under the plist's flags no child process, worker or outside read is possible",
  () => {
    const home = mkdtempSync(join(tmpdir(), "pd-home-"));
    mkdirSync(join(home, ".aoa-pause-detector/state"), { recursive: true });
    writeFileSync(join(home, "key.env"), "KEEPER_PRIVATE_KEY=0xnot-a-key");
    const repo = resolve(HERE, "../..");
    const flags = [
      PERM_FLAG,
      `--allow-fs-read=${repo}`,
      `--allow-fs-read=${join(home, ".aoa-pause-detector")}`,
      `--allow-fs-write=${join(home, ".aoa-pause-detector/state")}`,
    ];
    const probe = `
    const out = [];
    try { (await import("node:child_process")).execFileSync("/usr/bin/true"); out.push("spawn"); } catch {}
    try { new (await import("node:worker_threads")).Worker("1", { eval: true }); out.push("worker"); } catch {}
    try { (await import("node:fs")).readFileSync(${JSON.stringify(join(home, "key.env"))}); out.push("read"); } catch {}
    const { permissionProblems } = await import(${JSON.stringify(join(HERE, "detector.mjs"))});
    console.log(JSON.stringify({ out, problems: permissionProblems(process.permission, ${JSON.stringify(home)}) }));`;
    const r = runNode(flags, probe);
    const j = JSON.parse(r.stdout.trim().split("\n").pop());
    assert(j.out.length === 0, `allowed: ${j.out.join(",")}`);
    assert(j.problems.length === 0, j.problems.join("; "));
    // controls: without the model, and with child processes allowed, the detector refuses
    const bare = JSON.parse(runNode([], probe).stdout.trim().split("\n").pop());
    assert(bare.problems.length > 0 && bare.out.includes("spawn"), "control: no model not refused");
    const child = JSON.parse(
      runNode(
        [
          ...flags,
          Number(process.versions.node.split(".")[0]) >= 22
            ? "--allow-child-process"
            : "--allow-child-process",
        ],
        probe
      )
        .stdout.trim()
        .split("\n")
        .pop()
    );
    assert(
      child.problems.some(x => /child processes/.test(x)),
      "control: child processes not refused"
    );
  }
);
await cell("permission: detector.mjs refuses to start outside the permission model", () => {
  const r = spawnSync(process.execPath, [join(HERE, "detector.mjs"), "--config", "/nonexistent"], {
    encoding: "utf8",
  });
  assert(r.status === 78 && /permission model/.test(r.stderr), `${r.status} ${r.stderr}`);
});
await cell("config: the plist runs the pinned node under the permission model, exactly", () => {
  const x = readFileSync(join(HERE, "io.aastar.dvt-pause-detector.plist"), "utf8");
  const args = [
    ...x
      .match(/<key>ProgramArguments<\/key>\s*<array>([\s\S]*?)<\/array>/)[1]
      .matchAll(/<string>([^<]*)<\/string>/g),
  ].map(m => m[1]);
  const want = [
    "__HOME__/.local/keeper-node/node-v24.21.0/bin/node",
    "--permission",
    "--allow-fs-read=__REPO__",
    "--allow-fs-read=__HOME__/.aoa-pause-detector",
    "--allow-fs-write=__HOME__/.aoa-pause-detector/state",
    "__REPO__/deploy/pause-detector/detector.mjs",
    "--config",
    "__HOME__/.aoa-pause-detector/config.json",
  ];
  assert(args.join("\n") === want.join("\n"), args.join(" "));
});
await cell("config: the plist runs only detector.mjs, hourly, and passes no secret in argv", () => {
  const x = readFileSync(join(HERE, "io.aastar.dvt-pause-detector.plist"), "utf8");
  assert(/<key>StartInterval<\/key>\s*<integer>3600<\/integer>/.test(x), "not hourly");
  assert(x.includes("deploy/pause-detector/detector.mjs"), "does not run detector.mjs");
  assert(!/EnvironmentVariables/.test(x), "has EnvironmentVariables");
  assert(
    !/pause-job\.mjs|keystore/i.test(x.replace(/<!--[\s\S]*?-->/g, "")),
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
