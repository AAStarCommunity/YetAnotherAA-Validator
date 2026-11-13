#!/usr/bin/env node
// Cells for the rc.8 pause detector (deploy/pause-detector). Pure and scripted-chain cells; no
// network. Run: npm run check:pause-detector
//
// The first group is the guarantee DSR asked for: the detector has NO key, keystore, signing or
// broadcast code. It fails if any such call appears in the detector or anything it imports, and
// its own control cells prove the scanner sees one when it is there.
import { readFileSync } from "node:fs";
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
} from "./lib/detect.mjs";
import {
  configProblems,
  readOnlyChain,
  READ_METHODS,
  dueAlerts,
  resolvedKeys,
  DETECTOR_SECRETS,
} from "./detector.mjs";
import { readSecretFile } from "../pause-job/lib/secret-file.mjs";

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

/** Code with comments removed (a comment saying "no signing" is not code). Pure. */
export function codeOnly(text) {
  return text
    .replace(/\/\*[\s\S]*?\*\//g, " ")
    .split("\n")
    .map(l => l.replace(/(^|[^:"'`])\/\/.*$/, "$1"))
    .join("\n");
}
// anything that can hold a key, sign, or broadcast, or run another program that could
export const FORBIDDEN =
  /\b(Wallet|HDNodeWallet|BaseWallet|SigningKey|Signer|JsonRpcSigner|NonceManager|signTransaction|signMessage|signTypedData|sendTransaction|sendRawTransaction|broadcastTransaction|eth_sendRawTransaction|eth_sendTransaction|eth_signTransaction|eth_sign|personal_sign|privateKey|fromEncryptedJson|fromEncryptedJsonSync|encryptKeystoreJson|decryptKeystoreJson|Mnemonic|fromPhrase|child_process|spawn|execFile|execSync|fork|keystore|mktx)\b/;
export const ALLOWED_IMPORTS = new Set([
  "node:fs",
  "node:net",
  "node:os",
  "node:path",
  "node:url",
  "ethers",
]);
const IMPORT = /^\s*import\s+(?:[^"';]*?\sfrom\s+)?["']([^"']+)["']/gm;
const DYNAMIC = /\bimport\s*\(|\brequire\s*\(/;

/** Problems of the file at `path` and every local module it imports, transitively. */
export function scanTree(path, read = p => readFileSync(p, "utf8"), seen = new Set()) {
  const p = [];
  if (seen.has(path)) return p;
  seen.add(path);
  const code = codeOnly(read(path));
  const m = code.match(FORBIDDEN);
  if (m) p.push(`${path}: forbidden "${m[1]}"`);
  if (DYNAMIC.test(code)) p.push(`${path}: a dynamic import or require`);
  for (const [, spec] of code.matchAll(IMPORT)) {
    if (spec.startsWith(".")) {
      if (spec.endsWith(".json")) continue;
      p.push(...scanTree(resolve(dirname(path), spec), read, seen));
    } else if (!ALLOWED_IMPORTS.has(spec)) p.push(`${path}: imports ${spec}`);
  }
  return p;
}

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
await cell("no-signing CONTROL: a signTransaction call is caught", () => {
  const files = {
    "/x/a.mjs": 'import { b } from "./b.mjs";\n',
    "/x/b.mjs": "const r = await w.signTransaction(tx);\n",
  };
  const p = scanTree("/x/a.mjs", f => files[f]);
  assert(
    p.some(x => x.includes("signTransaction")),
    "not caught"
  );
});
await cell(
  "no-signing CONTROL: an ethers Wallet, an eth_sendRawTransaction and child_process are caught",
  () => {
    for (const src of [
      "const w = new ethers.Wallet(k);",
      'await rpc("eth_sendRawTransaction", [raw]);',
      'import { execFile } from "node:child_process";',
      "const k = readFileSync(cfg.keystore);",
      'const m = await import("./x.mjs");',
    ]) {
      const p = scanTree("/y.mjs", () => src);
      assert(p.length > 0, `not caught: ${src}`);
    }
  }
);
await cell("no-signing CONTROL: a comment that says 'no signing' is not code", () => {
  const p = scanTree(
    "/z.mjs",
    () => "// no Wallet, no signTransaction here\n/* keystore */\nconst a = 1;\n"
  );
  assert(p.length === 0, p.join("; "));
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
await cell("no-signing: the read-only allowlist is exactly the six read methods", () => {
  assert(
    [...READ_METHODS].sort().join() ===
      [
        "eth_call",
        "eth_chainId",
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
      if (tag === "finalized") return w.finalized;
      return w.latest;
    },
    blockByNumber: async n => {
      if (n === "latest") return { number: w.latest, hash: hashOf(w.latest) };
      afterB = true;
      return { number: n, hash: w.reorg ? hashOf(n + 9999) : hashOf(n) };
    },
    getLogs: async f => {
      if (w.failOnce?.delete(`logs:${Number(f.fromBlock)}`)) throw new Error("once");
      failIf(`logs:${Number(f.fromBlock)}`);
      failIf("logs");
      const a = Number(f.fromBlock);
      const b = Number(f.toBlock);
      assert(f.address === SP && f.topics[0] === OPERATOR_CONFIGURED, "log filter");
      return Object.entries(w.ops)
        .filter(([, o]) => o.logBlock >= a && o.logBlock <= b)
        .map(([op, o]) => ({
          address: SP,
          topics: [OPERATOR_CONFIGURED, ethers.zeroPadValue(op, 32)],
          blockNumber: ethers.toQuantity(o.logBlock),
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
const round = async (w, cfg = cfgOf(), st = emptyState(cfg)) => ({
  st,
  ...(await runRound(st, { chain: fakeChain(w), cfg })),
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
