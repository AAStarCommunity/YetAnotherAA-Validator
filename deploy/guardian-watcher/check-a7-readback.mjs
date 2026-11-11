// Self-test of the A7 read-back comparison (a7-readback.mjs): SP's frozen schema and examples
// (sha256-pinned fixtures), then a fake chain built consistent with a read-back and answering by
// ABI fragment, and one mutation per rule, including Codex A7 R1's counterexamples.
// Run: node deploy/guardian-watcher/check-a7-readback.mjs
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { AbiCoder, Interface, keccak256, getAddress, id as keccakId } from "ethers";
import {
  validate,
  compare,
  redact,
  SCHEMA_SHA256,
  ANVIL_COMMIT,
  EIP1967_IMPL,
  OWNERSHIP_2STEP_SLOT,
  REQUIRED_CONTRACTS,
  SAFE_GETTERS,
  isState,
} from "./a7-readback.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const fx = f => readFileSync(join(here, "fixtures/a7", f));
const sha = b => createHash("sha256").update(b).digest("hex");
const results = [];
const cell = (name, ok, got) =>
  results.push({
    name,
    ok: !!ok,
    got: ok ? "" : JSON.stringify(got, (k, v) => (typeof v === "bigint" ? v.toString() : v)),
  });

const schemaText = fx("aoa-a7-readback-1.schema.json");
const exampleText = fx("aoa-a7-readback-1.example.json");
const liveText = fx("aoa-a7-readback-1.live.example.json");
cell("schema is SP's frozen v4 (sha256)", sha(schemaText) === SCHEMA_SHA256, sha(schemaText));
cell(
  "fork example is SP's (sha256)",
  sha(exampleText) === "148224aa64140cdf287a60ee16fe8d0be7f8512657e6c4677bd55e339b455206",
  sha(exampleText)
);
cell(
  "live example is SP's (sha256)",
  sha(liveText) === "49c6492b73078d82aee0b5b454e65b82259107e7e568888a668731a93c602432",
  sha(liveText)
);
const schema = JSON.parse(schemaText);
const example = JSON.parse(exampleText);
const live = JSON.parse(liveText);
cell("fork example validates", validate(schema, example).length === 0, validate(schema, example));
cell("live example validates", validate(schema, live).length === 0, validate(schema, live));
{
  const v = structuredClone(example);
  v.contracts.superPaymaster.version = null;
  cell(
    "version null outside the two extensions is rejected by the schema",
    validate(schema, v).length > 0,
    null
  );
  const e = structuredClone(example);
  e.header.rpcUrl = "https://x";
  cell("an unknown header key is rejected by the schema", validate(schema, e).length > 0, null);
}

// ---- a complete, internally consistent read-back: SP's example plus every inventory key
const A = n => getAddress("0x" + n.toString(16).padStart(40, "0"));
const G1 = "0x9999999999999999999999999999999999999999";
const PK = [
  "0x" + "11".repeat(32),
  "0x" + "22".repeat(32),
  "0x" + "33".repeat(32),
  "0x" + "44".repeat(32),
];
const PK_TYPE = "tuple(bytes32 x_a, bytes32 x_b, bytes32 y_a, bytes32 y_b)";
const PK_HASH = keccak256(AbiCoder.defaultAbiCoder().encode([PK_TYPE], [PK]));
const base = structuredClone(example);
base.contracts.superPaymaster.extensionCodehash = base.contracts.spAdminExtension.codehash;
base.contracts.blsAggregator.guardianSet = [
  { address: G1, pubkeyHash: PK_HASH, slot: 1, isActive: true },
];
const filler = i => ({
  address: A(0x1000 + i),
  version: "n/a:no version()",
  codehash: "n/a:no code",
  erc1967Impl: "n/a:not a proxy",
  implCodehash: "n/a:not a proxy",
  extension: "n/a:no extension",
  extensionCodehash: "n/a:no extension",
  owner: "n/a:no owner",
  pendingOwner: "n/a:no owner",
  guardian: "n/a:no guardian role",
  roles: {},
});
REQUIRED_CONTRACTS.forEach((k, i) => {
  if (!(k in base.contracts)) base.contracts[k] = filler(i);
});
base.contracts.multiSendCallOnly = filler(99);
base.contracts.ownerSafe.threshold = 2;
base.contracts.ownerSafe.owners = [A(0xa1), A(0xa2), A(0xa3)];
base.contracts.ownerSafe.singleton = A(0x5a5a);
base.contracts.dvtValidator.categoryCount = 0;
// a value, so the Registry pendingOwner() / ERC-7201 cross-check runs
base.contracts.registry.pendingOwner = A(0);
base.checks = {
  "dvtValidator.categoryCount": 0,
  "blsAggregator.owner == superPaymaster.owner": true,
};
base.amsterdamProbe.estimateSimulate = { alchemy: 256645, tenderly: "n/a:no eth_simulateV1" };
const addressBook = Object.fromEntries(
  Object.entries(base.contracts).map(([k, c]) => [k, c.address])
);

// ---- the fake chain: ABIs typed from the read-back; answers by fragment and arguments
const typeOf = v =>
  typeof v === "boolean"
    ? "bool"
    : typeof v === "number"
      ? "uint256"
      : /^0x[0-9a-fA-F]{40}$/.test(v)
        ? "address"
        : /^0x[0-9a-fA-F]{64}$/.test(v)
          ? "bytes32"
          : /^\d+$/.test(v)
            ? "uint256"
            : "string";
const SKIP = [
  "address",
  "codehash",
  "erc1967Impl",
  "implCodehash",
  "extension",
  "extensionCodehash",
  "roles",
  "rolesSource",
];
const argKey = args => JSON.stringify(args.map(x => (typeof x === "bigint" ? Number(x) : x)));
function world(rb) {
  const abi = {};
  const answers = new Map();
  const codes = new Map();
  const hashOf = new Map();
  const slots = new Map();
  const put = (addr, hash) => {
    if (isState(addr) || isState(hash)) return;
    const c = "0x" + Buffer.from("code:" + addr.toLowerCase()).toString("hex");
    codes.set(addr.toLowerCase(), c);
    hashOf.set(c, hash.toLowerCase());
  };
  const ans = (addr, iface, sig, args, v) =>
    answers.set(`${addr.toLowerCase()}|${iface.getFunction(sig).selector}|${argKey(args)}`, v);
  const word = a => "0x" + "0".repeat(24) + String(a).slice(2).toLowerCase();
  for (const [key, c] of Object.entries(rb.contracts)) {
    if (isState(c.address)) continue;
    put(c.address, c.codehash);
    if (!isState(c.erc1967Impl)) {
      slots.set(`${c.address.toLowerCase()}|${EIP1967_IMPL}`, word(c.erc1967Impl));
      put(c.erc1967Impl, c.implCodehash);
    }
    if (!isState(c.extension)) put(c.extension, c.extensionCodehash);
    const frags = [];
    const vals = [];
    for (const [k, v] of Object.entries(c)) {
      if (SKIP.includes(k) || isState(v) || (v !== null && typeof v === "object")) continue;
      frags.push(`function ${k}() view returns (${typeOf(v)})`);
      vals.push([k, v]);
    }
    if (key === "superPaymaster") {
      frags.push("function EXTENSION() view returns (address)");
      vals.push(["EXTENSION", c.extension]);
    }
    if (key === "blsAggregator")
      frags.push(
        "function validatorAtSlot(uint8) view returns (address)",
        `function getBLSPublicKey(address validator) view returns (${PK_TYPE} publicKey, uint8 slot, bool isActive)`,
        "function slashThresholds(uint8) view returns (uint8)"
      );
    const iface = new Interface([...new Set(frags)]);
    abi[key] = iface;
    for (const [k, v] of vals) ans(c.address, iface, `${k}()`, [], v);
    if (key === "registry" && !isState(c.pendingOwner))
      slots.set(`${c.address.toLowerCase()}|${OWNERSHIP_2STEP_SLOT}`, word(c.pendingOwner));
    if (key === "blsAggregator") {
      for (let s = 1; s <= 64; s++)
        ans(c.address, iface, "validatorAtSlot(uint8)", [s], s === 1 ? G1 : A(0));
      ans(c.address, iface, "getBLSPublicKey(address)", [G1.toLowerCase()], [PK, 1n, true]);
      ans(c.address, iface, "slashThresholds(uint8)", [1], 2n);
      ans(c.address, iface, "slashThresholds(uint8)", [2], 3n);
    }
  }
  const safe = new Interface(SAFE_GETTERS);
  const sa = rb.contracts.ownerSafe;
  if (sa && !isState(sa.address)) {
    ans(sa.address, safe, "getThreshold()", [], BigInt(sa.threshold));
    ans(sa.address, safe, "getOwners()", [], sa.owners);
    slots.set(`${sa.address.toLowerCase()}|0x${"0".repeat(64)}`, word(sa.singleton));
  }
  // contracts with no file in SP's abis/ get an empty ABI HERE so the mechanics are exercised;
  // the real run marks them unverified (a7-fork.mjs)
  for (const k of Object.keys(rb.contracts)) abi[k] ??= new Interface([]);
  const reader = {
    chainId: async () => rb.header.chainId,
    head: async () => rb.header.readbackBlock,
    block: async n =>
      n === rb.header.readbackBlock ? { hash: rb.header.readbackBlockHash } : null,
    code: async (a, block) => (block !== undefined ? "0x" : (codes.get(a.toLowerCase()) ?? "0x")),
    keccak: c => hashOf.get(c) ?? "0x" + "e".repeat(64),
    slot: async (a, s) => slots.get(`${a.toLowerCase()}|${s}`) ?? "0x" + "0".repeat(64),
    call: async (a, iface, f, args = []) => {
      const k = `${a.toLowerCase()}|${f.selector}|${argKey(args)}`;
      return answers.has(k) ? { status: "value", v: answers.get(k) } : { status: "revert" };
    },
    logs: async () => [],
    upstreamHeader: async () => ({ blockAccessListHash: true, slotNumber: true }),
    probe: async () => ({ gasUsedFork: 256645, simulate: 256645, callAtGasUsed: true }),
  };
  return { reader, abi, safe };
}
const facts = (rb, w, over = {}) => ({
  anvilVersion: rb.header.anvilVersion,
  anvilCommit: ANVIL_COMMIT,
  dumpSha256: rb.header.dumpSha256,
  forkBlock: rb.header.forkBlock,
  abi: w.abi,
  safe: w.safe,
  addressBook,
  slashLevels: { WARNING: 0, MINOR: 1, MAJOR: 2 },
  ...over,
});
// the chain is always built from the CONSISTENT base; the read-back under test may be mutated
const run = async (rb, tweak = () => ({}), over = {}) => {
  const w = world(base);
  const reader = { ...w.reader, ...tweak(w, rb) };
  return compare(rb, reader, facts(rb, w, typeof over === "function" ? over(w) : over));
};
const failed = r => r.cmp.filter(x => !x.ok).map(x => x.path);
const clone = () => structuredClone(base);
const mut = async (name, f, expectPath, tweak, over) => {
  const rb = clone();
  f(rb);
  const r = await run(rb, tweak, over);
  cell(
    name,
    failed(r).some(p => p === expectPath || p.startsWith(expectPath)),
    {
      failed: failed(r),
      unverified: r.unverified,
    }
  );
};
const unv = async (name, f, expectPrefix, tweak, over) => {
  const rb = clone();
  f(rb);
  const r = await run(rb, tweak, over);
  cell(
    name,
    r.unverified.some(u => u.startsWith(expectPrefix)),
    {
      failed: failed(r),
      unverified: r.unverified,
    }
  );
};

// ---- positive: the complete consistent world is SAME STATE
const pos = await run(clone());
cell("complete consistent read-back: no mismatch", failed(pos).length === 0, failed(pos));
cell(
  "complete consistent read-back: nothing unverified",
  pos.unverified.length === 0,
  pos.unverified
);
cell(
  "guardianSet, signerMaskOrder, thresholds, Safe, extension, ERC-7201 and an equality check all compared",
  [
    `contracts.blsAggregator.guardianSet[${G1}].pubkeyHash`,
    "contracts.blsAggregator.signerMaskOrder.bits",
    "contracts.blsAggregator.thresholds.MAJOR",
    "contracts.ownerSafe.owners",
    "contracts.ownerSafe.singleton",
    "contracts.superPaymaster.extensionCodehash=spAdminExtension.codehash",
    "contracts.registry.pendingOwner=ERC-7201 slot",
    "checks.blsAggregator.owner == superPaymaster.owner",
  ].every(p => pos.cmp.some(x => x.path === p && x.ok)),
  pos.cmp.map(x => x.path)
);

// ---- SP's own example (placeholders) stops
{
  const w = world(base);
  const r = await compare(example, w.reader, facts(example, w));
  cell(
    "SP's example: the contracts it does not list are unverified (an inventory gap never passes)",
    REQUIRED_CONTRACTS.filter(k => !(k in example.contracts)).every(k =>
      r.unverified.some(u => u.startsWith(`contracts.${k} (missing`))
    ),
    r.unverified
  );
  cell(
    "SP's example (fixed at 248ef831): extensionCodehash equals spAdminExtension.codehash",
    !failed(r).includes("contracts.superPaymaster.extensionCodehash=spAdminExtension.codehash") &&
      r.cmp.some(
        x => x.path === "contracts.superPaymaster.extensionCodehash=spAdminExtension.codehash"
      ),
    failed(r)
  );
}

// ---- Codex A7 R1 #1: inventory and addresses
await unv(
  "R1#1: an empty contracts map is unverified",
  rb => (rb.contracts = {}),
  "contracts.superPaymaster (missing"
);
await unv("R1#1: empty checks are unverified", rb => (rb.checks = {}), "checks (empty)");
await unv(
  "R1#1: a valueState address without an address-book entry is unverified",
  rb => (rb.contracts.multiSendCallOnly.address = "n/a:not used"),
  "contracts.multiSendCallOnly.address",
  undefined,
  { addressBook: { ...addressBook, multiSendCallOnly: undefined } }
);
await mut(
  "an address other than the address book's fails",
  rb => (rb.contracts.registry.address = A(0xdead)),
  "contracts.registry.address"
);
await unv(
  "no address book: addresses are unverified",
  () => {},
  "contracts.superPaymaster.address (no address book)",
  undefined,
  { addressBook: null }
);
// ---- Codex A7 R1 #2: types from the ABI, never guessed
await mut(
  "R1#2: a string getter vs a reported 32 fails",
  rb => (rb.contracts.superPaymaster.version = 32),
  "contracts.superPaymaster.version"
);
await mut(
  "R1#2: two different owners are not equal",
  () => {},
  "checks.blsAggregator.owner == superPaymaster.owner",
  (w, rb) => ({
    call: async (a, i, f, args) =>
      a.toLowerCase() === rb.contracts.superPaymaster.address.toLowerCase() && f.name === "owner"
        ? { status: "value", v: A(0x77) }
        : w.reader.call(a, i, f, args),
  })
);
// ---- Codex A7 R1 #3: failures are not absence
await mut(
  "R1#3: a decoding failure on an n/a field fails (the getter returned data)",
  () => {},
  "contracts.blsAggregator.pendingRotation",
  w => ({
    call: async (a, i, f, args) =>
      f.name === "pendingRotation" ? { status: "decode" } : w.reader.call(a, i, f, args),
  }),
  w => ({
    abi: {
      ...w.abi,
      blsAggregator: new Interface([
        ...w.abi.blsAggregator.fragments.map(x => x.format("full")),
        "function pendingRotation() view returns (address)",
      ]),
    },
  })
);
{
  let threw = false;
  try {
    await run(clone(), () => ({
      call: async () => {
        throw new Error("rpc down");
      },
    }));
  } catch {
    threw = true;
  }
  cell("R1#3: an RPC failure throws (the run stops, no verdict)", threw, null);
}
// ---- Codex A7 R1 #4
await mut(
  "R1#4: a fork head other than readbackBlock fails",
  () => {},
  "header.readbackBlock=fork head",
  (w, rb) => ({ head: async () => rb.header.readbackBlock + 1 })
);
// ---- Codex A7 R1 #5
{
  const t = JSON.stringify({ providers: ["https://rpc.example/KEY"], tag: "wss://x" }, redact);
  cell("R1#5: URL-like strings are redacted", !/KEY|wss:/.test(t), t);
}
// ---- null = absent from SP's ABI (DSR), never by calling
{
  const r1 = await run(clone(), w => ({
    call: async (a, i, f, args) =>
      f.name === "version" ? { status: "value", v: "X-1.0" } : w.reader.call(a, i, f, args),
  }));
  cell(
    "null version, a fallback answers version(), ABI lacks it: passes",
    r1.cmp.some(x => x.path === "contracts.spAdminExtension.version" && x.ok),
    r1.cmp.filter(x => x.path === "contracts.spAdminExtension.version")
  );
  const r2 = await run(clone(), undefined, w => ({
    abi: {
      ...w.abi,
      spAdminExtension: new Interface(["function version() view returns (string)"]),
    },
  }));
  cell(
    "null version but version() IS in SP's ABI: fails",
    failed(r2).includes("contracts.spAdminExtension.version"),
    failed(r2)
  );
  const r3 = await run(clone(), undefined, w => {
    const abi = { ...w.abi };
    delete abi.spAdminExtension;
    return { abi };
  });
  cell(
    "null version without SP's ABI: unverified",
    r3.unverified.some(u => u.startsWith("contracts.spAdminExtension.version")),
    r3.unverified
  );
}
// ---- read methods
await mut(
  "guardianSet: another pubkeyHash fails",
  rb => (rb.contracts.blsAggregator.guardianSet[0].pubkeyHash = "0x" + "ab".repeat(32)),
  `contracts.blsAggregator.guardianSet[${G1}].pubkeyHash`
);
await mut(
  "guardianSet: a guardian SP left out fails",
  rb => (rb.contracts.blsAggregator.guardianSet = []),
  "contracts.blsAggregator.guardianSet.length"
);
await mut(
  "guardianSet: another slot fails",
  rb => (rb.contracts.blsAggregator.guardianSet[0].slot = 2),
  `contracts.blsAggregator.guardianSet[${G1}].slot`
);
await mut(
  "signerMaskOrder: bit 0 naming another address fails",
  rb => (rb.contracts.blsAggregator.signerMaskOrder.bits = [A(0x1)]),
  "contracts.blsAggregator.signerMaskOrder.bits"
);
await mut(
  "thresholds: MAJOR other than slashThresholds(2) fails",
  rb => (rb.contracts.blsAggregator.thresholds.MAJOR = 2),
  "contracts.blsAggregator.thresholds.MAJOR"
);
await unv(
  "thresholds: an unknown SlashLevel order is unverified",
  () => {},
  "contracts.blsAggregator.thresholds.MINOR",
  undefined,
  { slashLevels: null }
);
await mut(
  "extension: EXTENSION() other than SP's fails",
  rb => (rb.contracts.superPaymaster.extension = A(0x4445)),
  "contracts.superPaymaster.extension"
);
await mut(
  "an extension on a contract that has none fails",
  rb => (rb.contracts.registry.extension = A(0x4444)),
  "contracts.registry.extension"
);
await mut(
  "Safe owners differ: fails",
  rb => (rb.contracts.ownerSafe.owners = [A(0xa1)]),
  "contracts.ownerSafe.owners"
);
await mut(
  "Safe threshold differs: fails",
  rb => (rb.contracts.ownerSafe.threshold = 3),
  "contracts.ownerSafe.threshold"
);
await mut(
  "Safe singleton differs: fails",
  rb => (rb.contracts.ownerSafe.singleton = A(0x5a5b)),
  "contracts.ownerSafe.singleton"
);
await mut(
  "registry: pendingOwner() disagreeing with its ERC-7201 slot fails",
  () => {},
  "contracts.registry.pendingOwner=ERC-7201 slot",
  (w, rb) => ({
    slot: async (a, s) =>
      s === OWNERSHIP_2STEP_SLOT && a.toLowerCase() === rb.contracts.registry.address.toLowerCase()
        ? "0x" + "0".repeat(24) + "42".repeat(20)
        : w.reader.slot(a, s),
  })
);
{
  // a check with an address argument: registry.balanceOf(superPaymaster)
  const over = w => ({
    abi: {
      ...w.abi,
      registry: new Interface([
        ...w.abi.registry.fragments.map(x => x.format("full")),
        "function balanceOf(address) view returns (uint256)",
      ]),
    },
  });
  const tweak = (w, rb) => ({
    call: async (a, i, f, args) =>
      f.name === "balanceOf" &&
      a.toLowerCase() === rb.contracts.registry.address.toLowerCase() &&
      String(args[0]).toLowerCase() === rb.contracts.superPaymaster.address.toLowerCase()
        ? { status: "value", v: 1000n }
        : w.reader.call(a, i, f, args),
  });
  const ok = clone();
  ok.checks["registry.balanceOf(superPaymaster)"] = "1000";
  const r1 = await run(ok, tweak, over);
  cell(
    "a check with an argument reads fn(<that contract's address>): equal passes",
    r1.cmp.some(x => x.path === "checks.registry.balanceOf(superPaymaster)" && x.ok),
    failed(r1)
  );
  const bad = clone();
  bad.checks["registry.balanceOf(superPaymaster)"] = "999";
  const r2 = await run(bad, tweak, over);
  cell(
    "a check with an argument: a different value fails",
    failed(r2).includes("checks.registry.balanceOf(superPaymaster)"),
    failed(r2)
  );
}
{
  // roles from RoleGranted/RoleRevoked logs, confirmed with hasRole
  const ROLE = keccakId("ROLE_DVT");
  const acct = A(0xb0b);
  const over = w => ({
    abi: {
      ...w.abi,
      registry: new Interface([
        ...w.abi.registry.fragments.map(x => x.format("full")),
        "function hasRole(bytes32, address) view returns (bool)",
        "event RoleGranted(bytes32 indexed role, address indexed account, address indexed sender)",
        "event RoleRevoked(bytes32 indexed role, address indexed account, address indexed sender)",
      ]),
    },
  });
  const tweak = (w, rb) => ({
    logs: async () => [
      {
        topics: [
          keccakId("RoleGranted(bytes32,address,address)"),
          ROLE,
          "0x" + "0".repeat(24) + acct.slice(2).toLowerCase(),
          "0x" + "0".repeat(64),
        ],
      },
    ],
    call: async (a, i, f, args) =>
      f.name === "hasRole" && a.toLowerCase() === rb.contracts.registry.address.toLowerCase()
        ? { status: "value", v: true }
        : w.reader.call(a, i, f, args),
  });
  const ok = clone();
  ok.contracts.registry.roles = { [ROLE]: [acct] };
  ok.contracts.registry.rolesSource = { fromBlock: 100, toBlock: ok.header.readbackBlock };
  const r1 = await run(ok, tweak, over);
  cell(
    "roles: logs + hasRole equal SP's members: pass",
    !failed(r1).some(p => p.includes(".roles")) && !r1.unverified.some(u => u.includes(".roles")),
    { f: failed(r1), u: r1.unverified }
  );
  const bad = clone();
  bad.contracts.registry.roles = {};
  bad.contracts.registry.rolesSource = { fromBlock: 100, toBlock: bad.header.readbackBlock };
  const r2 = await run(bad, tweak, over);
  cell(
    "roles: a member SP left out fails",
    failed(r2).some(p => p.startsWith("contracts.registry.roles[")),
    failed(r2)
  );
  const nosrc = clone();
  nosrc.contracts.registry.roles = { [ROLE]: [acct] };
  const r3 = await run(nosrc, tweak, over);
  cell(
    "roles: an AccessControl contract without rolesSource is unverified",
    r3.unverified.some(u => u.startsWith("contracts.registry.roles (no rolesSource")),
    r3.unverified
  );
  const late = clone();
  late.contracts.registry.roles = { [ROLE]: [acct] };
  late.contracts.registry.rolesSource = { fromBlock: 100, toBlock: late.header.readbackBlock };
  const r4 = await run(
    late,
    (w, rb) => ({
      ...tweak(w, rb),
      code: async (a, b) => (b !== undefined ? "0x60" : w.reader.code(a)),
    }),
    over
  );
  cell(
    "roles: a log range starting after deployment (code before fromBlock) fails",
    failed(r4).includes("contracts.registry.rolesSource.fromBlock<=deployment"),
    failed(r4)
  );
}
// ---- the probe (schema v4)
await mut(
  "probe: SP's simulateV1 differs from gasUsedFork: fails",
  rb => (rb.amsterdamProbe.estimateSimulate.alchemy = 256646),
  "amsterdamProbe.sp:estimateSimulate.alchemy==gasUsedFork"
);
await mut(
  "probe: no provider with simulateV1: fails",
  rb => (rb.amsterdamProbe.estimateSimulate = { alchemy: "n/a:no", tenderly: "n/a:no" }),
  "amsterdamProbe.sp:some provider has eth_simulateV1"
);
await mut(
  "probe: a provider's eth_call at gasUsed failed: fails",
  rb => (rb.amsterdamProbe.callAtGasUsed.tenderly = false),
  "amsterdamProbe.sp:callAtGasUsed all true"
);
await mut(
  "probe: the rerun on this fork uses other gas: fails",
  () => {},
  "amsterdamProbe.fork:gasUsed",
  () => ({ probe: async () => ({ gasUsedFork: 256000, simulate: 256645, callAtGasUsed: true }) })
);
await mut(
  "probe: this script's own upstream simulateV1 differs: fails",
  () => {},
  "amsterdamProbe.upstream:simulateV1",
  () => ({ probe: async () => ({ gasUsedFork: 256645, simulate: 259849, callAtGasUsed: true }) })
);
await mut(
  "probe: this script's own upstream eth_call at gasUsed fails: fails",
  () => {},
  "amsterdamProbe.upstream:callAtGasUsed",
  () => ({ probe: async () => ({ gasUsedFork: 256645, simulate: 256645, callAtGasUsed: false }) })
);
{
  const rb = clone();
  rb.amsterdamProbe.estimateLive = { alchemy: 1, tenderly: 2 };
  rb.amsterdamProbe.estimateFork = 3;
  rb.amsterdamProbe.callAtGasUsedMinusOne = { alchemy: true, tenderly: true };
  const r = await run(rb);
  cell(
    "probe: estimates and gas-1 are recorded only, never judged",
    failed(r).length === 0,
    failed(r)
  );
  const rb2 = clone();
  rb2.amsterdamProbe.predicate = "true";
  const r2 = await run(rb2);
  cell(
    "an unknown probe predicate is never evaluated: unverified",
    r2.unverified.includes("amsterdamProbe.predicate"),
    r2.unverified
  );
}
// ---- header
await mut("a live read-back is never a fork's", rb => (rb.header.source = "live"), "header.source");
await mut(
  "readbackBlockHash differs: fails",
  rb => (rb.header.readbackBlockHash = "0x" + "12".repeat(32)),
  "header.readbackBlockHash",
  (w, rb) => ({ block: async () => ({ hash: base.header.readbackBlockHash }) })
);
await mut(
  "upstream forkId not Amsterdam: fails",
  rb => (rb.header.ethConfig.forkId = "0xdeadbeef"),
  "header.ethConfig.forkId"
);
await mut(
  "this script's own upstream lacks slotNumber: fails",
  () => {},
  "upstream.slotNumber",
  () => ({ upstreamHeader: async () => ({ blockAccessListHash: true, slotNumber: false }) })
);
await mut(
  "a provider given as a URL fails",
  rb => (rb.header.providers = ["https://rpc.example/key"]),
  "header.providers"
);

let nf = 0;
for (const r of results) {
  console.log(
    `${r.ok ? "ok  " : "FAIL"} ${r.name}${r.ok ? "" : `\n     got ${r.got.slice(0, 1500)}`}`
  );
  if (!r.ok) nf++;
}
console.log(`\n${results.length - nf}/${results.length} cells`);
process.exit(nf ? 1 : 0);
