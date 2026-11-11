// Self-test of the A7 read-back comparison (a7-readback.mjs): SP's frozen schema v5 and examples
// (sha256-pinned fixtures), then a fake chain built consistent with a complete, schema-valid
// read-back and answering by ABI fragment, and one mutation per rule, including Codex A7 R1/R2's
// counterexamples. Run: node deploy/guardian-watcher/check-a7-readback.mjs
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { AbiCoder, Interface, keccak256, getAddress, id as keccakId } from "ethers";
import {
  validate,
  compare,
  redact,
  sanitize,
  SCHEMA_SHA256,
  ANVIL_COMMIT,
  EIP1967_IMPL,
  OWNERSHIP_2STEP_SLOT,
  REQUIRED_CONTRACTS,
  SAFE_GETTERS,
  ENTRY_POINT_V07,
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
cell("schema is SP's frozen v7 (sha256)", sha(schemaText) === SCHEMA_SHA256, sha(schemaText));
cell(
  "fork example is SP's (sha256)",
  sha(exampleText) === "20fd1d952f52b195ab3379038be27ac63619ec76eff8a04796318b3d7a4da11b",
  sha(exampleText)
);
cell(
  "live example is SP's (sha256)",
  sha(liveText) === "a184468e12e157781433bef06dbe4c187710f1306c53d9824495d59200da9e7e",
  sha(liveText)
);
const schema = JSON.parse(schemaText);
const example = JSON.parse(exampleText);
const live = JSON.parse(liveText);
cell(
  "REQUIRED_CONTRACTS is exactly the pinned schema's contracts.required",
  JSON.stringify([...REQUIRED_CONTRACTS].sort()) ===
    JSON.stringify([...schema.properties.contracts.required].sort()),
  schema.properties.contracts.required
);
cell("fork example validates", validate(schema, example).length === 0, validate(schema, example));
cell("live example validates", validate(schema, live).length === 0, validate(schema, live));
{
  const v = structuredClone(example);
  delete v.contracts.evaluationCommunityToken;
  cell(
    "dropping a required contract is rejected by the schema",
    validate(schema, v).length > 0,
    null
  );
  const e = structuredClone(example);
  e.header.rpcUrl = "https://x";
  cell("an unknown header key is rejected by the schema", validate(schema, e).length > 0, null);
  // Codex A7 R6: a URL inside an invalid key never reaches the schema diagnostics
  const u = structuredClone(example);
  u.contracts.registry.roles = { "https://rpc.example/SYNTHETIC_API_SECRET": [true] };
  const errs = validate(schema, u);
  cell(
    "R6: schema diagnostics never print an input key holding a URL (any JSON-Pointer escaping)",
    errs.length > 0 &&
      !errs.join(" ").includes("SYNTHETIC_API_SECRET") &&
      !/https|~1/.test(errs.join(" ")),
    errs
  );
}

// ---- a complete, internally consistent, schema-valid read-back built from SP's example
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
const ROLE = keccakId("ROLE_COMMUNITY");
const MEMBER = "0x6666666666666666666666666666666666666666";
const base = structuredClone(example);
{
  // unique addresses (the example reuses placeholders), the canonical EntryPoint kept
  let n = 0x2000;
  for (const [k, c] of Object.entries(base.contracts))
    if (!isState(c.address) && k !== "entryPoint") c.address = A(n++);
  const C = base.contracts;
  C.superPaymaster.extension = C.spAdminExtension.address;
  C.superPaymaster.extensionCodehash = C.spAdminExtension.codehash;
  C.evaluationCommunityToken.SUPERPAYMASTER_ADDRESS = C.superPaymaster.address;
  // x-readMethods v5: only the Registry (and a Timelock) has a role system
  for (const [k, c] of Object.entries(C)) if (k !== "registry") c.roles = "n/a:no role system";
  C.registry.roles = { ROLE_COMMUNITY: [MEMBER] };
  C.registry.rolesSource = { fromBlock: 12000000, toBlock: base.header.readbackBlock };
  C.blsAggregator.guardianSet = [{ address: G1, pubkeyHash: PK_HASH, slot: 1, isActive: true }];
  C.blsAggregator.thresholds = { WARNING: 1, MINOR: 2, MAJOR: 3 };
  Object.assign(C.blsAggregator, {
    N: 1, // one occupied slot in this world
    pendingFraudProofVerifier: "0x0000000000000000000000000000000000000000",
    pendingFraudProofVerifierReadyAt: 0,
    minThreshold: 2,
    defaultThreshold: 2,
    SLASH_THRESHOLD_FLOOR: 2,
  });
  C.dvtValidator.categoryCount ??= 0;
  C.evaluationCommunityToken.POLICY_OFF = 0;
  C.evaluationCommunityToken.creditPolicy = 0;
  base.checks = {
    "dvtValidator.categoryCount": 0,
    "superPaymaster.fraudProofVerifier": "0x0000000000000000000000000000000000000000",
    "blsAggregator.owner == superPaymaster.owner": true,
    "evaluationCommunityToken.creditPolicy == evaluationCommunityToken.POLICY_OFF": true,
  };
  base.amsterdamProbe.estimateSimulate = { alchemy: 256645, tenderly: "n/a:no eth_simulateV1" };
}
cell(
  "the complete base read-back itself validates against the schema",
  validate(schema, base).length === 0,
  validate(schema, base)
);
const addressBook = Object.fromEntries(
  Object.entries(base.contracts)
    .filter(([, c]) => !isState(c.address))
    .map(([k, c]) => [k, c.address])
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
const DEPOSIT =
  "function getDepositInfo(address account) view returns ((uint256 deposit, bool staked, uint112 stake, uint32 unstakeDelaySec, uint48 withdrawTime) info)";
const argKey = args =>
  JSON.stringify(
    args.map(x => (typeof x === "bigint" ? Number(x) : typeof x === "string" ? x.toLowerCase() : x))
  );
const word = a => "0x" + "0".repeat(24) + String(a).slice(2).toLowerCase();
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
  const C = rb.contracts;
  const checkGetters = {};
  for (const [k, v] of Object.entries(rb.checks)) {
    const m = k.match(/^(\w+)\.(\w+)$/);
    if (m && !isState(v)) (checkGetters[m[1]] ??= []).push([m[2], v]);
  }
  for (const [key, c] of Object.entries(C)) {
    if (isState(c.address)) continue;
    put(c.address, c.codehash);
    if (!isState(c.erc1967Impl)) {
      slots.set(`${c.address.toLowerCase()}|${EIP1967_IMPL}`, word(c.erc1967Impl));
      put(c.erc1967Impl, c.implCodehash);
    }
    const frags = [];
    const vals = [];
    const skipHere =
      key === "entryPoint" ? ["deposit", "staked", "stake", "unstakeDelaySec", "withdrawTime"] : [];
    if (key === "ownerSafe") skipHere.push("version", "threshold", "owners", "singleton");
    if (key === "blsAggregator") skipHere.push("N"); // no N() in SP's ABI
    for (const [k, v] of Object.entries(c)) {
      if (
        SKIP.includes(k) ||
        skipHere.includes(k) ||
        isState(v) ||
        (v !== null && typeof v === "object")
      )
        continue;
      frags.push(`function ${k}() view returns (${typeOf(v)})`);
      vals.push([k, v]);
    }
    for (const [k, v] of checkGetters[key] ?? []) {
      frags.push(`function ${k}() view returns (${typeOf(v)})`);
      vals.push([k, v]);
    }
    if (key === "superPaymaster") {
      frags.push("function EXTENSION() view returns (address)");
      vals.push(["EXTENSION", c.extension]);
    }
    if (key === "blsAggregator")
      for (const [k, v] of Object.entries(c.thresholds ?? {}))
        if (!["WARNING", "MINOR", "MAJOR"].includes(k)) {
          frags.push(`function ${k}() view returns (uint256)`);
          vals.push([k, v]);
        }
    if (key === "blsAggregator")
      frags.push(
        "function validatorAtSlot(uint8) view returns (address)",
        `function getBLSPublicKey(address validator) view returns (${PK_TYPE} publicKey, uint8 slot, bool isActive)`,
        "function slashThresholds(uint8) view returns (uint8)"
      );
    if (key === "entryPoint") frags.push(DEPOSIT);
    if (key === "registry")
      frags.push(
        "function ROLE_COMMUNITY() view returns (bytes32)",
        "function hasRole(bytes32, address) view returns (bool)",
        "event RoleGranted(bytes32 indexed role, address indexed account, address indexed sender)",
        "event RoleRevoked(bytes32 indexed role, address indexed account, address indexed sender)",
        "event RoleRegistered(bytes32 indexed roleId, address indexed user, uint256 burnAmount, uint256 timestamp)",
        "event RoleExited(bytes32 indexed roleId, address indexed user, uint256 exitFee, uint256 timestamp)"
      );
    const iface = new Interface([...new Set(frags)]);
    abi[key] = iface;
    for (const [k, v] of vals) ans(c.address, iface, `${k}()`, [], v);
    if (key === "registry") {
      if (!isState(c.pendingOwner))
        slots.set(`${c.address.toLowerCase()}|${OWNERSHIP_2STEP_SLOT}`, word(c.pendingOwner));
      ans(c.address, iface, "ROLE_COMMUNITY()", [], ROLE);
      ans(c.address, iface, "hasRole(bytes32,address)", [ROLE, MEMBER], true);
    }
    if (key === "blsAggregator") {
      for (let s = 1; s <= 64; s++)
        ans(c.address, iface, "validatorAtSlot(uint8)", [s], s === 1 ? G1 : A(0));
      ans(c.address, iface, "getBLSPublicKey(address)", [G1], [PK, 1n, true]);
      [1n, 2n, 3n].forEach((v, i) => ans(c.address, iface, "slashThresholds(uint8)", [i], v));
    }
    if (key === "entryPoint") {
      const e = c;
      ans(c.address, iface, "getDepositInfo(address)", [C.superPaymaster.address], {
        deposit: BigInt(e.deposit),
        staked: e.staked,
        stake: BigInt(e.stake),
        unstakeDelaySec: BigInt(e.unstakeDelaySec),
        withdrawTime: BigInt(e.withdrawTime),
      });
    }
  }
  const safe = new Interface(SAFE_GETTERS);
  const sa = C.ownerSafe;
  ans(sa.address, safe, "VERSION()", [], sa.version);
  ans(sa.address, safe, "getThreshold()", [], BigInt(sa.threshold));
  ans(sa.address, safe, "getOwners()", [], sa.owners);
  slots.set(`${sa.address.toLowerCase()}|0x${"0".repeat(64)}`, word(sa.singleton));
  // contracts with no file in SP's abis/ get an empty ABI HERE so the mechanics are exercised;
  // the real run marks them unverified (a7-fork.mjs)
  for (const k of Object.keys(C)) abi[k] ??= new Interface([]);
  const reg = C.registry.address;
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
    logs: async ({ address }) =>
      address.toLowerCase() === reg.toLowerCase()
        ? [
            {
              topics: [
                abi.registry.getEvent("RoleRegistered").topicHash,
                ROLE,
                word(MEMBER),
                "0x" + "0".repeat(64),
              ],
            },
          ]
        : [],
    upstreamHeader: async () => ({ blockAccessListHash: true, slotNumber: true }),
    upstreamCodehash: async a => {
      const c = codes.get(a.toLowerCase());
      return c ? hashOf.get(c) : undefined;
    },
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
    { failed: failed(r), unverified: r.unverified }
  );
};
const unv = async (name, f, expectPrefix, tweak, over) => {
  const rb = clone();
  f(rb);
  const r = await run(rb, tweak, over);
  cell(
    name,
    r.unverified.some(u => u.startsWith(expectPrefix)),
    { failed: failed(r), unverified: r.unverified }
  );
};

// ---- positive
const pos = await run(clone());
cell("complete consistent read-back: no mismatch", failed(pos).length === 0, failed(pos));
cell(
  "complete consistent read-back: nothing unverified",
  pos.unverified.length === 0,
  pos.unverified
);
cell(
  "every read method was exercised",
  [
    `contracts.blsAggregator.guardianSet[${G1}].pubkeyHash`,
    "contracts.blsAggregator.guardianSet.addresses",
    "contracts.blsAggregator.signerMaskOrder.bits",
    "contracts.blsAggregator.thresholds.WARNING",
    "contracts.ownerSafe.version",
    "contracts.ownerSafe.owners",
    "contracts.ownerSafe.singleton",
    "contracts.entryPoint.deposit",
    "contracts.entryPoint.withdrawTime",
    "contracts.entryPoint.address=canonical EntryPoint v0.7",
    "contracts.entryPoint.codehash=upstream",
    "contracts.multiSendCallOnly.codehash=upstream",
    "contracts.evaluationCommunityToken.creditPolicy",
    "contracts.superPaymaster.extensionCodehash=spAdminExtension.codehash",
    "contracts.registry.pendingOwner=ERC-7201 slot",
    "contracts.registry.rolesSource.fromBlock<=deployment",
    "contracts.gTokenStaking.roles",
    "checks.blsAggregator.owner == superPaymaster.owner",
  ].every(
    p =>
      pos.cmp.some(x => x.path === p && x.ok) ||
      pos.cmp.some(x => x.path.startsWith("contracts.registry.roles[") && p === "x")
  ),
  pos.cmp
    .filter(x => !x.ok)
    .map(x => x.path)
    .concat(
      ["--- compared:"],
      pos.cmp.map(x => x.path)
    )
);
cell(
  "registry roles compared from the logs",
  pos.cmp.some(x => x.path.startsWith("contracts.registry.roles[") && x.ok),
  pos.cmp.map(x => x.path)
);

// ---- SP's own example and the v7 schema rules
{
  const v = structuredClone(example);
  v.contracts.blsAggregator.roles = {};
  cell(
    "v7 schema: a roles object on a contract without a role system is rejected",
    validate(schema, v).length > 0,
    null
  );
  cell(
    "v7 example: the credit-policy check compares two getters (creditPolicy == POLICY_OFF)",
    "evaluationCommunityToken.creditPolicy == evaluationCommunityToken.POLICY_OFF" in
      example.checks,
    Object.keys(example.checks)
  );
}

// ---- Codex A7 R1 #1 / R2 #1: inventory, fields and addresses are ours
await unv(
  "an empty contracts map is unverified",
  rb => (rb.contracts = {}),
  "contracts.superPaymaster (missing"
);
await unv("empty checks are unverified", rb => (rb.checks = {}), "checks (empty)");
for (const [k, f] of [
  ["blsAggregator", "guardianSet"],
  ["blsAggregator", "signerMaskOrder"],
  ["blsAggregator", "thresholds"],
  ["ownerSafe", "owners"],
  ["ownerSafe", "singleton"],
  ["ownerSafe", "threshold"],
  ["entryPoint", "deposit"],
  ["evaluationCommunityToken", "issuanceCap"],
])
  await unv(
    `R2#1: ${k}.${f} left out is unverified`,
    rb => delete rb.contracts[k][f],
    `contracts.${k}.${f} (missing`
  );
await unv(
  "R2#1: thresholds {} leaves every SlashLevel unverified",
  rb => (rb.contracts.blsAggregator.thresholds = {}),
  "contracts.blsAggregator.thresholds.WARNING (missing"
);
await unv(
  "R2#1: an unknown key inside signerMaskOrder is unverified",
  rb => (rb.contracts.blsAggregator.signerMaskOrder.extra = 1),
  "contracts.blsAggregator.signerMaskOrder.extra"
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
await mut(
  "an EntryPoint other than the canonical v0.7 fails",
  rb => (rb.contracts.entryPoint.address = A(0xe9)),
  "contracts.entryPoint.address=canonical",
  undefined,
  { addressBook: { ...addressBook, entryPoint: A(0xe9) } }
);
await mut(
  "an external contract whose code differs from upstream's fails",
  () => {},
  "contracts.multiSendCallOnly.codehash=upstream",
  w => ({ upstreamCodehash: async () => "0x" + "12".repeat(32) })
);
// ---- Codex A7 R3 #1: the BLS safety getters are required too
for (const f of [
  "fraudProofVerifier",
  "pendingFraudProofVerifier",
  "DVT_VALIDATOR",
  "domainSeparator",
  "MAX_VALIDATORS",
])
  await unv(
    `R3#1: blsAggregator.${f} left out is unverified`,
    rb => delete rb.contracts.blsAggregator[f],
    `contracts.blsAggregator.${f} (missing`
  );
await unv(
  "R3#1: blsAggregator.minThreshold left out is unverified",
  rb => delete rb.contracts.blsAggregator.minThreshold,
  "contracts.blsAggregator.minThreshold (missing"
);
await unv(
  "dvtValidator.categoryCount left out is unverified",
  rb => delete rb.contracts.dvtValidator.categoryCount,
  "contracts.dvtValidator.categoryCount (missing"
);
// ---- Codex A7 R3 #2: one role listed twice (by name and by id) fails
await mut(
  "R3#2: ROLE_COMMUNITY: [wrong] plus its bytes32 id: [actual] fails",
  rb =>
    (rb.contracts.registry.roles = {
      ROLE_COMMUNITY: ["0x0000000000000000000000000000000000000bad"],
      [ROLE]: [MEMBER],
    }),
  "contracts.registry.roles["
);
// ---- schema v7
await mut(
  "N other than the occupied slots fails",
  rb => (rb.contracts.blsAggregator.N = 3),
  "contracts.blsAggregator.N=occupied slots"
);
await unv(
  "a timelock declared in the address book but missing from the read-back is unverified",
  () => {},
  "contracts.timelockController (declared",
  undefined,
  { addressBook: { ...addressBook, timelockController: A(0x7171) } }
);
await mut(
  "creditPolicy == POLICY_OFF is read on chain: a policy other than OFF fails",
  () => {},
  "checks.evaluationCommunityToken.creditPolicy == evaluationCommunityToken.POLICY_OFF",
  (w, rb) => ({
    call: async (a, i, f, args) =>
      f.name === "creditPolicy" &&
      a.toLowerCase() === rb.contracts.evaluationCommunityToken.address.toLowerCase()
        ? { status: "value", v: 2 }
        : w.reader.call(a, i, f, args),
  })
);
// ---- R2 #2: the guardian SET, one to one
await mut(
  "R2#2: a duplicated guardian ([A, A]) fails on uniqueness, whatever the actual set",
  rb =>
    (rb.contracts.blsAggregator.guardianSet = [
      rb.contracts.blsAggregator.guardianSet[0],
      rb.contracts.blsAggregator.guardianSet[0],
    ]),
  "contracts.blsAggregator.guardianSet.unique"
);
await mut(
  "guardianSet: another pubkeyHash fails",
  rb => (rb.contracts.blsAggregator.guardianSet[0].pubkeyHash = "0x" + "ab".repeat(32)),
  `contracts.blsAggregator.guardianSet[${G1}].pubkeyHash`
);
await mut(
  "guardianSet: a guardian SP left out fails",
  rb => (rb.contracts.blsAggregator.guardianSet = []),
  "contracts.blsAggregator.guardianSet.addresses"
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
  "contracts.blsAggregator.thresholds (SlashLevel order unknown)",
  undefined,
  { slashLevels: null }
);
// ---- R1 #2: types from the ABI
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
// ---- R1 #3: failures are not absence
await mut(
  "R1#3: a decoding failure on an n/a field fails",
  rb => (rb.contracts.blsAggregator.pendingRotation = "n/a:none queued"),
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
await mut(
  "R1#4: a fork head other than readbackBlock fails",
  () => {},
  "header.readbackBlock=fork head",
  (w, rb) => ({ head: async () => rb.header.readbackBlock + 1 })
);
{
  const t = JSON.stringify({ providers: ["https://rpc.example/KEY"], tag: "wss://x" }, redact);
  cell("R1#5: URL-like strings are redacted", !/KEY|wss:/.test(t), t);
  // Codex A7 R4: a URL as an object KEY (e.g. a role name) is redacted too
  const rb = clone();
  rb.contracts.blsAggregator.roles = { "https://rpc.example/FAKE_SECRET": [] };
  const r = await run(rb);
  const out = JSON.stringify(
    sanitize({ failed: r.cmp.filter(x => !x.ok), unverified: r.unverified })
  );
  cell(
    "R4: a URL-shaped key in the read-back never reaches the record",
    !/FAKE_SECRET|https:/.test(out) && /redacted key/.test(out),
    out.slice(0, 600)
  ); // Codex A7 R5: production's top-level "rpc" exemption must not reach a nested "rpc"
  const rb5 = clone();
  rb5.contracts.ownerSafe.owners = {
    rpc: { "https://rpc.example/FAKE_SECRET": [] },
    x: { rpc: "https://y/Z" },
  };
  const r5 = await run(rb5);
  const rec = { rpc: "http://127.0.0.1:8546", failed: r5.cmp.filter(x => !x.ok) };
  const out5 = JSON.stringify(sanitize(rec, new Set(["rpc"])));
  cell(
    "R5: with production's exemption, a nested rpc key or value is still redacted; the top-level local rpc is kept",
    !/FAKE_SECRET|https:|y\/Z/.test(out5) && out5.includes("http://127.0.0.1:8546"),
    out5.slice(0, 600)
  );
}
// ---- null = absent from SP's ABI, never by calling
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
// ---- the other read methods
await mut(
  "Safe VERSION() other than SP's fails",
  rb => (rb.contracts.ownerSafe.version = "1.3.0"),
  "contracts.ownerSafe.version"
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
  "EntryPoint deposit other than getDepositInfo(superPaymaster) fails",
  rb => (rb.contracts.entryPoint.deposit = "1"),
  "contracts.entryPoint.deposit"
);
await mut(
  "EntryPoint staked other than getDepositInfo fails",
  rb => (rb.contracts.entryPoint.staked = !rb.contracts.entryPoint.staked),
  "contracts.entryPoint.staked"
);
await mut(
  "evaluationCommunityToken.creditPolicy differs: fails",
  rb => (rb.contracts.evaluationCommunityToken.creditPolicy = 2),
  "contracts.evaluationCommunityToken.creditPolicy"
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
  "roles listed on a contract without a role system fails",
  rb => (rb.contracts.gTokenStaking.roles = {}),
  "contracts.gTokenStaking.roles"
);
await mut(
  "registry: a member SP left out fails",
  rb => (rb.contracts.registry.roles = {}),
  "contracts.registry.roles["
);
await unv(
  "registry: no rolesSource is unverified",
  rb => delete rb.contracts.registry.rolesSource,
  "contracts.registry.roles (no rolesSource"
);
await mut(
  "registry: a log range starting after deployment fails",
  () => {},
  "contracts.registry.rolesSource.fromBlock<=deployment",
  w => ({ code: async (a, b) => (b !== undefined ? "0x60" : w.reader.code(a)) })
);
await mut(
  "registry: pendingOwner() disagreeing with its ERC-7201 slot fails",
  () => {},
  "contracts.registry.pendingOwner=ERC-7201 slot",
  (w, rb) => ({
    slot: async (a, s) =>
      s === OWNERSHIP_2STEP_SLOT ? "0x" + "0".repeat(24) + "42".repeat(20) : w.reader.slot(a, s),
  })
);
// ---- the probe (v4/v5)
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
  () => ({ block: async () => ({ hash: base.header.readbackBlockHash }) })
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
