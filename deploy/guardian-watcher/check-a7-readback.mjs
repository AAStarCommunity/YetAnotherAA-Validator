// Self-test of the A7 read-back comparison (a7-readback.mjs) on SP's own example file, through a
// fake chain that is consistent with it; then one mutation per rule.
// Run: node deploy/guardian-watcher/check-a7-readback.mjs [--schema <file> --example <file>]
// Without the flags it uses the copies under fixtures/a7/ (sha256-pinned below).
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  validate,
  compare,
  SCHEMA_SHA256,
  ANVIL_COMMIT,
  EIP1967_IMPL,
  isState,
} from "./a7-readback.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const opt = k => (args.indexOf(`--${k}`) >= 0 ? args[args.indexOf(`--${k}`) + 1] : undefined);
const EXAMPLE_SHA256 = "c58133b9f8dfe2317af96c6a9a43e7b2521900a69c591843f5c0afb6233b4812";
const LIVE_EXAMPLE_SHA256 = "61926c93fee774900765f9e9eca5d2dee44921d6191751929b18932d140e2b85";
const sha = b => createHash("sha256").update(b).digest("hex");
const schemaText = readFileSync(
  opt("schema") ?? join(here, "fixtures/a7/aoa-a7-readback-1.schema.json")
);
const exampleText = readFileSync(
  opt("example") ?? join(here, "fixtures/a7/aoa-a7-readback-1.example.json")
);
const results = [];
const cell = (name, ok, got) =>
  results.push({ name, ok: !!ok, got: ok ? "" : JSON.stringify(got) });
cell("the schema file is SP's (pinned sha256)", sha(schemaText) === SCHEMA_SHA256, sha(schemaText));
cell(
  "the example file is SP's (pinned sha256)",
  sha(exampleText) === EXAMPLE_SHA256,
  sha(exampleText)
);
const liveText = readFileSync(
  opt("live-example") ?? join(here, "fixtures/a7/aoa-a7-readback-1.live.example.json")
);
cell(
  "the live example file is SP's (pinned sha256)",
  sha(liveText) === LIVE_EXAMPLE_SHA256,
  sha(liveText)
);
const live = JSON.parse(liveText);
const schema = JSON.parse(schemaText);
const example = JSON.parse(exampleText);
// SP's example placeholders are internally inconsistent in one place: superPaymaster.extension is
// spAdminExtension's address, yet the two report different codehashes. A real chain cannot, so the
// comparison must catch it (cell below); the consistent base fixes that one derived value.
const consistent = structuredClone(example);
consistent.contracts.superPaymaster.extensionCodehash =
  consistent.contracts.spAdminExtension.codehash;
const clone = () => structuredClone(consistent);

// ---- a fake chain consistent with a read-back: code k hashes to the reported codehash, getters
// answer the reported values, and a valueState is a getter that returns nothing
function fakeWorld(rb, tweak = {}) {
  const code = new Map();
  const hashOf = new Map();
  const slots = new Map();
  const getters = new Map();
  const put = (addr, hash) => {
    if (!addr || isState(addr) || !hash || isState(hash)) return;
    const c = `0x${Buffer.from(`code:${addr.toLowerCase()}`).toString("hex")}`;
    code.set(addr.toLowerCase(), c);
    hashOf.set(c, hash.toLowerCase());
  };
  const g = (a, n, v) => getters.set(`${a.toLowerCase()}.${n}`, v);
  for (const c of Object.values(rb.contracts)) {
    if (isState(c.address)) continue;
    put(c.address, c.codehash);
    if (!isState(c.erc1967Impl)) {
      slots.set(
        `${c.address.toLowerCase()}.${EIP1967_IMPL}`,
        `0x${"0".repeat(24)}${c.erc1967Impl.slice(2).toLowerCase()}`
      );
      put(c.erc1967Impl, c.implCodehash);
    }
    if (!isState(c.extension)) put(c.extension, c.extensionCodehash);
    for (const [k, v] of Object.entries(c))
      if (!isState(v) && typeof v !== "object") g(c.address, k, v);
  }
  const addrOf = Object.fromEntries(
    Object.entries(rb.contracts)
      .filter(([, c]) => !isState(c.address))
      .map(([k, c]) => [k, c.address])
  );
  for (const [k, v] of Object.entries(rb.checks)) {
    const m = k.match(/^(\w+)\.(\w+)$/);
    if (m && addrOf[m[1]] && !isState(v)) g(addrOf[m[1]], m[2], v);
  }
  const h = rb.header;
  const pr = rb.amsterdamProbe;
  const reader = {
    chainId: async () => h.chainId,
    block: async n => (n === h.readbackBlock ? { hash: h.readbackBlockHash } : null),
    code: async a => code.get(a.toLowerCase()) ?? "0x",
    keccak: c => hashOf.get(c) ?? "0x" + "e".repeat(64),
    slot: async (a, s) => slots.get(`${a.toLowerCase()}.${s}`) ?? "0x" + "0".repeat(64),
    call: async (a, n) => getters.get(`${a.toLowerCase()}.${n}`),
    upstreamHeader: async () => ({ blockAccessListHash: true, slotNumber: true }),
    probe: async () => ({
      estimateFork: pr.estimateFork,
      gasUsedFork: pr.gasUsedFork,
      estimateLive: pr.expected.estimate,
    }),
    ...tweak,
  };
  return reader;
}
// SP's ABIs, consistent with the read-back: every non-null scalar key is a getter; a null one is not
import { id as keccakId } from "ethers";
const sel = n => keccakId(`${n}()`).slice(0, 10);
const abiOf = rb =>
  Object.fromEntries(
    Object.entries(rb.contracts).map(([k, c]) => [
      k,
      new Set(
        Object.entries(c)
          .filter(([, v]) => v !== null)
          .map(([n]) => sel(n))
      ),
    ])
  );
const facts = (rb, abi = abiOf(consistent)) => ({
  abi,
  anvilVersion: rb.header.anvilVersion,
  anvilCommit: ANVIL_COMMIT,
  dumpSha256: rb.header.dumpSha256,
  forkBlock: rb.header.forkBlock,
});
// the chain is always built from the CONSISTENT base; the read-back under test may be mutated
const run = async (rb, tweak) => compare(rb, fakeWorld(consistent, tweak), facts(rb));
const failedPaths = r => r.cmp.filter(x => !x.ok).map(x => x.path);

cell(
  "SP's example validates against SP's schema",
  validate(schema, example).length === 0,
  validate(schema, example)
);
{
  const bad = clone();
  delete bad.header.ethConfig.corroboration;
  cell(
    "a read-back without ethConfig.corroboration is rejected by the schema",
    validate(schema, bad).length > 0,
    null
  );
  const extra = clone();
  extra.header.rpcUrl = "https://x";
  cell(
    "an unknown header key (e.g. an RPC URL) is rejected by the schema",
    validate(schema, extra).length > 0,
    null
  );
}

cell(
  "SP's live example validates against SP's schema",
  validate(schema, live).length === 0,
  validate(schema, live)
);
{
  const v = structuredClone(live);
  v.header.anvilVersion = "n/a:live";
  cell(
    'anvilVersion "n/a:live" validates (the 685ff69d oneOf double match is fixed)',
    validate(schema, v).length === 0,
    validate(schema, v)
  );
  const nv = structuredClone(example);
  nv.contracts.superPaymaster.version = null;
  cell(
    "version null outside spAdminExtension / xPNTsTokenV2Ext is rejected (frozen schema)",
    validate(schema, nv).length > 0,
    null
  );
  const ev = structuredClone(example);
  ev.contracts.spAdminExtension.version = "X-1.0";
  cell(
    "a version on spAdminExtension is rejected (frozen schema)",
    validate(schema, ev).length > 0,
    null
  );
  const r = await compare(live, fakeWorld(consistent), facts(live));
  cell(
    "a live read-back is never accepted as the fork's: header.source fails",
    failedPaths(r).includes("header.source"),
    failedPaths(r)
  );
}

// the consistent world: everything compares, and what has no reader is listed (and so stops)
const base = await run(clone());
{
  const r = await compare(example, fakeWorld(consistent), facts(example));
  cell(
    "SP's raw example: extensionCodehash != the extension's own codehash is caught",
    failedPaths(r).includes("contracts.superPaymaster.extensionCodehash"),
    failedPaths(r)
  );
}
cell("consistent world: no mismatch", failedPaths(base).length === 0, failedPaths(base));
cell(
  "no reader for extension / roles / nested objects: listed unverified (the run stops)",
  [
    "contracts.superPaymaster.extension",
    "contracts.superPaymaster.roles",
    "contracts.blsAggregator.guardianSet",
    "contracts.blsAggregator.signerMaskOrder",
    "contracts.blsAggregator.thresholds",
  ].every(p => base.unverified.includes(p)),
  base.unverified
);
cell(
  "a check on a contract the file does not list (dvtValidator, entryPoint, community) is unverified, not passed",
  [
    "checks.dvtValidator.categoryCount",
    "checks.entryPoint.deposit(superPaymaster)",
    "checks.community.creditPolicy",
  ].every(p => base.unverified.includes(p)),
  base.unverified
);
cell(
  "scalar extras are read through their getter (REGISTRY, MAX_VALIDATORS, DVT_VALIDATOR, WRITER)",
  [
    "contracts.superPaymaster.REGISTRY",
    "contracts.blsAggregator.MAX_VALIDATORS",
    "contracts.blsAggregator.DVT_VALIDATOR",
    "contracts.disclosureRegistry.WRITER",
  ].every(p => base.cmp.some(x => x.path === p && x.ok)),
  base.cmp.map(x => x.path)
);
cell(
  "an equality check is evaluated from both getters",
  base.cmp.some(x => x.path === "checks.blsAggregator.owner == dvtValidator.owner") ||
    base.unverified.includes("checks.blsAggregator.owner == dvtValidator.owner"),
  base
);

const mut = async (name, f, expectPath, tweak) => {
  const rb = clone();
  f(rb);
  const r = await run(rb, tweak?.(rb));
  cell(
    name,
    failedPaths(r).some(p => p === expectPath || p.startsWith(expectPath)),
    failedPaths(r)
  );
};
await mut(
  "a different codehash on the fork fails",
  () => {},
  "contracts.superPaymaster.codehash",
  () => ({ keccak: () => "0x" + "1".repeat(64) })
);
await mut(
  "SP says n/a:not a proxy but the fork has an implementation slot: fails",
  () => {},
  "contracts.blsAggregator.erc1967Impl",
  () => ({ slot: async () => "0x" + "0".repeat(24) + "1".repeat(40) })
);
await mut(
  "owner differs: fails",
  rb => (rb.contracts.superPaymaster.owner = "0x" + "9".repeat(40)),
  "contracts.superPaymaster.owner"
);
// null = absent from SP's ABI, decided from the ABI, never by calling (DSR)
{
  const P = "contracts.spAdminExtension.version";
  const fallback = { call: async (a, n) => (n === "version" ? "X-1.0" : undefined) };
  const r1 = await compare(clone(), fakeWorld(consistent, fallback), facts(clone()));
  cell(
    "null version, a fallback contract answers version(), ABI has no version(): passes (not called)",
    r1.cmp.some(x => x.path === P && x.ok) && !r1.unverified.some(u => u.startsWith(P)),
    r1.cmp.filter(x => x.path === P)
  );
  const abi = abiOf(consistent);
  abi.spAdminExtension = new Set([...abi.spAdminExtension, sel("version")]);
  const r2 = await compare(clone(), fakeWorld(consistent), facts(clone(), abi));
  cell(
    "null version but version() IS in SP's ABI: fails",
    failedPaths(r2).includes(P),
    failedPaths(r2)
  );
  const r3 = await compare(clone(), fakeWorld(consistent), facts(clone(), {}));
  cell(
    "null version without SP's ABI: unverified (the run stops)",
    r3.unverified.some(u => u.startsWith(P)) && !r3.cmp.some(x => x.path === P),
    r3.unverified
  );
}
await mut(
  "a scalar extra differs (OPERATOR_WITHDRAWAL_WINDOW): fails",
  rb => (rb.contracts.superPaymaster.OPERATOR_WITHDRAWAL_WINDOW = 3600),
  "contracts.superPaymaster.OPERATOR_WITHDRAWAL_WINDOW"
);
await mut(
  "readbackBlockHash differs: fails",
  rb => (rb.header.readbackBlockHash = "0x" + "1".repeat(64)),
  "header.readbackBlockHash",
  rb => ({ block: async () => ({ hash: "0x" + "b".repeat(64) }) })
);
await mut(
  "anvilCommit other than the pinned build: fails",
  rb => (rb.header.anvilCommit = "1".repeat(40)),
  "header.anvilCommit"
);
await mut(
  "upstream forkId not Amsterdam: fails",
  rb => (rb.header.ethConfig.forkId = "0xdeadbeef"),
  "header.ethConfig.forkId"
);
await mut(
  "corroboration without slotNumber: fails",
  rb => (rb.header.ethConfig.corroboration.slotNumber = false),
  "header.ethConfig.corroboration.slotNumber"
);
await mut(
  "this script's own upstream lacks the Amsterdam fields: fails",
  () => {},
  "upstream.slotNumber",
  () => ({ upstreamHeader: async () => ({ blockAccessListHash: true, slotNumber: false }) })
);
await mut(
  "source live is not a fork read-back: fails",
  rb => (rb.header.source = "live"),
  "header.source"
);
await mut(
  "a provider given as a URL fails",
  rb => (rb.header.providers = ["https://rpc.example/key"]),
  "header.providers"
);
await mut(
  "probe: SP's live estimates disagree: fails",
  rb => (rb.amsterdamProbe.estimateLive.tenderly = 1),
  "amsterdamProbe.sp:estimateLive==estimateFork"
);
await mut(
  "probe: the rerun on this fork measures other gas: fails",
  () => {},
  "amsterdamProbe.fork:gasUsed",
  () => ({ probe: async () => ({ estimateFork: 53000, gasUsedFork: 51000, estimateLive: 53000 }) })
);
await mut(
  "probe: this script's own upstream estimate differs: fails",
  () => {},
  "amsterdamProbe.upstream:estimate",
  () => ({ probe: async () => ({ estimateFork: 53000, gasUsedFork: 52000, estimateLive: 60000 }) })
);
{
  const rb = clone();
  rb.amsterdamProbe.predicate = "true";
  const r = await run(rb);
  cell(
    "an unknown probe predicate is never evaluated: unverified",
    r.unverified.includes("amsterdamProbe.predicate"),
    r.unverified
  );
}

let failed = 0;
for (const r of results) {
  console.log(
    `${r.ok ? "ok  " : "FAIL"} ${r.name}${r.ok ? "" : `\n     got ${r.got.slice(0, 800)}`}`
  );
  if (!r.ok) failed++;
}
console.log(`\n${results.length - failed}/${results.length} cells`);
process.exit(failed ? 1 : 0);
