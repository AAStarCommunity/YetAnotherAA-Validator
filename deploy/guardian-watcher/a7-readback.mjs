// Comparison of SuperPaymaster's aoa-a7-readback/1 file (SP 8f330504, frozen v9;
// docs/release/a7/aoa-a7-readback-1.schema.json, read methods in its "x-readMethods") with what THIS
// script reads from the loaded fork. Pure: every chain read goes through an injected reader, so the
// rules are self-tested (check-a7-readback.mjs) without a chain.
//
// Rules (DSR 272084f2, 0829236d, the A7 schema messages, Codex A7 R1):
//   - the file validates against the pinned schema (Draft 2020-12) before anything is compared;
//   - the inventory is ours, not the file's: every SDK pins key must be present, checks non-empty;
//   - every address comes from the manifest address book (facts.addressBook), not from the file;
//   - every getter is read with its ABI from SP's committed abis/ at header.spCommit: the return
//     type comes from that ABI, never guessed; no ABI -> unverified;
//   - null = "absent": the selector is not in that ABI (never decided by calling: a contract with a
//     fallback answers any selector);
//   - "unreadable:..." / "n/a:...": our read must also yield nothing (not in the ABI, empty return or
//     revert); a decoding failure fails; an RPC failure THROWS and stops the whole run;
//   - every read is at the fork head, which must be header.readbackBlock (the state the drills get);
//   - anything without an independent reader is UNVERIFIED, which stops the rehearsal like a mismatch.
import Ajv2020 from "ajv/dist/2020.js";
import { AbiCoder, keccak256 } from "ethers";

export const SCHEMA_ID = "aoa-a7-readback/1";
/** sha256 of SP's FROZEN schema file at 8f330504 (v9, DSR-verified; any later change needs DSR
 * acceptance and a new hash). */
export const SCHEMA_SHA256 = "bc009b278348c25be8858ef04b0dd3decf24489421a6dbc98d67956e619dc106";
export const SCHEMA_SOURCE = {
  repo: "AAStarCommunity/SuperPaymaster",
  ref: "8f3305047a72f3f0132827447d70af1375debe8a",
  path: "docs/release/a7/aoa-a7-readback-1.schema.json",
};
export const ANVIL_COMMIT = "4e8874b2bdc840929585ca73e170993c50a4a531";
/** sha256 of SP's fork example at the pinned schema commit: its per-contract field list is the
 * field inventory (Codex A7 R11), independent of the read-back under test. */
export const EXAMPLE_SHA256 = "a5effd05cf469c01d05090b0e56704f4ccc9b55021c294f57c4d2d1e498706c2";
/** The check inventory from SP's pinned example: every check key it lists (Codex A7 R12). */
export const checkInventory = example => Object.keys(example?.checks ?? {});
/** The field inventory from SP's pinned example: contract key -> its non-common fields. */
export function fieldInventory(example) {
  const out = {};
  for (const [k, c] of Object.entries(example?.contracts ?? {}))
    out[k] = Object.keys(c).filter(f => !COMMON.includes(f) && f !== "rolesSource");
  return out;
}
/** Sepolia's Amsterdam (upstream EIP-7910 eth_config.current). */
export const AMSTERDAM = { activationTime: 1791294816, forkId: "0x6c1d9423" };
export const EIP1967_IMPL = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";
/** Ownable2StepNamespaced's ERC-7201 pending-owner slot (recomputed here: keccak256(abi.encode(
 * uint256(keccak256("aastar.storage.Ownership2Step")) - 1)) & ~0xff), a cross-check of pendingOwner(). */
export const OWNERSHIP_2STEP_SLOT =
  "0xdb5a3168abaa6147a9f3a4cb66016161119d4d50b6393344d27120286f742a00";
/** The probe rule this script evaluates (schema v4, DSR); any other wording is unverified. */
export const KNOWN_PREDICATES = [
  "all(estimateSimulate[p] == gasUsedFork == expected.gasUsed for p if int) and all(callAtGasUsed.values())",
];
/** The inventory: the frozen schema v5's contracts.required (20 keys); the self-test asserts the
 * pinned schema says exactly this. */
export const REQUIRED_CONTRACTS = [
  "superPaymaster",
  "spAdminExtension",
  "superPaymasterLens",
  "registry",
  "policyRegistry",
  "blsAggregator",
  "dvtValidator",
  "reputationSystem",
  "disclosureRegistry",
  "xPNTsFactoryV2",
  "xPNTsTokenV2Impl",
  "xPNTsTokenV2Ext",
  "aoaProtocolRegistry",
  "globalTierSource",
  "aPNTsCapped",
  "gTokenStaking",
  "entryPoint",
  "ownerSafe",
  "multiSendCallOnly",
  "evaluationCommunityToken",
];
/** Contract-specific fields that MUST be present (x-readMethods; Codex A7 R2 #1): a read-back that
 * leaves one out is unverified, never silently passed. */
export const REQUIRED_FIELDS = {
  blsAggregator: [
    "guardianSet",
    "signerMaskOrder",
    "thresholds",
    // x-readMethods "blsAggregator.verifier" and "thresholds" (Codex A7 R3 #1)
    "fraudProofVerifier",
    "pendingFraudProofVerifier",
    "DVT_VALIDATOR",
    "domainSeparator",
    "MAX_VALIDATORS",
    // schema v7 required
    "N",
    "pendingFraudProofVerifierReadyAt",
    "minThreshold",
    "defaultThreshold",
    "SLASH_THRESHOLD_FLOOR",
  ],
  dvtValidator: ["categoryCount"],
  disclosureRegistry: ["WRITER", "AGGREGATOR"],
  ownerSafe: ["threshold", "owners", "singleton"],
  entryPoint: ["deposit", "staked", "stake", "unstakeDelaySec", "withdrawTime"],
  evaluationCommunityToken: [
    "creditPolicy",
    "POLICY_OFF",
    "policyEpoch",
    "pendingPolicy",
    "pendingPolicyEta",
    "issuanceCap",
    "SUPERPAYMASTER_ADDRESS",
  ],
};
/** Contracts with a role system (x-readMethods v5); every other contract's roles must be "n/a:...". */
export const ROLE_SYSTEMS = ["registry", "timelockController"];
/** The canonical EntryPoint v0.7 (x-readMethods "externalVersion"). */
export const ENTRY_POINT_V07 = "0x0000000071727De22E5E9d8BAf0edAc6f37da032";
/** Pre-existing (not SP-deployed) contracts: identity = the fork's codehash equals upstream's. */
export const EXTERNAL_CONTRACTS = ["entryPoint", "multiSendCallOnly"];
/**
 * contractKey -> SP abis/<file> at header.spCommit. superPaymaster and xPNTsTokenV2Impl use SP's
 * combined ".full" ABIs (core + extension reached through the core's fallback, per the files' own
 * note); null = no file in abis/: every ABI-dependent field of that contract is unverified.
 */
export const ABI_FILES = {
  superPaymaster: "SuperPaymaster.full.json",
  spAdminExtension: "SuperPaymasterAdmin.json",
  superPaymasterLens: "SuperPaymasterLens.json",
  registry: "Registry.json",
  policyRegistry: "PolicyRegistry.json",
  blsAggregator: "BLSAggregator.json",
  dvtValidator: "DVTValidator.json",
  reputationSystem: "ReputationSystem.json",
  disclosureRegistry: null, // DVT's own contract: ABI from the DVT repo at the manifest's DVT commit
  xPNTsFactoryV2: "xPNTsFactoryV2.json",
  xPNTsTokenV2Impl: "xPNTsTokenV2.full.json",
  xPNTsTokenV2Ext: "xPNTsTokenV2Ext.json",
  aoaProtocolRegistry: "AOAProtocolRegistry.json",
  globalTierSource: "GlobalTierSource.json",
  aPNTsCapped: "APNTsCapped.json",
  gTokenStaking: "GTokenStaking.json",
  entryPoint: "EntryPoint.json",
  ownerSafe: null, // SP to add the official safe-smart-account release ABI (tag + sha256)
  multiSendCallOnly: null, // likewise
  evaluationCommunityToken: "xPNTsTokenV2.full.json", // an xPNTs v2 token instance (core + ext)
  timelockController: "TimelockController.json",
};
/** Safe getters (x-readMethods "ownerSafe"): typed reads only; Safe's ABI is not in SP's abis/, so
 * absence (null) on the Safe is never decided from this. */
export const SAFE_GETTERS = [
  "function VERSION() view returns (string)",
  "function getThreshold() view returns (uint256)",
  "function getOwners() view returns (address[])",
];

const IDENT = /^[A-Za-z_][A-Za-z0-9_]*$/;
const COMMON = [
  "address",
  "version",
  "codehash",
  "erc1967Impl",
  "implCodehash",
  "extension",
  "extensionCodehash",
  "owner",
  "pendingOwner",
  "guardian",
  "roles",
];
const ZERO = "0x0000000000000000000000000000000000000000";
const lc = v => String(v).toLowerCase();

const URL_LIKE = /[a-z][a-z0-9+.-]*:\/\/|\b(?:https?|wss?|ftp|file):/i;
/** Any string value or object key, at any depth, that looks like a URL. */
export function hasUrlLike(v) {
  if (typeof v === "string") return URL_LIKE.test(v);
  if (Array.isArray(v)) return v.some(hasUrlLike);
  if (v && typeof v === "object")
    return Object.entries(v).some(([k, x]) => URL_LIKE.test(k) || hasUrlLike(x));
  return false;
}

/** Every property name the schema itself defines (for masking input-derived diagnostic paths). */
function schemaNames(node, out = new Set()) {
  if (Array.isArray(node)) node.forEach(x => schemaNames(x, out));
  else if (node && typeof node === "object") {
    for (const k of ["properties", "patternProperties"])
      if (node[k] && typeof node[k] === "object") for (const n of Object.keys(node[k])) out.add(n);
    if (Array.isArray(node.required)) node.required.forEach(n => out.add(n));
    Object.values(node).forEach(x => schemaNames(x, out));
  }
  return out;
}

/** Schema validation: returns the list of errors (paths only), empty when valid. */
export function validate(schema, rb) {
  const ajv = new Ajv2020({ allErrors: true, strict: false });
  const ok = ajv.validate(schema, rb);
  // a path segment is input (a key of the read-back): only plain identifiers and indices are shown,
  // anything else (a URL, whatever its JSON-Pointer escaping) becomes "(key)" (Codex A7 R6)
  // only names the pinned schema itself defines, the inventory, and array indices are shown; any
  // other key comes from the input and is masked, whatever its shape (Codex A7 R7)
  const known = new Set([...REQUIRED_CONTRACTS, ...schemaNames(schema)]);
  const seg = x => (/^\d+$/.test(x) || known.has(x) ? x : "(key)");
  const path = p =>
    p
      ? p
          .split("/")
          .slice(1)
          .map(x => seg(x.replace(/~1/g, "/").replace(/~0/g, "~")))
          .map(x => `/${x}`)
          .join("")
      : "/";
  return ok ? [] : (ajv.errors ?? []).map(e => `${path(e.instancePath)} ${e.keyword}`);
}

export const isState = v => v === null || (typeof v === "string" && /^(unreadable|n\/a):/.test(v));

/** SP's JSON value vs a decoded ABI value of the getter's own type. */
function sameTyped(type, sp, v) {
  if (type === "address") return typeof sp === "string" && lc(sp) === lc(v);
  if (/^u?int\d*$/.test(type))
    return (typeof sp === "number" && Number.isSafeInteger(sp)) ||
      (typeof sp === "string" && /^-?\d+$/.test(sp))
      ? BigInt(sp) === BigInt(v)
      : false;
  if (type === "bool") return typeof sp === "boolean" && sp === v;
  if (/^bytes\d*$/.test(type)) return typeof sp === "string" && lc(sp) === lc(v);
  if (type === "string") return typeof sp === "string" && sp === v;
  return false;
}
const show = v => (typeof v === "bigint" ? v.toString() : Array.isArray(v) ? v.map(show) : v);
const wordAddr = w => (BigInt(w) === 0n ? ZERO : `0x${w.slice(-40)}`.toLowerCase());

/**
 * Compare the whole file. reader: {
 *   chainId(), head() -> number, block(n) -> {hash} | null,
 *   code(addr, blockTag?) -> hex, slot(addr, slot) -> 32-byte hex, keccak(hex) -> hash,
 *   call(addr, iface, fragment, args) -> {status: "value", v} | {status: "empty"} | {status: "revert"}
 *                                       | {status: "decode"}          (an RPC failure THROWS),
 *   logs({address, topics, fromBlock, toBlock}) -> [{topics, data}]   (THROWS on failure),
 *   upstreamHeader(n) -> {blockAccessListHash: bool, slotNumber: bool} | undefined,
 *   probe({sender, initcode, forkBlock, gasUsed}) -> {gasUsedFork, simulate, callAtGasUsed,
 *     estimateFork, estimateLive, callAtGasUsedMinusOne} (fields undefined when not obtainable)
 * }; facts: {anvilVersion, anvilCommit, dumpSha256, forkBlock, abi: {key: ethers.Interface},
 *   safe: ethers.Interface, addressBook: {key: address} | null, slashLevels: {name: index} | null}.
 * Returns {cmp: [{path, sp, fork, ok}], unverified: [path]}.
 */
export async function compare(rb, reader, facts) {
  const cmp = [];
  const unverified = [];
  const check = (path, sp, ours, ok) =>
    cmp.push({ path, sp: show(sp) ?? null, fork: show(ours) ?? null, ok: !!ok });
  const eq = (path, sp, ours) =>
    check(
      path,
      sp,
      ours,
      ours !== undefined && JSON.stringify(show(sp)) === JSON.stringify(show(ours))
    );
  const h = rb.header;

  // ---- header
  // data-quality gate (DSR): SP's read-back and address book carry names only; a URL-like string
  // anywhere (any "scheme://", or http/https/ws/wss/ftp/file followed by ":") is an SP defect. It is
  // reported as a fixed category and never echoed.
  for (const [what, v] of [
    ["read-back", rb],
    ["address book", facts.addressBookDoc ?? facts.addressBook ?? {}],
  ])
    if (hasUrlLike(v))
      cmp.push({
        path: `SP artefact contains URL-like string (${what})`,
        sp: null,
        fork: null,
        ok: false,
      });
  eq("header.source", "fork", h.source);
  eq("header.chainId", h.chainId, await reader.chainId());
  eq("header.forkBlock", h.forkBlock, facts.forkBlock);
  eq("header.hardfork", "amsterdam", h.hardfork);
  eq("header.anvilCommit", ANVIL_COMMIT, h.anvilCommit);
  eq("header.anvilCommit=binary", h.anvilCommit, facts.anvilCommit);
  eq("header.anvilVersion=binary", h.anvilVersion, facts.anvilVersion);
  eq("header.dumpSha256", h.dumpSha256, facts.dumpSha256);
  // the state handed to the drills IS the read-back block (Codex A7 R1 #4)
  eq("header.readbackBlock=fork head", h.readbackBlock, await reader.head());
  const blk = await reader.block(h.readbackBlock);
  check(
    "header.readbackBlockHash",
    h.readbackBlockHash,
    blk?.hash,
    !!blk?.hash && lc(blk.hash) === lc(h.readbackBlockHash)
  );
  if (!h.providers.every(p => /^[a-z0-9][a-z0-9._-]{0,40}$/i.test(p)))
    check("header.providers", "(names only)", "(not a provider name)", false);
  // Amsterdam from UPSTREAM only (the local engine's eth_config is its own configuration)
  eq("header.ethConfig.activationTime", AMSTERDAM.activationTime, h.ethConfig.activationTime);
  eq("header.ethConfig.forkId", AMSTERDAM.forkId, h.ethConfig.forkId);
  const co = h.ethConfig.corroboration;
  eq("header.ethConfig.corroboration.blockNumber", h.forkBlock, co.blockNumber);
  eq("header.ethConfig.corroboration.blockAccessListHash", true, co.blockAccessListHash);
  eq("header.ethConfig.corroboration.slotNumber", true, co.slotNumber);
  const up = await reader.upstreamHeader(h.forkBlock);
  eq("upstream.blockAccessListHash", true, up?.blockAccessListHash);
  eq("upstream.slotNumber", true, up?.slotNumber);

  // ---- inventory (Codex A7 R1 #1): ours, not the file's
  for (const k of REQUIRED_CONTRACTS)
    if (!(k in rb.contracts)) unverified.push(`contracts.${k} (missing from the read-back)`);
  if (Object.keys(rb.checks).length === 0) unverified.push("checks (empty)");
  // every check SP's pinned example lists must be in the read-back (Codex A7 R12)
  for (const k of facts.checkInventory ?? [])
    if (!(k in rb.checks)) unverified.push(`checks.${k} (missing from the read-back)`);
  // optional in the schema; required when the manifest's address book declares one (DSR)
  if (facts.addressBook?.timelockController && !("timelockController" in rb.contracts))
    unverified.push(
      "contracts.timelockController (declared in the address book, missing from the read-back)"
    );

  // one typed read through SP's ABI. kind: noabi | notinabi | unsupported | value | empty | revert | decode
  const read = async (iface, addr, sig, args = []) => {
    if (!iface) return { kind: "noabi" };
    const f = iface.getFunction(sig);
    if (!f) return { kind: "notinabi" };
    const r = await reader.call(addr, iface, f, args);
    return { kind: r.status, v: r.v, f };
  };
  const scalarOut = f => f.outputs.length === 1 && !/[[\]()]|tuple/.test(f.outputs[0].type);
  // the field rules, for one SP value and one zero-argument getter
  const field = async (path, iface, key, addr, name, sp) => {
    if (sp === null) {
      // absent: decided from SP's ABI only (DSR)
      if (!iface) return unverified.push(`${path} (null: no ABI for ${key})`);
      const f = iface.getFunction(`${name}()`);
      return check(path, null, f ? `${name}() in ABI` : null, !f);
    }
    const g = await read(iface, addr, `${name}()`);
    if (g.kind === "noabi") return unverified.push(`${path} (no ABI for ${key})`);
    if (g.f && !scalarOut(g.f)) return unverified.push(`${path} (non-scalar getter)`);
    if (isState(sp))
      return check(path, sp, g.kind, ["notinabi", "empty", "revert"].includes(g.kind));
    if (g.kind !== "value") return check(path, sp, g.kind, false);
    return check(path, sp, g.v, sameTyped(g.f.outputs[0].type, sp, g.v));
  };
  const codehashAt = async a => {
    const code = await reader.code(a);
    return code && code !== "0x" ? lc(reader.keccak(code)) : undefined;
  };

  // ---- contracts
  const addrOf = {};
  for (const [key, c] of Object.entries(rb.contracts)) {
    const P = `contracts.${key}`;
    const iface = facts.abi?.[key] ?? null;
    // the address comes from the manifest address book, never from the file (x-readMethods)
    const book = facts.addressBook?.[key];
    if (!facts.addressBook) unverified.push(`${P}.address (no address book)`);
    else if (book === undefined) unverified.push(`${P}.address (not in the address book)`);
    else if (isState(c.address)) check(`${P}.address`, c.address, book, false);
    else check(`${P}.address`, c.address, book, lc(book) === lc(c.address));
    if (isState(c.address)) {
      // "nothing deployed here" cannot be read: every other field must be a state, and is unread
      if (!book)
        unverified.push(`${P}.address (${c.address === null ? "null" : c.address.split(":")[0]})`);
      continue;
    }
    const a = c.address;
    addrOf[key] = a;
    // the contract-specific fields the read methods require (Codex A7 R2 #1): ours, not the file's
    for (const f of new Set([
      ...(REQUIRED_FIELDS[key] ?? []),
      ...(facts.fieldInventory?.[key] ?? []),
    ]))
      if (!(f in c)) unverified.push(`${P}.${f} (missing from the read-back)`);
    if (key === "entryPoint")
      check(
        `${P}.address=canonical EntryPoint v0.7`,
        ENTRY_POINT_V07,
        a,
        lc(a) === lc(ENTRY_POINT_V07)
      );
    const codehash = await codehashAt(a);
    // a pre-existing contract's identity is its code: the fork's must be upstream's at forkBlock
    if (EXTERNAL_CONTRACTS.includes(key)) {
      const upHash = await reader.upstreamCodehash(a, h.forkBlock);
      check(`${P}.codehash=upstream`, upHash, codehash, !!upHash && upHash === codehash);
    }
    if (isState(c.codehash)) check(`${P}.codehash`, c.codehash, codehash, codehash === undefined);
    else check(`${P}.codehash`, c.codehash, codehash, codehash === lc(c.codehash));
    const implWord = await reader.slot(a, EIP1967_IMPL);
    const impl = BigInt(implWord) !== 0n ? wordAddr(implWord) : undefined;
    if (isState(c.erc1967Impl)) check(`${P}.erc1967Impl`, c.erc1967Impl, impl, impl === undefined);
    else check(`${P}.erc1967Impl`, c.erc1967Impl, impl, impl === lc(c.erc1967Impl));
    // the SDK pins' spImpl / registryImpl are these proxies' erc1967Impl (schema v5, #412 F4)
    const pinImpl = { superPaymaster: "spImpl", registry: "registryImpl" }[key];
    if (pinImpl && facts.addressBook) {
      const want = facts.addressBook[pinImpl];
      if (!want) unverified.push(`${P}.erc1967Impl (address book has no ${pinImpl})`);
      else check(`${P}.erc1967Impl=pins.${pinImpl}`, want, impl, !!impl && impl === lc(want));
    }
    const implHash = impl ? await codehashAt(impl) : undefined;
    if (isState(c.implCodehash))
      check(`${P}.implCodehash`, c.implCodehash, implHash, implHash === undefined);
    else check(`${P}.implCodehash`, c.implCodehash, implHash, implHash === lc(c.implCodehash));

    // extension (x-readMethods): superPaymaster -> EXTENSION(); its codehash must equal
    // spAdminExtension's; every other contract has none
    if (key === "superPaymaster") {
      const g = await read(iface, a, "EXTENSION()");
      if (g.kind === "noabi") unverified.push(`${P}.extension (no ABI)`);
      else if (g.kind !== "value") check(`${P}.extension`, c.extension, g.kind, false);
      else {
        check(
          `${P}.extension`,
          c.extension,
          g.v,
          !isState(c.extension) && lc(g.v) === lc(c.extension)
        );
        const bookAdmin = facts.addressBook?.spAdminExtension;
        if (facts.addressBook && !bookAdmin)
          unverified.push(`${P}.extension (address book has no spAdminExtension)`);
        else if (bookAdmin)
          check(`${P}.extension=pins.spAdminExtension`, bookAdmin, g.v, lc(g.v) === lc(bookAdmin));
        const eh = await codehashAt(g.v);
        check(
          `${P}.extensionCodehash`,
          c.extensionCodehash,
          eh,
          !isState(c.extensionCodehash) && eh === lc(c.extensionCodehash)
        );
        const admin = rb.contracts.spAdminExtension;
        check(
          `${P}.extensionCodehash=spAdminExtension.codehash`,
          admin?.codehash,
          eh,
          !!admin && !isState(admin.codehash) && eh === lc(admin.codehash)
        );
      }
    } else {
      check(
        `${P}.extension`,
        c.extension,
        "(none by x-readMethods)",
        isState(c.extension) && c.extension !== null
      );
      check(
        `${P}.extensionCodehash`,
        c.extensionCodehash,
        "(none by x-readMethods)",
        isState(c.extensionCodehash) && c.extensionCodehash !== null
      );
    }

    for (const k of ["version", "owner", "pendingOwner", "guardian"]) {
      // the Safe exposes VERSION(), not version() (x-readMethods v5)
      if (key === "ownerSafe" && k === "version")
        await field(`${P}.version`, facts.safe, key, a, "VERSION", c.version);
      else await field(`${P}.${k}`, iface, key, a, k, c[k]);
    }
    // Registry: pendingOwner() cross-checked against its ERC-7201 slot (x-readMethods)
    if (key === "registry" && !isState(c.pendingOwner)) {
      const w = await reader.slot(a, OWNERSHIP_2STEP_SLOT);
      check(
        `${P}.pendingOwner=ERC-7201 slot`,
        c.pendingOwner,
        wordAddr(w),
        wordAddr(w) === lc(c.pendingOwner)
      );
    }

    // roles (x-readMethods): RoleGranted/RoleRevoked logs from deployment to readbackBlock, each
    // candidate confirmed with hasRole at the head; the range is the contract's rolesSource
    await roles(P, iface, key, a, c);

    // contract-specific keys
    for (const [k, v] of Object.entries(c)) {
      if (COMMON.includes(k) || k === "rolesSource") continue;
      if (
        key === "blsAggregator" &&
        ["guardianSet", "signerMaskOrder", "thresholds", "N"].includes(k)
      )
        continue; // below
      if (key === "ownerSafe" && ["threshold", "owners", "singleton"].includes(k)) continue; // below
      if (key === "entryPoint" && REQUIRED_FIELDS.entryPoint.includes(k)) continue; // below
      if (!IDENT.test(k) || (v !== null && typeof v === "object")) {
        unverified.push(`${P}.${k} (no read method)`);
        continue;
      }
      await field(`${P}.${k}`, iface, key, a, k, v);
    }
    if (key === "blsAggregator") await bls(P, iface, a, c);
    if (key === "ownerSafe") await safe(P, a, c);
    if (key === "entryPoint") await entryPoint(P, iface, a, c);
  }

  // EntryPoint v0.7: getDepositInfo(superPaymaster) -> deposit, staked, stake, unstakeDelaySec,
  // withdrawTime, recorded as fields of contracts.entryPoint (x-readMethods v5)
  async function entryPoint(P, iface, a, c) {
    const sp = rb.contracts.superPaymaster?.address;
    const g =
      isState(sp) || !sp ? { kind: "nosp" } : await read(iface, a, "getDepositInfo(address)", [sp]);
    for (const f of REQUIRED_FIELDS.entryPoint) {
      if (!(f in c)) continue; // already unverified above
      if (g.kind === "noabi") unverified.push(`${P}.${f} (no ABI)`);
      else if (g.kind !== "value") check(`${P}.${f}`, c[f], g.kind, false);
      else {
        const comp = g.f.outputs[0].components.find(x => x.name === f);
        if (!comp) check(`${P}.${f}`, c[f], "(no such DepositInfo field)", false);
        else check(`${P}.${f}`, c[f], g.v[f], sameTyped(comp.type, c[f], g.v[f]));
      }
    }
  }

  async function roles(P, iface, key, a, c) {
    // only the Registry's own role system and a TimelockController have roles (x-readMethods v5);
    // every other contract writes "n/a:no role system"
    if (!ROLE_SYSTEMS.includes(key))
      return check(
        `${P}.roles`,
        c.roles,
        "(no role system by x-readMethods)",
        typeof c.roles === "string" && c.roles.startsWith("n/a:")
      );
    if (!iface) return unverified.push(`${P}.roles (no ABI)`);
    const hasRoleF = iface.getFunction("hasRole(bytes32,address)");
    if (!hasRoleF || isState(c.roles) || typeof c.roles !== "object")
      return check(`${P}.roles`, c.roles, hasRoleF ? "hasRole in ABI" : "no hasRole", false);
    // candidates: every role event in SP's ABI whose first two indexed arguments are (role, account)
    const roleEvents = ["RoleGranted", "RoleRevoked", "RoleRegistered", "RoleExited"]
      .map(n => iface.getEvent(n))
      .filter(
        e =>
          e &&
          e.inputs[0]?.type === "bytes32" &&
          e.inputs[0].indexed &&
          e.inputs[1]?.type === "address" &&
          e.inputs[1].indexed
      );
    if (!roleEvents.length) return check(`${P}.roles`, "(role events)", "none in ABI", false);
    const src = c.rolesSource;
    if (!src || !Number.isSafeInteger(src.fromBlock) || src.toBlock !== h.readbackBlock)
      return unverified.push(`${P}.roles (no rolesSource {fromBlock, toBlock = readbackBlock})`);
    // the range starts at or before deployment: no code at fromBlock - 1
    const before = src.fromBlock > 0 ? await reader.code(a, src.fromBlock - 1) : "0x";
    check(
      `${P}.rolesSource.fromBlock<=deployment`,
      src.fromBlock,
      before === "0x" ? "no code before" : "code before",
      before === "0x"
    );
    const logs = await reader.logs({
      address: a,
      topics: [roleEvents.map(e => e.topicHash)],
      fromBlock: src.fromBlock,
      toBlock: h.readbackBlock,
    });
    const cand = new Map(); // role -> Set(account)
    for (const l of logs) {
      const role = lc(l.topics[1]);
      const acct = wordAddr(l.topics[2]);
      if (!cand.has(role)) cand.set(role, new Set());
      cand.get(role).add(acct);
    }
    const ours = new Map();
    for (const [role, accts] of cand)
      for (const acct of accts) {
        const r = await reader.call(a, iface, hasRoleF, [role, acct]);
        if (r.status !== "value") return check(`${P}.roles`, "(hasRole)", r.status, false);
        if (r.v === true) {
          if (!ours.has(role)) ours.set(role, new Set());
          ours.get(role).add(acct);
        }
      }
    // SP's keys: a bytes32 role id, or the name of a bytes32 getter in the ABI (e.g. ROLE_DVT)
    const spRoles = new Map();
    for (const [name, members] of Object.entries(c.roles)) {
      let id = /^0x[0-9a-fA-F]{64}$/.test(name) ? lc(name) : null;
      if (!id) {
        // a name that is not an identifier cannot be a getter (and is not echoed)
        if (!IDENT.test(name))
          return unverified.push(`${P}.roles.(key) (not a role id or getter name)`);
        const g = await read(iface, a, `${name}()`);
        if (g.kind !== "value" || g.f.outputs[0].type !== "bytes32")
          return unverified.push(`${P}.roles.${name} (role id not resolvable from the ABI)`);
        id = lc(g.v);
      }
      // a role named twice (by name and by id, or twice by name) could hide a contradiction
      // (Codex A7 R3 #2): the second occurrence fails
      if (spRoles.has(id)) {
        check(`${P}.roles[${id.slice(0, 10)}…]`, "one entry per role", "listed twice", false);
        continue;
      }
      spRoles.set(id, new Set(members.map(lc)));
    }
    const ids = new Set([...ours.keys(), ...spRoles.keys()]);
    for (const id of ids) {
      const o = [...(ours.get(id) ?? [])].sort();
      const s = [...(spRoles.get(id) ?? [])].sort();
      check(`${P}.roles[${id.slice(0, 10)}…]`, s, o, JSON.stringify(o) === JSON.stringify(s));
    }
    if (ids.size === 0) check(`${P}.roles`, c.roles, {}, true);
  }

  async function bls(P, iface, a, c) {
    if (!iface) {
      for (const k of ["guardianSet", "signerMaskOrder", "thresholds"])
        if (k in c) unverified.push(`${P}.${k} (no ABI)`);
      return;
    }
    // slots 1..MAX_VALIDATORS -> address; nonzero -> getBLSPublicKey (x-readMethods)
    const mv = await read(iface, a, "MAX_VALIDATORS()");
    if (mv.kind !== "value" || BigInt(mv.v) > 255n) {
      for (const k of ["guardianSet", "signerMaskOrder", "N"])
        if (k in c) check(`${P}.${k}`, "(MAX_VALIDATORS)", mv.kind, false);
    } else {
      const slots = [];
      for (let s = 1; s <= Number(mv.v); s++) {
        const g = await read(iface, a, "validatorAtSlot(uint8)", [s]);
        if (g.kind !== "value") {
          check(`${P}.validatorAtSlot(${s})`, "(address)", g.kind, false);
          return;
        }
        slots.push(lc(g.v));
      }
      // N has no getter in SP's ABI: it is the number of occupied slots (validatorAtSlot != 0)
      if ("N" in c) {
        const n = slots.filter(x => x !== ZERO).length;
        check(`${P}.N=occupied slots`, c.N, n, sameTyped("uint256", c.N, n));
      }
      if ("guardianSet" in c) {
        const ours = [];
        for (let i = 0; i < slots.length; i++) {
          if (slots[i] === ZERO) continue;
          const g = await read(iface, a, "getBLSPublicKey(address)", [slots[i]]);
          if (g.kind !== "value")
            return check(`${P}.guardianSet`, "(getBLSPublicKey)", g.kind, false);
          const out = g.v; // Result: [publicKey tuple, slot, isActive]
          const pkType = g.f.outputs[0];
          const pubkeyHash = lc(keccak256(AbiCoder.defaultAbiCoder().encode([pkType], [out[0]])));
          ours.push({ address: slots[i], pubkeyHash, slot: Number(out[1]), isActive: out[2] });
        }
        const spSet = Array.isArray(c.guardianSet) ? c.guardianSet : [];
        // the SET, one to one (Codex A7 R2 #2): unique addresses on SP's side, and exactly ours
        const spAddrs = spSet.map(e => lc(e?.address));
        const uniq = new Set(spAddrs);
        check(
          `${P}.guardianSet.unique`,
          "no duplicate address",
          uniq.size === spAddrs.length ? "unique" : "duplicates",
          uniq.size === spAddrs.length
        );
        const oursAddrs = ours.map(o => o.address).sort();
        check(
          `${P}.guardianSet.addresses`,
          [...uniq].sort(),
          oursAddrs,
          JSON.stringify([...uniq].sort()) === JSON.stringify(oursAddrs) &&
            uniq.size === spAddrs.length
        );
        check(`${P}.guardianSet.length`, spSet.length, ours.length, spSet.length === ours.length);
        for (const e of spSet) {
          const o = ours.find(x => x.address === lc(e?.address));
          const Q = `${P}.guardianSet[${e?.address}]`;
          if (!o) {
            check(Q, e, null, false);
            continue;
          }
          check(`${Q}.pubkeyHash`, e.pubkeyHash, o.pubkeyHash, lc(e.pubkeyHash) === o.pubkeyHash);
          // the read method defines an entry as pubkeyHash + slot + isActive (#412 review F1):
          // a field SP left out is unverified, never skipped
          for (const k of ["slot", "isActive"])
            if (e[k] === undefined || e[k] === null)
              unverified.push(`${Q}.${k} (missing from the read-back)`);
            else eq(`${Q}.${k}`, e[k], o[k]);
          for (const k of Object.keys(e))
            if (!["address", "pubkeyHash", "slot", "isActive"].includes(k))
              unverified.push(`${Q}.${k} (no read method)`);
        }
      }
      if ("signerMaskOrder" in c) {
        for (const k of Object.keys(c.signerMaskOrder ?? {}))
          if (!["source", "bits"].includes(k))
            unverified.push(`${P}.signerMaskOrder.${k} (no read method)`);
        // bit i selects slot i+1
        const bits = Array.isArray(c.signerMaskOrder?.bits) ? c.signerMaskOrder.bits.map(lc) : null;
        if (!bits) check(`${P}.signerMaskOrder.bits`, c.signerMaskOrder, null, false);
        else {
          const last = slots.reduce((m, x, i) => (x !== ZERO ? i + 1 : m), 0);
          const ours = slots.slice(0, Math.max(last, bits.length));
          check(
            `${P}.signerMaskOrder.bits`,
            bits,
            ours,
            JSON.stringify(bits) === JSON.stringify(ours)
          );
        }
      }
    }
    if ("thresholds" in c) {
      const t = c.thresholds;
      if (!t || typeof t !== "object" || Array.isArray(t)) {
        check(`${P}.thresholds`, t, null, false);
        return;
      }
      // every SlashLevel must be listed (x-readMethods: slashThresholds(level) for each SlashLevel)
      // the related constants (x-readMethods): listed in thresholds or as contract keys
      for (const k of ["minThreshold", "defaultThreshold", "SLASH_THRESHOLD_FLOOR"])
        if (!(k in t) && !(k in c))
          unverified.push(`${P}.thresholds.${k} (missing from the read-back)`);
      if (!facts.slashLevels) unverified.push(`${P}.thresholds (SlashLevel order unknown)`);
      else
        for (const lvl of Object.keys(facts.slashLevels))
          if (!(lvl in t)) unverified.push(`${P}.thresholds.${lvl} (missing from the read-back)`);
      for (const [name, v] of Object.entries(t)) {
        const Q = `${P}.thresholds.${name}`;
        // a related constant with its own getter (minThreshold, SLASH_THRESHOLD_FLOOR, ...)
        if (IDENT.test(name) && iface.getFunction(`${name}()`)) {
          await field(Q, iface, "blsAggregator", a, name, v);
          continue;
        }
        // a SlashLevel name: slashThresholds(uint8 level), the level's index from SP's source
        const idx = facts.slashLevels?.[name];
        if (idx === undefined) {
          unverified.push(`${Q} (SlashLevel index unknown)`);
          continue;
        }
        const g = await read(iface, a, "slashThresholds(uint8)", [idx]);
        if (g.kind !== "value") check(Q, v, g.kind, false);
        else check(Q, v, g.v, sameTyped(g.f.outputs[0].type, v, g.v));
      }
    }
  }

  async function safe(P, a, c) {
    const s = facts.safe;
    for (const [k, sig] of [
      ["threshold", "getThreshold()"],
      ["owners", "getOwners()"],
    ]) {
      if (!(k in c)) continue;
      const r = await reader.call(a, s, s.getFunction(sig), []);
      if (r.status !== "value") {
        check(`${P}.${k}`, c[k], r.status, false);
        continue;
      }
      if (k === "owners") {
        const o = [...r.v].map(lc);
        const sp = Array.isArray(c.owners) ? c.owners.map(lc) : null;
        check(
          `${P}.owners`,
          c.owners,
          o,
          // in order (#412 review F4): a drill's prevOwner is taken from this list
          !!sp && JSON.stringify(sp) === JSON.stringify(o)
        );
      } else check(`${P}.threshold`, c.threshold, r.v, sameTyped("uint256", c.threshold, r.v));
    }
    if ("singleton" in c) {
      const w = await reader.slot(a, "0x" + "0".repeat(64));
      check(
        `${P}.singleton`,
        c.singleton,
        wordAddr(w),
        typeof c.singleton === "string" && lc(c.singleton) === wordAddr(w)
      );
    }
  }

  // ---- checks: "<key>.<name>", "<key>.<name>(<key2>)" and "<key>.<a> == <key>.<b>"
  const ref = s => {
    const m = s.match(
      /^([A-Za-z_][A-Za-z0-9_]*)\.([A-Za-z_][A-Za-z0-9_]*)(?:\(([A-Za-z_][A-Za-z0-9_]*)\))?$/
    );
    if (!m || !addrOf[m[1]]) return null;
    if (m[3] && !addrOf[m[3]]) return null;
    return { key: m[1], name: m[2], arg: m[3] ? addrOf[m[3]] : null, addr: addrOf[m[1]] };
  };
  const readRef = r =>
    r.arg
      ? read(facts.abi?.[r.key], r.addr, `${r.name}(address)`, [r.arg])
      : read(facts.abi?.[r.key], r.addr, `${r.name}()`);
  for (const [k, v] of Object.entries(rb.checks)) {
    const P = `checks.${k}`;
    // "<key>.thresholds == {WARNING:2, MINOR:3, MAJOR:3}" (schema v8): every SlashLevel read on
    // chain with slashThresholds(level) and compared with the literal; the literal must name them all
    const lit = k.match(/^([A-Za-z_][A-Za-z0-9_]*)\.thresholds == \{([^{}]*)\}$/);
    if (lit) {
      const at = addrOf[lit[1]];
      const iface = facts.abi?.[lit[1]];
      const pairs = lit[2].split(",").map(x => x.trim().match(/^([A-Z_]+):(\d+)$/));
      if (!at || !iface || !facts.slashLevels || typeof v !== "boolean" || pairs.some(x => !x)) {
        unverified.push(`${P} (unresolvable)`);
        continue;
      }
      const want = Object.fromEntries(pairs.map(m => [m[1], BigInt(m[2])]));
      const levels = Object.keys(facts.slashLevels);
      if (JSON.stringify(Object.keys(want).sort()) !== JSON.stringify([...levels].sort())) {
        check(P, "every SlashLevel listed", Object.keys(want), false);
        continue;
      }
      let equal = true;
      let failed = null;
      for (const lvl of levels) {
        const g = await read(iface, at, "slashThresholds(uint8)", [facts.slashLevels[lvl]]);
        if (g.kind !== "value") failed = g.kind;
        else if (BigInt(g.v) !== want[lvl]) equal = false;
      }
      if (failed) check(P, v, failed, false);
      else check(P, v, equal, v === equal);
      continue;
    }
    const two = k.match(/^(\S+) == (\S+)$/);
    if (two) {
      const l = ref(two[1]);
      const r = ref(two[2]);
      if (!l || !r || typeof v !== "boolean") {
        // e.g. "x.creditPolicy == OFF": the right side must name a getter too (x.POLICY_OFF)
        unverified.push(`${P} (unresolvable: both sides must be <contractKey>.<getter>)`);
        continue;
      }
      const gl = await readRef(l);
      const gr = await readRef(r);
      if (gl.kind === "noabi" || gr.kind === "noabi") {
        unverified.push(`${P} (no ABI)`);
        continue;
      }
      if (
        gl.kind !== "value" ||
        gr.kind !== "value" ||
        !scalarOut(gl.f) ||
        !scalarOut(gr.f) ||
        gl.f.outputs[0].type !== gr.f.outputs[0].type
      ) {
        check(P, v, `${gl.kind}/${gr.kind}`, false);
        continue;
      }
      const equal = lc(gl.v) === lc(gr.v);
      check(P, v, equal, v === equal);
      continue;
    }
    const r = ref(k);
    if (!r) {
      unverified.push(`${P} (unresolvable: not a listed contract)`);
      continue;
    }
    if (!r.arg) {
      await field(P, facts.abi?.[r.key] ?? null, r.key, r.addr, r.name, v);
      continue;
    }
    const g = await readRef(r);
    if (g.kind === "noabi") unverified.push(`${P} (no ABI)`);
    else if (v === null)
      check(P, null, g.kind === "notinabi" ? null : "in ABI", g.kind === "notinabi");
    else if (isState(v)) check(P, v, g.kind, ["notinabi", "empty", "revert"].includes(g.kind));
    else if (g.kind !== "value" || !scalarOut(g.f)) check(P, v, g.kind, false);
    else check(P, v, g.v, sameTyped(g.f.outputs[0].type, v, g.v));
  }

  // ---- Amsterdam probe (schema v4, DSR): judged = simulateV1 gasUsed == fork receipt gasUsed ==
  // SP's expected.gasUsed (at least one provider), and eth_call at gas = gasUsed succeeds; recorded
  // only = estimates and gas - 1. Never eval()'d. Runs LAST: it sends a transaction on the fork.
  const pr = rb.amsterdamProbe;
  if (!KNOWN_PREDICATES.includes(pr.predicate)) unverified.push("amsterdamProbe.predicate");
  else {
    // every declared provider has an entry, and every entry is judged (Codex A7 R13): an integer
    // outside the safe range is a failure, never filtered out; "n/a:" / "unreadable:" means that
    // provider has no eth_simulateV1; anything else fails
    for (const prov of h.providers)
      if (!(prov in pr.estimateSimulate))
        unverified.push(`amsterdamProbe.estimateSimulate.${prov} (missing)`);
    for (const [prov, n] of Object.entries(pr.estimateSimulate))
      if (!Number.isSafeInteger(n) && !isState(n))
        check(
          `amsterdamProbe.sp:estimateSimulate.${prov}`,
          "a safe integer or n/a",
          "(unsupported value)",
          false
        );
    const sims = Object.entries(pr.estimateSimulate).filter(([, n]) => Number.isSafeInteger(n));
    check("amsterdamProbe.sp:some provider has eth_simulateV1", "≥1", sims.length, sims.length > 0);
    for (const [p, n] of sims) {
      eq(`amsterdamProbe.sp:estimateSimulate.${p}==gasUsedFork`, pr.gasUsedFork, n);
      eq(`amsterdamProbe.sp:estimateSimulate.${p}==expected.gasUsed`, pr.expected.gasUsed, n);
    }
    // every declared provider, not only the keys SP wrote (#412 review F4)
    for (const prov of h.providers)
      if (!(prov in pr.callAtGasUsed))
        unverified.push(`amsterdamProbe.callAtGasUsed.${prov} (missing)`);
    const calls = Object.entries(pr.callAtGasUsed);
    check(
      "amsterdamProbe.sp:callAtGasUsed all true",
      true,
      calls.length > 0 && calls.every(([, b]) => b === true),
      calls.length > 0 && calls.every(([, b]) => b === true)
    );
    const ours = await reader.probe({
      sender: pr.sender,
      initcode: pr.initcode,
      forkBlock: h.forkBlock,
      gasUsed: pr.expected.gasUsed,
    });
    eq("amsterdamProbe.fork:gasUsed", pr.expected.gasUsed, ours?.gasUsedFork);
    // this script's own upstream: simulateV1 when it has it, and eth_call at gas = gasUsed
    // judged, not skipped (#412 review F3): no eth_simulateV1 upstream is unverified; a revert or
    // an RPC error is a failure
    if (ours?.simulate === "unsupported")
      unverified.push("amsterdamProbe.upstream:simulateV1 (not offered)");
    else eq("amsterdamProbe.upstream:simulateV1", pr.expected.gasUsed, ours?.simulate);
    eq("amsterdamProbe.upstream:callAtGasUsed", true, ours?.callAtGasUsed);
  }
  return { cmp, unverified };
}

/** Any string that looks like a URL is redacted before printing or recording (Codex A7 R1 #5). */
const URLISH = /[a-z][a-z0-9+.-]*:\/\//i;
export const redact = (k, v) => (typeof v === "string" && URLISH.test(v) ? "(redacted)" : v);
/** Deep copy with URL-like KEYS and string values redacted (Codex A7 R4): a JSON replacer can
 * rewrite values but not keys, and read-back keys (e.g. role names) are external input. */
export function sanitize(v, keepTop = new Set(), depth = 0) {
  if (Array.isArray(v)) return v.map(x => sanitize(x, keepTop, depth + 1));
  if (typeof v === "bigint") return v.toString();
  if (v && typeof v === "object") {
    const out = {};
    let n = 0;
    for (const [k, x] of Object.entries(v)) {
      const key = URLISH.test(k) ? `(redacted key ${++n})` : k;
      // the exemption is for a TOP-LEVEL key of the record only (Codex A7 R5): a nested "rpc"
      // inside external input is redacted like anything else
      out[key] = depth === 0 && keepTop.has(k) ? x : sanitize(x, keepTop, depth + 1);
    }
    return out;
  }
  return redact("", v);
}
