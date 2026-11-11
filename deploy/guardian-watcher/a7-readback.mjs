// Comparison of SuperPaymaster's aoa-a7-readback/1 file (SP 2228c0b6, frozen;
// docs/release/a7/aoa-a7-readback-1.schema.json) with what THIS script reads from the loaded fork.
// Pure: every chain read goes through an injected reader, so the rules are self-tested
// (check-a7-readback.mjs) without a chain.
//
// Rules (DSR 272084f2, 0829236d and the A7 schema message):
//   - the file validates against the pinned schema (Draft 2020-12) before anything is compared;
//   - a value SP reports is compared with an independent read; a valueState (null "absent",
//     "unreadable:...", "n/a:...") says SP got nothing there, so our read must yield nothing too;
//   - anything this script has no independent reader for is listed as UNVERIFIED, and an unverified
//     field stops the rehearsal exactly like a mismatch (no drill on a state that was not proven).
import Ajv2020 from "ajv/dist/2020.js";

export const SCHEMA_ID = "aoa-a7-readback/1";
/** sha256 of SP's FROZEN schema file at 2228c0b6 (DSR-verified; any later change needs DSR
 * acceptance and a new hash). */
export const SCHEMA_SHA256 = "fb25b34e51c90a53b7058f9f9ca225510e7fb75d7d940a4538b7459ddbeefff0";
export const SCHEMA_SOURCE = {
  repo: "AAStarCommunity/SuperPaymaster",
  ref: "2228c0b66aadb497966fea2ef0a83c2f41d8ba39",
  path: "docs/release/a7/aoa-a7-readback-1.schema.json",
};
export const ANVIL_COMMIT = "4e8874b2bdc840929585ca73e170993c50a4a531";
/** Sepolia's Amsterdam (upstream EIP-7910 eth_config.current). */
export const AMSTERDAM = { activationTime: 1791294816, forkId: "0x6c1d9423" };
export const EIP1967_IMPL = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";
/** The probe rules this script can evaluate (SP's example wording); any other is unverified. */
export const KNOWN_PREDICATES = [
  "all(estimateLive[p] == estimateFork for p in estimateLive) and estimateFork == expected.estimate and gasUsedFork == expected.gasUsed",
];

const ZERO = "0x0000000000000000000000000000000000000000";
const IDENT = /^[A-Za-z_][A-Za-z0-9_]*$/;

/** Schema validation: returns the list of errors (paths only), empty when valid. */
export function validate(schema, rb) {
  const ajv = new Ajv2020({ allErrors: true, strict: false });
  const ok = ajv.validate(schema, rb);
  return ok ? [] : (ajv.errors ?? []).map(e => `${e.instancePath || "/"} ${e.keyword}`);
}

export const isState = v => v === null || (typeof v === "string" && /^(unreadable|n\/a):/.test(v));

const norm = v =>
  typeof v === "bigint"
    ? v.toString()
    : typeof v === "number"
      ? String(v)
      : typeof v === "string" && /^0x[0-9a-fA-F]*$/.test(v)
        ? v.toLowerCase()
        : v;
const same = (a, b) => JSON.stringify(norm(a)) === JSON.stringify(norm(b));

/** The ABI return type a scalar value implies, or null for one no getter can return. */
export function typeOf(v) {
  if (typeof v === "boolean") return "bool";
  if (typeof v === "number" && Number.isSafeInteger(v) && v >= 0) return "uint256";
  if (typeof v !== "string") return null;
  if (/^0x[0-9a-fA-F]{40}$/.test(v)) return "address";
  if (/^0x[0-9a-fA-F]{64}$/.test(v)) return "bytes32";
  if (/^[0-9]+$/.test(v)) return "uint256";
  return "string";
}

/**
 * Compare the whole file. reader: {
 *   chainId(), block(n) -> {hash} | null, code(addr), slot(addr, slot) -> 32-byte hex,
 *   call(addr, name, type) -> value | undefined (undefined = no value: absent or reverted),
 *   upstreamHeader(n) -> {blockAccessListHash: bool, slotNumber: bool} | undefined,
 *   probe({sender, initcode, forkBlock}) -> {estimateFork, gasUsedFork, estimateLive} | undefined
 * }; facts: {anvilVersion, anvilCommit, dumpSha256, forkBlock}.
 * Returns {cmp: [{path, sp, fork, ok}], unverified: [path]}.
 */
export async function compare(rb, reader, facts) {
  const cmp = [];
  const unverified = [];
  const check = (path, sp, ours) =>
    cmp.push({
      path,
      sp: sp ?? null,
      fork: ours ?? null,
      ok: ours !== undefined && same(sp, ours),
    });
  // a valueState from SP: our read must also yield nothing (undefined, or the empty/zero form)
  const nothing = (path, sp, ours) =>
    cmp.push({ path, sp, fork: ours ?? null, ok: ours === undefined || ours === null });
  const h = rb.header;

  // ---- header
  check("header.source", "fork", h.source);
  check("header.chainId", h.chainId, await reader.chainId());
  check("header.forkBlock", h.forkBlock, facts.forkBlock);
  check("header.hardfork", "amsterdam", h.hardfork);
  check("header.anvilCommit", ANVIL_COMMIT, h.anvilCommit);
  check("header.anvilCommit=binary", h.anvilCommit, facts.anvilCommit);
  check("header.anvilVersion=binary", h.anvilVersion, facts.anvilVersion);
  check("header.dumpSha256", h.dumpSha256, facts.dumpSha256);
  const blk = await reader.block(h.readbackBlock);
  check("header.readbackBlockHash", h.readbackBlockHash, blk?.hash);
  for (const p of h.providers)
    if (/[:/]/.test(p))
      cmp.push({ path: "header.providers", sp: "(a URL)", fork: null, ok: false });
  // Amsterdam from UPSTREAM only (the local engine's eth_config is its own configuration)
  check("header.ethConfig.activationTime", AMSTERDAM.activationTime, h.ethConfig.activationTime);
  check("header.ethConfig.forkId", AMSTERDAM.forkId, h.ethConfig.forkId);
  const co = h.ethConfig.corroboration;
  check("header.ethConfig.corroboration.blockNumber", h.forkBlock, co.blockNumber);
  check("header.ethConfig.corroboration.blockAccessListHash", true, co.blockAccessListHash);
  check("header.ethConfig.corroboration.slotNumber", true, co.slotNumber);
  // a third look, from this script's own upstream: the Amsterdam-only header fields at forkBlock
  const up = await reader.upstreamHeader(h.forkBlock);
  check("upstream.blockAccessListHash", true, up?.blockAccessListHash);
  check("upstream.slotNumber", true, up?.slotNumber);

  // ---- contracts
  const addrOf = {};
  for (const [key, c] of Object.entries(rb.contracts)) {
    const P = `contracts.${key}`;
    if (isState(c.address)) {
      // SP says there is nothing deployed for this key: every field must then be a state too
      for (const [k, v] of Object.entries(c))
        if (k !== "address" && !isState(v) && !(k === "roles" && same(v, {})) && k !== "version")
          cmp.push({ path: `${P}.${k}`, sp: v, fork: null, ok: false });
      continue;
    }
    const a = c.address;
    addrOf[key] = a;
    const code = await reader.code(a);
    const codehash = code && code !== "0x" ? reader.keccak(code) : undefined;
    if (isState(c.codehash)) nothing(`${P}.codehash`, c.codehash, codehash);
    else check(`${P}.codehash`, c.codehash, codehash);
    const implWord = await reader.slot(a, EIP1967_IMPL);
    const impl =
      implWord && BigInt(implWord) !== 0n ? `0x${implWord.slice(-40)}`.toLowerCase() : undefined;
    if (isState(c.erc1967Impl)) nothing(`${P}.erc1967Impl`, c.erc1967Impl, impl);
    else check(`${P}.erc1967Impl`, c.erc1967Impl, impl);
    const implCode = impl ? await reader.code(impl) : undefined;
    const implHash = implCode && implCode !== "0x" ? reader.keccak(implCode) : undefined;
    if (isState(c.implCodehash)) nothing(`${P}.implCodehash`, c.implCodehash, implHash);
    else check(`${P}.implCodehash`, c.implCodehash, implHash);
    // extension: no independent reader of WHERE a contract's extension is (SP to name the getter);
    // its codehash is checked against the address SP gives, the address itself stays unverified
    unverified.push(`${P}.extension`);
    if (!isState(c.extension) && !isState(c.extensionCodehash)) {
      const ec = await reader.code(c.extension);
      check(
        `${P}.extensionCodehash`,
        c.extensionCodehash,
        ec && ec !== "0x" ? reader.keccak(ec) : undefined
      );
    } else if (isState(c.extension) !== isState(c.extensionCodehash))
      cmp.push({ path: `${P}.extensionCodehash`, sp: c.extensionCodehash, fork: null, ok: false });
    for (const [k, type] of [
      ["version", "string"],
      ["owner", "address"],
      ["pendingOwner", "address"],
      ["guardian", "address"],
    ]) {
      const ours = await reader.call(a, k, type);
      if (isState(c[k])) nothing(`${P}.${k}`, c[k], ours);
      else check(`${P}.${k}`, c[k], ours);
    }
    // roles: no enumeration reader (role names -> members); unverified until SP names one
    unverified.push(`${P}.roles`);
    // contract-specific keys: a scalar is read through its same-named getter; a list/object is not
    const COMMON = new Set([
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
    ]);
    for (const [k, v] of Object.entries(c)) {
      if (COMMON.has(k)) continue;
      const t = isState(v) ? null : typeOf(v);
      if (!IDENT.test(k) || (!isState(v) && !t)) {
        unverified.push(`${P}.${k}`);
        continue;
      }
      if (isState(v)) {
        // a state for a getter we do not know the type of: nothing must come back as any type
        nothing(`${P}.${k}`, v, await reader.call(a, k, "uint256"));
        continue;
      }
      check(`${P}.${k}`, v, await reader.call(a, k, t));
    }
  }

  // ---- checks
  const getter = async (ref, type) => {
    const m = ref.match(/^([A-Za-z_][A-Za-z0-9_]*)\.([A-Za-z_][A-Za-z0-9_]*)$/);
    if (!m || !addrOf[m[1]]) return { ok: false };
    return { ok: true, v: await reader.call(addrOf[m[1]], m[2], type) };
  };
  for (const [k, v] of Object.entries(rb.checks)) {
    const P = `checks.${k}`;
    const eq = k.match(/^(\S+) == (\S+)$/);
    if (eq) {
      // equality of two getters; the type is taken from whichever side the contracts say
      if (typeof v !== "boolean") {
        unverified.push(P);
        continue;
      }
      let done = false;
      for (const type of ["address", "uint256", "bytes32", "bool", "string"]) {
        const l = await getter(eq[1], type);
        const r = await getter(eq[2], type);
        if (!l.ok || !r.ok) break;
        if (l.v === undefined || r.v === undefined) continue;
        check(P, v, same(l.v, r.v));
        done = true;
        break;
      }
      if (!done) unverified.push(P);
      continue;
    }
    const t = isState(v) ? "uint256" : typeOf(v);
    const g = t ? await getter(k, t) : { ok: false };
    if (!g.ok) {
      unverified.push(P);
      continue;
    }
    if (isState(v)) nothing(P, v, g.v);
    else check(P, v, g.v);
  }

  // ---- Amsterdam probe (behavioural positive control), evaluated by this script, never eval()
  const pr = rb.amsterdamProbe;
  if (!KNOWN_PREDICATES.includes(pr.predicate)) unverified.push("amsterdamProbe.predicate");
  else {
    const live = Object.entries(pr.estimateLive);
    check(
      "amsterdamProbe.sp:estimateLive==estimateFork",
      true,
      live.length > 0 && live.every(([, n]) => n === pr.estimateFork)
    );
    check(
      "amsterdamProbe.sp:estimateFork==expected.estimate",
      pr.expected.estimate,
      pr.estimateFork
    );
    check("amsterdamProbe.sp:gasUsedFork==expected.gasUsed", pr.expected.gasUsed, pr.gasUsedFork);
    const ours = await reader.probe({
      sender: pr.sender,
      initcode: pr.initcode,
      forkBlock: h.forkBlock,
    });
    check("amsterdamProbe.fork:estimate", pr.estimateFork, ours?.estimateFork);
    check("amsterdamProbe.fork:gasUsed", pr.expected.gasUsed, ours?.gasUsedFork);
    check("amsterdamProbe.upstream:estimate", pr.expected.estimate, ours?.estimateLive);
  }
  return { cmp, unverified };
}
