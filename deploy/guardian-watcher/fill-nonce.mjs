#!/usr/bin/env node
// Consume a registry writer nonce that no transaction will ever consume (#425 review B2, DSR): a
// 0-value transfer from the writer to itself at that nonce. It touches no registry. Two cases only:
//   - a record WAITS for it: after a same-writer registry switch its old disclose (at this nonce)
//     was evicted, so the watcher would wait, degraded, for good;
//   - it is a GAP the watcher reports (pending or skipped, held by no journal's active stage).
// A nonce held by a stage on the CURRENT registry is refused (that tx is the watcher's own to
// finish), and so is any other nonce. Prefer the M0 §5.5a recovery (a new writer) when it applies;
// this is the lighter path for one stuck nonce. After the fill is consumed at the finalized block,
// the waiting record is archived and disclosed again as usual.
//
// The watcher must be stopped (the command takes the watcher's lock):
//   launchctl bootout gui/$(id -u)/ai.aastar.aoa-watcher
//   RPC_URL=... node deploy/guardian-watcher/fill-nonce.mjs --config ~/.aoa-watcher/config.json \
//     --nonce <n> --reason "<why, one line>"
//   launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/ai.aastar.aoa-watcher.plist
//
// Every run is journalled in <dataDir>/nonce-fills.json: the entry is written "pending" before
// anything is signed, gets the signed hash before the broadcast, and is marked applied afterwards;
// an entry an interrupted run left pending is settled by the next run (applied when a node knows
// its tx). Exit 0 broadcast; 1 refused; 2 usage or the watcher still running; 3 a step failed.
import { dirname, join } from "node:path";
import { readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";

const W = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "services", "guardian-watcher");
const { Store, atomicWriteJson, readJson } = await import(join(W, "lib", "store.mjs"));
const { nonceUseOf, nonceGaps } = await import(join(W, "lib", "publisher.mjs"));
const { registryAt, sameRegistry, stageSigner } = await import(join(W, "lib", "publish.mjs"));

/** One plain local line, never an endpoint (a URL can carry a key). Pure. */
export function badReason(reason) {
  if (typeof reason !== "string" || reason.trim().length === 0) return "--reason is required";
  if (
    reason.length > 300 ||
    /[\x00-\x1f\x7f]/.test(reason) ||
    /[a-z][a-z0-9+.-]*:\/\//i.test(reason)
  )
    return "--reason must be one plain line of at most 300 characters, without a URL";
  return null;
}

/** Every publication journal; an unreadable one refuses the fill (it could hold this nonce). */
function journals(store) {
  const dir = join(store.dir, "publications");
  const out = [];
  for (const f of readdirSync(dir)) {
    if (!f.endsWith(".json")) continue;
    const id = f.slice(0, -5);
    const pub = store.getPublication(id); // throws on a damaged file
    if (pub) out.push({ id, pub });
  }
  return out;
}

const fillsPath = store => join(store.dir, "nonce-fills.json");
const readFills = store => readJson(fillsPath(store), { fills: [] }).fills ?? [];
const writeFills = (store, fills) => atomicWriteJson(fillsPath(store), { fills });

/**
 * Whether nonce `n` may be filled, against every journal and the node: { basis, ids } or
 * { refuse }. `where` is the configured registry { address, chainId }.
 */
export async function planFill(store, reg, where, n) {
  if (!Number.isSafeInteger(n) || n < 0)
    return { refuse: "--nonce must be a non-negative integer" };
  const writer = String(await reg.writer()).toLowerCase();
  const range = await reg.nonceRange();
  if (n < range.latest) return { refuse: `nonce ${n} is already consumed` };
  let pubs;
  try {
    pubs = journals(store);
  } catch {
    return { refuse: "a publication journal is unreadable; it could hold this nonce" };
  }
  const entries = {};
  const waits = [];
  // every journalled tx of this writer at this nonce on this chain, active or archived (Codex W2d
  // R8 #2): while a node still knows one, it is mined or evicted first, never replaced by a fill
  const known = [];
  for (const { id, pub } of pubs) {
    const u = nonceUseOf(pub);
    entries[id] = u ? { nonceUse: u } : {};
    for (const st of [pub.registry, ...(pub.registryHistory ?? [])]) {
      if (!st || st.nonce !== n) continue;
      const at = registryAt(st);
      const signer = stageSigner(st);
      if (!at || at.chainId !== where.chainId || !signer || signer.toLowerCase() !== writer)
        continue;
      for (const h of st.hashes ?? (st.hash ? [st.hash] : [])) known.push({ id, h });
    }
    if (!u || u.from !== writer || u.chainId !== where.chainId || u.nonce !== n) continue;
    // a stage on the current registry is the watcher's own to finish, whatever a wait marker says
    // (a marker left from an earlier configuration is stale: Codex W2d R8 #1)
    if (sameRegistry(registryAt(pub.registry), where))
      return { refuse: `nonce ${n} is held by ${id}'s stage on the current registry` };
    waits.push(id);
  }
  for (const k of known)
    if (await reg.knows(k.h))
      return {
        refuse: `a journalled tx at nonce ${n} (${k.id}) is still known to the node: it is mined or evicted first`,
      };
  // an earlier fill at this nonce that a node knows is not sent twice
  for (const f of readFills(store))
    if (f?.nonce === n && f.hash && (await reg.knows(f.hash)))
      return { refuse: `a fill at nonce ${n} is already known to the node` };
  if (waits.length) return { basis: "wait", ids: waits };
  if (nonceGaps(entries, writer, where.chainId, range).includes(n))
    return { basis: "gap", ids: [] };
  return { refuse: `nonce ${n} is neither waited for by a record nor a gap` };
}

/** Settle entries an interrupted run left pending: applied when a node knows the signed tx. */
export async function reconcileFills(store, reg) {
  const fills = readFills(store);
  let changed = 0;
  for (const f of fills) {
    if (f?.applied !== "pending") continue;
    f.applied = !!(f.hash && (await reg.knows(f.hash)));
    changed++;
  }
  if (changed) writeFills(store, fills);
  return changed;
}

/** The whole command after the lock: { code, msg }. */
export async function runFill(store, reg, where, n, reason, now = () => new Date().toISOString()) {
  const why = badReason(reason);
  if (why) return { code: 1, msg: why };
  await reconcileFills(store, reg);
  const plan = await planFill(store, reg, where, n);
  if (plan.refuse) return { code: 1, msg: plan.refuse };
  const fills = readFills(store);
  const entry = {
    at: now(),
    nonce: n,
    writer: String(await reg.writer()),
    chainId: where.chainId,
    basis: plan.basis,
    ids: plan.ids,
    reason,
    applied: "pending",
  };
  fills.push(entry);
  writeFills(store, fills); // journal before signing
  let signed;
  try {
    signed = await reg.signFill(n);
  } catch (e) {
    entry.applied = false;
    entry.error = e?.code === "FEE_CAP" ? "FEE_CAP" : "sign failed";
    writeFills(store, fills);
    return { code: 3, msg: `signing failed (${entry.error})` };
  }
  entry.hash = signed.hash;
  writeFills(store, fills); // journal before broadcast
  try {
    await reg.broadcast(signed.raw);
  } catch {
    // the node may have accepted it and the answer been lost (Codex W2d R8 #3): the outcome is
    // unknown, so the entry stays pending and the next run settles it from the node
    entry.error = "broadcast answer lost or refused (outcome unknown)";
    writeFills(store, fills);
    return {
      code: 3,
      msg: "the broadcast failed or its answer was lost; run the command again: it settles this entry from the node first",
    };
  }
  entry.applied = true;
  writeFills(store, fills);
  return {
    code: 0,
    msg: `nonce ${n} fill broadcast (${plan.basis}${plan.ids.length ? `: ${plan.ids.join(", ")}` : ""}); the watcher continues once it is consumed at the finalized block`,
  };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const die = (code, msg) => {
    console.error(`fill-nonce: ${msg}`);
    process.exit(code);
  };
  const arg = k => {
    const i = process.argv.indexOf(`--${k}`);
    return i > 0 ? process.argv[i + 1] : undefined;
  };
  const cfgPath = arg("config");
  const nonceArg = arg("nonce");
  if (!cfgPath || !/^\d+$/.test(nonceArg ?? ""))
    die(2, "usage: fill-nonce.mjs --config <watcher config> --nonce <n> --reason <text>");
  const { loadConfig, watcherLockPort } = await import(join(W, "watcher.mjs"));
  const { publishConfig, buildSinks } = await import(join(W, "lib", "sinks-config.mjs"));
  const { readRoles, currentRoles } = await import(join(W, "lib", "publisher.mjs"));
  const { acquireLock } = await import(join(W, "lib", "lock.mjs"));
  const { makeProvider } = await import(
    join(W, "..", "..", "scripts", "disclosure", "recheck-lib.mjs")
  );
  let cfg;
  try {
    cfg = loadConfig(cfgPath);
  } catch {
    die(2, "the watcher config does not load");
  }
  if (!cfg.publish?.enabled || !Number.isSafeInteger(cfg.chainId))
    die(2, "publication is not enabled in this config (no registry writer)");
  const p = publishConfig(cfg.publish);
  try {
    await acquireLock(watcherLockPort(cfg, p));
  } catch {
    die(2, "the watcher is running (its lock is held): stop it first");
  }
  if (!process.env.RPC_URL) die(2, "RPC_URL is required");
  const chain = makeProvider(process.env.RPC_URL);
  let reg;
  try {
    if (Number((await chain.getNetwork()).chainId) !== cfg.chainId)
      die(2, "the RPC is on another chain than chainId");
    const built = await buildSinks(p, chain, { chainId: cfg.chainId });
    const roles = await readRoles(chain, cfg.aggregator, p.registry.deployer);
    reg = built.registryFor(roles, () => currentRoles(chain, cfg.aggregator, p.registry.deployer));
  } catch {
    die(3, "the writer or its roles could not be loaded");
  }
  const where = { address: String(p.registry.address).toLowerCase(), chainId: String(cfg.chainId) };
  let r;
  try {
    r = await runFill(new Store(cfg.dataDir), reg, where, Number(nonceArg), arg("reason"));
  } catch {
    die(3, "a step failed; run the command again (the journal settles itself)");
  }
  if (r.code) die(r.code, r.msg);
  console.log(`fill-nonce: ${r.msg}`);
  process.exit(0);
}
