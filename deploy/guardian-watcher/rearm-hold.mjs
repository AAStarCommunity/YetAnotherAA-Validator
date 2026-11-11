#!/usr/bin/env node
// Re-arm an accusation that D-RPC2 holds for good (unconfirmed-final: the second provider kept
// reproducing something else), so the second provider is asked again (#422 review, DSR). Only that
// state can be re-armed; the states before and after, and the operator's reason, are written into
// the record's publication journal (holdRearms) and kept in the hold itself (rearmed). Nothing is
// published by this command: the record stays held until the second provider confirms it.
//
// The watcher must be stopped (the command takes the watcher's lock, so the two never write the
// same hold at once):
//   launchctl bootout gui/$(id -u)/ai.aastar.aoa-watcher
//   node deploy/guardian-watcher/rearm-hold.mjs --config ~/.aoa-watcher/config.json \
//     --id <record id> --reason "<why, one line>"
//   launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/ai.aastar.aoa-watcher.plist
//
// Exit 0 re-armed; 1 refused (not unconfirmed-final, unknown record, bad reason); 2 usage or the
// watcher still running; 3 a write failed.
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const W = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "services", "guardian-watcher");
const { loadConfig, watcherLockPort } = await import(join(W, "watcher.mjs"));
const { Store, atomicWriteJson } = await import(join(W, "lib", "store.mjs"));
const { getHold } = await import(join(W, "lib", "confirm.mjs"));
const { acquireLock } = await import(join(W, "lib", "lock.mjs"));

const die = (code, msg) => {
  console.error(`rearm-hold: ${msg}`);
  process.exit(code);
};
const arg = n => {
  const i = process.argv.indexOf(`--${n}`);
  return i > 0 ? process.argv[i + 1] : undefined;
};

/** The checks, pure: why this hold cannot be re-armed, or null. */
export function refusal(hold, reason) {
  if (!hold) return "no hold for this record";
  if (hold.state !== "unconfirmed-final")
    return `only an unconfirmed-final hold can be re-armed (this one is ${String(hold.state).slice(0, 40)})`;
  if (typeof reason !== "string" || reason.trim().length === 0) return "--reason is required";
  // one plain line, kept local; never an endpoint (a URL can carry a key)
  if (
    reason.length > 300 ||
    /[\x00-\x1f\x7f]/.test(reason) ||
    /[a-z][a-z0-9+.-]*:\/\//i.test(reason)
  )
    return "--reason must be one plain line of at most 300 characters, without a URL";
  return null;
}

/** The hold after re-arming, and the journal entry. Pure. */
export function rearmed(hold, reason, at) {
  const before = {
    state: hold.state,
    mismatches: hold.mismatches ?? null,
    attempts: hold.attempts ?? null,
    lastResult: hold.lastResult ?? null,
  };
  const entry = { at, reason, before, after: { state: "unconfirmed", mismatches: 0 } };
  const { nextAttemptAt: _n, ...rest } = hold;
  void _n;
  return {
    hold: {
      ...rest,
      state: "unconfirmed",
      mismatches: 0,
      unavailableStreak: 0,
      rearmed: [...(hold.rearmed ?? []), entry],
    },
    entry,
  };
}

/**
 * Settle journal entries an interrupted run left "pending", from the hold, which is the source of
 * truth (Codex D-RPC2 R8 #5): an entry whose time is in the hold's `rearmed` list was applied,
 * otherwise it was not. Returns the settled list, or null when there is nothing to settle. Pure.
 */
export function reconcile(journalList, hold) {
  const applied = new Set((hold?.rearmed ?? []).map(e => e.at));
  let changed = false;
  const out = (journalList ?? []).map(e => {
    if (e?.applied !== "pending") return e;
    changed = true;
    return { ...e, applied: applied.has(e.at) };
  });
  return changed ? out : null;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const cfgPath = arg("config");
  const id = arg("id");
  const reason = arg("reason");
  if (!cfgPath || !id)
    die(2, "usage: rearm-hold.mjs --config <watcher config> --id <record id> --reason <text>");
  let cfg;
  try {
    cfg = loadConfig(cfgPath);
  } catch {
    die(2, "the watcher config does not load");
  }
  try {
    Store.safeId(id);
  } catch {
    die(1, "not a record id");
  }
  try {
    // exactly the port the watcher takes for this config (Codex D-RPC2 R8 #3)
    await acquireLock(watcherLockPort(cfg));
  } catch {
    die(2, "the watcher is running (its lock is held): stop it first");
  }
  const store = new Store(cfg.dataDir);
  const hold = getHold(store, id);
  // first settle what an interrupted earlier run left pending
  try {
    const pub = store.getPublication(id);
    const settled = reconcile(pub?.holdRearms, hold);
    if (settled) {
      store.putPublication(id, { ...pub, holdRearms: settled });
      console.log(
        `rearm-hold: settled ${settled.filter(e => e.applied === true).length} applied / ${settled.filter(e => e.applied === false).length} not applied earlier re-arm(s)`
      );
    }
  } catch {
    die(3, "the record's journal cannot be read or written");
  }
  const why = refusal(hold, reason);
  if (why) die(1, why);
  const at = new Date().toISOString();
  const { hold: next, entry } = rearmed(hold, reason, at);
  // the journal first, as pending: an interruption after it is settled by the next run, from the hold
  try {
    const pub = store.getPublication(id) ?? {};
    store.putPublication(id, {
      ...pub,
      holdRearms: [...(pub.holdRearms ?? []), { ...entry, applied: "pending" }],
    });
    atomicWriteJson(join(store.dir, "holds", `${id}.json`), next);
    const pub2 = store.getPublication(id);
    const list = [...(pub2.holdRearms ?? [])];
    list[list.length - 1] = { ...list[list.length - 1], applied: true };
    store.putPublication(id, { ...pub2, holdRearms: list });
  } catch {
    die(3, "a write failed; run the command again to settle the journal (holdRearms)");
  }
  console.log(`rearm-hold: ${id} re-armed (was unconfirmed-final); it stays held until confirmed`);
  process.exit(0);
}
