#!/usr/bin/env node
// External heartbeat / lag check on the guardian watcher (M0 §5.5; DSR: drill item 4, kill-alert).
// It runs as its own launchd job (ai.aastar.aoa-watcher-heartbeat), never inside the watcher: a
// degraded flag the watcher writes cannot report that the watcher itself is dead. It reads only the
// watcher's status.json and alerts through the same Telegram bot and chat.
//
//   node deploy/guardian-watcher/heartbeat.mjs --config <watcher config.json> [--test]
//
// Rules (state in <dataDir>/heartbeat/, written atomically):
//   status.json missing, unreadable, or older than staleAfterMs (default 3 x intervalMs)
//       -> "watcher not running or stuck", at once, repeated at most every realertMs (1 h)
//   status.lagBlocks > maxLagBlocks                         -> "cursor N blocks behind", likewise
//   status.at unchanged across checks for longer than staleAfterMs, or in the future -> stale
//   status.healthy === false on unhealthyAfter (2) checks in a row -> "degraded" with a reason COUNT
//   back to healthy after an alert                          -> one RECOVERED message
//   state that cannot be written                            -> an alert at once (it would mute the rules)
// The bot token comes from the macOS Keychain (service aoa-dvt-alert-bot-token, account aoa-watcher,
// DSR 0829236d; or publish.telegram.service when set); it is handed to curl through stdin, never on
// a command line. Nothing from status.json is sent but numbers: fixed wording only.
import { spawnSync } from "node:child_process";
import { readFileSync, writeFileSync, renameSync, mkdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { hostname } from "node:os";

const args = process.argv.slice(2);
const ci = args.indexOf("--config");

/** One check. Everything external is injectable for the self-test. */
/** The status reflects a completed publication pass: finished, or interim carrying one. */
export function fromCompleted(status) {
  const p = status?.publication;
  if (!p || p.inProgress !== true) return true;
  return typeof p.at === "string" && !p.error;
}

export async function check({
  cfg,
  now = Date.now(),
  readStatus = p => readFileSync(p, "utf8"),
  statMtime = p => statSync(p).mtimeMs,
  send,
  writeState,
  readState,
}) {
  // The heartbeat reads config.json on its own (no watcher validation): every number it uses or
  // prints must be a positive safe integer, or the default is used and the bad setting is alerted
  // in fixed wording, never echoed (Codex W2c R24)
  let badSetting = false;
  const posInt = (v, def) => {
    if (v === undefined || v === null) return def;
    if (Number.isSafeInteger(v) && v > 0) return v;
    badSetting = true;
    return def;
  };
  const hb = cfg.heartbeat ?? {};
  const interval = posInt(cfg.intervalMs, 60_000);
  const staleAfter = posInt(hb.staleAfterMs, 3 * interval);
  const realert = posInt(hb.realertMs, 3_600_000);
  const unhealthyAfter = posInt(hb.unhealthyAfter, 2);
  const maxLag = posInt(cfg.maxLagBlocks, 300);
  const state = readState() ?? { alerting: null, lastSentAt: 0, unhealthyRuns: 0 };

  // what is wrong now, in fixed wording
  let problem = null;
  let status = null;
  try {
    status = JSON.parse(readStatus(join(cfg.dataDir, "status.json")));
  } catch {
    status = null;
  }
  const at = status && Date.parse(status.at);
  let age = null;
  let mtime = null;
  try {
    mtime = statMtime(join(cfg.dataDir, "status.json"));
    age = now - Math.max(Number.isFinite(at) ? at : 0, mtime);
  } catch {
    age = null;
  }
  // a timestamp in the future (clock rollback, or a bad write) would otherwise read as fresh until
  // it passes (Codex W2c R8 #2); and a status.at that does not change across checks is stale however
  // fresh it claims to be
  const future = Math.max(Number.isFinite(at) ? at : 0, mtime ?? 0) > now + 60_000;
  const sameAt = status && state.lastAt === status.at;
  const unchangedFor = sameAt && state.lastAtSeenSince ? now - state.lastAtSeenSince : 0;
  if (!status || age === null)
    problem = { key: "stale", text: "watcher not running or stuck: no readable status.json" };
  else if (future)
    problem = {
      key: "stale",
      text: "watcher status timestamp is in the future (clock or status.json wrong)",
    };
  else if (age > staleAfter)
    problem = {
      key: "stale",
      text: `watcher not running or stuck: status.json is ${Math.round(age / 60_000)} min old`,
    };
  else if (unchangedFor > staleAfter)
    problem = {
      key: "stale",
      text: `watcher not running or stuck: status unchanged for ${Math.round(unchangedFor / 60_000)} min`,
    };
  else if (Number.isSafeInteger(status.lagBlocks) && status.lagBlocks > maxLag)
    problem = {
      key: "lag",
      text: `cursor ${status.lagBlocks} blocks behind finalized (> ${maxLag})`,
    };
  if (!problem && badSetting)
    problem = {
      key: "config",
      text: "heartbeat config invalid: a numeric setting is not a positive integer (defaults used)",
    };
  const unhealthyRuns = status && status.healthy === false ? state.unhealthyRuns + 1 : 0;
  if (!problem && unhealthyRuns >= unhealthyAfter) {
    // only a count leaves the Mini: status.degraded is the watcher's text, and truncation is not
    // sanitization (Codex W2c R8 #1); the reasons are read on the Mini itself
    const n = Array.isArray(status.degraded) ? status.degraded.length : 0;
    problem = {
      key: "unhealthy",
      text: `watcher degraded for ${unhealthyRuns} checks (${n} reason${n === 1 ? "" : "s"} in status.json on the host)`,
    };
  }

  const host = hostLabel(hb);
  const next = {
    ...state,
    unhealthyRuns,
    lastAt: status?.at ?? null,
    lastAtSeenSince: sameAt ? (state.lastAtSeenSince ?? now) : now,
  };
  let sent = null;
  if (problem) {
    const changed = state.alerting !== problem.key;
    if (changed || now - (state.lastSentAt ?? 0) >= realert) {
      const ok = await send(`[aoa-watcher] ${host}: ${problem.text}`);
      if (ok) {
        next.lastSentAt = now;
        next.alerting = problem.key;
        sent = problem.key;
      }
    }
  } else if (state.alerting && status?.healthy === true && fromCompleted(status)) {
    // recovery needs a positive healthy from a completed iteration: a fresh but unhealthy status
    // below the unhealthy threshold (#413 review N1) is not "recovered". A status written while
    // publication is in progress counts only when it carries a completed pass's result (`at`):
    // the watcher then judges it by that pass and that iteration's slowness, so it is as healthy
    // as the completed iteration (#413 review Low 2: with checks phase-locked to the in-progress
    // window, RECOVERED was otherwise held back). Without a carried result it is not a recovery
    // (Codex W2c R18).
    const ok = await send(
      `[aoa-watcher] ${host}: RECOVERED (status fresh, lag within ${maxLag}, healthy)`
    );
    if (ok) {
      next.alerting = null;
      next.lastSentAt = now;
      sent = "recovered";
    }
  }
  if (!writeState(next)) {
    await send(
      `[aoa-watcher] ${host}: heartbeat cannot write its state; alerts may be muted until fixed`
    );
    return { problem: problem?.key ?? null, sent, stateWritten: false };
  }
  return { problem: problem?.key ?? null, sent, stateWritten: true };
}

/** Telegram through curl, the token in curl's config on stdin (never in argv). */
function telegramSend(cfg) {
  const svc =
    cfg.heartbeat?.keychainService ?? cfg.publish?.telegram?.service ?? "aoa-dvt-alert-bot-token";
  const acct = cfg.heartbeat?.keychainAccount ?? cfg.publish?.keychainAccount ?? "aoa-watcher";
  const chatId = cfg.heartbeat?.chatId ?? cfg.publish?.telegram?.chatId;
  return async text => {
    const tok = spawnSync("security", ["find-generic-password", "-s", svc, "-a", acct, "-w"], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    });
    if (tok.status !== 0 || !chatId) {
      console.error("heartbeat: no bot token in the Keychain or no chat id; cannot alert");
      return false;
    }
    const r = spawnSync(
      "curl",
      [
        "-sS",
        "-m",
        "20",
        "-K",
        "-",
        "--data-urlencode",
        `chat_id=${chatId}`,
        "--data-urlencode",
        `text=${text}`,
      ],
      {
        input: `url = "https://api.telegram.org/bot${tok.stdout.trim()}/sendMessage"\n`,
        encoding: "utf8",
        stdio: ["pipe", "pipe", "ignore"],
      }
    );
    let ok = false;
    try {
      ok = r.status === 0 && JSON.parse(r.stdout).ok === true;
    } catch {
      ok = false;
    }
    if (!ok) console.error("heartbeat: telegram send failed");
    return ok;
  };
}

if (process.argv[1] && process.argv[1].endsWith("heartbeat.mjs") && ci >= 0) {
  const cfg = JSON.parse(readFileSync(args[ci + 1], "utf8"));
  const dir = join(cfg.dataDir, "heartbeat");
  const statePath = join(dir, "state.json");
  const send = telegramSend(cfg);
  if (args.includes("--test")) {
    const ok = await send(
      `[aoa-watcher] ${hostLabel(cfg.heartbeat ?? {})}: heartbeat TEST at ${new Date().toISOString()}`
    );
    process.exit(ok ? 0 : 1);
  }
  const r = await check({
    cfg,
    send,
    readState: () => {
      try {
        return JSON.parse(readFileSync(statePath, "utf8"));
      } catch {
        return null;
      }
    },
    writeState: s => {
      try {
        mkdirSync(dir, { recursive: true, mode: 0o700 });
        const tmp = `${statePath}.tmp-${process.pid}`;
        writeFileSync(tmp, JSON.stringify(s) + "\n", { mode: 0o600 });
        renameSync(tmp, statePath);
        return true;
      } catch {
        return false;
      }
    },
  });
  console.log(JSON.stringify({ at: new Date().toISOString(), ...r }));
  process.exit(r.problem ? 1 : 0);
}

/** The host name in a message: a plain identifier only, never arbitrary config text (Codex W2c
 * R23 #2). A label outside that shape is replaced, the hostname is reduced to safe characters. */
export function hostLabel(hb) {
  if (hb?.label !== undefined)
    return /^[A-Za-z0-9._-]{1,40}$/.test(String(hb.label)) ? String(hb.label) : "invalid-label";
  return (
    hostname()
      .replace(/[^A-Za-z0-9.-]/g, "")
      .slice(0, 40) || "host"
  );
}
