// The dead-man check's run (deadman.mjs is the entry and its guards come first). README "Dead-man".
//
// One run reads the detector's heartbeat (~/.aoa-pause-detector/state/heartbeat.json, written by
// every COMPLETED round, clear or not) and decides:
//   - no completed round for more than MAX_SILENCE_MS (2 h, DSR), the heartbeat missing,
//     unreadable or dated in the future: ALERT "no successful round", repeated every REALERT_MS
//     while it lasts;
//   - a fresh heartbeat after an alert: one "rounds resumed" notice.
// It writes only ~/.aoa-pause-detector/deadman (its own state and status). It holds no key and
// reads no chain: it watches the detector, not SuperPaymaster.
import { homedir } from "node:os";
import { join } from "node:path";
import { GuardError, DIR, readOwnJson, recordStop } from "./lib/guard.mjs";
import { DETECTOR_SECRETS, telegram, writeDurable } from "./run.mjs";
import { readSecretFile } from "../pause-job/lib/secret-file.mjs";
import { safeText } from "../pause-job/lib/safe-error.mjs";

/** No completed detector round for this long is an alert (DSR: 2 h). */
export const MAX_SILENCE_MS = 2 * 3600_000;
/** While it lasts, the alert repeats this often. */
export const REALERT_MS = 6 * 3600_000;

/**
 * The decision, pure. `hb` is the parsed heartbeat (or null when missing/unreadable), `st` the
 * dead-man's own state { alerting, lastSent }. Returns { silent, ageMs, message, next } where
 * `message` is the text to send (or null) and `next` the state to keep IF that message was sent
 * (when it was not, the caller keeps `st`, so the alert is retried next run).
 */
export function deadmanDecision(hb, now, st) {
  const at = hb?.schema === "aoa-pause-detector-heartbeat/1" ? Date.parse(hb.at) : NaN;
  const ageMs = Number.isFinite(at) ? now - at : Infinity;
  // a heartbeat from the future is a clock problem or a forged file: never "alive"
  const silent = !(ageMs >= 0 && ageMs <= MAX_SILENCE_MS);
  const alerting = st?.alerting === true;
  const lastSent = Number.isFinite(st?.lastSent) ? st.lastSent : 0;
  if (silent) {
    const due = !alerting || now - lastSent >= REALERT_MS || lastSent > now;
    const since = Number.isFinite(at)
      ? `the last one was ${new Date(at).toISOString()}`
      : "no heartbeat on record";
    return {
      silent,
      ageMs,
      message: due
        ? `DEAD-MAN: the pause detector has had no successful round for more than 2 h (${since}). Check the job (launchctl print gui/$(id -u)/io.aastar.dvt-pause-detector) and its status.json.`
        : null,
      next: { alerting: true, lastSent: due ? now : lastSent },
    };
  }
  return {
    silent,
    ageMs,
    message: alerting ? "DEAD-MAN: the pause detector's rounds have resumed." : null,
    next: { alerting: false, lastSent },
  };
}

/** One run. Returns the exit code: 0 alive, 1 silent (alerted or not), 78 unusable config. */
export async function main() {
  const home = homedir();
  const d = join(home, DIR);
  const own = join(d, "deadman");
  const stop = (code, text) => {
    console.error(`pause-detector dead-man: ${text}`);
    recordStop(home, text, "deadman");
    return code;
  };
  let cfg;
  try {
    cfg = readOwnJson(join(d, "config.json"), "config");
  } catch (e) {
    return stop(78, e instanceof GuardError ? e.message : "config unreadable");
  }
  const tgOk = cfg?.telegram === null || /^-?[0-9]+$/.test(String(cfg?.telegram?.chatId ?? ""));
  if (!tgOk) return stop(78, "config: telegram must be null or { chatId }");
  let token = null;
  if (cfg.telegram)
    try {
      token = readSecretFile(DETECTOR_SECRETS.telegram, join(d, "secrets"), {
        names: DETECTOR_SECRETS,
      });
    } catch (e) {
      return stop(78, `the alert bot token file: ${safeText("secrets", e)}`);
    }
  let hb = null;
  try {
    hb = readOwnJson(join(d, "state", "heartbeat.json"), "heartbeat");
  } catch {
    hb = null; // missing or unreadable: no proof of life
  }
  let st = { alerting: false, lastSent: 0 };
  try {
    const j = readOwnJson(join(own, "state.json"), "dead-man state");
    if (j && typeof j === "object" && !Array.isArray(j)) st = j;
  } catch {
    /* first run, or unreadable: start fresh (an alert is then sent, never suppressed) */
  }
  const now = Date.now();
  const dec = deadmanDecision(hb, now, st);
  let delivery = { ok: true, sent: 0 };
  let keep = dec.next;
  if (dec.message) {
    const r = await telegram(
      cfg,
      token,
      `DVT pause detector (chain ${cfg.chainId}): ${dec.message}`
    );
    delivery = { ...r, sent: r.ok ? 1 : 0 };
    // an alert not delivered is retried next run (the old state is kept)
    if (!r.ok) keep = st;
  }
  try {
    writeDurable(join(own, "state.json"), keep);
    writeDurable(join(own, "status.json"), {
      schema: "aoa-pause-detector-deadman/1",
      at: new Date(now).toISOString(),
      heartbeatAt: hb?.at ?? null,
      silent: dec.silent,
      delivery,
    });
  } catch (e) {
    return stop(1, safeText("dead-man state", e));
  }
  return dec.silent || !delivery.ok ? 1 : 0;
}
