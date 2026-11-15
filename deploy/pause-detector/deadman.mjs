#!/usr/bin/env node
// The pause detector's DEAD-MAN check (DSR: required before the detector counts as rc.8's pause
// path). launchd runs it every 15 minutes (io.aastar.dvt-pause-detector-deadman), from the same
// bundle and under the same confinement as the detector, except that it may write only its own
// directory, ~/.aoa-pause-detector/deadman:
//
//   <pinned node> --permission --allow-fs-read=~/.aoa-pause-detector \
//     --allow-fs-write=~/.aoa-pause-detector/deadman \
//     ~/.aoa-pause-detector/app/deploy/pause-detector/deadman.mjs --config ~/.aoa-pause-detector/config.json
//
// Of the detector's files it reads only the heartbeat (state/heartbeat.json, written by each
// completed round); besides that it reads the shared config, the alert bot token and its own state.
// It alerts through the detector's Telegram path (aastar-monitor) when there has been no completed
// round for 2 hours, so a detector that never starts, hangs, crashes or is killed still gives a
// signal. Guards first, as in detector.mjs; then deadman-run.mjs.
import { homedir } from "node:os";
import { join } from "node:path";
import {
  DIR,
  bundleProblems,
  crashLabel,
  launchProblems,
  permissionProblems,
  recordStop,
  symlinkProblems,
} from "./lib/guard.mjs";

const home = homedir();
const d = join(home, DIR);
const refuse = problems => {
  const text = `refusing to run: ${problems.slice(0, 5).join("; ")}`;
  console.error(`pause-detector dead-man: ${text}`);
  recordStop(home, text, "deadman");
  process.exit(78);
};
const first = [
  ...permissionProblems(process.permission, home),
  ...launchProblems({
    execArgv: process.execArgv,
    script: process.argv[1],
    args: process.argv.slice(2),
    envNames: Object.keys(process.env),
    home,
    entry: "deadman",
  }),
];
if (first.length) refuse(first);
const tree = [...symlinkProblems(d), ...bundleProblems(join(d, "app"))];
if (tree.length) refuse(tree);
const crashed = e => {
  const what = crashLabel(e);
  console.error(`pause-detector dead-man: uncaught ${what}`);
  recordStop(home, `uncaught ${what}`, "deadman");
  process.exit(1);
};
process.on("uncaughtException", crashed);
process.on("unhandledRejection", crashed);
const { main } = await import("./deadman-run.mjs");
process.exit(await main());
