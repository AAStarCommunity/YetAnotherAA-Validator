#!/usr/bin/env node
// The rc.8 pause DETECTOR's entry (DSR: "detect, then act by hand"), run by launchd
// (io.aastar.dvt-pause-detector, StartInterval 3600) from its BUNDLE (bundle.mjs):
//
//   <pinned node> --permission --allow-fs-read=~/.aoa-pause-detector \
//     --allow-fs-write=~/.aoa-pause-detector/state \
//     ~/.aoa-pause-detector/app/deploy/pause-detector/detector.mjs --config ~/.aoa-pause-detector/config.json
//
// Before anything else is loaded, the guards (lib/guard.mjs, Node builtins only) check the
// permission model, the exact launch, and that the bundle is exactly its manifest with no symlink
// anywhere under ~/.aoa-pause-detector. Only then is run.mjs imported. README "The guarantee".
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

const refuse = problems => {
  const text = `refusing to run: ${problems.slice(0, 5).join("; ")}`;
  console.error(`pause-detector: ${text}`);
  recordStop(homedir(), text);
  process.exit(78);
};
const home = homedir();
const d = join(home, DIR);
const first = [
  ...permissionProblems(process.permission, home),
  ...launchProblems({
    execArgv: process.execArgv,
    script: process.argv[1],
    args: process.argv.slice(2),
    envNames: Object.keys(process.env),
    home,
  }),
];
if (first.length) refuse(first);
const tree = [...symlinkProblems(d), ...bundleProblems(join(d, "app"))];
if (tree.length) refuse(tree);
// from here on nothing dies silently (DSR): an uncaught exception or rejection is recorded as a stop
// (its code or class only, never its message, which may carry a URL) and the process exits non-zero
const crashed = e => {
  const what = crashLabel(e);
  const text = `uncaught ${what}`;
  console.error(`pause-detector: ${text}`);
  recordStop(home, text);
  process.exit(1);
};
process.on("uncaughtException", crashed);
process.on("unhandledRejection", crashed);
const { main } = await import("./run.mjs");
process.exit(await main());
