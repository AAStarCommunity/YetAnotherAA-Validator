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
  launchProblems,
  permissionProblems,
  symlinkProblems,
} from "./lib/guard.mjs";

const refuse = problems => {
  console.error(`pause-detector: refusing to run: ${problems.slice(0, 5).join("; ")}`);
  process.exit(78);
};
const home = homedir();
const d = join(home, DIR);
const first = [
  ...permissionProblems(process.permission, home),
  ...launchProblems({
    execArgv: process.execArgv,
    script: process.argv[1],
    envNames: Object.keys(process.env),
    home,
  }),
];
if (first.length) refuse(first);
const tree = [...symlinkProblems(d), ...bundleProblems(join(d, "app"))];
if (tree.length) refuse(tree);
const { main } = await import("./run.mjs");
process.exit(await main());
