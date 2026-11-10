// Shared JS<->Solidity vectors for the recheck encoding. `--write` regenerates
// contracts/test/fixtures/disclosure-vectors.json; without it, exits 1 if the committed file differs
// from what recheck-lib computes now (run by `npm run check:disclosure`).
// contracts/test/DisclosureRecheckParity.t.sol asserts DisclosureRegistry computes the same values.
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { ethers } from "ethers";
import {
  Kind,
  messageHashOf,
  commitmentKey,
  expectedCommitment,
  encodeMessageInputs,
  sortAddresses,
} from "./recheck-lib.mjs";

const OUT = fileURLToPath(
  new URL("../../contracts/test/fixtures/disclosure-vectors.json", import.meta.url)
);
const addr = s => ethers.getAddress(ethers.dataSlice(ethers.id(s), 12));
const ds = ethers.id("vector-domain-separator");
const signers = sortAddresses([addr("v1"), addr("v2"), addr("v3")]);
const anchor = ethers.id("vector-anchor");
const mask = 7n;

const cases = [
  [
    Kind.SLASH,
    7n,
    { operator: addr("op"), slashLevel: 1, epoch: 42n, evidenceHash: ethers.id("ev") },
  ],
  [Kind.GENERIC, 5n, { target: addr("tg"), callDataHash: ethers.id("cd"), requiredThreshold: 3n }],
  [Kind.QUEUE, 0n, { operator: addr("op"), slashLevel: 2, epoch: 43n }],
  [
    Kind.REPUTATION,
    (1n << 128n) - 1n,
    { users: [addr("u1"), addr("u2")], newScores: [10n, 20n], epoch: 44n },
  ],
];

const vectors = cases.map(([kind, id, f]) => {
  const mh = messageHashOf(ds, kind, id, f);
  const key = commitmentKey(kind, id, mh);
  return {
    kind,
    proposalId: ethers.toBeHex(id, 32),
    messageInputs: encodeMessageInputs(kind, f),
    messageHash: mh,
    key: ethers.toBeHex(key, 32),
    commitment: expectedCommitment(ds, key, mh, mask, signers, anchor),
  };
});
const json =
  JSON.stringify({ ds, signerMask: ethers.toBeHex(mask, 32), signers, anchor, vectors }, null, 2) +
  "\n";

if (process.argv.includes("--write")) {
  writeFileSync(OUT, json);
  console.log(`wrote ${OUT}`);
} else {
  const cur = readFileSync(OUT, "utf8");
  if (cur !== json) {
    console.error(
      "disclosure-vectors.json is stale vs recheck-lib.mjs; run: node scripts/disclosure/gen-vectors.mjs --write"
    );
    process.exit(1);
  }
  console.log("disclosure-vectors.json matches recheck-lib.mjs");
}
