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
  TAG_EVIDENCE,
  evidenceCategory,
  encodeEvidence,
  decodeEvidence,
  evidenceHashOf,
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

// M0 §3.1 evidence encoding (SP DVTValidator 0.8.0 EvidenceHashMismatch), in its own fixture so the
// message vectors above stay byte-identical. Categories and bodies are illustrative: the encoding is
// what both sides must agree on, whatever a category's body struct is.
const EV_OUT = fileURLToPath(
  new URL("../../contracts/test/fixtures/evidence-vectors.json", import.meta.url)
);
const coder = ethers.AbiCoder.defaultAbiCoder();
const overIssue = evidenceCategory("OverIssue", 1);
const auditSlash = evidenceCategory("AuditSlash", 1);
const evCases = [
  [overIssue, "0x"], // empty body
  [overIssue, "0x01"], // one byte (padding)
  [overIssue, coder.encode(["address", "address", "uint256"], [addr("tok"), addr("op"), 42n])],
  [
    auditSlash,
    coder.encode(["uint256", "address", "bytes32"], [7n, addr("op"), ethers.id("proof")]),
  ],
  [auditSlash, ethers.hexlify(new Uint8Array(1000).map((_, i) => i & 0xff))], // long body
];
const evVectors = evCases.map(([category, body]) => {
  const evidence = encodeEvidence(category, body);
  const back = decodeEvidence(evidence);
  if (back.category !== category || back.body !== ethers.hexlify(ethers.getBytes(body)))
    throw new Error("evidence round trip failed");
  const evidenceHash = evidenceHashOf(category, body);
  // Where abi.encode vs encodePacked matters: the evidence blob (bytes is dynamic, so abi.encode
  // carries an offset and a length word). For evidenceHash itself the two coincide, since its three
  // inputs are static bytes32 words; the vector records both facts so neither is assumed.
  const packedEvidence = ethers.solidityPacked(["bytes32", "bytes"], [category, body]);
  if (packedEvidence === evidence)
    throw new Error("packed evidence unexpectedly equals abi.encode");
  const packedHash = ethers.keccak256(
    ethers.solidityPacked(
      ["bytes32", "bytes32", "bytes32"],
      [TAG_EVIDENCE, category, ethers.keccak256(body)]
    )
  );
  if (packedHash !== evidenceHash) throw new Error("three static words should pack as they encode");
  return {
    category,
    body: ethers.hexlify(ethers.getBytes(body)),
    evidence,
    evidenceHash,
    packedEvidence,
  };
});
const evJson =
  JSON.stringify(
    {
      tagEvidence: TAG_EVIDENCE,
      tagPreimage: "SuperPaymaster.DVT.Evidence.v2",
      categories: {
        "DVT.Evidence.OverIssue.v1": overIssue,
        "DVT.Evidence.AuditSlash.v1": auditSlash,
      },
      vectors: evVectors,
    },
    null,
    2
  ) + "\n";

const outputs = [
  [OUT, json, "disclosure-vectors.json"],
  [EV_OUT, evJson, "evidence-vectors.json"],
];
if (process.argv.includes("--write")) {
  for (const [path, text] of outputs) {
    writeFileSync(path, text);
    console.log(`wrote ${path}`);
  }
} else {
  let stale = false;
  for (const [path, text, name] of outputs) {
    let cur = null;
    try {
      cur = readFileSync(path, "utf8");
    } catch {
      cur = null;
    }
    if (cur !== text) {
      console.error(
        `${name} is stale vs recheck-lib.mjs; run: node scripts/disclosure/gen-vectors.mjs --write`
      );
      stale = true;
    } else console.log(`${name} matches recheck-lib.mjs`);
  }
  if (stale) process.exit(1);
}
