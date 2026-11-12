// Shared JS<->Solidity vectors for the M0 §3.1 evidence encoding. `--write` regenerates
// contracts/test/fixtures/evidence-vectors.json; without it, exits 1 if the committed file differs
// from what evidence-lib computes now (`npm run check:evidence`). contracts/test/EvidenceHashParity.t.sol
// recomputes every vector in Solidity; scripts/evidence/sp-evidence-parity.mjs runs SP's own
// DVTValidator against the same file. (Split from scripts/disclosure/gen-vectors.mjs when the
// DisclosureRegistry vectors were retired, DSR 009967e4; the evidence output is byte-identical.)
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { ethers } from "ethers";
import {
  TAG_EVIDENCE,
  evidenceCategory,
  encodeEvidence,
  decodeEvidence,
  evidenceHashOf,
} from "./evidence-lib.mjs";

const addr = s => ethers.getAddress(ethers.dataSlice(ethers.id(s), 12));

// M0 §3.1 evidence encoding (SP DVTValidator 0.8.0 EvidenceHashMismatch). Categories and bodies are illustrative: the encoding is
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

if (process.argv.includes("--write")) {
  writeFileSync(EV_OUT, evJson);
  console.log(`wrote ${EV_OUT}`);
} else {
  let cur = null;
  try {
    cur = readFileSync(EV_OUT, "utf8");
  } catch {
    cur = null;
  }
  if (cur !== evJson) {
    console.error(
      "evidence-vectors.json is stale vs evidence-lib.mjs; run: node scripts/evidence/gen-evidence-vectors.mjs --write"
    );
    process.exit(1);
  }
  console.log("evidence-vectors.json matches evidence-lib.mjs");
}
