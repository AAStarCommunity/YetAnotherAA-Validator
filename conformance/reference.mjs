// aNode DVT — cross-language CONFORMANCE reference (Node.js / @noble/curves).
//
// This is the canonical, language-neutral definition of the aNode BLS signing + aggregation
// + EIP-2537 wire encoding. ANY implementation (Node.js / Go / Rust) is a valid aNode iff it
// reproduces `vectors.json` BYTE-FOR-BYTE from the same inputs.
//
//   Run reference (regenerate + self-verify):  node conformance/reference.mjs
//   Verify an impl's output against canonical:  node conformance/reference.mjs --check <file.json>
//
// The frozen contract these vectors pin (see docs/design/dvt-node-protocol.md):
//   curve     BLS12-381, signatures in G2, public keys in G1
//   DST       BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_   (RFC 9380; NB noble defaults _NUL_)
//   message   messagePoint = hashToCurve(userOpHash, {DST})                       (G2)
//   pubkey    pk = sk · G1.BASE                                                    (G1)
//   sign      sig = sk · messagePoint                                              (G2)
//   aggregate aggSig = Σ sig_i (G2 add) ; aggPk = Σ pk_i (G1 add)
//   encode    EIP-2537: G1 = x@16,y@80 (128B) ; G2 = x.c0@16,x.c1@80,y.c0@144,y.c1@208 (256B)
//   wire      validate(userOpHash, [nodeId_0..nodeId_{n-1}][aggSig(256B)])   → on-chain == 0
//
// A Go/Rust port must emit the SAME hex for: pubkey, messagePoint, sig, aggSig, aggPk, wire.
import { bls12_381 as bls } from "@noble/curves/bls12-381.js";
import { readFileSync, writeFileSync } from "fs";
import { fileURLToPath } from "url";
import { dirname, join } from "path";

const sigs = bls.longSignatures;
export const DST = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
const HERE = dirname(fileURLToPath(import.meta.url));
const VECTORS = join(HERE, "vectors.json");

const hexToBytes = h => {
  h = h.replace(/^0x/, "");
  const b = new Uint8Array(h.length / 2);
  for (let i = 0; i < b.length; i++) b[i] = parseInt(h.substr(i * 2, 2), 16);
  return b;
};
const toHex = u8 => "0x" + Buffer.from(u8).toString("hex");
const fp = x => x.toString(16).padStart(96, "0"); // 48-byte Fp coordinate

// EIP-2537 encodings — identical to src/utils/bls.util.ts (the node's wire format).
function encodeG1(point) {
  const a = point.toAffine();
  const r = new Uint8Array(128);
  r.set(hexToBytes(fp(a.x)), 16);
  r.set(hexToBytes(fp(a.y)), 80);
  return r;
}
function encodeG2(point) {
  const a = point.toAffine();
  const r = new Uint8Array(256);
  r.set(hexToBytes(fp(a.x.c0)), 16);
  r.set(hexToBytes(fp(a.x.c1)), 80);
  r.set(hexToBytes(fp(a.y.c0)), 144);
  r.set(hexToBytes(fp(a.y.c1)), 208);
  return r;
}

// Deterministic, language-neutral inputs. Secret keys are fixed 32-byte big-endian scalars
// (small values, valid in [1, r-1]); nodeIds are fixed bytes32 (registration-slot identifiers).
const SIGNERS = [
  { nodeId: "0x" + "00".repeat(31) + "01", sk: "0x" + "00".repeat(31) + "11" },
  { nodeId: "0x" + "00".repeat(31) + "02", sk: "0x" + "00".repeat(31) + "22" },
  { nodeId: "0x" + "00".repeat(31) + "03", sk: "0x" + "00".repeat(31) + "33" },
];
// Messages = stand-in userOpHashes (bytes32). One all-zero-ish, one "Hello", one arbitrary.
const MESSAGES = [
  "0x" + "00".repeat(31) + "2a",
  "0x48656c6c6f2c20776f726c642100000000000000000000000000000000000000",
  "0x" + "ab".repeat(32),
];

function buildVectors() {
  const signers = SIGNERS.map(s => {
    const pk = sigs.getPublicKey(hexToBytes(s.sk));
    return {
      nodeId: s.nodeId,
      sk: s.sk,
      pubkey: toHex(encodeG1(pk)),
      pubkeyCompact: pk.toHex(),
      _pkPoint: pk,
    };
  });
  const cases = MESSAGES.map(msg => {
    const mp = bls.G2.hashToCurve(hexToBytes(msg), { DST });
    const per = signers.map(s => {
      const sig = sigs.sign(mp, hexToBytes(s.sk));
      return {
        nodeId: s.nodeId,
        signature: toHex(encodeG2(sig)),
        signatureCompact: sig.toHex(),
        _sig: sig,
      };
    });
    const aggSig = sigs.aggregateSignatures(per.map(p => p._sig));
    const aggPk = signers.map(s => s._pkPoint).reduce((a, b) => a.add(b));
    const valid = sigs.verify(aggSig, mp, aggPk);
    if (!valid) throw new Error(`self-verify FAILED for message ${msg}`);
    const wire = new Uint8Array([
      ...signers.flatMap(s => [...hexToBytes(s.nodeId)]),
      ...encodeG2(aggSig),
    ]);
    return {
      userOpHash: msg,
      messagePoint: toHex(encodeG2(mp)),
      signatures: per.map(({ nodeId, signature, signatureCompact }) => ({
        nodeId,
        signature,
        signatureCompact,
      })),
      aggregateSignature: toHex(encodeG2(aggSig)),
      aggregatePublicKey: toHex(encodeG1(aggPk)),
      wire: toHex(wire),
      offchainVerify: valid,
    };
  });
  return {
    spec: "aNode DVT BLS conformance v1",
    curve: "BLS12-381",
    dst: DST,
    encoding: {
      g1: "EIP-2537 128B x@16 y@80",
      g2: "EIP-2537 256B x.c0@16 x.c1@80 y.c0@144 y.c1@208",
    },
    wireFormat:
      "[nodeId_0..nodeId_{n-1}][aggregateSignature(256B)] → AAStarBLSAlgorithm.validate(userOpHash, wire)==0",
    signers: signers.map(({ nodeId, sk, pubkey, pubkeyCompact }) => ({
      nodeId,
      sk,
      pubkey,
      pubkeyCompact,
    })),
    cases,
  };
}

const stable = obj => JSON.stringify(obj, null, 2) + "\n";

if (process.argv[2] === "--check") {
  // Compare an implementation's output to the canonical reference (byte-for-byte JSON).
  const file = process.argv[3];
  if (!file) {
    console.error("usage: node conformance/reference.mjs --check <impl-vectors.json>");
    process.exit(2);
  }
  const canonical = stable(buildVectors());
  const got = readFileSync(file, "utf8");
  if (got.trim() === canonical.trim()) {
    console.log(`✅ CONFORMANT — ${file} matches the canonical reference byte-for-byte.`);
    process.exit(0);
  }
  console.error(`❌ NON-CONFORMANT — ${file} differs from the canonical reference.`);
  // Show first differing line for a quick hint.
  const a = canonical.split("\n"),
    b = got.split("\n");
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    if (a[i] !== b[i]) {
      console.error(
        `  first diff @ line ${i + 1}:\n    canonical: ${a[i] ?? "(eof)"}\n    impl     : ${b[i] ?? "(eof)"}`
      );
      break;
    }
  }
  process.exit(1);
} else {
  const out = stable(buildVectors());
  writeFileSync(VECTORS, out);
  const v = JSON.parse(out);
  console.log(`✅ wrote ${VECTORS}`);
  console.log(
    `   ${v.signers.length} signers · ${v.cases.length} message cases · all offchain-verify = ${v.cases.every(c => c.offchainVerify)}`
  );
  console.log(`   DST ${v.dst}`);
}
