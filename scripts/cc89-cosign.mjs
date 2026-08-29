#!/usr/bin/env node
// CC-89 joint-testnet co-sign CLI — produce the 3-of-3 BLS aggregate `proof` SuperPaymaster's
// BLSAggregator.verifyAndExecute needs for a (disputed, over-issue) slash proposal.
//
// This is a thin ENTRYPOINT over the SAME primitives the DVT signer service uses in production
// (src/modules/bls + src/modules/audit/gossip-quorum-cosigner): @noble longSignatures over the
// SP-matching DST, EIP-2537 G2 encoding, proof = abi.encode(uint256 signerMask, bytes sigG2).
// It just signs with the 3 LOCAL guardian keys (node_dev_00{1,2,3}.json) instead of over gossip —
// which is correct for the testnet E2E where all 3 keys are on this machine (CLAUDE.md dev nodes).
//
// The messageHash is SP 4.11's slash-only expectedMessageHash (BLSAggregator.sol:977):
//   domainSeparator = keccak256(abi.encode(DOMAIN_NAME, chainId, aggregator, registry))
//   messageHash     = keccak256(abi.encode(domainSeparator, TAG_EXECUTE_SLASH,
//                                          proposalId, operator, slashLevel, epoch, evidenceHash))
// and each key signs hashToCurve(messageHash, DST) — byte-identical to BLSAggregator._checkSignatures.
// The Registry (4th domain field) is read from the aggregator on-chain and the locally-derived
// domainSeparator is asserted == aggregator.domainSeparator() BEFORE signing — so the hash we sign is
// provably the one the live contract reconstructs, not one we invented.
//
// Usage (real run — fields from SP):
//   PROPOSAL_ID=42 OPERATOR=0x.. SLASH_LEVEL=1 EPOCH=100 \
//     TOKEN=0x..            (over-issue evidenceHash = keccak(TAG,token,operator,epoch))  \
//     AGGREGATOR=0xf44E7E51..  SEPOLIA_RPC_URL=..  node scripts/cc89-cosign.mjs
//   (or pass EVIDENCE_HASH=0x.. directly instead of TOKEN)
// Self-test (no SP fields — proves the 3-key aggregate passes on-chain verify):
//   AGGREGATOR=0xf44E7E51..  SEPOLIA_RPC_URL=..  node scripts/cc89-cosign.mjs --selftest
//
// Output: the `proof` bytes to hand SP, after a staticcall to aggregator.verify(...) returns true.
import { bls12_381 as bls } from "@noble/curves/bls12-381.js";
import { ethers } from "ethers";
import { readFileSync, existsSync } from "fs";
// SINGLE SOURCE OF TRUTH for the SP 4.11 domain/tag/layout — shared with src/modules/audit/
// bls-consensus-domain.ts (pinned equal by bls-consensus-encoding.spec.ts). Do NOT re-derive here.
import {
  domainSeparator as spDomainSeparator,
  executeSlashMessageHash as spExecuteSlashMessageHash,
  overIssueEvidenceHash as spOverIssueEvidenceHash,
} from "./lib/bls-consensus-encoding.mjs";

const sigs = bls.longSignatures;
// MUST equal SP BLSAggregator BLS.sol hashToG2 DST + src/utils/bls.util.ts BLS_DST.
const BLS_DST = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
const coder = ethers.AbiCoder.defaultAbiCoder();
const die = m => {
  console.error("✗ " + m);
  process.exit(1);
};

// EIP-2537 G2 (256B) — identical layout to src/utils/bls.util.ts encodeG2Point.
const _fp = x => {
  const b = new Uint8Array(48);
  const s = x.toString(16).padStart(96, "0");
  for (let i = 0; i < 48; i++) b[i] = parseInt(s.substr(i * 2, 2), 16);
  return b;
};
const eip2537G2 = point => {
  const a = point.toAffine();
  const r = new Uint8Array(256);
  r.set(_fp(a.x.c0), 16);
  r.set(_fp(a.x.c1), 80);
  r.set(_fp(a.y.c0), 144);
  r.set(_fp(a.y.c1), 208);
  return "0x" + Buffer.from(r).toString("hex");
};

function loadKey(slot) {
  const f = `node_dev_00${slot}.json`;
  if (!existsSync(f)) die(`${f} not found — generate the 3 guardian keys first`);
  const s = JSON.parse(readFileSync(f, "utf8"));
  if (!s.privateKey) die(`${f} has no privateKey`);
  return Buffer.from(s.privateKey.replace(/^0x/, ""), "hex");
}

const selftest = process.argv.includes("--selftest");
const chainId = BigInt(process.env.CHAIN_ID || "11155111");
const aggregator = process.env.AGGREGATOR || die("AGGREGATOR required");
const rpc =
  process.env.SEPOLIA_RPC_URL || process.env.ETH_RPC_URL || die("SEPOLIA_RPC_URL required");

const provider = new ethers.JsonRpcProvider(rpc);

// ---- 1. messageHash ---------------------------------------------------------
let messageHash;
if (selftest) {
  messageHash = ethers.keccak256(ethers.toUtf8Bytes("cc89-cosign-selftest"));
  console.log(
    "SELF-TEST mode: signing a DUMMY messageHash to prove only that the 3-key aggregate + EIP-2537 " +
      "encoding verify on-chain. This is NOT a domain-bound message and does NOT prove verifyAndExecute " +
      "would accept it — the real path (no --selftest) attests domainSeparator vs the aggregator first."
  );
} else {
  const proposalId = BigInt(process.env.PROPOSAL_ID || die("PROPOSAL_ID required"));
  const operator = ethers.getAddress(process.env.OPERATOR || die("OPERATOR required"));
  const slashLevel = parseInt(process.env.SLASH_LEVEL || die("SLASH_LEVEL required"), 10);
  const epoch = BigInt(process.env.EPOCH || die("EPOCH required"));
  let evidenceHash = process.env.EVIDENCE_HASH;
  if (!evidenceHash) {
    const token = ethers.getAddress(process.env.TOKEN || die("TOKEN or EVIDENCE_HASH required"));
    evidenceHash = spOverIssueEvidenceHash(token, operator, epoch);
    console.log(`over-issue evidenceHash(${token}, ${operator}, ${epoch}) = ${evidenceHash}`);
  }

  // Read the Registry (4th domain field) from the aggregator itself — authoritative, no hand-entry.
  const domainProbe = new ethers.Contract(
    aggregator,
    [
      "function REGISTRY() view returns (address)",
      "function domainSeparator() view returns (bytes32)",
    ],
    provider
  );
  const registry = await domainProbe.REGISTRY();
  const domain = { chainId, aggregator, registry };
  const localDomainSeparator = spDomainSeparator(domain);
  // Strengthened self-check: prove the domain we are about to sign is the EXACT one the live
  // contract reconstructs — not merely whatever hash we hand its generic verify(). A mismatch means
  // wrong chainId/aggregator/Registry; signing would produce a proof SP's _checkSignatures rejects.
  const onChainDomain = await domainProbe.domainSeparator();
  if (onChainDomain.toLowerCase() !== localDomainSeparator.toLowerCase()) {
    die(
      `domainSeparator mismatch: local ${localDomainSeparator} != aggregator.domainSeparator() ${onChainDomain} ` +
        `(chainId ${chainId} / aggregator ${aggregator} / registry ${registry})`
    );
  }
  console.log(`domainSeparator (verified vs on-chain): ${localDomainSeparator}`);
  // SP 4.11 slash-only expectedMessageHash (BLSAggregator.sol:977) — via the shared encoding lib.
  messageHash = spExecuteSlashMessageHash(
    domain,
    proposalId,
    operator,
    slashLevel,
    epoch,
    evidenceHash
  );
}
console.log("messageHash:", messageHash);

// ---- 2. sign with the 3 local guardian keys + aggregate ---------------------
const msgG2 = bls.G2.hashToCurve(ethers.getBytes(messageHash), { DST: BLS_DST });
const perSig = [1, 2, 3].map(slot => sigs.sign(msgG2, loadKey(slot)));
const aggregate = sigs.aggregateSignatures(perSig);
const sigG2 = eip2537G2(aggregate);
const signerMask = 0x7n; // slots 1,2,3
const proof = coder.encode(["uint256", "bytes"], [signerMask, sigG2]);

// ---- 3. on-chain self-verify (definitive: passes ⇒ verifyAndExecute will accept) -----
const agg = new ethers.Contract(
  aggregator,
  ["function verify(bytes32,uint256,uint256,bytes) view returns (bool)"],
  provider
);
const ok = await agg.verify(messageHash, signerMask, 3n, sigG2);
console.log("\n=== aggregator.verify(messageHash, mask=0x7, threshold=3, sigG2) =", ok, "===");
if (!ok) die("on-chain verify returned FALSE — aggregate/encoding/keys mismatch, DO NOT submit");

console.log("\n✓ 3-of-3 aggregate VALID on-chain. Hand SP this proof for verifyAndExecute:");
console.log("signerMask:", "0x" + signerMask.toString(16));
console.log("sigG2 (EIP-2537 256B):", sigG2);
console.log("proof (abi.encode(uint256,bytes)):", proof);
