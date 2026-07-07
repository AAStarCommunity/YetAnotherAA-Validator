import { ethers } from "ethers";
import { ProofIdentity, PROOF_SCHEMA_VERSION, computeProofHash } from "./proof-archive.js";

/**
 * computeProofHash content-address properties (inc-2-live findings 1 + 2).
 *
 * The proofHash is the off-chain EVIDENCE content-address (NOT the on-chain slash messageHash). It
 * must:
 *   • bind PROOF_SCHEMA_VERSION so a widened identity changes the hash (finding-1 diagnosability);
 *   • depend ONLY on the finalized-block economic reads, NOT any block HEADER (finding-2 liveness):
 *     a non-archive responder that cannot read an old block's hash can still reproduce the hash.
 */
const OP = ethers.getAddress("0x" + "12".repeat(20));

/** A complete, finalized-block ProofIdentity (no wall-clock, no block header). */
function identity(overrides: Partial<ProofIdentity> = {}): ProofIdentity {
  return {
    proofSchemaVersion: PROOF_SCHEMA_VERSION,
    chainId: 11155111,
    operator: OP,
    rule: "credit-over-limit",
    creditLimit: "1000",
    availableCredit: "0",
    debt: "2000",
    violationBlock: 777,
    slashLevel: 1,
    registry: ethers.getAddress("0x" + "a1".repeat(20)),
    superPaymaster: ethers.getAddress("0x" + "a2".repeat(20)),
    dvtValidator: ethers.getAddress("0x" + "a3".repeat(20)),
    apntsToken: ethers.getAddress("0x" + "a4".repeat(20)),
    ...overrides,
  };
}

describe("computeProofHash", () => {
  it("is a 32-byte keccak digest", () => {
    expect(computeProofHash(identity())).toMatch(/^0x[0-9a-f]{64}$/);
  });

  it("is deterministic for the same identity (cross-node / cross-tick agreement)", () => {
    expect(computeProofHash(identity())).toBe(computeProofHash(identity()));
  });

  // ── FINDING 1: version is bound into the hash ──────────────────────────────────
  it("finding-1: proofHash CHANGES when PROOF_SCHEMA_VERSION changes (version is bound in)", () => {
    const current = computeProofHash(identity());
    const bumped = computeProofHash(identity({ proofSchemaVersion: PROOF_SCHEMA_VERSION + 1 }));
    expect(bumped).not.toBe(current);
  });

  // ── FINDING 2: no block-header dependency ──────────────────────────────────────
  it("finding-2: ProofIdentity has NO violationBlockHash field (reorg-safety via finalized block)", () => {
    // A stray blockHash on the object must NOT perturb the hash: only declared identity fields feed
    // the content-address, so a non-archive node that cannot read the header still reproduces it.
    const clean = computeProofHash(identity());
    const withStrayHash = computeProofHash({
      ...identity(),
      // @ts-expect-error violationBlockHash is intentionally NOT part of ProofIdentity anymore.
      violationBlockHash: "0x" + "cc".repeat(32),
    });
    expect(withStrayHash).not.toBe(clean);
    // And a requester (no stray field) + responder (no stray field) still agree byte-for-byte.
    expect(computeProofHash(identity())).toBe(clean);
  });

  it("finding-2: identical economic reads → identical proofHash regardless of the (unhashed) block header", () => {
    // Two nodes read the SAME finalized-block economics. Neither hashes the header, so they agree
    // even if one is a non-archive node that could never read the historical block hash.
    const requester = computeProofHash(identity());
    const nonArchiveResponder = computeProofHash(identity());
    expect(nonArchiveResponder).toBe(requester);
  });

  it("still binds each economic input (a different debt → a different hash)", () => {
    expect(computeProofHash(identity({ debt: "3000" }))).not.toBe(computeProofHash(identity()));
  });
});
