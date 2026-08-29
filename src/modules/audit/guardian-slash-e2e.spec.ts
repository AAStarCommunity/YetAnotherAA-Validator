import { ethers } from "ethers";
import { buildGuardianSignerRecord } from "./guardian-slash-watcher.core.js";
import { assembleOverIssueFraudProof } from "./guardian-fraud-proof-assembler.js";
import {
  VERIFY_AND_EXECUTE_ABI,
  overIssueEvidenceHash,
  overIssueSlashMessageHash,
  computeSignersCommitment,
  deriveFraudProofId,
} from "./guardian-fraud-proof.js";

/**
 * CC-89 stage-2 F3 — DVT-side E2E dry-run. Stitches the whole DVT half end to end:
 *   craft slash → WATCHER CORE builds + self-verifies the signer record → ASSEMBLER builds the
 *   fraudProof → assert the fraudProof's embedded data REPRODUCES the same A' commitment the on-chain
 *   OverIssueFraudProofVerifier recomputes (the load-bearing cross-module invariant).
 *
 * Byte-level acceptance by the Solidity verifier is transitively proven by the golden vector shared
 * with OverIssueFraudProofVerifier.t.sol (#223). See docs/design/cc89-e2e-runbook.md.
 */

const coder = ethers.AbiCoder.defaultAbiCoder();
const S1 = ethers.getAddress("0x0000000000000000000000000000000000001111");
const S2 = ethers.getAddress("0x0000000000000000000000000000000000002222");
const S3 = ethers.getAddress("0x0000000000000000000000000000000000003333");
const OPERATOR = ethers.getAddress("0x000000000000000000000000000000000000abcd");
const AGG = ethers.getAddress("0x0000000000000000000000000000000000000a99");
const REG = ethers.getAddress("0x00000000000000000000000000000000000000b5");
const TOKEN = ethers.getAddress("0x000000000000000000000000000000000000beef");
const CHAIN_ID = 11155111n;
const DOMAIN = { chainId: CHAIN_ID, aggregator: AGG, registry: REG };
const PID = 42n;
const LEVEL = 2;
const EPOCH = 1000n;
const MASK = 0x7n;
const TX_HASH = "0x" + "ab".repeat(32);
const EXEC_BLOCK = 500;

// The evidenceHash a correct over-issue slash MUST use (cross-repo convention).
const EVIDENCE = overIssueEvidenceHash(TOKEN, OPERATOR, EPOCH);
// The commitment SP would store for this slash — a HARDCODED golden literal (NOT computed via the
// production helper), so the E2E's ground truth is independent of a shared TS-helper drift; a helper
// or convention change that alters this value fails the pin-check below AND the chain assertions.
// Params: SP 4.11 domain {chainId=11155111, agg=0x…0a99, registry=0x…00b5}, pid=42, op=…abcd,
// level=2, epoch=1000, token=…beef, mask=0x7, signers=[S1,S2,S3]. (The TS↔Solidity byte-alignment
// itself is pinned by the golden vector shared between guardian-fraud-proof.spec.ts and
// OverIssueFraudProofVerifier.t.sol.)
const ON_CHAIN_COMMITMENT = "0x6861ffee36303335eaf09555377d293f8ce39694b34e1badb56da95ed112fe8a";

const va = new ethers.Interface([
  "function validatorAtSlot(uint8 slot) view returns (address)",
  "function proposalSignersCommitment(uint256 proposalId) view returns (bytes32)",
]);

/** Mock chain: the crafted over-issue slash (calldata, A' commitment, slot→address map). */
class MockProvider {
  private readonly validators: Record<number, string> = { 1: S3, 2: S1, 3: S2 }; // scrambled → sorts to S1,S2,S3
  get provider(): this {
    return this;
  }
  async resolveName(n: string): Promise<string> {
    return n;
  }
  async getTransaction(): Promise<{ data: string }> {
    const iface = new ethers.Interface([VERIFY_AND_EXECUTE_ABI]);
    return {
      data: iface.encodeFunctionData("verifyAndExecute", [
        PID,
        OPERATOR,
        LEVEL,
        [],
        [],
        EPOCH,
        EVIDENCE,
        coder.encode(["uint256", "bytes"], [MASK, "0xdead"]),
      ]),
    };
  }
  async getBlock(): Promise<{ timestamp: number }> {
    return { timestamp: 1_700_000_000 };
  }
  async call(tx: { data: string }): Promise<string> {
    const sel = tx.data.slice(0, 10);
    if (sel === va.getFunction("validatorAtSlot")!.selector) {
      const [slot] = va.decodeFunctionData("validatorAtSlot", tx.data);
      return va.encodeFunctionResult("validatorAtSlot", [
        this.validators[Number(slot)] ?? ethers.ZeroAddress,
      ]);
    }
    return va.encodeFunctionResult("proposalSignersCommitment", [ON_CHAIN_COMMITMENT]);
  }
}

describe("CC-89 stage-2 DVT-side E2E dry-run (watcher core → assembler)", () => {
  it("pins the golden commitment — the production helper still reproduces the hardcoded ground truth", () => {
    // Guards the OTHER direction: if computeSignersCommitment / overIssueSlashMessageHash drift, this
    // fails here (loudly) rather than silently moving the ground truth with the code under test.
    expect(
      computeSignersCommitment(
        DOMAIN,
        PID,
        overIssueSlashMessageHash(DOMAIN, PID, OPERATOR, LEVEL, EPOCH, TOKEN),
        MASK,
        [S1, S2, S3]
      )
    ).toBe(ON_CHAIN_COMMITMENT);
  });

  it("captures a slash, self-verifies, and assembles a fraudProof that reproduces the on-chain commitment", async () => {
    const provider = new MockProvider() as unknown as ethers.Provider;

    // B) WATCHER CORE — capture + self-verify.
    const record = await buildGuardianSignerRecord(
      provider,
      AGG,
      REG,
      CHAIN_ID,
      PID,
      TX_HASH,
      EXEC_BLOCK
    );
    expect(record.commitmentVerified).toBe(true);
    expect(record.claimedSigners).toEqual([S1, S2, S3]);
    expect(record.commitment).toBe(ON_CHAIN_COMMITMENT);

    // C) ASSEMBLER — accuse the exact committed signer set. A subset would let a
    // front-runner consume the one-shot fraudProofId and immunise the omitted signers.
    const assembled = assembleOverIssueFraudProof(record, TOKEN);
    expect(assembled.fraudProofId).toBe(deriveFraudProofId(PID));
    expect(assembled.guiltyGuardians).toEqual([S1, S2, S3]);

    // LOAD-BEARING E2E INVARIANT — decode the assembled fraudProof and independently recompute the
    // commitment the on-chain verifier will derive from it; it MUST equal the stored A' commitment.
    const [pid, op, level, epoch, token, mask, claimed] = coder.decode(
      ["uint256", "address", "uint8", "uint256", "address", "uint256", "address[]"],
      assembled.fraudProof
    );
    const recomputed = computeSignersCommitment(
      DOMAIN,
      BigInt(pid),
      overIssueSlashMessageHash(
        DOMAIN,
        BigInt(pid),
        ethers.getAddress(op),
        Number(level),
        BigInt(epoch),
        ethers.getAddress(token)
      ),
      BigInt(mask),
      [...claimed].map((a: string) => ethers.getAddress(a))
    );
    expect(recomputed).toBe(ON_CHAIN_COMMITMENT); // ⇒ the verifier's commitment check passes
    // SET-EXACT is the verifier's one-shot-id front-run protection.
    expect(assembled.guiltyGuardians).toEqual(record.claimedSigners);
  });

  it("refuses the chain when the disputed token does not bind (token-swap defense)", async () => {
    const provider = new MockProvider() as unknown as ethers.Provider;
    const record = await buildGuardianSignerRecord(
      provider,
      AGG,
      REG,
      CHAIN_ID,
      PID,
      TX_HASH,
      EXEC_BLOCK
    );
    const wrongToken = ethers.getAddress("0x000000000000000000000000000000000000c0de");
    expect(() => assembleOverIssueFraudProof(record, wrongToken)).toThrow(/does not bind/);
  });
});
